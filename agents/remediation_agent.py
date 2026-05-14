import asyncio
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from agents.analysis_agent import AnalysisResult
from llm.openai_client import OpenAIClient
from llm.prompts import remediation_prompt

logger = logging.getLogger(__name__)


@dataclass
class RemediationResult:
    dependency: str
    old_version: str
    new_version: str
    llm_used: bool
    llm_raw: Optional[Dict[str, Any]]
    notes: str


class RemediationAgent:
    def __init__(self) -> None:
        self.llm = OpenAIClient()

    async def remediate(self, repo_path: str, analysis: AnalysisResult, validation_feedback: str | None = None) -> RemediationResult:
        repo_dir = Path(repo_path)
        package_json_path = repo_dir / "package.json"
        package_lock_path = repo_dir / "package-lock.json"

        pkg = json.loads(package_json_path.read_text(encoding="utf-8"))
        deps = pkg.get("dependencies") or {}

        old_version = deps.get(analysis.dependency) or ""
        recommended = analysis.recommended_version

        prompt = remediation_prompt(analysis, validation_feedback=validation_feedback)

        llm_used = False
        llm_raw: Optional[Dict[str, Any]] = None
        new_version = recommended
        notes = ""

        # Strict mode: OpenAI call must succeed. No fallback.
        llm_used = True
        logger.info("[remediation] calling OpenAI model for %s", analysis.dependency)
        resp = await asyncio.to_thread(self.llm.generate_response, prompt)
        llm_raw = resp.raw
        new_version = self._parse_version_from_llm(resp.text, analysis.dependency) or recommended
        notes = "LLM suggested version applied"
        logger.info("[remediation] OpenAI response parsed version=%s", new_version)

        deps[analysis.dependency] = new_version
        pkg["dependencies"] = deps

        # Preserve formatting (indent=2); keep trailing newline.
        package_json_path.write_text(json.dumps(pkg, indent=2) + "\n", encoding="utf-8")
        logger.info("[remediation] updated package.json: %s=%s", analysis.dependency, new_version)

        # Remove lockfile so npm can regenerate cleanly for demo.
        if package_lock_path.exists():
            package_lock_path.unlink()

        # Re-install to update lockfile/node_modules.
        await self._run_cmd(["npm", "install"], cwd=repo_dir)

        return RemediationResult(
            dependency=analysis.dependency,
            old_version=old_version,
            new_version=new_version,
            llm_used=llm_used,
            llm_raw=llm_raw,
            notes=notes,
        )

    def _parse_version_from_llm(self, text: str, dependency: str) -> Optional[str]:
        # Expect JSON fragment like {"axios": "^1.6.0"}
        try:
            obj = json.loads(self._extract_json_object(text))
            if isinstance(obj, dict) and dependency in obj and isinstance(obj[dependency], str):
                return obj[dependency]
        except Exception:
            pass
        # fallback: find version-like string
        m = re.search(r"\^(\d+\.\d+\.\d+)", text)
        if m:
            return f"^{m.group(1)}"
        return None

    def _extract_json_object(self, text: str) -> str:
        match = re.search(r"\{.*\}", text, flags=re.S)
        if not match:
            raise ValueError("No JSON object found in LLM response")
        return match.group(0)

    async def _run_cmd(self, args: list[str], cwd: Path) -> str:
        proc = await asyncio.create_subprocess_exec(
            *args,
            cwd=str(cwd),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        out_b, _ = await proc.communicate()
        out = out_b.decode("utf-8", errors="replace")
        if proc.returncode != 0:
            raise RuntimeError(f"Command failed ({proc.returncode}): {' '.join(args)}\n{out}")
        return out
