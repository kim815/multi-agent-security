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

        recommended = analysis.recommended_version
        prompt = remediation_prompt(analysis, validation_feedback=validation_feedback)

        # Strict mode: OpenAI call must succeed. No fallback.
        logger.info("[remediation] calling OpenAI model for %s (%s)", analysis.dependency, analysis.ecosystem)
        resp = await asyncio.to_thread(self.llm.generate_response, prompt)
        llm_raw: Optional[Dict[str, Any]] = resp.raw
        new_version = self._parse_version_from_llm(resp.text, analysis.dependency) or recommended
        logger.info("[remediation] OpenAI response parsed version=%s", new_version)

        if analysis.ecosystem == "npm":
            old_version = self._apply_npm_fix(repo_dir, analysis.dependency, new_version)
            # Re-install to update lockfile/node_modules.
            await self._run_cmd(["npm", "install"], cwd=repo_dir)
            notes = "Updated package.json dependencies"
        elif analysis.ecosystem == "python":
            old_version = self._apply_requirements_fix(repo_dir, analysis.dependency, new_version)
            notes = "Updated requirements.txt"
        else:
            raise ValueError(f"Unsupported ecosystem: {analysis.ecosystem}")

        return RemediationResult(
            dependency=analysis.dependency,
            old_version=old_version,
            new_version=new_version,
            llm_used=True,
            llm_raw=llm_raw,
            notes=notes,
        )

    def _apply_npm_fix(self, repo_dir: Path, dependency: str, new_version: str) -> str:
        package_json_path = repo_dir / "package.json"
        package_lock_path = repo_dir / "package-lock.json"
        if not package_json_path.exists():
            raise FileNotFoundError(f"package.json not found at {package_json_path}")

        pkg = json.loads(package_json_path.read_text(encoding="utf-8"))
        deps = pkg.get("dependencies") or {}
        old_version = deps.get(dependency) or ""
        deps[dependency] = new_version
        pkg["dependencies"] = deps

        # Preserve formatting (indent=2); keep trailing newline.
        package_json_path.write_text(json.dumps(pkg, indent=2) + "\n", encoding="utf-8")
        logger.info("[remediation] updated package.json: %s=%s", dependency, new_version)

        # Remove lockfile so npm can regenerate cleanly for demo.
        if package_lock_path.exists():
            package_lock_path.unlink()

        return old_version

    def _apply_requirements_fix(self, repo_dir: Path, dependency: str, new_spec: str) -> str:
        req = repo_dir / "requirements.txt"
        if not req.exists():
            raise FileNotFoundError(f"requirements.txt not found at {req}")

        lines = req.read_text(encoding="utf-8").splitlines(keepends=False)
        old = ""
        out: list[str] = []
        matched = False

        # For MVP we only handle simple pinned specs like:
        #   requests==2.19.0
        #   requests>=2.19.0
        # and we preserve comments/blank lines.
        dep_re = re.compile(rf"^\s*{re.escape(dependency)}\s*(?P<spec>(==|>=|<=|~=|!=|>|<).*)?\s*(#.*)?$")
        for line in lines:
            m = dep_re.match(line)
            if not m:
                out.append(line)
                continue

            matched = True
            old = (dependency + (m.group("spec") or "")).strip()

            # Normalize new_spec: allow bare version "2.31.0" from LLM, convert to ==
            spec = new_spec.strip()
            if re.fullmatch(r"\d+\.\d+(\.\d+)?", spec):
                spec = f"=={spec}"
            # If LLM gave caret-style (npm-ish), strip leading ^ and pin.
            if spec.startswith("^") and re.fullmatch(r"\^\d+\.\d+\.\d+", spec):
                spec = f"=={spec[1:]}"

            out.append(f"{dependency}{spec}")

        if not matched:
            # Append at end
            spec = new_spec.strip()
            if re.fullmatch(r"\d+\.\d+(\.\d+)?", spec):
                spec = f"=={spec}"
            if spec.startswith("^") and re.fullmatch(r"\^\d+\.\d+\.\d+", spec):
                spec = f"=={spec[1:]}"
            out.append(f"{dependency}{spec}")

        req.write_text("\n".join(out) + "\n", encoding="utf-8")
        logger.info("[remediation] updated requirements.txt: %s=%s", dependency, new_spec)
        return old

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
