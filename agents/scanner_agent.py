import asyncio
import json
import logging
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from git import Repo

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityFinding:
    package: str
    severity: str
    vulnerable_version: str
    patched_version: str
    cve: str
    overview: str
    recommendation: str


class ScannerAgent:
    """Detect vulnerabilities using npm audit.

    No remediation logic should live here.
    """

    async def clone_repo(self, repo_url: str, dest_dir: str) -> str:
        """Clone repo into dest_dir fresh."""
        dest = Path(dest_dir)
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True, exist_ok=True)

        token = os.getenv("GITHUB_TOKEN")
        clone_url = repo_url
        if token and repo_url.startswith("https://") and "@" not in repo_url:
            # Inject token for private repo clone.
            clone_url = repo_url.replace("https://", f"https://{token}@", 1)

        logger.info("Cloning repo %s -> %s", repo_url, dest)
        await asyncio.to_thread(Repo.clone_from, clone_url, str(dest))
        return str(dest)

    async def scan(self, repo_path: str) -> List[VulnerabilityFinding]:
        repo_dir = Path(repo_path)
        package_json = repo_dir / "package.json"
        if not package_json.exists():
            logger.info("No package.json found at %s", package_json)
            return []

        # Install dependencies (use clean install where possible)
        await self._run_cmd(["npm", "install"], cwd=repo_dir)

        audit_json = await self._run_cmd(["npm", "audit", "--json"], cwd=repo_dir, allow_failure=True)
        findings = self._parse_npm_audit_json(audit_json)
        logger.info("Scanner found %d vulnerability finding(s)", len(findings))
        return findings

    async def _run_cmd(self, args: List[str], cwd: Path, allow_failure: bool = False) -> str:
        logger.info("Running command: %s (cwd=%s)", " ".join(args), cwd)
        proc = await asyncio.create_subprocess_exec(
            *args,
            cwd=str(cwd),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env={**os.environ, "npm_config_fund": "false", "npm_config_audit": "false"},
        )
        out_b, _ = await proc.communicate()
        out = out_b.decode("utf-8", errors="replace")
        if proc.returncode != 0 and not allow_failure:
            raise RuntimeError(f"Command failed ({proc.returncode}): {' '.join(args)}\n{out}")
        return out

    def _parse_npm_audit_json(self, audit_output: str) -> List[VulnerabilityFinding]:
        # npm audit --json prints JSON to stdout even if exit code != 0.
        # Unfortunately, some environments inject extra output (warnings, banners, etc).
        data = self._loads_first_json_object(audit_output)

        vulns: List[VulnerabilityFinding] = []

        # npm v6 style: advisories
        advisories = (data.get("advisories") or {})
        for _, adv in advisories.items():
            module = adv.get("module_name")
            severity = (adv.get("severity") or "unknown").lower()
            vulnerable_versions = adv.get("vulnerable_versions") or ""
            patched_versions = adv.get("patched_versions") or ""
            cves = adv.get("cves") or []
            cve = cves[0] if cves else (adv.get("cwe") or "")
            overview = adv.get("overview") or adv.get("title") or ""
            recommendation = adv.get("recommendation") or "Upgrade dependency"

            vulns.append(
                VulnerabilityFinding(
                    package=module or "",
                    severity=severity,
                    vulnerable_version=vulnerable_versions,
                    patched_version=patched_versions,
                    cve=cve or "",
                    overview=overview,
                    recommendation=recommendation,
                )
            )

        # npm v7+ style: vulnerabilities object
        vulnerabilities = data.get("vulnerabilities") or {}
        for pkg, v in vulnerabilities.items():
            if not isinstance(v, dict):
                continue
            severity = (v.get("severity") or "unknown").lower()

            # Derive "patched version" from fixAvailable when it contains a suggested version.
            # Example: {"name": "axios", "version": "1.6.0", "isSemVerMajor": true}
            patched_versions = ""
            fix_available = v.get("fixAvailable")
            if isinstance(fix_available, dict) and isinstance(fix_available.get("version"), str):
                patched_versions = f">={fix_available['version']}"
            elif fix_available is True:
                patched_versions = "available"

            via = v.get("via") or []
            # via can include strings and objects
            via_objs = [x for x in via if isinstance(x, dict)]
            if not via_objs:
                continue

            # Create one finding per (pkg) for the MVP: pick the first advisory object for overview/cve.
            via_obj = via_objs[0]
            title = via_obj.get("title") or ""
            url = via_obj.get("url") or ""
            cwe = ""
            if isinstance(via_obj.get("cwe"), list) and via_obj.get("cwe"):
                cwe = via_obj.get("cwe")[0]
            cves = via_obj.get("cves") or []
            cve = cves[0] if cves else cwe
            range_ = via_obj.get("range") or ""

            vulns.append(
                VulnerabilityFinding(
                    package=pkg,
                    severity=severity,
                    vulnerable_version=range_ or "",
                    patched_version=patched_versions,
                    cve=cve or "",
                    overview=(title + (f" ({url})" if url else "")).strip(),
                    recommendation="Upgrade dependency",
                )
            )

        # Deduplicate by package (prefer the one with a concrete patched_version like ">=x.y.z").
        seen = set()
        best_by_pkg: Dict[str, VulnerabilityFinding] = {}
        for f in vulns:
            if not f.package:
                continue
            curr = best_by_pkg.get(f.package)
            if curr is None:
                best_by_pkg[f.package] = f
                continue
            # Prefer entries that have a semver in patched_version.
            curr_has_ver = bool(re.search(r"\d+\.\d+\.\d+", curr.patched_version or ""))
            f_has_ver = bool(re.search(r"\d+\.\d+\.\d+", f.patched_version or ""))
            if f_has_ver and not curr_has_ver:
                best_by_pkg[f.package] = f
                continue
            # Prefer higher severity as a fallback.
            sev_rank = {"critical": 4, "high": 3, "moderate": 2, "low": 1, "unknown": 0}
            if sev_rank.get(f.severity, 0) > sev_rank.get(curr.severity, 0):
                best_by_pkg[f.package] = f

        uniq = list(best_by_pkg.values())
        # Stable order for reports
        uniq.sort(key=lambda x: (x.package, x.severity))
        return uniq

    def _loads_first_json_object(self, s: str) -> Dict[str, Any]:
        """Extract and parse the first top-level JSON object in a string.

        Handles "Extra data" by scanning for a balanced {...} region.
        """

        s = s.lstrip()
        # Fast path
        try:
            obj = json.loads(s)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass

        start = s.find("{")
        if start == -1:
            raise json.JSONDecodeError("No JSON object start found", s, 0)

        depth = 0
        in_str = False
        esc = False
        for i in range(start, len(s)):
            ch = s[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue

            if ch == '"':
                in_str = True
                continue

            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidate = s[start : i + 1]
                    obj = json.loads(candidate)
                    if not isinstance(obj, dict):
                        raise json.JSONDecodeError("Top-level JSON is not an object", candidate, 0)
                    return obj

        raise json.JSONDecodeError("Unterminated JSON object", s, start)
