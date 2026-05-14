import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List

from agents.analysis_agent import AnalysisResult
from agents.scanner_agent import ScannerAgent

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    passed: bool
    details: str


class ValidationAgent:
    def __init__(self, scanner: ScannerAgent) -> None:
        self.scanner = scanner

    async def validate(self, repo_path: str, expected_fixed: List[AnalysisResult]) -> ValidationResult:
        repo_dir = Path(repo_path)
        package_json = repo_dir / "package.json"
        if not package_json.exists():
            return ValidationResult(passed=False, details="package.json missing after remediation")

        # Run scanner again.
        findings = await self.scanner.scan(repo_path)
        expected_names = {a.dependency for a in expected_fixed}
        remaining = [f for f in findings if f.package in expected_names]

        if remaining:
            detail_lines = [f"{f.package}: {f.severity} {f.overview}" for f in remaining]
            return ValidationResult(passed=False, details="Vulnerabilities still present: " + "; ".join(detail_lines))

        return ValidationResult(passed=True, details="npm audit no longer reports the targeted vulnerabilities")
