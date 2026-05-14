import re
from dataclasses import dataclass
from typing import Optional

from agents.scanner_agent import VulnerabilityFinding


@dataclass
class AnalysisResult:
    dependency: str
    issue_type: str
    severity: str
    current_version: str
    recommended_version: str
    explanation: str
    fix_strategy: str
    cve: str = ""
    cwe: str = ""
    vulnerable_range: str = ""
    patched_versions: str = ""


class AnalysisAgent:
    """Normalize scanner findings into remediation-friendly analysis."""

    def analyze(self, finding: VulnerabilityFinding) -> AnalysisResult:
        issue_type = self._infer_issue_type(finding.overview)
        recommended_version = self._infer_recommended_version(finding.patched_version)

        explanation = (
            f"Dependency '{finding.package}' is vulnerable ({finding.severity}). "
            f"Details: {finding.overview}. "
            f"Recommended action: {finding.recommendation}."
        ).strip()

        return AnalysisResult(
            dependency=finding.package,
            issue_type=issue_type,
            severity=finding.severity.upper(),
            current_version=finding.vulnerable_version,
            recommended_version=recommended_version,
            explanation=explanation,
            fix_strategy="Upgrade dependency version",
            cve=finding.cve,
            vulnerable_range=finding.vulnerable_version,
            patched_versions=finding.patched_version,
        )

    def _infer_issue_type(self, overview: str) -> str:
        text = (overview or "").lower()
        if "ssrf" in text:
            return "SSRF Vulnerability"
        if "prototype pollution" in text:
            return "Prototype Pollution"
        if "xss" in text or "cross-site scripting" in text:
            return "XSS Vulnerability"
        if "csrf" in text:
            return "CSRF Vulnerability"
        return "Dependency Vulnerability"

    def _infer_recommended_version(self, patched_versions: str) -> str:
        # patched_versions often like ">=1.6.0"; convert to caret for demo friendliness.
        match = re.search(r"(\d+\.\d+\.\d+)", patched_versions or "")
        if match:
            return f"^{match.group(1)}"
        # fallback
        return "latest"
