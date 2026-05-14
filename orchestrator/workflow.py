import json
import logging
import os
import shutil
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from agents.analysis_agent import AnalysisAgent, AnalysisResult
from agents.pr_agent import PRAgent
from agents.remediation_agent import RemediationAgent, RemediationResult
from agents.scanner_agent import ScannerAgent, VulnerabilityFinding
from agents.validation_agent import ValidationAgent, ValidationResult

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parents[1]
SANDBOX_DIR = BASE_DIR / "sandbox" / "repo_clones"
RESULTS_DIR = BASE_DIR / "results"


@dataclass
class WorkflowResult:
    repo_url: str
    commit_sha: str
    cloned_path: str
    vulnerabilities: List[Dict[str, Any]]
    analysis: List[Dict[str, Any]]
    remediation: List[Dict[str, Any]]
    validation: Dict[str, Any]
    report_path: str
    pr: Optional[Dict[str, Any]] = None


async def run_workflow(repo_url: str, commit_sha: str) -> Dict[str, Any]:
    """End-to-end MVP workflow.

    Contract:
    - Inputs: repo_url, commit_sha
    - Output: serializable dict with results and report path
    """

    SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    workflow_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    work_dir = SANDBOX_DIR / f"{workflow_id}"

    if work_dir.exists():
        shutil.rmtree(work_dir)

    scanner = ScannerAgent()
    analysis_agent = AnalysisAgent()
    remediation_agent = RemediationAgent()
    validation_agent = ValidationAgent(scanner=scanner)

    logger.info("[workflow] starting id=%s repo=%s commit=%s", workflow_id, repo_url, commit_sha)
    logger.info("[workflow] cloning into %s", work_dir)
    local_repo_path = await scanner.clone_repo(repo_url=repo_url, dest_dir=str(work_dir))
    logger.info("[workflow] clone complete path=%s", local_repo_path)

    logger.info("[workflow] scanning dependencies (npm + python)")
    findings: List[VulnerabilityFinding] = await scanner.scan(local_repo_path)
    if not findings:
        report_path = _write_report(
            workflow_id=workflow_id,
            report={
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "repo_url": repo_url,
                "commit_sha": commit_sha,
                "status": "no_vulnerabilities",
            },
        )
        return asdict(
            WorkflowResult(
                repo_url=repo_url,
                commit_sha=commit_sha,
                cloned_path=local_repo_path,
                vulnerabilities=[],
                analysis=[],
                remediation=[],
                validation={"passed": True, "details": "No vulnerabilities detected"},
                report_path=report_path,
            )
        )

    logger.info("[workflow] analyzing %d finding(s)", len(findings))
    analyses: List[AnalysisResult] = [analysis_agent.analyze(f) for f in findings]

    remediation_results: List[RemediationResult] = []
    last_validation: Optional[ValidationResult] = None

    # Self-correction loop (max 3 total attempts: initial + 2 retries)
    for attempt in range(1, 4):
        logger.info("[workflow] remediation attempt %s/3", attempt)

        remediation_results = []
        for ar in analyses:
            logger.info("[workflow] remediating dependency=%s recommended=%s", ar.dependency, ar.recommended_version)
            rr = await remediation_agent.remediate(
                local_repo_path,
                ar,
                validation_feedback=(last_validation.details if last_validation else None),
            )
            remediation_results.append(rr)
            logger.info("[workflow] remediation applied %s: %s -> %s (llm_used=%s)", rr.dependency, rr.old_version, rr.new_version, rr.llm_used)

        logger.info("[workflow] validating remediation via dependency rescans")
        last_validation = await validation_agent.validate(local_repo_path, expected_fixed=analyses)
        logger.info("[workflow] validation passed=%s", last_validation.passed)
        if last_validation.passed:
            break

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repo_url": repo_url,
        "commit_sha": commit_sha,
        "vulnerabilities": [asdict(f) for f in findings],
        "analysis": [asdict(a) for a in analyses],
        "remediation": [asdict(r) for r in remediation_results],
        "validation": asdict(last_validation) if last_validation else {"passed": False, "details": "No validation run"},
    }

    report_path = _write_report(workflow_id=workflow_id, report=report)

    pr_info: Optional[Dict[str, Any]] = None
    if os.getenv("GITHUB_TOKEN") and last_validation and last_validation.passed:
        pr_agent = PRAgent()
        logger.info("[workflow] creating PR for branch=%s", f"security-fix/{workflow_id}")
        pr_info = await pr_agent.create_pr_if_possible(
            local_repo_path=local_repo_path,
            repo_url=repo_url,
            base_branch=os.getenv("GITHUB_BASE_BRANCH", "main"),
            branch_name=f"security-fix/{workflow_id}",
            title="Automated Security Fix: dependency vulnerability remediation",
            body=f"Automated remediation report: {Path(report_path).name}",
        )
        if pr_info and pr_info.get("html_url"):
            logger.info("[workflow] PR ready: %s", pr_info.get("html_url"))
    elif os.getenv("GITHUB_TOKEN"):
        logger.info("[workflow] skipping PR creation (validation did not pass)")

    return asdict(
        WorkflowResult(
            repo_url=repo_url,
            commit_sha=commit_sha,
            cloned_path=local_repo_path,
            vulnerabilities=[asdict(f) for f in findings],
            analysis=[asdict(a) for a in analyses],
            remediation=[asdict(r) for r in remediation_results],
            validation=asdict(last_validation) if last_validation else {"passed": False, "details": "No validation"},
            report_path=report_path,
            pr=pr_info,
        )
    )


def _write_report(workflow_id: str, report: Dict[str, Any]) -> str:
    out = RESULTS_DIR / f"report_{workflow_id}.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=False), encoding="utf-8")
    logger.info("Wrote report to %s", out)
    return str(out)
