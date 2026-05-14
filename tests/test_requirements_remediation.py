from pathlib import Path

from agents.remediation_agent import RemediationAgent


def test_apply_requirements_fix_replaces_existing_line(tmp_path: Path):
    repo = tmp_path
    (repo / "requirements.txt").write_text("requests==2.19.0\nflask==2.0.0\n", encoding="utf-8")

    agent = RemediationAgent()
    old = agent._apply_requirements_fix(repo, "requests", "==2.31.0")

    assert "requests==2.31.0" in (repo / "requirements.txt").read_text(encoding="utf-8")
    assert old.startswith("requests")


def test_apply_requirements_fix_appends_when_missing(tmp_path: Path):
    repo = tmp_path
    (repo / "requirements.txt").write_text("flask==2.0.0\n", encoding="utf-8")

    agent = RemediationAgent()
    old = agent._apply_requirements_fix(repo, "requests", "2.31.0")

    txt = (repo / "requirements.txt").read_text(encoding="utf-8")
    assert "requests==2.31.0" in txt
    assert old == ""
