import json

from agents.scanner_agent import ScannerAgent


def test_parse_pip_audit_json_extracts_findings():
    agent = ScannerAgent()

    sample = [
        {
            "name": "requests",
            "version": "2.19.0",
            "vulns": [
                {
                    "id": "PYSEC-2023-999",
                    "aliases": ["CVE-2023-1234"],
                    "description": "Some vulnerability",
                    "fix_versions": ["2.20.0"],
                }
            ],
        }
    ]

    findings = agent._parse_pip_audit_json(json.dumps(sample))
    assert len(findings) == 1
    f = findings[0]
    assert f.ecosystem == "python"
    assert f.package == "requests"
    assert f.vulnerable_version == "2.19.0"
    assert f.patched_version == ">=2.20.0"
    assert f.cve == "CVE-2023-1234"


def test_parse_pip_audit_json_handles_banner_noise():
    agent = ScannerAgent()

    sample = [
        {
            "name": "urllib3",
            "version": "1.25.0",
            "vulns": [
                {
                    "id": "PYSEC-0000-000",
                    "aliases": [],
                    "description": "desc",
                    "fix_versions": ["1.26.0"],
                }
            ],
        }
    ]

    noisy = "WARNING: something\n" + json.dumps(sample) + "\nmore text"
    findings = agent._parse_pip_audit_json(noisy)
    assert len(findings) == 1
    assert findings[0].package == "urllib3"
