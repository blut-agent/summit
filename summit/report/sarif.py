"""SARIF and JUnit XML report output.

SARIF feeds GitHub code scanning and any SARIF-compatible dashboard.
JUnit XML feeds CI/CD test reporting pipelines. Both are machine-readable
formats that make summit findings visible wherever your team already looks.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from ..scan.core import Finding

_SARIF_SEVERITY = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_JUNIT_SEVERITY = {"critical": "error", "high": "error", "medium": "warning", "low": "info", "info": "info"}


def write_sarif(findings: list[Finding], path: str, tool_name: str = "summit") -> str:
    """Write findings as a SARIF 2.1.0 report."""
    results = []
    rules = []
    rule_ids = sorted({f.check_id for f in findings})
    for rule_id in rule_ids:
        sample = next(f for f in findings if f.check_id == rule_id)
        rules.append({
            "id": rule_id,
            "name": sample.title,
            "shortDescription": {"text": sample.title},
            "fullDescription": {"text": sample.detail or sample.title},
            "help": {"text": sample.remediation or "See the summit documentation."},
            "properties": {
                "security-severity": _security_severity_score(sample.severity),
                "tags": [sample.severity, sample.confidence] + ([sample.cwe] if sample.cwe else []),
            },
        })
    for finding in findings:
        results.append({
            "ruleId": finding.check_id,
            "level": _SARIF_SEVERITY.get(finding.severity, "note"),
            "message": {"text": f"{finding.title}. {finding.detail} Evidence: {finding.evidence}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.url},
                },
                "properties": {
                    "param": finding.param,
                    "confidence": finding.confidence,
                    "cwe": finding.cwe,
                    "cves": finding.cves,
                },
            }],
        })
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "informationUri": "https://github.com/pennacle-security/summit",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)
    return path


def write_junit(findings: list[Finding], path: str, tool_name: str = "summit") -> str:
    """Write findings as a JUnit XML report (each finding = one test case)."""
    from xml.sax.saxutils import escape

    total = len(findings)
    errors = sum(1 for f in findings if f.severity in ("critical", "high"))
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuites name="{tool_name}" tests="{total}" failures="0" errors="{errors}">',
        f'<testsuite name="{tool_name} findings" tests="{total}" errors="{errors}" failures="0">',
    ]
    for finding in findings:
        status = _JUNIT_SEVERITY.get(finding.severity, "info")
        name = f"{finding.title} [{finding.severity}]"
        classname = finding.url
        if status == "error":
            lines.append(f'  <testcase name="{escape(name)}" classname="{escape(classname)}">')
            lines.append(f'    <error message="{escape(finding.title)}" type="{finding.severity}">')
            lines.append(f"      {escape(finding.detail)}")
            lines.append(f"      Evidence: {escape(finding.evidence)}")
            if finding.cwe:
                lines.append(f"      CWE: {escape(finding.cwe)}")
            lines.append("    </error>")
            lines.append("  </testcase>")
        else:
            lines.append(f'  <testcase name="{escape(name)}" classname="{escape(classname)}" status="{status}"/>')
    lines.append("</testsuite>")
    lines.append("</testsuites>")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


def _security_severity_score(severity: str) -> str:
    """CVSS-like score string for SARIF security-severity property."""
    return {"critical": "9.0", "high": "7.0", "medium": "5.0", "low": "3.0", "info": "1.0"}.get(severity, "0.0")
