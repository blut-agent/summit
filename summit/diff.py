"""Scan diffing - compare two scan reports to find new, resolved, and regressed findings.

`summit diff <old.json> <new.json>` classifies findings using the
existing dedup key (check_id, normalized url). Useful for CI gating
with `--fail-on new` so a pipeline doesn't re-fail on known findings.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .normalize import normalize_url


@dataclass
class DiffResult:
    new: list[dict]
    resolved: list[dict]
    unchanged: list[dict]
    regressed: list[dict]  # same finding, worse severity


def _finding_key(finding: dict) -> tuple:
    url = normalize_url(finding.get("url", ""))
    return (finding.get("check_id", ""), url, finding.get("param", ""))


_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def diff_reports(old_path: str, new_path: str) -> DiffResult:
    with open(old_path, encoding="utf-8") as fh:
        old_findings = json.load(fh).get("findings", [])
    with open(new_path, encoding="utf-8") as fh:
        new_findings = json.load(fh).get("findings", [])

    old_map = {_finding_key(f): f for f in old_findings}
    new_map = {_finding_key(f): f for f in new_findings}

    result = DiffResult(new=[], resolved=[], unchanged=[], regressed=[])

    for key, new_finding in new_map.items():
        if key not in old_map:
            result.new.append(new_finding)
        else:
            old_finding = old_map[key]
            old_sev = _SEVERITY_ORDER.get(old_finding.get("severity", "info"), 0)
            new_sev = _SEVERITY_ORDER.get(new_finding.get("severity", "info"), 0)
            if new_sev > old_sev:
                result.regressed.append(new_finding)
            else:
                result.unchanged.append(new_finding)

    for key, old_finding in old_map.items():
        if key not in new_map:
            result.resolved.append(old_finding)

    return result


def render_diff(result: DiffResult) -> str:
    lines = []
    if result.new:
        lines.append(f"\nNEW findings ({len(result.new)}):")
        for f in result.new:
            lines.append(f"  [{f.get('severity', '?').upper()}] {f.get('title', '?')} - {f.get('url', '?')}")
    if result.resolved:
        lines.append(f"\nRESOLVED findings ({len(result.resolved)}):")
        for f in result.resolved:
            lines.append(f"  {f.get('title', '?')} - {f.get('url', '?')}")
    if result.regressed:
        lines.append(f"\nREGRESSED findings ({len(result.regressed)}):")
        for f in result.regressed:
            lines.append(f"  [{f.get('severity', '?').upper()}] {f.get('title', '?')} - {f.get('url', '?')}")
    if not result.new and not result.resolved and not result.regressed:
        lines.append("\nNo changes between scans.")
    lines.append(f"\nSummary: {len(result.new)} new, {len(result.resolved)} resolved, "
                 f"{len(result.regressed)} regressed, {len(result.unchanged)} unchanged")
    return "\n".join(lines)
