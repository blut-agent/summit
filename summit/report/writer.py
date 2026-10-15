from __future__ import annotations

import html
import json
from datetime import datetime, timezone

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLORS = {
    "critical": "#7f1d1d",
    "high": "#b91c1c",
    "medium": "#b45309",
    "low": "#4d7c0f",
    "info": "#374151",
}


def sort_findings(findings):
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.url))


def write_json(findings, path: str) -> str:
    payload = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "total": len(findings),
        "findings": [f.as_dict() for f in sort_findings(findings)],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return path


def write_console(findings, target: str) -> str:
    lines = ["", f"Summit report - {target}", "=" * 60, f"Total findings: {len(findings)}", ""]
    current_severity = None
    for finding in sort_findings(findings):
        if finding.severity != current_severity:
            current_severity = finding.severity
            lines.append(f"[{current_severity.upper()}]")
        lines.append(f"  {finding.title}  ({finding.check_id})")
        location = finding.url + (f"  param: {finding.param}" if finding.param else "")
        lines.append(f"    URL: {location}")
        if finding.evidence:
            lines.append(f"    Evidence: {finding.evidence[:200]}")
        lines.append("")
    return "\n".join(lines)


def write_html(findings, path: str, target: str) -> str:
    rows = []
    for finding in sort_findings(findings):
        color = SEVERITY_COLORS.get(finding.severity, "#374151")
        rows.append(
            "<tr>"
            f"<td><span class='sev' style='background:{color}'>{html.escape(finding.severity.upper())}</span></td>"
            f"<td>{html.escape(finding.title)}</td>"
            f"<td class='url'>{html.escape(finding.url)}</td>"
            f"<td>{html.escape(finding.check_id)}</td>"
            "</tr>"
        )
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    document = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Summit Report - {html.escape(target)}</title>
<style>
body {{ font-family: -apple-system, 'Segoe UI', sans-serif; margin: 2rem; color: #111; }}
h1 {{ font-size: 1.4rem; }}
table {{ border-collapse: collapse; width: 100%; }}
td, th {{ border-bottom: 1px solid #e5e7eb; padding: 8px 10px; text-align: left; font-size: 0.9rem; }}
.url {{ font-family: monospace; font-size: 0.8rem; word-break: break-all; }}
.sev {{ color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
</style>
</head>
<body>
<h1>Summit scan report</h1>
<p>Target: {html.escape(target)} &middot; Generated: {generated} &middot; Findings: {len(findings)}</p>
<table>
<tr><th>Severity</th><th>Finding</th><th>URL</th><th>Check</th></tr>
{''.join(rows)}
</table>
<p style="color:#6b7280;font-size:0.8rem">Only use Summit on systems you are authorized to test.</p>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(document)
    return path
