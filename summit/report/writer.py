"""Report writers - console, JSON, HTML.

One sort order, three renderings. The console writer is the human
face of every scan: severity-grouped, colour-coded, and honest about
confidence. The HTML writer is a self-contained dark-theme document
with severity filters - no external assets, safe to email or attach
to a ticket. JSON keeps the machine schema `diff.py` and CI depend on.
"""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime, timezone

from .. import __version__, colors
from ..scan.core import CWE_BY_CHECK_ID, IMPACT_BY_CHECK_ID

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Chip colours for the HTML report (dark theme).
SEVERITY_COLORS = {
    "critical": "#f87171",
    "high": "#fb923c",
    "medium": "#f472b6",
    "low": "#4ade80",
    "info": "#22d3ee",
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


# ---------------------------------------------------------------------------
# console
# ---------------------------------------------------------------------------


def write_console(findings, target: str) -> str:
    counts = Counter(f.severity for f in findings)
    sorted_findings = sort_findings(findings)

    lines: list[str] = [""]
    lines.append(colors.header(f"Summit report · {target}", width=70))
    lines.append("")
    lines.append(f"  {colors.bold('Total findings:')} {len(findings)}")
    if counts:
        block, _, legend = colors.summary_bar(counts).partition("\n")
        lines.append(f"  {block}")
        lines.append(f"  {legend}")
    lines.append("")

    if not sorted_findings:
        lines.append("  " + colors.ok("No findings - the target looks clean for the checks that ran."))
        lines.append("")
        return "\n".join(lines)

    current_severity = None
    for finding in sorted_findings:
        if finding.severity != current_severity:
            current_severity = finding.severity
            lines.append("")
            lines.append(f"  {colors.severity_badge(current_severity)}")
            lines.append("")
        cwe = finding.cwe or CWE_BY_CHECK_ID.get(finding.check_id, "")
        meta_bits = [colors.check_tag(finding.check_id), colors.confidence_tag(finding.confidence)]
        if cwe:
            meta_bits.append(colors.gray(cwe))
        if finding.cves:
            meta_bits.append(colors.gray(", ".join(finding.cves)))
        lines.append(f"    {colors.bold(finding.title)}")
        lines.append(f"      {'  ·  '.join(meta_bits)}")
        location = finding.url + (f"  param: {finding.param}" if finding.param else "")
        lines.append(f"      {colors.gray('URL:')} {colors.url_text(location)}")
        if finding.detail:
            lines.append(f"      {colors.gray('Detail:')} {finding.detail}")
        if finding.evidence:
            lines.append(f"      {colors.gray('Evidence:')} {colors.evidence_text(finding.evidence)}")
        impact = finding.impact or IMPACT_BY_CHECK_ID.get(finding.check_id, "")
        if impact:
            lines.append(f"      {colors.gray('Impact:')} {impact}")
        if finding.remediation:
            lines.append(f"      {colors.gray('Fix:')} {finding.remediation}")
        lines.append("")

    lines.append(colors.rule(70))
    lines.append(f"  {colors.gray('Only use Summit on systems you are authorized to test.')}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

_HTML_CSS = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin: 0; background: #070b14; color: #e2e8f0;
  font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; }
.wrap { max-width: 1080px; margin: 0 auto; padding: 40px 24px 80px; }
.brand { font-weight: 800; letter-spacing: .18em; font-size: .85rem;
  background: linear-gradient(90deg, #22d3ee, #a78bfa, #f472b6);
  -webkit-background-clip: text; background-clip: text; color: transparent; }
h1 { font-size: 1.35rem; margin: .35rem 0 .25rem; font-weight: 650; }
.sub { color: #94a3b8; font-size: .85rem; margin: 0 0 24px; }
.sub code { color: #cbd5e1; }
.cards { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 22px; }
.card { background: #0f172a; border: 1px solid #1e293b; border-radius: 10px;
  padding: 10px 16px; min-width: 92px; }
.card .n { font-size: 1.3rem; font-weight: 700; }
.card .l { font-size: .7rem; letter-spacing: .08em; color: #94a3b8; text-transform: uppercase; }
.bar { display: flex; gap: 6px; margin: 0 0 22px; flex-wrap: wrap; }
.fbtn, #q { background: #0f172a; color: #cbd5e1; border: 1px solid #1e293b;
  border-radius: 8px; padding: 7px 14px; font-size: .8rem; cursor: pointer; }
.fbtn:hover { border-color: #334155; }
.fbtn.on { border-color: #22d3ee; color: #22d3ee; }
#q { cursor: text; min-width: 220px; }
table { border-collapse: collapse; width: 100%; }
th { text-align: left; font-size: .7rem; letter-spacing: .08em; color: #94a3b8;
  text-transform: uppercase; padding: 8px 10px; border-bottom: 1px solid #1e293b; }
td { padding: 10px; border-bottom: 1px solid #131c30; vertical-align: top; font-size: .85rem; }
.chip { display: inline-block; padding: 2px 9px; border-radius: 999px;
  font-size: .68rem; font-weight: 700; letter-spacing: .05em; color: #070b14; }
.chip-critical { background: #f87171; } .chip-high { background: #fb923c; }
.chip-medium { background: #f472b6; } .chip-low { background: #4ade80; }
.chip-info { background: #22d3ee; }
details summary { cursor: pointer; font-weight: 600; color: #f1f5f9; }
details summary::marker { color: #22d3ee; }
.kv { margin: 10px 0 4px; color: #cbd5e1; }
.kv p { margin: 6px 0; }
.k { display: inline-block; min-width: 92px; color: #64748b;
  font-size: .7rem; letter-spacing: .06em; text-transform: uppercase; }
.kv code { background: #0f172a; border: 1px solid #1e293b; border-radius: 6px;
  padding: 2px 6px; color: #fbd38d; word-break: break-all; }
.kv pre { background: #0f172a; border: 1px solid #1e293b; border-radius: 8px;
  padding: 10px; overflow-x: auto; white-space: pre-wrap; word-break: break-all;
  color: #cbd5e1; font-size: .78rem; }
.url { font-family: ui-monospace, Consolas, monospace; font-size: .76rem;
  color: #7dd3fc; word-break: break-all; }
.meta { font-family: ui-monospace, Consolas, monospace; font-size: .72rem; color: #94a3b8; }
.conf { color: #a78bfa; }
.empty { background: #0f172a; border: 1px dashed #334155; border-radius: 12px;
  padding: 28px; text-align: center; color: #94a3b8; }
footer { margin-top: 40px; color: #475569; font-size: .75rem; }
"""

_HTML_JS = """
const state = { sev: 'all', q: '' };
function apply() {
  document.querySelectorAll('tbody tr').forEach((tr) => {
    const sevOk = state.sev === 'all' || tr.dataset.sev === state.sev;
    const textOk = !state.q || tr.textContent.toLowerCase().includes(state.q);
    tr.style.display = sevOk && textOk ? '' : 'none';
  });
  document.querySelectorAll('.fbtn').forEach((b) => b.classList.toggle('on', b.dataset.sev === state.sev));
}
document.querySelectorAll('.fbtn').forEach((b) => b.addEventListener('click', () => { state.sev = b.dataset.sev; apply(); }));
const q = document.getElementById('q');
if (q) { q.addEventListener('input', (e) => { state.q = e.target.value.toLowerCase(); apply(); }); }
"""


def _html_details(finding) -> str:
    blocks: list[str] = []
    if finding.detail:
        blocks.append(f"<p><span class='k'>Detail</span>{html.escape(finding.detail)}</p>")
    if finding.evidence:
        blocks.append(f"<p><span class='k'>Evidence</span><code>{html.escape(finding.evidence)}</code></p>")
    impact = finding.impact or IMPACT_BY_CHECK_ID.get(finding.check_id, "")
    if impact:
        blocks.append(f"<p><span class='k'>Impact</span>{html.escape(impact)}</p>")
    if finding.remediation:
        blocks.append(f"<p><span class='k'>Remediation</span>{html.escape(finding.remediation)}</p>")
    poc = getattr(finding, "poc", "")
    if poc:
        blocks.append(f"<p><span class='k'>PoC</span></p><pre>{html.escape(poc)}</pre>")
    steps = getattr(finding, "verification_steps", "")
    if steps:
        blocks.append(f"<p><span class='k'>Verify</span>{html.escape(steps)}</p>")
    return "".join(blocks) or "<p class='k'>No extra detail captured.</p>"


def write_html(findings, path: str, target: str) -> str:
    counts = Counter(f.severity for f in findings)
    sorted_findings = sort_findings(findings)

    rows: list[str] = []
    for finding in sorted_findings:
        cwe = finding.cwe or CWE_BY_CHECK_ID.get(finding.check_id, "")
        location = finding.url + (f"  param: {finding.param}" if finding.param else "")
        meta = html.escape(finding.check_id)
        if cwe:
            meta += f"<br>{html.escape(cwe)}"
        if finding.cves:
            meta += f"<br>{html.escape(', '.join(finding.cves))}"
        rows.append(
            f"<tr data-sev=\"{html.escape(finding.severity)}\">"
            f"<td><span class='chip chip-{html.escape(finding.severity)}'>{html.escape(finding.severity.upper())}</span></td>"
            "<td><details>"
            f"<summary>{html.escape(finding.title)}</summary>"
            f"<div class='kv'>{_html_details(finding)}</div>"
            "</details></td>"
            f"<td class='url'>{html.escape(location)}</td>"
            f"<td class='meta'>{meta}<br><span class='conf'>{html.escape(finding.confidence)}</span></td>"
            "</tr>"
        )

    cards = "".join(
        f"<div class='card'><div class='n' style='color:{SEVERITY_COLORS[severity]}'>{counts.get(severity, 0)}</div>"
        f"<div class='l'>{severity}</div></div>"
        for severity in ("critical", "high", "medium", "low", "info")
    )
    buttons = "<button class='fbtn on' data-sev='all'>All</button>" + "".join(
        f"<button class='fbtn' data-sev='{severity}'>{severity.capitalize()} {counts.get(severity, 0)}</button>"
        for severity in ("critical", "high", "medium", "low", "info")
    )

    if rows:
        table = (
            "<table><thead><tr><th>Severity</th><th>Finding</th><th>URL</th><th>Check</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )
    else:
        table = "<div class='empty'>No findings - the target looks clean for the checks that ran.</div>"

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Summit report - {html.escape(target)}</title>
<style>{_HTML_CSS}</style>
</head>
<body>
<div class="wrap">
  <div class="brand">SUMMIT · PENNACLE SECURITY</div>
  <h1>Web security scan report</h1>
  <p class="sub">Target: <code>{html.escape(target)}</code> · Generated: {generated} · Findings: {len(findings)}</p>
  <div class="cards">{cards}</div>
  <div class="bar">{buttons}<input id="q" type="search" placeholder="filter by text, URL, check..."></div>
  {table}
  <footer>Only use Summit on systems you are authorized to test. Generated by summit {html.escape(__version__)}.</footer>
</div>
<script>{_HTML_JS}</script>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(document)
    return path
