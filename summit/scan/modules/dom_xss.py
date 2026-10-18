"""DOM-based XSS detection (CWE-79) - static source->sink analysis.

A reflected-payload check cannot see `location.hash` flowing into
`innerHTML`: the payload never leaves the browser. This module parses
the page's own scripts, finds DOM sources (location, referrer, postMessage)
and DOM sinks (innerHTML, document.write, eval), and reports when both
live in the same script block. Static analysis cannot prove exploitability,
so the finding is `needs-manual` severity-capped on purpose - it tells a
human where to look, it does not claim working XSS.
"""

from __future__ import annotations

import re

from ...http.models import HttpResponse
from ...scan.core import Finding

_SOURCES = {
    "location.hash": re.compile(r"location\s*\.\s*hash", re.IGNORECASE),
    "location.search": re.compile(r"location\s*\.\s*search", re.IGNORECASE),
    "location.href": re.compile(r"location\s*\.\s*href", re.IGNORECASE),
    "document.URL": re.compile(r"document\s*\.\s*(?:URL|documentURI)", re.IGNORECASE),
    "document.referrer": re.compile(r"document\s*\.\s*referrer", re.IGNORECASE),
    "window.name": re.compile(r"window\s*\.\s*name", re.IGNORECASE),
    "postMessage": re.compile(r"addEventListener\s*\(\s*['\"]message['\"]|onmessage\s*=|postMessage", re.IGNORECASE),
    "URLSearchParams": re.compile(r"URLSearchParams", re.IGNORECASE),
}

_SINKS = {
    "innerHTML": re.compile(r"\.innerHTML\s*=", re.IGNORECASE),
    "outerHTML": re.compile(r"\.outerHTML\s*=", re.IGNORECASE),
    "document.write": re.compile(r"document\s*\.\s*write\s*\(", re.IGNORECASE),
    "insertAdjacentHTML": re.compile(r"insertAdjacentHTML\s*\(", re.IGNORECASE),
    "dangerouslySetInnerHTML": re.compile(r"dangerouslySetInnerHTML", re.IGNORECASE),
    ".html()": re.compile(r"\.html\s*\(", re.IGNORECASE),
    "eval": re.compile(r"\beval\s*\(", re.IGNORECASE),
    "new Function": re.compile(r"new\s+Function\s*\(", re.IGNORECASE),
    "setTimeout(string)": re.compile(r"setTimeout\s*\(\s*['\"`]", re.IGNORECASE),
}

_SCRIPT_BLOCK = re.compile(r"<script\b[^>]*>(.*?)</script>", re.DOTALL | re.IGNORECASE)


def _script_blocks(text: str, url: str) -> list[str]:
    if url.split("?", 1)[0].lower().endswith(".js"):
        return [text]
    return _SCRIPT_BLOCK.findall(text)


def find_dom_flows(html: str, url: str = "") -> list[str]:
    """Return ['location.hash -> innerHTML', ...] pairs found in one block."""
    flows: set[str] = set()
    for block in _script_blocks(html, url):
        if len(block) < 10:
            continue
        found_sinks = [name for name, pattern in _SINKS.items() if pattern.search(block)]
        if not found_sinks:
            continue
        for source_name, source_pattern in _SOURCES.items():
            if source_pattern.search(block):
                for sink_name in found_sinks:
                    flows.add(f"{source_name} → {sink_name}")
    return sorted(flows)


def check_dom_xss(response: HttpResponse) -> list[Finding]:
    content_type = (response.header("content-type") or "").lower()
    is_javascript = response.request.url.split("?", 1)[0].lower().endswith(".js") or "javascript" in content_type
    if not is_javascript and "html" not in content_type:
        return []
    flows = find_dom_flows(response.text[:300_000], response.request.url)
    if not flows:
        return []
    listing = "; ".join(flows[:6])
    return [
        Finding(
            check_id="dom-xss",
            title=f"DOM XSS candidate: {flows[0]}",
            severity="medium",
            url=response.request.url,
            confidence="needs-manual",
            detail=(
                f"Static analysis found DOM source-to-sink flow(s) in this page's scripts: {listing}. "
                "A script reads attacker-controllable input (URL fragment, query, referrer, postMessage) "
                "and writes it into an HTML/script sink. Whether it is exploitable depends on runtime "
                "sanitization - verify manually in a browser before reporting."
            ),
            evidence=f"source→sink: {listing}",
            remediation=(
                "Use textContent instead of innerHTML, sanitize with a vetted library (DOMPurify), "
                "and avoid eval/document.write with untrusted input."
            ),
        )
    ]
