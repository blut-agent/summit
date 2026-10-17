"""Adaptive probe prioritizer - the part of summit that decides *what to
try first*.

This is deliberately not called a neural network: it is a transparent
scoring model, and every weight is readable in this file. Points are
ordered so the highest-signal parameters are probed first, which means
the first meaningful findings appear early and a Ctrl+C mid-scan still
leaves you with the interesting half done.

Score:
    3 - the parameter name maps to a known injection family
        (id/user/page -> SQLi, q/search/message -> XSS, url/next ->
        redirect, file/path -> traversal)
    2 - the value itself is a strong signal (numeric, or URL-shaped)
    1 - everything else still gets probed, just later
"""

from __future__ import annotations

from .scan.core import InjectionPoint

_SIGNALS: dict[str, tuple[str, ...]] = {
    "sqli": ("id", "uid", "user", "userid", "page", "cat", "category", "item", "num", "count"),
    "xss": ("q", "query", "search", "name", "msg", "message", "comment", "email", "keyword", "term"),
    "redirect": ("url", "next", "redirect", "return", "goto", "link", "dest", "continue", "target"),
    "traversal": ("file", "path", "doc", "template", "include", "lang"),
    "nosql": ("json", "data", "filter", "where", "sort", "fields"),
    "cmd": ("cmd", "exec", "command", "host", "ip", "ping"),
    "ssti": ("template", "tpl", "render", "view"),
    "enumeration": ("email", "username", "login", "account"),
}

_TECH_BOOSTS: dict[str, dict[str, int]] = {
    "php": {"traversal": 2, "cmd": 1},
    "python": {"ssti": 2, "nosql": 1},
    "node": {"nosql": 2, "ssti": 1},
    "java": {"ssti": 2, "cmd": 1},
}


def score_point(point: InjectionPoint, detected_tech: str | None = None) -> int:
    name = point.param.lower()
    score = 1
    for hints in _SIGNALS.values():
        if name in hints or any(name.startswith(hint) for hint in hints if len(hint) >= 4):
            score = 3
            break
    value = point.original_value.strip()
    if value.isdigit() or value.startswith(("http://", "https://", "/", "//")):
        score = max(score, 2)
    # Tech-aware boost: if a specific backend was detected (from WAF/body
    # CVE detection), boost params relevant to that technology's common vulns.
    if detected_tech:
        tech_lower = detected_tech.lower()
        for tech_key, family_boosts in _TECH_BOOSTS.items():
            if tech_key in tech_lower:
                for family, hints in _SIGNALS.items():
                    if name in hints:
                        score += family_boosts.get(family, 0)
                        break
    return score


def prioritize(points: list[InjectionPoint], detected_tech: str | None = None) -> list[InjectionPoint]:
    """Highest-signal points first; stable for identical scores."""
    return sorted(points, key=lambda p: score_point(p, detected_tech), reverse=True)
