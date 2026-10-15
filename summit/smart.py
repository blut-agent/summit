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
}


def score_point(point: InjectionPoint) -> int:
    name = point.param.lower()
    score = 1
    for hints in _SIGNALS.values():
        if name in hints or any(name.startswith(hint) for hint in hints if len(hint) >= 4):
            score = 3
            break
    value = point.original_value.strip()
    if value.isdigit() or value.startswith(("http://", "https://", "/", "//")):
        score = max(score, 2)
    return score


def prioritize(points: list[InjectionPoint]) -> list[InjectionPoint]:
    """Highest-signal points first; stable for identical scores."""
    return sorted(points, key=score_point, reverse=True)
