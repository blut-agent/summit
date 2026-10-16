"""Security headers grading - the securityheaders.com A..F scale.

Deterministic: points for each header present, deductions for the
dangerous ones. The grade lands as an info finding so a scan report
opens with the headline before the individual header findings.
"""

from __future__ import annotations

from ...http.models import HttpResponse
from ...scan.core import Finding

# (header, points)
_GRADED = [
    ("strict-transport-security", 25),
    ("content-security-policy", 25),
    ("x-frame-options", 15),
    ("x-content-type-options", 15),
    ("referrer-policy", 10),
    ("permissions-policy", 10),
]


def headers_grade(response: HttpResponse) -> tuple[str, int, int]:
    """Return (grade, score, max) for the response's security headers."""
    score = 0
    for header, points in _GRADED:
        if response.header(header):
            score += points
    # dangerous combination: CSP report-only is not real protection
    csp = response.header("content-security-policy").lower()
    if "report-only" in csp:
        score -= 15
    score = max(0, min(100, score))
    if score >= 90:
        return "A", score, 100
    if score >= 75:
        return "B", score, 100
    if score >= 50:
        return "C", score, 100
    if score >= 25:
        return "D", score, 100
    return "F", score, 100


def check_headers_grade(response: HttpResponse) -> list[Finding]:
    grade, score, maximum = headers_grade(response)
    return [
        Finding(
            check_id="headers-grade",
            title=f"Security headers grade: {grade} ({score}/{maximum})",
            severity="info",
            url=response.request.url,
            detail="Roll-up of the individual security header findings. The grade is deterministic: "
            "points per header present, deductions for report-only CSP.",
            evidence=f"score {score}/{maximum} -> grade {grade}",
        )
    ]
