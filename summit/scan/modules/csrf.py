"""Cross-site request forgery (CWE-352) - form-level check.

A state-changing form (POST, or one containing a password field) that
carries no CSRF-style hidden field lets other websites submit it as the
victim. The check runs over the forms the spider collected and reports
`potential`: a framework can also enforce CSRF via cookies or headers,
so the absence of a hidden field alone is not proof - but it is where
the review starts.
"""

from __future__ import annotations

from ...http.models import HttpResponse
from ...scan.core import Finding

_CSRF_HINTS = ("csrf", "token", "_token", "authenticity_token", "_csrf")


def check_csrf_forms(response: HttpResponse, forms: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for form in forms:
        method = (form.get("method") or "GET").upper()
        fields = form.get("fields") or {}
        has_password = any("password" in name.lower() or "passwd" in name.lower() for name in fields)
        if method != "POST" and not has_password:
            continue
        if any(hint in name.lower() for name in fields for hint in _CSRF_HINTS):
            continue
        findings.append(
            Finding(
                check_id="csrf-missing",
                title="Form without CSRF protection",
                severity="medium",
                url=form.get("action") or response.request.url,
                confidence="potential",
                detail=(
                    f"A {method} form"
                    + (" containing a password field" if has_password else "")
                    + " carries no CSRF-style field (csrf/token). If the server does not verify "
                    "a token through cookies or headers instead, other websites can submit this "
                    "form as the victim."
                ),
                evidence=f"form action: {form.get('action')} method: {method}",
                remediation="Add a per-session CSRF token to every state-changing form and verify it server-side.",
            )
        )
    return findings
