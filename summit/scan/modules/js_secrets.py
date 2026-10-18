"""Hardcoded secrets in client-side code (CWE-798, CWE-540).

API keys, tokens and private keys shipped to the browser are readable by
anyone with view-source. Patterns are deliberately tight (vendor-shaped
prefixes, entropy checks, placeholder exclusion) so the report stays
signal-only: one finding per page, values redacted, `likely` unless a
private key block is found - a decoy key in a demo bundle should not
read as `confirmed` without a human glance.
"""

from __future__ import annotations

import re

from ...http.models import HttpResponse
from ...scan.core import Finding

_VENDOR_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "medium"),
    ("Google OAuth client secret", re.compile(r"\bGOCSPX-[0-9A-Za-z_\-]{20,}\b"), "medium"),
    ("Stripe live secret key", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"), "high"),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "high"),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "medium"),
]

_PRIVATE_KEY = re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")

_GENERIC = re.compile(
    r"(?:api[_-]?key|apikey|client[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token)"
    r"\s*[:=]\s*[\"']([A-Za-z0-9_\-./+=]{20,})[\"']",
    re.IGNORECASE,
)

_EXCLUDE_VALUES = {"AKIAIOSFODNN7EXAMPLE"}

_PLACEHOLDER_HINTS = (
    "example", "sample", "dummy", "placeholder", "changeme", "your_", "your-",
    "xxxx", "fake", "redacted", "insert", "todo", "test-key", "testkey",
)


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(hint in lowered for hint in _PLACEHOLDER_HINTS)


def _entropy_ok(value: str) -> bool:
    classes = sum(bool(re.search(pattern, value)) for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    return classes >= 2


def redact(value: str) -> str:
    if len(value) <= 12:
        return value[:2] + "…"
    return f"{value[:6]}…{value[-4:]}"


def detect_secrets(text: str) -> list[dict]:
    """Return [{'kind', 'value', 'severity'}] with duplicates collapsed."""
    hits: dict[str, dict] = {}
    if _PRIVATE_KEY.search(text):
        hits["private-key"] = {"kind": "Private key block", "value": "-----BEGIN PRIVATE KEY-----", "severity": "high"}
    for kind, pattern, severity in _VENDOR_PATTERNS:
        for value in pattern.findall(text):
            if value in _EXCLUDE_VALUES or _is_placeholder(value):
                continue
            hits.setdefault(value, {"kind": kind, "value": value, "severity": severity})
    for value in _GENERIC.findall(text):
        if value in _EXCLUDE_VALUES or _is_placeholder(value) or not _entropy_ok(value):
            continue
        hits.setdefault(value, {"kind": "Generic API key / secret", "value": value, "severity": "medium"})
    return list(hits.values())


def check_js_secrets(response: HttpResponse) -> list[Finding]:
    """One finding per page listing every distinct secret found."""
    body = response.text[:200_000]
    if not body or len(body) < 20:
        return []
    hits = detect_secrets(body)
    if not hits:
        return []
    has_private_key = any(hit["kind"] == "Private key block" for hit in hits)
    severity = "high" if has_private_key else "medium"
    confidence = "confirmed" if has_private_key else "likely"
    kinds = sorted({hit["kind"] for hit in hits})
    samples = "; ".join(f"{hit['kind']}: {redact(hit['value'])}" for hit in hits[:5])
    detail = (
        f"The response ships {len(hits)} hardcoded credential(s) to the browser: {', '.join(kinds)}. "
        "Anyone who loads this page can read them. Secrets embedded in client code are also shipped "
        "in every cached copy and version history."
    )
    remediation = (
        "Move the secret to a backend component, rotate it immediately, and review history/caches "
        "for exposure. Restrict any remaining key by referrer/IP where the vendor supports it."
    )
    return [
        Finding(
            check_id="js-secret",
            title=f"Hardcoded secret in client-side code: {', '.join(kinds[:4])}",
            severity=severity,
            url=response.request.url,
            confidence=confidence,
            detail=detail,
            evidence=samples,
            remediation=remediation,
        )
    ]
