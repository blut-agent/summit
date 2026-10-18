"""Cacheable sensitive responses (CWE-524).

A response containing credentials, tokens or internal data without
`Cache-Control: no-store` can end up in shared browser and proxy
caches - the next user of that machine reads your secrets from disk.
Passive, per response: sensitive content marker present + no
no-store/private directive.
"""

from __future__ import annotations

from ...http.models import HttpResponse
from ...scan.core import Finding

_SENSITIVE_MARKERS = [
    "password",
    "passwd",
    "token",
    "app_key",
    "api_key",
    "secret",
    "salary",
    "session_id",
    "authorization",
]

_SAFE_DIRECTIVES = ("no-store", "private", "no-cache")


def check_cacheable_sensitive(response: HttpResponse) -> list[Finding]:
    if response.status != 200:
        return []
    cache_control = response.header("cache-control").lower()
    if any(directive in cache_control for directive in _SAFE_DIRECTIVES):
        return []
    body = response.text[:100_000].lower()
    marker = next((m for m in _SENSITIVE_MARKERS if m in body), None)
    if marker is None:
        return []
    return [
        Finding(
            check_id="cacheable-sensitive",
            title="Cacheable response contains sensitive content",
            severity="medium",
            url=response.request.url,
            confidence="needs-manual",
            detail=f"The response contains a sensitive marker ({marker!r}) but sets no Cache-Control "
            "restriction. Shared caches and the browser back-button cache may retain it for the next user.",
            evidence=f"sensitive marker: {marker!r}; Cache-Control: {response.header('cache-control') or '(absent)'}",
            remediation="Set `Cache-Control: no-store` (and `Pragma: no-cache`) on any response carrying credentials or private data.",
        )
    ]
