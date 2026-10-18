"""WAF and block-page detection.

Determines whether a response is a WAF/CDN block rather than a real
application response. If a probe response is a block, the vulnerability
check should NOT report a finding - it should record an informational
note and back off from that host.

Detection: status codes 403/406/429/503 + small body + block-page
keywords, or WAF-specific headers.
"""

from __future__ import annotations

import re

from ..http.models import HttpResponse

BLOCK_STATUSES = {403, 406, 429, 503}

WAF_HEADERS = {
    "cf-ray": "Cloudflare",
    "cf-mitigated": "Cloudflare",
    "x-akamai-transformed": "Akamai",
    "x-akamai-request-id": "Akamai",
    "x-sucuri-id": "Sucuri",
    "x-sucuri-cache": "Sucuri",
    "x-iinfo": "Imperva",
    "x-cdn": "Incapsula",
}

BLOCK_BODY_PATTERNS = [
    re.compile(r"access denied", re.IGNORECASE),
    re.compile(r"request blocked", re.IGNORECASE),
    re.compile(r"banned", re.IGNORECASE),
    re.compile(r"you have been blocked", re.IGNORECASE),
    re.compile(r"cloudflare", re.IGNORECASE),
    re.compile(r"sucuri web site firewall", re.IGNORECASE),
    re.compile(r"incapsula incident id", re.IGNORECASE),
    re.compile(r"akamai reference number", re.IGNORECASE),
    re.compile(r"blocked by", re.IGNORECASE),
    re.compile(r"security check", re.IGNORECASE),
    re.compile(r"captcha", re.IGNORECASE),
]

_MAX_BLOCK_BODY = 5_000


def is_waf_block(response: HttpResponse) -> tuple[bool, str]:
    """Return (is_block, waf_or_reason) for a probe response."""
    # Check WAF-specific headers (these fire regardless of status code)
    for header, vendor in WAF_HEADERS.items():
        if response.header(header):
            # cf-ray alone doesn't mean blocked - it's on every CF response.
            # Only flag if the status is also a block status.
            if response.status in BLOCK_STATUSES:
                return True, vendor
            if header in ("cf-mitigated", "x-sucuri-id", "x-iinfo"):
                return True, vendor

    # Check status code + body patterns
    if response.status in BLOCK_STATUSES:
        body = response.text[:_MAX_BLOCK_BODY].lower()
        for pattern in BLOCK_BODY_PATTERNS:
            if pattern.search(body):
                return True, f"block page (HTTP {response.status})"
        # Small body on a block status with no meaningful content
        if len(response.body) < 500 and response.status in (403, 406):
            return True, f"small body on HTTP {response.status}"

    return False, ""


def is_probe_blocked(response: HttpResponse) -> bool:
    """Convenience function for check modules: was this probe blocked?"""
    blocked, _ = is_waf_block(response)
    return blocked
