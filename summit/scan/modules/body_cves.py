"""Modern client-side library CVE detection (CWE-1104).

Server banners are one source; the response BODY is another. Script
tags like `jquery-3.4.1.min.js` and meta generators like
`WordPress 5.7.1` are version disclosures the passive checks already
see - this module matches them against known CVEs the same way the
banner database does.

Every finding stays `needs-manual`: a version string in a filename is a
strong hint, not proof the vulnerable code path is reachable.
"""

from __future__ import annotations

import re

from ...http.models import HttpResponse
from ...scan.core import Finding

# (body regex, [range specs], CVE id, description) - same range grammar
# as the banner database: ">=a,<b" packaging ranges separated by ";",
# or comma-separated exact versions for non-PEP440 strings.
BODY_TECH_DATABASE: list[tuple[str, list[tuple[str, str, str]]]] = [
    (
        r"jquery[-.] ?(\d+\.\d+(?:\.\d+)?)",
        [
            (">=1.2.0,<3.5.0", "CVE-2020-11023", "XSS via crafted HTML passed to jQuery DOM manipulation methods"),
        ],
    ),
    (
        r"lodash(?:[-./@\s]) ?(\d+\.\d+\.\d+)",
        [
            (">=4.0.0,<4.17.19", "CVE-2020-8203", "prototype pollution via zipObjectDeep - possible RCE in Node.js contexts"),
        ],
    ),
    (
        r"WordPress (\d+\.\d+(?:\.\d+)?)",
        [
            ("5.7.0|5.7.1", "CVE-2021-29447", "XXE via media upload - file disclosure and SSRF"),
        ],
    ),
]

_MAX_BODY = 100_000


def detect_body_cves(body: str) -> list[dict]:
    """Match body signatures against the client-side CVE database."""
    from ...cve import _range_matches

    results: list[dict] = []
    text = body[:_MAX_BODY]
    for pattern, entries in BODY_TECH_DATABASE:
        match = re.search(pattern, text, re.IGNORECASE)
        if not match:
            continue
        version = match.group(1)
        for range_spec, cve_id, description in entries:
            if _range_matches(version, range_spec):
                results.append({
                    "cve": cve_id,
                    "version": version,
                    "description": description,
                    "source": match.group(0),
                })
                break  # one CVE per product per response
    return results


def check_body_cves(response: HttpResponse) -> list[Finding]:
    hits = detect_body_cves(response.text)
    findings: list[Finding] = []
    for hit in hits:
        findings.append(
            Finding(
                check_id="cve-detected",
                title=f"Known CVE in client-side library: {hit['cve']}",
                severity="medium",
                url=response.request.url,
                confidence="needs-manual",
                cves=[hit["cve"]],
                detail=(
                    f"The response references {hit['source']!r}, which is affected by "
                    f"{hit['cve']}: {hit['description']}. A version string in a filename is a "
                    "strong hint but not proof the vulnerable code path is reachable."
                ),
                evidence=f"{hit['source']} -> {hit['cve']}",
                remediation="Update the library past the affected range, or verify the vulnerable code path is unreachable.",
            )
        )
    return findings
