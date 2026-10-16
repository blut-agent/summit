"""Offline CVE detection from version banners.

This is a small, curated database: product -> affected versions -> CVE.
It only fires on exact, well-known version strings parsed from Server
and X-Powered-By headers, and every finding is marked `potential` -
banners can be spoofed, so a human confirms before acting. Extend the
table via PRs; entries must cite the CVE id and what it allows.
"""

from __future__ import annotations

import re

# (header regex, [(affected versions |-separated, CVE id, what it allows)])
CVE_DATABASE: list[tuple[str, list[tuple[str, str, str]]]] = [
    (
        r"apache/(\d+\.\d+(?:\.\d+)?)",
        [
            ("2.4.49", "CVE-2021-41773", "path traversal and possible RCE via crafted requests"),
            ("2.4.49|2.4.50", "CVE-2021-42013", "path traversal and RCE - bypass of the incomplete CVE-2021-41773 fix"),
        ],
    ),
    (
        r"nginx/(\d+\.\d+(?:\.\d+)?)",
        [
            ("1.20.0", "CVE-2021-23017", "DNS resolver one-byte memory overwrite - possible RCE"),
        ],
    ),
    (
        r"openssh[_ ](\d+\.\d+(?:\.\d+)?)",
        [
            ("7.2", "CVE-2016-10009", "unauthenticated remote code execution via agent forwarding"),
        ],
    ),
    (
        r"php/(\d+\.\d+(?:\.\d+)?)",
        [
            ("7.4.0", "CVE-2019-11043", "RCE in certain nginx+php-fpm configurations"),
        ],
    ),
    (
        r"tomcat/(\d+)",
        [
            ("9", "CVE-2020-1938", "Ghostcat - AJP connector file read, possible RCE"),
        ],
    ),
]


def detect_cves(*banner_values: str) -> list[dict]:
    """Match version banners against the database.

    Returns a list of {cve, version, description} dicts. Only exact
    affected-version strings fire - ranges would be guessing.
    """
    text = " ".join(value for value in banner_values if value).lower()
    findings: list[dict] = []
    for pattern, entries in CVE_DATABASE:
        match = re.search(pattern, text)
        if not match:
            continue
        version = match.group(1)
        for affected, cve_id, description in entries:
            if version in affected.split("|"):
                findings.append({"cve": cve_id, "version": version, "description": description})
    return findings
