"""Offline CVE detection from version banners.

A small, curated database: product -> affected version ranges -> CVE.
Ranges are matched with `packaging.version` (proper semantic comparison,
not string tricks); products whose versions are not PEP-440 shaped
(OpenSSL's `1.0.1f`) fall back to explicit exact-version lists.

Every finding is marked `needs-manual` - banners are trivially spoofed.
Extend the table via PRs; entries must cite the CVE id and what it
allows, and ranges must be defensible from the advisory.
"""

from __future__ import annotations

import re

from packaging.version import InvalidVersion, Version

# (header regex, [range specs]) - a range spec is one or more ranges
# separated by ";". Each range is either ">=a,<b" (packaging comparison)
# or a comma-separated list of exact versions (for non-PEP440 versions).
CVE_DATABASE: list[tuple[str, list[tuple[str, str, str]]]] = [
    (
        r"apache/(\d+\.\d+(?:\.\d+)?)",
        [
            (">=2.4.49,<2.4.50", "CVE-2021-41773", "path traversal and possible RCE via crafted requests"),
            (">=2.4.49,<=2.4.50", "CVE-2021-42013", "path traversal and RCE - bypass of the incomplete CVE-2021-41773 fix"),
        ],
    ),
    (
        r"nginx/(\d+\.\d+(?:\.\d+)?)",
        [
            (">=1.20.0,<1.20.1", "CVE-2021-23017", "DNS resolver one-byte memory overwrite - possible RCE"),
        ],
    ),
    (
        r"openssl/(\d+\.\d+\.\d+[a-z]?)",
        [
            (
                "1.0.1,1.0.1a,1.0.1b,1.0.1c,1.0.1d,1.0.1e,1.0.1f",
                "CVE-2014-0160",
                "Heartbleed - up to 64KB of process memory leaked per request",
            ),
        ],
    ),
    (
        r"php/(\d+\.\d+(?:\.\d+)?)",
        [
            (">=7.1.0,<7.3.11", "CVE-2019-11043", "RCE in certain nginx + php-fpm configurations"),
        ],
    ),
    (
        r"tomcat/(\d+(?:\.\d+)*)",
        [
            (
                ">=6.0.0,<6.0.53;>=7.0.0,<7.0.100;>=8.0.0,<8.5.51;>=9.0.0,<9.0.31;>=10.0.0,<10.0.2",
                "CVE-2020-1938",
                "Ghostcat - AJP connector file read, possible RCE",
            ),
        ],
    ),
    (
        r"wordpress\s*(\d+\.\d+(?:\.\d+)?)",
        [
            (">=5.0.0,<5.8.3", "CVE-2022-21661", "WP_Query SQL injection via crafted query parameters"),
            (">=6.0.0,<6.0.2", "CVE-2022-35914", "Unauthenticated blind SSRF via pingback"),
        ],
    ),
    (
        r"php/(\d+\.\d+\.\d+)",
        [
            (">=8.1.0,<=8.1.5", "CVE-2022-31626", "Buffer overflow in mysqlnd - possible RCE"),
            (">=8.0.0,<=8.0.19", "CVE-2022-31626", "Buffer overflow in mysqlnd - possible RCE"),
        ],
    ),
    (
        r"nginx/(\d+\.\d+(?:\.\d+)?)",
        [
            (">=1.23.0,<=1.23.3", "CVE-2023-44487", "HTTP/2 Rapid Reset - DoS via stream multiplexing"),
        ],
    ),
    (
        r"jetty/(\d+\.\d+(?:\.\d+)?)",
        [
            (">=9.4.0,<=9.4.52", "CVE-2023-44487", "HTTP/2 Rapid Reset - DoS via stream multiplexing"),
        ],
    ),
]

# Frontend/library signatures matched in the response BODY. These ship
# version numbers inside script URLs or generator meta tags, which makes
# detection deterministic: jquery-3.4.1.min.js cannot be anything else.
# (regex, version, CVE id, description)
BODY_CVE_DATABASE: list[tuple[str, str, str, str]] = [
    (r"jquery[-.]3\.4\.\d+", "3.4.x", "CVE-2020-11023", "XSS via cross-domain ajax responses passed to jQuery DOM methods"),
    (r"jquery[-.]1\.12\.\d+", "1.12.x", "CVE-2020-11023", "XSS via cross-domain ajax responses passed to jQuery DOM methods"),
    (r"lodash[-.]4\.17\.(?:1[0-5]|1[0-4]\d|15)", "4.17.15", "CVE-2020-8203", "prototype pollution in lodash zipObjectDeep - possible RCE"),
    (r"WordPress\s+5\.7\.[01]", "5.7.0/5.7.1", "CVE-2021-29447", "XXE via media upload - file disclosure and SSRF"),
]


def _version(value: str):
    try:
        return Version(value)
    except InvalidVersion:
        return None


def _range_matches(version: str, range_spec: str) -> bool:
    parsed = _version(version)
    for part in re.split(r"[;|]", range_spec):
        part = part.strip()
        if not part:
            continue
        if parsed is not None and (">" in part or "<" in part):
            # packaging range: ">=a,<b" (<= and > single-sided also fine)
            ok = True
            for clause in part.split(","):
                clause = clause.strip()
                operator = clause[:2] if clause[:2] in (">=", "<=") else clause[0]
                bound = _version(clause[len(operator):].strip())
                if bound is None:
                    ok = False
                    break
                if operator == ">=" and not parsed >= bound:
                    ok = False
                elif operator == "<=" and not parsed <= bound:
                    ok = False
                elif operator == ">" and not parsed > bound:
                    ok = False
                elif operator == "<" and not parsed < bound:
                    ok = False
            if ok:
                return True
        else:
            # exact-version list (non-PEP440 versions like 1.0.1f)
            if version in [token.strip() for token in part.split(",")]:
                return True
    return False


def detect_body_cves(body: str) -> list[dict]:
    """Match library/framework versions embedded in the response body.

    Returns {cve, version, description} dicts for every signature hit.
    """
    findings: list[dict] = []
    for pattern, version, cve_id, description in BODY_CVE_DATABASE:
        if re.search(pattern, body, re.IGNORECASE):
            findings.append({"cve": cve_id, "version": version, "description": description})
    return findings


def detect_cves(*banner_values: str) -> list[dict]:
    """Match version banners against the database.

    Returns a list of {cve, version, description} dicts.
    """
    text = " ".join(value for value in banner_values if value).lower()
    findings: list[dict] = []
    for pattern, entries in CVE_DATABASE:
        match = re.search(pattern, text)
        if not match:
            continue
        version = match.group(1)
        for range_spec, cve_id, description in entries:
            if _range_matches(version, range_spec):
                findings.append({"cve": cve_id, "version": version, "description": description})
    return findings
