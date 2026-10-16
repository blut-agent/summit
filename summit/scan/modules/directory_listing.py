"""Directory listing detection (CWE-548) - content signature.

A 200 on /files/ proves nothing (wildcard routing). A 200 whose body
reads "Directory listing for" or "Index of /" is the web server
announcing every file it has. Content signature only.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ...http.client import HttpClient
from ...http.models import HttpRequest
from ...scan.core import Finding

LISTING_SIGNATURES = [
    "directory listing for",
    "index of /",
]


def run_directory_listing(client: HttpClient, base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    split = urlsplit(base_url)
    origin = f"{split.scheme}://{split.netloc}"
    for path in ("/files/", "/uploads/", "/static/", "/backup/", "/"):
        try:
            response = client.send(HttpRequest(method="GET", url=origin + path))
        except Exception:
            continue
        if response.status != 200:
            continue
        body = response.text[:50_000].lower()
        signature = next((sig for sig in LISTING_SIGNATURES if sig in body), None)
        if signature is None:
            continue
        findings.append(
            Finding(
                check_id="directory-listing",
                title=f"Directory listing enabled: {path}",
                severity="medium",
                url=origin + path,
                confidence="confirmed",
                detail=f"The server renders an index page for {path} - every file and subdirectory is one click away for anyone.",
                evidence=f"listing signature: {signature!r}",
                remediation="Disable autoindex at the server level; serve an explicit 403 or a controlled index page.",
            )
        )
    return findings
