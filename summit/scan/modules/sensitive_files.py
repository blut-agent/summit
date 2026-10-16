"""Sensitive file exposure (CWE-538) - signatures, not just status codes.

A 200 response for /.env proves nothing on wildcard-routing servers
(that is why the fuzzer has a wildcard baseline). This check requires
the body to match the file's real content, which makes false positives
practically impossible.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ...http.client import HttpClient
from ...http.models import HttpRequest
from ...scan.core import Finding

# (path, content signatures - any one match confirms, name)
PATH_SIGNATURES = [
    ("/.env", ["APP_KEY=", "DB_PASSWORD=", "SECRET_KEY="], "environment file"),
    ("/.git/config", ["[core]", "repositoryformatversion"], "git repository metadata"),
    ("/.git/HEAD", ["ref: refs/"], "git repository head"),
    ("/.aws/credentials", ["aws_access_key_id", "[default]"], "AWS credentials file"),
    ("/backup.sql", ["CREATE TABLE", "INSERT INTO"], "database dump"),
    ("/wp-config.php", ["DB_NAME", "DB_PASSWORD"], "WordPress configuration"),
    ("/web.config.bak", ["connectionString", "system.web"], "IIS configuration backup"),
]


def run_sensitive_files(client: HttpClient, base_url: str) -> list[Finding]:
    """Check a handful of high-value paths once per scan. Content decides."""
    findings: list[Finding] = []
    split = urlsplit(base_url)
    origin = f"{split.scheme}://{split.netloc}"
    for path, signatures, name in PATH_SIGNATURES:
        try:
            response = client.send(HttpRequest(method="GET", url=origin + path))
        except Exception:
            continue
        if response.status != 200:
            continue
        body = response.text[:50_000].lower()
        hit = next((signature for signature in signatures if signature.lower() in body), None)
        if hit is None:
            continue
        findings.append(
            Finding(
                check_id="sensitive-file",
                title=f"Sensitive file exposed: {path}",
                severity="high",
                url=origin + path,
                confidence="confirmed",
                detail=f"The server returns a 200 with content that matches a real {name}. "
                "Status-code-only scanners flood this check with false positives; the content signature is what makes it certain.",
                evidence=f"content signature: {hit!r}",
                remediation="Remove the file from the web root, revoke any credentials it contains, "
                "and block access to dotfiles and backups at the server level.",
            )
        )
    return findings
