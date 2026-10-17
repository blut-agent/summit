"""Subdomain takeover verification via CNAME + service fingerprint.

This module checks if a subdomain's DNS points to a service (S3,
Heroku, GitHub Pages, Azure, etc.) but the service returns an
"unclaimed resource" error. If so, registering the resource would
give an attacker control over the subdomain.

Unlike the passive takeover check (which looks at response bodies of
pages the scanner crawls), this check actively queries DNS for CNAME
records and verifies the takeover condition. It requires the `dnspython`
library OR falls back to `nslookup`/`dig` system tools.

No active claiming is ever performed - detection only.
"""

from __future__ import annotations

import subprocess

from ...http.client import HttpClient
from ...http.models import HttpRequest
from ...scan.core import Finding

# (service, CNAME pattern, unclaimed response signature, remediation)
TAKEOVER_CNAME_DB = [
    ("AWS S3", ".s3.amazonaws.com", "NoSuchBucket", "Create the S3 bucket or remove the DNS record."),
    ("GitHub Pages", ".github.io", "There isn't a GitHub Pages site here", "Add a GitHub Pages site or remove the CNAME record."),
    ("Heroku", ".herokuapp.com", "No such app", "Register the Heroku app or remove the DNS record."),
    ("Azure", ".azurewebsites.net", "404 Web Site not found", "Create the Azure Web App or remove the DNS record."),
    ("Shopify", ".myshopify.com", "Sorry, this shop is currently unavailable", "Claim the Shopify store or remove the DNS record."),
    ("Fastly", ".fastly.net", "Fastly error: unknown domain", "Add the domain to the Fastly service or remove the DNS record."),
    ("Pantheon", ".pantheonsite.io",
     "The gods are wise, but do not know of the site which you seek",
     "Claim the Pantheon site or remove the DNS record."),
    ("Surge.sh", ".surge.sh", "project not found", "Deploy a Surge project or remove the DNS record."),
]


def _resolve_cname(hostname: str) -> str | None:
    """Resolve CNAME for hostname using system tools (no external deps)."""
    try:
        result = subprocess.run(
            ["nslookup", "-type=cname", hostname],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            line = line.strip().lower()
            if "canonical name" in line or "cname" in line:
                parts = line.split("=", 1)
                if len(parts) == 2:
                    return parts[1].strip().rstrip(".")
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def check_cname_takeover(client: HttpClient, subdomains: list[str]) -> list[Finding]:
    """Actively verify CNAME-based takeover for a list of subdomains."""
    findings: list[Finding] = []
    for subdomain in subdomains:
        try:
            response = client.send(HttpRequest(method="GET", url=f"http://{subdomain}"))
        except Exception:
            continue
        if response.status not in (404, 403, 301, 302):
            continue
        cname = _resolve_cname(subdomain)
        if cname is None:
            continue
        body = response.text[:50_000].lower()
        for service, cname_suffix, signature, remediation in TAKEOVER_CNAME_DB:
            if cname_suffix in cname and signature.lower() in body:
                findings.append(
                    Finding(
                        check_id="subdomain-takeover",
                        title=f"Subdomain takeover confirmed: {subdomain} -> {service}",
                        severity="critical",
                        url=f"http://{subdomain}",
                        confidence="confirmed",
                        detail=(
                            f"The subdomain {subdomain} has a CNAME record pointing to "
                            f"{cname} ({service}), but the {service} resource returns an "
                            "unclaimed-resource error. Registering the resource would give "
                            "an attacker full control over this subdomain."
                        ),
                        evidence=f"CNAME: {cname} -> {service} unclaimed page (HTTP {response.status})",
                        remediation=remediation,
                    )
                )
                break
    return findings
