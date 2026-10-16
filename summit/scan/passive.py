from __future__ import annotations

import re

from ..captcha import check_challenge
from ..cve import detect_cves
from ..http.models import HttpResponse
from ..takeover import check_takeover
from ..waf import detect_waf
from .core import Finding
from .modules.cacheable import check_cacheable_sensitive
from .modules.headers_grade import check_headers_grade

SECURITY_HEADERS = [
    ("strict-transport-security", "Strict-Transport-Security", "HSTS forces browsers to use HTTPS."),
    ("content-security-policy", "Content-Security-Policy", "CSP restricts which scripts and resources the page can load."),
    ("x-content-type-options", "X-Content-Type-Options", "Prevents MIME-type sniffing."),
    ("x-frame-options", "X-Frame-Options", "Protects against clickjacking."),
    ("referrer-policy", "Referrer-Policy", "Controls how much referrer data is leaked."),
    ("permissions-policy", "Permissions-Policy", "Restricts browser features like camera and geolocation."),
]

SQL_ERROR_SIGNATURES = {
    "MySQL": ["You have an error in your SQL syntax", "Warning: mysqli_", "supplied argument is not a valid MySQL"],
    "PostgreSQL": ["PG::SyntaxError", "unterminated quoted string at or near", "psycopg2.errors.SyntaxError"],
    "MSSQL": ["Unclosed quotation mark after the character string", "Microsoft OLE DB Provider for SQL Server", "Incorrect syntax near"],
    "SQLite": ["sqlite3.OperationalError", "Warning: SQLite3::", "unrecognized token"],
    "Oracle": ["ORA-01756", "ORA-00936", "quoted string not properly terminated"],
}

TRACE_HINTS = [
    "Traceback (most recent call last)",
    "at org.apache.",
    "System.NullReferenceException",
    "at java.",
    "Fatal error:",
]

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_MAX_BODY = 200_000


def check_security_headers(response: HttpResponse) -> list[Finding]:
    findings = []
    url = response.request.url
    for header, title, why in SECURITY_HEADERS:
        if not response.header(header):
            findings.append(
                Finding(
                    check_id="passive-security-headers",
                    title=f"Missing {title} header",
                    severity="low",
                    url=url,
                    detail=f"The response does not set {title}. {why}",
                    remediation=f"Set the {title} header on responses.",
                )
            )
    return findings


def check_cookies(response: HttpResponse) -> list[Finding]:
    findings = []
    url = response.request.url
    for cookie in response.set_cookies:
        name = cookie.split("=", 1)[0].strip()
        lowered = cookie.lower()
        if "secure" not in lowered:
            findings.append(
                Finding(
                    check_id="passive-cookie-flags",
                    title=f"Cookie '{name}' missing Secure flag",
                    severity="medium",
                    url=url,
                    detail="The cookie can be sent over plain HTTP and may leak on an insecure connection.",
                    remediation="Add the Secure attribute to session cookies.",
                )
            )
        if "httponly" not in lowered:
            findings.append(
                Finding(
                    check_id="passive-cookie-flags",
                    title=f"Cookie '{name}' missing HttpOnly flag",
                    severity="low",
                    url=url,
                    detail="Client-side scripts can read the cookie, which increases XSS impact.",
                    remediation="Add the HttpOnly attribute to session cookies.",
                )
            )
        if "samesite" not in lowered:
            findings.append(
                Finding(
                    check_id="passive-cookie-flags",
                    title=f"Cookie '{name}' missing SameSite attribute",
                    severity="low",
                    url=url,
                    detail="Without SameSite the cookie may be attached to cross-site requests.",
                    remediation="Set SameSite=Lax or Strict for session cookies.",
                )
            )
    return findings


def check_error_disclosure(response: HttpResponse) -> list[Finding]:
    findings = []
    url = response.request.url
    body = response.text[:_MAX_BODY]
    for db, signatures in SQL_ERROR_SIGNATURES.items():
        for signature in signatures:
            if signature in body:
                findings.append(
                    Finding(
                        check_id="passive-error-disclosure",
                        title=f"Possible {db} error message in response",
                        severity="medium",
                        url=url,
                        detail=f"The response body contains a {db} error string. Verbose database errors help attackers craft injections.",
                        evidence=signature,
                        remediation="Disable verbose errors in production and return generic messages.",
                    )
                )
                break
    for hint in TRACE_HINTS:
        if hint in body:
            findings.append(
                Finding(
                    check_id="passive-error-disclosure",
                    title="Stack trace or verbose error in response",
                    severity="medium",
                    url=url,
                    detail="The response leaks framework or runtime internals.",
                    evidence=hint,
                    remediation="Turn off debug mode and configure friendly error pages.",
                )
            )
            break
    return findings


def check_server_disclosure(response: HttpResponse) -> list[Finding]:
    findings = []
    url = response.request.url
    server = response.header("server")
    if server and any(ch.isdigit() for ch in server):
        findings.append(
            Finding(
                check_id="passive-info-disclosure",
                title=f"Server version disclosed: {server}",
                severity="info",
                url=url,
                detail="The Server header includes a version number, which makes targeted attacks easier.",
                remediation="Remove or reduce the Server header.",
            )
        )
        # Version banners can be matched against known CVEs - marked
        # `potential` because banners are trivially spoofed.
        for entry in detect_cves(server):
            findings.append(
                Finding(
                    check_id="cve-detected",
                    title=f"Known CVE matches banner version: {entry['cve']}",
                    severity="high",
                    url=url,
                    confidence="potential",
                    cves=[entry["cve"]],
                    detail=f"Server header advertises version {entry['version']}, which is affected by "
                    f"{entry['cve']}: {entry['description']}. Banners can be spoofed - confirm the "
                    "real version before reporting.",
                    evidence=f"{server} -> {entry['cve']}",
                    remediation="Patch to a fixed release, or confirm the banner is intentionally spoofed.",
                )
            )
    powered = response.header("x-powered-by")
    if powered:
        findings.append(
            Finding(
                check_id="passive-info-disclosure",
                title=f"Technology disclosed via X-Powered-By: {powered}",
                severity="info",
                url=url,
                detail="The X-Powered-By header reveals the backend technology.",
                remediation="Remove the X-Powered-By header.",
            )
        )
        for entry in detect_cves(powered):
            findings.append(
                Finding(
                    check_id="cve-detected",
                    title=f"Known CVE matches banner version: {entry['cve']}",
                    severity="high",
                    url=url,
                    confidence="potential",
                    cves=[entry["cve"]],
                    detail=f"X-Powered-By advertises version {entry['version']}, affected by {entry['cve']}: {entry['description']}.",
                    evidence=f"{powered} -> {entry['cve']}",
                    remediation="Patch to a fixed release, or remove the banner.",
                )
            )
    return findings


def check_cors(response: HttpResponse) -> list[Finding]:
    acao = response.header("access-control-allow-origin")
    acac = response.header("access-control-allow-credentials")
    if acao == "*" and acac.strip().lower() == "true":
        return [
            Finding(
                check_id="passive-cors",
                title="CORS policy sets wildcard origin with credentials",
                severity="low",
                url=response.request.url,
                detail=(
                    "Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials is true. "
                    "Browsers reject this combination, but it signals a misconfigured CORS policy."
                ),
                remediation="Reflect a whitelist of trusted origins instead of '*'.",
            )
        ]
    return []


def check_emails(response: HttpResponse) -> list[Finding]:
    found = sorted(set(EMAIL_RE.findall(response.text[:_MAX_BODY])))
    if found:
        return [
            Finding(
                check_id="passive-email-leak",
                title=f"Email address exposed in page: {', '.join(found[:5])}",
                severity="info",
                url=response.request.url,
                detail="Publicly exposed emails are a target for enumeration and phishing.",
                remediation="Use contact forms or obfuscate emails on public pages.",
            )
        ]
    return []


def check_waf(response: HttpResponse) -> list[Finding]:
    detected = detect_waf(response)
    if not detected:
        return []
    name, evidence = detected
    return [
        Finding(
            check_id="waf-detected",
            title=f"WAF detected: {name}",
            severity="info",
            url=response.request.url,
            detail=(
                "The target sits behind a WAF. Summit adapts: blocked probes are retried "
                "with tamper variants (see the waf-bypass check)."
            ),
            evidence=evidence,
        )
    ]


def run_passive(response: HttpResponse) -> list[Finding]:
    findings: list[Finding] = []
    for checker in (
        check_security_headers,
        check_cookies,
        check_error_disclosure,
        check_server_disclosure,
        check_cors,
        check_emails,
        check_waf,
        check_challenge,
        check_takeover,
        check_cacheable_sensitive,
        check_headers_grade,
    ):
        findings.extend(checker(response))
    return findings
