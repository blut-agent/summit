"""TLS / certificate audit - the basics ssl can tell us for free.

`summit tls <host>` connects once, reads the served certificate and
checks the things that bite in real engagements:

- expired certificate (CWE-295, confirmed - dates do not lie)
- certificate expiring within 14 days (low, likely)
- self-signed certificate (CWE-295, confirmed - issuer equals subject)
- legacy TLS versions still accepted: TLSv1.0 / TLSv1.1 (CWE-326, confirmed
  - we complete the handshake with those protocol versions ourselves)

This is a standalone command, not part of `scan`, because it talks to
the network by definition.
"""

from __future__ import annotations

import socket
import ssl
import tempfile
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .scan.core import Finding

_EXPIRY_WARN_DAYS = 14
_LEGACY_VERSIONS = ("TLSv1", "TLSv1_1")


def _decode_cert(pem: str) -> dict:
    """Stdlib-only certificate decoding. Uses the private-but-stable
    _test_decode_cert helper; wrapped so failures are honest errors."""
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as handle:
        handle.write(pem)
        path = handle.name
    try:
        return ssl._ssl._test_decode_cert(path)
    finally:
        import os

        os.unlink(path)


def cert_findings(info: dict, legacy_versions: list[str], now: datetime | None = None) -> list[Finding]:
    """Pure verdict logic over a decoded certificate + handshake results."""
    now = now or datetime.now(timezone.utc)
    findings: list[Finding] = []
    not_after = info.get("notAfter", "")
    try:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        expiry = None
    if expiry is not None:
        days_left = (expiry - now).days
        if days_left < 0:
            findings.append(
                Finding(
                    check_id="tls-cert-expired",
                    title=f"Certificate expired {abs(days_left)} day(s) ago",
                    severity="high",
                    url=f"https://{info.get('subject', [('?',)])[0][0][1]}",
                    confidence="confirmed",
                    cwe="CWE-295",
                    detail=f"The certificate valid-until date is {not_after}. Visitors get browser "
                    "warnings, and many clients refuse the connection outright.",
                    evidence=f"notAfter: {not_after} (expired {abs(days_left)}d ago)",
                    remediation="Renew the certificate immediately.",
                )
            )
        elif days_left <= _EXPIRY_WARN_DAYS:
            findings.append(
                Finding(
                    check_id="tls-cert-expiring",
                    title=f"Certificate expires in {days_left} day(s)",
                    severity="low",
                    url=f"https://{info.get('subject', [('?',)])[0][0][1]}",
                    confidence="likely",
                    cwe="CWE-295",
                    detail=f"The certificate valid-until date is {not_after}. Renewal windows this short usually mean automation is broken.",
                    evidence=f"notAfter: {not_after} ({days_left}d left)",
                    remediation="Renew before expiry; check the ACME automation.",
                )
            )
    issuer = _names(info.get("issuer"))
    subject = _names(info.get("subject"))
    if issuer and subject and issuer == subject:
        findings.append(
            Finding(
                check_id="tls-cert-self-signed",
                title="Self-signed certificate",
                severity="medium",
                url=f"https://{subject}",
                confidence="confirmed",
                cwe="CWE-295",
                detail="Issuer equals subject - the certificate is self-signed and provides no third-party identity guarantee.",
                evidence=f"issuer: {issuer}",
                remediation="Use a certificate from a public CA for anything user-facing.",
            )
        )
    if legacy_versions:
        findings.append(
            Finding(
                check_id="tls-legacy-versions",
                title="Legacy TLS versions accepted",
                severity="medium",
                url=f"https://{subject or 'target'}",
                confidence="confirmed",
                cwe="CWE-326",
                    detail=f"The server completed handshakes with {', '.join(legacy_versions)}. These "
                    "protocol versions have known weaknesses and fail modern compliance scans.",
                evidence=f"handshake succeeded with: {', '.join(legacy_versions)}",
                remediation="Disable TLSv1.0/1.1 server-side; require TLSv1.2+.",
            )
        )
    return findings


def _names(entry) -> str:
    try:
        return "/".join(f"{key}={value}" for rdn in entry for key, value in rdn)
    except Exception:
        return ""


def audit(host: str, port: int = 443, timeout: float = 10.0) -> list[Finding]:
    split = urlsplit(host if "://" in host else "https://" + host)
    hostname = split.hostname or host
    legacy: list[str] = []
    for version in _LEGACY_VERSIONS:
        context = ssl.SSLContext(getattr(ssl, f"PROTOCOL_{version}"))
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname):
                    legacy.append(version)
        except (ssl.SSLError, OSError):
            continue
    try:
        pem = ssl.get_server_certificate((hostname, port))
        info = _decode_cert(pem)
    except (OSError, ssl.SSLError) as exc:
        raise ConnectionError(f"could not retrieve the TLS certificate from {hostname}:{port}: {exc}") from exc
    return cert_findings(info, legacy)
