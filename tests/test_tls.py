from datetime import datetime, timedelta, timezone

from summit.tls import cert_findings


def decoded_cert(not_after: str, self_signed: bool = False):
    # mirrors the real ssl._test_decode_cert structure (3-level tuples)
    subject = ((("commonName", "target.local"),),)
    if self_signed:
        issuer = subject
    else:
        issuer = ((("organizationName", "Real CA Inc"),),)
    return {"notAfter": not_after, "issuer": issuer, "subject": subject}


def test_expired_certificate_flagged():
    expired = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%b %d %H:%M:%S %Y GMT")
    findings = cert_findings(decoded_cert(expired), legacy_versions=[])
    assert any(f.check_id == "tls-cert-expired" and f.confidence == "confirmed" for f in findings)
    assert all(f.cwe == "CWE-295" for f in findings if f.check_id == "tls-cert-expired")


def test_expiring_soon_flagged_as_potential():
    soon = (datetime.now(timezone.utc) + timedelta(days=5)).strftime("%b %d %H:%M:%S %Y GMT")
    findings = cert_findings(decoded_cert(soon), legacy_versions=[])
    assert any(f.check_id == "tls-cert-expiring" and f.confidence == "potential" for f in findings)


def test_self_signed_flagged():
    not_expired = (datetime.now(timezone.utc) + timedelta(days=200)).strftime("%b %d %H:%M:%S %Y GMT")
    findings = cert_findings(decoded_cert(not_expired, self_signed=True), legacy_versions=[])
    assert any(f.check_id == "tls-cert-self-signed" and f.confidence == "confirmed" for f in findings)


def test_legacy_tls_versions_flagged():
    not_expired = (datetime.now(timezone.utc) + timedelta(days=200)).strftime("%b %d %H:%M:%S %Y GMT")
    findings = cert_findings(decoded_cert(not_expired), legacy_versions=["TLSv1", "TLSv1_1"])
    legacy = next(f for f in findings if f.check_id == "tls-legacy-versions")
    assert legacy.cwe == "CWE-326"
    assert "TLSv1" in legacy.evidence


def test_healthy_certificate_is_quiet():
    not_expired = (datetime.now(timezone.utc) + timedelta(days=200)).strftime("%b %d %H:%M:%S %Y GMT")
    findings = cert_findings(decoded_cert(not_expired), legacy_versions=[])
    assert findings == []
