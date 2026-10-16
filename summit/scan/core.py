from __future__ import annotations

from dataclasses import dataclass, field

from ..http.client import HttpClient
from ..http.models import HttpRequest

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}


def min_severity(severity: str) -> str:
    """Smallest severity name whose rank covers `severity` (for --min-severity)."""
    return severity if severity in SEVERITY_RANK else "info"


def filter_by_severities(findings: list["Finding"], allowed: set[str]) -> list["Finding"]:
    return [f for f in findings if f.severity in allowed]


def filter_by_min_severity(findings: list["Finding"], minimum: str) -> list["Finding"]:
    floor = SEVERITY_RANK.get(minimum, 0)
    return [f for f in findings if SEVERITY_RANK.get(f.severity, 0) >= floor]

# Central CWE mapping: every check_id gets its CWE so findings are
# referenceable without each module repeating the constant.
CWE_BY_CHECK_ID = {
    "passive-security-headers": "CWE-693",
    "passive-cookie-flags": "CWE-614",
    "passive-error-disclosure": "CWE-209",
    "passive-info-disclosure": "CWE-200",
    "passive-cors": "CWE-942",
    "passive-email-leak": "CWE-359",
    "waf-detected": "CWE-693",
    "captcha-challenge": "",
    "takeover-signature": "CWE-350",
    "sqli-error": "CWE-89",
    "sqli-boolean": "CWE-89",
    "xss-reflection": "CWE-79",
    "xss-reflection-hardened": "CWE-79",
    "waf-bypass": "CWE-693",
    "host-header-injection": "CWE-640",
    "cors-reflection": "CWE-942",
    "open-redirect": "CWE-601",
    "path-traversal": "CWE-22",
    "authorize-bypass": "CWE-639",
    "authorize-partial": "CWE-639",
    "paramminer-reflected": "CWE-200",
    "paramminer-behavior": "CWE-200",
    "fuzz-dir": "CWE-538",
    "linkcheck-dead-domain": "CWE-350",
    "linkcheck-parked": "CWE-350",
    "linkcheck-broken": "CWE-350",
    "linkcheck-unreachable": "CWE-350",
    "linkcheck-private-target": "CWE-918",
    "os-command-injection": "CWE-78",
    "ssti": "CWE-1336",
    "crlf-injection": "CWE-113",
    "sensitive-file": "CWE-538",
    "cve-detected": "CWE-1104",
    "sqli-time": "CWE-89",
    "graphql-introspection": "CWE-200",
}


def cwe_for(check_id: str) -> str:
    return CWE_BY_CHECK_ID.get(check_id, "")


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    url: str
    param: str = ""
    detail: str = ""
    evidence: str = ""
    remediation: str = ""
    # "confirmed" = observed fact (raw reflection, file content, fresh DB
    # error, 3xx Location). "potential" = heuristic signal.
    confidence: str = "potential"
    # CWE identifier, resolved from check_id when the module does not set it.
    cwe: str = ""
    # CVE identifiers detected for this finding (e.g. from version banners).
    cves: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "url": self.url,
            "param": self.param,
            "detail": self.detail,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "cwe": self.cwe or cwe_for(self.check_id),
            "cves": list(self.cves),
        }


@dataclass
class InjectionPoint:
    request: HttpRequest
    param: str
    original_value: str
    location: str = "query"


class Check:
    """Base class for active checks. Subclass and override ``run``."""

    check_id: str = "generic"
    title: str = "Generic check"
    severity: str = "medium"

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        raise NotImplementedError
