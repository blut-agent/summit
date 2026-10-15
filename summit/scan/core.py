from __future__ import annotations

from dataclasses import dataclass

from ..http.client import HttpClient
from ..http.models import HttpRequest

SEVERITIES = ("info", "low", "medium", "high", "critical")


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

    def as_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity,
            "url": self.url,
            "param": self.param,
            "detail": self.detail,
            "evidence": self.evidence[:400],
            "remediation": self.remediation,
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
