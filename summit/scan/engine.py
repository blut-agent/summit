from __future__ import annotations

from ..http.client import HttpClient
from ..http.models import HttpResponse
from .core import Check, Finding, InjectionPoint
from .modules import ALL_CHECKS
from .passive import run_passive


def build_targets(spider_result: dict) -> list[InjectionPoint]:
    """Collect injectable query parameters from every crawled page."""
    points: list[InjectionPoint] = []
    seen: set[tuple[str, str]] = set()
    for response in spider_result.get("pages", []):
        request = response.request
        for name, value in request.params.items():
            key = (request.url, name)
            if key in seen:
                continue
            seen.add(key)
            points.append(InjectionPoint(request=request, param=name, original_value=value, location="query"))
    return points


class ScanEngine:
    """Runs passive checks on every page, then active checks on injection points."""

    def __init__(self, client: HttpClient, active: bool = True, checks: list[Check] | None = None) -> None:
        self.client = client
        self.active = active
        self.checks = checks if checks is not None else list(ALL_CHECKS)
        self.findings: list[Finding] = []
        self.errors: list[str] = []
        self._seen: set[tuple[str, str, str]] = set()

    def add(self, finding: Finding) -> None:
        key = (finding.check_id, finding.url, finding.param)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(finding)

    def scan(self, spider_result: dict) -> list[Finding]:
        for response in spider_result.get("pages", []):
            for finding in run_passive(response):
                self.add(finding)

        if self.active:
            targets = build_targets(spider_result)
            for check in self.checks:
                for point in targets:
                    try:
                        for finding in check.run(point, self.client):
                            self.add(finding)
                    except Exception as exc:
                        self.errors.append(f"{check.check_id} failed on {point.request.url} [{point.param}]: {exc}")
        return self.findings
