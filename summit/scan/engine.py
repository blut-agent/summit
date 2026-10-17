from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..http.client import HttpClient
from ..smart import prioritize, score_point
from .core import Check, Finding, InjectionPoint
from .linkcheck import check_links
from .modules import ALL_CHECKS
from .passive import run_passive

# Tracking params are never injectable - probing them only burns requests
# and pads reports.
_TRACKER_HINTS = ("utm_", "fbclid", "gclid", "msclkid", "mc_cid", "mc_eid", "_ga")


def _is_probe_worthy(name: str, value: str) -> bool:
    lowered = name.lower()
    if any(lowered.startswith(hint) or lowered == hint for hint in _TRACKER_HINTS):
        return False
    # Opaque tokens/hashes (>= 40 alphanumeric chars) are session or
    # signature material - probing them adds noise, not signal.
    if len(value) >= 40 and value.isalnum():
        return False
    return True


def build_targets(spider_result: dict) -> list[InjectionPoint]:
    """Collect injectable query parameters from every crawled page."""
    points: list[InjectionPoint] = []
    seen: set[tuple[str, str]] = set()
    skipped = 0
    for response in spider_result.get("pages", []):
        request = response.request
        for name, value in request.params.items():
            key = (request.url, name)
            if key in seen:
                continue
            seen.add(key)
            if not _is_probe_worthy(name, value):
                skipped += 1
                continue
            points.append(InjectionPoint(request=request, param=name, original_value=value, location="query"))
    if skipped:
        spider_result.setdefault("notes", []).append(f"skipped {skipped} tracker/opaque parameter(s)")
    return points


class ScanEngine:
    """Passive checks on every page, then active checks and link health in parallel."""

    def __init__(
        self,
        client: HttpClient,
        active: bool = True,
        checks: list[Check] | None = None,
        workers: int = 8,
        linkcheck_enabled: bool = True,
    ) -> None:
        self.client = client
        self.active = active
        self.checks = checks if checks is not None else list(ALL_CHECKS)
        self.workers = max(1, workers)
        self.linkcheck_enabled = linkcheck_enabled
        self.findings: list[Finding] = []
        self.errors: list[str] = []
        self.elapsed = 0.0
        self.high_signal = 0
        self._seen: set[tuple[str, str, str]] = set()
        # Worker threads add findings concurrently; the lock keeps the
        # dedupe set and list consistent instead of relying on GIL luck.
        self._add_lock = threading.Lock()

    def add(self, finding: Finding) -> None:
        with self._add_lock:
            key = (finding.check_id, finding.url, finding.param)
            if key in self._seen:
                return
            self._seen.add(key)
            self.findings.append(finding)

    def _run_check(self, check: Check, point: InjectionPoint) -> list[Finding]:
        try:
            return check.run(point, self.client)
        except Exception as exc:
            # One broken check must never kill the scan.
            self.errors.append(f"{check.check_id} failed on {point.request.url} [{point.param}]: {exc}")
            return []

    def scan(self, spider_result: dict) -> list[Finding]:
        started = time.monotonic()

        for response in spider_result.get("pages", []):
            for finding in run_passive(response):
                self.add(finding)

        if self.active:
            # The prioritizer orders high-signal parameters first, so the
            # interesting findings show up early in the report stream.
            targets = prioritize(build_targets(spider_result))
            self.high_signal = sum(1 for point in targets if score_point(point) >= 2)
            tasks = [(check, point) for check in self.checks for point in targets]
            if tasks:
                with ThreadPoolExecutor(max_workers=self.workers) as pool:
                    futures = [pool.submit(self._run_check, check, point) for check, point in tasks]
                    for future in as_completed(futures):
                        for finding in future.result():
                            self.add(finding)

        if self.linkcheck_enabled:
            external = spider_result.get("external_links", [])
            if external:
                try:
                    for finding in check_links(external, workers=self.workers, timeout=self.client.timeout):
                        self.add(finding)
                except Exception as exc:
                    self.errors.append(f"linkcheck failed: {exc}")

        # Sensitive-file check runs once per scan against the target origin -
        # it is path-based, not parameter-based like the active checks.
        # GraphQL introspection detection runs the same way.
        if self.active:
            pages = spider_result.get("pages", [])
            if pages:
                from urllib.parse import urlsplit
                from .modules.sensitive_files import run_sensitive_files
                from ..graphql import check_graphql

                origin = urlsplit(pages[0].request.url)
                base = f"{origin.scheme}://{origin.netloc}"
                try:
                    for finding in run_sensitive_files(self.client, base):
                        self.add(finding)
                except Exception as exc:
                    self.errors.append(f"sensitive-file check failed: {exc}")
                try:
                    for finding in check_graphql(self.client, base):
                        self.add(finding)
                except Exception as exc:
                    self.errors.append(f"graphql check failed: {exc}")
                from .modules.csrf import check_csrf_forms

                try:
                    for finding in check_csrf_forms(None, spider_result.get("forms", [])):
                        self.add(finding)
                except Exception as exc:
                    self.errors.append(f"csrf check failed: {exc}")
                from .modules.directory_listing import run_directory_listing

                try:
                    for finding in run_directory_listing(self.client, base):
                        self.add(finding)
                except Exception as exc:
                    self.errors.append(f"directory-listing check failed: {exc}")

        self.elapsed = time.monotonic() - started
        return self.findings
