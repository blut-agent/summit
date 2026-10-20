from __future__ import annotations

import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable
from urllib.parse import urlencode

from ..http.client import HttpClient
from ..http.models import HttpRequest
from ..smart import prioritize, score_point
from .core import Check, Finding, InjectionPoint
from .linkcheck import check_links
from .modules import ALL_CHECKS
from .modules.http_methods import run_http_methods
from .modules.takeover_cname import check_cname_takeover
from .modules.xxe import run_xxe
from .passive import run_passive
from .runtime import set_deep

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
    """Collect injectable query parameters and POST form fields.

    Bodies matter: login forms, search forms and API stubs take their
    input as POST fields, and a query-only scanner never sees them.
    One field is varied at a time so a finding maps to a single input.
    """
    points: list[InjectionPoint] = []
    seen: set[tuple[str, str, str]] = set()
    skipped = 0
    for response in spider_result.get("pages", []):
        request = response.request
        for name, value in request.params.items():
            key = (request.url, name, "query")
            if key in seen:
                continue
            seen.add(key)
            if not _is_probe_worthy(name, value):
                skipped += 1
                continue
            points.append(InjectionPoint(request=request, param=name, original_value=value, location="query"))

    for form in spider_result.get("forms", []):
        if (form.get("method") or "").upper() != "POST":
            continue
        action = form.get("action") or ""
        fields = form.get("fields") or {}
        if not action or not fields:
            continue
        body = urlencode(list(fields.items())).encode()
        request = HttpRequest(
            method="POST",
            url=action,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=body,
        )
        for name, value in fields.items():
            key = (action, name, "body")
            if key in seen:
                continue
            seen.add(key)
            if not _is_probe_worthy(name, value):
                skipped += 1
                continue
            points.append(InjectionPoint(request=request, param=name, original_value=value, location="body"))

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
        deep: bool = False,
        takeover: bool = True,
        oob_check: Check | None = None,
        oob_callback_base: str = "",
        oob_raw_base: str = "",
        oob_hit_checker: Callable[[str], bool] | None = None,
    ) -> None:
        self.client = client
        self.active = active
        self.checks = checks if checks is not None else list(ALL_CHECKS)
        self.workers = max(1, workers)
        self.linkcheck_enabled = linkcheck_enabled
        self.deep = deep
        self.takeover = takeover
        self.oob_check = oob_check
        self.oob_callback_base = oob_callback_base
        self.oob_raw_base = oob_raw_base
        self.oob_hit_checker = oob_hit_checker
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
        set_deep(self.deep)

        for response in spider_result.get("pages", []):
            for finding in run_passive(response):
                self.add(finding)

        if self.active:
            # Detect backend technology for tech-aware prioritization
            detected_tech = None
            for response in spider_result.get("pages", []):
                powered = response.header("x-powered-by") or response.header("server") or ""
                detected_tech = powered
                break

            # The prioritizer orders high-signal parameters first, so the
            # interesting findings show up early in the report stream.
            targets = prioritize(build_targets(spider_result), detected_tech)
            self.high_signal = sum(1 for point in targets if score_point(point) >= 2)
            checks = list(self.checks)
            if self.oob_check is not None:
                checks.append(self.oob_check)
            tasks = [(check, point) for check in checks for point in targets]
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
                try:
                    for finding in run_http_methods(self.client, base):
                        self.add(finding)
                except Exception as exc:
                    self.errors.append(f"http-methods check failed: {exc}")
                try:
                    for finding in run_xxe(self.client, spider_result.get("forms", []), base):
                        self.add(finding)
                except Exception as exc:
                    self.errors.append(f"xxe check failed: {exc}")
                if self.oob_callback_base and self.oob_hit_checker is not None:
                    from .modules.oob_spray import run_oob_spray

                    try:
                        for finding in run_oob_spray(
                            self.client,
                            base,
                            spider_result.get("forms", []),
                            self.oob_callback_base,
                            self.oob_hit_checker,
                            jndi_base=self.oob_raw_base,
                        ):
                            self.add(finding)
                    except Exception as exc:
                        self.errors.append(f"oob spray failed: {exc}")
                if self.takeover:
                    host = origin.hostname or ""
                    if self._takeover_worthy(host):
                        try:
                            for finding in check_cname_takeover(self.client, [host]):
                                self.add(finding)
                        except Exception as exc:
                            self.errors.append(f"cname takeover check failed: {exc}")

        self.elapsed = time.monotonic() - started
        return self.findings

    @staticmethod
    def _takeover_worthy(host: str) -> bool:
        """Skip IPs and local names - there is no CNAME chain to hijack."""
        lowered = host.lower()
        if lowered in ("localhost",) or lowered.endswith(".local"):
            return False
        try:
            ipaddress.ip_address(lowered)
            return False
        except ValueError:
            return True
