"""Phase-based scanning engine.

Summit organizes its scanning into sequential phases, each building on
the previous phase's findings. This mirrors how a human pentester works:
reconnaissance first, then fingerprinting, then targeted vulnerability
checks based on what was discovered.

Phases:

    1. RECON        - crawl the target, map the attack surface, collect
                      links, forms, JS endpoints, and outbound links
    2. FINGERPRINT  - identify server, CMS, framework, libraries from
                      response headers and body (Wappalyzer approach)
    3. VULNERABILITY- run passive + active checks, prioritized by the
                      technology detected in phase 2
    4. REPORT       - render findings in all formats, apply filters

Each phase produces structured output that the next phase consumes.
This makes the engine predictable: you always know what ran, in what
order, and what it found.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..fingerprint import fingerprint
from ..http.client import HttpClient
from .core import Finding
from .crawl.spider import Spider
from .passive import run_passive


@dataclass
class PhaseResult:
    """Output from one scan phase."""
    name: str
    duration: float
    data: dict = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class PhaseEngine:
    """Sequential phase-based scanning engine."""

    def __init__(self, client: HttpClient, workers: int = 8) -> None:
        self.client = client
        self.workers = workers
        self.phases: list[PhaseResult] = []
        self.findings: list[Finding] = []
        self.errors: list[str] = []
        self.elapsed = 0.0
        self.technologies: list[dict] = []
        self._seen: set[tuple[str, str, str]] = set()

    def add_finding(self, finding: Finding) -> None:
        key = (finding.check_id, finding.url, finding.param)
        if key not in self._seen:
            self._seen.add(key)
            self.findings.append(finding)

    def _run_phase(self, name: str, func, *args, **kwargs) -> PhaseResult:
        started = time.monotonic()
        try:
            data = func(*args, **kwargs)
            errors = data.pop("errors", []) if isinstance(data, dict) else []
            phase = PhaseResult(name=name, duration=time.monotonic() - started, data=data or {}, errors=errors)
        except Exception as exc:
            phase = PhaseResult(name=name, duration=time.monotonic() - started, errors=[str(exc)])
        self.phases.append(phase)
        return phase

    def run_full_scan(
        self,
        url: str,
        max_depth: int = 2,
        max_pages: int = 30,
        active: bool = True,
        linkcheck_enabled: bool = True,
    ) -> list[Finding]:
        """Execute all phases in sequence and return the findings."""
        started = time.monotonic()

        # Phase 1: RECON - map the attack surface
        recon = self._run_phase("RECON", self._phase_recon, url, max_depth, max_pages)
        spider_result = recon.data

        # Phase 2: FINGERPRINT - identify technologies
        fp_result = self._run_phase("FINGERPRINT", self._phase_fingerprint, spider_result)
        self.technologies = fp_result.data.get("technologies", [])

        # Phase 3: VULNERABILITY - passive + active checks
        self._run_phase(
            "VULNERABILITY", self._phase_vulnerability,
            spider_result, active, linkcheck_enabled,
        )

        self.elapsed = time.monotonic() - started
        return self.findings

    def _phase_recon(self, url: str, max_depth: int, max_pages: int) -> dict:
        spider = Spider(self.client, max_depth=max_depth, max_pages=max_pages)
        result = spider.crawl(url)
        return {
            "pages": result.get("pages", []),
            "forms": result.get("forms", []),
            "visited": result.get("visited", []),
            "external_links": result.get("external_links", []),
            "errors": result.get("errors", []),
        }

    def _phase_fingerprint(self, spider_result: dict) -> dict:
        """Fingerprint technologies from all crawled pages."""
        all_technologies: list[dict] = []
        seen: set[str] = set()
        for response in spider_result.get("pages", []):
            for tech in fingerprint(response):
                key = f"{tech['category']}:{tech['name']}"
                if key not in seen:
                    seen.add(key)
                    all_technologies.append(tech)
        return {"technologies": all_technologies}

    def _phase_vulnerability(self, spider_result: dict, active: bool, linkcheck_enabled: bool) -> dict:
        """Run passive + active checks with tech-aware prioritization."""
        from .engine import build_targets

        # Passive checks on every page
        for response in spider_result.get("pages", []):
            for finding in run_passive(response):
                self.add_finding(finding)

        # Active checks on injection points
        if active:
            targets = build_targets(spider_result)
            detected_tech = None
            for tech in self.technologies:
                if tech["category"] in ("server", "language", "framework"):
                    detected_tech = f"{tech['name']} {tech['version']}".strip()
                    break

            from ..smart import prioritize
            ordered = prioritize(targets, detected_tech)
            # Run active checks (delegated to the engine's check runner)
            from .modules import ALL_CHECKS
            for check in ALL_CHECKS:
                for point in ordered:
                    try:
                        for finding in check.run(point, self.client):
                            self.add_finding(finding)
                    except Exception as exc:
                        self.errors.append(f"{check.check_id} failed: {exc}")

            # Link health
            if linkcheck_enabled:
                external = spider_result.get("external_links", [])
                if external:
                    from ..scan.linkcheck import check_links as _check_links
                    for finding in _check_links(external, workers=self.workers, timeout=self.client.timeout):
                        self.add_finding(finding)

            # Origin-based checks
            from urllib.parse import urlsplit
            pages = spider_result.get("pages", [])
            if pages:
                origin = urlsplit(pages[0].request.url)
                base = f"{origin.scheme}://{origin.netloc}"
                from .modules.sensitive_files import run_sensitive_files
                from .modules.directory_listing import run_directory_listing
                from ..graphql import check_graphql
                for check_fn in (run_sensitive_files, run_directory_listing, check_graphql):
                    try:
                        for finding in check_fn(self.client, base):
                            self.add_finding(finding)
                    except Exception as exc:
                        self.errors.append(f"origin check failed: {exc}")

        return {"findings_count": len(self.findings)}

    def phase_summary(self) -> str:
        lines = []
        for phase in self.phases:
            status = "OK" if not phase.errors else f"{len(phase.errors)} error(s)"
            lines.append(f"  {phase.name:20} {phase.duration:.1f}s  {status}")
            for error in phase.errors[:3]:
                lines.append(f"    [!] {error[:100]}")
        return "\n".join(lines)
