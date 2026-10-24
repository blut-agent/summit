from __future__ import annotations

import re
from collections import deque
from html.parser import HTMLParser
from typing import Callable
from urllib.parse import urlencode, urljoin, urlsplit

from ..http.client import HttpClient
from ..http.models import HttpRequest, HttpResponse
from .js_endpoints import extract_from_page

_LINK_ATTRS = {"a": "href", "link": "href", "script": "src", "img": "src", "iframe": "src", "form": "action"}
_LOC_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.IGNORECASE | re.DOTALL)


def _normalize_host(host: str | None) -> str:
    return (host or "").lower().removeprefix("www.")


class _Extractor(HTMLParser):
    """Collects links and form definitions from an HTML page."""

    def __init__(self) -> None:
        super().__init__()
        self.urls: list[str] = []
        self.forms: list[dict] = []
        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = dict(attrs)
        attr_name = _LINK_ATTRS.get(tag)
        if attr_name and attr_map.get(attr_name):
            self.urls.append(attr_map[attr_name])
        if tag == "form":
            self._current_form = {
                "action": attr_map.get("action") or "",
                "method": (attr_map.get("method") or "GET").upper(),
                "inputs": [],
            }
        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append(
                {
                    "name": attr_map.get("name") or "",
                    "type": (attr_map.get("type") or "text").lower(),
                    "value": attr_map.get("value") or "",
                }
            )

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


class Spider:
    """Breadth-first crawler with same-host scope control."""

    def __init__(
        self,
        client: HttpClient,
        scope_hosts: set[str] | None = None,
        max_depth: int = 3,
        max_pages: int = 50,
        delay: float = 0.0,
        on_page: Callable[[str], None] | None = None,
    ) -> None:
        self.client = client
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.delay = delay
        self.on_page = on_page
        self.scope_hosts = {_normalize_host(h) for h in scope_hosts} if scope_hosts else None

    def in_scope(self, url: str) -> bool:
        if not self.scope_hosts:
            return False
        return _normalize_host(urlsplit(url).hostname) in self.scope_hosts

    def _discover_seeds(self, origin: str) -> list[str]:
        """robots.txt + sitemap.xml are the site's own public index."""
        seeds: list[str] = []
        sitemap_urls: list[str] = []
        try:
            if self.on_page is not None:
                self.on_page(origin + "/robots.txt")
            robots = self.client.send(HttpRequest(method="GET", url=origin + "/robots.txt"))
            if robots.status == 200:
                for line in robots.text[:50_000].splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    lowered = line.lower()
                    if lowered.startswith(("disallow:", "allow:")):
                        path = line.split(":", 1)[1].strip().rstrip("$")
                        if path and "*" not in path and path != "/":
                            seeds.append(urljoin(origin + "/", path))
                    elif lowered.startswith("sitemap:"):
                        sitemap_url = line.split(":", 1)[1].strip()
                        if sitemap_url.startswith(("http://", "https://")):
                            sitemap_urls.append(sitemap_url)
        except Exception:
            pass
        sitemap_urls.append(origin + "/sitemap.xml")
        for sitemap_url in sitemap_urls[:3]:
            seeds.extend(self._parse_sitemap(sitemap_url))
        return seeds[:200]

    def _parse_sitemap(self, url: str) -> list[str]:
        try:
            if self.on_page is not None:
                self.on_page(url)
            response = self.client.send(HttpRequest(method="GET", url=url))
        except Exception:
            return []
        head = response.text[:2000].lower()
        if response.status != 200 or "<loc" not in head:
            return []
        locs = _LOC_RE.findall(response.text[:200_000])
        # Nested sitemap indexes are skipped: one level of expansion keeps
        # request volume bounded.
        return [loc.strip() for loc in locs if not loc.strip().endswith(".xml")]

    def crawl(self, start_url: str) -> dict:
        if self.scope_hosts is None:
            start_host = _normalize_host(urlsplit(start_url).hostname)
            self.scope_hosts = {start_host} if start_host else set()

        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(start_url, 0)])
        # robots.txt and sitemap.xml are the site's own index of pages -
        # crawling them first finds content no link points at.
        split = urlsplit(start_url)
        origin_base = f"{split.scheme}://{split.netloc}"
        for seed in self._discover_seeds(origin_base):
            if self.in_scope(seed):
                queue.append((seed.split("#", 1)[0], 0))
        pages: list[HttpResponse] = []
        forms: list[dict] = []
        errors: list[str] = []
        external_links: set[str] = set()

        while queue and len(visited) < self.max_pages:
            url, depth = queue.popleft()
            clean = url.split("#", 1)[0]
            if not clean or clean.rstrip("/") in visited or not self.in_scope(clean):
                continue
            visited.add(clean.rstrip("/"))
            if self.on_page is not None:
                self.on_page(clean)
            try:
                # Redirects are followed during crawling: endpoints behind a
                # 302 are part of the attack surface, and missing them was a
                # systematic false-negative source.
                response = self.client.send(HttpRequest(method="GET", url=clean), allow_redirects=True)
            except Exception as exc:
                errors.append(f"{clean}: {exc}")
                continue
            pages.append(response)
            # Always extract from fetched pages - we already paid the HTTP
            # request cost, so skipping extraction here would waste it and
            # cause false negatives (forms/links on depth-limit pages).
            extractor = _Extractor()
            try:
                extractor.feed(response.text)
            except Exception as exc:
                errors.append(f"parse failed for {clean}: {exc}")
                continue
            base = response.request.url
            for link in extractor.urls:
                absolute = urljoin(base, link)
                if not absolute.startswith(("http://", "https://")):
                    continue
                if self.in_scope(absolute):
                    if depth < self.max_depth:
                        queue.append((absolute, depth + 1))
                    else:
                        external_links.add(absolute.split("#", 1)[0])
                else:
                    external_links.add(absolute.split("#", 1)[0])

            # JavaScript endpoint extraction (AJAX-spider pass): fetch/axios/
            # XHR targets hidden inside the page and any same-host .js files
            # it references. These are attack surface a plain <a href> crawler
            # never sees.
            js_endpoints, js_files = extract_from_page(response.text, base, {urlsplit(base).hostname or ""})
            for endpoint in js_endpoints:
                if endpoint.startswith(("http://", "https://")):
                    if self.in_scope(endpoint):
                        queue.append((endpoint.split("#", 1)[0], depth + 1))
                    else:
                        external_links.add(endpoint.split("#", 1)[0])
            for js_file in js_files:
                if self.in_scope(js_file):
                    queue.append((js_file.split("#", 1)[0], depth + 1))

            for form in extractor.forms:
                action = urljoin(base, form["action"] or clean)
                fields: dict[str, str] = {}
                for input_ in form["inputs"]:
                    if input_["name"]:
                        fields[input_["name"]] = input_["value"]
                # GET forms are just query strings, so feed them back into the queue.
                if form["method"] == "GET":
                    query = urlencode(fields)
                    queue.append((f"{action}?{query}" if query else action, depth + 1))
                forms.append({"action": action, "method": form["method"], "fields": fields})

        return {
            "pages": pages,
            "forms": forms,
            "visited": sorted(visited),
            "external_links": sorted(external_links),
            "errors": errors,
        }
