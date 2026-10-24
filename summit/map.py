"""Attack-surface mapping without exploitation.

`summit map` answers the first question on an engagement: *what is
actually here?* It walks the target once, then inventories the pages,
forms, parameters, JavaScript endpoints, technologies and outbound
links it can see. No attack traffic, no templates, no exploitation -
just a clean map you can hand to the rest of the scan.

The module is deliberately dependency-free and human-readable: one
crawl, a few dicts, and writers that never invent findings.
"""

from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urlsplit

from .crawl.spider import Spider
from .fingerprint import fingerprint
from .http.client import HttpClient
from .http.models import HttpResponse
from .scan.engine import build_targets

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _title(response: HttpResponse) -> str:
    match = _TITLE_RE.search(response.text[:20_000])
    if not match:
        return ""
    return " ".join(match.group(1).split())[:200]


def _page(response: HttpResponse) -> dict:
    return {
        "url": response.request.url,
        "status": response.status,
        "bytes": len(response.body),
        "title": _title(response),
        "content_type": response.header("content-type"),
        "params": sorted(response.request.params),
        "technologies": fingerprint(response),
    }


def _unique_technologies(pages: list[dict]) -> list[dict]:
    seen: set[tuple[str, str, str]] = set()
    items: list[dict] = []
    for page in pages:
        for tech in page["technologies"]:
            key = (tech["category"], tech["name"], tech["version"])
            if key in seen:
                continue
            seen.add(key)
            items.append(tech)
    return items


def map_target(
    client: HttpClient,
    url: str,
    *,
    max_depth: int = 3,
    max_pages: int = 50,
    on_page: Callable[[str], None] | None = None,
) -> dict:
    """Crawl one target and return a structured attack-surface map."""
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError("map needs an absolute http:// or https:// URL")
    if urlsplit(url).hostname is None:
        raise ValueError(f"map needs a valid target hostname: {url}")

    spider = Spider(client, max_depth=max_depth, max_pages=max_pages, on_page=on_page)
    result = spider.crawl(url)
    pages = [_page(response) for response in result["pages"]]
    # build_targets is read-only in spirit, but it records skipped trackers
    # on the spider result. Give it a copy so the public map stays clean.
    points = build_targets(dict(result))

    return {
        "target": url,
        "generated": datetime.now(timezone.utc).isoformat(),
        "pages": pages,
        "forms": result["forms"],
        "visited": result["visited"],
        "external_links": result["external_links"],
        "technologies": _unique_technologies(pages),
        "injection_points": [
            {
                "url": point.request.url,
                "method": point.request.method,
                "param": point.param,
                "location": point.location,
                "value": point.original_value,
            }
            for point in points
        ],
        "notes": result.get("notes", []),
        "errors": result["errors"],
        "summary": {
            "pages": len(pages),
            "forms": len(result["forms"]),
            "visited": len(result["visited"]),
            "external_links": len(result["external_links"]),
            "technologies": len(_unique_technologies(pages)),
            "injection_points": len(points),
            "errors": len(result["errors"]),
        },
    }


def _write(path: str, text: str) -> str:
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return path


def write_map_json(surface: dict, path: str) -> str:
    payload = dict(surface)
    payload["generated"] = datetime.now(timezone.utc).isoformat()
    return _write(path, json.dumps(payload, indent=2) + "\n")


def write_map_markdown(surface: dict, path: str) -> str:
    lines = [
        f"# Attack surface map - {surface['target']}",
        "",
        f"Generated: {surface['generated']}",
        "",
        "| Metric | Count |",
        "|---|---:|",
    ]
    for key, value in surface["summary"].items():
        lines.append(f"| {key.replace('_', ' ').capitalize()} | {value} |")
    lines.extend(["", "## Pages", "", "| URL | Status | Bytes | Title | Params |", "|---|---:|---:|---|---|"])
    for page in surface["pages"]:
        params = ", ".join(page["params"]) or "-"
        lines.append(f"| `{page['url']}` | {page['status']} | {page['bytes']} | {page['title'] or '-'} | {params} |")
    if surface["forms"]:
        lines.extend(["", "## Forms", "", "| Action | Method | Fields |", "|---|---|---|"])
        for form in surface["forms"]:
            fields = ", ".join(form.get("fields", {}).keys()) or "-"
            lines.append(f"| `{form.get('action', '')}` | {form.get('method', '')} | {fields} |")
    if surface["injection_points"]:
        lines.extend(["", "## Injection points", "", "| URL | Method | Param | Location |", "|---|---|---|---|"])
        for point in surface["injection_points"]:
            lines.append(f"| `{point['url']}` | {point['method']} | `{point['param']}` | {point['location']} |")
    if surface["technologies"]:
        lines.extend(["", "## Technologies", "", "| Category | Name | Version |", "|---|---|---|"])
        for tech in surface["technologies"]:
            lines.append(f"| {tech['category']} | {tech['name']} | {tech['version'] or '-'} |")
    if surface["external_links"]:
        lines.extend(["", "## External links", ""])
        lines.extend(f"- {link}" for link in surface["external_links"])
    if surface["errors"]:
        lines.extend(["", "## Errors", ""])
        lines.extend(f"- {error}" for error in surface["errors"])
    return _write(path, "\n".join(lines) + "\n")


def write_map_html(surface: dict, path: str) -> str:
    def esc(value) -> str:
        return html.escape(str(value), quote=True)

    page_rows = "".join(
        "<tr>"
        f"<td><code>{esc(page['url'])}</code></td>"
        f"<td>{esc(page['status'])}</td>"
        f"<td>{esc(page['bytes'])}</td>"
        f"<td>{esc(page['title'] or '-')}</td>"
        f"<td>{esc(', '.join(page['params']) or '-')}</td>"
        "</tr>"
        for page in surface["pages"]
    )
    form_rows = "".join(
        "<tr>"
        f"<td><code>{esc(form.get('action', ''))}</code></td>"
        f"<td>{esc(form.get('method', ''))}</td>"
        f"<td>{esc(', '.join(form.get('fields', {}).keys()) or '-')}</td>"
        "</tr>"
        for form in surface["forms"]
    )
    point_rows = "".join(
        "<tr>"
        f"<td><code>{esc(point['url'])}</code></td>"
        f"<td>{esc(point['method'])}</td>"
        f"<td><code>{esc(point['param'])}</code></td>"
        f"<td>{esc(point['location'])}</td>"
        "</tr>"
        for point in surface["injection_points"]
    )
    tech_rows = "".join(
        "<tr>"
        f"<td>{esc(tech['category'])}</td>"
        f"<td>{esc(tech['name'])}</td>"
        f"<td>{esc(tech['version'] or '-')}</td>"
        "</tr>"
        for tech in surface["technologies"]
    )
    cards = "".join(
        f"<div class='card'><div class='n'>{esc(value)}</div><div class='l'>{esc(key.replace('_', ' '))}</div></div>"
        for key, value in surface["summary"].items()
    )
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Attack surface map - {esc(surface['target'])}</title>
<style>
:root {{ color-scheme: dark; }}
body {{ margin:0; background:#070b14; color:#e2e8f0; font-family:-apple-system,'Segoe UI',Roboto,sans-serif; }}
.wrap {{ max-width:1080px; margin:0 auto; padding:40px 24px 80px; }}
h1 {{ font-size:1.35rem; margin:.35rem 0 .25rem; }}
.sub {{ color:#94a3b8; margin:0 0 24px; }}
.cards {{ display:flex; flex-wrap:wrap; gap:10px; margin-bottom:24px; }}
.card {{ background:#0f172a; border:1px solid #1e293b; border-radius:10px; padding:10px 16px; min-width:92px; }}
.card .n {{ font-size:1.3rem; font-weight:700; }}
.card .l {{ font-size:.7rem; color:#94a3b8; text-transform:uppercase; }}
h2 {{ font-size:1rem; margin:32px 0 10px; color:#f1f5f9; }}
table {{ border-collapse:collapse; width:100%; }}
th, td {{ padding:8px 10px; border-bottom:1px solid #131c30; font-size:.85rem; text-align:left; vertical-align:top; }}
th {{ color:#94a3b8; text-transform:uppercase; font-size:.7rem; }}
code {{ color:#7dd3fc; word-break:break-all; }}
.empty {{ color:#94a3b8; }}
</style>
</head>
<body><div class="wrap">
<h1>Attack surface map</h1>
<p class="sub">Target: <code>{esc(surface['target'])}</code> &middot; Generated: {esc(surface['generated'])}</p>
<div class="cards">{cards}</div>
<h2>Pages</h2>
<table><thead><tr><th>URL</th><th>Status</th><th>Bytes</th><th>Title</th><th>Params</th></tr></thead>
<tbody>{page_rows or '<tr><td colspan="5" class="empty">No pages crawled.</td></tr>'}</tbody></table>
<h2>Forms</h2>
<table><thead><tr><th>Action</th><th>Method</th><th>Fields</th></tr></thead>
<tbody>{form_rows or '<tr><td colspan="3" class="empty">No forms found.</td></tr>'}</tbody></table>
<h2>Injection points</h2>
<table><thead><tr><th>URL</th><th>Method</th><th>Param</th><th>Location</th></tr></thead>
<tbody>{point_rows or '<tr><td colspan="4" class="empty">No parameters mapped.</td></tr>'}</tbody></table>
<h2>Technologies</h2>
<table><thead><tr><th>Category</th><th>Name</th><th>Version</th></tr></thead>
<tbody>{tech_rows or '<tr><td colspan="3" class="empty">No technologies fingerprinted.</td></tr>'}</tbody></table>
</div></body></html>
"""
    return _write(path, document)
