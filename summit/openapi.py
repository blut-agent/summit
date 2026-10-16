"""OpenAPI / Swagger-driven scanning.

Modern APIs ship their own attack surface map: the OpenAPI document.
Feed it to summit and every documented endpoint becomes a scan target
with its query parameters filled from examples and defaults - no
crawling, no guessing, complete coverage of what the API admits to.

JSON specs are supported natively. YAML specs need converting to JSON
first (this project keeps its dependency list at exactly one).
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlencode

from .http.models import HttpRequest

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def load_spec(path: str) -> dict:
    document = Path(path).read_text(encoding="utf-8")
    try:
        return json.loads(document)
    except json.JSONDecodeError:
        pass
    # Not JSON - try YAML (pyyaml is an optional integration; the error is
    # explicit when it is missing).
    try:
        import yaml
    except ImportError as exc:
        raise ValueError(
            f"{path} is not valid JSON, and PyYAML is not installed to read YAML specs "
            f"({exc}). Install it with `pip install pyyaml`, or convert the spec to JSON."
        ) from exc
    spec = yaml.safe_load(document)
    if not isinstance(spec, dict):
        raise ValueError(f"{path} did not parse into an OpenAPI object")
    return spec


def _example_for(param: dict) -> str:
    schema = param.get("schema") or {}
    for candidate in (param.get("example"), schema.get("example"), schema.get("default")):
        if candidate is not None:
            return str(candidate)
    return "1"


def build_requests(spec: dict, base_url: str | None = None) -> list[HttpRequest]:
    """Turn paths+methods+parameters into concrete HttpRequest targets."""
    if base_url is None:
        servers = spec.get("servers") or []
        base_url = servers[0].get("url", "http://localhost") if servers else "http://localhost"

    targets: list[HttpRequest] = []
    seen: set[tuple[str, str]] = set()
    for path, methods in (spec.get("paths") or {}).items():
        shared_params = methods.get("parameters") or []
        for method, operation in methods.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(operation, dict):
                continue
            url_path = path
            query_pairs: list[tuple[str, str]] = []
            for param in list(shared_params) + list(operation.get("parameters") or []):
                location = param.get("in")
                name = param.get("name")
                if not name:
                    continue
                value = _example_for(param)
                if location == "path":
                    url_path = url_path.replace("{" + name + "}", value)
                elif location == "query":
                    query_pairs.append((name, value))
            full_url = base_url.rstrip("/") + url_path
            if query_pairs:
                full_url += "?" + urlencode(query_pairs)
            key = (method.upper(), full_url)
            if key in seen:
                continue
            seen.add(key)
            targets.append(HttpRequest(method=method.upper(), url=full_url))
    return targets


def spec_pages(client, spec: dict, base_url: str | None = None):
    """Send every built target and return spider_result-shaped pages for the engine."""
    pages = []
    errors: list[str] = []
    for request in build_requests(spec, base_url):
        try:
            pages.append(client.send(request))
        except Exception as exc:
            errors.append(f"{request.method} {request.url}: {exc}")
    return {
        "pages": pages,
        "forms": [],
        "visited": [p.request.url for p in pages],
        "external_links": [],
        "errors": errors,
    }
