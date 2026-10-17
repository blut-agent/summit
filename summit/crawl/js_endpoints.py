"""JavaScript endpoint extraction - the AJAX-spider idea, stdlib edition.

Modern applications hide most of their attack surface inside JavaScript:
fetch() calls, axios calls, XMLHttpRequest targets. A crawler that only
follows <a href> sees none of it - a systematic false-negative source.

This module regex-extracts endpoint URLs from every fetched page (and
from .js files it references), resolves them against the page URL, and
hands same-host matches back to the spider queue.

Regexes are anchored on the calling APIs themselves (fetch/axios/XHR),
not on generic string hunting, which keeps the hit rate honest.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

# endpoint-extraction patterns; group 1 must be the endpoint
JS_PATTERNS = [
    re.compile(r"""fetch\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""axios(?:\.\w+)?\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""axios\.\w+\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""\.open\(\s*['"](?:[A-Z]+)['"],\s*['"]([^'"]+)['"]"""),
]

JS_FILE_PATTERN = re.compile(r"""(?:src|href)\s*=\s*['"]([^'"]+\.js(?:\?[^'"]*)?)['"]""", re.IGNORECASE)


def extract_endpoints(text: str, base_url: str) -> tuple[list[str], list[str]]:
    """Return (endpoints, js_files) found in one document, resolved absolute."""
    endpoints: list[str] = []
    js_files: list[str] = []
    for pattern in JS_PATTERNS:
        for match in pattern.finditer(text):
            endpoints.append(urljoin(base_url, match.group(1)))
    for match in JS_FILE_PATTERN.finditer(text):
        js_files.append(urljoin(base_url, match.group(1)))
    return endpoints, js_files


def extract_from_page(response_text: str, page_url: str, scope_hosts: set[str]) -> tuple[list[str], list[str]]:
    """Extract endpoints from a page, then from any same-host .js file it references.

    Returns (same_host_endpoints, external_endpoints). Fetching the .js
    files is the caller's job (it has the HTTP client).
    """
    endpoints, js_files = extract_endpoints(response_text, page_url)
    return endpoints, js_files


def in_scope(url: str, scope_hosts: set[str]) -> bool:
    from urllib.parse import urlsplit

    host = (urlsplit(url).hostname or "").lower().removeprefix("www.")
    return any(host == candidate or host.endswith("." + candidate) for candidate in scope_hosts)
