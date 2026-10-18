"""URL normalization for dedup and comparison.

Removes fragments, sorts query params, strips trailing punctuation,
and decodes HTML entities so that duplicate findings collapse into
one entry.
"""

from __future__ import annotations

import html
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# Trailing punctuation that our own extractor sometimes leaves behind
_TRAILING_JUNK = ".,;:)]}>'\""


def normalize_url(url: str) -> str:
    """Normalize a URL for comparison: strip fragments, sort query params,
    remove trailing junk, collapse duplicate slashes in the path."""
    url = url.split("#", 1)[0]  # remove fragment
    url = html.unescape(url)  # decode HTML entities
    url = url.rstrip(_TRAILING_JUNK)  # strip trailing punctuation
    split = urlsplit(url)
    path = re.sub(r"/{2,}", "/", split.path)  # collapse duplicate slashes
    # Sort query params for consistent ordering
    pairs = sorted(parse_qsl(split.query, keep_blank_values=True))
    query = urlencode(pairs) if pairs else ""
    return urlunsplit((split.scheme, split.netloc, path, query, ""))


def dedup_findings(findings: list) -> list:
    """Deduplicate findings by (check_id, normalized host, normalized evidence).
    Multiple findings with the same key are merged into one with affected_urls[]."""
    from .scan.core import Finding

    deduped: dict[tuple, Finding] = {}
    for finding in findings:
        normalized_url = normalize_url(finding.url)
        host = urlsplit(normalized_url).hostname or ""
        key = (finding.check_id, host, finding.evidence[:100])
        if key in deduped:
            existing = deduped[key]
            if normalized_url not in existing.affected_urls:
                existing.affected_urls.append(normalized_url)
                existing.affected_urls.append(finding.url)
        else:
            finding.affected_urls = [normalized_url]
            deduped[key] = finding
    return list(deduped.values())


def check_placeholder_sanity(findings: list) -> list[str]:
    """Check for unrendered {placeholder} patterns in finding text.
    Returns a list of error descriptions for findings with unrendered templates."""
    errors = []
    placeholder_re = re.compile(r"\{[a-z_]+\}")
    for finding in findings:
        for field_name in ("title", "detail", "evidence", "remediation", "impact"):
            value = getattr(finding, field_name, "")
            if isinstance(value, str):
                matches = placeholder_re.findall(value)
                if matches:
                    errors.append(
                        f"{finding.check_id}.{field_name}: unrendered placeholder(s) {matches} "
                        f"in: {value[:100]}"
                    )
    return errors
