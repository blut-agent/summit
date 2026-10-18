"""YAML-based template engine - the Nuclei-equivalence gap.

Templates let anyone write custom checks without Python. Each template
specifies what to match and - critically - what makes a match
`confirmed` vs `needs-manual`. The loader refuses to load templates
with HIGH/CRITICAL severity that don't specify a confidence rule,
because custom templates are the #1 way false positives creep back in.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from .. import __version__
from ..http.client import HttpClient
from ..http.models import HttpRequest, HttpResponse
from ..scan.core import Finding
from ..waf_block import is_probe_blocked

_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_VALID_CONFIDENCES = {"confirmed", "likely", "needs-manual", "info"}
_VALID_MATCHER_TYPES = {"word", "regex", "status", "dsl"}
_VALID_PARTS = {"body", "header", "status"}


class TemplateError(Exception):
    """Raised when a template is invalid or fails validation."""


@dataclass
class TemplateMatcher:
    type: str  # word | regex | status | dsl
    part: str  # body | header | status
    condition: str  # the value to match (word, regex pattern, status code)
    negative: bool = False  # if True, the match must NOT be present


@dataclass
class TemplateRequest:
    method: str
    path: str
    headers: dict[str, str]
    body: str | None
    matchers: list[TemplateMatcher]
    matchers_condition: str  # and | or


@dataclass
class Template:
    id: str
    name: str
    severity: str
    description: str
    confidence: str
    confidence_rule: str
    cwe: str
    cve: list[str]
    tags: list[str]
    requests: list[TemplateRequest]
    impact: str
    remediation: str
    path: str


def load_template(path: str) -> Template:
    """Load and validate a single YAML template."""
    file = Path(path)
    if not file.exists():
        raise TemplateError(f"template file not found: {path}")
    raw = yaml.safe_load(file.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise TemplateError(f"{path}: expected a YAML object")
    return _parse_template(raw, path)


def load_templates(directory: str) -> list[Template]:
    """Load all .yaml templates from a directory (non-recursive)."""
    templates = []
    dir_path = Path(directory)
    if not dir_path.is_dir():
        raise TemplateError(f"template directory not found: {directory}")
    for file in sorted(dir_path.glob("*.yaml")):
        templates.append(load_template(str(file)))
    return templates


def validate_template(path: str) -> list[str]:
    """Validate a template and return a list of errors (empty = valid)."""
    errors = []
    try:
        template = load_template(path)
    except TemplateError as exc:
        return [str(exc)]
    except Exception as exc:
        return [f"{path}: YAML parse error: {exc}"]

    if not template.confidence_rule:
        if template.severity in ("high", "critical"):
            errors.append(f"{path}: HIGH/CRITICAL template missing 'confidence-rule' - "
                          "specify what makes a match confirmed vs needs-manual")
    if not template.requests:
        errors.append(f"{path}: no requests defined")

    for i, req in enumerate(template.requests):
        for matcher in req.matchers:
            if matcher.type not in _VALID_MATCHER_TYPES:
                errors.append(f"{path}: request[{i}] invalid matcher type: {matcher.type}")
            if matcher.part not in _VALID_PARTS:
                errors.append(f"{path}: request[{i}] invalid matcher part: {matcher.part}")

    return errors


def _parse_template(raw: dict, path: str) -> Template:
    # Required fields
    template_id = raw.get("id", "")
    if not template_id:
        raise TemplateError(f"{path}: missing 'id' field")

    info = raw.get("info", {})
    if not isinstance(info, dict):
        raise TemplateError(f"{path}: 'info' must be an object")

    name = info.get("name", "")
    severity = info.get("severity", "info").lower()
    if severity not in _VALID_SEVERITIES:
        raise TemplateError(f"{path}: invalid severity '{severity}'")

    confidence = info.get("confidence", "needs-manual").lower()
    if confidence not in _VALID_CONFIDENCES:
        raise TemplateError(f"{path}: invalid confidence '{confidence}'")

    confidence_rule = info.get("confidence-rule", "")
    if severity in ("high", "critical") and not confidence_rule:
        raise TemplateError(
            f"{path}: HIGH/CRITICAL template missing 'confidence-rule' in info. "
            "Specify what makes a match confirmed vs needs-manual. "
            "Example: confidence-rule: 'baseline divergence + raw content proof'"
        )

    description = info.get("description", "")
    references = info.get("references", [])
    # references is parsed for future use in report generation
    _ = references
    cwe = info.get("classification", {}).get("cwe-id", "") if isinstance(info.get("classification"), dict) else ""
    cve = info.get("classification", {}).get("cve-id", []) if isinstance(info.get("classification"), dict) else []
    if isinstance(cve, str):
        cve = [cve]
    tags = info.get("tags", [])

    impact = info.get("impact", "")
    remediation = info.get("remediation", "")

    # Parse requests
    requests_raw = raw.get("requests", [])
    if not isinstance(requests_raw, list):
        raise TemplateError(f"{path}: 'requests' must be a list")

    parsed_requests: list[TemplateRequest] = []
    for req_raw in requests_raw:
        if not isinstance(req_raw, dict):
            continue
        method = req_raw.get("method", "GET").upper()
        path_template = req_raw.get("path", "/")
        headers = req_raw.get("headers", {})
        body = req_raw.get("body")
        matchers_condition = req_raw.get("matchers-condition", "or").lower()
        if matchers_condition not in ("and", "or"):
            matchers_condition = "or"

        matchers: list[TemplateMatcher] = []
        for m_raw in req_raw.get("matchers", []):
            if not isinstance(m_raw, dict):
                continue
            m_type = m_raw.get("type", "word").lower()
            m_part = m_raw.get("part", "body").lower()
            m_negative = m_raw.get("negative", False)
            condition = ""
            if m_type == "word":
                words = m_raw.get("words", [])
                condition = "|".join(str(w) for w in words)
            elif m_type == "regex":
                condition = m_raw.get("regex", "")
            elif m_type == "status":
                condition = str(m_raw.get("status", ""))
            elif m_type == "dsl":
                condition = m_raw.get("dsl", "")
            matchers.append(TemplateMatcher(type=m_type, part=m_part, condition=condition, negative=m_negative))

        parsed_requests.append(TemplateRequest(
            method=method, path=path_template, headers=headers,
            body=body, matchers=matchers, matchers_condition=matchers_condition,
        ))

    return Template(
        id=template_id, name=name, severity=severity,
        description=description, confidence=confidence,
        confidence_rule=confidence_rule, cwe=cwe, cve=cve,
        tags=tags, requests=parsed_requests,
        impact=impact, remediation=remediation, path=path,
    )


def _match_content(response: HttpResponse, matcher: TemplateMatcher) -> bool:
    """Evaluate a single matcher against the response."""
    if matcher.type == "status":
        try:
            expected = int(matcher.condition)
            matched = response.status == expected
        except ValueError:
            matched = False
    elif matcher.type == "word":
        words = matcher.condition.split("|")
        if matcher.part == "body":
            body = response.text.lower()
            matched = any(word.lower() in body for word in words if word)
        elif matcher.part == "header":
            matched = any(word.lower() in response.headers_text().lower() for word in words if word)
        else:
            matched = False
    elif matcher.type == "regex":
        try:
            pattern = re.compile(matcher.condition, re.IGNORECASE)
            if matcher.part == "body":
                matched = bool(pattern.search(response.text[:100_000]))
            elif matcher.part == "header":
                matched = bool(pattern.search(response.headers_text()))
            else:
                matched = False
        except re.error:
            matched = False
    elif matcher.type == "dsl":
        # Basic DSL: 'status == 200' or 'contains(body, "word")'
        try:
            if "status ==" in matcher.condition:
                expected = int(matcher.condition.split("==")[1].strip())
                matched = response.status == expected
            elif "contains(" in matcher.condition:
                inner = matcher.condition.split("contains(")[1].split(")")[0].strip().strip("'\"")
                matched = inner.lower() in response.text[:100_000].lower()
            else:
                matched = False
        except (ValueError, IndexError):
            matched = False
    else:
        matched = False

    if matcher.negative:
        return not matched
    return matched


def run_template(
    template: Template,
    client: HttpClient,
    target_url: str,
    baseline_response: HttpResponse | None = None,
) -> list[Finding]:
    """Run a template against a target URL and return findings."""
    findings: list[Finding] = []
    split = urlsplit(target_url)
    origin = f"{split.scheme}://{split.netloc}"

    for req_template in template.requests:
        # Resolve {{BaseURL}} placeholder
        resolved_path = req_template.path.replace("{{BaseURL}}", origin)
        full_url = resolved_path

        # Build headers (template headers + defaults)
        headers = dict(req_template.headers)
        headers.setdefault("User-Agent", f"Summit/{__version__} (+https://github.com/pennacle-security/summit)")

        # Build body
        body = req_template.body.encode("utf-8") if req_template.body else None

        # Send the request
        request = HttpRequest(
            method=req_template.method,
            url=full_url,
            headers=headers,
            body=body,
        )
        response = client.send(request)

        # WAF block guard: skip if the response is a WAF block page
        if is_probe_blocked(response):
            continue

        # Evaluate matchers
        if req_template.matchers:
            if req_template.matchers_condition == "and":
                matched = all(_match_content(response, m) for m in req_template.matchers)
            else:
                matched = any(_match_content(response, m) for m in req_template.matchers)
        else:
            matched = False

        if not matched:
            continue

        # Build the finding
        poc_lines = [f"{req_template.method} {full_url}"]
        for key, value in headers.items():
            poc_lines.append(f"  {key}: {value}")
        if body:
            poc_lines.append(f"  Body: {body[:200]}")
        poc = "\n".join(poc_lines)
        poc += f"\n# Response: HTTP {response.status}, {len(response.body)} bytes"

        findings.append(Finding(
            check_id=template.id,
            title=template.name,
            severity=template.severity,
            url=full_url,
            confidence=template.confidence,
            detail=template.description,
            evidence=f"HTTP {response.status}, matched by template {template.id}",
            remediation=template.remediation,
            cwe=template.cwe,
            cves=list(template.cve),
            impact=template.impact,
            poc=poc,
            verification_steps=template.confidence_rule,
        ))

