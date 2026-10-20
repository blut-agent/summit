"""YAML check templates - Nuclei-style detection logic without Python.

Templates let anyone write custom checks without touching the scanner.
Each template lists HTTP requests and matchers; the matcher set has to
prove the issue, not hint at it - a bare 200 never counts. Templates
that claim HIGH or CRITICAL severity must also state their confidence
rule, because custom templates are the easiest way for false positives
to creep back into a report.

Supported matchers: word, regex, status, dsl. Supported DSL:
`status == 200`, `status != 403`, `contains(body, "text")`,
`contains(header, "text")`, `len(body) > 1000`. Placeholders:
{{BaseURL}}, {{Host}}, {{Hostname}}, {{Scheme}}, {{Port}}, {{Path}},
{{File}}. `path` may be a list, and `stop-at-first-match` /
`follow-redirects` behave like their Nuclei counterparts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
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

_PLACEHOLDER_RE = re.compile(
    r"\{\{\s*(BaseURL|Hostname|Host|Port|Scheme|Path|File)\s*\}\}", re.IGNORECASE
)
_DSL_STATUS_RE = re.compile(r"^status\s*(==|!=)\s*(\d{3})$", re.IGNORECASE)
_DSL_CONTAINS_RE = re.compile(
    r"^contains\(\s*(body|header)\s*,\s*[\"'](.+)[\"']\s*\)$", re.IGNORECASE
)
_DSL_LEN_RE = re.compile(r"^len\(\s*body\s*\)\s*(>=|<=|>|<)\s*(\d+)$", re.IGNORECASE)


class TemplateError(Exception):
    """Raised when a template is invalid or fails validation."""


@dataclass
class TemplateMatcher:
    type: str  # word | regex | status | dsl
    part: str = "body"  # body | header | status
    words: list[str] = field(default_factory=list)
    regex: str = ""
    statuses: list[int] = field(default_factory=list)
    dsl: str = ""
    match_all: bool = False  # word matcher `condition: and`
    negative: bool = False  # the matcher must NOT hold


@dataclass
class TemplateRequest:
    method: str
    paths: list[str]
    headers: dict[str, str]
    body: str | None
    matchers: list[TemplateMatcher]
    matchers_condition: str  # and | or
    follow_redirects: bool = False


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
    stop_at_first_match: bool = False


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
        if not req.paths:
            errors.append(f"{path}: request[{i}] has no path")
        for matcher in req.matchers:
            if matcher.type not in _VALID_MATCHER_TYPES:
                errors.append(f"{path}: request[{i}] invalid matcher type: {matcher.type}")
                continue
            if matcher.part not in _VALID_PARTS:
                errors.append(f"{path}: request[{i}] invalid matcher part: {matcher.part}")
            if matcher.type == "word" and not matcher.words:
                errors.append(f"{path}: request[{i}] word matcher has no words")
            if matcher.type == "regex":
                if not matcher.regex:
                    errors.append(f"{path}: request[{i}] regex matcher has no pattern")
                else:
                    try:
                        re.compile(matcher.regex)
                    except re.error as exc:
                        errors.append(f"{path}: request[{i}] invalid regex: {exc}")
            if matcher.type == "status" and not matcher.statuses:
                errors.append(f"{path}: request[{i}] status matcher has no status")
            if matcher.type == "dsl" and not _dsl_supported(matcher.dsl):
                errors.append(
                    f"{path}: request[{i}] unsupported dsl: {matcher.dsl!r} "
                    "(supported: status ==/!= N, contains(body|header, \"text\"), len(body) >/</>=/<= N)"
                )

    return errors


def _as_bool(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _parse_statuses(value) -> list[int]:
    values = value if isinstance(value, list) else [value]
    statuses: list[int] = []
    for item in values:
        try:
            statuses.append(int(str(item).strip()))
        except (TypeError, ValueError):
            continue
    return statuses


def _dsl_supported(expression: str) -> bool:
    expr = expression.strip()
    return bool(
        _DSL_STATUS_RE.match(expr)
        or _DSL_CONTAINS_RE.match(expr)
        or _DSL_LEN_RE.match(expr)
    )


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
    classification = info.get("classification", {})
    if not isinstance(classification, dict):
        classification = {}
    cwe = classification.get("cwe-id", "")
    cve = classification.get("cve-id", [])
    if isinstance(cve, str):
        cve = [cve]
    tags = info.get("tags", [])
    impact = info.get("impact", "")
    remediation = info.get("remediation", "")
    stop_at_first_match = _as_bool(raw.get("stop-at-first-match", False))

    # Parse requests
    requests_raw = raw.get("requests", [])
    if not isinstance(requests_raw, list):
        raise TemplateError(f"{path}: 'requests' must be a list")

    parsed_requests: list[TemplateRequest] = []
    for req_raw in requests_raw:
        if not isinstance(req_raw, dict):
            continue
        method = str(req_raw.get("method", "GET")).upper()
        paths_raw = req_raw.get("path", "/")
        paths = [str(p) for p in paths_raw] if isinstance(paths_raw, list) else [str(paths_raw)]
        headers_raw = req_raw.get("headers", {})
        headers = {str(k): str(v) for k, v in headers_raw.items()} if isinstance(headers_raw, dict) else {}
        body = req_raw.get("body")
        body = str(body) if body is not None else None
        matchers_condition = str(req_raw.get("matchers-condition", "or")).lower()
        if matchers_condition not in ("and", "or"):
            raise TemplateError(f"{path}: invalid matchers-condition '{matchers_condition}' (and|or)")
        follow_redirects = _as_bool(req_raw.get("follow-redirects", False))

        matchers: list[TemplateMatcher] = []
        matchers_raw = req_raw.get("matchers", [])
        if isinstance(matchers_raw, dict):
            matchers_raw = [matchers_raw]
        for m_raw in matchers_raw:
            if not isinstance(m_raw, dict):
                continue
            m_type = str(m_raw.get("type", "word")).lower()
            m_part = str(m_raw.get("part", "status" if m_type == "status" else "body")).lower()
            negative = _as_bool(m_raw.get("negative", False))
            if m_type == "word":
                words_raw = m_raw.get("words", [])
                words = [str(w) for w in words_raw] if isinstance(words_raw, list) else [str(words_raw)]
                condition = str(m_raw.get("condition", "or")).lower()
                if condition not in ("and", "or"):
                    raise TemplateError(f"{path}: invalid word condition '{condition}' (and|or)")
                matcher = TemplateMatcher(
                    type="word", part=m_part, words=words,
                    match_all=condition == "and", negative=negative,
                )
            elif m_type == "regex":
                matcher = TemplateMatcher(
                    type="regex", part=m_part, regex=str(m_raw.get("regex", "")),
                    negative=negative,
                )
            elif m_type == "status":
                matcher = TemplateMatcher(
                    type="status", part="status",
                    statuses=_parse_statuses(m_raw.get("status", [])), negative=negative,
                )
            elif m_type == "dsl":
                matcher = TemplateMatcher(
                    type="dsl", part=m_part, dsl=str(m_raw.get("dsl", "")),
                    negative=negative,
                )
            else:
                matcher = TemplateMatcher(type=m_type, part=m_part, negative=negative)
            matchers.append(matcher)

        parsed_requests.append(TemplateRequest(
            method=method, paths=paths, headers=headers, body=body,
            matchers=matchers, matchers_condition=matchers_condition,
            follow_redirects=follow_redirects,
        ))

    return Template(
        id=template_id, name=name, severity=severity,
        description=description, confidence=confidence,
        confidence_rule=confidence_rule, cwe=cwe, cve=cve,
        tags=tags, requests=parsed_requests,
        impact=impact, remediation=remediation, path=path,
        stop_at_first_match=stop_at_first_match,
    )


def _resolve_placeholders(text: str, split) -> str:
    """Substitute the Nuclei-style vars we support in paths and headers."""
    if "{{" not in text:
        return text
    default_port = "443" if split.scheme == "https" else "80"
    path = split.path or "/"
    values = {
        "baseurl": f"{split.scheme}://{split.netloc}",
        "hostname": split.hostname or "",
        "host": split.netloc,
        "port": str(split.port or default_port),
        "scheme": split.scheme,
        "path": path,
        "file": path.rsplit("/", 1)[-1],
    }
    return _PLACEHOLDER_RE.sub(lambda m: values[m.group(1).lower()], text)


def _eval_dsl(response: HttpResponse, expression: str) -> tuple[bool, str]:
    expr = expression.strip()
    match = _DSL_STATUS_RE.match(expr)
    if match:
        expected = int(match.group(2))
        matched = response.status == expected if match.group(1) == "==" else response.status != expected
        return matched, f"status {response.status}"
    match = _DSL_CONTAINS_RE.match(expr)
    if match:
        source = response.text[:100_000] if match.group(1).lower() == "body" else response.headers_text()
        needle = match.group(2)
        matched = needle.lower() in source.lower()
        return matched, f"contains({match.group(1).lower()}, {needle[:60]!r})"
    match = _DSL_LEN_RE.match(expr)
    if match:
        size = len(response.body)
        expected = int(match.group(2))
        operation = match.group(1)
        matched = {
            "<": size < expected,
            "<=": size <= expected,
            ">": size > expected,
            ">=": size >= expected,
        }[operation]
        return matched, f"len(body)={size}"
    return False, f"unsupported dsl: {expr}"


def _match_response(response: HttpResponse, matcher: TemplateMatcher) -> tuple[bool, str]:
    """Evaluate one matcher; return (matched, human-readable detail)."""
    if matcher.type == "status":
        matched = response.status in matcher.statuses
        detail = f"status {response.status}"
    elif matcher.type == "word":
        if matcher.part == "header":
            haystack = response.headers_text().lower()
        else:
            haystack = response.text[:100_000].lower()
        if matcher.match_all:
            matched = all(word.lower() in haystack for word in matcher.words if word)
        else:
            matched = any(word.lower() in haystack for word in matcher.words if word)
        hit = next((word for word in matcher.words if word.lower() in haystack), "")
        detail = f"word {hit!r}" if matched else "words not found"
    elif matcher.type == "regex":
        try:
            pattern = re.compile(matcher.regex, re.IGNORECASE)
        except re.error:
            return False, "invalid regex"
        source = response.headers_text() if matcher.part == "header" else response.text[:100_000]
        found = pattern.search(source) if matcher.part in ("body", "header") else None
        matched = bool(found)
        detail = f"regex {found.group(0)[:80]!r}" if found else "regex not matched"
    elif matcher.type == "dsl":
        matched, detail = _eval_dsl(response, matcher.dsl)
    else:
        matched, detail = False, f"unknown matcher {matcher.type}"

    if matcher.negative:
        if not matched:
            return True, f"absence confirmed ({detail})"
        return False, f"unexpected match ({detail})"
    return matched, detail


def _match_content(response: HttpResponse, matcher: TemplateMatcher) -> bool:
    """Backward-compatible boolean wrapper around _match_response."""
    return _match_response(response, matcher)[0]


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
        for path_template in req_template.paths:
            resolved_path = _resolve_placeholders(path_template, split)
            if not resolved_path.startswith(("http://", "https://")):
                resolved_path = origin + (resolved_path if resolved_path.startswith("/") else "/" + resolved_path)

            headers = {
                key: _resolve_placeholders(value, split)
                for key, value in req_template.headers.items()
            }
            headers.setdefault(
                "User-Agent",
                f"Summit/{__version__} (+https://github.com/pennacle-security/summit)",
            )
            body_text = _resolve_placeholders(req_template.body, split) if req_template.body else None
            body = body_text.encode("utf-8") if body_text else None

            request = HttpRequest(
                method=req_template.method,
                url=resolved_path,
                headers=headers,
                body=body,
            )
            try:
                response = client.send(request, allow_redirects=req_template.follow_redirects)
            except Exception:
                continue

            # WAF block guard: a block page proves nothing.
            if is_probe_blocked(response):
                continue

            if not req_template.matchers:
                continue

            results = [_match_response(response, matcher) for matcher in req_template.matchers]
            if req_template.matchers_condition == "and":
                matched = all(ok for ok, _ in results)
            else:
                matched = any(ok for ok, _ in results)

            if not matched:
                continue

            detail = next((text for ok, text in results if ok), "matchers satisfied")

            poc_lines = [f"{req_template.method} {resolved_path}"]
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
                url=resolved_path,
                confidence=template.confidence,
                detail=template.description,
                evidence=f"HTTP {response.status} · {detail}",
                remediation=template.remediation,
                cwe=template.cwe,
                cves=list(template.cve),
                impact=template.impact,
                poc=poc,
                verification_steps=template.confidence_rule,
            ))

            if template.stop_at_first_match:
                return findings

    return findings
