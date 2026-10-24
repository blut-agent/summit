"""v1.4.0 regressions: live progress, template evidence rules, metadata."""

from __future__ import annotations

import io
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from summit.http.client import HttpClient
from summit.progress import ProgressReporter
from summit.templates import (
    load_template,
    load_templates,
    run_template,
    validate_template,
)

BUILTIN = Path(__file__).resolve().parent.parent / "summit" / "templates" / "builtin"


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server API
        body = b"summit-template-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # keep test output clean
        return


def _template_text(**overrides: str) -> str:
    values = {
        "id": "test-template",
        "severity": "medium",
        "confidence": "needs-manual",
        "cwe": "CWE-200",
        "cve": "",
        "tags": "[test]",
        "matcher": "word",
        "words": "[summit-template-ok]",
        "status": "[200]",
    }
    values.update(overrides)
    return f"""\
id: {values['id']}
info:
  name: Test template
  severity: {values['severity']}
  description: A test template.
  confidence: {values['confidence']}
  classification:
    cwe-id: {values['cwe']}
{f"    cve-id: {values['cve']}" if values['cve'] else ''}
  tags: {values['tags']}
requests:
  - method: GET
    path:
      - '{{{{BaseURL}}}}/probe?x=1'
    matchers:
      - type: {values['matcher']}
        part: body
        words: {values['words']}
        status: {values['status']}
"""


def _write_template(tmp_path: Path, text: str, name: str = "test.yaml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def _start_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


@pytest.fixture
def http_server():
    server, thread = _start_server()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_progress_reporter_shows_each_request_url_on_a_tty():
    stream = io.StringIO()
    reporter = ProgressReporter(enabled=True, stream=stream, tty=True, width=120)

    reporter.phase("SCAN", 2)
    reporter.task("sqli", "GET", "https://example.test/search?q=1")
    reporter.hit(1)
    reporter.task("xss", "GET", "https://example.test/search?q=2")
    reporter.finish()

    output = stream.getvalue()
    assert "https://example.test/search?q=1" in output
    assert "[SCAN]" in output
    assert "\r" in output
    assert "+1" in output


def test_progress_reporter_keeps_complete_lines_when_piped():
    stream = io.StringIO()
    reporter = ProgressReporter(enabled=True, stream=stream, tty=False)

    reporter.phase("TEMPLATES", 1)
    reporter.event("exposed-git-config", "GET", "https://example.test/.git/config")
    reporter.finish("[TEMPLATES] 1 template(s)")

    lines = stream.getvalue().splitlines()
    assert any("https://example.test/.git/config" in line for line in lines)
    assert "[TEMPLATES] 1 template(s)" in lines
    assert "\r" not in stream.getvalue()


def test_disabled_progress_is_silent():
    stream = io.StringIO()
    reporter = ProgressReporter(enabled=False, stream=stream, tty=True)
    reporter.phase("SCAN", 1)
    reporter.task("sqli", "GET", "https://example.test/")
    reporter.finish("done")
    assert stream.getvalue() == ""


def test_run_template_reports_the_real_request_url(tmp_path, http_server):
    path = _write_template(
        tmp_path,
        _template_text(),
    )
    seen: list[tuple[str, str]] = []

    findings = run_template(
        load_template(str(path)),
        HttpClient(timeout=3),
        http_server,
        on_request=lambda method, url: seen.append((method, url)),
    )

    assert len(findings) == 1
    assert seen == [("GET", f"{http_server}/probe?x=1")]


def test_validator_rejects_missing_cwe(tmp_path):
    path = _write_template(tmp_path, _template_text(cwe=""))
    assert any("cwe-id" in error for error in validate_template(str(path)))


def test_validator_rejects_cve_tag_without_cve_id(tmp_path):
    path = _write_template(tmp_path, _template_text(tags="[cve]", cve=""))
    assert any("cve-id" in error for error in validate_template(str(path)))


def test_validator_rejects_cve_id_without_cve_tag(tmp_path):
    path = _write_template(
        tmp_path,
        _template_text(tags="[test]", cve="CVE-2024-4577"),
    )
    assert any("'cve' tag" in error for error in validate_template(str(path)))


def test_validator_rejects_status_only_confirmed_template(tmp_path):
    path = _write_template(
        tmp_path,
        _template_text(confidence="confirmed", matcher="status", words="[]"),
    )
    assert any("status code alone" in error for error in validate_template(str(path)))


def test_all_builtin_templates_have_consistent_cwe_and_cve_metadata():
    templates = load_templates(str(BUILTIN))
    assert len(templates) == 37
    for template in templates:
        assert template.cwe, template.path
        if "cve" in {tag.lower() for tag in template.tags}:
            assert template.cve, template.path
