"""v1.1.0 regressions: colours, config, diff, OOB listener, new checks
(js-secrets, http-methods, XXE, HPP), the with_value injection-point plumbing,
the deep-mode flag, and the report writers.

Everything here is offline unless noted: the live tests bind 127.0.0.1 on
an ephemeral port and always shut down in a finally block.
"""

import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from summit import __version__, colors
from summit.banner import render_banner
from summit.config import Settings, default_config_path, load_settings, resolve_paths, save_settings
from summit.diff import diff_reports, render_diff
from summit.http.client import HttpClient
from summit.http.models import HttpRequest, HttpResponse
from summit.oob import OobServer, _extract_token, new_token
from summit.report.writer import write_html, write_json
from summit.scan import runtime
from summit.scan.core import Finding, InjectionPoint
from summit.scan.modules.http_methods import run_http_methods
from summit.scan.modules.hpp import HppCheck
from summit.scan.modules.js_secrets import check_js_secrets, detect_secrets, redact
from summit.scan.modules.xxe import find_xxe_indicator, run_xxe
from summit.templates import validate_template


def start_server(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


# --- colours ---------------------------------------------------------------


def test_severity_badge_plain_fallback_when_disabled():
    saved = colors.enabled()
    try:
        colors.set_enabled(False)
        assert colors.severity_badge("critical") == "[CRITICAL]"
    finally:
        colors.set_enabled(saved)


def test_severity_badge_16color_path_uses_background_code():
    saved_enabled, saved_truecolor = colors.enabled(), colors._truecolor
    try:
        colors.set_enabled(True)
        colors.set_truecolor(False)
        badge = colors.severity_badge("critical")
        assert "\033[101m" in badge  # bright_red background, not a foreground code
        assert colors.strip_ansi(badge).strip() == "CRITICAL"
    finally:
        colors.set_enabled(saved_enabled)
        colors.set_truecolor(saved_truecolor)


def test_strip_ansi_roundtrip():
    saved = colors.enabled()
    try:
        colors.set_enabled(True)
        painted = colors.red("hello")
        assert "\033[" in painted
        assert colors.strip_ansi(painted) == "hello"
    finally:
        colors.set_enabled(saved)


# --- config ----------------------------------------------------------------


def test_settings_roundtrip(tmp_path):
    target = tmp_path / "config.json"
    saved = Settings(workers=12, timeout=4.5, deep=True, cookie="session=abc", output_dir="reports")
    save_settings(saved, target)
    loaded = load_settings(target)
    assert loaded.to_dict() == saved.to_dict()


def test_settings_from_dict_coerces_string_numbers():
    loaded = Settings.from_dict({"workers": "12", "timeout": "4.5", "rate": "2.5"})
    assert loaded.workers == 12 and isinstance(loaded.workers, int)
    assert loaded.timeout == 4.5
    assert loaded.rate == 2.5


def test_settings_from_dict_drops_unknown_and_bad_values():
    loaded = Settings.from_dict({"unknown_key": True, "workers": "many", "headers": "not-a-dict"})
    assert loaded.workers == 8
    assert loaded.headers == {}


def test_settings_from_dict_treats_null_as_missing():
    loaded = Settings.from_dict({"workers": None, "timeout": None, "retries": None, "delay": None})
    assert (loaded.workers, loaded.timeout, loaded.retries, loaded.delay) == (8, 10.0, 1, 0.0)


def test_load_settings_corrupt_file_degrades_to_defaults(tmp_path):
    target = tmp_path / "config.json"
    target.write_text("{ definitely not json", encoding="utf-8")
    assert load_settings(target).to_dict() == Settings().to_dict()


def test_load_settings_missing_file_degrades_to_defaults(tmp_path):
    assert load_settings(tmp_path / "nope.json").to_dict() == Settings().to_dict()


def test_default_config_path_env_override(monkeypatch, tmp_path):
    custom = tmp_path / "custom.json"
    monkeypatch.setenv("SUMMIT_CONFIG", str(custom))
    assert default_config_path() == custom


def test_resolve_paths_expands_user_home():
    settings = Settings(output_dir="~/summit-reports", template_dir="~/summit-templates")
    resolve_paths(settings)
    assert "~" not in settings.output_dir
    assert "~" not in settings.template_dir


def test_effective_headers_adds_cookie_without_clobbering():
    settings = Settings(cookie="session=abc")
    assert settings.effective_headers()["Cookie"] == "session=abc"
    settings = Settings(cookie="session=abc", headers={"Cookie": "keep=me"})
    assert settings.effective_headers()["Cookie"] == "keep=me"


# --- diff ------------------------------------------------------------------


def _write_report(path, findings):
    path.write_text(json.dumps({"findings": findings}), encoding="utf-8")


def _finding(check_id, url, severity, param=""):
    return {"check_id": check_id, "url": url, "param": param, "severity": severity, "title": check_id}


def test_diff_classifies_all_four_buckets(tmp_path):
    old = [
        _finding("xss-reflection", "http://t.local/?q=1", "medium", "q"),
        _finding("cors-reflection", "http://t.local/", "high"),
        _finding("passive-security-headers", "http://t.local/", "low"),
    ]
    new = [
        _finding("xss-reflection", "http://t.local/?q=1", "critical", "q"),  # regressed
        _finding("cors-reflection", "http://t.local/", "high"),  # unchanged
        _finding("sqli-error", "http://t.local/?id=1", "critical", "id"),  # new
    ]
    old_path, new_path = tmp_path / "old.json", tmp_path / "new.json"
    _write_report(old_path, old)
    _write_report(new_path, new)
    result = diff_reports(str(old_path), str(new_path))
    assert [f["check_id"] for f in result.new] == ["sqli-error"]
    assert [f["check_id"] for f in result.resolved] == ["passive-security-headers"]
    assert [f["check_id"] for f in result.regressed] == ["xss-reflection"]
    assert [f["check_id"] for f in result.unchanged] == ["cors-reflection"]
    assert "1 new" in render_diff(result)


def test_diff_identical_reports_are_quiet(tmp_path):
    findings = [_finding("xss-reflection", "http://t.local/?q=1", "high", "q")]
    old_path, new_path = tmp_path / "old.json", tmp_path / "new.json"
    _write_report(old_path, findings)
    _write_report(new_path, findings)
    result = diff_reports(str(old_path), str(new_path))
    assert not result.new and not result.resolved and not result.regressed
    assert len(result.unchanged) == 1
    assert "No changes between scans." in render_diff(result)


# --- OOB listener ----------------------------------------------------------


def test_new_token_shape_and_uniqueness():
    token = new_token()
    assert token.startswith("sm") and len(token) == 18
    assert len({new_token() for _ in range(50)}) == 50


def test_oob_extract_token_ignores_probe_noise():
    assert _extract_token("/probe/abc123", "") == "abc123"
    assert _extract_token("/", "token=xyz") == "xyz"
    assert _extract_token("/favicon.ico", "") == ""
    assert _extract_token("/", "") == ""


def test_oob_server_records_callback_and_wait_for():
    server = OobServer(bind="127.0.0.1", port=0)
    try:
        base_url = server.start()
        assert server.running
        token = new_token("t")
        with urllib.request.urlopen(f"{base_url}/probe/{token}", timeout=5) as response:
            assert response.status == 200
        hit = server.wait_for(token, timeout=3.0)
        assert hit is not None
        assert hit.method == "GET"
        assert server.seen(token)
        assert not server.seen("sm-never-sent")
    finally:
        server.stop()
    assert not server.running


# --- js_secrets ------------------------------------------------------------


def _js_response(body: str) -> HttpResponse:
    return HttpResponse(
        status=200,
        headers={"Content-Type": "application/javascript"},
        body=body.encode(),
        request=HttpRequest(method="GET", url="http://test.local/app.js"),
    )


def test_aws_key_detected_as_high_vendor_match():
    hits = detect_secrets("const key = 'AKIAABCDEFGHIJKLMNOP';")
    assert [h["kind"] for h in hits] == ["AWS access key"]
    assert hits[0]["severity"] == "high"


def test_aws_example_key_is_excluded():
    assert detect_secrets("AKIAIOSFODNN7EXAMPLE") == []


def test_placeholder_api_key_is_excluded():
    assert detect_secrets("api_key = 'your_api_key_here_1234567890'") == []


def test_private_key_block_confirms_finding():
    body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    findings = check_js_secrets(_js_response(body))
    assert len(findings) == 1
    assert findings[0].confidence == "confirmed"
    assert "Private key block" in findings[0].title


def test_vendor_key_reports_likely_and_redacted():
    findings = check_js_secrets(_js_response("window.cfg = { key: 'AKIAABCDEFGHIJKLMNOP' };"))
    assert len(findings) == 1
    assert findings[0].confidence == "likely"
    assert findings[0].severity == "medium"  # lifetime cap: likely never exceeds medium
    assert "…" in findings[0].evidence
    assert "AKIAABCDEFGHIJKLMNOP" not in findings[0].evidence


def test_redact_keeps_edges_only():
    assert redact("AKIAABCDEFGHIJKLMNOP") == "AKIAAB…MNOP"


def test_clean_javascript_is_quiet():
    assert check_js_secrets(_js_response("console.log('nothing to see');")) == []


# --- http_methods ----------------------------------------------------------


class TraceEchoHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_TRACE(self):
        marker = self.headers.get("X-Summit-Trace", "")
        body = f"<html>echo: {marker}</html>".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class WriteMethodsHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, OPTIONS, PUT, DELETE, PATCH")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


class QuietMethodsHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


def test_trace_echo_is_confirmed_high():
    server, port = start_server(TraceEchoHandler)
    try:
        findings = run_http_methods(HttpClient(), f"http://127.0.0.1:{port}/")
        trace = [f for f in findings if f.check_id == "trace-enabled"]
        assert len(trace) == 1
        assert trace[0].confidence == "confirmed"
        assert trace[0].severity == "high"
    finally:
        server.shutdown()


def test_advertised_write_methods_are_likely_only():
    server, port = start_server(WriteMethodsHandler)
    try:
        findings = run_http_methods(HttpClient(), f"http://127.0.0.1:{port}/")
        assert len(findings) == 1
        assert findings[0].check_id == "http-methods-advertised"
        assert findings[0].confidence == "likely"
        assert "PUT" in findings[0].title and "DELETE" in findings[0].title
    finally:
        server.shutdown()


def test_method_check_quiet_on_plain_server():
    server, port = start_server(QuietMethodsHandler)
    try:
        assert run_http_methods(HttpClient(), f"http://127.0.0.1:{port}/") == []
    finally:
        server.shutdown()


# --- hpp -------------------------------------------------------------------


class HppHandler(BaseHTTPRequestHandler):
    """Switchable duplicate-parameter handling for the HPP tests."""

    def do_GET(self):
        split = urlsplit(self.path)
        values = parse_qs(split.query, keep_blank_values=True).get("p", [""])
        if split.path == "/concat":
            shown = ", ".join(values)      # the backend exposes both values
        elif split.path == "/raw-echo":
            shown = split.query            # the page echoes the query string
        elif split.path == "/last":
            shown = values[-1]             # last value wins
        else:
            shown = values[0]              # first value wins
        body = f"<html><body>{shown}</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _hpp_point(port: int, path: str) -> InjectionPoint:
    return InjectionPoint(
        request=HttpRequest(method="GET", url=f"http://127.0.0.1:{port}{path}?p=orig"),
        param="p",
        original_value="orig",
    )


def test_hpp_both_values_processed_is_confirmed_medium():
    server, port = start_server(HppHandler)
    try:
        findings = HppCheck().run(_hpp_point(port, "/concat"), HttpClient())
        assert len(findings) == 1
        assert findings[0].check_id == "hpp"
        assert findings[0].confidence == "confirmed"
        assert findings[0].severity == "medium"
    finally:
        server.shutdown()


def test_hpp_raw_query_echo_is_not_a_false_positive():
    # a page echoing the raw query proves reflection, not dual processing
    server, port = start_server(HppHandler)
    try:
        assert HppCheck().run(_hpp_point(port, "/raw-echo"), HttpClient()) == []
    finally:
        server.shutdown()


def test_hpp_first_value_wins_is_quiet():
    server, port = start_server(HppHandler)
    try:
        assert HppCheck().run(_hpp_point(port, "/first"), HttpClient()) == []
    finally:
        server.shutdown()


def test_hpp_last_value_wins_is_needs_manual_low():
    server, port = start_server(HppHandler)
    try:
        findings = HppCheck().run(_hpp_point(port, "/last"), HttpClient())
        assert len(findings) == 1
        assert findings[0].confidence == "needs-manual"
        assert findings[0].severity == "low"
    finally:
        server.shutdown()


# --- xxe -------------------------------------------------------------------


def test_xxe_indicator_detection():
    assert find_xxe_indicator("root:x:0:0:root:/root:/bin/bash") == "root:x:0:0:"
    assert find_xxe_indicator("<result>nothing here</result>") is None


class XxeLeakHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)
        body = b"<result>root:x:0:0:root:/root:/bin/bash</result>"
        self.send_response(200)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class XxeCleanHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            self.rfile.read(length)
        body = b"<result>well-formed but safe</result>"
        self.send_response(200)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def test_xxe_fallback_endpoint_confirms_file_disclosure():
    server, port = start_server(XxeLeakHandler)
    try:
        findings = run_xxe(HttpClient(), [], f"http://127.0.0.1:{port}")
        assert len(findings) == 1
        assert findings[0].check_id == "xxe"
        assert findings[0].confidence == "confirmed"
    finally:
        server.shutdown()


def test_xxe_quiet_when_no_file_content_returns():
    server, port = start_server(XxeCleanHandler)
    try:
        assert run_xxe(HttpClient(), [], f"http://127.0.0.1:{port}") == []
    finally:
        server.shutdown()


# --- InjectionPoint.with_value ---------------------------------------------


def test_with_value_replaces_query_parameter():
    point = InjectionPoint(
        request=HttpRequest(method="GET", url="http://t.local/search?q=old&page=2"),
        param="q",
        original_value="old",
    )
    updated = point.with_value("new")
    assert updated.params == {"q": "new", "page": "2"}


def test_with_value_replaces_form_field_and_encodes():
    point = InjectionPoint(
        request=HttpRequest(method="POST", url="http://t.local/login", body=b"user=demo&pass=old"),
        param="pass",
        original_value="old",
        location="body",
    )
    updated = point.with_value("x&y")
    assert updated.body == b"user=demo&pass=x%26y"
    assert updated.headers["Content-Type"] == "application/x-www-form-urlencoded"


def test_with_value_appends_missing_form_field():
    point = InjectionPoint(
        request=HttpRequest(method="POST", url="http://t.local/", body=b"a=1"),
        param="extra",
        original_value="",
        location="body",
    )
    updated = point.with_value("v")
    assert b"extra=v" in (updated.body or b"")


def test_with_value_replaces_header():
    point = InjectionPoint(
        request=HttpRequest(method="GET", url="http://t.local/", headers={"X-Token": "old"}),
        param="X-Token",
        original_value="old",
        location="header",
    )
    updated = point.with_value("new")
    assert updated.headers["X-Token"] == "new"


# --- runtime deep flag -----------------------------------------------------


def test_deep_flag_roundtrip():
    original = runtime.deep()
    try:
        runtime.set_deep(True)
        assert runtime.deep() is True
        runtime.set_deep(False)
        assert runtime.deep() is False
    finally:
        runtime.set_deep(original)


# --- report writers --------------------------------------------------------


def _sample_finding():
    return Finding(
        check_id="xss-reflection",
        title="Reflected XSS",
        severity="high",
        url="http://t.local/?q=1",
        param="q",
        confidence="confirmed",
        evidence="payload reflected raw: <script>alert(1)</script>",
    )


def test_write_json_keeps_diff_schema(tmp_path):
    path = write_json([_sample_finding()], str(tmp_path / "report.json"))
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    assert data["total"] == 1
    assert data["findings"][0]["check_id"] == "xss-reflection"
    assert data["findings"][0]["cwe"] == "CWE-79"
    assert "generated" in data


def test_write_html_is_self_contained_with_version_and_filters(tmp_path):
    path = write_html([_sample_finding()], str(tmp_path / "report.html"), "http://t.local")
    text = Path(path).read_text(encoding="utf-8")
    assert __version__ in text
    assert "chip-high" in text
    assert 'data-sev="high"' in text
    assert "<script>" in text  # inline filter script keeps the report portable
    assert "Reflected XSS" in text


def test_write_html_escapes_finding_content(tmp_path):
    finding = _sample_finding()
    finding.title = "<img src=x onerror=alert(1)>"
    path = write_html([finding], str(tmp_path / "report.html"), "http://t.local")
    text = Path(path).read_text(encoding="utf-8")
    assert "<img src=x onerror=alert(1)>" not in text
    assert "&lt;img" in text


# --- templates -------------------------------------------------------------


def test_all_builtin_templates_validate_clean():
    builtin = Path(__file__).resolve().parent.parent / "summit" / "templates" / "builtin"
    templates = sorted(builtin.glob("*.yaml"))
    assert len(templates) == 12
    for template_file in templates:
        errors = validate_template(str(template_file))
        assert errors == [], f"{template_file.name}: {errors}"


# --- banner ----------------------------------------------------------------


def test_banner_renders_version_in_both_variants():
    full = colors.strip_ansi(render_banner("1.1.0"))
    compact = colors.strip_ansi(render_banner("1.1.0", compact=True))
    assert "1.1.0" in full
    # the full variant draws the wordmark as block art instead of literal text
    assert "███████╗" in full and "╚══════╝" in full
    assert "1.1.0" in compact and "SUMMIT" in compact
