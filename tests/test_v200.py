"""v2.0.0 regressions: Intruder-style payload fuzzing, GraphQL field
suggestions, and the Markdown report writer."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from summit.fuzz.intruder import (
    encode_payload,
    findings_from,
    parse_positions,
    pitchfork_requests,
    run_intruder,
    sniper_requests,
)
from summit.graphql import check_graphql_suggestions
from summit.http.client import HttpClient
from summit.report.writer import write_markdown
from summit.scan.core import Finding


# ---------------------------------------------------------------------------
# pure helpers
# ---------------------------------------------------------------------------

RAW_REQUEST = (
    "GET /api/discount?code=§SUMMIT10§ HTTP/1.1\r\n"
    "Host: target.local\r\n"
    "User-Agent: §summit§\r\n"
    "\r\n"
)


def test_parse_positions_returns_original_values_in_order():
    assert parse_positions(RAW_REQUEST) == ["SUMMIT10", "summit"]


def test_encode_payload_variants():
    assert encode_payload("a b", "none") == "a b"
    assert encode_payload("a b", "url") == "a%20b"
    assert encode_payload("x", "b64") == "eA=="
    with pytest.raises(ValueError):
        encode_payload("x", "rot13")


def test_sniper_substitutes_one_position_at_a_time():
    single = (
        "GET /api/discount?code=§SUMMIT10§ HTTP/1.1\r\n"
        "Host: target.local\r\n"
        "\r\n"
    )
    requests = sniper_requests(single, ["A", "B"], encoder="none")
    assert len(requests) == 2
    assert requests[0].url.endswith("code=A")
    assert requests[1].url.endswith("code=B")


def test_sniper_multi_position_walks_position_major():
    requests = sniper_requests(RAW_REQUEST, ["P1", "P2"], encoder="none")
    assert len(requests) == 4
    assert requests[0].url.endswith("code=P1") and requests[0].headers["User-Agent"] == "summit"
    assert requests[1].url.endswith("code=P2") and requests[1].headers["User-Agent"] == "summit"
    assert requests[2].url.endswith("code=SUMMIT10") and requests[2].headers["User-Agent"] == "P1"
    assert requests[3].url.endswith("code=SUMMIT10") and requests[3].headers["User-Agent"] == "P2"


def test_pitchfork_pairs_positions_with_sets():
    requests = pitchfork_requests(RAW_REQUEST, [["A", "B"], ["X", "Y"]], encoder="none")
    assert len(requests) == 2
    assert requests[0].url.endswith("code=A") and requests[0].headers["User-Agent"] == "X"
    assert requests[1].url.endswith("code=B") and requests[1].headers["User-Agent"] == "Y"


def test_pitchfork_rejects_mismatched_sets():
    with pytest.raises(ValueError, match="one payload set per position"):
        pitchfork_requests(RAW_REQUEST, [["A"]], encoder="none")


def test_positionless_request_is_rejected():
    plain = "GET / HTTP/1.1\r\nHost: target.local\r\n\r\n"
    with pytest.raises(ValueError, match="positions"):
        sniper_requests(plain, ["A"])


# ---------------------------------------------------------------------------
# live server
# ---------------------------------------------------------------------------


class _FuzzHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server API
        split = urlsplit(self.path)
        query = {k: v[0] for k, v in parse_qs(split.query, keep_blank_values=True).items()}
        if split.path == "/api/discount":
            if query.get("code") == "SUMMIT10":
                body = b"<html><body>Discount applied: 10% off your order.</body></html>"
                status = 200
            else:
                body = b"<html><body>Invalid discount code.</body></html>"
                status = 404
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif split.path == "/graphql":
            if "summitNoSuchFieldProbe" in query.get("query", ""):
                payload = {"errors": [{"message": "Cannot query field 'summitNoSuchFieldProbe' on type 'Query'. Did you mean 'secret'?"}]}
            else:
                payload = {"data": {"__schema": {"queryType": {"name": "Query"}}}}
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif split.path == "/api/quiet-gql":
            # GraphQL-shaped but honest: no suggestions in the error.
            payload = {"errors": [{"message": "Invalid query syntax."}]}
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_POST(self):  # noqa: N802 - http.server API
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        try:
            posted = json.loads(raw or "{}")
        except ValueError:
            posted = {}
        if self.path == "/graphql" and "summitNoSuchFieldProbe" in str(posted.get("query", "")):
            payload = {"errors": [{"message": "Cannot query field 'summitNoSuchFieldProbe' on type 'Query'. Did you mean 'secret'?"}]}
            body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        return


@pytest.fixture
def target():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FuzzHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)


class _QuietHandler(BaseHTTPRequestHandler):
    """Same server minus the leaking /graphql route - for the negative tests."""

    def _answer(self, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - http.server API
        split = urlsplit(self.path)
        if split.path == "/api/quiet-gql":
            self._answer({"errors": [{"message": "Invalid query syntax."}]})
        elif split.path == "/graphql":
            self._answer({"errors": [{"message": "Cannot query field 'x' on type 'Query'."}]})
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    do_POST = do_GET  # noqa: N802 - same answers either way

    def log_message(self, *args):
        return


@pytest.fixture
def quiet_target():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)


def _discount_request(netloc: str) -> str:
    return (
        "GET /api/discount?code=§SUMMIT10§ HTTP/1.1\r\n"
        f"Host: {netloc}\r\n"
        "User-Agent: summit-tests\r\n"
        "\r\n"
    )


def test_intruder_flags_divergent_payloads(target):
    client = HttpClient(timeout=3)
    result = run_intruder(client, _discount_request(target.split("//", 1)[1]), payloads=["BOGUS1", "BOGUS2"])

    assert result.control is not None and result.control.status == 200
    divergent = [hit for hit in result.hits if hit.divergent]
    assert len(divergent) == 2
    assert all(hit.response is not None and hit.response.status == 404 for hit in divergent)
    assert {hit.payloads[0] for hit in divergent} == {"BOGUS1", "BOGUS2"}


def test_intruder_stays_quiet_when_payloads_behave_alike(target):
    client = HttpClient(timeout=3)
    raw = _discount_request(target.split("//", 1)[1]).replace("SUMMIT10", "BOGUS1")
    result = run_intruder(client, raw, payloads=["BOGUS1", "BOGUS2"])

    assert result.control is not None and result.control.status == 404
    assert all(not hit.divergent for hit in result.hits)
    assert findings_from(result) == []


def test_intruder_findings_carry_needs_manual_low(target):
    client = HttpClient(timeout=3)
    result = run_intruder(client, _discount_request(target.split("//", 1)[1]), payloads=["BOGUS1"])
    findings = findings_from(result)

    assert len(findings) == 1
    assert findings[0].check_id == "fuzz-divergence"
    assert findings[0].confidence == "needs-manual"
    assert findings[0].severity == "low"
    assert "404" in findings[0].evidence and "200" in findings[0].evidence


# ---------------------------------------------------------------------------
# GraphQL field suggestions
# ---------------------------------------------------------------------------


def test_graphql_suggestions_detected(target):
    client = HttpClient(timeout=3)
    findings = check_graphql_suggestions(client, target)

    assert len(findings) == 1
    assert findings[0].check_id == "graphql-field-suggestions"
    assert findings[0].confidence == "confirmed"
    assert "did you mean" in findings[0].evidence.lower()


def test_graphql_suggestions_silent_without_suggestions(quiet_target):
    # a real GraphQL endpoint with honest errors must not be flagged
    client = HttpClient(timeout=3)
    findings = check_graphql_suggestions(client, quiet_target)
    assert findings == []


def test_graphql_suggestions_ignores_plain_404(quiet_target):
    # no GraphQL-shaped validation error anywhere -> no finding
    client = HttpClient(timeout=3)
    findings = check_graphql_suggestions(client, quiet_target + "/nowhere")
    assert findings == []


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------


def _finding(**overrides) -> Finding:
    base = dict(
        check_id="sqli-error",
        title="SQL injection",
        severity="critical",
        url="http://target.local/user?id=1",
        detail="Database error surfaced.",
        evidence="unquoted user input",
        confidence="confirmed",
    )
    base.update(overrides)
    return Finding(**base)


def test_markdown_report_structure(tmp_path):
    findings = [
        _finding(),
        _finding(check_id="passive-cookie-flags", title="Cookie flags", severity="low",
                 confidence="needs-manual"),
    ]
    path = write_markdown(findings, str(tmp_path / "report.md"), "http://target.local")
    text = Path(path).read_text(encoding="utf-8")

    assert "# Summit report - http://target.local" in text
    assert "| Severity | Count |" in text
    assert "| critical | 1 |" in text
    assert "## Findings" in text
    assert "#### [CRITICAL] SQL injection" in text
    assert "#### [LOW] Cookie flags" in text
    assert "confidence: `confirmed`" in text
    assert "CWE: `CWE-89`" in text
    # sections must appear highest severity first
    assert text.index("#### [CRITICAL]") < text.index("#### [LOW]")


def test_markdown_report_escapes_pipes_and_handles_empty(tmp_path):
    findings = [_finding(detail="broken | output", title="Inject|ed")]
    path = write_markdown(findings, str(tmp_path / "report.md"), "target")
    text = Path(path).read_text(encoding="utf-8")
    assert "broken \\| output" in text

    empty = write_markdown([], str(tmp_path / "empty.md"), "target")
    assert "No findings" in Path(empty).read_text(encoding="utf-8")
