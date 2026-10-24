"""v1.5.0 regressions: attack surface mapping and report output."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from summit.http.client import HttpClient
from summit.map import (
    map_target,
    write_map_html,
    write_map_json,
    write_map_markdown,
)


class _MapHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server API
        if self.path == "/login":
            body = (
                b"<html><head><title>Login</title></head><body>"
                b"<form action='/do-login' method='POST'>"
                b"<input name='user' value='summit'>"
                b"<input type='password' name='password'>"
                b"</form></body></html>"
            )
        elif self.path == "/app.js":
            body = b"fetch('/api/profile')"
        else:
            body = (
                b"<html><head><title>Target home</title></head><body>"
                b"<a href='/login'>login</a>"
                b"<a href='https://example.test/out'>outbound</a>"
                b"<script src='/app.js'></script>"
                b"</body></html>"
            )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return


@pytest.fixture
def target():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _MapHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_map_target_inventories_surface(target):
    surface = map_target(HttpClient(timeout=3), target, max_depth=1, max_pages=5)

    assert surface["target"] == target
    assert surface["summary"]["pages"] >= 2
    assert surface["summary"]["forms"] == 1
    assert surface["summary"]["injection_points"] >= 1
    assert any(page["title"] == "Target home" for page in surface["pages"])
    assert any(point["param"] == "user" for point in surface["injection_points"])
    assert any(tech["name"] for tech in surface["technologies"])
    assert "https://example.test/out" in surface["external_links"]


def test_map_exports_json_html_and_markdown(target, tmp_path):
    surface = map_target(HttpClient(timeout=3), target, max_depth=1, max_pages=5)
    json_path = write_map_json(surface, str(tmp_path / "map.json"))
    html_path = write_map_html(surface, str(tmp_path / "map.html"))
    markdown_path = write_map_markdown(surface, str(tmp_path / "map.md"))

    data = json.loads(Path(json_path).read_text(encoding="utf-8"))
    assert data["target"] == target
    assert data["summary"]["pages"] == surface["summary"]["pages"]

    html_text = Path(html_path).read_text(encoding="utf-8")
    assert "<title>Attack surface map" in html_text
    assert "Target home" in html_text
    assert "Login" in html_text

    markdown_text = Path(markdown_path).read_text(encoding="utf-8")
    assert "# Attack surface map" in markdown_text
    assert "## Injection points" in markdown_text


def test_map_rejects_non_http_target():
    with pytest.raises(ValueError, match="absolute http"):
        map_target(HttpClient(timeout=1), "ftp://example.test")


def test_map_html_escapes_hostile_titles(tmp_path):
    surface = {
        "target": "http://target.test",
        "generated": "2026-01-01T00:00:00+00:00",
        "pages": [
            {
                "url": "http://target.test/<script>",
                "status": 200,
                "bytes": 10,
                "title": "<img src=x onerror=alert(1)>",
                "content_type": "text/html",
                "params": [],
                "technologies": [],
            }
        ],
        "forms": [],
        "visited": ["http://target.test/<script>"],
        "external_links": [],
        "technologies": [],
        "injection_points": [],
        "notes": [],
        "errors": [],
        "summary": {"pages": 1, "forms": 0, "visited": 1, "external_links": 0,
                    "technologies": 0, "injection_points": 0, "errors": 0},
    }
    path = write_map_html(surface, str(tmp_path / "map.html"))
    text = Path(path).read_text(encoding="utf-8")
    assert "<img src=x onerror=alert(1)>" not in text
    assert "src=" in text
