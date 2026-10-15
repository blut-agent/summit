import pytest

from summit.http.models import HttpRequest

RAW = (
    "GET /search?q=test&page=2 HTTP/1.1\r\n"
    "Host: example.com\r\n"
    "User-Agent: test\r\n"
    "\r\n"
)


def test_from_raw_parses_request_line_and_headers():
    request = HttpRequest.from_raw(RAW)
    assert request.method == "GET"
    assert request.url == "http://example.com/search?q=test&page=2"
    assert request.headers["Host"] == "example.com"


def test_from_raw_with_body():
    raw = "POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nuser=a&pass=b"
    request = HttpRequest.from_raw(raw)
    assert request.method == "POST"
    assert request.body == b"user=a&pass=b"


def test_from_raw_rejects_missing_host():
    raw = "GET / HTTP/1.1\r\n\r\n"
    with pytest.raises(ValueError):
        HttpRequest.from_raw(raw)


def test_with_query_param_replaces_value():
    request = HttpRequest.from_raw(RAW)
    modified = request.with_query_param("q", "injected")
    assert modified.params["q"] == "injected"
    assert modified.params["page"] == "2"


def test_with_query_param_appends_when_missing():
    request = HttpRequest.from_raw(RAW)
    modified = request.with_query_param("new", "1")
    assert modified.params["new"] == "1"
