from summit.http.models import HttpRequest, HttpResponse
from summit.scan.passive import check_cookies, run_passive


def make_request():
    return HttpRequest(method="GET", url="http://test.local/")


def make_response(body=b"<html></html>", headers=None, set_cookies=None, status=200):
    return HttpResponse(
        status=status,
        headers=headers or {},
        body=body,
        request=make_request(),
        set_cookies=set_cookies or [],
    )


def test_missing_security_headers_reported():
    findings = run_passive(make_response(headers={"Content-Type": "text/html"}))
    ids = {f.check_id for f in findings}
    assert "passive-security-headers" in ids
    titles = " ".join(f.title for f in findings)
    assert "Content-Security-Policy" in titles
    assert "Strict-Transport-Security" in titles


def test_cookie_flags_checked():
    findings = check_cookies(make_response(set_cookies=["sessionid=abc123; Path=/"]))
    titles = " ".join(f.title for f in findings)
    assert "Secure" in titles
    assert "HttpOnly" in titles
    assert "SameSite" in titles


def test_sql_error_detected():
    body = b"<html>Warning: mysqli_query(): You have an error in your SQL syntax near</html>"
    findings = run_passive(make_response(body=body, status=500))
    assert any("MySQL" in f.title for f in findings)


def test_stack_trace_detected():
    body = b"Traceback (most recent call last):\n  File app.py"
    findings = run_passive(make_response(body=body, status=500))
    assert any("Stack trace" in f.title for f in findings)


def test_email_leak_detected():
    body = b"Contact us at admin@test.local for help"
    findings = run_passive(make_response(body=body))
    assert any(f.check_id == "passive-email-leak" for f in findings)


def test_clean_response_has_no_error_findings():
    body = b"<html><body>hello</body></html>"
    findings = run_passive(make_response(body=body))
    assert not any(f.check_id == "passive-error-disclosure" for f in findings)
