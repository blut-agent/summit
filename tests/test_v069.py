from summit.cve import detect_cves
from summit.http.models import HttpRequest, HttpResponse
from summit.scan.modules.body_cves import check_body_cves, detect_body_cves


def make_response(body: str):
    return HttpResponse(
        status=200,
        headers={},
        body=body.encode(),
        request=HttpRequest(method="GET", url="http://test.local/"),
    )


def test_jquery_3_4_1_maps_to_cve():
    hits = detect_body_cves('<script src="https://code.jquery.com/jquery-3.4.1.min.js"></script>')
    ids = {h["cve"] for h in hits}
    assert "CVE-2020-11023" in ids


def test_jquery_3_5_1_is_clean():
    hits = detect_body_cves('<script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>')
    assert not any(h["cve"] == "CVE-2020-11023" for h in hits)


def test_lodash_4_17_15_maps_to_cve():
    hits = detect_body_cves("lodash 4.17.15 is bundled")
    assert any(h["cve"] == "CVE-2020-8203" for h in hits)


def test_wordpress_5_7_1_maps_to_cve():
    hits = detect_body_cves('<meta name="generator" content="WordPress 5.7.1">')
    assert any(h["cve"] == "CVE-2021-29447" for h in hits)


def test_wordpress_5_7_2_is_clean():
    hits = detect_body_cves('<meta name="generator" content="WordPress 5.7.2">')
    assert not any(h["cve"] == "CVE-2021-29447" for h in hits)


def test_check_body_cves_produces_finding_with_cve():
    findings = check_body_cves(make_response('<script src="jquery-3.4.1.min.js"></script>'))
    assert len(findings) == 1
    assert findings[0].cves == ["CVE-2020-11023"]
    assert findings[0].confidence == "potential"


def test_clean_body_is_quiet():
    assert check_body_cves(make_response("<html><body>hello world</body></html>")) == []


def test_banner_cve_still_works_alongside():
    hits = detect_cves("Apache/2.4.49")
    assert any(h["cve"] == "CVE-2021-41773" for h in hits)
