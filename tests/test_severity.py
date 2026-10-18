from summit.scan.core import Finding, filter_by_min_severity, filter_by_severities


def make(severity: str):
    return Finding(check_id="x", title="t", severity=severity, url="http://x/", confidence="confirmed")


def test_filter_by_severities():
    findings = [make("critical"), make("low"), make("info")]
    kept = filter_by_severities(findings, {"critical", "low"})
    assert [f.severity for f in kept] == ["critical", "low"]


def test_filter_by_min_severity_uses_rank_not_alphabet():
    findings = [make("info"), make("medium"), make("critical"), make("high")]
    kept = filter_by_min_severity(findings, "high")
    assert [f.severity for f in kept] == ["critical", "high"]  # alphabetical would keep "high" and "info"


def test_min_severity_info_keeps_everything():
    findings = [make("info"), make("critical")]
    assert len(filter_by_min_severity(findings, "info")) == 2
