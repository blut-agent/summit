# Report Formats

Summit outputs findings in six formats. Every format carries the same data: confidence label, CWE, CVE, impact statement, remediation, and complete untruncated evidence.

## Console

The default output. Human-readable, sorted by severity, with per-severity breakdown:

```
Summit report - http://target.local
============================================================
Total findings: 113  (critical 4, high 18, medium 14, low 24, info 53)

[CRITICAL]
  SQL injection (error-based)  (sqli-error)  [confirmed]  CWE-89
    URL: http://target.local/user?id=1  param: id
    Detail: Parameter 'id' triggered a MySQL error...
    Evidence: unrecognized token
    Impact: Full database access: read, modify or destroy every record.
    Fix: Use parameterized queries / prepared statements.
```

## JSON

Machine-readable. Every field is present, evidence is never truncated:

```json
{
  "generated": "2026-10-17T12:00:00+00:00",
  "total": 113,
  "findings": [{
    "check_id": "sqli-error",
    "title": "SQL injection (error-based)",
    "severity": "critical",
    "url": "http://target.local/user?id=1",
    "param": "id",
    "detail": "Parameter 'id' triggered a MySQL error...",
    "evidence": "unrecognized token",
    "remediation": "Use parameterized queries...",
    "confidence": "confirmed",
    "cwe": "CWE-89",
    "cves": [],
    "impact": "Full database access: read, modify or destroy every record."
  }]
}
```

## HTML

Self-contained HTML with inline CSS. Severity summary table up top, findings table below. Dark mode compatible. Open directly in a browser.

## SARIF 2.1.0

GitHub code scanning compatible. Upload via the code scanning API or the `github/codeql-action/upload-sarif` action:

```bash
summit scan https://target.local --sarif report.sarif
```

Findings appear in the repository's Security tab with severity, CWE, and remediation. Findings are ranked by SARIF level: `error` (critical/high), `warning` (medium), `note` (low/info).

## JUnit XML

CI/CD pipeline compatible. Jenkins, GitLab CI, and GitHub Actions parse JUnit XML natively. Each finding becomes a test case:

```bash
summit scan https://target.local --junit report.xml
```

Critical and high findings are reported as `<error>` elements; lower severities as passing test cases with status attributes.

## Comparison

| Format | Use case | Machine-readable | Severity tags | CWE/CVE |
|---|---|---|---|---|
| Console | Human review | no | severity headers | yes |
| JSON | Scripting, automation | yes | severity field | yes |
| HTML | Sharing, archiving | no | color-coded | yes |
| SARIF | GitHub Security tab | yes | SARIF level | yes |
| JUnit XML | CI/CD pipeline | yes | error/info | CWE only |
