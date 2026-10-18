from __future__ import annotations

from ...http.client import HttpClient
from ..core import Check, Finding, InjectionPoint
from ..runtime import deep

ERROR_SIGNATURES = {
    "MySQL": ["You have an error in your SQL syntax", "Warning: mysqli_", "MySQLSyntaxErrorException"],
    "PostgreSQL": ["PG::SyntaxError", "unterminated quoted string at or near", "psycopg2.errors.SyntaxError"],
    "MSSQL": ["Unclosed quotation mark after the character string", "Microsoft OLE DB Provider for SQL Server", "Incorrect syntax near"],
    "SQLite": ["sqlite3.OperationalError", "Warning: SQLite3::", "unrecognized token"],
    "Oracle": ["ORA-01756", "ORA-00936", "quoted string not properly terminated"],
}


class SqliErrorCheck(Check):
    check_id = "sqli-error"
    title = "SQL injection (error-based)"
    severity = "critical"

    PROBES = ["'", '"', "')", "1' OR '1'='1"]
    # Deep mode: function-based errors that name the engine, plus
    # quote-balancing variants that escaping alone never reaches.
    DEEP_PROBES = [
        "%27",
        "1 AND extractvalue(1,concat(0x7e,version()))",
        "' AND updatexml(1,concat(0x7e,version()),1)-- -",
        "') OR ('1'='1",
        "\\",
        "1 OR 1=CONVERT(int, @@version)-- -",
    ]

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        baseline = client.send(point.request).text
        probes = (self.PROBES + self.DEEP_PROBES) if deep() else self.PROBES
        for probe in probes:
            request = point.with_value(point.original_value + probe)
            body = client.send(request).text
            for db, signatures in ERROR_SIGNATURES.items():
                for signature in signatures:
                    if signature in body and signature not in baseline:
                        return [
                            Finding(
                                check_id=self.check_id,
                                title=self.title,
                                severity=self.severity,
                                url=point.request.url,
                                param=point.param,
                                confidence="confirmed",
                                detail=f"Parameter '{point.param}' triggered a {db} error when the value was appended with {probe!r}.",
                                evidence=signature,
                                remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                            )
                        ]
        return []


class SqliBooleanCheck(Check):
    check_id = "sqli-boolean"
    title = "SQL injection (boolean-based)"
    severity = "critical"

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        original = point.original_value.strip()
        if not original.isdigit():
            return []
        base_response = client.send(point.request)
        true_response = client.send(point.with_value(f"{original} AND 1=1"))
        false_response = client.send(point.with_value(f"{original} AND 1=2"))
        if true_response.status != 200 or false_response.status != 200:
            return []
        len_true = len(true_response.body)
        len_false = len(false_response.body)
        len_base = len(base_response.body)
        if abs(len_true - len_false) > 50 and abs(len_true - len_base) <= 50:
            return [
                Finding(
                    check_id=self.check_id,
                    title=self.title,
                    severity=self.severity,
                    url=point.request.url,
                    param=point.param,
                    confidence="likely",
                    detail=(
                        f"Numeric parameter '{point.param}' returns different response sizes for "
                        f"'{original} AND 1=1' vs '{original} AND 1=2' while matching the baseline otherwise. "
                        "Verify manually before reporting."
                    ),
                    evidence=f"len(true)={len_true}, len(false)={len_false}, len(base)={len_base}",
                    remediation="Use parameterized queries / prepared statements.",
                )
            ]
        return []
