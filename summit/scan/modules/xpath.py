"""XPath injection (CWE-643) - error-based, baseline-diffed.

XPath has no boolean oracle worth trusting across arbitrary pages, but
a parser error is unambiguous: our quote reached an XPath expression
and broke its syntax. The baseline page must not already contain that
error (`baseline diffing`), which keeps legacy pages full of static
debug text from producing false positives.
"""

from __future__ import annotations

from ...http.client import HttpClient
from ..core import Check, Finding, InjectionPoint
from ..runtime import deep

ERROR_SIGNATURES = [
    "XPathException",
    "XPath syntax error",
    "Invalid XPath expression",
    "Invalid predicate",
    "javax.xml.xpath.XPathExpressionException",
    "lxml.etree.XPathEvalError",
    "SimpleXMLElement::xpath()",
    "DOMXPath::query()",
    "System.Xml.XPath",
    "org.jaxen",
    "MSXML2.DOMDocument",
    "XPathEvalError",
]


class XpathInjectionCheck(Check):
    check_id = "xpath-injection"
    title = "XPath injection (error-based)"
    severity = "high"

    PROBES = ["'", "']", "' or '1'='1"]
    DEEP_PROBES = [
        "1' and '1'='2",
        "count(//*[contains(name(),'",
        "'] | //*[",
    ]

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        baseline = client.send(point.request).text
        probes = (self.PROBES + self.DEEP_PROBES) if deep() else self.PROBES
        for probe in probes:
            request = point.with_value(point.original_value + probe)
            try:
                body = client.send(request).text[:100_000]
            except Exception:
                continue
            for signature in ERROR_SIGNATURES:
                if signature in body and signature not in baseline:
                    return [
                        Finding(
                            check_id=self.check_id,
                            title=self.title,
                            severity=self.severity,
                            url=point.request.url,
                            param=point.param,
                            confidence="confirmed",
                            detail=(
                                f"Parameter '{point.param}' was concatenated into an XPath expression: "
                                f"appending {probe!r} produced a fresh XML query parser error. "
                                "XPath injection exposes the whole XML document - credentials, "
                                "pricing rules and user records included."
                            ),
                            evidence=signature,
                            remediation=(
                                "Use parameterised XPath (XPath variables) or escape user input; "
                                "never concatenate it into the expression."
                            ),
                        )
                    ]
        return []
