"""Server-side template injection (CWE-1336, an RCE class) - math canary.

The classic, reliable detection: inject a template expression that
computes arithmetic (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`). If the response
contains `49`, a template engine evaluated our input - code execution.
A finding requires the computed value to be present AND absent from the
baseline, so static page content can never trigger it.
"""

from __future__ import annotations

from ...http.client import HttpClient
from ...scan.core import Check, Finding, InjectionPoint
from ..runtime import deep

PROBES = [
    ("Jinja2/Twig", "{{7*7}}", "49"),
    ("Freemarker/Velocity", "${7*7}", "49"),
    ("ERB", "<%= 7*7 %>", "49"),
    ("Smarty", "{7*7}", "49"),
]

# Deep mode: engine-specific expressions that distinguish the backend
# instead of stopping at the first generic match.
DEEP_PROBES = [
    ("Jinja2 concat", "{{7*'7'}}", "7777777"),
    ("Spring EL", "*{7*7}", "49"),
    ("Thymeleaf", "[[${7*7}]]", "49"),
    ("Pebble", "{{ 7 * 7 }}", "49"),
]


class SstiCheck(Check):
    check_id = "ssti"
    title = "Server-side template injection (RCE candidate)"
    severity = "critical"

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        baseline = client.send(point.request)
        if "49" in baseline.text:
            return []  # the number is already on the page - cannot attribute evaluation to us
        probes = (PROBES + DEEP_PROBES) if deep() else PROBES
        for engine, payload, computed in probes:
            request = point.with_value(payload)
            response = client.send(request)
            # The raw template must be GONE from the response (replaced by the
            # computed value). A page that echoes `{{7*7}}` literally AND
            # happens to contain "49" elsewhere is reflection, not evaluation.
            if computed in response.text and payload not in response.text:
                return [
                    Finding(
                        check_id=self.check_id,
                        title=self.title,
                        severity=self.severity,
                        url=point.request.url,
                        param=point.param,
                        confidence="confirmed",
                        detail=(
                            f"Parameter '{point.param}' was evaluated by a template engine "
                            f"({engine}): {{7*7}} came back as 49. Template injection is RCE "
                            "unless the sandbox forbids it - treat as code execution."
                        ),
                        evidence=f"{engine}: {payload} -> {computed}",
                        remediation="Use logic-less templating for user input, or pass user data "
                        "as context variables - never into the template itself.",
                    )
                ]
        return []
