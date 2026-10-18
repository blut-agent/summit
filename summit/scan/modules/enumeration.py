"""User enumeration via differential responses (CWE-204).

Registration, login and password-reset endpoints often reveal which
usernames or emails exist: "this email is already registered" versus
"registration successful". The check probes a parameter that looks
identity-shaped (email / user / username / login) with two values and
reports a difference as `likely` - the message wording decides if
it is a real leak, and that is a human call.

FP discipline: only identity-shaped parameters are probed, and the
probe pair is deliberately boring (no injection payloads) so this
check never collides with the injection checks.
"""

from __future__ import annotations

from ...http.client import HttpClient
from ...scan.core import Check, Finding, InjectionPoint

_IDENTITY_HINTS = ("email", "user", "username", "login", "account")
_PROBE_A = "summit-probe-a@summit.local"
_PROBE_B = "summit-probe-b@summit.local"


class EnumerationCheck(Check):
    check_id = "email-enumeration"
    title = "Possible user enumeration via differential response"
    severity = "medium"

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        if not any(hint in point.param.lower() for hint in _IDENTITY_HINTS):
            return []
        response_a = client.send(point.with_value(_PROBE_A))
        response_b = client.send(point.with_value(_PROBE_B))
        if response_a.status != response_b.status or abs(len(response_a.body) - len(response_b.body)) > 20:
            return [
                Finding(
                    check_id=self.check_id,
                    title=self.title,
                    severity=self.severity,
                    url=point.request.url,
                    param=point.param,
                    confidence="likely",
                    detail=(
                        f"Parameter '{point.param}' produced different responses for two equally "
                        f"unknown values (HTTP {response_a.status}/{len(response_a.body)}B vs "
                        f"{response_b.status}/{len(response_b.body)}B). If the difference is "
                        "triggered by real usernames or emails, attackers can enumerate your user base."
                    ),
                    evidence=f"probe A: HTTP {response_a.status}/{len(response_a.body)}B, "
                    f"probe B: HTTP {response_b.status}/{len(response_b.body)}B",
                    remediation="Return identical generic responses and identical timing for known and unknown identities.",
                )
            ]
        return []
