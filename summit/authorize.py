"""Authorization testing - the Autorize workflow, made scriptable.

You provide URLs and two role definitions - typically a privileged
session and a low-privilege one. Summit requests every URL as every
role, compares the responses, and flags the case that matters most:
a low-privilege role receiving the same answer as the privileged one.
That is broken access control (BOLA/IDOR) - the single most
consequential bug class in bug bounty.

Verdicts per URL:

- ``enforced`` - the roles see different responses (working authz)
- ``broken``   - the low-privilege response matches the privileged one
- ``partial``  - same status, different body (worth a human look)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .http.client import HttpClient
from .http.models import HttpRequest, HttpResponse
from .scan.core import Finding


@dataclass
class Role:
    name: str
    headers: dict[str, str]


@dataclass
class AuthResult:
    url: str
    privileged_role: str
    other_role: str
    privileged: HttpResponse
    other: HttpResponse
    verdict: str


def _signature(response: HttpResponse) -> tuple:
    return (response.status, len(response.body), hashlib.sha256(response.body).hexdigest()[:16])


def compare(privileged: HttpResponse, other: HttpResponse) -> str:
    if _signature(privileged) == _signature(other):
        return "broken"
    if privileged.status == other.status:
        return "partial"
    return "enforced"


def run_authorize(
    client: HttpClient,
    urls: list[str],
    privileged: Role,
    other: Role,
) -> list[AuthResult]:
    """Request every URL as both roles and classify the difference."""
    results: list[AuthResult] = []
    for url in urls:
        try:
            privileged_response = client.send(HttpRequest(method="GET", url=url, headers=dict(privileged.headers)))
            other_response = client.send(HttpRequest(method="GET", url=url, headers=dict(other.headers)))
        except Exception:
            continue  # unreachable URL - report nothing, the scanner already handles reachability
        results.append(
            AuthResult(
                url=url,
                privileged_role=privileged.name,
                other_role=other.name,
                privileged=privileged_response,
                other=other_response,
                verdict=compare(privileged_response, other_response),
            )
        )
    return results


def findings_from(results: list[AuthResult]) -> list[Finding]:
    findings: list[Finding] = []
    for result in results:
        if result.verdict == "broken":
            # Guard against the classic login-redirect false positive: if the
            # "privileged" response is itself a redirect or an empty shell,
            # both roles are probably bouncing off the same auth wall - there
            # is no privileged content to leak in the first place.
            privileged_usable = (
                result.privileged.status == 200
                and len(result.privileged.body) >= 100
            )
            if not privileged_usable:
                continue
            findings.append(
                Finding(
                    check_id="authorize-bypass",
                    title="Broken access control (BOLA/IDOR candidate)",
                    severity="critical",
                    url=result.url,
                    confidence="confirmed",
                    detail=(
                        f"Role '{result.other_role}' received an identical response to privileged role "
                        f"'{result.privileged_role}' (same status, same body). The endpoint does not "
                        "enforce authorization - verify the object ids are truly equivalent for both roles."
                    ),
                    evidence=f"both roles: HTTP {result.privileged.status}, {len(result.privileged.body)} bytes",
                    remediation="Enforce authorization server-side on every request; deny by default.",
                )
            )
        elif result.verdict == "partial":
            findings.append(
                Finding(
                    check_id="authorize-partial",
                    title="Authorization response differs only in body",
                    severity="medium",
                    url=result.url,
                    confidence="needs-manual",
                    detail=(
                        f"Roles '{result.privileged_role}' and '{result.other_role}' get the same status "
                        "but different bodies - could be personalization, could be leaking privileged data. Worth a human look."
                    ),
                    evidence=f"HTTP {result.privileged.status}, privileged {len(result.privileged.body)}B vs other {len(result.other.body)}B",
                    remediation="Confirm the response difference is intentional personalization, not data leakage.",
                )
            )
    return findings


def parse_role(spec: str) -> Role:
    """Parse 'name=Header: value' into a Role, e.g. 'admin=Cookie: session=abc'."""
    name, _, rest = spec.partition("=")
    header_name, _, header_value = rest.partition(":")
    if not name.strip() or not header_name.strip():
        raise ValueError(f"role spec must look like 'name=Header: value', got: {spec!r}")
    return Role(name.strip(), {header_name.strip(): header_value.strip()})
