"""Session fixation detection (CWE-384).

Session fixation occurs when an attacker can set a user's session ID
before the user logs in. After login, the attacker uses the same
session ID to hijack the authenticated session.

Detection: check if the session cookie value changes after a
state-changing request. If the cookie value stays the same across
login/authenticated states, the session was not regenerated - a
fixation surface.
"""

from __future__ import annotations

from ...http.client import HttpClient
from ...scan.core import Check, Finding, InjectionPoint


class SessionFixationCheck(Check):
    check_id = "session-fixation"
    title = "Session fixation (session not regenerated)"
    severity = "medium"

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        # Look for session-like cookies in the baseline response
        baseline = client.send(point.request)
        session_cookies = [
            cookie for cookie in baseline.set_cookies
            if any(name in cookie.lower() for name in ("session", "sid", "jsessionid", "phpsession"))
        ]
        if not session_cookies:
            return []

        # Send a second request - if the session cookie value is the same,
        # the server is not rotating session IDs
        second = client.send(point.request)
        second_cookies = [
            cookie for cookie in second.set_cookies
            if any(name in cookie.lower() for name in ("session", "sid", "jsessionid", "phpsession"))
        ]

        # Compare cookie values
        def extract_values(cookies: list[str]) -> set[str]:
            values = set()
            for cookie in cookies:
                parts = cookie.split(";", 1)[0].strip()
                if "=" in parts:
                    values.add(parts.split("=", 1)[1])
            return values

        first_values = extract_values(session_cookies)
        second_values = extract_values(second_cookies)

        if first_values and first_values == second_values:
            return [
                Finding(
                    check_id=self.check_id,
                    title=self.title,
                    severity=self.severity,
                    url=point.request.url,
                    param=point.param,
                    confidence="needs-manual",
                    detail=(
                        "The session cookie value did not change between two consecutive requests. "
                        "If the server also does not regenerate the session ID after login, an "
                        "attacker who fixes the session ID before login can hijack the authenticated "
                        "session. This is `needs-manual` because session regeneration may happen on a "
                        "different endpoint (e.g., the actual login POST)."
                    ),
                    evidence=f"same session cookie value across 2 requests: {list(first_values)[0][:20]}...",
                    remediation="Regenerate the session ID after every authentication state change (login, privilege change, logout).",
                )
            ]
        return []
