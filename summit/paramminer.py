"""Hidden parameter mining - the Param Miner approach, scripted.

Servers routinely read request parameters that the application never
shows in its HTML: debug switches, feature flags, internal overrides.
Those parameters are an attack surface nobody tests, because nobody
knows they exist.

Mining strategy, kept deliberately simple and honest:

1. fetch the URL once as a baseline
2. replay it with one candidate parameter at a time, each carrying a
   unique marker value
3. a candidate is reported only when something objectively changed:
   the marker is reflected back (confirmed), or the status/size changed
   meaningfully (potential)

No timing attacks, no cache deception, no external callbacks - those
are separate tools with separate risks.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from .http.client import HttpClient
from .http.models import HttpRequest
from .scan.core import Finding

# Parameter names seen in real applications and CTF-writes. Short on
# purpose: 70 requests is polite, 700 is an attack.
CANDIDATES = [
    "debug", "test", "admin", "internal", "source", "lang", "language", "locale",
    "theme", "preview", "draft", "role", "is_admin", "isadmin", "verbose", "trace",
    "level", "env", "environment", "config", "settings", "overrides", "impersonate",
    "as_user", "user_id", "account_id", "debug_level", "xdebug", "profile",
    "mock", "sandbox", "staging", "bypass", "secret", "key", "token", "access",
    "sudo", "root", "su", "act_as", "view", "format", "render", "raw", "output",
    "export", "download", "include", "template", "page_id", "site", "ref",
    "log", "logging", "audit", "show", "expand", "all", "full", "detail",
]

_MARKER_TEMPLATE = "summit-{name}-9k2probe"
_MAX_BEHAVIOR_DELTA = 50


def _probe(client: HttpClient, url: str, name: str, base_status: int, base_len: int):
    marker = _MARKER_TEMPLATE.format(name=name)
    request = HttpRequest(method="GET", url=url)
    probe_request = request.with_query_param(name, marker)
    response = client.send(probe_request)
    if marker in response.text:
        return Finding(
            check_id="paramminer-reflected",
            title=f"Hidden parameter discovered (reflected): {name}",
            severity="medium",
            url=url,
            param=name,
            confidence="confirmed",
            detail=f"Parameter '{name}' is read by the server and its value is reflected - it was never mentioned in the application's HTML.",
            evidence=f"{name}={marker} -> reflected",
            remediation="Inventory every parameter the server reads; undocumented parameters should be removed or documented.",
        )
    if response.status != base_status or abs(len(response.body) - base_len) > _MAX_BEHAVIOR_DELTA:
        return Finding(
            check_id="paramminer-behavior",
            title=f"Hidden parameter changes behavior: {name}",
            severity="low",
            url=url,
            param=name,
            confidence="potential",
            detail=f"Adding parameter '{name}' changed the response (status or size) even though the application never advertises it.",
            evidence=f"baseline HTTP {base_status}/{base_len}B -> HTTP {response.status}/{len(response.body)}B",
            remediation="Investigate what the parameter controls; undocumented state changes are attack surface.",
        )
    return None


def mine(client: HttpClient, url: str, workers: int = 8) -> list[Finding]:
    """Probe candidate parameters on one URL, in parallel. One finding per discovery."""
    baseline = client.send(HttpRequest(method="GET", url=url))
    base_status, base_len = baseline.status, len(baseline.body)

    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_probe, client, url, name, base_status, base_len) for name in CANDIDATES]
        for future in as_completed(futures):
            finding = future.result()
            if finding is not None:
                findings.append(finding)
    return findings
