"""OS command injection (CWE-78) - marker + control probe, deterministic.

Echo-based detection with an anti-false-positive control, commix-style:

- probe A appends `echo <exec-marker>` through a shell separator
- probe B appends `<invalid-command> <control-marker>` through the same
  separator

A server that EXECUTES our string outputs the exec marker (probe A) but
nothing for probe B (the invalid command fails). A server that merely
REFLECTS input echoes both markers - and that combination is suppressed.
This is what keeps the check quiet on every reflecting parameter, which
is where naive command-injection scanners drown in false positives.

Time-based blind detection is deliberately NOT implemented here - it is
noisy, slow, and one misconfigured target turns `sleep` into a denial of
service. Confirmed findings only; there is no heuristic variant.
"""

from __future__ import annotations

from ...http.client import HttpClient
from ...scan.core import Check, Finding

EXEC_MARKER = "summit-cmd-9k2"
CONTROL_MARKER = "summit-ctl-4k8"


def _variants() -> list[tuple[str, str, str]]:
    exec_echo = f"echo {EXEC_MARKER}"
    control = f"nosuchcmd0x0 {CONTROL_MARKER}"
    return [
        ("semicolon", f";{exec_echo}", f";{control}"),
        ("pipe", f"|{exec_echo}", f"|{control}"),
        ("double-ampersand", f"&&{exec_echo}", f"&&{control}"),
        ("single-ampersand", f"&{exec_echo}", f"&{control}"),
        ("backticks", f"`{exec_echo}`", f"`{control}`"),
        ("command-substitution", f"$({exec_echo})", f"$({control})"),
        ("newline", f"\n{exec_echo}", f"\n{control}"),
    ]


class OsCommandInjectionCheck(Check):
    check_id = "os-command-injection"
    title = "OS command injection"
    severity = "critical"

    def run(self, point, client: HttpClient) -> list[Finding]:
        baseline = client.send(point.request)
        if EXEC_MARKER in baseline.text or CONTROL_MARKER in baseline.text:
            return []  # markers already present - cannot attribute execution to us
        for label, exec_payload, control_payload in _variants():
            exec_response = client.send(
                point.with_value(point.original_value + exec_payload)
            )
            exec_count = exec_response.text.count(EXEC_MARKER)
            if exec_count == 0:
                continue
            control_response = client.send(
                point.with_value(point.original_value + control_payload)
            )
            control_count = control_response.text.count(CONTROL_MARKER)
            if control_count >= exec_count:
                continue  # the marker only appears inside echoed input - reflection, not execution
            return [
                Finding(
                    check_id=self.check_id,
                    title=self.title,
                    severity=self.severity,
                    url=point.request.url,
                    param=point.param,
                    confidence="confirmed",
                    detail=(
                        f"Parameter '{point.param}' reached a command interpreter: appending "
                        f"{exec_payload!r} ({label}) made the exec marker appear more often than the "
                        "control marker - the extra occurrence is command output, not reflection. "
                        "User input is reaching a shell without sanitization."
                    ),
                    evidence=f"{label}: exec marker x{exec_count}, control marker x{control_count}",
                    remediation="Never pass user input to a shell. Use library APIs "
                    "(subprocess with argument lists) and validate against an allowlist.",
                )
            ]
        return []
