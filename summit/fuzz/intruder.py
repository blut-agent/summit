"""Intruder-style payload fuzzing for raw requests.

Burp's Intruder is the one paid workflow this project kept missing: hand
it a request, mark the spots worth varying, and let a payload list run
through them. This module is that idea with the standard library only.

Positions are marked with section signs in a raw request file - the same
convention Intruder uses, so existing Burp request files paste straight
in:

    GET /api/discount?code=§SUMMIT10§ HTTP/1.1
    Host: target.local

A control request (the originals, markers removed) is measured first,
and a response only counts as a divergence when it really moved: a
different status code, or a body size beyond tolerance. Divergence is
where a human starts looking - it is never an automatic vulnerability,
so findings carry confidence=needs-manual and severity stays low.
"""

from __future__ import annotations

import base64
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from urllib.parse import quote

from ..http.client import HttpClient
from ..http.models import HttpRequest, HttpResponse
from ..scan.core import Finding

# Intruder's position marker. Kept out of the raw string during parsing;
# anything between a pair of section signs is one position.
POSITION = re.compile(r"§([^§\n]*)§")

ENCODERS = ("none", "url", "b64")

# A body is "the same" while it stays within this many bytes of the
# control response. Tight enough to catch the discount-code case, loose
# enough to ignore CDN padding jitter on otherwise identical pages.
LENGTH_TOLERANCE = 100


@dataclass
class IntruderHit:
    """One fuzzed request and how it compared to the control."""

    payloads: tuple[str, ...]
    request: HttpRequest
    response: HttpResponse | None
    divergent: bool


@dataclass
class IntruderResult:
    control: HttpResponse | None
    hits: list[IntruderHit]


def parse_positions(raw: str) -> list[str]:
    """Return the original value of every §position§, in order."""
    return [match.group(1) for match in POSITION.finditer(raw)]


def encode_payload(value: str, encoder: str) -> str:
    if encoder == "url":
        return quote(value, safe="")
    if encoder == "b64":
        return base64.b64encode(value.encode("utf-8")).decode("ascii")
    if encoder == "none":
        return value
    raise ValueError(f"unknown encoder: {encoder} - valid: {', '.join(ENCODERS)}")


def _render(raw: str, values: list[str]) -> HttpRequest:
    """Substitute the position slots with `values` and parse the request.

    The number of values must match the number of positions; callers
    guarantee that. Parsing happens after substitution so a payload is
    free to reshape the request line, a header or the body alike.
    """
    iterator = iter(values)
    filled = POSITION.sub(lambda _: next(iterator), raw)
    return HttpRequest.from_raw(filled)


def sniper_requests(raw: str, payloads: list[str], encoder: str = "none") -> list[HttpRequest]:
    """One position at a time: N positions x M payloads = N*M requests.

    Positions not under test keep their original values, so every request
    differs from the control in exactly one slot and a divergence maps
    back to a single payload.
    """
    originals = parse_positions(raw)
    if not originals:
        raise ValueError("no §positions§ found in the request - mark at least one")
    requests: list[HttpRequest] = []
    for index in range(len(originals)):
        for payload in payloads:
            values = list(originals)
            values[index] = encode_payload(payload, encoder)
            requests.append(_render(raw, values))
    return requests


def pitchfork_requests(raw: str, payload_sets: list[list[str]], encoder: str = "none") -> list[HttpRequest]:
    """Positions paired with payload sets, one row per request.

    Position 1 takes payload set 1, position 2 takes set 2, and so on.
    Sets may differ in length; shorter ones stop the run at their last
    row rather than padding with empty strings.
    """
    originals = parse_positions(raw)
    if not originals:
        raise ValueError("no §positions§ found in the request - mark at least one")
    if len(payload_sets) != len(originals):
        raise ValueError(
            f"pitchfork needs one payload set per position: {len(originals)} position(s), "
            f"{len(payload_sets)} set(s)"
        )
    rows = min(len(payload_set) for payload_set in payload_sets)
    if rows == 0:
        return []
    requests: list[HttpRequest] = []
    for row in range(rows):
        values = [
            encode_payload(payload_set[row], encoder)
            for payload_set in payload_sets
        ]
        requests.append(_render(raw, values))
    return requests


def _is_divergent(response: HttpResponse | None, control: HttpResponse | None) -> bool:
    if response is None or control is None:
        return True  # a request that died while the control lived is signal
    if response.status != control.status:
        return True
    return abs(len(response.body) - len(control.body)) > LENGTH_TOLERANCE


def run_intruder(
    client: HttpClient,
    raw: str,
    payloads: list[str] | None = None,
    payload_sets: list[list[str]] | None = None,
    mode: str = "sniper",
    encoder: str = "none",
    threads: int = 10,
) -> IntruderResult:
    """Run the marked positions through the payload list.

    The control request goes first so every probe has a fixed reference.
    `payloads` drives sniper mode; `payload_sets` drives pitchfork mode.
    """
    if encoder not in ENCODERS:
        raise ValueError(f"unknown encoder: {encoder} - valid: {', '.join(ENCODERS)}")
    originals = parse_positions(raw)
    if not originals:
        raise ValueError("no §positions§ found in the request - mark at least one")

    control: HttpResponse | None = None
    try:
        control = client.send(_render(raw, list(originals)))
    except Exception:
        control = None  # the control dying makes every probe divergent

    plan: list[tuple[tuple[str, ...], HttpRequest]] = []
    if mode == "pitchfork":
        if payload_sets is None:
            raise ValueError("pitchfork mode needs payload_sets (one list per position)")
        for row, request in enumerate(pitchfork_requests(raw, payload_sets, encoder)):
            plan.append((tuple(payload_set[row] for payload_set in payload_sets), request))
    else:
        if not payloads:
            raise ValueError("sniper mode needs a payload list")
        # sniper_requests walks position-major: position first, then its
        # payload run. Labels follow that order.
        labels = [(payload,) for _ in originals for payload in payloads]
        plan = list(zip(labels, sniper_requests(raw, payloads, encoder)))

    hits: list[IntruderHit] = []

    def probe(request: HttpRequest) -> HttpResponse | None:
        try:
            return client.send(request)
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futures = {pool.submit(probe, request): (label, request) for label, request in plan}
        for future in as_completed(futures):
            label, request = futures[future]
            response = future.result()
            hits.append(
                IntruderHit(
                    payloads=label,
                    request=request,
                    response=response,
                    divergent=_is_divergent(response, control),
                )
            )

    hits.sort(key=lambda hit: (not hit.divergent, hit.payloads))
    return IntruderResult(control=control, hits=hits)


def findings_from(result: IntruderResult) -> list[Finding]:
    """One finding per divergent payload, needs-manual by design."""
    if result.control is None:
        return []
    findings: list[Finding] = []
    for hit in result.hits:
        if not hit.divergent or hit.response is None:
            continue
        summary = (
            f"HTTP {hit.response.status}, {len(hit.response.body)} bytes "
            f"(control: HTTP {result.control.status}, {len(result.control.body)} bytes)"
        )
        findings.append(
            Finding(
                check_id="fuzz-divergence",
                title=f"Payload diverges from the control: {', '.join(hit.payloads)}",
                severity="low",
                url=hit.request.url,
                param=", ".join(hit.payloads),
                detail=(
                    "This payload produced a materially different response from the original "
                    "request. Divergence is where hidden behavior lives: valid identifiers, "
                    "debug flags and privilege boundaries usually show up as exactly this "
                    "kind of status or size shift. Confirm by hand what the difference means."
                ),
                evidence=summary,
                remediation=(
                    "Review the divergent response manually. If it reveals an undocumented "
                    "behavior, decide whether that endpoint should answer unauthenticated callers at all."
                ),
            )
        )
    return findings
