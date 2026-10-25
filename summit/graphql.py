"""GraphQL introspection detection (CWE-200).

GraphQL APIs that leave introspection enabled hand attackers a complete
map of the schema - every type, field and mutation - which is step one
of every GraphQL attack. The probe sends a minimal introspection query
as POST (and GET as fallback) to common GraphQL paths and confirms only
when the response actually contains a `__schema` payload.

Introspection is not the only way the schema leaks, though. Most GraphQL
servers answer an invalid field with a validation error that suggests
close matches - "Did you mean 'secrets'?" - one schema name at a time.
`check_graphql_suggestions` probes for that channel separately: a server
can disable introspection and still hand out its schema this way.
"""

from __future__ import annotations

import json
from urllib.parse import quote, urlsplit

from .http.client import HttpClient
from .http.models import HttpRequest, HttpResponse
from .scan.core import Finding

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql", "/graphql/console"]
INTROSPECTION_BODY = json.dumps({"query": "{ __schema { queryType { name } } }"})
# Deliberately not a real field: servers that leak suggestions answer with
# the closest real names, which is exactly the leak this check listens for.
FIELD_PROBE_QUERY = "{ summitNoSuchFieldProbe }"
FIELD_PROBE_BODY = json.dumps({"query": FIELD_PROBE_QUERY})


def check_graphql(client: HttpClient, base_url: str) -> list[Finding]:
    """Probe common GraphQL paths once per scan. Content decides."""
    findings: list[Finding] = []
    split = urlsplit(base_url)
    origin = f"{split.scheme}://{split.netloc}"
    for path in GRAPHQL_PATHS:
        url = origin + path
        try:
            response = client.send(
                HttpRequest(
                    method="POST",
                    url=url,
                    headers={"Content-Type": "application/json"},
                    body=INTROSPECTION_BODY.encode(),
                )
            )
            if not (response.status == 200 and "__schema" in response.text):
                # some servers only accept GET queries
                response = client.send(HttpRequest(method="GET", url=url + "?query=%7B%20__schema%20%7B%20queryType%20%7B%20name%20%7D%20%7D%20%7D"))
            if response.status == 200 and "__schema" in response.text:
                findings.append(
                    Finding(
                        check_id="graphql-introspection",
                        title=f"GraphQL introspection enabled: {path}",
                        severity="low",
                        url=url,
                        confidence="confirmed",
                        detail=(
                            "Introspection is enabled on a production GraphQL endpoint. The response "
                            "contains a __schema payload - a complete map of every type, field and "
                            "mutation, which is the starting point for most GraphQL attacks."
                        ),
                        evidence=f"POST {path} -> HTTP {response.status} with __schema payload",
                        remediation="Disable introspection in production, or restrict it to authenticated admin roles.",
                    )
                )
                break  # one confirmed introspection endpoint is enough
        except Exception:
            continue
    return findings


def _suggestions_message(response: HttpResponse) -> str:
    """Return the error message when the response suggests field names."""
    try:
        payload = json.loads(response.text)
    except ValueError:
        return ""
    errors = payload.get("errors") if isinstance(payload, dict) else None
    if not isinstance(errors, list):
        return ""
    message = " ".join(
        str(entry.get("message", "")) for entry in errors if isinstance(entry, dict)
    )
    if "did you mean" in message.lower():
        return message
    return ""


def check_graphql_suggestions(client: HttpClient, base_url: str) -> list[Finding]:
    """Probe GraphQL paths with a bogus field; "Did you mean" answers leak
    schema names even where introspection is disabled.

    The probe only counts responses shaped like GraphQL validation errors,
    so plain 404 pages and non-GraphQL endpoints stay quiet.
    """
    findings: list[Finding] = []
    split = urlsplit(base_url)
    origin = f"{split.scheme}://{split.netloc}"
    for path in GRAPHQL_PATHS:
        url = origin + path
        try:
            response = client.send(
                HttpRequest(
                    method="POST",
                    url=url,
                    headers={"Content-Type": "application/json"},
                    body=FIELD_PROBE_BODY.encode(),
                )
            )
            if not _suggestions_message(response):
                # some servers only accept GET queries
                response = client.send(
                    HttpRequest(
                        method="GET",
                        url=f"{url}?query={quote(FIELD_PROBE_QUERY)}",
                    )
                )
            message = _suggestions_message(response)
        except Exception:
            continue
        if not message:
            continue
        findings.append(
            Finding(
                check_id="graphql-field-suggestions",
                title=f"GraphQL field suggestions leak the schema: {path}",
                severity="low",
                url=url,
                confidence="confirmed",
                detail=(
                    "The endpoint answers an invalid field with validation errors that "
                    "suggest close matches. Each error names real schema fields, so the "
                    "full API surface can be enumerated one probe at a time even with "
                    "introspection disabled."
                ),
                evidence=f"POST {path} -> {message.strip()[:200]}",
                remediation=(
                    "Stop returning field suggestions in production. Apollo Server: "
                    "mask validation errors or set __typename-aware error masking; "
                    "GraphQL Java: omit suggestions from ExceptionWhileDataFetching."
                ),
            )
        )
        break  # one leaking endpoint is enough to make the point
    return findings
