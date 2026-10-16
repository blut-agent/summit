"""GraphQL introspection detection (CWE-200).

GraphQL APIs that leave introspection enabled hand attackers a complete
map of the schema - every type, field and mutation - which is step one
of every GraphQL attack. The probe sends a minimal introspection query
as POST (and GET as fallback) to common GraphQL paths and confirms only
when the response actually contains a `__schema` payload.
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from .http.client import HttpClient
from .http.models import HttpRequest
from .scan.core import Finding

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql", "/graphql/console"]
INTROSPECTION_BODY = json.dumps({"query": "{ __schema { queryType { name } } }"})


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
