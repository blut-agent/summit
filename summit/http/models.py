from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


@dataclass
class HttpRequest:
    method: str = "GET"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None

    @classmethod
    def from_raw(cls, raw: str) -> "HttpRequest":
        """Parse a raw HTTP request (the format Burp/ZAP repeater uses)."""
        text = raw.replace("\r\n", "\n")
        head, sep, body = text.partition("\n\n")
        lines = [line for line in head.split("\n") if line.strip()]
        if not lines:
            raise ValueError("empty request")
        parts = lines[0].split()
        if len(parts) < 2:
            raise ValueError(f"malformed request line: {lines[0]!r}")
        method, target = parts[0].upper(), parts[1]
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            headers[key.strip()] = value.strip()
        if target.startswith("http://") or target.startswith("https://"):
            url = target
        else:
            host = headers.get("Host")
            if not host:
                raise ValueError("missing Host header")
            url = f"http://{host}{target}"
        return cls(
            method=method,
            url=url,
            headers=headers,
            body=body.encode("utf-8") if sep and body else None,
        )

    @property
    def params(self) -> dict[str, str]:
        return dict(parse_qsl(urlsplit(self.url).query, keep_blank_values=True))

    def with_query_param(self, name: str, value: str) -> "HttpRequest":
        """Return a copy with the given query parameter replaced (or appended)."""
        split = urlsplit(self.url)
        pairs = [
            (key, value if key == name else original)
            for key, original in parse_qsl(split.query, keep_blank_values=True)
        ]
        if name not in {key for key, _ in pairs}:
            pairs.append((name, value))
        return HttpRequest(
            method=self.method,
            url=urlunsplit(split._replace(query=urlencode(pairs))),
            headers=dict(self.headers),
            body=self.body,
        )

    def with_header(self, name: str, value: str) -> "HttpRequest":
        """Return a copy with the given header set (Host included - requests
        honors an explicit Host instead of deriving one from the URL)."""
        headers = dict(self.headers)
        headers[name] = value
        return HttpRequest(method=self.method, url=self.url, headers=headers, body=self.body)


@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    request: HttpRequest = field(default_factory=HttpRequest)
    elapsed: float = 0.0
    set_cookies: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def header(self, name: str, default: str = "") -> str:
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return default

    def headers_text(self) -> str:
        """All response headers as one 'Name: value' block, for matchers."""
        return "\r\n".join(f"{key}: {value}" for key, value in self.headers.items())
