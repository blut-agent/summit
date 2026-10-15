"""Encoder/decoder toolkit - the parts of Burp's Decoder you actually use,
plus JWT decoding. Decoding a JWT here shows the header and payload; it
does NOT verify the signature, and it says so.
"""

from __future__ import annotations

import base64
import binascii
import json
import urllib.parse

SUPPORTED_ENCODINGS = ("b64", "url", "hex", "jwt")


def b64_encode(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def b64_decode(value: str) -> str:
    cleaned = "".join(value.split())
    padded = cleaned + "=" * (-len(cleaned) % 4)
    try:
        return base64.b64decode(padded, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        # Tokens often use the base64url alphabet; try that before giving up.
        return base64.urlsafe_b64decode(padded + "=" * (-(len(padded)) % 4)).decode("utf-8")


def jwt_decode(token: str) -> str:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("a JWT has three dot-separated parts; this has %d" % len(parts))
    try:
        header = json.loads(b64_decode(parts[0]))
        payload = json.loads(b64_decode(parts[1]))
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"JWT segments are not valid base64url JSON: {exc}") from exc
    note = "signature NOT verified - decoding only"
    return (
        "header:\n"
        + json.dumps(header, indent=2)
        + "\n\npayload:\n"
        + json.dumps(payload, indent=2)
        + f"\n\n({note})"
    )


def encode_text(value: str, encoding: str) -> str:
    if encoding == "b64":
        return b64_encode(value)
    if encoding == "url":
        return urllib.parse.quote(value, safe="")
    if encoding == "hex":
        return value.encode("utf-8").hex()
    raise ValueError(f"unsupported encoding: {encoding} (use b64, url, hex)")


def decode_text(value: str, encoding: str) -> str:
    if encoding == "b64":
        return b64_decode(value)
    if encoding == "url":
        return urllib.parse.unquote(value)
    if encoding == "hex":
        try:
            return bytes.fromhex(value.strip()).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError(f"invalid hex input: {exc}") from exc
    if encoding == "jwt":
        return jwt_decode(value)
    raise ValueError(f"unsupported encoding: {encoding} (use b64, url, hex, jwt)")
