"""CAPTCHA and anti-bot challenge detection.

Summit does not solve CAPTCHAs - that belongs to a human with a browser,
and automating it would cross lines we will not cross. What the scanner
does is detect the challenge, tell you exactly which one is in the way,
and stop burning requests against it. Knowing "this endpoint sits behind
reCAPTCHA" is actionable; hammering it is not.
"""

from __future__ import annotations

from .http.models import HttpResponse
from .scan.core import Finding

CHALLENGE_SIGNATURES: list[tuple[str, list[str]]] = [
    ("reCAPTCHA", ["recaptcha/api.js", "g-recaptcha", "grecaptcha.execute"]),
    ("hCaptcha", ["hcaptcha.com/1/api.js", "h-captcha"]),
    ("Cloudflare challenge", ["cf_chl_opt", "checking your browser", "verifying you are human"]),
]

_TURNSTILE = "challenges.cloudflare.com/turnstile"
_MAX_BODY = 20_000


def detect_challenge(response: HttpResponse) -> tuple[str, str] | None:
    """Return (challenge name, evidence) when the response contains one."""
    body = response.text[:_MAX_BODY].lower()
    if _TURNSTILE in body:
        return "Cloudflare Turnstile", _TURNSTILE
    for name, markers in CHALLENGE_SIGNATURES:
        for marker in markers:
            if marker in body:
                return name, marker
    return None


def check_challenge(response: HttpResponse) -> list[Finding]:
    detected = detect_challenge(response)
    if not detected:
        return []
    name, evidence = detected
    return [
        Finding(
            check_id="captcha-challenge",
            title=f"CAPTCHA/challenge detected: {name}",
            severity="info",
            url=response.request.url,
            detail=(
                f"This endpoint is protected by {name}. Summit reports the challenge "
                "instead of hammering it - automated CAPTCHA solving is out of scope "
                "by design. Test this surface manually in a browser."
            ),
            evidence=evidence,
        )
    ]
