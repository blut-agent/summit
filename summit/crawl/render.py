"""Optional headless rendering via Playwright.

JS-heavy pages hide their real DOM behind script execution: injected
forms, event handlers and fetch() targets never appear in the raw HTML.
`--render` loads each page in headless Chromium and hands the rendered
DOM back to the passive checks (DOM XSS, secrets, forms).

Playwright stays optional on purpose - the core install keeps three
dependencies. When it is missing, the caller gets a plain message
explaining exactly how to add it.
"""

from __future__ import annotations

from ..http.models import HttpRequest, HttpResponse


class RenderUnavailable(RuntimeError):
    """Raised when Playwright is not installed."""


def available() -> bool:
    try:
        import playwright  # noqa: F401
    except ImportError:
        return False
    return True


def render_pages(urls: list[str], timeout: float = 20.0, max_pages: int = 25) -> list[HttpResponse]:
    """Render each URL in Chromium; return synthetic responses for the DOM."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RenderUnavailable(
            "headless rendering needs the optional Playwright dependency: "
            "pip install playwright && playwright install chromium"
        ) from exc

    rendered: list[HttpResponse] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            for url in urls[:max_pages]:
                try:
                    page.goto(url, wait_until="networkidle", timeout=int(timeout * 1000))
                    html = page.content()
                except Exception:
                    continue
                rendered.append(
                    HttpResponse(
                        status=200,
                        headers={"Content-Type": "text/html; charset=utf-8"},
                        body=html.encode("utf-8"),
                        request=HttpRequest(method="GET", url=url),
                    )
                )
        finally:
            browser.close()
    return rendered
