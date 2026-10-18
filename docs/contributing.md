# Contributing

Full guide: [CONTRIBUTING.md](https://github.com/pennacle-security/.github/blob/main/CONTRIBUTING.md). The short version, plus the part people ask about most.

## The one pattern to learn

Every active check is a class. Study `summit/scan/modules/xss.py` - it is the reference implementation of the pattern:

```python
class XssReflectCheck(Check):
    check_id = "xss-reflection"     # unique id, used in reports and CI gates
    title = "Reflected XSS"
    severity = "high"

    def run(self, point: InjectionPoint, client: HttpClient) -> list[Finding]:
        # point = one injectable parameter on one request
        # client = the shared HTTP client (rate limiting and retries included)
        ...
        return [Finding(..., confidence="confirmed" | "likely" | "needs-manual" | "info", evidence=...)]
```

Rules that keep the report trustworthy:

1. baseline-diff everything - compare against the same request untouched
2. set `confidence` honestly: `confirmed` only for observed facts - the label caps severity (`likely` -> max medium, `needs-manual` -> max low)
3. safe defaults: probe hosts that cannot resolve, no third-party callback servers
4. register in `summit/scan/modules/__init__.py`
5. add at least one test; `examples/vuln_app.py` is your live target

## Where to start

Issues labeled [good first issue](https://github.com/pennacle-security/summit/labels/good%20first%20issue) come with step-by-step instructions - most take under 30 minutes. Your first issue or PR gets an automatic hello from the welcome bot, and merged PRs earn a spot on the contributors wall in the README.

## Ground rules

- Python 3.10+, stdlib + requests. New dependencies need a discussion first.
- `pytest -q` must pass; `python examples/evidence.py` must end `27/27 claims verified`.
- Commits: short imperative subject, lowercase, no fluff.

## Questions

The [Q&A discussion](https://github.com/pennacle-security/summit/discussions/categories/q-a) is the fastest path - mention the issue number and we will find it.
