# reqlens

A **passive** HTTP traffic analyzer for authorized web-application security testing.

You log in to an application you are authorized to test, capture the traffic (HAR, Burp
Suite XML, mitmproxy, or OWASP ZAP export), and give the capture to reqlens. It reads every
request and response and produces a report of *possible* issues. Each one comes with an
explanation, a single-step manual test you can run yourself, and a short lesson on the
vulnerability class.

> **Status:** under construction (phase 1 of 7: scaffold and data model). The full
> README, covering capture how-to, privacy model, and every flag, lands as the features do.

## The passive-only guarantee

- reqlens **never sends a request to the target**. It only reads capture files on disk.
- It never runs, simulates, or scripts an exploit. Findings are leads, never confirmations.
- The only network code in the project is the optional AI provider layer, reached only
  with `--ai`.
- Captured data is treated as untrusted. Terminal escape and control characters are
  stripped before anything is printed or written.

The test suite blocks every socket by default, so any code path that tried to reach the
network would fail the tests.

## Development

```bash
python -m venv .venv
.venv\Scripts\python -m pip install -e .[dev]
.venv\Scripts\python -m pytest
.venv\Scripts\python -m ruff check .
```
