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

## Privacy model (so far)

A HAR file holds **live session tokens**. Log out of the application after capturing, so
the tokens in the file stop working, and keep captures out of version control.

- **Scope first.** `--scope app.test,*.api.app.test` (or `--scope-file`) is required.
  Traffic to any other host is dropped before anything reads it. Only the host name and a
  request count are kept, so you can see what was excluded. Well-known analytics, ad and
  CDN hosts are dropped as noise even if a wildcard matches them. Name one exactly to keep it.
- **Redaction before analysis.** Cookie values, auth headers, API keys, tokens in URLs, and
  secret-named fields become `<redacted:xxxxxxxx>` fingerprints. The fingerprint is a keyed
  hash with a fresh random key each run, so repeats correlate within a run but short
  secrets can't be guessed back from it. JWTs are decoded to their header and safe claims
  (`alg`, `kid`, `exp`, roles, scopes). The signature is dropped and identity claims are
  fingerprinted. Body and query values are masked to shapes such as `<str:12>`, `<email>`
  or `<int>`. Names and structure are kept.
- `--show-redaction N` prints transaction N exactly as later stages see it.
- `--keep-body-values` keeps non-secret body and query values for your own local report.
  Credentials and tokens are still removed, and the AI layer (planned for a later phase)
  will never use this view.

## Local checks and the knowledge layer (no AI)

Every run checks the redacted traffic for security headers, cookie attributes, CORS, JWTs
and tokens in URLs, information disclosure, access-control signals (BOLA/IDOR, excessive
data exposure, mass assignment, admin endpoints), caching of authenticated responses, and
GraphQL. Each finding is mapped to the OWASP API Security Top 10 (2023) and the OWASP WSTG.
It comes with what was observed, why it may matter, one manual test you can run yourself,
and a short lesson.

Two commands work without any capture or AI:

```bash
reqlens --check-jwt -              # paste a token on stdin (keeps it out of shell history)
reqlens --check-hashes VALUE ...   # identify likely hash/encoding types
```

`--check-jwt` names the algorithm (for example *RS256, RSA signature with SHA-256*). It then
lists the attack classes worth testing: algorithm confusion, `alg: none` acceptance,
signature verification, `kid`/`jku`/embedded-key tricks, key hygiene, expiry, and sensitive
claims. Each comes with a manual test and a reference. The signature is never shown.

`--check-hashes` only identifies values. Nothing is ever cracked.

Status: report files (md/html/json) are planned for phase 4; findings are printed for now.

## Development

```bash
python -m venv .venv
.venv\Scripts\python -m pip install -e .[dev]
.venv\Scripts\python -m pytest
.venv\Scripts\python -m ruff check .
```
