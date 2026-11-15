# reqlens

A **passive** HTTP traffic analyzer for authorized web-application security testing.

You log in to an application you are authorized to test, capture the traffic (HAR, Burp
Suite XML, mitmproxy, or OWASP ZAP export), and give the capture to reqlens. It reads every
request and response and produces a report of *possible* issues. Each one comes with an
explanation, a single-step manual test you can run yourself, and a short lesson on the
vulnerability class.

> **Status:** under construction (phase 6 of 7 done: all four input formats, redaction,
> local checks, reports, optional tools). Opt-in AI analysis comes next.
> The full README, covering capture how-to and every flag, lands as the features do.

## Input formats

The format is detected from each file's content. `--input-format` forces it.

| Format | How to export it | Notes |
|---|---|---|
| `har` | Browser DevTools > Network > "Save all as HAR". Burp, ZAP and mitmproxy can also export HAR. | |
| `burp` | Burp Suite: select items in Proxy > HTTP history, then right-click > "Save items" (XML; base64 on or off). | Project files (`.burp`) are not supported. The XML's DOCTYPE is removed before parsing, so no entity or external reference is ever expanded. |
| `mitmproxy` | `mitmdump -w session.flow`, or "Save" in mitmproxy/mitmweb. | Read with reqlens' own bounded parser; nothing is unpickled or executed. Non-HTTP flows are skipped. |
| `zap` | OWASP ZAP: select messages in History, then right-click > "Export Messages to File". | Usually saved as `.txt`. Name the file or use a glob, since directory scans skip `.txt`. |

Several files, a directory or a glob can be given at once, and mixed formats merge into one
analysis. Chunked and gzip/deflate-encoded bodies are decoded with a size cap. Brotli and
zstd bodies are kept as a placeholder.

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

## Optional external tools

reqlens works fully without these. If they are installed, it uses them for identification
only. It never installs, updates or configures them.

| Tool | How reqlens finds it | What it is used for |
|---|---|---|
| [jwt_tool](https://github.com/ticarpi/jwt_tool) | `REQLENS_JWT_TOOL=/path/to/jwt_tool.py`, or `jwt_tool.py` on PATH. Its Python dependencies must be installed for the interpreter in `REQLENS_JWT_TOOL_PYTHON` (default: the interpreter running reqlens). | Plain decode, to cross-check the algorithm and header fields reqlens read |
| [hashcat](https://hashcat.net) | `REQLENS_HASHCAT=/path/to/hashcat`, or `hashcat` on PATH | `--identify`, to list the hash modes that match a value's shape |

What the tools receive:

- **Never your captured secrets.** jwt_tool gets a token rebuilt from the redacted header
  and claims. Identity claims are already fingerprints, the signature is a dummy, and any
  `jku`/`x5u` key URL is pointed at a `.invalid` host. hashcat gets a made-up sample with
  the same shape as the captured value, such as 32 hex characters or a bcrypt-shaped string.
- **No shell, no command-line secrets.** Input goes in through stdin or a file in a fresh,
  empty temporary directory. That directory is the tool's working directory and is deleted
  afterwards.
- **A minimal environment.** API keys and every other non-essential variable are removed.
- **Identification only.** jwt_tool never gets a target URL or a scan, tamper or crack
  mode. hashcat never gets a cracking mode. Each run has a timeout.
- reqlens cannot OS-sandbox a child process, so a tool runs with your user's permissions.
  That is why it is only ever given redacted shapes.

If a tool is missing, reqlens prints one line saying so and continues. Each report lists
which tools were available, with their versions, so runs can be reproduced. `--no-external`
turns tool use off entirely; then no process is started.

## Reports

```bash
reqlens session.har --scope app.test --report-format md,html,json -o reports/app-2026-11
```

- `--report-format` takes one or more of `md`, `html` and `json` (default `md`). `-o` sets
  the path prefix (default `reqlens-report`); each format adds its own extension.
- Every report opens with a passive-analysis banner. It then gives a summary: capture
  files (names only), scope, transaction and endpoint counts, excluded hosts, redaction
  totals, optional tools used, and the AI provider, if any. Findings follow, ordered by
  OWASP category and then concern.
- **HTML** is a single self-contained page with no scripts and no external resources. Its
  Content-Security-Policy forbids both, and it has CSS-only concern filters plus
  light and dark themes.
- **JSON** follows schema `reqlens.report/1` and is meant for pipelines.
- Reports contain only redacted values. All captured text is sanitised, then escaped for
  each format. In Markdown, evidence is shown literally inside code spans.

## Development

```bash
python -m venv .venv
.venv\Scripts\python -m pip install -e .[dev]
.venv\Scripts\python -m pytest
.venv\Scripts\python -m ruff check .
```
