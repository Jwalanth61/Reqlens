# reqlens

A **passive** HTTP traffic analyzer for authorized web-application security testing.

## The name

**reqlens** means **request lens**. A lens lets you see more clearly without touching what
you're looking at, and that's how this tool works on your traffic:

- **It looks, and never acts.** A lens only takes in what's already there. reqlens reads
  requests and responses you already captured, and sends nothing to the application.
- **It brings detail into focus.** Weak cookie flags, a token's algorithm, an object ID in a
  path, an over-generous CORS header: details that blur together across hundreds of
  requests are brought out one at a time, with an explanation.
- **It filters what you don't need to see.** Out-of-scope hosts, analytics noise and every
  secret value are removed first, so what reaches your report (or an AI) is structure,
  not credentials.
- **It helps you learn to see for yourself.** Each finding comes with a manual test and a
  short lesson, so over time you spot these patterns without the tool.

You log in to an application you are authorized to test and capture your own traffic with
browser DevTools (HAR), Burp Suite, mitmproxy or OWASP ZAP. reqlens reads every request and
response in that capture: headers, cookies, tokens and bodies. It then writes a report of
*possible* issues. Each one comes with:

- what was observed,
- why it may matter,
- a single-step manual test you can run yourself, and
- a short lesson on the vulnerability class, mapped to the OWASP API Security Top 10 (2023)
  and the OWASP Web Security Testing Guide (WSTG).

```bash
reqlens session.har --scope app.example.test --report-format md,html
```

## The passive-only guarantee

These are built into the code structure and enforced by tests, not just documented:

1. **reqlens never sends a request to the target.** It only reads capture files that already
   exist. It has no crawler, replay, mutation, fuzzing, brute force or exploit code. The only
   network code in the project lives in `reqlens/ai/providers/`. It is imported only when you
   pass `--ai`, and it only talks to the AI provider you chose. A test scans every module's
   imports to enforce this. Another test runs a full analysis and checks that no
   network-capable module was even loaded.
2. **reqlens never performs, simulates or scripts an exploit.** Every finding is an
   observation plus one manual step for your own test accounts on your authorized target.
   Findings are "possible" or "informational", never "confirmed"; the data model rejects
   anything else.
3. **The AI only ever produces text.** It gets no tools, filesystem or shell. Its answer is
   validated against a fixed schema, and any code, commands or script tags in it are
   removed. Nothing it returns is executed.
4. **Captured data is untrusted.** Terminal escape and control characters are stripped
   before anything is printed or written. Reports escape everything, and the HTML report
   forbids scripts through its Content-Security-Policy. Captured content is never passed to
   another program on its command line. Instruction-like text found in traffic (for example
   "ignore previous instructions") is reported as an observation and never followed.

The test suite blocks all network access by default. AI tests are allowed to reach
`127.0.0.1` only, where a local mock server stands in for the provider.

## How reqlens differs from scanners and proxies

| | Active scanners (e.g. Burp Scanner, ZAP active scan) | Intercepting proxies (Burp, ZAP, mitmproxy) | **reqlens** |
|---|---|---|---|
| Sends traffic to the target | Yes, many requests | Yes, forwards and replays | **Never** |
| Needs authorization to run | Yes | Yes | You need it to *capture* and to run the manual tests; reqlens itself only reads files |
| Output | Confirmed and suspected issues | Traffic you inspect yourself | Possible issues, with a manual test and a lesson for each |
| Safe on production data | Depends on configuration | Depends on use | Yes: secrets are redacted before analysis |

reqlens works alongside a proxy: capture with the proxy, analyze with reqlens, then verify
the leads by hand in the proxy.

## Install

Python 3.9 or newer. The core has no third-party dependencies.

```bash
pip install .            # adds the `reqlens` command
pip install .[ai]        # optional: the Anthropic package for --ai-provider anthropic
```

You can also run it without installing, using `python reqlens.py ...` or
`python -m reqlens ...`.

## Capturing traffic safely

1. Use **test accounts** on an application you are **authorized** to test.
2. Capture one of these:
   - **Browser (HAR):** open DevTools > Network, tick "Preserve log", use the app, then
     right-click > "Save all as HAR (with content)".
   - **Burp Suite:** in Proxy > HTTP history, select the items, then right-click >
     "Save items" to export XML.
   - **mitmproxy:** `mitmdump -w session.flow`, or "Save" in mitmproxy or mitmweb.
   - **OWASP ZAP:** in History, select messages, then right-click > "Export Messages to
     File".
3. **Log out afterwards.** A capture holds **live session tokens and cookies**. Logging out
   (or letting the session expire) makes them useless if the file leaks. Keep captures out
   of version control; `.gitignore` already excludes `*.har`, `*.flow` and `captures/`.

## Pipeline

```
load -> scope -> redact -> group -> local checks (+ optional tools) -> optional AI -> report
```

| Stage | What happens |
|---|---|
| **Load** | HAR, Burp XML, mitmproxy flows and ZAP exports are detected automatically and merged. Chunked and gzip/deflate bodies are decoded with a size cap. |
| **Scope** | `--scope` is required. Other hosts, and well-known analytics, ad and CDN hosts, are dropped before anything reads them. The report lists them by name and count only. |
| **Redact** | Secrets become `<redacted:xxxxxxxx>` fingerprints, made with a keyed hash under a fresh random key each run. JWTs are reduced to their header and safe claims. Personal data is detected and masked. Body and query values become shapes such as `<str:12>`, `<email>` or `<int>`. If redaction fails, the run stops. |
| **Group** | `/users/123` and `/users/456` become `/users/{id}`; each GraphQL operation is its own endpoint. |
| **Checks** | Headers, cookies, CORS, tokens/JWT, information disclosure, access-control signals (BOLA/IDOR, excessive data exposure, mass assignment, admin endpoints), caching, GraphQL. |
| **AI** (opt-in) | A redacted, condensed digest is sent once to the provider you chose. The answer is cached. |
| **Report** | Markdown, HTML and/or JSON, ordered by OWASP category and then concern. |

## Privacy model

- **Nothing leaves your machine unless you pass `--ai`.** Even then, only a redacted digest
  is sent.
- **Cookies:** names and attributes (`Secure`, `HttpOnly`, `SameSite`, `Domain`, `Path`,
  expiry) are kept. Values become fingerprints, so a value set at login can be matched to
  the same value sent later.
- **Authorization headers, API keys, tokens in URLs and secret-named fields:** the scheme
  and structure are kept; the secret is fingerprinted.
- **JWTs:** `alg`, `typ`, whether a `kid` is present, `iss`, `exp`, `iat`, and role/scope
  values are kept. The signature is dropped. Identity claims such as `sub` and `email` are
  fingerprinted.
- **Personal data** (emails, phone numbers, card numbers, government IDs): detected and
  masked. The report records that a value of that type was present.
- **Bodies:** structure is kept (JSON keys, form field names, sizes) and values are masked.
  `--keep-body-values` shows non-secret values in *your local report only*. Credentials and
  tokens are still removed, and the AI always gets a separately computed strict view.
- **`--show-redaction N`** prints transaction N exactly as later stages see it, so you can
  check nothing leaks.
- **The AI digest** contains only endpoint patterns, statuses, auth type, field *names*,
  short role/scope values, and cookie and JWT structure. Every fingerprint becomes an alias
  numbered in order of appearance (`<T1>`, `<T2>`...). Equal values stay recognisable,
  nothing derived from a secret is sent, and the same capture always produces the same
  digest. That last property is what makes the answer cache work. A final check refuses to
  send anything token-shaped.

## The no-AI knowledge layer

These commands need neither a capture nor AI:

```bash
reqlens --check-jwt -              # paste a token on stdin (keeps it out of shell history)
reqlens --check-hashes VALUE ...   # identify likely hash/encoding types
```

For a token whose header says `alg: RS256`, `--check-jwt` prints *Identified: RS256 (RSA
signature (PKCS#1 v1.5) with SHA-256)*. It then lists what to test by hand:
- algorithm confusion (HS256 signed with the public key),
- `alg: none` acceptance,
- whether the signature is verified at all,
- `kid` injection, if a `kid` header is present,
- key strength and rotation,
- lifetime and sensitive-claim notes.

Each item comes with an explanation, a manual test and a reference. `--check-hashes` only
identifies values; nothing is ever cracked.

## Optional external tools

| Tool | How reqlens finds it | Used for |
|---|---|---|
| [jwt_tool](https://github.com/ticarpi/jwt_tool) | `REQLENS_JWT_TOOL=/path/to/jwt_tool.py` (dependencies in `REQLENS_JWT_TOOL_PYTHON`'s interpreter), or `jwt_tool.py` on PATH | Plain decode, to cross-check the algorithm and header |
| [hashcat](https://hashcat.net) | `REQLENS_HASHCAT=/path/to/hashcat`, or `hashcat` on PATH | `--identify`: which hash modes match a value's shape |

- Tools only ever receive **redacted shapes**. jwt_tool gets a token rebuilt from the
  redacted parts, with a dummy signature and any key URL pointed at a `.invalid` host.
  hashcat gets a made-up sample of the same shape.
- No shell is used and no captured content goes on a command line. Each run happens in an
  empty temporary folder, with API keys removed from its environment, and has a timeout.
- reqlens never installs these tools. If one is missing, you get a one-line note and the
  run continues. Reports record which tools ran, with their versions.

## AI analysis (optional, off by default)

```bash
reqlens session.har --scope app.test --ai --ai-dry-run      # see exactly what would be sent
reqlens session.har --scope app.test --ai                   # Claude API (default)
reqlens session.har --scope app.test --ai --ai-provider openai --ai-model <model>
reqlens session.har --scope app.test --ai --ai-provider ollama --ai-model llama3
reqlens session.har --scope app.test --ai --ai-provider codex   # signed-in CLI, no API key
```

- **Providers:** `anthropic` (default model `claude-opus-5-5`, via the official package,
  with the server-side refusal fallback on models that support it), `openai`, `ollama` (or
  any OpenAI-compatible server via `--ai-base-url`), and the signed-in CLIs `codex`,
  `claude` and `gemini`.
- **API keys come from environment variables only:** `REQLENS_AI_KEY`, `OPENAI_API_KEY`, or
  `ANTHROPIC_API_KEY`, which the Anthropic package reads itself. They are never taken from a
  flag, printed, or written to a report.
- **CLI providers** get the prompt on stdin only. They run with their own tools off or
  read-only, in an empty temporary folder.
- The AI is asked for what rules miss: business-logic oddities, relationships between
  endpoints, and role differences. Each AI finding carries `source: ai`, a single-step
  manual test, and a lesson.
- **Cost control:** the digest is ranked and trimmed to `--ai-budget` (default 3000
  estimated input tokens), and output is capped. `--ai-dry-run` sends nothing. Answers are
  cached in `$XDG_CACHE_HOME/reqlens` (or `~/.cache/reqlens`), readable only by you, so
  re-running on the same capture costs no tokens. `--ai-no-cache` bypasses the cache.
- If the AI step fails (bad key, refusal, network), the error is shown in the report's AI
  section and the local report is still written.

## Every flag

| Flag | Meaning |
|---|---|
| `CAPTURE ...` | Capture files, directories (scanned for `.har .json .xml .flow .flows .mitm .zap`) or globs |
| `--input-format {har,burp,mitmproxy,zap}` | Force the format instead of detecting it |
| `--scope HOSTS` | Comma-separated authorized hosts; `*.app.test` matches subdomains (required) |
| `--scope-file PATH` | One authorized host per line; `#` starts a comment |
| `--report-format md,html,json` | One or more report formats (default `md`) |
| `-o, --output PREFIX` | Report path prefix; each format adds its extension (default `reqlens-report`) |
| `--keep-body-values` | Show non-secret body/query values in your local report (never sent to AI) |
| `--show-redaction N` | Print transaction N after redaction, then exit |
| `--no-external` | Don't use jwt_tool or hashcat even if installed (no process is started) |
| `--check-jwt TOKEN` | Identify a JWT and list attack classes to test by hand (`-` reads stdin) |
| `--check-hashes VALUE ...` | Identify hash/encoding types (`-` reads one value per line from stdin) |
| `--ai` | Run the optional AI analysis |
| `--ai-provider` | `anthropic` (default), `openai`, `ollama`, `codex`, `claude`, `gemini`; env `REQLENS_AI_PROVIDER` |
| `--ai-model` | Model name (required for `openai` and `ollama`); env `REQLENS_AI_MODEL` |
| `--ai-base-url` | Override the API address, e.g. an OpenAI-compatible server |
| `--ai-budget N` | Maximum estimated input tokens to send (default 3000, minimum 800) |
| `--ai-dry-run` | Show the exact digest and token estimate; send nothing |
| `--ai-no-cache` | Ignore and don't save cached AI answers |
| `--version` | Print the version |

Exit codes: `0` success, `1` error, `2` usage error, `3` safety violation (a bug, which stops
the run rather than risk a leak), `130` interrupted.

## Reports

- Every report opens with a passive-analysis banner and a summary. The summary covers
  capture file names (without folders), scope, counts, excluded hosts, redaction totals,
  optional tools and the AI provider.
- Findings follow, ordered by OWASP category and then concern (`high`, `medium`, `low`,
  `info`). Concern says what to test first; it is not a severity rating.
- **HTML** is one self-contained page with no scripts and no external resources. It has
  CSS-only concern filters and light and dark themes.
- **JSON** follows schema `reqlens.report/1` and is meant for pipelines.

## Development

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e .[dev,ai]    # Windows; use .venv/bin/python elsewhere
.venv/Scripts/python -m pytest
.venv/Scripts/python -m ruff check . && .venv/Scripts/python -m ruff format --check .
```

All tests run offline. AI providers are tested against a local mock server, and CLI
providers against fake executables (both ported from Inicon). External tools are tested
with fake scripts that record exactly what they receive.
