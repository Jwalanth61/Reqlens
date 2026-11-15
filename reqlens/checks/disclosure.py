"""Information disclosure in responses: stack traces, database/framework errors, internal
addresses and paths, version strings, personal data, and instruction-like text."""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from collections.abc import Iterable

from reqlens.checks import Context
from reqlens.knowledge.catalog import make_finding
from reqlens.model import Finding, Transaction

STACKTRACE_PATTERNS = (
    ("Python traceback", re.compile(r"Traceback \(most recent call last\)")),
    ("Java stack trace", re.compile(r"\bat [\w$.]+\([\w$]+\.java:\d+\)")),
    (".NET stack trace", re.compile(r"\bat [\w.`<>]+\(.*\) in .+:line \d+")),
    ("Node.js stack trace", re.compile(r"\bat .+ \(/[^)]+\.(?:js|ts|mjs|cjs):\d+:\d+\)")),
    ("Ruby backtrace", re.compile(r"\.rb:\d+:in `")),
    ("PHP error", re.compile(r"(?:Fatal error|Warning|Parse error|Notice)</b>?:.+ on line", re.S)),
    ("Go panic", re.compile(r"goroutine \d+ \[running\]")),
)
SQL_PATTERNS = (
    ("MySQL", re.compile(r"You have an error in your SQL syntax|mysql_fetch|mysqli?_", re.I)),
    ("Oracle", re.compile(r"\bORA-\d{5}\b")),
    ("PostgreSQL", re.compile(r"PG::\w+Error|psycopg2\.|PSQLException|syntax error at or near")),
    ("SQL Server", re.compile(r"Unclosed quotation mark|SqlException|Incorrect syntax near")),
    ("SQLite", re.compile(r"sqlite3\.OperationalError|SQLITE_ERROR|SQLiteException")),
    ("generic SQL", re.compile(r"SQLSTATE\[|JDBCException|ODBC (?:Driver|SQL)")),
)
DEBUG_PATTERNS = (
    (
        "Django debug page",
        re.compile(r"You're seeing this error because you have\s+<code>DEBUG = True"),
    ),
    ("Werkzeug debugger", re.compile(r"Werkzeug Debugger|The debugger caught an exception")),
    ("Laravel Whoops/Ignition", re.compile(r"Whoops, looks like something went wrong|Ignition")),
    ("Rails exception page", re.compile(r"Action Controller: Exception caught")),
    ("ASP.NET error page", re.compile(r"Server Error in '/' Application")),
    ("Spring Whitelabel error page", re.compile(r"Whitelabel Error Page")),
    ("Symfony debug page", re.compile(r"Symfony Exception|sf-toolbar")),
)
INTERNAL_HOST_RE = re.compile(
    r"\b(?:[a-z0-9-]+\.)+(?:internal|local|localdomain|corp|lan|intranet|svc\.cluster\.local)\b"
    r"|\blocalhost:\d{2,5}\b",
    re.IGNORECASE,
)
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
FILE_PATH_RE = re.compile(
    r"(?:/(?:home|var/www|usr/src/app|usr/local/lib|opt|srv|app)/[\w.\-/]+"
    r"|[A-Z]:\\(?:inetpub|Users|Program Files|Windows|www|app)[\\\w .\-]+)"
)
VERSION_BODY_RE = re.compile(
    r"\b(Apache|nginx|Microsoft-IIS|Tomcat|Jetty|PHP|Express|Kestrel|LiteSpeed|OpenResty|"
    r"WildFly|JBoss|WebLogic|Werkzeug|gunicorn)[/ ]v?(\d+\.\d+(?:\.\d+)?)",
    re.IGNORECASE,
)
INSTRUCTION_RE = re.compile(
    r"ignore (?:all |any )?(?:the )?(?:previous|prior|above) instructions|"
    r"disregard (?:all |the )?(?:previous|prior|above)|you are (?:now )?an? (?:ai|assistant|"
    r"language model)|system prompt|<\|im_start\|>|###\s*instruction",
    re.IGNORECASE,
)


def _texts(tx: Transaction) -> Iterable[tuple[str, str, str]]:
    """(location, name, text) for every response header and the response body."""
    for name, value in tx.response_headers:
        yield "response header", name, value
    if tx.response_body:
        yield "response body", "", tx.response_body


def _snippet(text: str, start: int, end: int, pad: int = 60) -> str:
    return text[max(0, start - pad) : min(len(text), end + pad)]


def _first_match(patterns, text: str):
    for label, pattern in patterns:
        match = pattern.search(text)
        if match:
            return label, match
    return None


def run(ctx: Context) -> Iterable[Finding]:
    """Yield disclosure findings."""
    scope_hosts = set(ctx.scope)
    for tx in ctx.transactions:
        for location, name, text in _texts(tx):
            for check_id, patterns in (
                ("DISC-STACKTRACE", STACKTRACE_PATTERNS),
                ("DISC-SQL-ERROR", SQL_PATTERNS),
                ("DISC-DEBUG-PAGE", DEBUG_PATTERNS),
            ):
                hit = _first_match(patterns, text)
                if hit:
                    label, match = hit
                    yield make_finding(
                        check_id,
                        [ctx.evidence(tx, location, name, _snippet(text, *match.span()))],
                        observed=f"{label} pattern found.",
                    )
            yield from _internal(ctx, tx, location, name, text, scope_hosts)
            match = VERSION_BODY_RE.search(text) if location == "response body" else None
            if match:
                yield make_finding(
                    "DISC-VERSION-BODY",
                    [ctx.evidence(tx, location, name, _snippet(text, *match.span(), pad=30))],
                    observed=f"{match.group(1)} {match.group(2)} mentioned in the body.",
                )
        yield from _instructions(ctx, tx)
    yield from _pii(ctx)


def _internal(ctx, tx, location, name, text, scope_hosts) -> Iterable[Finding]:
    for match in IPV4_RE.finditer(text):
        try:
            address = ipaddress.ip_address(match.group(0))
        except ValueError:
            continue
        if address.is_private and not address.is_loopback and match.group(0) not in scope_hosts:
            yield make_finding(
                "DISC-INTERNAL-IP",
                [ctx.evidence(tx, location, name, _snippet(text, *match.span(), pad=40))],
                observed=f"Private address {match.group(0)}.",
            )
            break
    if "<ip-private>" in text:
        yield make_finding(
            "DISC-INTERNAL-IP",
            [ctx.evidence(tx, location, name, "<ip-private> (masked value)")],
            observed="A field holds a private IP address (value masked by redaction).",
        )
    match = INTERNAL_HOST_RE.search(text)
    if match and match.group(0).lower() not in scope_hosts:
        yield make_finding(
            "DISC-INTERNAL-HOST",
            [ctx.evidence(tx, location, name, _snippet(text, *match.span(), pad=40))],
            observed=f"Internal hostname {match.group(0)}.",
        )
    match = FILE_PATH_RE.search(text)
    if match:
        yield make_finding(
            "DISC-FILE-PATH",
            [ctx.evidence(tx, location, name, _snippet(text, *match.span(), pad=30))],
            observed=f"Path {match.group(0)}.",
        )


def _instructions(ctx: Context, tx: Transaction) -> Iterable[Finding]:
    sources = [("request body", tx.request_body), ("response body", tx.response_body)]
    sources += [("response header", f"{n}: {v}") for n, v in tx.response_headers]
    for location, text in sources:
        match = INSTRUCTION_RE.search(text or "")
        if match:
            yield make_finding(
                "OBS-INSTRUCTION-TEXT",
                [ctx.evidence(tx, location, "", _snippet(text, *match.span(), pad=40))],
                observed="Captured text addressed to an AI/tool; treated as data only.",
            )
            return


def _pii(ctx: Context) -> Iterable[Finding]:
    """One finding per endpoint, summarising every kind of personal data its responses held."""
    for endpoint in ctx.endpoints:
        kinds: Counter = Counter()
        evidence = []
        for tx in endpoint.members:
            for hit in tx.pii:
                if hit.location.startswith("response"):
                    kinds[hit.kind] += 1
                    evidence.append(ctx.evidence(tx, hit.location, hit.name, f"<{hit.kind}>"))
        if not kinds:
            continue
        serious = kinds.keys() & {"card", "gov-id"}
        summary = ", ".join(f"{kind} x{count}" for kind, count in sorted(kinds.items()))
        yield make_finding(
            "DISC-PII-RESPONSE",
            evidence,
            title=f"Personal data in responses ({endpoint.key})",
            concern="medium" if serious else "info",
            observed=f"Detected across {len(endpoint.members)} response(s): {summary}.",
        )
