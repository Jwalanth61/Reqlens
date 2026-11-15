"""Local rule checks. They always run, need no AI, and read only redacted transactions.

Each module exposes ``run(ctx) -> Iterable[Finding]``. The runner merges findings that share
a check id and title (e.g. one 'HSTS missing' finding per host, listing endpoints as
evidence) and sorts them for the report.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Callable

from reqlens.errors import SafetyViolation
from reqlens.group import Endpoint
from reqlens.model import Evidence, Finding, Transaction
from reqlens.sanitize import clean_text, truncate

MAX_EVIDENCE = 8
"""Evidence items kept per finding; ``occurrences`` keeps the full count."""


@dataclass
class Context:
    """Everything a check may look at."""

    transactions: list[Transaction]
    endpoints: list[Endpoint]
    scope: list[str] = field(default_factory=list)
    _endpoint_of: dict[int, Endpoint] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        unredacted = [tx.index for tx in self.transactions if not tx.redacted]
        if unredacted:
            raise SafetyViolation(f"checks received unredacted transactions: {unredacted[:5]}")
        for endpoint in self.endpoints:
            for tx in endpoint.members:
                self._endpoint_of[tx.index] = endpoint

    def endpoint_key(self, tx: Transaction) -> str:
        """Endpoint pattern for a transaction (falls back to method + URL path)."""
        endpoint = self._endpoint_of.get(tx.index)
        return endpoint.key if endpoint else f"{tx.method} {tx.host}{tx.path}"

    def evidence(self, tx: Transaction, location: str, name: str = "", value: str = "") -> Evidence:
        """Evidence for ``tx``; the value is sanitised and shortened."""
        return Evidence(
            transaction_index=tx.index,
            endpoint=self.endpoint_key(tx),
            location=location,
            name=clean_text(name, keep_newlines=False),
            value=truncate(clean_text(value, keep_newlines=False), 240),
        )


Check = Callable[[Context], Iterable[Finding]]


def _registry() -> list[tuple[str, Check]]:
    from reqlens.checks import (
        access,
        caching,
        cookies,
        cors,
        disclosure,
        graphql,
        headers,
        tokens,
    )

    return [
        ("headers", headers.run),
        ("cookies", cookies.run),
        ("cors", cors.run),
        ("tokens", tokens.run),
        ("disclosure", disclosure.run),
        ("access", access.run),
        ("caching", caching.run),
        ("graphql", graphql.run),
    ]


def merge(findings: Iterable[Finding]) -> list[Finding]:
    """Merge findings with the same check id and title; cap evidence; keep the max concern."""
    merged: dict[tuple[str, str], Finding] = {}
    for finding in findings:
        key = (finding.check_id, finding.title)
        current = merged.get(key)
        if current is None:
            finding.occurrences = max(finding.occurrences, len(finding.evidence))
            finding.evidence = finding.evidence[:MAX_EVIDENCE]
            merged[key] = finding
            continue
        current.occurrences += max(finding.occurrences, len(finding.evidence))
        for item in finding.evidence:
            if item not in current.evidence and len(current.evidence) < MAX_EVIDENCE:
                current.evidence.append(item)
        if finding.concern.rank < current.concern.rank:
            current.concern = finding.concern
        if finding.observed and finding.observed not in current.observed:
            current.observed = (current.observed + " " + finding.observed).strip()
    return sorted(merged.values(), key=lambda f: f.sort_key)


def run_checks(ctx: Context, only: list[str] | None = None) -> list[Finding]:
    """Run every registered check (or the named subset) and return merged, sorted findings."""
    found: list[Finding] = []
    for name, check in _registry():
        if only is None or name in only:
            found.extend(check(ctx))
    return merge(found)


# --- helpers shared by check modules -------------------------------------------------------


def is_html(tx: Transaction) -> bool:
    """True if the response is an HTML document."""
    return "html" in (tx.response_header("content-type") or "").lower()


def is_static_asset(tx: Transaction) -> bool:
    """True for scripts, styles, images and fonts (by content type or extension)."""
    content_type = (tx.response_header("content-type") or "").lower()
    if content_type.startswith(("image/", "font/", "text/css", "audio/", "video/")):
        return True
    if "javascript" in content_type:
        return True
    return tx.path.lower().endswith(
        (
            ".js",
            ".css",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".svg",
            ".ico",
            ".woff",
            ".woff2",
            ".ttf",
            ".map",
            ".webp",
        )
    )


def is_authenticated(tx: Transaction) -> bool:
    """True if the request carried a cookie or Authorization header."""
    return bool(tx.request_header("authorization") or tx.request_header("cookie"))


def json_body(text: str) -> Any:
    """Parse a (redacted) JSON body, or return ``None``."""
    stripped = text.lstrip()
    if not stripped.startswith(("{", "[")):
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def json_keys(node: Any, limit: int = 2000) -> list[str]:
    """All object keys in a JSON value (depth-first, bounded)."""
    keys: list[str] = []
    stack = [node]
    while stack and len(keys) < limit:
        current = stack.pop()
        if isinstance(current, dict):
            keys.extend(str(k) for k in current)
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current[:50])
    return keys
