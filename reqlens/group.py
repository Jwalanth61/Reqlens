"""Collapse transactions into endpoint patterns.

``GET /users/123`` and ``GET /users/456`` become one endpoint ``GET /users/{id}``. Checks
that look at an endpoint's shape analyse one representative; checks that care about every
occurrence (cookies, tokens) can still walk all members.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from reqlens.model import Transaction

_SEGMENT_RULES: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"^\d+$"), "{id}"),
    (re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"),
     "{uuid}"),
    (re.compile(r"^[0-9a-fA-F]{24}$"), "{objectid}"),
    (re.compile(r"^[0-9a-fA-F]{16,}$"), "{hex}"),
    (re.compile(r"^<(?:redacted|jwt):[0-9a-f]+>$"), "{token}"),
    (re.compile(r"^<email>$"), "{email}"),
    (re.compile(r"^<(?:phone|card|gov-id)>$"), "{pii}"),
    (re.compile(r"^\d{4}-\d{2}-\d{2}$"), "{date}"),
    (re.compile(r"^(?=.*\d)[A-Za-z0-9_-]{20,}$"), "{token}"),
)  # fmt: skip


def normalise_segment(segment: str) -> str:
    """Replace a variable-looking path segment with a ``{placeholder}``."""
    for pattern, placeholder in _SEGMENT_RULES:
        if pattern.match(segment):
            return placeholder
    return segment


def path_pattern(path: str) -> str:
    """Normalise every segment of a URL path."""
    return "/".join(normalise_segment(segment) for segment in path.split("/")) or "/"


def _graphql_operation(tx: Transaction) -> str:
    """``operationName`` of a JSON GraphQL request body, or ''."""
    body = tx.request_body.lstrip()
    if not body.startswith("{") or "operationName" not in body:
        return ""
    try:
        data = json.loads(body)
    except ValueError:
        return ""
    name = data.get("operationName") if isinstance(data, dict) else None
    return name if isinstance(name, str) else ""


@dataclass
class Endpoint:
    """All transactions sharing one method + host + path pattern (+ GraphQL operation)."""

    method: str
    host: str
    pattern: str
    operation: str = ""
    members: list[Transaction] = field(default_factory=list)

    @property
    def key(self) -> str:
        """Human-readable id, e.g. ``GET app.test/users/{id}``."""
        suffix = f" ({self.operation})" if self.operation else ""
        return f"{self.method} {self.host}{self.pattern}{suffix}"

    @property
    def representative(self) -> Transaction:
        """The member analysed for shape checks: first 2xx response, else the first member."""
        for tx in self.members:
            if tx.status is not None and 200 <= tx.status < 300:
                return tx
        return self.members[0]

    @property
    def statuses(self) -> list[int]:
        """Distinct response statuses seen, sorted."""
        return sorted({tx.status for tx in self.members if tx.status is not None})


def group_transactions(transactions: list[Transaction]) -> list[Endpoint]:
    """Group transactions into endpoints, preserving first-seen order."""
    endpoints: dict[tuple[str, str, str, str], Endpoint] = {}
    for tx in transactions:
        operation = _graphql_operation(tx)
        key = (tx.method, tx.host, path_pattern(tx.path), operation)
        endpoint = endpoints.get(key)
        if endpoint is None:
            endpoint = Endpoint(method=key[0], host=key[1], pattern=key[2], operation=operation)
            endpoints[key] = endpoint
        endpoint.members.append(tx)
    return list(endpoints.values())
