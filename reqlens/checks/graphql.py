"""GraphQL: endpoint inventory, introspection in captured traffic, field suggestions."""

from __future__ import annotations

from collections.abc import Iterable

from reqlens.checks import Context, json_body
from reqlens.knowledge.catalog import make_finding
from reqlens.model import Finding, Transaction


def _is_graphql(tx: Transaction) -> bool:
    if "graphql" in tx.path.lower():
        return True
    body = json_body(tx.request_body)
    return isinstance(body, dict) and isinstance(body.get("query"), str) and ("{" in body["query"])


def run(ctx: Context) -> Iterable[Finding]:
    """Yield GraphQL findings."""
    graphql = [tx for tx in ctx.transactions if _is_graphql(tx)]
    if not graphql:
        return
    by_endpoint: dict[str, list[Transaction]] = {}
    for tx in graphql:
        by_endpoint.setdefault(f"{tx.host}{tx.path}", []).append(tx)
    for url, members in by_endpoint.items():
        operations = sorted({ctx.endpoint_key(tx) for tx in members})
        yield make_finding(
            "GQL-ENDPOINT",
            [ctx.evidence(tx, "url", "operation", ctx.endpoint_key(tx)) for tx in members],
            title=f"GraphQL endpoint in use ({url})",
            observed=f"{len(operations)} distinct operation(s) captured.",
        )
    for tx in graphql:
        request, response = tx.request_body, tx.response_body
        asked = "__schema" in request or "IntrospectionQuery" in request
        answered = "__schema" in response and (tx.status or 0) < 400
        if answered:
            yield make_finding(
                "GQL-INTROSPECTION",
                [ctx.evidence(tx, "response body", "__schema", "schema returned")],
                observed="An introspection query was answered with the schema.",
            )
        elif asked:
            yield make_finding(
                "GQL-INTROSPECTION",
                [ctx.evidence(tx, "request body", "__schema", f"status {tx.status}")],
                concern="info",
                informational=True,
                title="GraphQL introspection requested (response did not include a schema)",
                observed="The client sent an introspection query; the captured response did "
                "not contain a schema, so introspection may be disabled.",
            )
        if "Did you mean" in response:
            yield make_finding(
                "GQL-FIELD-SUGGESTIONS",
                [ctx.evidence(tx, "response body", "errors", "Did you mean ...")],
            )
