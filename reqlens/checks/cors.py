"""CORS response headers compared with the request's Origin."""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlsplit

from reqlens.checks import Context, is_authenticated
from reqlens.knowledge.catalog import make_finding
from reqlens.model import Finding
from reqlens.scope import in_scope


def run(ctx: Context) -> Iterable[Finding]:
    """Yield CORS findings per endpoint."""
    for tx in ctx.transactions:
        allow_origin = (tx.response_header("access-control-allow-origin") or "").strip()
        if not allow_origin:
            continue
        credentials = (tx.response_header("access-control-allow-credentials") or "").strip()
        with_credentials = credentials.lower() == "true"
        origin = (tx.request_header("origin") or "").strip()
        evidence = [
            ctx.evidence(tx, "response header", "Access-Control-Allow-Origin", allow_origin),
        ]
        if credentials:
            evidence.append(
                ctx.evidence(tx, "response header", "Access-Control-Allow-Credentials", credentials)
            )
        cred_note = " with credentials allowed" if with_credentials else ""

        if allow_origin == "null":
            yield make_finding(
                "CORS-NULL-ORIGIN",
                evidence,
                concern="medium" if with_credentials else "low",
                observed=f"Access-Control-Allow-Origin: null{cred_note}.",
            )
        elif allow_origin == "*":
            if with_credentials:
                yield make_finding("CORS-WILDCARD-CREDENTIALS", evidence)
            elif is_authenticated(tx):
                yield make_finding(
                    "CORS-WILDCARD-AUTHENTICATED",
                    evidence,
                    observed="The request carried a cookie or Authorization "
                    "header and the response allows any origin.",
                )
        elif origin and allow_origin.rstrip("/") == origin.rstrip("/"):
            origin_host = (urlsplit(origin).hostname or "").lower()
            if origin_host and not in_scope(origin_host, ctx.scope):
                yield make_finding(
                    "CORS-REFLECTED-ORIGIN",
                    evidence,
                    concern="high" if with_credentials else "medium",
                    observed=f"Request Origin {origin} (outside your scope) was echoed back"
                    f"{cred_note}.",
                )
