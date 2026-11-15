"""Caching of authenticated responses."""

from __future__ import annotations

from collections.abc import Iterable

from reqlens.checks import Context, is_authenticated, is_static_asset
from reqlens.knowledge.catalog import make_finding
from reqlens.model import Finding


def run(ctx: Context) -> Iterable[Finding]:
    """Authenticated 2xx responses with a body and no ``no-store`` (one finding per host)."""
    by_host: dict[str, list] = {}
    public: dict[str, bool] = {}
    for tx in ctx.transactions:
        if not (tx.status and 200 <= tx.status < 300 and tx.response_body):
            continue
        if not is_authenticated(tx) or is_static_asset(tx):
            continue
        cache_control = (tx.response_header("cache-control") or "").lower()
        if "no-store" in cache_control:
            continue
        value = cache_control or "(absent)"
        by_host.setdefault(tx.host, []).append(
            ctx.evidence(tx, "response header", "Cache-Control", value)
        )
        if "public" in cache_control or (
            "max-age" in cache_control
            and "private" not in cache_control
            and "max-age=0" not in cache_control
        ):
            public[tx.host] = True
    for host, evidence in by_host.items():
        yield make_finding(
            "CACHE-AUTH-NO-STORE",
            evidence,
            title=f"Authenticated response may be cached ({host})",
            concern="medium" if public.get(host) else "low",
            observed=f"{len(evidence)} authenticated response(s) without Cache-Control: no-store"
            + ("; some are explicitly cacheable by shared caches." if public.get(host) else "."),
        )
