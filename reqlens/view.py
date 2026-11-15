"""Plain-text rendering for the terminal (``--show-redaction`` and run summaries).

Everything rendered here passes through :func:`reqlens.sanitize.clean_text`.
"""

from __future__ import annotations

from reqlens.group import Endpoint
from reqlens.loaders.base import LoadResult
from reqlens.model import Transaction
from reqlens.sanitize import clean_text
from reqlens.scope import ScopeResult


def _line(text: str) -> str:
    return clean_text(text, keep_newlines=False)


def render_transaction(tx: Transaction, policy_label: str) -> str:
    """Show a transaction as an HTTP-like text block, plus what redaction removed."""
    if not tx.redacted:
        raise ValueError("refusing to render an unredacted transaction")
    lines = [
        f"# transaction {tx.index} after redaction ({policy_label})",
        "",
        _line(f"{tx.method} {tx.url}"),
    ]
    lines += [_line(f"{name}: {value}") for name, value in tx.request_headers]
    if tx.request_body:
        lines += ["", clean_text(tx.request_body)]
    lines += ["", f"--- response {tx.status if tx.status is not None else '(none captured)'}"]
    lines += [_line(f"{name}: {value}") for name, value in tx.response_headers]
    if tx.response_body:
        lines += ["", clean_text(tx.response_body)]
    if tx.tokens:
        lines += ["", "--- secrets removed (structure only)"]
        for token in tx.tokens:
            detail = f"{token.kind} in {token.location}"
            if token.name:
                detail += f" '{token.name}'"
            detail += f": {token.format}, {token.length} chars, fingerprint {token.fingerprint}"
            if token.in_url:
                detail += ", carried in URL"
            lines.append(_line(f"- {detail}"))
            if token.jwt_header:
                lines.append(_line(f"    jwt header: {token.jwt_header}"))
            if token.jwt_claims:
                lines.append(_line(f"    jwt claims: {token.jwt_claims}"))
    if tx.pii:
        lines += ["", "--- personal data detected"]
        for hit in tx.pii:
            where = f"{hit.location} '{hit.name}'" if hit.name else hit.location
            lines.append(_line(f"- {hit.kind} in {where}"))
    if tx.notes:
        lines += ["", "--- notes"] + [_line(f"- {note}") for note in tx.notes]
    return "\n".join(lines)


def render_summary(
    loaded: LoadResult, scoped: ScopeResult, redacted: list[Transaction], endpoints: list[Endpoint]
) -> str:
    """One-screen summary of the pipeline so far."""
    hosts = sorted({tx.host for tx in scoped.kept})
    tokens = sum(len(tx.tokens) for tx in redacted)
    pii = sum(len(tx.pii) for tx in redacted)
    lines = [
        f"loaded {len(loaded.transactions)} transactions from {len(loaded.files)} file(s)",
        f"in scope: {len(scoped.kept)} transactions on {', '.join(hosts)}",
    ]
    if scoped.dropped:
        noise = [d for d in scoped.dropped.values() if d.reason == "third-party noise"]
        other = [d for d in scoped.dropped.values() if d.reason == "out of scope"]
        lines.append(
            f"dropped: {sum(d.count for d in other)} out-of-scope and "
            f"{sum(d.count for d in noise)} third-party-noise requests"
        )
        for item in sorted(scoped.dropped.values(), key=lambda d: (-d.count, d.host)):
            lines.append(f"  - {item.host} ({item.count}, {item.reason})")
    lines.append(f"redacted: {tokens} secret values and {pii} personal-data values removed")
    lines.append(f"grouped into {len(endpoints)} endpoint patterns:")
    for endpoint in endpoints:
        statuses = ",".join(str(s) for s in endpoint.statuses) or "-"
        lines.append(f"  - {endpoint.key}  x{len(endpoint.members)}  [{statuses}]")
    return "\n".join(_line(line) for line in lines)
