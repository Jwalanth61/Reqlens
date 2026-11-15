"""Plain-text rendering for the terminal (``--show-redaction`` and run summaries).

Everything rendered here passes through :func:`reqlens.sanitize.clean_text`.
"""

from __future__ import annotations

import textwrap

from reqlens import config
from reqlens.group import Endpoint
from reqlens.knowledge import catalog, hashes
from reqlens.knowledge import jwt as jwt_knowledge
from reqlens.loaders.base import LoadResult
from reqlens.model import Finding, TokenRecord, Transaction
from reqlens.sanitize import clean_text
from reqlens.scope import ScopeResult

_WIDTH = 96


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


def _wrap(label: str, text: str, indent: str = "   ") -> list[str]:
    body = textwrap.fill(
        _line(text),
        width=_WIDTH,
        initial_indent=f"{indent}{label}",
        subsequent_indent=indent + "  ",
    )
    return body.splitlines()


def _finding_block(number: int, finding: Finding) -> list[str]:
    category = catalog.CATEGORIES.get(finding.category, "")
    meta = f"concern: {finding.concern.value} | {finding.confidence.value} | {finding.category}"
    if category:
        meta += f" {category}"
    if finding.wstg:
        meta += f" | {', '.join(finding.wstg)}"
    lines = [_line(f"{number}. {finding.title}"), f"   [{meta}]"]
    if finding.observed:
        lines += _wrap("Observed: ", finding.observed)
    lines += _wrap("Why it may matter: ", finding.why)
    lines += _wrap("Manual test: ", finding.manual_test)
    lines += _wrap("Learn: ", finding.learning)
    if finding.evidence:
        extra = finding.occurrences - len(finding.evidence)
        lines.append("   Evidence:")
        for item in finding.evidence:
            where = f"{item.location} {item.name}".strip()
            lines.append(
                _line(f"     - #{item.transaction_index} {item.endpoint} | {where}: {item.value}")
            )
        if extra > 0:
            lines.append(f"     - ... and {extra} more")
    for reference in finding.references:
        lines.append(_line(f"   Reference: {reference}"))
    return lines


def render_findings(findings: list[Finding]) -> str:
    """Terminal listing of findings, grouped by category (already sorted)."""
    lines = [_line(config.PASSIVE_BANNER), ""]
    if not findings:
        lines.append("No findings from the local checks.")
        return "\n".join(lines)
    counts = {level: 0 for level in ("high", "medium", "low", "info")}
    for finding in findings:
        counts[finding.concern.value] += 1
    lines.append(
        f"{len(findings)} findings: "
        + ", ".join(f"{count} {level}" for level, count in counts.items() if count)
    )
    current = None
    for number, finding in enumerate(findings, 1):
        if finding.category != current:
            current = finding.category
            name = catalog.CATEGORIES.get(current, "")
            lines += ["", f"== {current} {name} ==".rstrip()]
        lines += [""] + _finding_block(number, finding)
    return "\n".join(lines)


def render_jwt_knowledge(token: TokenRecord) -> str:
    """The --check-jwt report: identification plus attack classes to test by hand."""
    alg = str(token.jwt_header.get("alg", ""))
    lines = [
        _line(f"Identified: {jwt_knowledge.describe(alg)}"),
        _line(f"Header: {token.jwt_header}"),
        _line(f"Claims (identity values fingerprinted): {token.jwt_claims}"),
        "Signature: " + ("present (not shown)" if token.format == "jwt" else "none"),
        "",
        "Possible issues to test. reqlens performs none of these; run them yourself, once,",
        "with your own test account, and only against targets you are authorized to test.",
    ]
    for number, issue in enumerate(jwt_knowledge.analyse(token), 1):
        entry = catalog.entry(issue.check_id)
        lines += [
            "",
            _line(
                f"{number}. {entry.title}  [concern: {issue.concern or entry.concern.value} | "
                f"{entry.category} | {', '.join(entry.wstg)}]"
            ),
        ]
        lines += _wrap("Observed: ", issue.observed)
        lines += _wrap("Why it may matter: ", entry.why)
        lines += _wrap("Manual test: ", entry.manual_test)
        lines += _wrap("Learn: ", entry.learning)
        lines += [_line(f"   Reference: {ref}") for ref in entry.references]
    return "\n".join(lines)


def render_hash_knowledge(values: list[str]) -> str:
    """The --check-hashes report. Values themselves are not echoed, only their shape."""
    lines = ["Hash / encoding identification (identification only; nothing is cracked)."]
    for number, value in enumerate(values, 1):
        fmt, candidates = hashes.identify_value(value)
        lines += ["", f"{number}. value of {len(value.strip())} characters, shape {fmt}"]
        if not candidates:
            lines.append("   No common hash or token format matches this shape.")
        for candidate in candidates:
            mode = (
                (f" (hashcat mode {candidate.hashcat_mode}, for offline tests of values you own)")
                if candidate.hashcat_mode is not None
                else ""
            )
            lines += _wrap(f"- {candidate.name}: ", candidate.note + mode)
            if candidate.password_hash:
                lines += _wrap(
                    "",
                    "Password-hash format: if an API returns this to clients, "
                    "that is a serious exposure in itself.",
                )
    return "\n".join(lines)
