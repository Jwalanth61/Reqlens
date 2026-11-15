"""Security response headers: HSTS, CSP, framing, nosniff, Referrer-Policy,
Permissions-Policy, and version banners."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable

from reqlens.checks import Context, is_html
from reqlens.knowledge.catalog import make_finding
from reqlens.model import Finding, Transaction

MIN_HSTS_MAX_AGE = 15_552_000  # 180 days
VERSION_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-runtime-version",
    "x-version",
)
_VERSION_RE = re.compile(r"\d+\.\d+")
_META_CSP_RE = re.compile(r"<meta[^>]+http-equiv=[\"']?content-security-policy", re.IGNORECASE)


def parse_csp(policy: str) -> dict[str, list[str]]:
    """Split a CSP header into ``{directive: [sources]}`` (lower-case directive names)."""
    directives: dict[str, list[str]] = {}
    for part in policy.split(";"):
        tokens = part.split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t for t in tokens[1:]])
    return directives


def csp_weaknesses(policy: str) -> list[str]:
    """Reasons the policy's script sources are weak (empty if none found)."""
    directives = parse_csp(policy)
    sources = directives.get("script-src", directives.get("default-src"))
    if sources is None:
        return ["no script-src or default-src directive"]
    lowered = [s.lower() for s in sources]
    reasons = []
    has_nonce_or_hash = any(
        s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in lowered
    )
    if "'unsafe-inline'" in lowered and not has_nonce_or_hash and "'strict-dynamic'" not in lowered:
        reasons.append("'unsafe-inline' in script sources")
    if "'unsafe-eval'" in lowered:
        reasons.append("'unsafe-eval' in script sources")
    broad = [s for s in lowered if s in ("*", "http:", "https:", "data:")]
    if broad:
        reasons.append(f"broad script source(s): {' '.join(broad)}")
    return reasons


def _by_host(ctx: Context) -> dict[str, list[Transaction]]:
    hosts: dict[str, list[Transaction]] = defaultdict(list)
    for tx in ctx.transactions:
        if tx.status is not None:
            hosts[tx.host].append(tx)
    return hosts


def run(ctx: Context) -> Iterable[Finding]:
    """Yield header findings, one per check and host."""
    for host, responses in _by_host(ctx).items():
        yield from _hsts(ctx, host, responses)
        pages = [tx for tx in responses if is_html(tx) and 200 <= (tx.status or 0) < 300]
        yield from _csp(ctx, host, pages)
        yield from _framing(ctx, host, pages)
        yield from _nosniff(ctx, host, responses)
        yield from _referrer(ctx, host, pages)
        yield from _permissions(ctx, host, pages)
    yield from _versions(ctx)


def _hsts(ctx: Context, host: str, responses: list[Transaction]) -> Iterable[Finding]:
    https = [tx for tx in responses if tx.scheme == "https"]
    if not https:
        return
    with_header = [tx for tx in https if tx.response_header("strict-transport-security")]
    if not with_header:
        evidence = [
            ctx.evidence(tx, "response header", "Strict-Transport-Security", "(absent)")
            for tx in https
        ]
        yield make_finding(
            "HDR-HSTS-MISSING",
            evidence,
            title=f"HSTS header missing ({host})",
            observed=f"None of the {len(https)} HTTPS responses from {host} sent "
            "Strict-Transport-Security.",
        )
        return
    for tx in with_header:
        value = tx.response_header("strict-transport-security") or ""
        match = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.IGNORECASE)
        if match and int(match.group(1)) < MIN_HSTS_MAX_AGE:
            yield make_finding(
                "HDR-HSTS-WEAK",
                [ctx.evidence(tx, "response header", "Strict-Transport-Security", value)],
                title=f"HSTS max-age is short ({host})",
                observed=f"max-age={match.group(1)} seconds "
                f"(about {int(match.group(1)) // 86400} days).",
            )


def _csp(ctx: Context, host: str, pages: list[Transaction]) -> Iterable[Finding]:
    missing = []
    for tx in pages:
        policy = tx.response_header("content-security-policy")
        report_only = tx.response_header("content-security-policy-report-only")
        if policy:
            reasons = csp_weaknesses(policy)
            if reasons:
                yield make_finding(
                    "HDR-CSP-WEAK",
                    [ctx.evidence(tx, "response header", "Content-Security-Policy", policy)],
                    title=f"Content-Security-Policy allows unsafe script sources ({host})",
                    observed="; ".join(reasons) + ".",
                )
        elif report_only:
            yield make_finding(
                "HDR-CSP-REPORT-ONLY",
                [
                    ctx.evidence(
                        tx, "response header", "Content-Security-Policy-Report-Only", report_only
                    )
                ],
                title=f"Content-Security-Policy is report-only ({host})",
            )
        elif not _META_CSP_RE.search(tx.response_body):
            missing.append(
                ctx.evidence(tx, "response header", "Content-Security-Policy", "(absent)")
            )
    if missing:
        yield make_finding(
            "HDR-CSP-MISSING",
            missing,
            title=f"Content-Security-Policy missing on HTML pages ({host})",
            observed=f"{len(missing)} HTML page(s) on {host} have no CSP.",
        )


def _framing(ctx: Context, host: str, pages: list[Transaction]) -> Iterable[Finding]:
    evidence = []
    for tx in pages:
        xfo = tx.response_header("x-frame-options")
        csp = parse_csp(tx.response_header("content-security-policy") or "")
        if not xfo and "frame-ancestors" not in csp:
            evidence.append(ctx.evidence(tx, "response header", "X-Frame-Options", "(absent)"))
    if evidence:
        yield make_finding(
            "HDR-FRAME-MISSING",
            evidence,
            title=f"Page can be framed (clickjacking protection missing) ({host})",
            observed="Neither X-Frame-Options nor CSP frame-ancestors is set.",
        )


def _nosniff(ctx: Context, host: str, responses: list[Transaction]) -> Iterable[Finding]:
    evidence = [
        ctx.evidence(tx, "response header", "X-Content-Type-Options", "(absent)")
        for tx in responses
        if tx.response_body
        and (tx.response_header("x-content-type-options") or "").strip().lower() != "nosniff"
    ]
    if evidence:
        yield make_finding(
            "HDR-NOSNIFF-MISSING",
            evidence,
            title=f"X-Content-Type-Options: nosniff missing ({host})",
        )


def _referrer(ctx: Context, host: str, pages: list[Transaction]) -> Iterable[Finding]:
    missing, unsafe = [], []
    for tx in pages:
        policy = (tx.response_header("referrer-policy") or "").strip().lower()
        if not policy:
            missing.append(ctx.evidence(tx, "response header", "Referrer-Policy", "(absent)"))
        elif policy.split(",")[-1].strip() in ("unsafe-url", "no-referrer-when-downgrade"):
            unsafe.append(ctx.evidence(tx, "response header", "Referrer-Policy", policy))
    if missing:
        yield make_finding(
            "HDR-REFERRER-MISSING", missing, title=f"Referrer-Policy not set ({host})"
        )
    if unsafe:
        yield make_finding(
            "HDR-REFERRER-UNSAFE",
            unsafe,
            title=f"Referrer-Policy sends full URLs to other sites ({host})",
        )


def _permissions(ctx: Context, host: str, pages: list[Transaction]) -> Iterable[Finding]:
    evidence = [
        ctx.evidence(tx, "response header", "Permissions-Policy", "(absent)")
        for tx in pages
        if not tx.response_header("permissions-policy")
    ]
    if evidence:
        yield make_finding(
            "HDR-PERMISSIONS-MISSING", evidence, title=f"Permissions-Policy not set ({host})"
        )


def _versions(ctx: Context) -> Iterable[Finding]:
    seen: set[tuple[str, str, str]] = set()
    for tx in ctx.transactions:
        for name, value in tx.response_headers:
            if name.lower() in VERSION_HEADERS and _VERSION_RE.search(value):
                key = (tx.host, name.lower(), value)
                if key in seen:
                    continue
                seen.add(key)
                yield make_finding(
                    "HDR-VERSION-DISCLOSURE",
                    [ctx.evidence(tx, "response header", name, value)],
                    title=f"Software version disclosed in response headers ({tx.host})",
                    observed=f"{name}: {value}.",
                )
