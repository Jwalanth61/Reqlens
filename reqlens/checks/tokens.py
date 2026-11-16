"""Token checks: JWT attack classes (from the knowledge layer), tokens in URLs, and
password hashes or digests returned by the API. Works only from redaction's TokenRecords."""

from __future__ import annotations

import re
from collections.abc import Iterable

from reqlens.checks import Context
from reqlens.knowledge import hashes
from reqlens.knowledge import jwt as jwt_knowledge
from reqlens.knowledge.catalog import make_finding
from reqlens.model import Finding, TokenRecord, Transaction

_DIGEST_FIELD_RE = re.compile(r"(pass|pwd|hash|secret|digest|salt)", re.IGNORECASE)

# Cache-busting parameters: a public content hash or build stamp appended to static asset
# URLs (e.g. ASP.NET bundles' ?v=<base64url SHA-256>). Redaction still masks them, but they
# are not credentials, so a static asset carrying one is not a token-in-URL lead.
_CACHE_BUSTER_NAMES = frozenset(
    {"v", "ver", "version", "_", "cb", "cachebust", "cachebuster", "rev", "build", "hash"}
)
_STATIC_EXT_RE = re.compile(
    r"\.(js|mjs|css|map|woff2?|ttf|otf|eot|png|jpe?g|gif|svg|ico|webp|avif)$", re.IGNORECASE
)
_STATIC_DIR_RE = re.compile(
    r"^/(scripts|content|bundles|static|assets|dist|css|js|fonts|images|img)/", re.IGNORECASE
)
_STATIC_TYPE_RE = re.compile(
    r"^(text/css|(text|application)/(x-)?javascript|application/ecmascript|font/|image/)",
    re.IGNORECASE,
)


def is_static_asset(tx: Transaction) -> bool:
    """True for scripts, stylesheets, fonts and images (by content type, extension or folder)."""
    content_type = (tx.response_header("Content-Type") or "").strip()
    if content_type:
        return bool(_STATIC_TYPE_RE.match(content_type))
    path = tx.path
    return bool(_STATIC_EXT_RE.search(path) or _STATIC_DIR_RE.match(path))


def is_cache_buster(tx: Transaction, token: TokenRecord) -> bool:
    """A cache-busting query parameter on a static asset: public, not a secret."""
    return (
        token.location.endswith("query")
        and token.name.lower() in _CACHE_BUSTER_NAMES
        and is_static_asset(tx)
    )


def family_key(token: TokenRecord) -> tuple:
    """Tokens from the same issuer/algorithm/key produce the same findings; analyse once."""
    header = token.jwt_header
    return (
        header.get("alg"),
        header.get("kid"),
        token.jwt_claims.get("iss"),
        token.format,
        tuple(sorted(header)),
        "exp" in token.jwt_claims,
    )


def run(ctx: Context) -> Iterable[Finding]:
    """Yield token findings."""
    families: dict[tuple, tuple[Transaction, TokenRecord]] = {}
    family_members: dict[tuple, list[tuple[Transaction, TokenRecord]]] = {}
    for tx in ctx.transactions:
        for token in tx.tokens:
            if token.kind == "jwt":
                key = family_key(token)
                families.setdefault(key, (tx, token))
                family_members.setdefault(key, []).append((tx, token))
            elif token.in_url and not is_cache_buster(tx, token):
                yield make_finding(
                    "TOKEN-IN-URL",
                    [
                        ctx.evidence(
                            tx, token.location, token.name, f"<redacted:{token.fingerprint}>"
                        )
                    ],
                    title=f"Secret token carried in the URL ('{token.name}' on {tx.host})",
                    observed=f"Parameter '{token.name}' carries a {token.format} secret.",
                )
            yield from _hash_findings(ctx, tx, token)

    for key, (_first_tx, token) in families.items():
        members = family_members[key]
        evidence = [
            ctx.evidence(
                m_tx,
                m_token.location,
                m_token.name or "jwt",
                f"<jwt:{m_token.fingerprint}> alg={m_token.jwt_header.get('alg')}",
            )
            for m_tx, m_token in members
        ]
        alg = token.jwt_header.get("alg", "?")
        for issue in jwt_knowledge.analyse(token):
            finding = make_finding(
                issue.check_id,
                evidence,
                source="knowledge",
                observed=issue.observed,
                concern=issue.concern,
            )
            finding.title = f"{finding.title} [{alg}]"
            finding.occurrences = len(members)
            yield finding


def hash_of_interest(token: TokenRecord) -> bool:
    """True for response values shaped like a password hash, or a hex digest in a
    credential-like field. Shared with the optional hashcat step."""
    if "response" not in token.location:
        return False
    candidates = hashes.identify_format(token.format)
    if any(c.password_hash for c in candidates):
        return True
    return (
        bool(candidates)
        and token.format.startswith("hex:")
        and bool(_DIGEST_FIELD_RE.search(token.name or ""))
    )


def _hash_findings(ctx: Context, tx: Transaction, token: TokenRecord) -> Iterable[Finding]:
    if not hash_of_interest(token):
        return
    candidates = hashes.identify_format(token.format)
    evidence = [ctx.evidence(tx, token.location, token.name, f"<redacted:{token.fingerprint}>")]
    names = ", ".join(c.name for c in candidates)
    if any(c.password_hash for c in candidates):
        yield make_finding(
            "HASH-PASSWORD-HASH-EXPOSED",
            evidence,
            source="knowledge",
            observed=f"Field '{token.name or '(free text)'}' holds a value shaped like: {names}.",
        )
    else:
        yield make_finding(
            "HASH-DIGEST-EXPOSED",
            evidence,
            source="knowledge",
            observed=f"Field '{token.name}' holds a {token.format} value; could be: {names}.",
        )
