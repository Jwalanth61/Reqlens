"""Cookie attributes from Set-Cookie headers (values are already redacted)."""

from __future__ import annotations

import contextlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from reqlens.checks import Context
from reqlens.knowledge.catalog import make_finding
from reqlens.model import Finding, Transaction
from reqlens.redact import is_sensitive_name

SESSION_NAMES = frozenset(
    {
        "jsessionid",
        "phpsessid",
        "asp.net_sessionid",
        "aspsessionid",
        "connect.sid",
        "sid",
        "laravel_session",
        "_session_id",
        "session",
        "sessionid",
        "ci_session",
        "cfid",
        "cftoken",
        "remember",
        "remember_me",
        "rememberme",
        "auth",
        "token",
    }
)
PERSISTENT_SECONDS = 7 * 86400


@dataclass
class SetCookie:
    """Parsed Set-Cookie header (value already redacted)."""

    name: str
    attributes: dict[str, str] = field(default_factory=dict)
    """Lower-case attribute name -> value ('' for flags)."""

    @property
    def is_session_like(self) -> bool:
        lowered = self.name.lower()
        return (
            lowered in SESSION_NAMES
            or lowered.startswith(("__host-", "__secure-"))
            or (is_sensitive_name(self.name))
        )


def parse_set_cookie(value: str) -> SetCookie:
    """Parse a Set-Cookie value into name and attributes."""
    first, *rest = value.split(";")
    cookie = SetCookie(first.partition("=")[0].strip())
    for part in rest:
        name, _, attr_value = part.strip().partition("=")
        if name:
            cookie.attributes[name.lower()] = attr_value.strip()
    return cookie


def lifetime_seconds(cookie: SetCookie, tx: Transaction) -> float | None:
    """Seconds until expiry from Max-Age or Expires (relative to the response Date)."""
    if "max-age" in cookie.attributes:
        try:
            return float(cookie.attributes["max-age"])
        except ValueError:
            return None
    expires = cookie.attributes.get("expires")
    if not expires:
        return None
    try:
        expiry = parsedate_to_datetime(expires)
    except (TypeError, ValueError):
        return None
    reference = datetime.now(timezone.utc)
    date_header = tx.response_header("date")
    if date_header:
        with contextlib.suppress(TypeError, ValueError):
            reference = parsedate_to_datetime(date_header)
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    return (expiry - reference).total_seconds()


def run(ctx: Context) -> Iterable[Finding]:
    """One finding per (cookie, issue, host); repeats of the same cookie are merged."""
    seen: set[tuple[str, str]] = set()
    for tx in ctx.transactions:
        for name, value in tx.response_headers:
            if name.lower() != "set-cookie":
                continue
            cookie = parse_set_cookie(value)
            key = (tx.host, cookie.name)
            if not cookie.name or key in seen:
                continue
            seen.add(key)
            yield from _check_cookie(ctx, tx, cookie, value)


def _check_cookie(ctx: Context, tx: Transaction, cookie: SetCookie, raw: str) -> Iterable[Finding]:
    attrs = cookie.attributes
    evidence = [ctx.evidence(tx, "response header", "Set-Cookie", raw)]
    label = f"'{cookie.name}' on {tx.host}"
    session = cookie.is_session_like
    kind = "session-like cookie" if session else "cookie"

    if "max-age" in attrs and attrs["max-age"].lstrip("-").isdigit() and int(attrs["max-age"]) <= 0:
        return  # a deletion cookie; attributes don't matter

    if tx.scheme == "https" and "secure" not in attrs:
        yield make_finding(
            "CK-SECURE-MISSING",
            evidence,
            title=f"Cookie {label} set without Secure",
            concern="medium" if session else "low",
            observed=f"The {kind} {label} lacks the Secure attribute.",
        )
    if session and "httponly" not in attrs:
        yield make_finding(
            "CK-HTTPONLY-MISSING",
            evidence,
            title=f"Session cookie {label} readable by JavaScript",
            observed=f"The {kind} {label} lacks HttpOnly.",
        )
    samesite = attrs.get("samesite", None)
    if samesite is None:
        yield make_finding(
            "CK-SAMESITE-MISSING",
            evidence,
            title=f"Cookie {label} set without SameSite",
            concern="low" if session else "info",
        )
    elif samesite.lower() == "none" and "secure" not in attrs:
        yield make_finding(
            "CK-SAMESITE-NONE-INSECURE",
            evidence,
            title=f"Cookie {label}: SameSite=None without Secure",
        )
    domain = attrs.get("domain", "").lstrip(".").lower()
    if domain and domain != tx.host:
        yield make_finding(
            "CK-DOMAIN-BROAD",
            evidence,
            title=f"Cookie {label} scoped to parent domain {domain}",
            concern="low" if session else "info",
            observed=f"Domain={domain} shares the cookie with every subdomain of {domain}.",
        )
    if session:
        lifetime = lifetime_seconds(cookie, tx)
        if lifetime is not None and lifetime > PERSISTENT_SECONDS:
            yield make_finding(
                "CK-SESSION-PERSISTENT",
                evidence,
                title=f"Long-lived session cookie {label}",
                observed=f"Cookie stays valid for about {lifetime / 86400:.0f} days.",
            )
