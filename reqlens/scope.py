"""Scope filtering: keep only hosts the user is authorized to test.

Out-of-scope traffic is dropped before redaction and analysis, so its content never reaches
a check, a report body, or an AI provider. Only the host name and a request count are kept,
so the report can list what was excluded.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from reqlens.errors import ScopeError
from reqlens.model import Transaction

NOISE_DOMAINS: tuple[str, ...] = (
    # analytics / tag managers / session replay
    "google-analytics.com",
    "analytics.google.com",
    "googletagmanager.com",
    "googletagservices.com",
    "stats.g.doubleclick.net",
    "hotjar.com",
    "hotjar.io",
    "segment.io",
    "segment.com",
    "mixpanel.com",
    "amplitude.com",
    "fullstory.com",
    "clarity.ms",
    "heap.io",
    "heapanalytics.com",
    "newrelic.com",
    "nr-data.net",
    "datadoghq.com",
    "datadoghq.eu",
    "browser-intake-datadoghq.com",
    "sentry.io",
    "ingest.sentry.io",
    "bugsnag.com",
    "launchdarkly.com",
    "optimizely.com",
    "intercom.io",
    "intercomcdn.com",
    # advertising
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "adservice.google.com",
    "facebook.net",
    "connect.facebook.net",
    "ads.linkedin.com",
    "px.ads.linkedin.com",
    "bat.bing.com",
    "ads-twitter.com",
    "criteo.com",
    "taboola.com",
    "outbrain.com",
    # CDNs and font hosts
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "gstatic.com",
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "ajax.googleapis.com",
    "code.jquery.com",
    "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com",
    "use.fontawesome.com",
    "kit.fontawesome.com",
    "static.cloudflareinsights.com",
    "cloudflareinsights.com",
    # browser / OS background traffic
    "clients2.google.com",
    "update.googleapis.com",
    "safebrowsing.googleapis.com",
    "firefox.settings.services.mozilla.com",
    "incoming.telemetry.mozilla.org",
)


@dataclass
class DroppedHost:
    """A host excluded from analysis, with why and how many requests it had."""

    host: str
    reason: str
    """``third-party noise`` or ``out of scope``."""
    count: int = 0


@dataclass
class ScopeResult:
    """In-scope transactions plus a summary of everything dropped."""

    kept: list[Transaction] = field(default_factory=list)
    dropped: dict[str, DroppedHost] = field(default_factory=dict)

    @property
    def dropped_count(self) -> int:
        """Total requests dropped."""
        return sum(item.count for item in self.dropped.values())


def _domain_match(host: str, domain: str) -> bool:
    """True if ``host`` equals ``domain`` or is a subdomain of it."""
    return host == domain or host.endswith("." + domain)


def is_noise(host: str) -> bool:
    """True for well-known analytics, advertising, CDN and browser-background hosts."""
    return any(_domain_match(host, domain) for domain in NOISE_DOMAINS)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def host_matches(host: str, pattern: str) -> bool:
    """Match a host against one scope entry.

    ``app.test`` matches exactly that host. ``*.app.test`` matches its subdomains (not
    ``app.test`` itself; list both if you want both). IP addresses match exactly. Ports are
    ignored (the transaction's host never includes one).
    """
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        base = pattern[2:]
        return bool(base) and not _is_ip(host) and host.endswith("." + base)
    if ":" in pattern and not _is_ip(pattern.strip("[]")):
        pattern = pattern.split(":", 1)[0]  # tolerate "host:port" in scope entries
    return host == pattern.strip("[]")


def in_scope(host: str, scope: list[str]) -> bool:
    """True if ``host`` matches any scope entry."""
    return any(host_matches(host, pattern) for pattern in scope)


def apply_scope(transactions: list[Transaction], scope: list[str]) -> ScopeResult:
    """Split transactions into in-scope ones and a per-host summary of dropped ones.

    Known noise hosts are dropped even when a wildcard would match them; naming the exact
    host in the scope keeps it.
    """
    if not scope:
        raise ScopeError("a scope is required")
    result = ScopeResult()
    for tx in transactions:
        host = tx.host
        exact = host in [pattern.lower().rstrip(".") for pattern in scope]
        if is_noise(host) and not exact:
            reason = "third-party noise"
        elif in_scope(host, scope):
            result.kept.append(tx)
            continue
        else:
            reason = "out of scope"
        entry = result.dropped.setdefault(host, DroppedHost(host=host, reason=reason))
        entry.count += 1
    if not result.kept:
        seen = sorted(result.dropped.values(), key=lambda item: -item.count)[:10]
        hosts = ", ".join(f"{item.host} ({item.count})" for item in seen)
        raise ScopeError(
            f"no transactions match the scope {','.join(scope)}. Hosts in the capture: {hosts}"
        )
    return result
