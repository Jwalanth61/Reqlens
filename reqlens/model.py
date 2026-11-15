"""Core data model. Every loader produces :class:`Transaction` objects; every check
produces :class:`Finding` objects. Later stages depend only on these types."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from reqlens.errors import SafetyViolation

Header = tuple[str, str]
"""A single header as ``(name, value)``. Lists of these keep order and duplicates."""


def header_values(headers: list[Header], name: str) -> list[str]:
    """Return every value of header ``name`` (case-insensitive), in order."""
    wanted = name.lower()
    return [value for key, value in headers if key.lower() == wanted]


def header_value(headers: list[Header], name: str) -> str | None:
    """Return the first value of header ``name`` (case-insensitive), or ``None``."""
    values = header_values(headers, name)
    return values[0] if values else None


@dataclass
class TokenRecord:
    """Structural facts about a secret that redaction removed. Never holds the secret.

    Later stages (token checks, the knowledge layer) work from these facts alone.
    """

    kind: str
    """``jwt``, ``cookie``, ``bearer``, ``basic``, ``header-token``, ``field``, ``opaque``."""
    location: str
    """e.g. ``request header``, ``request cookie``, ``url query``, ``response body``."""
    name: str
    """Header, cookie, parameter, or field name ('' when found in free text)."""
    fingerprint: str
    """Keyed hash prefix; equal values in one run get equal fingerprints."""
    length: int
    format: str
    """Shape of the value, e.g. ``jwt``, ``jwt-unsigned``, ``hex:64``, ``bcrypt``,
    ``base64url:43``, ``uuid``, ``digits:6``, ``text:12``."""
    in_url: bool = False
    jwt_header: dict = field(default_factory=dict)
    """Decoded JWT header with secret-bearing members replaced (e.g. embedded keys)."""
    jwt_claims: dict = field(default_factory=dict)
    """Decoded JWT claims: analysis-relevant values kept, identity values fingerprinted."""


@dataclass(frozen=True)
class PiiHit:
    """A personal-data value that was detected (and masked unless the user kept values)."""

    kind: str
    """``email``, ``phone``, ``card``, or ``gov-id``."""
    location: str
    name: str


@dataclass
class Transaction:
    """One captured request/response pair, normalised from any input format.

    Bodies are text. Binary bodies are represented by a placeholder that records their
    size and content type; reqlens does not analyse binary payloads.
    """

    index: int
    """Position in the merged capture (stable id used in evidence)."""
    source: str
    """Capture file this transaction came from."""
    method: str
    url: str
    request_headers: list[Header] = field(default_factory=list)
    request_body: str = ""
    status: int | None = None
    """HTTP status, or ``None`` if the capture holds no response."""
    response_headers: list[Header] = field(default_factory=list)
    response_body: str = ""
    started: str | None = None
    """Start time as given by the capture (ISO 8601 when available)."""
    duration_ms: float | None = None
    notes: list[str] = field(default_factory=list)
    """Facts recorded during loading/redaction, e.g. 'response body truncated'."""
    redacted: bool = False
    """True once :mod:`reqlens.redact` produced this object. Checks refuse raw data."""
    tokens: list[TokenRecord] = field(default_factory=list)
    """Secrets removed by redaction, described structurally."""
    pii: list[PiiHit] = field(default_factory=list)
    """Personal data detected by redaction."""

    @property
    def host(self) -> str:
        """Lower-case host name without port."""
        return (urlsplit(self.url).hostname or "").lower()

    @property
    def scheme(self) -> str:
        """URL scheme, lower-case (``http``/``https``)."""
        return urlsplit(self.url).scheme.lower()

    @property
    def path(self) -> str:
        """URL path (``/`` when empty)."""
        return urlsplit(self.url).path or "/"

    @property
    def query(self) -> str:
        """Raw query string, without the leading ``?``."""
        return urlsplit(self.url).query

    def request_header(self, name: str) -> str | None:
        """First request header value for ``name``."""
        return header_value(self.request_headers, name)

    def response_header(self, name: str) -> str | None:
        """First response header value for ``name``."""
        return header_value(self.response_headers, name)


class Concern(str, enum.Enum):
    """How much a finding deserves attention. Ordering is used to sort reports.

    This is a priority for manual testing, not a severity of a confirmed vulnerability.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """0 for HIGH ... 3 for INFO (sort ascending for most important first)."""
        return list(Concern).index(self)


class Confidence(str, enum.Enum):
    """reqlens never confirms a vulnerability, so only these two values exist."""

    POSSIBLE = "possible"
    INFORMATIONAL = "informational"


@dataclass(frozen=True)
class Evidence:
    """Where a finding was observed. ``value`` is always a redacted excerpt."""

    transaction_index: int
    endpoint: str
    """``METHOD host/path-pattern`` of the transaction."""
    location: str
    """e.g. ``response header``, ``cookie``, ``request body``, ``jwt header``."""
    name: str = ""
    """Header, cookie, field, or claim name, when applicable."""
    value: str = ""
    """Redacted excerpt. Never a raw secret."""


@dataclass
class Finding:
    """A possible issue for a human to verify manually."""

    check_id: str
    """Stable identifier, e.g. ``HDR-HSTS-MISSING``."""
    title: str
    category: str
    """OWASP API Security Top 10 (2023) or Web Top 10 id, e.g. ``API8:2023``."""
    concern: Concern
    why: str
    """Why this may matter."""
    manual_test: str
    """One single-step test for the user's authorized scope. Never an automated attack."""
    learning: str
    """Short lesson on the vulnerability class."""
    confidence: Confidence = Confidence.POSSIBLE
    wstg: list[str] = field(default_factory=list)
    """OWASP WSTG test ids, e.g. ``WSTG-SESS-02``."""
    evidence: list[Evidence] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    source: str = "rule"
    """``rule``, ``knowledge``, ``external``, or ``ai``."""

    def __post_init__(self) -> None:
        """Coerce enum fields and refuse any confidence other than possible/informational."""
        try:
            self.concern = Concern(self.concern)
        except ValueError as exc:
            raise SafetyViolation(f"invalid concern level: {self.concern!r}") from exc
        try:
            self.confidence = Confidence(self.confidence)
        except ValueError as exc:
            raise SafetyViolation(
                f"confidence must be 'possible' or 'informational', got {self.confidence!r}; "
                "reqlens never reports a confirmed vulnerability"
            ) from exc

    @property
    def sort_key(self) -> tuple[str, int, str]:
        """Order by category, then concern (highest first), then title."""
        return (self.category, self.concern.rank, self.title)
