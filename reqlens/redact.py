"""Secret removal. Runs before any check, report, or AI call sees a transaction.

Principles
----------
* **Keep the shape, drop the secret.** Header, cookie, parameter and field *names* survive;
  secret *values* become ``<redacted:xxxxxxxx>`` fingerprints, so repeats still correlate.
* **Fingerprints are keyed.** They are HMAC-SHA256 prefixes under a random per-run key, so
  a short secret (a PIN, a 6-digit code) cannot be recovered by hashing guesses.
* **JWTs are decoded, not kept.** The header and analysis-relevant claims (``alg``, ``exp``,
  roles, scopes) are recorded as a :class:`~reqlens.model.TokenRecord`; the signature and
  identity claims are dropped or fingerprinted.
* **Body values are masked by default** to type/length placeholders (``<str:12>``,
  ``<email>``, ``<int>``). ``keep_body_values`` keeps non-secret values for a local report,
  but credentials, tokens and other secrets are redacted regardless.
* **Fail closed.** Any unexpected error stops the run instead of passing data through.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field, replace
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

from reqlens import config
from reqlens.errors import RedactionError
from reqlens.model import Header, PiiHit, TokenRecord, Transaction, header_value

# --- Name-based sensitivity ----------------------------------------------------------------

_SENSITIVE_WORDS = frozenset(
    {
        "password",
        "passwd",
        "pass",
        "pwd",
        "passphrase",
        "secret",
        "token",
        "apikey",
        "authorization",
        "key",
        "auth",
        "session",
        "sess",
        "sid",
        "csrf",
        "xsrf",
        "otp",
        "pin",
        "cvv",
        "cvc",
        "ssn",
        "signature",
        "sig",
        "credential",
        "credentials",
        "cookie",
        "refresh",
        "bearer",
        "assertion",
        "jwt",
        "private",
        "mfa",
        "totp",
    }
)
_SENSITIVE_SUBSTRINGS = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "sessionid",
    "sessid",
    "session",
    "csrf",
    "xsrf",
    "credential",
    "jwt",
    "bearer",
    "signature",
    "privatekey",
)
_QUERY_ONLY_SENSITIVE = frozenset({"code", "state_token", "ticket", "x-amz-credential"})

# Header names that contain a sensitive word but carry policy, not secrets.
_NON_SECRET_HEADER_PREFIXES = ("access-control-", "www-authenticate", "sec-websocket-protocol")

# JSON/form fields whose text is kept (with secrets/PII scrubbed) instead of masked, because
# their content is what disclosure, GraphQL and role checks need to read.
_READABLE_KEYS = frozenset(
    {
        "error",
        "errors",
        "message",
        "msg",
        "detail",
        "details",
        "description",
        "exception",
        "trace",
        "stack",
        "stacktrace",
        "reason",
        "title",
        "type",
        "kind",
        "status",
        "role",
        "roles",
        "scope",
        "scopes",
        "permission",
        "permissions",
        "group",
        "groups",
        "operationname",
        "query",
        "__typename",
        "method",
        "level",
        "code_name",
    }
)

_JWT_KEEP_CLAIMS = frozenset(
    {
        "exp",
        "iat",
        "nbf",
        "auth_time",
        "iss",
        "aud",
        "azp",
        "client_id",
        "scope",
        "scp",
        "role",
        "roles",
        "groups",
        "permissions",
        "perms",
        "authorities",
        "token_use",
        "typ",
        "amr",
        "acr",
        "ver",
        "realm_access",
        "resource_access",
        "admin",
        "is_admin",
        "isadmin",
    }
)
_JWT_FINGERPRINT_CLAIMS = frozenset(
    {"sub", "jti", "sid", "session_state", "nonce", "at_hash", "c_hash", "oid", "uid"}
)
_JWT_PII_CLAIMS = {
    "email": "email",
    "phone_number": "phone",
    "name": "name",
    "given_name": "name",
    "family_name": "name",
    "preferred_username": "name",
    "upn": "email",
}

_SET_COOKIE_ATTRS = frozenset(
    {
        "expires",
        "max-age",
        "domain",
        "path",
        "secure",
        "httponly",
        "samesite",
        "priority",
        "partitioned",
    }
)
_URL_HEADERS = frozenset({"location", "referer", "content-location", "origin", "refresh"})

# --- Value patterns ----------------------------------------------------------------------

_JWT_RE = re.compile(r"ey[A-Za-z0-9_-]{8,}\.ey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
_GOV_ID_RES = (
    re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),  # US SSN
    re.compile(r"(?<!\d)[2-9]\d{3} \d{4} \d{4}(?!\d)"),  # IN Aadhaar
    re.compile(r"(?<![A-Za-z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Za-z0-9])"),  # IN PAN
    re.compile(r"(?<![A-Za-z0-9])[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D](?![A-Za-z0-9])"),  # UK NINO
)
_CARD_RE = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")
_PHONE_RE = re.compile(
    r"(?<![\w+])(?:\+\d{1,3}[\s-]?\d[\d\s-]{6,14}\d|\(?\d{3}\)?[\s-]\d{3}[\s-]\d{4})(?!\w)"
)
_KV_SECRET_RE = re.compile(
    r"(?i)([\w-]*(?:password|passwd|pwd|secret|token|apikey|api_key|api-key|sessionid|"
    r"session_id|sessid)[\w-]*)(\"?'?\s*[:=]\s*\"?'?)([^\s\"'&,;<>]{1,512})"
)
_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/=_-]{20,}")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_DATETIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?)?$"
)
_DIAGNOSTIC_RE = re.compile(
    r"(Exception|Traceback \(most recent call last\)|\bat [\w$.<>]+\(|SQLSTATE|SQL syntax|"
    r"ORA-\d{5}|PG::|psycopg2|mysqli?_|SQLite|NullReference|undefined method|Fatal error|"
    r"stack trace|Stack trace|line \d+|\.java:\d+|\.py\", line|\.php on line)"
)

_HASH_PREFIXES = (
    (re.compile(r"^\$2[abxy]?\$\d\d\$"), "bcrypt"),
    (re.compile(r"^\$argon2(id|i|d)\$"), "argon2"),
    (re.compile(r"^\$6\$"), "sha512-crypt"),
    (re.compile(r"^\$5\$"), "sha256-crypt"),
    (re.compile(r"^\$1\$"), "md5-crypt"),
    (re.compile(r"^\$apr1\$"), "apr1-md5"),
    (re.compile(r"^pbkdf2_sha256\$"), "django-pbkdf2-sha256"),
    (re.compile(r"^\{SSHA\}"), "ldap-ssha"),
    (re.compile(r"^\{SHA\}"), "ldap-sha"),
)


# --- Helpers -------------------------------------------------------------------------------


def name_words(name: str) -> list[str]:
    """Split a header/field name into lower-case words (snake, kebab, camelCase)."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return [word for word in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if word]


def is_sensitive_name(name: str) -> bool:
    """True if a header/cookie/field name suggests its value is a secret."""
    lowered = name.lower()
    if any(word in _SENSITIVE_WORDS for word in name_words(name)):
        return True
    return any(part in lowered for part in _SENSITIVE_SUBSTRINGS)


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum(n / total * math.log2(n / total) for n in counts.values())


def looks_random(value: str) -> bool:
    """Heuristic for secret-like strings: long, mixed character classes, high entropy."""
    if len(value) < 20 or _UUID_RE.match(value):
        return False
    if _HEX_RE.match(value):
        return len(value) >= 32
    has_digit = any(c.isdigit() for c in value)
    has_upper = any(c.isupper() for c in value)
    has_lower = any(c.islower() for c in value)
    if not (has_digit or (len(value) >= 32 and has_upper and has_lower)):
        return False
    if not (has_lower or has_upper):
        return False
    return shannon_entropy(value) >= 3.3


def luhn_valid(digits: str) -> bool:
    """Luhn checksum, used to tell card numbers from other long digit runs."""
    total = 0
    for position, char in enumerate(reversed(digits)):
        number = int(char)
        if position % 2 == 1:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def describe_format(value: str) -> str:
    """Shape of a secret, kept so later stages can identify token/hash types."""
    for pattern, label in _HASH_PREFIXES:
        if pattern.match(value):
            return label
    if _UUID_RE.match(value):
        return "uuid"
    if value.isdigit():
        return f"digits:{len(value)}"
    if _HEX_RE.match(value):
        return f"hex:{len(value)}"
    if re.fullmatch(r"[A-Za-z0-9_-]+", value):
        return f"base64url:{len(value)}"
    if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value):
        return f"base64:{len(value)}"
    return f"text:{len(value)}"


def _b64url_json(segment: str) -> Any:
    """Decode a base64url JSON segment, or ``None``."""
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        return json.loads(raw.decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


def _content_type(headers: list[Header]) -> str:
    """Raw Content-Type (case preserved: multipart boundaries are case-sensitive)."""
    return header_value(headers, "content-type") or ""


# --- Redactor -----------------------------------------------------------------------------


@dataclass(frozen=True)
class RedactionPolicy:
    """What redaction keeps. The default is the strictest policy."""

    keep_body_values: bool = False
    """Keep non-secret body/query values (local reports only; never used for AI)."""


@dataclass
class _Collector:
    """Per-transaction record of what was removed."""

    tokens: list[TokenRecord] = field(default_factory=list)
    pii: list[PiiHit] = field(default_factory=list)


class Redactor:
    """Produces redacted copies of transactions. Originals are never modified."""

    def __init__(self, policy: RedactionPolicy | None = None, key: bytes | None = None):
        self.policy = policy or RedactionPolicy()
        self._key = key if key is not None else os.urandom(32)

    # -- public API ------------------------------------------------------------------------

    def fingerprint(self, value: str) -> str:
        """Keyed, truncated hash of ``value``."""
        mac = hmac.new(self._key, value.encode("utf-8", "surrogatepass"), hashlib.sha256)
        return mac.hexdigest()[: config.FINGERPRINT_HEX_CHARS]

    def redact_all(self, transactions: list[Transaction]) -> list[Transaction]:
        """Redact every transaction (fail closed)."""
        return [self.redact(tx) for tx in transactions]

    def redact(self, tx: Transaction) -> Transaction:
        """Return a redacted copy of ``tx``. Raises :class:`RedactionError` on any failure."""
        if tx.redacted:
            return tx
        try:
            return self._redact(tx)
        except RedactionError:
            raise
        except Exception as exc:  # fail closed, but never echo data in the message
            raise RedactionError(
                f"redaction failed for transaction {tx.index} ({type(exc).__name__}); "
                "stopping rather than risk leaking unredacted data"
            ) from None

    def describe_jwt(self, token: str) -> TokenRecord | None:
        """Decode a JWT the user supplied (``--check-jwt``) into a redacted TokenRecord.

        Returns ``None`` if the value is not a JWT. The signature is never kept.
        """
        token = token.strip()
        if not _JWT_RE.fullmatch(token):
            return None
        sink = _Collector()
        if self._jwt(token, sink, "supplied token", "", False) is None:
            return None
        return sink.tokens[-1]

    # -- transaction -----------------------------------------------------------------------

    def _redact(self, tx: Transaction) -> Transaction:
        sink = _Collector()
        request_headers = [
            (name, self._header(name, value, sink, "request header"))
            for name, value in tx.request_headers
        ]
        response_headers = [
            (name, self._header(name, value, sink, "response header"))
            for name, value in tx.response_headers
        ]
        return replace(
            tx,
            url=self._url(tx.url, sink, "url"),
            request_headers=request_headers,
            response_headers=response_headers,
            request_body=self._body(
                tx.request_body, _content_type(tx.request_headers), sink, "request body"
            ),
            response_body=self._body(
                tx.response_body, _content_type(tx.response_headers), sink, "response body"
            ),
            notes=list(tx.notes),
            redacted=True,
            redaction_policy="keep-values" if self.policy.keep_body_values else "strict",
            tokens=sink.tokens,
            pii=sink.pii,
        )

    # -- headers ---------------------------------------------------------------------------

    def _header(self, name: str, value: str, sink: _Collector, where: str) -> str:
        lname = name.lower()
        if lname == "cookie":
            return self._cookie_header(value, sink)
        if lname == "set-cookie":
            return self._set_cookie(value, sink)
        if lname in ("authorization", "proxy-authorization"):
            return self._authorization(name, value, sink, where)
        if lname in _URL_HEADERS:
            return self._url(value, sink, f"{where} {name}")
        if is_sensitive_name(lname) and not lname.startswith(_NON_SECRET_HEADER_PREFIXES):
            return self._secret(value, sink, "header-token", where, name)
        return self._scrub(value, sink, where, name)

    def _cookie_header(self, value: str, sink: _Collector) -> str:
        parts = []
        for pair in value.split(";"):
            pair = pair.strip()
            if not pair:
                continue
            name, sep, cookie_value = pair.partition("=")
            if not sep:
                parts.append(self._secret(name, sink, "cookie", "request cookie", ""))
                continue
            redacted = self._secret(cookie_value, sink, "cookie", "request cookie", name.strip())
            parts.append(f"{self._scrub(name.strip(), sink, 'request cookie', '')}={redacted}")
        return "; ".join(parts)

    def _set_cookie(self, value: str, sink: _Collector) -> str:
        where = "response cookie"
        first, *attributes = value.split(";")
        name, sep, cookie_value = first.strip().partition("=")
        if sep:
            name = self._scrub(name.strip(), sink, where, "")
            out = [f"{name}={self._secret(cookie_value, sink, 'cookie', where, name)}"]
        else:
            out = [self._secret(first, sink, "cookie", where, "")]
        for attribute in attributes:
            attr_name, attr_sep, attr_value = attribute.strip().partition("=")
            if not attr_name:
                continue
            if attr_name.lower() in _SET_COOKIE_ATTRS:
                kept = self._scrub(attr_value.strip(), sink, where, attr_name)
                out.append(f"{attr_name}={kept}" if attr_sep else attr_name)
            else:
                safe_name = self._scrub(attr_name, sink, where, "")
                if attr_sep:
                    hidden = self._secret(attr_value, sink, "cookie", where, attr_name)
                    out.append(f"{safe_name}={hidden}")
                else:
                    out.append(safe_name)
        return "; ".join(out)

    def _authorization(self, name: str, value: str, sink: _Collector, where: str) -> str:
        scheme, _, credentials = value.strip().partition(" ")
        credentials = credentials.strip()
        if not credentials:
            return self._secret(scheme, sink, "header-token", where, name)
        safe_scheme = re.sub(r"[^A-Za-z0-9_-]", "", scheme)[:32]
        if scheme.lower() == "basic":
            fingerprint = self.fingerprint(credentials)
            decoded = None
            with contextlib.suppress(binascii.Error, ValueError, UnicodeDecodeError):
                decoded = base64.b64decode(credentials, validate=True).decode("utf-8")
            fmt = "user:password" if decoded and ":" in decoded else describe_format(credentials)
            if decoded and _EMAIL_RE.search(decoded.partition(":")[0]):
                sink.pii.append(PiiHit("email", where, name))
            sink.tokens.append(
                TokenRecord("basic", where, name, fingerprint, len(credentials), fmt)
            )
            return f"{safe_scheme} <redacted:{fingerprint}>"
        kind = "bearer" if scheme.lower() == "bearer" else "header-token"
        return f"{safe_scheme} {self._secret(credentials, sink, kind, where, name)}"

    # -- secrets and JWTs ------------------------------------------------------------------

    def _secret(
        self,
        value: str,
        sink: _Collector,
        kind: str,
        location: str,
        name: str,
        in_url: bool = False,
    ) -> str:
        """Replace a whole value known to be secret."""
        value = value.strip()
        if not value:
            return ""
        if _JWT_RE.fullmatch(value):
            replaced = self._jwt(value, sink, location, name, in_url)
            if replaced is not None:
                return replaced
        fingerprint = self.fingerprint(value)
        sink.tokens.append(
            TokenRecord(
                kind, location, name, fingerprint, len(value), describe_format(value), in_url
            )
        )
        return f"<redacted:{fingerprint}>"

    def _jwt(
        self, token: str, sink: _Collector, location: str, name: str, in_url: bool
    ) -> str | None:
        """Record a JWT's safe structure and return its placeholder; ``None`` if not a JWT."""
        header_b64, payload_b64, signature = token.split(".", 2)
        header = _b64url_json(header_b64)
        if not isinstance(header, dict) or "alg" not in header:
            return None
        payload = _b64url_json(payload_b64)
        fingerprint = self.fingerprint(token)
        scratch = _Collector()  # identity claims are never reported as body PII twice
        claims = self._jwt_claims(payload, scratch, location) if isinstance(payload, dict) else {}
        sink.pii.extend(scratch.pii)
        sink.tokens.append(
            TokenRecord(
                kind="jwt",
                location=location,
                name=name,
                fingerprint=fingerprint,
                length=len(token),
                format="jwt" if signature else "jwt-unsigned",
                in_url=in_url,
                jwt_header=self._jwt_header(header, sink, location),
                jwt_claims=claims,
            )
        )
        return f"<jwt:{fingerprint}>"

    def _jwt_header(self, header: dict, sink: _Collector, location: str) -> dict:
        safe: dict = {}
        for key, value in header.items():
            key = self._scrub(str(key), sink, location, "jwt header")
            if key in ("jwk", "x5c"):
                safe[key] = f"<embedded {key}>"
            elif isinstance(value, str):
                safe[key] = self._scrub(value, sink, location, "jwt header")
            elif isinstance(value, (bool, int, float)) or value is None:
                safe[key] = value
            else:
                safe[key] = f"<{type(value).__name__}>"
        return safe

    def _jwt_claims(self, payload: dict, sink: _Collector, location: str, depth: int = 0) -> dict:
        safe: dict = {}
        for key, value in payload.items():
            key = self._scrub(str(key), sink, location, "jwt claim")
            lowered = key.lower()
            if isinstance(value, dict) and depth < 4:
                safe[key] = self._jwt_claims(value, sink, location, depth + 1)
            elif lowered in _JWT_KEEP_CLAIMS:
                safe[key] = self._keep_claim(value, sink, location)
            elif lowered in _JWT_PII_CLAIMS:
                sink.pii.append(PiiHit(_JWT_PII_CLAIMS[lowered], location, f"jwt claim {key}"))
                safe[key] = f"<redacted:{self.fingerprint(str(value))}>"
            elif lowered in _JWT_FINGERPRINT_CLAIMS or is_sensitive_name(key):
                safe[key] = f"<redacted:{self.fingerprint(str(value))}>"
            else:
                safe[key] = self._mask(value, key, sink, location)
        return safe

    def _keep_claim(self, value: Any, sink: _Collector, location: str) -> Any:
        if isinstance(value, str):
            return self._scrub(value, sink, location, "jwt claim")
        if isinstance(value, list):
            return [self._keep_claim(item, sink, location) for item in value[:50]]
        if isinstance(value, dict):
            return self._jwt_claims(value, sink, location, 1)
        return value

    # -- URLs ------------------------------------------------------------------------------

    def _url(self, url: str, sink: _Collector, location: str) -> str:
        try:
            parts = urlsplit(url.strip())
        except ValueError:
            return self._scrub(url, sink, location, "")
        netloc = parts.netloc
        if "@" in netloc:
            userinfo, _, hostport = netloc.rpartition("@")
            hidden = self._secret(unquote(userinfo), sink, "url-userinfo", location, "", True)
            netloc = f"{hidden}@{hostport}"
        path = "/".join(
            self._scrub(unquote(segment), sink, location, "path")
            for segment in parts.path.split("/")
        )
        query = self._query(parts.query, sink, location)
        fragment = (
            self._query(parts.fragment, sink, location)
            if "=" in parts.fragment
            else (self._scrub(unquote(parts.fragment), sink, location, "fragment"))
        )
        return urlunsplit((parts.scheme, netloc, path, query, fragment))

    def _query(self, query: str, sink: _Collector, location: str) -> str:
        if not query:
            return ""
        pairs = []
        for name, value in parse_qsl(query, keep_blank_values=True):
            safe_name = self._scrub(name, sink, location, "")
            lname = name.lower()
            if value and (is_sensitive_name(name) or lname in _QUERY_ONLY_SENSITIVE):
                kept = self._secret(value, sink, "query-param", f"{location} query", name, True)
            elif self.policy.keep_body_values:
                kept = self._scrub(
                    value, sink, f"{location} query", name, mask_pii=False, in_url=True
                )
            else:
                kept = str(self._mask(value, name, sink, f"{location} query", in_url=True))
            pairs.append(f"{safe_name}={kept}")
        return "&".join(pairs)

    # -- bodies ----------------------------------------------------------------------------

    def _body(self, body: str, raw_content_type: str, sink: _Collector, location: str) -> str:
        if not body:
            return ""
        content_type = raw_content_type.lower()
        stripped = body.lstrip()
        if "json" in content_type or (stripped[:1] in "{[" and "html" not in content_type):
            redacted = self._json_body(body, sink, location)
            if redacted is not None:
                return redacted
        if "x-www-form-urlencoded" in content_type:
            return self._form_body(body, sink, location)
        if "multipart/form-data" in content_type:
            redacted = self._multipart_body(body, raw_content_type, sink, location)
            if redacted is not None:
                return redacted
        if ("xml" in content_type and "html" not in content_type) or stripped.startswith("<?xml"):
            redacted = self._xml_body(body, sink, location)
            if redacted is not None:
                return redacted
        return self._scrub(body, sink, location, "", mask_pii=not self.policy.keep_body_values)

    def _json_body(self, body: str, sink: _Collector, location: str) -> str | None:
        try:
            data = json.loads(body)
        except ValueError:
            return None
        except RecursionError:
            return f"[body omitted: {len(body)} characters, JSON nested too deeply]"
        try:
            walked = self._walk(data, "", sink, location)
        except RecursionError:
            return f"[body omitted: {len(body)} characters, JSON nested too deeply]"
        return json.dumps(walked, ensure_ascii=False)

    def _walk(self, node: Any, key: str, sink: _Collector, location: str) -> Any:
        if isinstance(node, dict):
            return {
                self._scrub(str(k), sink, location, ""): self._walk(v, str(k), sink, location)
                for k, v in node.items()
            }
        if isinstance(node, list):
            return [self._walk(item, key, sink, location) for item in node]
        return self._field(key, node, sink, location)

    def _field(self, key: str, value: Any, sink: _Collector, location: str) -> Any:
        """Redact one scalar body value according to its name and the policy."""
        if value is None or isinstance(value, bool):
            return value
        text = value if isinstance(value, str) else str(value)
        if is_sensitive_name(key) and text != "":
            return self._secret(text, sink, "field", location, key)
        if isinstance(value, str):
            if key.lower() in _READABLE_KEYS or _DIAGNOSTIC_RE.search(value):
                return self._scrub(value, sink, location, key)
            if self.policy.keep_body_values:
                return self._scrub(value, sink, location, key, mask_pii=False)
            return self._mask(value, key, sink, location)
        if self.policy.keep_body_values:
            return value
        return self._mask(value, key, sink, location)

    def _form_body(self, body: str, sink: _Collector, location: str) -> str:
        pairs = []
        for name, value in parse_qsl(body, keep_blank_values=True):
            kept = self._field(name, value, sink, location)
            pairs.append(f"{self._scrub(name, sink, location, '')}={kept}")
        return "&".join(pairs)

    def _multipart_body(
        self, body: str, content_type: str, sink: _Collector, location: str
    ) -> str | None:
        match = re.search(r'boundary="?([^";]+)"?', content_type)
        if not match:
            return None
        boundary = match.group(1)
        out = []
        for chunk in body.split("--" + boundary)[1:]:
            if chunk.strip() in ("", "--"):
                continue
            head, sep, content = chunk.lstrip("\r\n").partition("\r\n\r\n")
            if not sep:
                head, sep, content = chunk.lstrip("\n").partition("\n\n")
            name_match = re.search(r'(?<![A-Za-z])name="([^"]*)"', head)
            file_match = re.search(r'filename="([^"]*)"', head)
            name = name_match.group(1) if name_match else ""
            safe_name = self._scrub(name, sink, location, "")
            content = content.rstrip("\r\n")
            if file_match:
                extension = os.path.splitext(file_match.group(1))[1][:10] or "none"
                out.append(
                    f'[file part "{safe_name}": extension {extension}, {len(content)} characters]'
                )
            else:
                out.append(f"{safe_name}={self._field(name, content, sink, location)}")
        return "\n".join(out) if out else None

    def _xml_body(self, body: str, sink: _Collector, location: str) -> str | None:
        if re.search(r"<!DOCTYPE|<!ENTITY", body, re.IGNORECASE):
            return None  # never let a parser expand entities; fall back to text scrubbing
        try:
            root = ET.fromstring(body)
        except ET.ParseError:
            return None
        for element in root.iter():
            tag = element.tag.rsplit("}", 1)[-1] if isinstance(element.tag, str) else ""
            for attr, attr_value in list(element.attrib.items()):
                element.set(
                    attr, str(self._field(attr.rsplit("}", 1)[-1], attr_value, sink, location))
                )
            if element.text and element.text.strip():
                element.text = str(self._field(tag, element.text.strip(), sink, location))
            if element.tail and element.tail.strip():
                element.tail = self._scrub(element.tail, sink, location, tag)
        return ET.tostring(root, encoding="unicode")

    # -- masking (default for values) ------------------------------------------------------

    def _mask(
        self, value: Any, key: str, sink: _Collector, location: str, in_url: bool = False
    ) -> str:
        """Replace a value with a placeholder describing its type and size."""
        if isinstance(value, bool) or value is None:
            return str(value).lower()
        if isinstance(value, int):
            return "<int>"
        if isinstance(value, float):
            return "<float>"
        if isinstance(value, (list, dict)):
            return f"<{type(value).__name__}:{len(value)}>"
        text = str(value)
        if text == "":
            return ""
        if _JWT_RE.fullmatch(text):
            replaced = self._jwt(text, sink, location, key, in_url)
            if replaced is not None:
                return replaced
        if _EMAIL_RE.fullmatch(text):
            sink.pii.append(PiiHit("email", location, key))
            return "<email>"
        compact = re.sub(r"[ -]", "", text)
        if compact.isdigit() and 13 <= len(compact) <= 19 and luhn_valid(compact):
            sink.pii.append(PiiHit("card", location, key))
            return "<card>"
        if any(pattern.fullmatch(text) for pattern in _GOV_ID_RES):
            sink.pii.append(PiiHit("gov-id", location, key))
            return "<gov-id>"
        if _PHONE_RE.fullmatch(text) or (
            any(w in ("phone", "mobile", "tel", "msisdn") for w in name_words(key))
            and re.fullmatch(r"\+?[\d\s()-]{7,20}", text)
        ):
            sink.pii.append(PiiHit("phone", location, key))
            return "<phone>"
        if _UUID_RE.match(text):
            return "<uuid>"
        if text.isdigit():
            return f"<digits:{len(text)}>"
        if _DATETIME_RE.match(text):
            return "<datetime>"
        try:
            address = ipaddress.ip_address(text)
            return "<ip-private>" if address.is_private or address.is_loopback else "<ip>"
        except ValueError:
            pass
        if re.match(r"^https?://", text, re.IGNORECASE):
            host = (urlsplit(text).hostname or "").lower()
            return f"<url:{self._scrub(host, sink, location, key)}>"
        if looks_random(text):
            return self._secret(text, sink, "opaque", location, key, in_url)
        return f"<str:{len(text)}>"

    # -- scrubbing (free text: keep the words, remove secrets and PII) ---------------------

    def _scrub(
        self,
        text: str,
        sink: _Collector,
        location: str,
        name: str,
        mask_pii: bool = True,
        in_url: bool = False,
    ) -> str:
        """Remove secrets (always) and PII (unless ``mask_pii`` is False) from free text."""
        if not text:
            return text

        def jwt_sub(match: re.Match) -> str:
            replaced = self._jwt(match.group(0), sink, location, name, in_url)
            if replaced is not None:
                return replaced
            return self._secret(match.group(0), sink, "opaque", location, name, in_url)

        def pii_sub(kind: str, placeholder: str):
            def substitute(match: re.Match) -> str:
                sink.pii.append(PiiHit(kind, location, name))
                return placeholder if mask_pii else match.group(0)

            return substitute

        def card_sub(match: re.Match) -> str:
            digits = re.sub(r"[ -]", "", match.group(0))
            if 13 <= len(digits) <= 19 and luhn_valid(digits):
                sink.pii.append(PiiHit("card", location, name))
                return "<card>" if mask_pii else match.group(0)
            return match.group(0)

        def kv_sub(match: re.Match) -> str:
            hidden = self._secret(match.group(3), sink, "field", location, match.group(1), in_url)
            return f"{match.group(1)}{match.group(2)}{hidden}"

        def candidate_sub(match: re.Match) -> str:
            token = match.group(0)
            if "/" in token and not (token.endswith("=") or "+" in token):
                pieces = [piece for piece in token.split("/") if len(piece) >= 16]
                if not any(looks_random(piece) for piece in pieces):
                    return token
            elif not looks_random(token):
                return token
            return self._secret(token, sink, "opaque", location, name, in_url)

        text = _JWT_RE.sub(jwt_sub, text)
        text = _KV_SECRET_RE.sub(kv_sub, text)
        text = _EMAIL_RE.sub(pii_sub("email", "<email>"), text)
        text = _CARD_RE.sub(card_sub, text)  # before gov-ids: a spaced card is not an Aadhaar
        for pattern in _GOV_ID_RES:
            text = pattern.sub(pii_sub("gov-id", "<gov-id>"), text)
        text = _PHONE_RE.sub(pii_sub("phone", "<phone>"), text)
        text = _CANDIDATE_RE.sub(candidate_sub, text)
        return text
