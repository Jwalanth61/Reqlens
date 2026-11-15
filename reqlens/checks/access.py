"""Access-control signals: object IDs in requests (BOLA/IDOR), sensitive fields in
responses (excessive data exposure), writable objects with privileged fields (mass
assignment), and administrative endpoints (function-level authorization)."""

from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import parse_qsl

from reqlens.checks import Context, json_body, json_keys
from reqlens.group import Endpoint
from reqlens.knowledge.catalog import make_finding
from reqlens.model import Finding
from reqlens.redact import name_words

ID_SEGMENTS = {"{id}": "numeric", "{uuid}": "UUID", "{objectid}": "ObjectId", "{hex}": "hex"}
_ID_NAME_RE = re.compile(r"(?:^|[_-])id$|Id$|^id$|^uuid$|_uuid$|Uuid$")
_NUMERIC_PLACEHOLDER_RE = re.compile(r"^(?:<int>|<digits:\d+>|\d+)$")

EXCESSIVE_CREDENTIAL = {
    "password",
    "passwd",
    "hash",
    "salt",
    "secret",
    "apikey",
    "privatekey",
    "resettoken",
    "otp",
    "mfasecret",
    "totp",
    "pin",
}
EXCESSIVE_PERSONAL = {
    "ssn",
    "dob",
    "dateofbirth",
    "salary",
    "iban",
    "creditcard",
    "cardnumber",
    "passport",
    "taxid",
    "internal",
    "internalnotes",
}
PRIVILEGED_FIELDS = {
    "role",
    "roles",
    "isadmin",
    "admin",
    "is_admin",
    "permissions",
    "verified",
    "isverified",
    "email_verified",
    "balance",
    "credit",
    "credits",
    "plan",
    "tier",
    "owner",
    "ownerid",
    "userid",
    "accountid",
    "approved",
    "status",
    "isstaff",
    "issuperuser",
    "group",
    "groups",
    "scope",
    "scopes",
}
ADMIN_SEGMENTS = {
    "admin",
    "administrator",
    "internal",
    "manage",
    "management",
    "debug",
    "actuator",
    "console",
    "superuser",
    "staff",
    "backoffice",
}
WRITE_METHODS = {"POST", "PUT", "PATCH"}
_AUTH_PATH_RE = re.compile(r"/(login|signin|token|oauth|auth|session)s?\b", re.I)


def _compact(name: str) -> str:
    return "".join(name_words(name))


def run(ctx: Context) -> Iterable[Finding]:
    """Yield access-control findings, one per endpoint and check."""
    for endpoint in ctx.endpoints:
        yield from _idor(ctx, endpoint)
        yield from _excessive(ctx, endpoint)
        yield from _function_level(ctx, endpoint)
    yield from _mass_assignment(ctx)


def _request_id_params(endpoint: Endpoint) -> list[tuple[str, str, str]]:
    """(location, name, kind) for ID-like query/body parameters of the representative."""
    tx = endpoint.representative
    found: list[tuple[str, str, str]] = []
    for name, value in parse_qsl(tx.query, keep_blank_values=True):
        if _ID_NAME_RE.search(name):
            kind = "numeric" if _NUMERIC_PLACEHOLDER_RE.match(value) else "opaque"
            found.append(("url query", name, kind))
    body = json_body(tx.request_body)
    if isinstance(body, dict):
        for name, value in body.items():
            if _ID_NAME_RE.search(str(name)) and not isinstance(value, (dict, list)):
                kind = "numeric" if _NUMERIC_PLACEHOLDER_RE.match(str(value)) else "opaque"
                found.append(("request body", str(name), kind))
    return found


def _idor(ctx: Context, endpoint: Endpoint) -> Iterable[Finding]:
    path_ids = [ID_SEGMENTS[s] for s in endpoint.pattern.split("/") if s in ID_SEGMENTS]
    params = _request_id_params(endpoint)
    if not path_ids and not params:
        return
    tx = endpoint.representative
    numeric = "numeric" in path_ids or any(kind == "numeric" for *_, kind in params)
    parts = []
    if path_ids:
        parts.append(f"path identifier(s): {', '.join(path_ids)}")
    if params:
        parts.append("parameter(s): " + ", ".join(f"{name} ({kind})" for _, name, kind in params))
    statuses = endpoint.statuses
    note = ""
    if any(s in (401, 403, 404) for s in statuses) and any(200 <= s < 300 for s in statuses):
        note = (
            f" Responses for different IDs returned {statuses}: the server checks some "
            "access, which makes a two-account test especially informative."
        )
    evidence = [ctx.evidence(tx, "url", "path", endpoint.pattern)]
    evidence += [ctx.evidence(tx, loc, name, kind) for loc, name, kind in params]
    sentence = "; ".join(parts)
    yield make_finding(
        "ACC-IDOR",
        evidence,
        title=f"Object identifier in request: test BOLA/IDOR ({endpoint.key})",
        concern="medium" if numeric else "low",
        observed=f"{sentence[:1].upper()}{sentence[1:]}."
        + (" Sequential numbers are easy to guess." if numeric else "")
        + note,
    )


def _excessive(ctx: Context, endpoint: Endpoint) -> Iterable[Finding]:
    if _AUTH_PATH_RE.search(endpoint.pattern):
        return  # login/token endpoints are expected to return credentials
    tx = endpoint.representative
    body = json_body(tx.response_body)
    if body is None:
        return
    keys = json_keys(body)
    compact = {key: _compact(key) for key in keys}
    credential = sorted(
        {
            k
            for k, c in compact.items()
            if c in EXCESSIVE_CREDENTIAL or c.endswith(("hash", "secret"))
        }
    )
    personal = sorted({k for k, c in compact.items() if c in EXCESSIVE_PERSONAL})
    if not credential and not personal:
        return
    fields = credential + personal
    yield make_finding(
        "ACC-EXCESSIVE-DATA",
        [ctx.evidence(tx, "response body", ", ".join(fields[:12]), f"{len(set(keys))} fields")],
        title=f"Response may expose more fields than needed ({endpoint.key})",
        concern="medium" if credential else "low",
        observed=f"Sensitive-looking fields in the response: {', '.join(fields[:12])}.",
    )


def _mass_assignment(ctx: Context) -> Iterable[Finding]:
    """Compare write requests with the object shape returned for the same path pattern."""
    shapes: dict[tuple[str, str], set[str]] = {}
    for endpoint in ctx.endpoints:
        for tx in endpoint.members:
            body = json_body(tx.response_body)
            if isinstance(body, dict):
                shapes.setdefault((endpoint.host, endpoint.pattern), set()).update(
                    str(k) for k in body
                )
    for endpoint in ctx.endpoints:
        if endpoint.method not in WRITE_METHODS or _AUTH_PATH_RE.search(endpoint.pattern):
            continue
        tx = endpoint.representative
        request = json_body(tx.request_body)
        if not isinstance(request, dict) or not request:
            continue
        sent = {str(k) for k in request}
        returned = shapes.get((endpoint.host, endpoint.pattern), set())
        privileged = sorted(k for k in returned - sent if _compact(k) in PRIVILEGED_FIELDS)
        mirror = len(sent & returned) >= 3 and len(sent & returned) / len(sent) >= 0.6
        if not privileged and not mirror:
            continue
        observed = []
        if privileged:
            observed.append(
                f"The object has privileged-looking fields not sent by the client: "
                f"{', '.join(privileged)}."
            )
        if mirror:
            observed.append(
                "The request sends back most of the object's own fields, which "
                "suggests the server binds whole objects."
            )
        yield make_finding(
            "ACC-MASS-ASSIGNMENT",
            [
                ctx.evidence(
                    tx,
                    "request body",
                    ", ".join(sorted(sent))[:200],
                    f"candidates: {', '.join(privileged) or '(mirrored fields)'}",
                )
            ],
            title=f"Writable object: test mass assignment ({endpoint.key})",
            concern="medium" if privileged else "low",
            observed=" ".join(observed),
        )


def _function_level(ctx: Context, endpoint: Endpoint) -> Iterable[Finding]:
    segments = {s.lower() for s in endpoint.pattern.split("/")}
    hit = sorted(segments & ADMIN_SEGMENTS)
    if hit:
        tx = endpoint.representative
        yield make_finding(
            "ACC-FUNCTION-LEVEL",
            [ctx.evidence(tx, "url", "path", endpoint.pattern)],
            title=f"Administrative or internal endpoint seen ({endpoint.key})",
            concern="medium" if endpoint.method in WRITE_METHODS | {"DELETE"} else "low",
            observed=f"Path contains: {', '.join(hit)}.",
        )
