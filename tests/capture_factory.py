"""Builds a synthetic HAR capture full of known secrets, for redaction and pipeline tests.

Every value in ``SECRETS`` must never appear in redacted output, in any form.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_jwt(header: dict, payload: dict, signature: bytes = b"s" * 32) -> str:
    return ".".join(
        [
            b64url(json.dumps(header).encode()),
            b64url(json.dumps(payload).encode()),
            b64url(signature) if signature else "",
        ]
    )


SESSION_COOKIE = "s3ss10nV4lu3QwErTy0987654321zzXX"
REMEMBER_COOKIE = "rememberMeTok3nAbCdEf1234567890xy"
PASSWORD = "Hunter2-Correct-Horse!"
OWNER_EMAIL = "alice.secret@example.test"
USER_SUB = "user-8812-unique-sub"
API_KEY = "ak_live_9f8e7d6c5b4a3210ffeeddccbbaa"
URL_TOKEN = "urlT0kenSuperSecret77665544"
REFRESH_TOKEN = "rt_Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Ji1"
CSRF_TOKEN = "csrf9a8b7c6d5e4f3a2b1c0d9e8f7a6b"
CARD = "4111 1111 1111 1111"
PHONE = "+1 415 555 0100"
SSN = "123-45-6789"
BASIC_USER = "svc-admin"
BASIC_PASSWORD = "B4sicP4ssw0rd"
BASIC_B64 = base64.b64encode(f"{BASIC_USER}:{BASIC_PASSWORD}".encode()).decode()
HTML_SECRET = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"
JS_API_KEY = "pk_test_51HxYzAbCdEfGhIjKlMnOp"
SIGNATURE_BYTES = b"\x8a\x01\xffsig-bytes-that-are-secret\x00\x13"

JWT = make_jwt(
    {"alg": "RS256", "typ": "JWT", "kid": "key-2024-01"},
    {
        "sub": USER_SUB,
        "email": OWNER_EMAIL,
        "role": "user",
        "scope": "read:profile write:profile",
        "iss": "https://auth.app.test",
        "exp": 1893456000,
        "iat": 1700000000,
    },
    SIGNATURE_BYTES,
)
JWT_SIGNATURE = JWT.split(".")[2]
JWT_PAYLOAD = JWT.split(".")[1]

SECRETS = [
    SESSION_COOKIE,
    REMEMBER_COOKIE,
    PASSWORD,
    OWNER_EMAIL,
    USER_SUB,
    API_KEY,
    URL_TOKEN,
    REFRESH_TOKEN,
    CSRF_TOKEN,
    CARD,
    CARD.replace(" ", ""),
    PHONE,
    SSN,
    BASIC_B64,
    BASIC_PASSWORD,
    HTML_SECRET,
    JS_API_KEY,
    JWT,
    JWT_SIGNATURE,
    JWT_PAYLOAD,
]


def _headers(pairs: list[tuple[str, str]]) -> list[dict]:
    return [{"name": name, "value": value} for name, value in pairs]


def _entry(
    method: str,
    url: str,
    request_headers: list[tuple[str, str]],
    status: int = 200,
    response_headers: list[tuple[str, str]] | None = None,
    request_body: str | None = None,
    request_mime: str = "application/json",
    response_body: str = "",
    response_mime: str = "application/json",
    response_encoding: str | None = None,
) -> dict:
    request: dict = {
        "method": method,
        "url": url,
        "httpVersion": "HTTP/2",
        "headers": _headers([(":authority", "app.test")] + request_headers),
        "queryString": [],
        "cookies": [],
    }
    if request_body is not None:
        request["postData"] = {"mimeType": request_mime, "text": request_body}
    content: dict = {"size": len(response_body), "mimeType": response_mime, "text": response_body}
    if response_encoding:
        content["encoding"] = response_encoding
    return {
        "startedDateTime": "2026-11-15T10:00:00.000Z",
        "time": 42.5,
        "request": request,
        "response": {
            "status": status,
            "statusText": "",
            "httpVersion": "HTTP/2",
            "headers": _headers(response_headers or [("Content-Type", response_mime)]),
            "cookies": [],
            "content": content,
        },
    }


def build_har() -> dict:
    """A small login-then-browse session with secrets in every place they hide."""
    entries = [
        _entry(
            "POST",
            "https://app.test/api/login",
            [("Content-Type", "application/json")],
            request_body=json.dumps({"email": OWNER_EMAIL, "password": PASSWORD, "remember": True}),
            response_headers=[
                ("Content-Type", "application/json"),
                ("Set-Cookie", f"session={SESSION_COOKIE}; Path=/; HttpOnly; Secure; SameSite=Lax"),
                ("Set-Cookie", f"remember={REMEMBER_COOKIE}; Path=/; Max-Age=2592000"),
                ("Server", "nginx/1.18.0"),
            ],
            response_body=json.dumps(
                {
                    "access_token": JWT,
                    "refresh_token": REFRESH_TOKEN,
                    "user": {"id": 123, "email": OWNER_EMAIL, "phone": PHONE, "isAdmin": False},
                }
            ),
        ),
        _entry(
            "GET",
            "https://app.test/api/users/123",
            [("Authorization", f"Bearer {JWT}"), ("Cookie", f"session={SESSION_COOKIE}")],
            response_body=json.dumps(
                {"id": 123, "name": "Alice", "email": OWNER_EMAIL, "ssn": SSN, "card": CARD}
            ),
        ),
        _entry(
            "GET",
            "https://app.test/api/users/456",
            [("Authorization", f"Bearer {JWT}"), ("Cookie", f"session={SESSION_COOKIE}")],
            status=403,
            response_body=json.dumps({"error": "Forbidden for user " + OWNER_EMAIL}),
        ),
        _entry(
            "GET",
            f"https://app.test/download?file=report.pdf&token={URL_TOKEN}&page=2",
            [("X-API-Key", API_KEY), ("X-CSRF-Token", CSRF_TOKEN)],
            response_body="ok",
            response_mime="text/plain",
        ),
        _entry(
            "GET",
            "https://app.test/profile",
            [("Authorization", f"Basic {BASIC_B64}")],
            response_mime="text/html",
            response_body=(
                f"<html><body><p>Contact {OWNER_EMAIL} or {PHONE}</p>"
                f'<input type="hidden" name="csrf" value="{HTML_SECRET}">'
                f'<script>var apiKey = "{JS_API_KEY}";</script>'
                f"<p>Card on file: {CARD}</p></body></html>"
            ),
        ),
        _entry(
            "POST",
            "https://api.app.test/v1/settings",
            [("Content-Type", "application/x-www-form-urlencoded")],
            request_body=f"display_name=Alice&new_password={PASSWORD}&csrf_token={CSRF_TOKEN}",
            request_mime="application/x-www-form-urlencoded",
            response_body=base64.b64encode(json.dumps({"saved": True}).encode()).decode(),
            response_encoding="base64",
        ),
        _entry(
            "GET",
            "https://www.google-analytics.com/collect?cid=999",
            [],
            response_mime="image/gif",
        ),
        _entry("GET", "https://other.example/out-of-scope", [], response_body="external"),
        _entry("GET", "data:image/png;base64,AAAA", []),
    ]
    return {
        "log": {"version": "1.2", "creator": {"name": "test", "version": "1"}, "entries": entries}
    }


def write_har(directory: Path, name: str = "session.har") -> Path:
    path = directory / name
    path.write_text(json.dumps(build_har()), encoding="utf-8")
    return path
