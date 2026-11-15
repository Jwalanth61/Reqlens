"""Redaction is the most important module: these tests try hard to make secrets leak."""

from __future__ import annotations

import dataclasses
import json
import random
import string
from urllib.parse import quote

import capture_factory as cf
import pytest

from reqlens.errors import RedactionError
from reqlens.loaders import load_captures
from reqlens.model import Transaction
from reqlens.redact import (
    RedactionPolicy,
    Redactor,
    describe_format,
    is_sensitive_name,
    looks_random,
    luhn_valid,
)

KEY = b"k" * 32


def dump(tx: Transaction) -> str:
    """Everything a later stage could read from a transaction, as one string."""
    return json.dumps(dataclasses.asdict(tx), ensure_ascii=False)


def assert_no_secrets(text: str, secrets: list[str]) -> None:
    for secret in secrets:
        for form in {secret, quote(secret, safe=""), json.dumps(secret)[1:-1]}:
            assert form not in text, f"secret leaked: {secret[:6]}..."


@pytest.fixture
def transactions(tmp_path) -> list[Transaction]:
    return load_captures([str(cf.write_har(tmp_path))]).transactions


@pytest.fixture
def strict(transactions) -> list[Transaction]:
    return Redactor(key=KEY).redact_all(transactions)


@pytest.fixture
def keep(transactions) -> list[Transaction]:
    return Redactor(RedactionPolicy(keep_body_values=True), key=KEY).redact_all(transactions)


def by_path(txs: list[Transaction], fragment: str) -> Transaction:
    return next(tx for tx in txs if fragment in tx.url)


# --- the core guarantee --------------------------------------------------------------------


def test_raw_capture_really_contains_the_secrets(transactions):
    """Guard against a vacuous test: the secrets must be present before redaction."""
    raw = "".join(dump(tx) for tx in transactions)
    for secret in cf.SECRETS:
        # only present base64-encoded, or only in its spaced form
        if secret in (cf.BASIC_PASSWORD, cf.USER_SUB, cf.CARD.replace(" ", "")):
            continue
        assert secret in raw, secret


def test_no_secret_survives_strict_redaction(strict):
    assert_no_secrets("".join(dump(tx) for tx in strict), cf.SECRETS)


def test_no_secret_survives_keep_body_values(keep):
    """Even when the user keeps body values, credentials and tokens are removed."""
    always_secret = [
        s
        for s in cf.SECRETS
        if s not in (cf.OWNER_EMAIL, cf.PHONE, cf.SSN, cf.CARD, cf.CARD.replace(" ", ""))
    ]
    assert_no_secrets("".join(dump(tx) for tx in keep), always_secret)


def test_original_transactions_are_not_modified(transactions):
    before = [dump(tx) for tx in transactions]
    Redactor(key=KEY).redact_all(transactions)
    assert [dump(tx) for tx in transactions] == before


def test_redacted_flag_and_idempotence(strict):
    assert all(tx.redacted for tx in strict)
    redactor = Redactor(key=KEY)
    assert redactor.redact(strict[0]) is strict[0]


# --- cookies -------------------------------------------------------------------------------


def test_set_cookie_keeps_names_and_attributes(strict):
    login = by_path(strict, "/api/login")
    cookies = [v for n, v in login.response_headers if n.lower() == "set-cookie"]
    assert cookies[0].startswith("session=<redacted:")
    assert "Path=/" in cookies[0] and "HttpOnly" in cookies[0] and "Secure" in cookies[0]
    assert "SameSite=Lax" in cookies[0]
    assert cookies[1].startswith("remember=<redacted:") and "Max-Age=2592000" in cookies[1]


def test_cookie_fingerprints_correlate_between_set_cookie_and_cookie(strict):
    login = by_path(strict, "/api/login")
    set_fp = next(t.fingerprint for t in login.tokens if t.name == "session")
    later = by_path(strict, "/api/users/123")
    cookie = later.request_header("Cookie")
    assert cookie == f"session=<redacted:{set_fp}>"


def test_fingerprints_differ_between_runs_with_random_keys(transactions):
    first = Redactor().redact(transactions[1]).request_header("Cookie")
    second = Redactor().redact(transactions[1]).request_header("Cookie")
    assert first != second


# --- authorization and JWTs ----------------------------------------------------------------


def test_bearer_jwt_is_decoded_structurally(strict):
    tx = by_path(strict, "/api/users/123")
    assert tx.request_header("Authorization").startswith("Bearer <jwt:")
    jwt = next(t for t in tx.tokens if t.kind == "jwt")
    assert jwt.jwt_header == {"alg": "RS256", "typ": "JWT", "kid": "key-2024-01"}
    claims = jwt.jwt_claims
    assert claims["role"] == "user"
    assert claims["scope"] == "read:profile write:profile"
    assert claims["iss"] == "https://auth.app.test"
    assert claims["exp"] == 1893456000 and claims["iat"] == 1700000000
    assert claims["sub"].startswith("<redacted:")
    assert claims["email"].startswith("<redacted:")
    assert jwt.format == "jwt"


def test_unsigned_jwt_is_flagged():
    token = cf.make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "x", "role": "admin"}, b"")
    tx = Transaction(0, "t", "GET", "https://app.test/", [("Authorization", f"Bearer {token}")])
    out = Redactor(key=KEY).redact(tx)
    jwt = out.tokens[0]
    assert jwt.format == "jwt-unsigned"
    assert jwt.jwt_header["alg"] == "none"
    assert jwt.jwt_claims["role"] == "admin"
    assert token not in dump(out)


def test_jwt_embedded_jwk_is_not_copied():
    token = cf.make_jwt({"alg": "RS256", "jwk": {"n": "SECRETMODULUS", "e": "AQAB"}}, {"sub": "x"})
    tx = Transaction(0, "t", "GET", "https://app.test/", [("Authorization", f"Bearer {token}")])
    out = Redactor(key=KEY).redact(tx)
    assert out.tokens[0].jwt_header["jwk"] == "<embedded jwk>"
    assert "SECRETMODULUS" not in dump(out)


def test_basic_auth_is_fully_hidden(strict):
    tx = by_path(strict, "/profile")
    assert tx.request_header("Authorization").startswith("Basic <redacted:")
    basic = next(t for t in tx.tokens if t.kind == "basic")
    assert basic.format == "user:password"
    assert cf.BASIC_USER not in dump(tx)


def test_other_auth_schemes_keep_only_the_scheme():
    tx = Transaction(
        0,
        "t",
        "GET",
        "https://app.test/",
        [("Authorization", 'Digest username="bob", response="abcdef0123456789"')],
    )
    out = Redactor(key=KEY).redact(tx).request_header("Authorization")
    assert out.startswith("Digest <redacted:")
    assert "bob" not in out


# --- URLs ----------------------------------------------------------------------------------


def test_url_token_is_redacted_and_marked_in_url(strict):
    tx = by_path(strict, "/download")
    assert "token=<redacted:" in tx.url
    assert "file=<str:10>" in tx.url and "page=<digits:1>" in tx.url
    token = next(t for t in tx.tokens if t.name == "token")
    assert token.in_url is True


def test_keep_body_values_keeps_plain_query_values(keep):
    tx = by_path(keep, "/download")
    assert "file=report.pdf" in tx.url and "page=2" in tx.url
    assert "token=<redacted:" in tx.url


def test_url_userinfo_and_fragment_tokens():
    url = "https://bob:pa55word@app.test/cb#access_token=abc123SECRETxyz&state=1"
    out = Redactor(key=KEY).redact(Transaction(0, "t", "GET", url)).url
    assert "pa55word" not in out and "bob" not in out
    assert "abc123SECRETxyz" not in out
    assert out.startswith("https://<redacted:")


def test_path_segments_keep_ids_but_lose_secrets():
    url = f"https://app.test/users/42/reset/{cf.URL_TOKEN}/{cf.OWNER_EMAIL}"
    out = Redactor(key=KEY).redact(Transaction(0, "t", "GET", url)).url
    assert "/users/42/reset/<redacted:" in out
    assert "<email>" in out


# --- headers -------------------------------------------------------------------------------


def test_sensitive_headers_are_redacted_but_policy_headers_are_not():
    tx = Transaction(
        0,
        "t",
        "GET",
        "https://app.test/",
        [("X-API-Key", cf.API_KEY), ("X-CSRF-Token", cf.CSRF_TOKEN)],
        response_headers=[
            ("Access-Control-Allow-Credentials", "true"),
            ("Access-Control-Allow-Origin", "https://evil.test"),
            ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
            ("Content-Security-Policy", "default-src 'self'"),
            ("Server", "Apache/2.4.41 (Ubuntu)"),
        ],
    )
    out = Redactor(key=KEY).redact(tx)
    assert out.request_header("X-API-Key").startswith("<redacted:")
    assert out.request_header("X-CSRF-Token").startswith("<redacted:")
    assert out.response_header("Access-Control-Allow-Credentials") == "true"
    assert out.response_header("Access-Control-Allow-Origin") == "https://evil.test"
    assert out.response_header("Strict-Transport-Security") == "max-age=31536000; includeSubDomains"
    assert out.response_header("Content-Security-Policy") == "default-src 'self'"
    assert out.response_header("Server") == "Apache/2.4.41 (Ubuntu)"


def test_referer_and_location_urls_are_redacted():
    tx = Transaction(
        0,
        "t",
        "GET",
        "https://app.test/",
        [("Referer", f"https://app.test/cb?code={cf.URL_TOKEN}")],
        response_headers=[("Location", f"/next?session_id={cf.SESSION_COOKIE}")],
    )
    out = dump(Redactor(key=KEY).redact(tx))
    assert cf.URL_TOKEN not in out and cf.SESSION_COOKIE not in out


# --- bodies --------------------------------------------------------------------------------


def test_json_body_keeps_keys_and_masks_values(strict):
    login = by_path(strict, "/api/login")
    request = json.loads(login.request_body)
    assert set(request) == {"email", "password", "remember"}
    assert request["email"] == "<email>"
    assert request["password"].startswith("<redacted:")
    assert request["remember"] is True
    response = json.loads(login.response_body)
    assert response["access_token"].startswith("<jwt:")
    assert response["refresh_token"].startswith("<redacted:")
    assert response["user"] == {
        "id": "<int>",
        "email": "<email>",
        "phone": "<phone>",
        "isAdmin": False,
    }


def test_pii_is_recorded(strict):
    tx = by_path(strict, "/api/users/123")
    kinds = {hit.kind for hit in tx.pii}
    assert {"email", "card"} <= kinds
    body = json.loads(tx.response_body)
    assert body["ssn"].startswith("<redacted:")  # sensitive name wins over gov-id masking
    assert body["card"] == "<card>"


def test_error_messages_stay_readable_without_pii(strict):
    tx = by_path(strict, "/api/users/456")
    assert json.loads(tx.response_body) == {"error": "Forbidden for user <email>"}


def test_html_body_is_scrubbed(strict):
    tx = by_path(strict, "/profile")
    assert "<html><body><p>Contact <email> or <phone></p>" in tx.response_body
    assert "Card on file: <card>" in tx.response_body
    assert 'apiKey = "<redacted:' in tx.response_body


def test_form_body_and_base64_response(strict):
    tx = by_path(strict, "/v1/settings")
    assert tx.request_body.startswith("display_name=<str:5>&new_password=<redacted:")
    assert "csrf_token=<redacted:" in tx.request_body
    assert json.loads(tx.response_body) == {"saved": True}


def test_keep_body_values_keeps_non_secret_values(keep):
    tx = by_path(keep, "/v1/settings")
    assert "display_name=Alice" in tx.request_body
    assert "new_password=<redacted:" in tx.request_body


def test_multipart_body():
    body = (
        '--XyZ\r\nContent-Disposition: form-data; name="comment"\r\n\r\nHello\r\n'
        '--XyZ\r\nContent-Disposition: form-data; name="api_token"\r\n\r\n'
        f"{cf.API_KEY}\r\n"
        '--XyZ\r\nContent-Disposition: form-data; name="doc"; filename="alice-passport.pdf"'
        "\r\nContent-Type: application/pdf\r\n\r\nPDFDATA\r\n--XyZ--\r\n"
    )
    tx = Transaction(
        0,
        "t",
        "POST",
        "https://app.test/upload",
        [("Content-Type", "multipart/form-data; boundary=XyZ")],
        body,
    )
    out = Redactor(key=KEY).redact(tx).request_body
    assert "comment=<str:5>" in out
    assert "api_token=<redacted:" in out
    assert 'file part "doc": extension .pdf' in out
    assert "alice-passport" not in out and cf.API_KEY not in out and "PDFDATA" not in out


def test_xml_body_masks_text_and_refuses_entities():
    xml = f"<user><name>Alice</name><password>{cf.PASSWORD}</password><id>7</id></user>"
    tx = Transaction(
        0, "t", "POST", "https://app.test/x", [("Content-Type", "application/xml")], xml
    )
    out = Redactor(key=KEY).redact(tx).request_body
    assert "<name>&lt;str:5&gt;</name>" in out
    assert cf.PASSWORD not in out
    evil = f'<?xml version="1.0"?><!DOCTYPE a [<!ENTITY e "x">]><a>&e; {cf.API_KEY}</a>'
    tx = Transaction(0, "t", "POST", "https://app.test/x", [("Content-Type", "text/xml")], evil)
    assert cf.API_KEY not in Redactor(key=KEY).redact(tx).request_body


def test_deeply_nested_json_is_omitted_not_leaked():
    body = "[" * 5000 + '"' + cf.API_KEY + '"' + "]" * 5000
    tx = Transaction(
        0, "t", "POST", "https://app.test/x", [("Content-Type", "application/json")], body
    )
    out = Redactor(key=KEY).redact(tx).request_body
    assert cf.API_KEY not in out


def test_redaction_fails_closed(monkeypatch):
    redactor = Redactor(key=KEY)

    def boom(*_args, **_kwargs):
        raise RuntimeError(cf.API_KEY)

    monkeypatch.setattr(redactor, "_body", boom)
    with pytest.raises(RedactionError) as excinfo:
        redactor.redact(Transaction(3, "t", "GET", "https://app.test/"))
    assert "transaction 3" in str(excinfo.value)
    assert cf.API_KEY not in str(excinfo.value)


# --- randomised leak hunting ---------------------------------------------------------------


def _random_token(rng: random.Random, length: int) -> str:
    alphabet = string.ascii_letters + string.digits + "-_"
    return "".join(rng.choice(alphabet) for _ in range(length))


@pytest.mark.parametrize("seed", range(40))
def test_random_secrets_never_leak_from_any_position(seed):
    rng = random.Random(seed)
    secret = _random_token(rng, rng.randint(24, 64))
    hexsecret = "".join(rng.choice("0123456789abcdef") for _ in range(40))
    tx = Transaction(
        index=0,
        source="t",
        method="POST",
        url=f"https://app.test/a?access_token={secret}&q=1",
        request_headers=[
            ("Cookie", f"sid={secret}; theme=dark"),
            ("Authorization", f"Bearer {secret}"),
            ("X-Auth-Token", secret),
            ("Content-Type", "application/json"),
        ],
        request_body=json.dumps({"data": secret, "nested": [{"value": hexsecret}]}),
        status=200,
        response_headers=[
            ("Set-Cookie", f"sid={secret}; Secure"),
            ("Content-Type", "text/html"),
            ("X-Debug", f"trace {secret}"),
        ],
        response_body=f"<div data-x='{secret}'>hello</div><!-- {hexsecret} -->",
    )
    for policy in (RedactionPolicy(), RedactionPolicy(keep_body_values=True)):
        out = dump(Redactor(policy).redact(tx))
        assert secret not in out
        assert hexsecret not in out


# --- helpers -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name, expected",
    [
        ("Authorization", True),
        ("X-API-Key", True),
        ("sessionId", True),
        ("csrf_token", True),
        ("JSESSIONID", True),
        ("refreshToken", True),
        ("pin", True),
        ("author", False),
        ("Content-Type", False),
        ("keepAlive", False),
        ("pinned", False),
        ("display_name", False),
    ],
)
def test_is_sensitive_name(name, expected):
    assert is_sensitive_name(name) is expected


def test_looks_random():
    assert looks_random("aB3dE5fG7hJ9kL1mN3pQ5r")
    assert looks_random("9f86d081884c7d659a2feaa0c55ad015")
    assert not looks_random("content-security-policy-report")
    assert not looks_random("550e8400-e29b-41d4-a716-446655440000")
    assert not looks_random("short1")


def test_luhn_and_formats():
    assert luhn_valid("4111111111111111") and not luhn_valid("4111111111111112")
    assert describe_format("$2b$12$abcdefghijklmnopqrstuv") == "bcrypt"
    assert describe_format("d41d8cd98f00b204e9800998ecf8427e") == "hex:32"
    assert describe_format("550e8400-e29b-41d4-a716-446655440000") == "uuid"
    assert describe_format("123456") == "digits:6"
    assert describe_format("abc-DEF_123") == "base64url:11"
