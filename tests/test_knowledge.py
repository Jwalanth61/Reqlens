"""No-AI knowledge layer: JWT and hash identification, and the catalog itself."""

from __future__ import annotations

import re
from pathlib import Path

import capture_factory as cf
import pytest

from reqlens.cli import main
from reqlens.knowledge import catalog, hashes
from reqlens.knowledge import jwt as jwt_knowledge
from reqlens.model import Confidence
from reqlens.redact import Redactor

ROOT = Path(__file__).resolve().parent.parent


def record(header: dict, payload: dict, signature: bytes = b"s" * 32):
    token = cf.make_jwt(header, payload, signature)
    result = Redactor().describe_jwt(token)
    assert result is not None
    return result


def ids(token) -> list[str]:
    return [issue.check_id for issue in jwt_knowledge.analyse(token)]


# --- the spec's RS256 example --------------------------------------------------------------


def test_rs256_example_lists_the_expected_attack_classes():
    token = record({"alg": "RS256", "typ": "JWT", "kid": "k1"}, {"sub": "x", "exp": 2, "iat": 1})
    found = ids(token)
    assert found[:2] == ["JWT-ALG-CONFUSION", "JWT-NONE-ACCEPTANCE"]
    assert "JWT-KID-INJECTION" in found
    assert "JWT-KEY-HYGIENE" in found
    assert "JWT-HMAC-WEAK-SECRET" not in found
    assert jwt_knowledge.describe("RS256").startswith("RS256 (RSA signature")


def test_rs256_without_kid_has_no_kid_issue():
    found = ids(record({"alg": "RS256"}, {"exp": 2, "iat": 1}))
    assert "JWT-KID-INJECTION" not in found


def test_check_jwt_cli_output(capsys):
    token = cf.make_jwt({"alg": "RS256", "typ": "JWT", "kid": "key-1"}, {"sub": "u1", "exp": 2})
    assert main(["--check-jwt", token]) == 0
    out = capsys.readouterr().out
    assert out.startswith("Identified: RS256 (RSA signature")
    assert "Algorithm confusion" in out
    assert "alg: none" in out
    assert "'kid'" in out
    assert "key strength and rotation" in out
    assert "Manual test:" in out and "Reference:" in out
    assert "reqlens performs none of these" in out
    signature = token.split(".")[2]
    assert signature not in out and token not in out


def test_check_jwt_reads_stdin(capsys, monkeypatch):
    import io

    token = cf.make_jwt({"alg": "HS256"}, {"sub": "u1"})
    monkeypatch.setattr("sys.stdin", io.StringIO(token + "\n"))
    assert main(["--check-jwt", "-"]) == 0
    out = capsys.readouterr().out
    assert "HMAC with SHA-256" in out and "secret strength" in out
    assert "no expiry" in out


def test_check_jwt_rejects_non_jwt_and_mixing_with_captures(capsys):
    assert main(["--check-jwt", "not-a-token"]) == 2
    assert main(["cap.har", "--check-jwt", "x"]) == 2


# --- other algorithms ----------------------------------------------------------------------


def test_alg_none():
    found = ids(record({"alg": "none"}, {"exp": 2, "iat": 1}, b""))
    assert found[0] == "JWT-ALG-NONE"
    assert "JWT-NONE-ACCEPTANCE" not in found


def test_hs256():
    found = ids(record({"alg": "HS256"}, {"exp": 2, "iat": 1}))
    assert "JWT-HMAC-WEAK-SECRET" in found
    assert "JWT-ALG-CONFUSION" not in found and "JWT-KEY-HYGIENE" not in found


def test_es256_includes_psychic_signature_check():
    found = ids(record({"alg": "ES256"}, {"exp": 2, "iat": 1}))
    assert {"JWT-ALG-CONFUSION", "JWT-ECDSA-PSYCHIC", "JWT-KEY-HYGIENE"} <= set(found)


def test_header_key_sources():
    found = ids(
        record(
            {"alg": "RS256", "jku": "https://keys.app.test/jwks", "jwk": {"n": "x"}},
            {"exp": 2, "iat": 1},
        )
    )
    assert "JWT-JKU-X5U" in found and "JWT-EMBEDDED-JWK" in found


def test_kid_shape_is_described():
    issues = jwt_knowledge.analyse(record({"alg": "HS256", "kid": "../../keys/a"}, {"exp": 1}))
    kid = next(i for i in issues if i.check_id == "JWT-KID-INJECTION")
    assert "file path" in kid.observed


def test_expiry_rules():
    assert "JWT-EXP-MISSING" in ids(record({"alg": "HS256"}, {"sub": "x"}))
    long_issue = next(
        i
        for i in jwt_knowledge.analyse(record({"alg": "HS256"}, {"iat": 0, "exp": 90 * 86400}))
        if i.check_id == "JWT-EXP-LONG"
    )
    assert long_issue.concern == "medium"
    short = ids(record({"alg": "HS256"}, {"iat": 0, "exp": 900}))
    assert "JWT-EXP-LONG" not in short and "JWT-EXP-MISSING" not in short


def test_sensitive_claims():
    found = ids(record({"alg": "HS256"}, {"exp": 1, "email": "a@b.test", "phone_number": "1"}))
    assert "JWT-SENSITIVE-CLAIMS" in found


# --- hashes --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value, expected, password_hash",
    [
        ("$2b$12$" + "a" * 53, "bcrypt", True),
        ("$argon2id$v=19$m=65536,t=3,p=4$abc$def", "Argon2", True),
        ("$6$salt$" + "x" * 86, "sha512crypt ($6$)", True),
        ("d41d8cd98f00b204e9800998ecf8427e", "MD5", False),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "SHA-1", False),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA-256", False),
    ],
)
def test_identify_hash_values(value, expected, password_hash):
    _, candidates = hashes.identify_value(value)
    assert candidates[0].name == expected
    assert candidates[0].password_hash is password_hash


def test_identify_base64_digest_size():
    fmt, candidates = hashes.identify_value("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")
    assert fmt.startswith("base64")
    assert "32 bytes" in candidates[0].name and "SHA-256" in candidates[0].note


def test_check_hashes_cli_does_not_echo_values(capsys):
    value = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert main(["--check-hashes", value, "$2b$12$" + "b" * 53]) == 0
    out = " ".join(capsys.readouterr().out.split())
    assert "SHA-256" in out and "bcrypt" in out and "hashcat mode 1400" in out
    assert value not in out
    assert "nothing is cracked" in out


# --- catalog integrity ---------------------------------------------------------------------


def test_every_check_id_used_in_code_exists_in_catalog():
    used: set[str] = set()
    for path in (ROOT / "reqlens").rglob("*.py"):
        if path.name == "catalog.py":
            continue
        used |= set(
            re.findall(
                r"\"((?:HDR|CK|CORS|JWT|TOKEN|DISC|OBS|ACC|CACHE|GQL|HASH|EXT)-[A-Z0-9-]+)\"",
                path.read_text(encoding="utf-8"),
            )
        )
    assert used, "no check ids found; the scan pattern is broken"
    assert used <= set(catalog.CATALOG), sorted(used - set(catalog.CATALOG))


@pytest.mark.parametrize("check_id", sorted(catalog.CATALOG))
def test_catalog_entries_are_complete(check_id):
    entry = catalog.CATALOG[check_id]
    assert entry.category in catalog.CATEGORIES
    for text in (entry.title, entry.why, entry.manual_test, entry.learning):
        assert len(text) > 15
    assert entry.references, "every entry cites at least one reference"
    assert all(ref.startswith("https://") for ref in entry.references)
    assert entry.wstg
    lowered = entry.manual_test.lower()
    for forbidden in ("loop", "for each id", "enumerate all", "every user", "dump"):
        assert forbidden not in lowered, f"manual test must stay single-step: {forbidden!r}"


def test_findings_are_never_confirmed():
    for check_id in catalog.CATALOG:
        finding = catalog.make_finding(check_id)
        assert finding.confidence in (Confidence.POSSIBLE, Confidence.INFORMATIONAL)
