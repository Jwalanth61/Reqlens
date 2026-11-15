"""JWT knowledge: identify the algorithm, then list the attack classes worth testing by hand.

Works only from a redacted :class:`~reqlens.model.TokenRecord` (decoded header and safe
claims). It never needs, sees, or produces a token or a signature.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from reqlens.model import TokenRecord

ALGORITHMS: dict[str, str] = {
    "none": "no signature (unsigned token)",
    "HS256": "HMAC with SHA-256 (shared secret)",
    "HS384": "HMAC with SHA-384 (shared secret)",
    "HS512": "HMAC with SHA-512 (shared secret)",
    "RS256": "RSA signature (PKCS#1 v1.5) with SHA-256",
    "RS384": "RSA signature (PKCS#1 v1.5) with SHA-384",
    "RS512": "RSA signature (PKCS#1 v1.5) with SHA-512",
    "PS256": "RSA-PSS signature with SHA-256",
    "PS384": "RSA-PSS signature with SHA-384",
    "PS512": "RSA-PSS signature with SHA-512",
    "ES256": "ECDSA signature on P-256 with SHA-256",
    "ES256K": "ECDSA signature on secp256k1 with SHA-256",
    "ES384": "ECDSA signature on P-384 with SHA-384",
    "ES512": "ECDSA signature on P-521 with SHA-512",
    "EdDSA": "Edwards-curve signature (Ed25519/Ed448)",
}

_PII_CLAIMS = {
    "email",
    "phone_number",
    "name",
    "given_name",
    "family_name",
    "address",
    "birthdate",
    "preferred_username",
    "upn",
    "ssn",
    "dob",
}


@dataclass(frozen=True)
class JwtIssue:
    """One attack class worth testing, with what was observed in this token."""

    check_id: str
    observed: str
    concern: str | None = None
    """Overrides the catalog's default concern when the observation warrants it."""


def family(alg: str) -> str:
    """``none``, ``hmac``, ``rsa``, ``ecdsa``, ``eddsa`` or ``unknown``."""
    upper = alg.upper()
    if upper == "NONE" or alg == "":
        return "none"
    if upper.startswith("HS"):
        return "hmac"
    if upper.startswith(("RS", "PS")):
        return "rsa"
    if upper.startswith("ES"):
        return "ecdsa"
    if upper == "EDDSA":
        return "eddsa"
    return "unknown"


def describe(alg: str) -> str:
    """Human description, e.g. ``RS256 (RSA signature (PKCS#1 v1.5) with SHA-256)``."""
    known = ALGORITHMS.get(alg) or ALGORITHMS.get(alg.upper())
    return f"{alg} ({known})" if known else f"{alg or '(missing)'} (unrecognised algorithm)"


def _kid_shape(kid: str) -> str:
    """Describe a kid value without judging it: path-like, URL-like, or quote-bearing."""
    if re.search(r"(\.\./|/|\\)", kid):
        return "looks like a file path"
    if re.match(r"^[a-z]+://", kid, re.IGNORECASE):
        return "looks like a URL"
    if re.search(r"['\";]", kid):
        return "contains quote or semicolon characters"
    return "looks like an opaque identifier"


def analyse(token: TokenRecord) -> list[JwtIssue]:
    """Attack classes worth testing for this token, most important first."""
    header = token.jwt_header
    claims = token.jwt_claims
    alg = str(header.get("alg", ""))
    kind = family(alg)
    issues: list[JwtIssue] = []

    if kind == "none" or token.format == "jwt-unsigned":
        issues.append(
            JwtIssue(
                "JWT-ALG-NONE",
                f"Token header says alg={alg or 'missing'} and the token has no signature.",
            )
        )
    else:
        described = describe(alg)
        if kind in ("rsa", "ecdsa"):
            issues.append(
                JwtIssue(
                    "JWT-ALG-CONFUSION",
                    f"Identified: {described}. The verification key is public, so a server that "
                    "also accepts HS256 could be fooled with it.",
                )
            )
        issues.append(JwtIssue("JWT-NONE-ACCEPTANCE", f"Identified: {described}."))
        issues.append(JwtIssue("JWT-SIGNATURE-CHECK", f"Identified: {described}."))
        if kind == "hmac":
            issues.append(
                JwtIssue(
                    "JWT-HMAC-WEAK-SECRET",
                    f"Identified: {described}. Anyone holding one token can test secret guesses "
                    "offline.",
                )
            )
        if kind == "ecdsa":
            issues.append(JwtIssue("JWT-ECDSA-PSYCHIC", f"Identified: {described}."))

    if "kid" in header:
        issues.append(
            JwtIssue(
                "JWT-KID-INJECTION",
                f"Header has a kid ({_kid_shape(str(header['kid']))}).",
            )
        )
    for key in ("jku", "x5u"):
        if key in header:
            issues.append(JwtIssue("JWT-JKU-X5U", f"Header has {key} = {header[key]}."))
    for key in ("jwk", "x5c"):
        if key in header:
            issues.append(JwtIssue("JWT-EMBEDDED-JWK", f"Header embeds a key ({key})."))

    if kind in ("rsa", "ecdsa", "eddsa"):
        issues.append(
            JwtIssue(
                "JWT-KEY-HYGIENE",
                f"Asymmetric algorithm {alg}; issuer {claims.get('iss', '(no iss claim)')}.",
            )
        )

    issues.extend(_expiry_issues(claims))
    sensitive = sorted(k for k in claims if k.lower() in _PII_CLAIMS)
    if sensitive:
        issues.append(
            JwtIssue(
                "JWT-SENSITIVE-CLAIMS", f"Claims carrying personal data: {', '.join(sensitive)}."
            )
        )
    if token.in_url:
        issues.append(JwtIssue("TOKEN-IN-URL", f"JWT carried in the URL ({token.name})."))
    return issues


def _expiry_issues(claims: dict) -> list[JwtIssue]:
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        return [JwtIssue("JWT-EXP-MISSING", "No numeric exp claim in the token.")]
    iat = claims.get("iat") if isinstance(claims.get("iat"), (int, float)) else None
    if iat is None:
        iat = claims.get("nbf") if isinstance(claims.get("nbf"), (int, float)) else None
    if iat is None:
        return []
    lifetime = exp - iat
    if lifetime > 86400:
        concern_hint = "days" if lifetime >= 2 * 86400 else "hours"
        amount = lifetime / 86400 if concern_hint == "days" else lifetime / 3600
        return [
            JwtIssue(
                "JWT-EXP-LONG",
                f"Token is valid for about {amount:.0f} {concern_hint} (exp - iat).",
                "medium" if lifetime > 30 * 86400 else None,
            )
        ]
    return []
