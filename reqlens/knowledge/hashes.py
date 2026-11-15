"""Hash / encoding identification from a value's *shape* (format string), not its content.

Identification only. reqlens never cracks anything and never tests guesses against a
target. The hashcat mode numbers are given so a human can, if they choose, test a value
they own offline on their own machine.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass

from reqlens.redact import describe_format


@dataclass(frozen=True)
class HashCandidate:
    """One possible identity for a value."""

    name: str
    note: str
    hashcat_mode: int | None = None
    password_hash: bool = False
    """True for slow, salted password-hash formats (their exposure is always serious)."""


_FORMATS: dict[str, list[HashCandidate]] = {
    "bcrypt": [
        HashCandidate(
            "bcrypt",
            "Adaptive password hash with built-in salt and cost "
            "factor. Strong if the cost is 10 or more.",
            3200,
            True,
        )
    ],
    "argon2": [
        HashCandidate(
            "Argon2",
            "Modern memory-hard password hash; the recommended choice (argon2id).",
            None,
            True,
        )
    ],
    "sha512-crypt": [
        HashCandidate(
            "sha512crypt ($6$)",
            "Unix password hash, salted, iterated. Acceptable but slower attacks than bcrypt.",
            1800,
            True,
        )
    ],
    "sha256-crypt": [
        HashCandidate("sha256crypt ($5$)", "Unix password hash, salted, iterated.", 7400, True)
    ],
    "md5-crypt": [
        HashCandidate(
            "md5crypt ($1$)", "Legacy Unix password hash; fast to attack today.", 500, True
        )
    ],
    "apr1-md5": [
        HashCandidate("Apache apr1 MD5", "Legacy .htpasswd hash; fast to attack.", 1600, True)
    ],
    "django-pbkdf2-sha256": [
        HashCandidate("Django PBKDF2-SHA256", "Salted, iterated password hash.", 10000, True)
    ],
    "ldap-ssha": [HashCandidate("LDAP {SSHA}", "Salted SHA-1; fast to attack.", 111, True)],
    "ldap-sha": [HashCandidate("LDAP {SHA}", "Unsalted SHA-1; fast to attack.", 101, True)],
    "uuid": [
        HashCandidate(
            "UUID",
            "Identifier, not a hash. Version-4 UUIDs are random; "
            "version-1 UUIDs embed a timestamp and MAC address.",
        )
    ],
}

_HEX_LENGTHS: dict[int, list[HashCandidate]] = {
    32: [
        HashCandidate(
            "MD5",
            "Fast, broken digest. As a password hash it is trivially "
            "reversible for common passwords.",
            0,
        ),
        HashCandidate("NTLM", "Windows password hash (MD4 of UTF-16LE password).", 1000),
        HashCandidate("128-bit random token", "Could simply be a random identifier/key."),
    ],
    40: [
        HashCandidate("SHA-1", "Fast digest with practical collisions; weak for passwords.", 100),
        HashCandidate("160-bit random token", "Could simply be a random identifier."),
    ],
    56: [HashCandidate("SHA-224", "Fast digest.", 1300)],
    64: [
        HashCandidate(
            "SHA-256", "Fast digest. Fine for integrity, unsuitable alone for passwords.", 1400
        ),
        HashCandidate("HMAC-SHA256 output / 256-bit key", "Could be a MAC or a random key."),
    ],
    96: [HashCandidate("SHA-384", "Fast digest.", 10800)],
    128: [HashCandidate("SHA-512", "Fast digest; unsuitable alone for passwords.", 1700)],
}


def identify_format(fmt: str) -> list[HashCandidate]:
    """Candidates for a format string produced by :func:`reqlens.redact.describe_format`."""
    if fmt in _FORMATS:
        return list(_FORMATS[fmt])
    match = re.fullmatch(r"hex:(\d+)", fmt)
    if match:
        return list(_HEX_LENGTHS.get(int(match.group(1)), []))
    match = re.fullmatch(r"digits:(\d+)", fmt)
    if match and int(match.group(1)) in (4, 6, 8):
        return [
            HashCandidate(
                f"{match.group(1)}-digit code",
                "Short numeric code (OTP, PIN or "
                "verification code). Check rate limiting on where it's used.",
            )
        ]
    return []


def identify_value(value: str) -> tuple[str, list[HashCandidate]]:
    """Identify a raw value supplied by the user (``--check-hashes``). Nothing is stored."""
    value = value.strip()
    fmt = describe_format(value)
    candidates = identify_format(fmt)
    if not candidates and fmt.startswith(("base64:", "base64url:")):
        decoded = _decoded_length(value)
        if decoded is not None:
            bits = decoded * 8
            hex_like = _HEX_LENGTHS.get(decoded * 2, [])
            names = ", ".join(c.name for c in hex_like) or "no common digest"
            candidates = [
                HashCandidate(
                    f"base64-encoded {decoded} bytes ({bits} bits)",
                    f"Same size as: {names}. Could also be a random token or key of that size.",
                )
            ]
    return fmt, candidates


def _decoded_length(value: str) -> int | None:
    padded = value + "=" * (-len(value) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return len(decoder(padded))
        except (binascii.Error, ValueError):
            continue
    return None
