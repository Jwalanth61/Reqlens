"""Neutralise untrusted text before it reaches a terminal, a report, or a prompt.

Captured traffic is attacker-influenced data. It may contain ANSI escape sequences that
rewrite the terminal, bidirectional-override characters that disguise text, or NUL bytes.
Everything printed or written by reqlens passes through :func:`clean_text` first.
"""

from __future__ import annotations

import re

# CSI / OSC / other ESC-introduced sequences, matched before stripping lone control chars.
_ANSI_RE = re.compile(
    r"""
    \x1b\[[0-?]*[ -/]*[@-~]          # CSI ... final byte
    | \x1b\][^\x07\x1b]*(?:\x07|\x1b\\)  # OSC ... BEL or ST
    | \x1b[PX^_][^\x1b]*\x1b\\       # DCS / SOS / PM / APC ... ST
    | \x1b[@-Z\\-_]                  # two-byte escapes
    """,
    re.VERBOSE,
)

# C0 controls except \t \n, DEL, C1 controls (includes 8-bit CSI \x9b).
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

# Bidi overrides/isolates and zero-width characters used to disguise text.
_INVISIBLE_RE = re.compile("[​-‏‪-‮⁦-⁩﻿]")


def clean_text(value: str, *, keep_newlines: bool = True) -> str:
    """Return ``value`` with escape sequences and control/invisible characters removed.

    Carriage returns are normalised away. With ``keep_newlines=False`` newlines and tabs
    become single spaces, for single-line contexts such as table cells and headers.
    """
    text = _ANSI_RE.sub("", value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _CONTROL_RE.sub("", text)
    text = _INVISIBLE_RE.sub("", text)
    if not keep_newlines:
        text = re.sub(r"[\t\n]+", " ", text)
    return text


def truncate(value: str, limit: int, marker: str = "...[truncated]") -> str:
    """Shorten ``value`` to at most ``limit`` characters, appending ``marker`` if cut."""
    if limit <= 0:
        return ""
    if len(value) <= limit:
        return value
    if limit <= len(marker):
        return value[:limit]
    return value[: limit - len(marker)] + marker
