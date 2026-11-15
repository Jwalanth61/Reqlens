"""Small text helpers used across the AI step (same contract as Inicon's ai/text.py)."""

from __future__ import annotations

from reqlens.sanitize import clean_text


def clean(text: object, limit: int | None = None) -> str:
    """Remove escape/control/invisible characters and optionally cap the length."""
    cleaned = clean_text(str(text))
    return cleaned if limit is None else cleaned[:limit]


def one_line(text: object, limit: int) -> str:
    """Collapse whitespace to single spaces, remove control characters, cap the length."""
    return clean(" ".join(str(text).split()), limit)


def estimate_tokens(text: str) -> int:
    """Rough token estimate. Paths and placeholders tokenise badly: assume 3 chars/token."""
    return (len(text) + 2) // 3
