"""Types shared by every provider."""

from __future__ import annotations

from typing import NamedTuple


class Usage(NamedTuple):
    """Tokens a provider reported using for one request."""

    input: int
    output: int


class Answer(NamedTuple):
    """What a provider returned."""

    text: str
    usage: Usage | None  # None when the provider doesn't report token usage
    model: str  # the model that answered
