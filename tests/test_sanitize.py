from __future__ import annotations

import pytest

from reqlens.sanitize import clean_text, truncate


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("\x1b[31mred\x1b[0m", "red"),
        ("\x1b]0;evil title\x07ok", "ok"),
        ("\x1b]8;;https://x.test\x1b\\link\x1b]8;;\x1b\\", "link"),
        ("a\x00b\x07c\x7fd", "abcd"),
        ("over\rwrite", "over\nwrite"),
        ("‮evil‬", "evil"),
        ("zero​width", "zerowidth"),
        ("\x9b31mx", "31mx"),
        ("tab\tand\nnewline", "tab\tand\nnewline"),
    ],
)
def test_clean_text_strips_escapes(raw, expected):
    assert clean_text(raw) == expected


def test_clean_text_single_line():
    assert clean_text("a\n\tb\r\nc", keep_newlines=False) == "a b c"


def test_truncate():
    assert truncate("short", 10) == "short"
    assert truncate("abcdefghijklmnopqrstuvwxyz", 20) == "abcdef...[truncated]"
    assert len(truncate("x" * 100, 20)) == 20
    assert truncate("abc", 0) == ""
