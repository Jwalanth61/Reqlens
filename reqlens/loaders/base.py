"""Helpers shared by all capture loaders."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from pathlib import Path

from reqlens import config
from reqlens.errors import InputError
from reqlens.model import Transaction

_BINARY_MIME_PREFIXES = (
    "image/",
    "audio/",
    "video/",
    "font/",
    "application/octet-stream",
    "application/pdf",
    "application/zip",
    "application/gzip",
    "application/x-protobuf",
    "application/wasm",
    "application/vnd.ms-fontobject",
    "application/font",
    "application/x-font",
)


@dataclass
class LoadResult:
    """Transactions read from one or more captures, plus non-fatal warnings."""

    transactions: list[Transaction] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)

    def extend(self, other: LoadResult) -> None:
        """Append another result (indices must already be globally unique)."""
        self.transactions.extend(other.transactions)
        self.warnings.extend(other.warnings)
        self.files.extend(other.files)


def read_capture_text(path: Path) -> str:
    """Read a capture as text, enforcing the size limit. Undecodable bytes are replaced."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc.strerror}") from exc
    if size > config.MAX_CAPTURE_BYTES:
        raise InputError(
            f"{path} is {size} bytes; the limit is {config.MAX_CAPTURE_BYTES} bytes. "
            "Split the capture or export only the relevant session."
        )
    try:
        return path.read_bytes().decode("utf-8-sig", errors="replace")
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc.strerror}") from exc


def is_binary_mime(mime: str) -> bool:
    """True for content types reqlens does not analyse as text."""
    mime = mime.lower().strip()
    return any(mime.startswith(prefix) for prefix in _BINARY_MIME_PREFIXES)


def binary_placeholder(size: int, mime: str) -> str:
    """Text that stands in for a binary body."""
    return f"[binary body: {size} bytes, {mime or 'unknown type'}]"


def decode_body(text: str | None, encoding: str | None, mime: str) -> tuple[str, list[str]]:
    """Turn a captured body into analysable text.

    Base64 bodies are decoded; binary content becomes a placeholder. Returns the text and
    any notes worth recording on the transaction.
    """
    notes: list[str] = []
    if not text:
        return "", notes
    if encoding and encoding.lower() == "base64":
        try:
            raw = base64.b64decode(text, validate=False)
        except (binascii.Error, ValueError):
            notes.append("body marked base64 but could not be decoded")
            return "", notes
        if is_binary_mime(mime) or b"\x00" in raw[:4096]:
            return binary_placeholder(len(raw), mime), notes
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return binary_placeholder(len(raw), mime), notes
    elif is_binary_mime(mime):
        return binary_placeholder(len(text), mime), notes
    return limit_body(text, notes), notes


def limit_body(text: str, notes: list[str]) -> str:
    """Truncate very large bodies, recording that it happened."""
    if len(text) > config.MAX_BODY_CHARS:
        notes.append(f"body truncated from {len(text)} to {config.MAX_BODY_CHARS} characters")
        return text[: config.MAX_BODY_CHARS]
    return text
