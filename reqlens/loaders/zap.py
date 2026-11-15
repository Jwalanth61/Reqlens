"""OWASP ZAP message export (History > select messages > "Export Messages to File").

The file holds raw HTTP messages, each block introduced by a separator line such as
``==== 12 ==========``, containing the request (headers, body) followed by the response
(status line, headers, body). Bodies are delimited by Content-Length when present and
otherwise by the next status line or separator. ZAP's HAR export is read by the HAR loader.
"""

from __future__ import annotations

import re
from pathlib import Path

from reqlens import config
from reqlens.errors import InputError
from reqlens.loaders.base import LoadResult
from reqlens.loaders.http import (
    build_transaction,
    is_http_url,
    split_message,
    url_from_request_line,
)
from reqlens.model import header_value

CRLF = b"\r\n"
SEPARATOR = re.compile(rb"^={3,}[ \t]*\d+[ \t]*={3,}[ \t]*\r?$", re.MULTILINE)
_STATUS_LINE = re.compile(rb"(?:^|\r?\n)(HTTP/\d(?:\.\d)?[ \t]+\d{3}[^\r\n]*)")
_REQUEST_LINE = re.compile(r"^([A-Z]+)\s+(\S+)\s+HTTP/\d(?:\.\d)?$")
_HEADER_END = re.compile(rb"\r?\n\r?\n")


def looks_like_zap(head: bytes) -> bool:
    """Cheap sniff: the first non-blank line is a ZAP separator."""
    return bool(SEPARATOR.match(head.lstrip(CRLF + b"\t \xef\xbb\xbf")))


def _content_length(message: bytes) -> int | None:
    head_end = _HEADER_END.search(message)
    if head_end is None:
        return None
    _, headers, _ = split_message(message[: head_end.end()])
    value = (header_value(headers, "content-length") or "").strip()
    return int(value) if value.isdigit() else None


def _take_message(block: bytes, stop_at_status: bool) -> tuple[bytes, bytes]:
    """Split ``block`` into (one message, the rest)."""
    head_end = _HEADER_END.search(block)
    if head_end is None:
        return block, b""
    length = _content_length(block)
    if length is not None:
        end = head_end.end() + length
        return block[:end], block[end:]
    if stop_at_status:
        status = _STATUS_LINE.search(block, head_end.end())
        if status:
            return block[: status.start(1)], block[status.start(1) :]
    return block, b""


def _trim_padding(message: bytes) -> bytes:
    """Drop the blank lines ZAP writes after a body, unless Content-Length fixed its size."""
    head_end = _HEADER_END.search(message)
    if head_end is None:
        return message.rstrip(CRLF) + CRLF + CRLF
    if _content_length(message) is not None:
        return message
    return message[: head_end.end()] + message[head_end.end() :].rstrip(CRLF)


def _block_to_transaction(block: bytes, path: Path, index: int):
    block = block.lstrip(CRLF)
    if not block.strip():
        return None
    request_raw, rest = _take_message(block, stop_at_status=True)
    rest = rest.lstrip(CRLF)
    response_raw = None
    if rest.startswith(b"HTTP/"):
        response_raw = _trim_padding(_take_message(rest, stop_at_status=False)[0])
    request_raw = _trim_padding(request_raw)
    start_line, headers, _ = split_message(request_raw)
    match = _REQUEST_LINE.match(start_line)
    if not match:
        raise ValueError("no request line")
    notes = []
    target = match.group(2)
    if not re.match(r"^https?://", target, re.IGNORECASE):
        notes.append("request line had no scheme; https assumed")
    url = url_from_request_line(target, headers, "https")
    if not is_http_url(url):
        return None
    return build_transaction(
        index=index,
        source=path,
        method=match.group(1),
        url=url,
        request_raw=request_raw,
        response_raw=response_raw,
        notes=notes,
    )


def load(path: Path, start_index: int = 0) -> LoadResult:
    """Read a ZAP message export into transactions numbered from ``start_index``."""
    try:
        size = path.stat().st_size
        if size > config.MAX_CAPTURE_BYTES:
            raise InputError(f"{path} is {size} bytes; the limit is {config.MAX_CAPTURE_BYTES}")
        data = path.read_bytes()
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc.strerror}") from exc
    separators = list(SEPARATOR.finditer(data))
    if not separators:
        raise InputError(f"{path} has no ZAP message separators (==== N ==========)")
    result = LoadResult(files=[str(path)])
    for number, match in enumerate(separators, 1):
        end = separators[number].start() if number < len(separators) else len(data)
        block = data[match.end() : end]
        try:
            tx = _block_to_transaction(block, path, start_index + len(result.transactions))
        except (ValueError, TypeError):
            result.warnings.append(f"{path.name}: message {number} skipped (malformed)")
            continue
        if tx is not None:
            result.transactions.append(tx)
    return result
