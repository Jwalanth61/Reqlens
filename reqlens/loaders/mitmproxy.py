"""mitmproxy saved flows (``mitmdump -w`` / "Save" in mitmproxy or mitmweb).

The file is a sequence of tnetstring-encoded flow dictionaries. reqlens has its own small,
bounded tnetstring reader (no mitmproxy dependency, no pickle, nothing executed). Only HTTP
flows are used; TCP, UDP, DNS and WebSocket-only flows are skipped. mitmproxy's HAR export
is read by the HAR loader instead.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from reqlens import config
from reqlens.errors import InputError
from reqlens.loaders.base import LoadResult
from reqlens.loaders.http import decode_body, is_http_url
from reqlens.model import Header, Transaction

MAX_DEPTH = 64
_DEFAULT_PORTS = {"http": 80, "https": 443}


class TNetStringError(ValueError):
    """Malformed tnetstring data."""


def looks_like_mitmproxy(head: bytes) -> bool:
    """Cheap sniff: starts with ``<digits>:`` and the first record looks like a dict."""
    match = re.match(rb"(\d{1,10}):", head)
    return bool(match) and (b"version" in head[:4096] or b"request" in head[:4096])


def parse_tnetstring(data: bytes, pos: int = 0, depth: int = 0) -> tuple[Any, int]:
    """Parse one tnetstring at ``pos``; return (value, position after it)."""
    if depth > MAX_DEPTH:
        raise TNetStringError("nesting too deep")
    colon = data.find(b":", pos, pos + 12)
    if colon == -1 or not data[pos:colon].isdigit():
        raise TNetStringError(f"bad length prefix at byte {pos}")
    length = int(data[pos:colon])
    start = colon + 1
    end = start + length
    if end >= len(data):
        raise TNetStringError(f"truncated value at byte {pos}")
    payload, tag = data[start:end], data[end : end + 1]
    if tag == b",":
        value: Any = payload
    elif tag == b";":
        value = payload.decode("utf-8", errors="replace")
    elif tag == b"#":
        value = int(payload)
    elif tag == b"^":
        value = float(payload)
    elif tag == b"!":
        value = payload == b"true"
    elif tag == b"~":
        value = None
    elif tag == b"]":
        value = []
        inner = 0
        while inner < len(payload):
            item, inner = parse_tnetstring(payload, inner, depth + 1)
            value.append(item)
    elif tag == b"}":
        value = {}
        inner = 0
        while inner < len(payload):
            key, inner = parse_tnetstring(payload, inner, depth + 1)
            item, inner = parse_tnetstring(payload, inner, depth + 1)
            value[_text(key)] = item
    else:
        raise TNetStringError(f"unknown type tag {tag!r} at byte {end}")
    return value, end + 1


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return "" if value is None else str(value)


def _headers(raw: Any) -> list[Header]:
    headers: list[Header] = []
    for pair in raw or []:
        if isinstance(pair, (list, tuple)) and len(pair) == 2:
            name = _text(pair[0])
            if name and not name.startswith(":"):
                headers.append((name, _text(pair[1])))
    return headers


def _url(request: dict) -> str:
    scheme = _text(request.get("scheme")).lower() or "http"
    host = _text(request.get("host"))
    authority = _text(request.get("authority"))
    if authority and not re.match(r"^\d+\.\d+\.\d+\.\d+(:\d+)?$", authority):
        host = authority.rsplit(":", 1)[0] if authority.count(":") == 1 else authority
    port = request.get("port")
    path = _text(request.get("path")) or "/"
    if re.match(r"^https?://", path, re.IGNORECASE):
        return path
    port_part = f":{port}" if isinstance(port, int) and port != _DEFAULT_PORTS.get(scheme) else ""
    return f"{scheme}://{host}{port_part}{path}"


def _content(message: dict) -> bytes:
    content = message.get("content")
    if content is None:
        content = message.get("raw_content")
    if isinstance(content, str):
        return content.encode("utf-8", errors="replace")
    return content if isinstance(content, bytes) else b""


def flow_to_transaction(flow: dict, path: Path, index: int) -> Transaction | None:
    """Convert one mitmproxy flow dict; ``None`` for non-HTTP flows."""
    if _text(flow.get("type")) not in ("http", ""):
        return None
    request = flow.get("request")
    if not isinstance(request, dict):
        return None
    url = _url(request)
    if not is_http_url(url):
        return None
    notes: list[str] = []
    request_headers = _headers(request.get("headers"))
    response = flow.get("response") if isinstance(flow.get("response"), dict) else None
    response_headers = _headers(response.get("headers")) if response else []
    status = response.get("status_code") if response else None
    started = request.get("timestamp_start")
    ended = response.get("timestamp_end") if response else None
    duration = (
        (ended - started) * 1000
        if isinstance(started, (int, float)) and isinstance(ended, (int, float))
        else None
    )
    return Transaction(
        index=index,
        source=str(path),
        method=_text(request.get("method")).upper() or "GET",
        url=url,
        request_headers=request_headers,
        request_body=decode_body(_content(request), request_headers, notes, "request"),
        status=status if isinstance(status, int) and status > 0 else None,
        response_headers=response_headers,
        response_body=decode_body(_content(response), response_headers, notes, "response")
        if response
        else "",
        started=str(started) if started is not None else None,
        duration_ms=duration,
        notes=notes,
    )


def load(path: Path, start_index: int = 0) -> LoadResult:
    """Read a mitmproxy flow file into transactions numbered from ``start_index``."""
    try:
        size = path.stat().st_size
        if size > config.MAX_CAPTURE_BYTES:
            raise InputError(f"{path} is {size} bytes; the limit is {config.MAX_CAPTURE_BYTES}")
        data = path.read_bytes()
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc.strerror}") from exc
    result = LoadResult(files=[str(path)])
    pos = 0
    skipped = 0
    record = 0
    while pos < len(data):
        if data[pos : pos + 1].isspace():
            pos += 1
            continue
        try:
            flow, pos = parse_tnetstring(data, pos)
        except (TNetStringError, ValueError) as exc:
            if record == 0:
                raise InputError(f"{path} is not a mitmproxy flow file: {exc}") from exc
            result.warnings.append(f"{path.name}: stopped at flow {record + 1} (malformed: {exc})")
            break
        record += 1
        if not isinstance(flow, dict):
            skipped += 1
            continue
        try:
            tx = flow_to_transaction(flow, path, start_index + len(result.transactions))
        except (TypeError, ValueError, AttributeError):
            result.warnings.append(f"{path.name}: flow {record} skipped (malformed)")
            continue
        if tx is None:
            skipped += 1
        else:
            result.transactions.append(tx)
    if skipped:
        result.warnings.append(f"{path.name}: {skipped} non-HTTP flows skipped")
    return result
