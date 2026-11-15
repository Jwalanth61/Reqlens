"""Raw HTTP/1.x message parsing and body decoding, shared by the Burp, ZAP and mitmproxy
loaders. Everything here works on bytes already on disk; nothing is sent anywhere.

Body decoding handles chunked transfer encoding and gzip/deflate content encoding with a
hard output limit (so a compressed "zip bomb" can't exhaust memory). Brotli and zstd are not
in the standard library; such bodies become a placeholder.
"""

from __future__ import annotations

import re
import zlib
from pathlib import Path
from urllib.parse import urlsplit

from reqlens import config
from reqlens.loaders.base import binary_placeholder, is_binary_mime, limit_body
from reqlens.model import Header, Transaction, header_value

_HEADER_END = re.compile(rb"\r?\n\r?\n")
_CHARSET = re.compile(r"charset\s*=\s*\"?([\w.:-]+)", re.IGNORECASE)


def split_message(raw: bytes) -> tuple[str, list[Header], bytes]:
    """Split a raw HTTP message into (start line, headers, body bytes)."""
    match = _HEADER_END.search(raw)
    head, body = (raw[: match.start()], raw[match.end() :]) if match else (raw, b"")
    lines = head.decode("utf-8", errors="replace").splitlines()
    start = lines[0].strip() if lines else ""
    headers: list[Header] = []
    for line in lines[1:]:
        if line[:1] in (" ", "\t") and headers:  # obsolete line folding
            name, value = headers[-1]
            headers[-1] = (name, value + " " + line.strip())
            continue
        name, sep, value = line.partition(":")
        if sep and name.strip() and not name.startswith(":"):
            headers.append((name.strip(), value.strip()))
    return start, headers, body


def dechunk(body: bytes) -> bytes | None:
    """Decode ``Transfer-Encoding: chunked``; ``None`` if the body isn't valid chunking."""
    out = bytearray()
    pos = 0
    while True:
        line_end = body.find(b"\n", pos)
        if line_end == -1:
            line_end = len(body)  # last-chunk line without a newline (trimmed export)
        size_text = body[pos:line_end].split(b";", 1)[0].strip()
        if not size_text and line_end == len(body):
            return None
        try:
            size = int(size_text, 16)
        except ValueError:
            return None
        if size == 0:
            return bytes(out)
        start = line_end + 1
        out += body[start : start + size]
        if len(out) > config.MAX_BODY_CHARS * 4:
            return bytes(out)
        pos = start + size
        if body[pos : pos + 2] == b"\r\n":
            pos += 2
        elif body[pos : pos + 1] == b"\n":
            pos += 1


def _inflate(body: bytes, encoding: str, notes: list[str]) -> bytes | None:
    """gzip/deflate decompression bounded to a few times the body limit."""
    limit = config.MAX_BODY_CHARS * 4
    for wbits in (31,) if encoding in ("gzip", "x-gzip") else (15, -15):
        try:
            decompressor = zlib.decompressobj(wbits)
            data = decompressor.decompress(body, limit)
        except zlib.error:
            continue
        if decompressor.unconsumed_tail:
            notes.append(f"decompressed body exceeded {limit} bytes and was cut")
        return data
    return None


def decode_body(body: bytes, headers: list[Header], notes: list[str], label: str) -> str:
    """Turn raw body bytes into analysable text (or a placeholder)."""
    if not body:
        return ""
    transfer = (header_value(headers, "transfer-encoding") or "").lower()
    if "chunked" in transfer:
        decoded = dechunk(body)
        if decoded is not None:
            body = decoded
    encoding = (header_value(headers, "content-encoding") or "").lower().strip()
    if encoding and encoding != "identity":
        if encoding in ("gzip", "x-gzip", "deflate"):
            inflated = _inflate(body, encoding, notes)
            if inflated is None:
                notes.append(f"{label} body marked {encoding} but could not be decompressed")
                return f"[compressed body ({encoding}), {len(body)} bytes, not decodable]"
            body = inflated
        else:
            notes.append(f"{label} body uses {encoding} encoding, which reqlens cannot decode")
            return f"[compressed body ({encoding}), {len(body)} bytes, not analysed]"
    content_type = header_value(headers, "content-type") or ""
    if is_binary_mime(content_type) or b"\x00" in body[:4096]:
        return binary_placeholder(len(body), content_type)
    charset_match = _CHARSET.search(content_type)
    charset = charset_match.group(1) if charset_match else "utf-8"
    try:
        text = body.decode(charset, errors="replace")
    except LookupError:
        text = body.decode("utf-8", errors="replace")
    body_notes: list[str] = []
    text = limit_body(text, body_notes)
    notes.extend(f"{label} {note}" for note in body_notes)
    return text


def url_from_request_line(target: str, headers: list[Header], default_scheme: str) -> str:
    """Absolute URL from a request target (absolute-form, or origin-form + Host header)."""
    if re.match(r"^https?://", target, re.IGNORECASE):
        return target
    host = header_value(headers, "host") or ""
    if not target.startswith("/"):
        target = "/" + target
    return f"{default_scheme}://{host}{target}"


def build_transaction(
    *,
    index: int,
    source: Path,
    method: str,
    url: str,
    request_raw: bytes,
    response_raw: bytes | None,
    status: int | None = None,
    started: str | None = None,
    duration_ms: float | None = None,
    notes: list[str] | None = None,
) -> Transaction:
    """Build a Transaction from raw request/response bytes."""
    notes = list(notes or [])
    _, request_headers, request_body = split_message(request_raw)
    response_headers: list[Header] = []
    response_text = ""
    if response_raw:
        status_line, response_headers, response_body = split_message(response_raw)
        match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", status_line)
        if status is None and match:
            status = int(match.group(1))
        response_text = decode_body(response_body, response_headers, notes, "response")
    return Transaction(
        index=index,
        source=str(source),
        method=method.upper(),
        url=url,
        request_headers=request_headers,
        request_body=decode_body(request_body, request_headers, notes, "request"),
        status=status,
        response_headers=response_headers,
        response_body=response_text,
        started=started,
        duration_ms=duration_ms,
        notes=notes,
    )


def is_http_url(url: str) -> bool:
    """True for absolute http(s) URLs with a host."""
    parts = urlsplit(url)
    return parts.scheme.lower() in ("http", "https") and bool(parts.hostname)
