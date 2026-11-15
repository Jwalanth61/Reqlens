"""HAR 1.2 loader (browser DevTools, Burp, ZAP, mitmproxy and Charles can all export HAR)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

from reqlens.errors import InputError
from reqlens.loaders.base import LoadResult, decode_body, limit_body, read_capture_text
from reqlens.model import Header, Transaction, header_values


def looks_like_har(head: str) -> bool:
    """Cheap sniff on the first few KB of a file."""
    stripped = head.lstrip()
    return stripped.startswith("{") and '"log"' in stripped and '"entries"' in stripped


def load(path: Path, start_index: int = 0) -> LoadResult:
    """Read a HAR file into transactions numbered from ``start_index``."""
    text = read_capture_text(path)
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise InputError(f"{path} is not valid JSON (HAR files are JSON): {exc}") from exc
    entries = _entries(data)
    if entries is None:
        raise InputError(f"{path} is JSON but has no log.entries array; is it a HAR file?")

    result = LoadResult(files=[str(path)])
    skipped_scheme = 0
    for position, entry in enumerate(entries):
        try:
            tx = _entry_to_transaction(entry, path, start_index + len(result.transactions))
        except (KeyError, TypeError, ValueError, AttributeError):
            result.warnings.append(f"{path.name}: entry {position} skipped (malformed)")
            continue
        if tx is None:
            skipped_scheme += 1
            continue
        result.transactions.append(tx)
    if skipped_scheme:
        result.warnings.append(
            f"{path.name}: {skipped_scheme} non-HTTP entries skipped (data:, blob:, extensions)"
        )
    return result


def _entries(data: Any) -> list | None:
    """Return ``log.entries`` if present and a list."""
    if not isinstance(data, dict):
        return None
    log = data.get("log")
    if not isinstance(log, dict):
        return None
    entries = log.get("entries")
    return entries if isinstance(entries, list) else None


def _entry_to_transaction(entry: dict, path: Path, index: int) -> Transaction | None:
    """Convert one HAR entry; ``None`` for non-HTTP(S) URLs."""
    request = entry["request"]
    url = str(request["url"])
    if not url.lower().startswith(("http://", "https://")):
        return None
    response = entry.get("response") or {}

    request_headers = _headers(request.get("headers"))
    response_headers = _headers(response.get("headers"))
    _synthesise_cookie_headers(request, response, request_headers, response_headers)

    notes: list[str] = []
    request_body = _request_body(request.get("postData"), notes)
    content = response.get("content") or {}
    response_body, body_notes = decode_body(
        content.get("text"), content.get("encoding"), str(content.get("mimeType") or "")
    )
    notes.extend(f"response {note}" for note in body_notes)

    status = response.get("status")
    status = int(status) if isinstance(status, (int, float)) and status > 0 else None
    duration = entry.get("time")
    return Transaction(
        index=index,
        source=str(path),
        method=str(request.get("method") or "GET").upper(),
        url=url,
        request_headers=request_headers,
        request_body=request_body,
        status=status,
        response_headers=response_headers,
        response_body=response_body,
        started=entry.get("startedDateTime"),
        duration_ms=float(duration) if isinstance(duration, (int, float)) else None,
        notes=notes,
    )


def _headers(raw: Any) -> list[Header]:
    """Normalise a HAR header list, dropping HTTP/2 pseudo-headers (``:authority`` etc.)."""
    headers: list[Header] = []
    for item in raw or []:
        name = str(item.get("name", ""))
        if not name or name.startswith(":"):
            continue
        headers.append((name, str(item.get("value", ""))))
    return headers


def _synthesise_cookie_headers(
    request: dict,
    response: dict,
    request_headers: list[Header],
    response_headers: list[Header],
) -> None:
    """Some exporters strip Cookie/Set-Cookie headers but keep the ``cookies`` arrays.

    Rebuild the headers from those arrays so cookie checks and redaction see them.
    """
    cookies = request.get("cookies") or []
    if cookies and not header_values(request_headers, "cookie"):
        pairs = "; ".join(f"{c.get('name', '')}={c.get('value', '')}" for c in cookies)
        request_headers.append(("Cookie", pairs))

    cookies = response.get("cookies") or []
    if cookies and not header_values(response_headers, "set-cookie"):
        for cookie in cookies:
            response_headers.append(("Set-Cookie", _set_cookie_from_har(cookie)))


def _set_cookie_from_har(cookie: dict) -> str:
    """Build a Set-Cookie header value from a HAR cookie object."""
    parts = [f"{cookie.get('name', '')}={cookie.get('value', '')}"]
    for key, label in (("path", "Path"), ("domain", "Domain"), ("expires", "Expires")):
        if cookie.get(key):
            parts.append(f"{label}={cookie[key]}")
    if cookie.get("httpOnly"):
        parts.append("HttpOnly")
    if cookie.get("secure"):
        parts.append("Secure")
    if cookie.get("sameSite"):
        parts.append(f"SameSite={cookie['sameSite']}")
    return "; ".join(parts)


def _request_body(post_data: Any, notes: list[str]) -> str:
    """Request body text, rebuilt from ``params`` when ``text`` is absent."""
    if not isinstance(post_data, dict):
        return ""
    text = post_data.get("text")
    if text:
        return limit_body(str(text), notes)
    params = post_data.get("params") or []
    if params:
        return "&".join(
            f"{quote(str(p.get('name', '')))}={quote(str(p.get('value', '')))}" for p in params
        )
    return ""
