"""Burp Suite XML export ("Save items" from Proxy > HTTP history, Target or Logger).

Burp's export starts with a DOCTYPE that declares its elements. reqlens removes the whole
DOCTYPE before parsing, so no entity or external reference in a capture file can ever be
expanded or fetched. Items are parsed in streaming mode.
"""

from __future__ import annotations

import base64
import binascii
import io
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from reqlens.errors import InputError
from reqlens.loaders.base import LoadResult, read_capture_text
from reqlens.loaders.http import build_transaction, is_http_url

_DOCTYPE = re.compile(r"<!DOCTYPE\b[^\[>]*(?:\[.*?\]\s*)?>", re.DOTALL | re.IGNORECASE)


def looks_like_burp(head: str) -> bool:
    """Cheap sniff: XML whose root is <items burpVersion=...>."""
    return head.lstrip().startswith("<") and "burpVersion" in head and "<items" in head


def strip_doctype(text: str) -> str:
    """Remove the document's DOCTYPE (and its internal subset) so nothing can be expanded.

    Only the prologue (text before the root element) is touched: a DOCTYPE inside a captured
    request's CDATA is evidence and must stay as it was.
    """
    root = re.search(r"<items\b", text)
    if root is None:
        return text
    return _DOCTYPE.sub("", text[: root.start()]) + text[root.start() :]


def _payload(element: ET.Element | None) -> bytes:
    """Bytes of a <request>/<response> element (base64 or plain)."""
    if element is None or not (element.text or "").strip():
        return b""
    text = element.text or ""
    if element.get("base64", "false").lower() == "true":
        try:
            return base64.b64decode(text, validate=False)
        except (binascii.Error, ValueError):
            return b""
    return text.encode("utf-8", errors="replace")


def _text(item: ET.Element, tag: str) -> str:
    child = item.find(tag)
    return (child.text or "").strip() if child is not None else ""


def load(path: Path, start_index: int = 0) -> LoadResult:
    """Read a Burp XML export into transactions numbered from ``start_index``."""
    # Without a DOCTYPE, any entity declaration is a parse error, and text such as an XXE
    # payload inside a captured request's CDATA stays inert text.
    text = strip_doctype(read_capture_text(path))
    result = LoadResult(files=[str(path)])
    position = 0
    try:
        for _event, item in ET.iterparse(io.BytesIO(text.encode("utf-8")), events=("end",)):
            if item.tag != "item":
                continue
            position += 1
            try:
                tx = _item_to_transaction(item, path, start_index + len(result.transactions))
            except (ValueError, TypeError):
                tx = None
                result.warnings.append(f"{path.name}: item {position} skipped (malformed)")
            if tx is not None:
                result.transactions.append(tx)
            item.clear()
    except ET.ParseError as exc:
        raise InputError(f"{path} is not well-formed Burp XML: {exc}") from exc
    return result


def _item_to_transaction(item: ET.Element, path: Path, index: int):
    url = _text(item, "url")
    if not is_http_url(url):
        return None
    request_raw = _payload(item.find("request"))
    response_raw = _payload(item.find("response"))
    status_text = _text(item, "status")
    status = int(status_text) if status_text.isdigit() and int(status_text) > 0 else None
    return build_transaction(
        index=index,
        source=path,
        method=_text(item, "method") or "GET",
        url=url,
        request_raw=request_raw,
        response_raw=response_raw or None,
        status=status,
        started=_text(item, "time") or None,
    )
