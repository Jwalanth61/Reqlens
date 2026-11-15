"""Convert the synthetic HAR capture into Burp XML, mitmproxy flows and a ZAP export, so every
loader can be checked against the same traffic (and the same planted secrets).

Some responses are deliberately gzip-compressed or chunked, as real proxies record them.
"""

from __future__ import annotations

import base64
import gzip
from pathlib import Path
from urllib.parse import urlsplit

import capture_factory as cf

CRLF = b"\r\n"


def entries() -> list[dict]:
    """HAR entries that any format can represent (http/https only)."""
    return [
        e
        for e in cf.build_har()["log"]["entries"]
        if e["request"]["url"].startswith(("http://", "https://"))
    ]


def _headers(items: list[dict]) -> list[tuple[str, str]]:
    return [(h["name"], h["value"]) for h in items if not h["name"].startswith(":")]


def _response_body(entry: dict) -> bytes:
    content = entry["response"]["content"]
    text = content.get("text") or ""
    if content.get("encoding") == "base64":
        return base64.b64decode(text)
    return text.encode("utf-8")


def _request_body(entry: dict) -> bytes:
    post = entry["request"].get("postData") or {}
    return (post.get("text") or "").encode("utf-8")


def _chunked(body: bytes) -> bytes:
    half = len(body) // 2
    parts = [body[:half], body[half:]]
    return (
        b"".join(f"{len(p):x}".encode() + CRLF + p + CRLF for p in parts if p) + b"0" + CRLF + CRLF
    )


def raw_request(entry: dict, absolute: bool = False) -> bytes:
    url = entry["request"]["url"]
    parts = urlsplit(url)
    target = url if absolute else (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    headers = [("Host", parts.netloc)] + _headers(entry["request"]["headers"])
    body = _request_body(entry)
    if body:
        headers.append(("Content-Length", str(len(body))))
    lines = [f"{entry['request']['method']} {target} HTTP/1.1"] + [f"{n}: {v}" for n, v in headers]
    return "\r\n".join(lines).encode("utf-8") + CRLF + CRLF + body


def raw_response(entry: dict, position: int) -> tuple[bytes, list[tuple[str, str]], bytes]:
    """(raw message, headers, wire body). Entry 1 is gzipped, entry 2 chunked."""
    body = _response_body(entry)
    headers = _headers(entry["response"]["headers"])
    wire = body
    if position == 1 and body:
        wire = gzip.compress(body)
        headers += [("Content-Encoding", "gzip"), ("Content-Length", str(len(wire)))]
    elif position == 2 and body:
        wire = _chunked(body)
        headers.append(("Transfer-Encoding", "chunked"))
    else:
        headers.append(("Content-Length", str(len(wire))))
    lines = [f"HTTP/1.1 {entry['response']['status']} OK"] + [f"{n}: {v}" for n, v in headers]
    return "\r\n".join(lines).encode("utf-8") + CRLF + CRLF + wire, headers, wire


# --- Burp ----------------------------------------------------------------------------------

BURP_DOCTYPE = """<!DOCTYPE items [
<!ELEMENT items (item*)>
<!ATTLIST items burpVersion CDATA "">
<!ATTLIST items exportTime CDATA "">
<!ELEMENT item (time, url, host, port, protocol, method, path, extension, request, status,
  responselength, mimetype, response, comment)>
<!ATTLIST request base64 (true|false) "false">
<!ATTLIST response base64 (true|false) "false">
]>"""


def to_burp(directory: Path) -> Path:
    items = []
    for position, entry in enumerate(entries()):
        url = entry["request"]["url"]
        parts = urlsplit(url)
        response, _, _ = raw_response(entry, position)
        items.append(
            "<item>"
            "<time>Sun Nov 15 10:00:00 UTC 2026</time>"
            f"<url><![CDATA[{url}]]></url>"
            f'<host ip="10.0.0.1">{parts.hostname}</host><port>443</port>'
            f"<protocol>{parts.scheme}</protocol>"
            f"<method><![CDATA[{entry['request']['method']}]]></method>"
            f"<path><![CDATA[{parts.path}]]></path><extension>null</extension>"
            f'<request base64="true"><![CDATA[{base64.b64encode(raw_request(entry)).decode()}]]>'
            "</request>"
            f"<status>{entry['response']['status']}</status>"
            f"<responselength>{len(response)}</responselength><mimetype>JSON</mimetype>"
            f'<response base64="true"><![CDATA[{base64.b64encode(response).decode()}]]>'
            "</response><comment></comment></item>"
        )
    xml = (
        '<?xml version="1.0"?>\n' + BURP_DOCTYPE + "\n"
        '<items burpVersion="2024.10.1" exportTime="Sun Nov 15 10:00:00 UTC 2026">\n'
        + "\n".join(items)
        + "\n</items>\n"
    )
    path = directory / "burp-items.xml"
    path.write_text(xml, encoding="utf-8")
    return path


# --- mitmproxy -----------------------------------------------------------------------------


def tnet(value) -> bytes:
    """Minimal tnetstring encoder (test helper)."""
    if value is None:
        payload, tag = b"", b"~"
    elif isinstance(value, bool):
        payload, tag = (b"true" if value else b"false"), b"!"
    elif isinstance(value, int):
        payload, tag = str(value).encode(), b"#"
    elif isinstance(value, float):
        payload, tag = repr(value).encode(), b"^"
    elif isinstance(value, bytes):
        payload, tag = value, b","
    elif isinstance(value, str):
        payload, tag = value.encode("utf-8"), b";"
    elif isinstance(value, (list, tuple)):
        payload, tag = b"".join(tnet(v) for v in value), b"]"
    elif isinstance(value, dict):
        payload, tag = b"".join(tnet(k) + tnet(v) for k, v in value.items()), b"}"
    else:
        raise TypeError(type(value))
    return str(len(payload)).encode() + b":" + payload + tag


def to_mitmproxy(directory: Path) -> Path:
    flows = [tnet({"version": 19, "type": "tcp", "id": "tcp-1", "messages": []})]
    for position, entry in enumerate(entries()):
        parts = urlsplit(entry["request"]["url"])
        _, response_headers, wire = raw_response(entry, position)
        request_headers = [("Host", parts.netloc)] + _headers(entry["request"]["headers"])
        flows.append(
            tnet(
                {
                    "version": 19,
                    "type": "http",
                    "id": f"flow-{position}",
                    "request": {
                        "host": parts.hostname,
                        "port": 443,
                        "method": entry["request"]["method"].encode(),
                        "scheme": parts.scheme.encode(),
                        "authority": b"",
                        "path": (
                            (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
                        ).encode(),
                        "http_version": b"HTTP/1.1",
                        "headers": [[n.encode(), v.encode()] for n, v in request_headers],
                        "content": _request_body(entry),
                        "timestamp_start": 1700000000.0,
                        "timestamp_end": 1700000000.01,
                    },
                    "response": {
                        "http_version": b"HTTP/1.1",
                        "status_code": entry["response"]["status"],
                        "reason": b"OK",
                        "headers": [[n.encode(), v.encode()] for n, v in response_headers],
                        "content": wire,
                        "timestamp_start": 1700000000.02,
                        "timestamp_end": 1700000000.05,
                    },
                }
            )
        )
    path = directory / "session.flow"
    path.write_bytes(b"".join(flows))
    return path


# --- ZAP -----------------------------------------------------------------------------------


def to_zap(directory: Path) -> Path:
    blocks = []
    for position, entry in enumerate(entries(), 1):
        response, _, _ = raw_response(entry, position - 1)
        blocks.append(
            f"==== {position} ==========\n".encode()
            + raw_request(entry, absolute=True)
            + b"\n"
            + response
            + b"\n"
        )
    path = directory / "zap-export.txt"
    path.write_bytes(b"".join(blocks))
    return path


CONVERTERS = {"burp": to_burp, "mitmproxy": to_mitmproxy, "zap": to_zap}
