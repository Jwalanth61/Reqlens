"""Burp, mitmproxy and ZAP loaders: same traffic as the HAR capture, same results."""

from __future__ import annotations

import gzip
import json
import zlib

import capture_factory as cf
import capture_formats as fmt
import pytest

from reqlens import config
from reqlens.cli import main
from reqlens.errors import InputError
from reqlens.loaders import detect_format, load_captures
from reqlens.loaders import mitmproxy as mitm
from reqlens.loaders.http import dechunk, decode_body, split_message

FORMATS = ["burp", "mitmproxy", "zap"]


def har_transactions(tmp_path):
    return load_captures([str(cf.write_har(tmp_path))]).transactions


@pytest.mark.parametrize("name", FORMATS)
def test_format_is_detected(tmp_path, name):
    path = fmt.CONVERTERS[name](tmp_path)
    assert detect_format(path) == name


@pytest.mark.parametrize("name", FORMATS)
def test_loader_matches_har(tmp_path, name):
    expected = har_transactions(tmp_path)
    loaded = load_captures([str(fmt.CONVERTERS[name](tmp_path))])
    got = loaded.transactions
    assert len(got) == len(expected)
    for want, have in zip(expected, got):
        assert have.method == want.method
        assert have.url == want.url
        assert have.status == want.status
        assert have.request_body == want.request_body
        assert have.response_body == want.response_body, have.url
        names = {n.lower() for n, _ in have.request_headers}
        assert {n.lower() for n, _ in want.request_headers} <= names
        assert have.response_headers and have.request_headers


@pytest.mark.parametrize("name", FORMATS)
def test_pipeline_gives_same_findings_without_secrets(tmp_path, name):
    har_dir, other_dir = tmp_path / "har", tmp_path / "other"
    har_dir.mkdir()
    other_dir.mkdir()
    reports = {}
    for label, capture, directory in (
        ("har", cf.write_har(har_dir), har_dir),
        (name, fmt.CONVERTERS[name](other_dir), other_dir),
    ):
        assert (
            main(
                [
                    str(capture),
                    "--scope",
                    "app.test,api.app.test",
                    "--report-format",
                    "json",
                    "-o",
                    str(directory / "r"),
                ]
            )
            == 0
        )
        reports[label] = (directory / "r.json").read_text(encoding="utf-8")
    ids = {k: sorted(f["title"] for f in json.loads(v)["findings"]) for k, v in reports.items()}
    assert ids[name] == ids["har"]
    for secret in cf.SECRETS:
        assert secret not in reports[name]


def test_mixed_formats_merge_with_unique_indices(tmp_path):
    paths = [str(cf.write_har(tmp_path))] + [str(fmt.CONVERTERS[n](tmp_path)) for n in FORMATS]
    loaded = load_captures(paths)
    assert [tx.index for tx in loaded.transactions] == list(range(len(loaded.transactions)))
    assert len(loaded.files) == 4


# --- Burp safety and details ---------------------------------------------------------------


def _burp(tmp_path, body: str, doctype: str = "") -> str:
    path = tmp_path / "b.xml"
    text = '<?xml version="1.0"?>' + doctype + '<items burpVersion="1">' + body + "</items>"
    path.write_bytes(text.encode("utf-8"))
    return str(path)


def test_burp_external_entity_is_never_resolved(tmp_path):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("TOP-SECRET-FILE-CONTENT", encoding="utf-8")
    doctype = f'<!DOCTYPE items [<!ENTITY xxe SYSTEM "{secret_file.as_uri()}">]>'
    item = "<item><url>https://app.test/</url><method>GET</method><comment>&xxe;</comment></item>"
    with pytest.raises(InputError, match="not well-formed"):
        load_captures([_burp(tmp_path, item, doctype)])


def test_burp_billion_laughs_is_not_expanded(tmp_path):
    doctype = (
        '<!DOCTYPE items [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;">'
        '<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;">]>'
    )
    item = "<item><url>https://app.test/</url><method>GET</method><comment>&c;</comment></item>"
    with pytest.raises(InputError):
        load_captures([_burp(tmp_path, item, doctype)])


def test_burp_xxe_payload_inside_a_request_is_just_text(tmp_path):
    request = (
        "POST /x HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/xml\r\n\r\n"
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]><r>&e;</r>'
    )
    item = (
        f"<item><url>https://app.test/x</url><method>POST</method>"
        f'<request base64="false"><![CDATA[{request}]]></request><status>400</status></item>'
    )
    tx = load_captures([_burp(tmp_path, item)]).transactions[0]
    assert "<!ENTITY e SYSTEM" in tx.request_body
    assert tx.status == 400 and tx.response_body == ""


def test_burp_skips_non_http_and_malformed_items(tmp_path):
    items = (
        "<item><url>ws://app.test/socket</url><method>GET</method></item>"
        "<item><url>https://app.test/ok</url><method>GET</method></item>"
    )
    loaded = load_captures([_burp(tmp_path, items)])
    assert [tx.url for tx in loaded.transactions] == ["https://app.test/ok"]


# --- mitmproxy details ---------------------------------------------------------------------


def test_tnetstring_round_trip():
    value = {"a": [1, 2.5, True, None, b"x", "y"], "nested": {"k": b"v"}}
    parsed, end = mitm.parse_tnetstring(fmt.tnet(value))
    assert parsed == {"a": [1, 2.5, True, None, b"x", "y"], "nested": {"k": b"v"}}
    assert end == len(fmt.tnet(value))


def test_tnetstring_rejects_deep_nesting_and_bad_data():
    deep = b"0:]"
    for _ in range(mitm.MAX_DEPTH + 5):
        deep = str(len(deep)).encode() + b":" + deep + b"]"
    with pytest.raises(mitm.TNetStringError, match="too deep"):
        mitm.parse_tnetstring(deep)
    with pytest.raises(mitm.TNetStringError):
        mitm.parse_tnetstring(b"99:short,")
    with pytest.raises(mitm.TNetStringError):
        mitm.parse_tnetstring(b"3:abc?")


def test_mitmproxy_truncated_file_keeps_earlier_flows(tmp_path):
    good = fmt.to_mitmproxy(tmp_path).read_bytes()
    path = tmp_path / "cut.flow"
    path.write_bytes(good + b"500:{truncated")
    loaded = load_captures([str(path)], "mitmproxy")
    assert len(loaded.transactions) == len(fmt.entries())
    assert any("stopped at flow" in w for w in loaded.warnings)
    assert any("1 non-HTTP flows skipped" in w for w in loaded.warnings)


def test_mitmproxy_garbage_is_an_input_error(tmp_path):
    path = tmp_path / "junk.flow"
    path.write_bytes(b"12:not a flow")
    with pytest.raises(InputError, match="not a mitmproxy flow file"):
        load_captures([str(path)], "mitmproxy")


# --- ZAP details ---------------------------------------------------------------------------


def test_zap_without_content_length_and_origin_form(tmp_path):
    text = (
        b"==== 1 ==========\n"
        b"POST /api/notes HTTP/1.1\r\nHost: app.test\r\nContent-Type: text/plain\r\n\r\n"
        b"hello there\n"
        b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n"
        b'{"id": 5}\n\n'
        b"==== 2 ==========\n"
        b"GET https://app.test/b HTTP/1.1\r\nHost: app.test\r\n\r\n\n"
    )
    path = tmp_path / "z.txt"
    path.write_bytes(text)
    first, second = load_captures([str(path)]).transactions
    assert first.url == "https://app.test/api/notes" and first.request_body == "hello there"
    assert first.status == 201 and first.response_body == '{"id": 5}'
    assert any("https assumed" in note for note in first.notes)
    assert second.url == "https://app.test/b" and second.status is None


# --- body decoding -------------------------------------------------------------------------


def test_split_message_and_folding():
    start, headers, body = split_message(
        b"HTTP/1.1 200 OK\r\nX-A: 1\r\n  continued\r\n:pseudo: x\r\n\r\nbody"
    )
    assert start == "HTTP/1.1 200 OK"
    assert headers == [("X-A", "1 continued")]
    assert body == b"body"


def test_dechunk():
    assert dechunk(b"4\r\nWiki\r\n5;ext=1\r\npedia\r\n0\r\n\r\n") == b"Wikipedia"
    assert dechunk(b"zz\r\nbad") is None


def test_decode_body_variants():
    notes: list[str] = []
    gz = gzip.compress(b'{"a": 1}')
    assert decode_body(gz, [("Content-Encoding", "gzip")], notes, "response") == '{"a": 1}'
    deflated = zlib.compress(b"plain")
    assert decode_body(deflated, [("Content-Encoding", "deflate")], notes, "response") == "plain"
    assert "not analysed" in decode_body(b"xx", [("Content-Encoding", "br")], notes, "response")
    latin = "café".encode("latin-1")
    assert (
        decode_body(latin, [("Content-Type", "text/plain; charset=latin-1")], notes, "r") == "café"
    )
    assert decode_body(b"\x89PNG\x00", [("Content-Type", "image/png")], notes, "r").startswith(
        "[binary body"
    )


def test_gzip_bomb_is_bounded(monkeypatch):
    monkeypatch.setattr(config, "MAX_BODY_CHARS", 1000)
    bomb = gzip.compress(b"A" * 1_000_000)
    notes: list[str] = []
    text = decode_body(bomb, [("Content-Encoding", "gzip")], notes, "response")
    assert len(text) == 1000
    assert any("exceeded" in note for note in notes)
