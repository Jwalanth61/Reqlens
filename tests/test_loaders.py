from __future__ import annotations

import base64
import json
from pathlib import Path

import capture_factory as cf
import pytest

from reqlens import config
from reqlens.errors import FormatDetectionError, InputError
from reqlens.loaders import detect_format, expand_inputs, load_captures


def write(tmp_path, name, data) -> str:
    path = tmp_path / name
    path.write_text(json.dumps(data) if not isinstance(data, str) else data, encoding="utf-8")
    return str(path)


def har(*entries) -> dict:
    return {"log": {"version": "1.2", "entries": list(entries)}}


def entry(url="https://app.test/", **response) -> dict:
    return {
        "startedDateTime": "2026-11-15T10:00:00Z",
        "time": 1,
        "request": {"method": "get", "url": url, "headers": [{"name": ":path", "value": "/"}]},
        "response": {
            "status": 200,
            "headers": [],
            "content": {"mimeType": "text/plain"},
            **response,
        },
    }


def test_load_sample_har(tmp_path):
    result = load_captures([str(cf.write_har(tmp_path))])
    # 9 entries, one data: URL skipped
    assert len(result.transactions) == 8
    assert [tx.index for tx in result.transactions] == list(range(8))
    assert any("non-HTTP" in warning for warning in result.warnings)
    login = result.transactions[0]
    assert login.method == "POST" and login.status == 200
    assert login.duration_ms == 42.5
    assert all(not name.startswith(":") for name, _ in login.request_headers)


def test_base64_text_body_is_decoded(tmp_path):
    body = base64.b64encode(b'{"ok": true}').decode()
    path = write(
        tmp_path,
        "a.har",
        har(entry(content={"mimeType": "application/json", "text": body, "encoding": "base64"})),
    )
    assert load_captures([path]).transactions[0].response_body == '{"ok": true}'


def test_binary_body_becomes_placeholder(tmp_path):
    body = base64.b64encode(b"\x89PNG\r\n\x1a\n\x00\x00").decode()
    path = write(
        tmp_path,
        "a.har",
        har(entry(content={"mimeType": "image/png", "text": body, "encoding": "base64"})),
    )
    assert load_captures([path]).transactions[0].response_body == (
        "[binary body: 10 bytes, image/png]"
    )


def test_cookie_arrays_become_headers(tmp_path):
    item = entry()
    item["request"]["cookies"] = [{"name": "sid", "value": "abc"}]
    item["response"]["cookies"] = [
        {
            "name": "sid",
            "value": "new",
            "path": "/",
            "httpOnly": True,
            "secure": True,
            "sameSite": "Strict",
        }
    ]
    tx = load_captures([write(tmp_path, "a.har", har(item))]).transactions[0]
    assert tx.request_header("Cookie") == "sid=abc"
    assert tx.response_header("Set-Cookie") == "sid=new; Path=/; HttpOnly; Secure; SameSite=Strict"


def test_post_params_without_text(tmp_path):
    item = entry()
    item["request"]["postData"] = {
        "mimeType": "application/x-www-form-urlencoded",
        "params": [{"name": "a b", "value": "1&2"}],
    }
    tx = load_captures([write(tmp_path, "a.har", har(item))]).transactions[0]
    assert tx.request_body == "a%20b=1%262"


def test_malformed_entries_are_skipped_with_warning(tmp_path):
    path = write(tmp_path, "a.har", har({"request": None}, entry()))
    result = load_captures([path])
    assert len(result.transactions) == 1
    assert any("entry 0 skipped" in warning for warning in result.warnings)


def test_status_zero_means_no_response(tmp_path):
    path = write(tmp_path, "a.har", har(entry(status=0)))
    assert load_captures([path]).transactions[0].status is None


def test_large_body_is_truncated(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "MAX_BODY_CHARS", 10)
    path = write(
        tmp_path, "a.har", har(entry(content={"mimeType": "text/plain", "text": "x" * 50}))
    )
    tx = load_captures([path]).transactions[0]
    assert tx.response_body == "x" * 10
    assert any("truncated" in note for note in tx.notes)


def test_file_size_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "MAX_CAPTURE_BYTES", 10)
    path = write(tmp_path, "a.har", har(entry()))
    with pytest.raises(InputError, match="limit"):
        load_captures([path])


def test_invalid_json_and_missing_entries(tmp_path):
    with pytest.raises(InputError, match="not valid JSON"):
        load_captures([write(tmp_path, "a.har", "{not json")], "har")
    with pytest.raises(InputError, match="no log.entries"):
        load_captures([write(tmp_path, "b.har", {"log": {}})], "har")


def test_detect_format(tmp_path):
    assert detect_format(Path(write(tmp_path, "a.json", har(entry())))) == "har"
    burp = write(tmp_path, "b.xml", '<?xml version="1.0"?><items burpVersion="2024.1">')
    assert detect_format(Path(burp)) == "burp"
    with pytest.raises(FormatDetectionError, match="--input-format"):
        detect_format(Path(write(tmp_path, "c.txt", "hello")))


def test_capture_without_transactions_is_an_error(tmp_path):
    burp = write(tmp_path, "b.xml", '<?xml version="1.0"?><items burpVersion="2024.1"></items>')
    with pytest.raises(InputError, match="no HTTP transactions"):
        load_captures([burp])


def test_burp_project_file_gets_a_hint(tmp_path):
    project = tmp_path / "proj.burp"
    project.write_bytes(b"\x00\x01binary project")
    with pytest.raises(FormatDetectionError, match="Save items"):
        load_captures([str(project)])


def test_expand_directory_glob_and_merge(tmp_path):
    (tmp_path / "caps").mkdir()
    write(tmp_path / "caps", "one.har", har(entry("https://app.test/1")))
    write(
        tmp_path / "caps", "two.har", har(entry("https://app.test/2"), entry("https://app.test/3"))
    )
    write(tmp_path / "caps", "notes.txt", "ignore me")
    assert [p.name for p in expand_inputs([str(tmp_path / "caps")])] == ["one.har", "two.har"]
    assert len(expand_inputs([str(tmp_path / "caps" / "*.har")])) == 2
    merged = load_captures([str(tmp_path / "caps")])
    assert [tx.index for tx in merged.transactions] == [0, 1, 2]
    assert [tx.path for tx in merged.transactions] == ["/1", "/2", "/3"]


def test_missing_input(tmp_path):
    with pytest.raises(InputError, match="not found"):
        expand_inputs([str(tmp_path / "nope.har")])
    with pytest.raises(InputError, match="no files match"):
        expand_inputs([str(tmp_path / "*.har")])
