"""End-to-end CLI runs on a synthetic capture, with every socket blocked (see conftest)."""

from __future__ import annotations

import socket

import capture_factory as cf

from reqlens.cli import main


def test_full_run_with_sockets_blocked(tmp_path, capsys):
    # conftest already blocks sockets; assert that here too so the test can't pass vacuously.
    assert socket.socket.__name__ == "_blocked"
    path = cf.write_har(tmp_path)
    code = main([str(path), "--scope", "app.test,api.app.test"])
    out, err = capsys.readouterr()
    assert code == 0
    assert "loaded 8 transactions from 1 file(s)" in out
    assert "in scope: 6 transactions on api.app.test, app.test" in out
    assert "other.example (1, out of scope)" in out
    assert "www.google-analytics.com (1, third-party noise)" in out
    assert "GET app.test/api/users/{id}  x2  [200,403]" in out
    for secret in cf.SECRETS:
        assert secret not in out and secret not in err


def test_show_redaction_prints_no_secrets(tmp_path, capsys):
    path = cf.write_har(tmp_path)
    for index in range(6):
        assert (
            main([str(path), "--scope", "app.test,api.app.test", "--show-redaction", str(index)])
            == 0
        )
    out = capsys.readouterr().out
    assert "after redaction (strict" in out
    assert "jwt in request header 'Authorization'" in out
    assert "'alg': 'RS256'" in out
    for secret in cf.SECRETS:
        assert secret not in out


def test_show_redaction_refuses_out_of_scope(tmp_path, capsys):
    path = cf.write_har(tmp_path)
    assert main([str(path), "--scope", "app.test", "--show-redaction", "7"]) == 2
    assert "outside the scope" in capsys.readouterr().err
    assert main([str(path), "--scope", "app.test", "--show-redaction", "99"]) == 2


def test_capture_text_cannot_inject_terminal_escapes(tmp_path, capsys):
    import json

    data = cf.build_har()
    data["log"]["entries"][0]["request"]["url"] = "https://app.test/\x1b[2J\x1b]0;pwned\x07x"
    path = tmp_path / "evil.har"
    path.write_text(json.dumps(data), encoding="utf-8")
    assert main([str(path), "--scope", "app.test", "--show-redaction", "0"]) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out


def test_full_run_prints_findings_without_secrets(tmp_path, capsys):
    path = cf.write_har(tmp_path)
    assert main([str(path), "--scope", "app.test,api.app.test"]) == 0
    out = capsys.readouterr().out
    assert "reqlens is a passive analyzer" in out
    assert "== API1:2023 Broken Object Level Authorization ==" in out
    assert "Algorithm confusion (asymmetric -> HS256) worth testing [RS256]" in out
    assert "Secret token carried in the URL ('token' on app.test)" in out
    assert "report written:" in out and "reqlens-report.md" in out
    for secret in cf.SECRETS:
        assert secret not in out
