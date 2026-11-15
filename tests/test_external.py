"""Optional external tools: graceful absence, and that tools only ever see redacted shapes."""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

import capture_factory as cf
import fake_tools
import pytest

from reqlens.cli import main
from reqlens.external import detect_tools, minimal_env, run_sandboxed
from reqlens.external import hashcat as hashcat_mod
from reqlens.external import jwt_tool as jwt_mod
from reqlens.redact import Redactor

BCRYPT = "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"
JKU_JWT = cf.make_jwt(
    {"alg": "RS256", "typ": "JWT", "kid": "k1", "jku": "https://keys.app.test/jwks.json"},
    {
        "sub": cf.USER_SUB,
        "email": cf.OWNER_EMAIL,
        "role": "user",
        "exp": 1893456000,
        "iat": 1700000000,
    },
    cf.SIGNATURE_BYTES,
)
ALL_SECRETS = cf.SECRETS + [BCRYPT, JKU_JWT, JKU_JWT.split(".")[2], "keys.app.test"]


@pytest.fixture
def fakes(tmp_path, monkeypatch):
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    hashcat, jwt_tool = fake_tools.install(tools_dir)
    monkeypatch.setenv("REQLENS_HASHCAT", str(hashcat))
    monkeypatch.setenv("REQLENS_JWT_TOOL", str(jwt_tool))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-should-never-reach-a-tool")
    return hashcat, jwt_tool


@pytest.fixture
def no_tools(monkeypatch):
    monkeypatch.delenv("REQLENS_HASHCAT", raising=False)
    monkeypatch.delenv("REQLENS_JWT_TOOL", raising=False)
    monkeypatch.setattr("shutil.which", lambda name: None)


@pytest.fixture
def spy_runs(monkeypatch):
    """Record every argv reqlens passes to subprocess.run."""
    calls: list[list[str]] = []
    real_run = subprocess.run

    def spy(argv, *args, **kwargs):
        calls.append(list(argv))
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr("reqlens.external.subprocess.run", spy)
    return calls


def capture_with_jwt_and_hash(directory: Path) -> Path:
    har = cf.build_har()
    har["log"]["entries"].append(
        cf._entry(
            "GET",
            "https://app.test/api/admin/users/9",
            [("Authorization", f"Bearer {JKU_JWT}")],
            response_body=json.dumps({"id": 9, "password_hash": BCRYPT}),
        )
    )
    path = directory / "capture.har"
    path.write_text(json.dumps(har), encoding="utf-8")
    return path


# --- absent / disabled ---------------------------------------------------------------------


def test_missing_tools_degrade_gracefully(tmp_path, capsys, no_tools):
    capture = cf.write_har(tmp_path)
    assert (
        main(
            [
                str(capture),
                "--scope",
                "app.test",
                "--report-format",
                "json",
                "-o",
                str(tmp_path / "r"),
            ]
        )
        == 0
    )
    err = capsys.readouterr().err
    assert "optional tool jwt_tool: not found; continuing without it" in err
    assert "optional tool hashcat: not found; continuing without it" in err
    report = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert report["summary"]["external_tools"] == {"jwt_tool": "not found", "hashcat": "not found"}


def test_no_external_never_starts_a_process(tmp_path, capsys, fakes, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("a process was started despite --no-external")

    monkeypatch.setattr("reqlens.external.subprocess.run", forbidden)
    capture = capture_with_jwt_and_hash(tmp_path)
    assert (
        main(
            [
                str(capture),
                "--scope",
                "app.test",
                "--no-external",
                "--report-format",
                "json",
                "-o",
                str(tmp_path / "r"),
            ]
        )
        == 0
    )
    report = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert set(report["summary"]["external_tools"].values()) == {"disabled (--no-external)"}
    assert "optional tool" not in capsys.readouterr().err


# --- with (fake) tools ---------------------------------------------------------------------


def test_tools_add_findings_from_redacted_shapes_only(tmp_path, capsys, fakes, spy_runs):
    hashcat_path, jwt_path = fakes
    capture = capture_with_jwt_and_hash(tmp_path)
    assert (
        main(
            [
                str(capture),
                "--scope",
                "app.test",
                "--report-format",
                "json",
                "-o",
                str(tmp_path / "r"),
            ]
        )
        == 0
    )
    report = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
    assert report["summary"]["external_tools"] == {"jwt_tool": "2.2.7", "hashcat": "v6.2.6"}

    external = {f["check_id"]: f for f in report["findings"] if f["source"] == "external"}
    assert "This agrees with reqlens (alg RS256)" in external["EXT-JWT-TOOL"]["observed"]
    assert "3200 bcrypt" in external["EXT-HASHCAT-IDENTIFY"]["observed"]

    hash_runs = [r for r in fake_tools.read_log(hashcat_path) if "sample" in r]
    assert hash_runs and all(
        r["sample"].strip() == hashcat_mod.sample_for_format("bcrypt") for r in hash_runs
    )
    assert all(r["listing"] == ["sample.hash"] for r in hash_runs)

    jwt_runs = [r for r in fake_tools.read_log(jwt_path) if r["argv"] != ["-h"]]
    assert jwt_runs
    for run in jwt_runs:
        token = run["argv"][0]
        header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
        assert header["alg"] == "RS256"
        assert "jku" not in header or header["jku"] == jwt_mod.NEUTRAL_URL
        assert token.split(".")[2] in (jwt_mod.DUMMY_SIGNATURE, "")
        assert run["listing"] == []

    for run in fake_tools.read_log(hashcat_path) + fake_tools.read_log(jwt_path):
        logged = json.dumps(run)
        for secret in ALL_SECRETS:
            assert secret not in logged
        assert "ANTHROPIC_API_KEY" not in run["env"]
        assert not any(name.startswith("REQLENS_") for name in run["env"])
        assert not Path(run["cwd"]).exists(), "sandbox directory must be removed"
        assert Path(run["cwd"]).name.startswith("reqlens-tool-")

    for argv in spy_runs:
        joined = " ".join(argv)
        assert "eyJ" not in joined, "a token must never appear on a command line"
        for secret in ALL_SECRETS:
            assert secret not in joined


def test_check_hashes_with_hashcat(capsys, fakes):
    assert main(["--check-hashes", BCRYPT, "d41d8cd98f00b204e9800998ecf8427e", "xyz!"]) == 0
    out = capsys.readouterr().out
    assert "Optional tool hashcat (--identify on a synthetic sample of each shape)" in out
    assert "3200 bcrypt" in out and "900 MD4" in out
    assert "shape text:4: no sample for this shape; skipped" in out
    hashcat_path, _ = fakes
    for run in fake_tools.read_log(hashcat_path):
        assert BCRYPT not in json.dumps(run)


def test_check_jwt_with_jwt_tool(capsys, fakes):
    assert main(["--check-jwt", JKU_JWT]) == 0
    out = capsys.readouterr().out
    assert "Optional tool jwt_tool (decode only, redacted token)" in out
    assert "This agrees with reqlens (alg RS256)" in out
    assert "\x1b" not in out
    for secret in (JKU_JWT, JKU_JWT.split(".")[2], cf.OWNER_EMAIL):
        assert secret not in out


# --- units ---------------------------------------------------------------------------------


def test_samples_have_the_right_shape():
    assert len(hashcat_mod.sample_for_format("hex:32")) == 32
    assert hashcat_mod.sample_for_format("bcrypt").startswith("$2b$12$")
    assert len(hashcat_mod.sample_for_format("bcrypt")) == 60
    assert hashcat_mod.sample_for_format("text:9") is None
    assert hashcat_mod.sample_for_format("hex:4") is None


def test_parse_identify_table():
    output = (
        "The following 2 hash-modes match the structure of your input hash:\n\n"
        "      # | Name                | Category\n"
        "  ======+=====================+=========\n"
        "    900 | MD4                 | Raw Hash\n"
        "      0 | MD5                 | Raw Hash\n"
    )
    modes = hashcat_mod.parse_identify(output)
    assert [(m.mode, m.name) for m in modes] == [(900, "MD4"), (0, "MD5")]


def test_parse_decode_and_first_run_problem():
    good = jwt_mod.parse_decode(
        'Token header values:\n[+] alg = "HS256"\n[+] typ = "JWT"\n'
        "Token payload values:\n[+] sub = x\n[-] TOKEN IS EXPIRED!\n"
    )
    assert good.header == {"alg": "HS256", "typ": "JWT"}
    assert good.notes == ["[-] TOKEN IS EXPIRED!"]
    assert jwt_mod.parse_decode("Config file created.").problem


def test_rebuild_token_neutralises_key_urls_and_signature():
    record = Redactor().describe_jwt(JKU_JWT)
    token = jwt_mod.rebuild_token(record)
    header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
    claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
    assert header["jku"] == jwt_mod.NEUTRAL_URL and header["alg"] == "RS256"
    assert claims["role"] == "user" and claims["sub"].startswith("<redacted:")
    assert token.split(".")[2] == jwt_mod.DUMMY_SIGNATURE
    for secret in ALL_SECRETS:
        assert secret not in token


def test_jwt_tool_must_be_the_python_script(tmp_path, monkeypatch):
    binary = tmp_path / "jwt_tool.exe"
    binary.write_text("not really", encoding="utf-8")
    monkeypatch.setenv("REQLENS_JWT_TOOL", str(binary))
    status = jwt_mod.detect()
    assert not status.available and "jwt_tool.py" in status.detail


def test_minimal_env_drops_secrets(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-x")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "y")
    env = minimal_env(str(tmp_path))
    assert "OPENAI_API_KEY" not in env and "AWS_SECRET_ACCESS_KEY" not in env
    assert env["TEMP"] == str(tmp_path) and env["NO_COLOR"] == "1"


def test_run_sandboxed_timeout_and_cleanup():
    result = run_sandboxed([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.5)
    assert result.timed_out


def test_run_sandboxed_reports_missing_executable(tmp_path):
    result = run_sandboxed([str(tmp_path / "does-not-exist.exe")], timeout=5)
    assert result.returncode is None and "could not start" in result.stderr


def test_detect_tools_disabled_does_nothing():
    statuses = detect_tools(enabled=False)
    assert all(not s.available for s in statuses.values())
