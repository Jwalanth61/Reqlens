from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from reqlens.cli import build_parser, main, options_from_args, parse_report_formats, parse_scope
from reqlens.errors import UsageError

ROOT = Path(__file__).resolve().parent.parent


def test_scope_is_required():
    with pytest.raises(UsageError, match="scope is required"):
        parse_scope(None, None)


def test_scope_flag_and_file_merge(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("# authorized\nAPI.app.test\napp.test  # dup\n\n", encoding="utf-8")
    assert parse_scope("app.test, *.cdn.app.test", str(scope_file)) == [
        "app.test",
        "*.cdn.app.test",
        "api.app.test",
    ]


def test_missing_scope_file_is_usage_error(tmp_path):
    with pytest.raises(UsageError, match="cannot read scope file"):
        parse_scope(None, str(tmp_path / "nope.txt"))


def test_report_formats_ordered_and_validated():
    assert parse_report_formats("json, MD") == ["md", "json"]
    with pytest.raises(UsageError, match="pdf"):
        parse_report_formats("md,pdf")
    with pytest.raises(UsageError):
        parse_report_formats(" , ")


def test_options_defaults():
    args = build_parser().parse_args(["cap.har", "--scope", "app.test"])
    opts = options_from_args(args)
    assert opts.report_formats == ["md"]
    assert opts.output == "reqlens-report"
    assert opts.use_external_tools is True
    assert opts.input_format is None


def test_input_format_choices():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["cap.har", "--input-format", "pcap"])


def test_main_without_scope_exits_2(capsys):
    assert main(["cap.har"]) == 2
    assert "scope is required" in capsys.readouterr().err


def test_pyproject_version_matches_package():
    from reqlens import __version__

    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert f'version = "{__version__}"' in text


@pytest.mark.parametrize(
    "command",
    [
        [sys.executable, "reqlens.py", "--version"],
        [sys.executable, "-m", "reqlens", "--version"],
    ],
)
def test_entry_points_report_version(command):
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0
    assert result.stdout.startswith("reqlens ")
