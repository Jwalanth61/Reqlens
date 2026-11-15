"""Report rendering: content, safety of untrusted text, and the files on disk."""

from __future__ import annotations

import json
import re
from pathlib import Path

import capture_factory as cf
import pytest

from reqlens.cli import main
from reqlens.errors import ReportError
from reqlens.knowledge.catalog import make_finding
from reqlens.model import Evidence
from reqlens.report import ReportData, RunSummary, output_base, write_reports
from reqlens.report import html as html_report
from reqlens.report import json as json_report
from reqlens.report import markdown as md_report

EVIL = "<script>alert(1)</script>\x1b[31m|`pipe`|[x](javascript:alert(1))"


def summary(**overrides) -> RunSummary:
    base = dict(
        capture_files=["session.har"],
        scope=["app.test"],
        transactions_loaded=3,
        transactions_in_scope=2,
        hosts=["app.test"],
        endpoints=2,
        generated_at="2026-11-15T00:00:00Z",
    )
    base.update(overrides)
    return RunSummary(**base)


def evil_data() -> ReportData:
    finding = make_finding(
        "DISC-STACKTRACE",
        [Evidence(4, "GET app.test/x", "response body", "trace", EVIL)],
        title="Stack trace " + EVIL,
        observed="seen " + EVIL,
    )
    finding.references.append("javascript:alert(1)")
    return ReportData(summary(hosts=["app.test" + EVIL]), [finding])


# --- full pipeline -------------------------------------------------------------------------


@pytest.fixture
def reports(tmp_path) -> dict[str, str]:
    capture = cf.write_har(tmp_path)
    prefix = tmp_path / "out" / "run1"
    prefix.parent.mkdir()
    assert (
        main(
            [
                str(capture),
                "--scope",
                "app.test,api.app.test",
                "--report-format",
                "json,md,html",
                "-o",
                str(prefix),
            ]
        )
        == 0
    )
    return {
        ext: (prefix.parent / f"run1.{ext}").read_text(encoding="utf-8")
        for ext in ("md", "html", "json")
    }


def test_all_formats_written_without_secrets(reports):
    for text in reports.values():
        assert "passive analyzer" in text
        for secret in cf.SECRETS:
            assert secret not in text


def test_json_report_structure(reports):
    data = json.loads(reports["json"])
    assert data["schema"] == "reqlens.report/1"
    assert data["tool"]["name"] == "reqlens"
    assert data["summary"]["capture_files"] == ["session.har"]
    assert data["summary"]["transactions_in_scope"] == 6
    assert data["summary"]["dropped_hosts"][0]["host"] in (
        "other.example",
        "www.google-analytics.com",
    )
    assert sum(data["counts"]["by_concern"].values()) == len(data["findings"])
    for finding in data["findings"]:
        assert finding["confidence"] in ("possible", "informational")
        assert finding["concern"] in ("high", "medium", "low", "info")
        assert finding["manual_test"] and finding["learning"] and finding["references"]
    titles = [f["title"] for f in data["findings"]]
    assert "Algorithm confusion (asymmetric -> HS256) worth testing [RS256]" in titles


def test_findings_ordered_by_category_then_concern(reports):
    findings = json.loads(reports["json"])["findings"]
    rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    keys = [(f["category"], rank[f["concern"]]) for f in findings]
    assert keys == sorted(keys)


def test_markdown_and_html_sections(reports):
    md, page = reports["md"], reports["html"]
    for text in (md, page):
        assert "Broken Object Level Authorization" in text
        assert "Manual test." in text and "Learn." in text
        assert "Hosts excluded from analysis" in text
    assert "## Summary" in md and "| Capture files | session.har |" in md
    assert "Content-Security-Policy" in page and "default-src 'none'" in page
    assert "<script" not in page.lower()


def test_default_output_is_markdown_in_cwd(tmp_path):
    capture = cf.write_har(tmp_path)
    assert main([str(capture), "--scope", "app.test"]) == 0
    assert Path("reqlens-report.md").exists()
    assert not Path("reqlens-report.html").exists()


# --- untrusted text ------------------------------------------------------------------------


def _outside_code_spans(markdown: str) -> str:
    """Markdown with every code span removed (code spans display their content literally)."""
    return re.sub(r"(`+) .*? \1", "", markdown)


def test_markdown_neutralises_untrusted_text():
    out = md_report.render(evil_data())
    assert "\x1b" not in out
    prose = _outside_code_spans(out)
    assert "<script" not in prose and "&lt;script&gt;" in prose
    assert not re.search(r"(?<!\\)\]\(", prose)  # no unescaped link syntax
    assert "- <javascript:" not in prose  # unsafe reference is not an autolink
    assert "`` <script>" in out  # evidence kept, literally, inside a code span


def test_html_neutralises_untrusted_text():
    out = html_report.render(evil_data())
    assert "<script>" not in out and "&lt;script&gt;" in out
    assert "\x1b" not in out
    assert 'href="javascript:' not in out
    assert "<code>javascript:alert(1)</code>" in out


def test_json_strips_control_characters():
    data = json.loads(json_report.render(evil_data()))
    assert "\x1b" not in json.dumps(data)
    assert data["findings"][0]["evidence"][0]["value"].startswith("<script>")  # data, escaped later


def test_markdown_code_span_handles_backticks_and_pipes():
    assert md_report.code("a`b") == "`` a`b ``"
    assert md_report.code("x|y") == r"` x\|y `"
    assert md_report.code("") == "` `"


# --- files ---------------------------------------------------------------------------------


def test_output_base_strips_report_extensions():
    assert output_base("out/report.html") == Path("out/report")
    assert output_base("out/report") == Path("out/report")
    assert output_base("out/report.v2") == Path("out/report.v2")


def test_missing_output_directory_is_an_error(tmp_path):
    with pytest.raises(ReportError, match="does not exist"):
        write_reports(ReportData(summary(), []), ["md"], str(tmp_path / "nope" / "r"))


def test_write_is_atomic_and_leaves_no_temp_files(tmp_path):
    paths = write_reports(ReportData(summary(), []), ["md", "html", "json"], str(tmp_path / "r"))
    assert sorted(p.name for p in paths) == ["r.html", "r.json", "r.md"]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["r.html", "r.json", "r.md"]
    assert "found nothing to report" in (tmp_path / "r.md").read_text(encoding="utf-8")
