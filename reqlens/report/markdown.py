"""Markdown report.

Captured text never becomes live Markdown or HTML: prose is escaped, and evidence values are
put in code spans (which Markdown renderers display literally).
"""

from __future__ import annotations

import re

from reqlens.knowledge.catalog import CATEGORIES
from reqlens.model import Finding
from reqlens.report import ReportData
from reqlens.sanitize import clean_text

# Characters that can start emphasis, code, links, tables or strikethrough mid-line.
# '<', '>' and '&' are entity-encoded separately, so raw HTML can never form.
_MD_SPECIAL = re.compile(r"([\\`*_\[\]|~])")


def text(value: str) -> str:
    """Escape untrusted text for Markdown prose (single line)."""
    cleaned = clean_text(str(value), keep_newlines=False)
    cleaned = cleaned.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _MD_SPECIAL.sub(r"\\\1", cleaned)


def code(value: str) -> str:
    """A code span that holds any text literally, safe inside table cells."""
    cleaned = clean_text(str(value), keep_newlines=False).replace("|", "\\|")
    if not cleaned:
        return "` `"
    longest = max((len(run) for run in re.findall(r"`+", cleaned)), default=0)
    fence = "`" * (longest + 1)
    return f"{fence} {cleaned} {fence}"


def _link(url: str) -> str:
    """References are https URLs from the catalog; anything else is shown as code."""
    if re.fullmatch(r"https://[A-Za-z0-9.\-]+(/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?", url):
        return f"<{url}>"
    return code(url)


def _summary(data: ReportData) -> list[str]:
    s = data.summary
    counts = data.concern_counts
    findings_line = ", ".join(f"{n} {level}" for level, n in counts.items()) or "none"
    tools = ", ".join(f"{name} ({version})" for name, version in s.external_tools.items())
    rows = [
        ("Generated", s.generated_at),
        ("reqlens version", s.tool_version),
        ("Capture files", ", ".join(s.capture_files)),
        ("Authorized scope", ", ".join(s.scope)),
        ("Transactions", f"{s.transactions_in_scope} in scope of {s.transactions_loaded} loaded"),
        ("Hosts analysed", ", ".join(s.hosts)),
        ("Endpoint patterns", str(s.endpoints)),
        ("Findings", f"{len(data.findings)} ({findings_line})"),
        (
            "Redaction",
            f"{s.redaction_policy}; {s.secrets_redacted} secret values removed, "
            f"{s.pii_detected} personal-data values detected",
        ),
        ("Optional tools", tools or "none used"),
        ("AI analysis", s.ai_provider or "not used (local checks only)"),
    ]
    lines = ["## Summary", "", "| | |", "|---|---|"]
    lines += [f"| {label} | {text(value)} |" for label, value in rows]
    if s.dropped_hosts:
        lines += [
            "",
            "### Hosts excluded from analysis",
            "",
            "Their traffic was discarded before redaction; only these counts remain.",
            "",
            "| Host | Reason | Requests |",
            "|---|---|---|",
        ]
        lines += [f"| {code(d.host)} | {text(d.reason)} | {d.count} |" for d in s.dropped_hosts]
    if data.findings:
        lines += [
            "",
            "### Findings by category",
            "",
            "| Category | High | Medium | Low | Info |",
            "|---|---|---|---|---|",
        ]
        for category, row in data.category_counts.items():
            name = text(f"{category} {CATEGORIES.get(category, '')}".strip())
            lines.append(
                f"| {name} | {row['high']} | {row['medium']} | {row['low']} | {row['info']} |"
            )
    return lines


def _finding(number: int, finding: Finding) -> list[str]:
    meta = [
        f"**Concern:** {finding.concern.value}",
        f"**Confidence:** {finding.confidence.value}",
        f"**OWASP:** {text(finding.category)}",
    ]
    if finding.wstg:
        meta.append(f"**WSTG:** {text(', '.join(finding.wstg))}")
    meta.append(f"**Source:** {text(finding.source)}")
    lines = [f"### {number}. {text(finding.title)}", "", " · ".join(meta), ""]
    if finding.observed:
        lines += [f"**Observed.** {text(finding.observed)}", ""]
    lines += [
        f"**Why it may matter.** {text(finding.why)}",
        "",
        f"**Manual test.** {text(finding.manual_test)}",
        "",
        f"**Learn.** {text(finding.learning)}",
        "",
    ]
    if finding.evidence:
        shown = len(finding.evidence)
        total = max(finding.occurrences, shown)
        note = f" ({total} occurrences, first {shown} shown)" if total > shown else ""
        lines += [
            f"**Evidence**{note}",
            "",
            "| # | Endpoint | Where | Value (redacted) |",
            "|---|---|---|---|",
        ]
        for item in finding.evidence:
            where = f"{item.location} {item.name}".strip()
            lines.append(
                f"| {item.transaction_index} | {code(item.endpoint)} | {text(where)} "
                f"| {code(item.value)} |"
            )
        lines.append("")
    if finding.references:
        lines += ["**References**", ""] + [f"- {_link(ref)}" for ref in finding.references]
        lines.append("")
    return lines


def _ai_section(data: ReportData) -> list[str]:
    ai = data.ai
    lines = [
        "## AI analysis",
        "",
        f"**Provider:** {text(ai.provider)} · **Model:** {text(ai.model)} · "
        f"**Status:** {text(ai.status)}",
        "",
        text(ai.message),
        "",
    ]
    if ai.digest_tokens:
        lines += [
            f"Only a redacted digest was used: about {ai.digest_tokens} tokens, {ai.kept} "
            f"entries kept, {ai.dropped} left out for the budget. AI findings above are marked "
            "**Source:** ai; like every finding they are leads to verify by hand.",
            "",
        ]
    for label, items in (
        ("Relationships between endpoints", ai.relationships),
        ("Anomalies", ai.anomalies),
        ("Next steps", ai.next_steps),
    ):
        if items:
            lines += [f"**{label}**", ""] + [f"- {text(item)}" for item in items] + [""]
    return lines


def render(data: ReportData) -> str:
    """Render the full Markdown report."""
    lines = [
        "# reqlens report",
        "",
        f"> **Passive analysis: leads, not confirmed vulnerabilities.** {text(data.banner)}",
        "",
    ]
    lines += _summary(data)
    lines += ["", "## Findings", ""]
    if not data.findings:
        lines.append("The local checks found nothing to report in this capture.")
    current = None
    for number, finding in enumerate(data.findings, 1):
        if finding.category != current:
            current = finding.category
            name = text(f"{current} {CATEGORIES.get(current, '')}".strip())
            lines += [f"## {name}", ""]
        lines += _finding(number, finding)
    if data.ai is not None:
        lines += _ai_section(data)
    lines += [
        "## How to read this report",
        "",
        "- **Concern** ranks what to test first (high, medium, low, info). It is not a "
        "severity rating: nothing here has been confirmed.",
        "- **Manual test** is a single step for you to run yourself, with your own test "
        "accounts, on targets you are authorized to test. reqlens performed none of them.",
        "- Values shown as `<redacted:xxxxxxxx>` are keyed fingerprints of secrets; equal "
        "fingerprints mean equal values within this run. `<str:12>`, `<email>` and similar "
        "describe masked values.",
        "",
    ]
    return "\n".join(lines)
