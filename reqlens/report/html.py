"""Self-contained HTML report: one file, inline CSS, no scripts, no external resources.

The page sets a Content-Security-Policy that forbids scripts and remote loads, so even if
captured text slipped through escaping it could not execute or phone home. Every dynamic
string is sanitised and HTML-escaped. Concern filtering is pure CSS (radio buttons).
"""

from __future__ import annotations

import html
import re

from reqlens.knowledge.catalog import CATEGORIES
from reqlens.model import Finding
from reqlens.report import CONCERN_ORDER, ReportData
from reqlens.sanitize import clean_text

_SAFE_URL = re.compile(r"https://[A-Za-z0-9.\-]+(/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?")

CSS = """
:root{--bg:#f7f7f5;--card:#ffffff;--text:#1d1d1b;--muted:#5f5e5a;--border:#dcdad3;
--high:#a32d2d;--high-bg:#fcebeb;--medium:#854f0b;--medium-bg:#faeeda;--low:#185fa5;
--low-bg:#e6f1fb;--info:#5f5e5a;--info-bg:#f1efe8;--banner:#633806;--banner-bg:#faeeda;
--code:#f1efe8;--accent:#534ab7}
@media (prefers-color-scheme:dark){:root{--bg:#1b1b1a;--card:#252524;--text:#ecebe6;
--muted:#b4b2a9;--border:#3d3d3a;--high:#f09595;--high-bg:#501313;--medium:#fac775;
--medium-bg:#412402;--low:#85b7eb;--low-bg:#042c53;--info:#d3d1c7;--info-bg:#2c2c2a;
--banner:#fac775;--banner-bg:#412402;--code:#2c2c2a;--accent:#afa9ec}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 system-ui,-apple-system,
"Segoe UI",Roboto,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:20px;margin:36px 0 12px}
h3{font-size:16px;margin:0}
.sub{color:var(--muted);margin:0 0 16px}
.banner{background:var(--banner-bg);color:var(--banner);border:1px solid var(--banner);
border-radius:10px;padding:12px 16px;margin:16px 0}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;
margin:16px 0}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:12px}
.card b{display:block;font-size:24px}
.card.high b{color:var(--high)}.card.medium b{color:var(--medium)}
.card.low b{color:var(--low)}.card.info b{color:var(--info)}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid
var(--border);border-radius:10px;overflow:hidden;margin:8px 0}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--border);
vertical-align:top;overflow-wrap:anywhere}
th{color:var(--muted);font-weight:600;width:200px}
code{background:var(--code);border-radius:4px;padding:1px 5px;font:13px/1.5 ui-monospace,
SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}
.badge{display:inline-block;border-radius:999px;padding:1px 10px;font-size:12px;
font-weight:600;margin-right:6px}
.badge.high{background:var(--high-bg);color:var(--high)}
.badge.medium{background:var(--medium-bg);color:var(--medium)}
.badge.low{background:var(--low-bg);color:var(--low)}
.badge.info{background:var(--info-bg);color:var(--info)}
.badge.meta{background:var(--code);color:var(--muted);font-weight:500}
.finding{background:var(--card);border:1px solid var(--border);border-left:4px solid
var(--info);border-radius:0;padding:14px 16px;margin:12px 0}
.finding.high{border-left-color:var(--high)}.finding.medium{border-left-color:var(--medium)}
.finding.low{border-left-color:var(--low)}
.finding h3{margin-bottom:6px}.finding p{margin:8px 0}
.label{font-weight:600}
details{margin-top:8px}summary{cursor:pointer;color:var(--accent)}
a{color:var(--accent)}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0 0}
.filters input{position:absolute;opacity:0}
.filters label{border:1px solid var(--border);background:var(--card);border-radius:999px;
padding:3px 12px;cursor:pointer;font-size:13px}
.filters input:checked+label{border-color:var(--accent);color:var(--accent);font-weight:600}
.filters input:focus-visible+label{outline:2px solid var(--accent)}
body:has(#f-high:checked) .finding:not(.high),
body:has(#f-medium:checked) .finding:not(.medium),
body:has(#f-low:checked) .finding:not(.low),
body:has(#f-info:checked) .finding:not(.info){display:none}
ol.toc{padding-left:22px}ol.toc li{margin:2px 0}
footer{color:var(--muted);font-size:13px;margin-top:40px}
"""


def e(value: object) -> str:
    """Sanitise and escape untrusted text for HTML (single line)."""
    return html.escape(clean_text(str(value), keep_newlines=False), quote=True)


def _link(url: str) -> str:
    if _SAFE_URL.fullmatch(url):
        return f'<a href="{html.escape(url, quote=True)}" rel="noopener noreferrer">{e(url)}</a>'
    return f"<code>{e(url)}</code>"


def _summary(data: ReportData) -> str:
    s = data.summary
    cards = "".join(
        f'<div class="card {level}"><b>{count}</b>{level}</div>'
        for level, count in data.concern_counts.items()
    )
    tools = ", ".join(f"{name} ({version})" for name, version in s.external_tools.items())
    rows = [
        ("Generated", s.generated_at),
        ("reqlens version", s.tool_version),
        ("Capture files", ", ".join(s.capture_files)),
        ("Authorized scope", ", ".join(s.scope)),
        ("Transactions", f"{s.transactions_in_scope} in scope of {s.transactions_loaded} loaded"),
        ("Hosts analysed", ", ".join(s.hosts)),
        ("Endpoint patterns", s.endpoints),
        (
            "Redaction",
            f"{s.redaction_policy}; {s.secrets_redacted} secret values removed, "
            f"{s.pii_detected} personal-data values detected",
        ),
        ("Optional tools", tools or "none used"),
        ("AI analysis", s.ai_provider or "not used (local checks only)"),
    ]
    parts = [
        f'<section aria-label="Summary"><h2>Summary</h2><div class="cards">{cards}</div>',
        "<table>",
    ]
    parts += [f"<tr><th>{e(label)}</th><td>{e(value)}</td></tr>" for label, value in rows]
    parts.append("</table>")
    if s.dropped_hosts:
        parts.append(
            '<h3>Hosts excluded from analysis</h3><p class="sub">Their traffic was '
            "discarded before redaction; only these counts remain.</p><table>"
            "<tr><th>Host</th><th>Reason</th><th>Requests</th></tr>"
        )
        parts += [
            f"<tr><td><code>{e(d.host)}</code></td><td>{e(d.reason)}</td><td>{d.count}</td></tr>"
            for d in s.dropped_hosts
        ]
        parts.append("</table>")
    if data.findings:
        parts.append(
            "<h3>Findings by category</h3><table><tr><th>Category</th>"
            + "".join(f"<th>{level}</th>" for level in CONCERN_ORDER)
            + "</tr>"
        )
        for category, row in data.category_counts.items():
            name = f"{category} {CATEGORIES.get(category, '')}".strip()
            parts.append(
                f"<tr><td>{e(name)}</td>"
                + "".join(f"<td>{row[level]}</td>" for level in CONCERN_ORDER)
                + "</tr>"
            )
        parts.append("</table>")
    parts.append("</section>")
    return "".join(parts)


def _finding(number: int, finding: Finding) -> str:
    level = finding.concern.value
    badges = [
        f'<span class="badge {level}">{level}</span>',
        f'<span class="badge meta">{e(finding.confidence.value)}</span>',
        f'<span class="badge meta">{e(finding.category)}</span>',
    ]
    badges += [f'<span class="badge meta">{e(w)}</span>' for w in finding.wstg]
    badges.append(f'<span class="badge meta">source: {e(finding.source)}</span>')
    parts = [
        f'<article class="finding {level}" id="f{number}">',
        f"<h3>{number}. {e(finding.title)}</h3><div>{''.join(badges)}</div>",
    ]
    if finding.observed:
        parts.append(f'<p><span class="label">Observed.</span> {e(finding.observed)}</p>')
    parts.append(f'<p><span class="label">Why it may matter.</span> {e(finding.why)}</p>')
    parts.append(f'<p><span class="label">Manual test.</span> {e(finding.manual_test)}</p>')
    parts.append(f'<p><span class="label">Learn.</span> {e(finding.learning)}</p>')
    if finding.evidence:
        shown = len(finding.evidence)
        total = max(finding.occurrences, shown)
        note = f", first {shown} shown" if total > shown else ""
        parts.append(
            f"<details><summary>Evidence ({total} occurrence"
            f"{'s' if total != 1 else ''}{note})</summary><table>"
            "<tr><th>#</th><th>Endpoint</th><th>Where</th><th>Value (redacted)</th></tr>"
        )
        for item in finding.evidence:
            where = f"{item.location} {item.name}".strip()
            parts.append(
                f"<tr><td>{item.transaction_index}</td><td><code>{e(item.endpoint)}"
                f"</code></td><td>{e(where)}</td><td><code>{e(item.value)}</code></td>"
                "</tr>"
            )
        parts.append("</table></details>")
    if finding.references:
        parts.append(
            "<details><summary>References</summary><ul>"
            + "".join(f"<li>{_link(ref)}</li>" for ref in finding.references)
            + "</ul></details>"
        )
    parts.append("</article>")
    return "".join(parts)


def _filters() -> str:
    options = [("all", "All")] + [(level, level.capitalize()) for level in CONCERN_ORDER]
    inputs = "".join(
        f'<input type="radio" name="concern" id="f-{key}"{" checked" if key == "all" else ""}>'
        f'<label for="f-{key}">{label}</label>'
        for key, label in options
    )
    return f'<div class="filters" role="group" aria-label="Filter by concern">{inputs}</div>'


def _ai_section(data: ReportData) -> str:
    ai = data.ai
    parts = [
        '<section aria-label="AI analysis"><h2>AI analysis</h2>',
        f'<p><span class="badge meta">{e(ai.provider)}</span><span class="badge meta">'
        f'{e(ai.model)}</span><span class="badge meta">{e(ai.status)}</span></p>',
        f"<p>{e(ai.message)}</p>",
    ]
    if ai.digest_tokens:
        parts.append(
            f"<p>Only a redacted digest was used: about {ai.digest_tokens} tokens, {ai.kept} "
            f"entries kept, {ai.dropped} left out for the budget. AI findings are marked "
            "<em>source: ai</em>; like every finding they are leads to verify by hand.</p>"
        )
    for label, items in (
        ("Relationships between endpoints", ai.relationships),
        ("Anomalies", ai.anomalies),
        ("Next steps", ai.next_steps),
    ):
        if items:
            parts.append(
                f"<h3>{e(label)}</h3><ul>"
                + "".join(f"<li>{e(item)}</li>" for item in items)
                + "</ul>"
            )
    parts.append("</section>")
    return "".join(parts)


def render(data: ReportData) -> str:
    """Render the full HTML report."""
    body = [
        "<main>",
        "<h1>reqlens report</h1>",
        f'<p class="sub">Generated {e(data.summary.generated_at)} · reqlens '
        f"{e(data.summary.tool_version)}</p>",
        '<div class="banner" role="note"><strong>Passive analysis: leads, not confirmed '
        f"vulnerabilities.</strong> {e(data.banner)}</div>",
        _summary(data),
        "<h2>Findings</h2>",
    ]
    if data.findings:
        body.append(_filters())
        body.append(
            '<ol class="toc">'
            + "".join(
                f'<li><a href="#f{n}">{e(f.title)}</a> <span class="badge {f.concern.value}">'
                f"{f.concern.value}</span></li>"
                for n, f in enumerate(data.findings, 1)
            )
            + "</ol>"
        )
    else:
        body.append("<p>The local checks found nothing to report in this capture.</p>")
    current = None
    for number, finding in enumerate(data.findings, 1):
        if finding.category != current:
            current = finding.category
            body.append(f"<h2>{e(current)} {e(CATEGORIES.get(current, ''))}</h2>")
        body.append(_finding(number, finding))
    if data.ai is not None:
        body.append(_ai_section(data))
    body.append(
        "<footer><p><strong>How to read this report.</strong> Concern ranks what to test "
        "first; it is not a severity rating, because nothing here has been confirmed. Each "
        "manual test is a single step for you to run yourself, with your own test accounts, "
        "on targets you are authorized to test; reqlens performed none of them. "
        "<code>&lt;redacted:xxxxxxxx&gt;</code> values are keyed fingerprints of secrets "
        "(equal within this run); <code>&lt;str:12&gt;</code>, <code>&lt;email&gt;</code> and "
        "similar describe masked values.</p></footer></main>"
    )
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        "style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'\">"
        '<meta name="referrer" content="no-referrer">'
        "<title>reqlens report</title>"
        f"<style>{CSS}</style></head><body>" + "".join(body) + "</body></html>\n"
    )
