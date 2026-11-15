"""Report generation: one data object, rendered as Markdown, HTML and/or JSON.

Reports only ever contain redacted values (or, with ``--keep-body-values``, the user's own
non-secret body values). Every string is passed through
:func:`reqlens.sanitize.clean_text` and then escaped for the target format.
"""

from __future__ import annotations

import os
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from reqlens import __version__, config
from reqlens.errors import ReportError
from reqlens.group import Endpoint
from reqlens.loaders.base import LoadResult
from reqlens.model import Concern, Finding, Transaction
from reqlens.scope import ScopeResult

CONCERN_ORDER = [level.value for level in Concern]


@dataclass
class DroppedHostSummary:
    """A host excluded from analysis."""

    host: str
    reason: str
    count: int


@dataclass
class RunSummary:
    """Facts about the run shown in every report's header."""

    capture_files: list[str]
    """File names only (no directories, which can contain user names)."""
    scope: list[str]
    transactions_loaded: int
    transactions_in_scope: int
    hosts: list[str]
    endpoints: int
    dropped_hosts: list[DroppedHostSummary] = field(default_factory=list)
    secrets_redacted: int = 0
    pii_detected: int = 0
    redaction_policy: str = "strict"
    external_tools: dict[str, str] = field(default_factory=dict)
    """Optional tool name -> version string, or 'not found' / 'disabled'."""
    ai_provider: str | None = None
    tool_version: str = __version__
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )


@dataclass
class AISection:
    """What the optional AI step did, for the report (never contains capture values)."""

    provider: str
    model: str
    status: str
    """``answered``, ``cached``, ``dry-run``, ``nothing-to-send`` or ``error``."""
    message: str
    """Token use, cache note, or the error, in one sentence."""
    digest_tokens: int = 0
    kept: int = 0
    dropped: int = 0
    relationships: list[str] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        """Short text for the summary table."""
        return f"{self.provider} / {self.model} ({self.status})"


@dataclass
class ReportData:
    """Everything a renderer needs."""

    summary: RunSummary
    findings: list[Finding]
    ai: AISection | None = None

    @property
    def concern_counts(self) -> dict[str, int]:
        """Findings per concern level, in display order (zeros included)."""
        counts = Counter(f.concern.value for f in self.findings)
        return {level: counts.get(level, 0) for level in CONCERN_ORDER}

    @property
    def category_counts(self) -> dict[str, dict[str, int]]:
        """``{category: {concern: count}}`` in category order."""
        table: dict[str, dict[str, int]] = {}
        for finding in self.findings:
            row = table.setdefault(finding.category, {level: 0 for level in CONCERN_ORDER})
            row[finding.concern.value] += 1
        return dict(sorted(table.items()))

    @property
    def banner(self) -> str:
        """The passive-tool notice every report starts with."""
        return config.PASSIVE_BANNER


def build_summary(
    loaded: LoadResult,
    scoped: ScopeResult,
    redacted: list[Transaction],
    endpoints: list[Endpoint],
    scope: list[str],
    redaction_policy: str = "strict (values masked)",
    external_tools: dict[str, str] | None = None,
    ai_provider: str | None = None,
) -> RunSummary:
    """Collect the run facts shown in every report header."""
    dropped = sorted(scoped.dropped.values(), key=lambda d: (-d.count, d.host))
    return RunSummary(
        capture_files=[Path(name).name for name in loaded.files],
        scope=list(scope),
        transactions_loaded=len(loaded.transactions),
        transactions_in_scope=len(scoped.kept),
        hosts=sorted({tx.host for tx in scoped.kept}),
        endpoints=len(endpoints),
        dropped_hosts=[DroppedHostSummary(d.host, d.reason, d.count) for d in dropped],
        secrets_redacted=sum(len(tx.tokens) for tx in redacted),
        pii_detected=sum(len(tx.pii) for tx in redacted),
        redaction_policy=redaction_policy,
        external_tools=dict(external_tools or {}),
        ai_provider=ai_provider,
    )


def _renderers() -> dict[str, tuple[str, Callable[[ReportData], str]]]:
    from reqlens.report import html, json, markdown

    return {
        "md": (".md", markdown.render),
        "html": (".html", html.render),
        "json": (".json", json.render),
    }


def output_base(prefix: str) -> Path:
    """Strip a trailing report extension so ``-o out.html`` doesn't become ``out.html.md``."""
    path = Path(prefix)
    if path.suffix.lower() in (".md", ".html", ".htm", ".json"):
        path = path.with_suffix("")
    return path


def write_reports(data: ReportData, formats: list[str], prefix: str) -> list[Path]:
    """Render and write each requested format. Each file is written atomically."""
    renderers = _renderers()
    base = output_base(prefix)
    directory = base.parent if str(base.parent) else Path(".")
    if not directory.is_dir():
        raise ReportError(f"output directory does not exist: {directory}")
    written = []
    for fmt in formats:
        suffix, render = renderers[fmt]
        target = base.with_name(base.name + suffix)
        _atomic_write(target, render(data))
        written.append(target)
    return written


def _atomic_write(target: Path, text: str) -> None:
    temp = None
    try:
        handle, temp = tempfile.mkstemp(dir=target.parent, prefix=".reqlens-", suffix=".tmp")
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        os.replace(temp, target)
        temp = None
    except OSError as exc:
        raise ReportError(f"cannot write {target}: {exc.strerror or exc}") from exc
    finally:
        if temp is not None and os.path.exists(temp):
            os.unlink(temp)
