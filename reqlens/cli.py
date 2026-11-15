"""Command-line interface: argument parsing and the pipeline order.

Pipeline (each stage only sees the output of the one before it):

1. load      -> list[Transaction]           (loaders/)
2. scope     -> in-scope transactions       (scope.py)
3. redact    -> redacted transactions       (redact.py)   -- before anything else looks
4. group     -> one representative/endpoint (group.py)
5. checks    -> list[Finding]               (checks/ + knowledge/), no AI, always runs
6. ai        -> extra findings              (ai/), only with --ai
7. report    -> md / html / json files      (report/)

Stages are filled in phase by phase; until a stage exists, :func:`run` says so plainly.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from reqlens import __version__, config
from reqlens.ai.constants import DEFAULT_BUDGET as AI_DEFAULT_BUDGET
from reqlens.ai.constants import PROVIDERS as AI_PROVIDERS
from reqlens.checks import Context, merge, run_checks
from reqlens.errors import ReqlensError, UsageError
from reqlens.external import ToolStatus, detect_tools, hashcat, jwt_tool
from reqlens.external.findings import describe_hashcat, describe_jwt_tool, external_findings
from reqlens.group import group_transactions
from reqlens.loaders import load_captures
from reqlens.redact import RedactionPolicy, Redactor, describe_format
from reqlens.report import ReportData, build_summary, write_reports
from reqlens.sanitize import clean_text
from reqlens.scope import apply_scope
from reqlens.view import (
    render_findings,
    render_hash_knowledge,
    render_jwt_knowledge,
    render_summary,
    render_transaction,
)


@dataclass
class Options:
    """Validated, normalised options passed to the pipeline."""

    inputs: list[str]
    input_format: str | None
    scope: list[str]
    report_formats: list[str]
    output: str
    keep_body_values: bool = False
    show_redaction: int | None = None
    use_external_tools: bool = True
    check_jwt: str | None = None
    check_hashes: list[str] | None = None
    ai: bool = False
    ai_provider: str = "anthropic"
    ai_model: str | None = None
    ai_base_url: str | None = None
    ai_budget: int = 3000
    ai_dry_run: bool = False
    ai_no_cache: bool = False

    @property
    def ai_requested(self) -> bool:
        """True when the AI step runs (for real or as a dry run)."""
        return self.ai or self.ai_dry_run


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser. Flag names are part of the public interface."""
    parser = argparse.ArgumentParser(
        prog="reqlens",
        description=(
            "Passive HTTP capture analyzer. Reads existing capture files (HAR, Burp XML, "
            "mitmproxy, ZAP) and reports possible vulnerabilities with manual tests and "
            "lessons. Never sends a request to the target."
        ),
    )
    parser.add_argument(
        "inputs",
        nargs="*",
        metavar="CAPTURE",
        help="capture file, directory, or glob; several are merged into one analysis",
    )
    parser.add_argument(
        "--check-jwt",
        metavar="TOKEN",
        help="no capture needed: identify a JWT's algorithm and list attack classes to test "
        "by hand. Pass '-' to read the token from stdin (keeps it out of shell history)",
    )
    parser.add_argument(
        "--check-hashes",
        nargs="+",
        metavar="VALUE",
        help="no capture needed: identify likely hash/encoding types of values. Pass '-' to "
        "read one value per line from stdin",
    )
    parser.add_argument(
        "--input-format",
        choices=config.INPUT_FORMATS,
        help="force the capture format instead of auto-detecting it",
    )
    parser.add_argument(
        "--scope",
        metavar="HOSTS",
        help="comma-separated hosts you are authorized to test (e.g. app.test,api.app.test); "
        "'*.app.test' matches subdomains",
    )
    parser.add_argument(
        "--scope-file",
        metavar="PATH",
        help="file with one authorized host per line ('#' starts a comment)",
    )
    parser.add_argument(
        "--report-format",
        default=",".join(config.DEFAULT_REPORT_FORMATS),
        metavar="FORMATS",
        help="comma-separated report formats: md,html,json (default: md)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=config.DEFAULT_OUTPUT_PREFIX,
        metavar="PREFIX",
        help="output path prefix; extensions are added per format (default: reqlens-report)",
    )
    parser.add_argument(
        "--keep-body-values",
        action="store_true",
        help="show raw body values in your local report (never sent to AI; cookies, tokens "
        "and other secrets stay redacted)",
    )
    parser.add_argument(
        "--show-redaction",
        type=int,
        metavar="N",
        help="print transaction N exactly as it looks after redaction, then exit",
    )
    parser.add_argument(
        "--no-external",
        action="store_true",
        help="do not use optional external tools (jwt_tool, hashcat) even if installed",
    )
    parser.add_argument("--version", action="version", version=f"reqlens {__version__}")

    group = parser.add_argument_group(
        "AI analysis (optional, off by default)",
        "Condenses the strictly redacted capture locally, then asks an AI model once what the "
        "rules missed. Only a redacted digest is sent: never raw captures, secrets or PII. "
        "API keys are read from environment variables only (REQLENS_AI_KEY, OPENAI_API_KEY, "
        "ANTHROPIC_API_KEY).",
    )
    group.add_argument("--ai", action="store_true", help="Analyse the capture with an AI model")
    group.add_argument(
        "--ai-provider",
        choices=AI_PROVIDERS,
        default=os.environ.get("REQLENS_AI_PROVIDER", "anthropic"),
        help="anthropic/openai/ollama use an API; codex/claude/gemini use that signed-in CLI "
        "(default: anthropic)",
    )
    group.add_argument(
        "--ai-model",
        default=os.environ.get("REQLENS_AI_MODEL"),
        help="Model name (required for openai and ollama)",
    )
    group.add_argument(
        "--ai-base-url", help="Override the API address, e.g. an OpenAI-compatible server"
    )
    group.add_argument(
        "--ai-budget",
        type=int,
        default=AI_DEFAULT_BUDGET,
        help=f"Max estimated input tokens to send (default: {AI_DEFAULT_BUDGET})",
    )
    group.add_argument(
        "--ai-dry-run",
        action="store_true",
        help="Show what would be sent and its token estimate; send nothing",
    )
    group.add_argument(
        "--ai-no-cache", action="store_true", help="Ignore and don't save cached AI answers"
    )
    return parser


def parse_scope(scope: str | None, scope_file: str | None) -> list[str]:
    """Combine ``--scope`` and ``--scope-file`` into a de-duplicated, lower-case host list."""
    hosts: list[str] = []
    if scope:
        hosts.extend(part.strip() for part in scope.split(","))
    if scope_file:
        try:
            text = Path(scope_file).read_text(encoding="utf-8")
        except OSError as exc:
            raise UsageError(f"cannot read scope file {scope_file!r}: {exc.strerror}") from exc
        for line in text.splitlines():
            hosts.append(line.split("#", 1)[0].strip())
    cleaned: list[str] = []
    for host in hosts:
        host = host.lower().rstrip(".")
        if host and host not in cleaned:
            cleaned.append(host)
    if not cleaned:
        raise UsageError(
            "a scope is required: pass --scope host1,host2 or --scope-file PATH with the hosts "
            "you are authorized to test"
        )
    return cleaned


def parse_report_formats(value: str) -> list[str]:
    """Validate ``--report-format`` and return the formats in a stable order."""
    requested = {part.strip().lower() for part in value.split(",") if part.strip()}
    unknown = requested - set(config.REPORT_FORMATS)
    if unknown:
        raise UsageError(
            f"unknown report format(s): {', '.join(sorted(unknown))}; "
            f"choose from {','.join(config.REPORT_FORMATS)}"
        )
    if not requested:
        raise UsageError("--report-format needs at least one of md,html,json")
    return [fmt for fmt in config.REPORT_FORMATS if fmt in requested]


def options_from_args(args: argparse.Namespace) -> Options:
    """Validate parsed arguments and build :class:`Options`."""
    knowledge_mode = args.check_jwt is not None or args.check_hashes is not None
    if knowledge_mode and args.inputs:
        raise UsageError("--check-jwt and --check-hashes run on their own; drop the capture files")
    if not knowledge_mode and not args.inputs:
        raise UsageError("give at least one capture file (or use --check-jwt / --check-hashes)")
    if knowledge_mode and (args.ai or args.ai_dry_run):
        raise UsageError("--check-jwt and --check-hashes never use AI; drop --ai/--ai-dry-run")
    return Options(
        inputs=list(args.inputs),
        input_format=args.input_format,
        scope=[] if knowledge_mode else parse_scope(args.scope, args.scope_file),
        check_jwt=args.check_jwt,
        check_hashes=args.check_hashes,
        report_formats=parse_report_formats(args.report_format),
        output=args.output,
        keep_body_values=args.keep_body_values,
        show_redaction=args.show_redaction,
        use_external_tools=not args.no_external,
        ai=args.ai,
        ai_provider=args.ai_provider,
        ai_model=args.ai_model,
        ai_base_url=args.ai_base_url,
        ai_budget=args.ai_budget,
        ai_dry_run=args.ai_dry_run,
        ai_no_cache=args.ai_no_cache,
    )


def run(options: Options) -> int:
    """Run the pipeline in order. Returns the process exit code."""
    if options.check_jwt is not None or options.check_hashes is not None:
        return _knowledge_mode(options)
    if options.ai_requested:
        from reqlens.ai.settings import check_settings

        # Fail before reading any capture if the AI settings can't work.
        check_settings(
            options.ai_provider,
            options.ai_model,
            options.ai_base_url,
            options.ai_budget,
            dry_run=options.ai_dry_run,
        )
    # 1. load
    loaded = load_captures(options.inputs, options.input_format)
    for warning in loaded.warnings:
        _note(warning)
    # 2. scope (out-of-scope traffic is discarded here, before anything reads it)
    scoped = apply_scope(loaded.transactions, options.scope)
    # 3. redact
    policy = RedactionPolicy(keep_body_values=options.keep_body_values)
    redactor = Redactor(policy)
    if options.show_redaction is not None:
        return _show_redaction(options.show_redaction, loaded, scoped, redactor)
    redacted = redactor.redact_all(scoped.kept)
    # 4. group
    endpoints = group_transactions(redacted)
    print(render_summary(loaded, scoped, redacted, endpoints))
    # 5. local checks + knowledge layer (no AI), then optional external tools
    context = Context(redacted, endpoints, options.scope)
    findings = run_checks(context)
    tools = _detect_tools(options.use_external_tools)
    tool_findings, tool_notes = external_findings(context, tools)
    for note in tool_notes:
        _note(note)
    findings = merge(findings + tool_findings)
    # 6. AI analysis (opt-in). It always gets a strictly redacted view, even when the local
    #    report keeps body values.
    ai_section = None
    if options.ai_requested:
        ai_section, ai_findings = _ai_step(options, scoped, redacted, endpoints, findings)
        findings = merge(findings + ai_findings)
    # 7. reports
    summary = build_summary(
        loaded,
        scoped,
        redacted,
        endpoints,
        options.scope,
        redaction_policy="values kept (local report only)"
        if options.keep_body_values
        else "strict (values masked)",
        external_tools={name: status.label for name, status in tools.items()},
        ai_provider=ai_section.label if ai_section else None,
    )
    written = write_reports(
        ReportData(summary, findings, ai_section), options.report_formats, options.output
    )
    print()
    print(render_findings(findings))
    print()
    for path in written:
        print(f"report written: {clean_text(str(path), keep_newlines=False)}")
    return 0


def _ai_step(options: Options, scoped, redacted, endpoints, findings):
    """Run the optional AI analysis on a strictly redacted view. Returns (section, findings)."""
    from reqlens import ai

    if options.keep_body_values:
        strict = Redactor(RedactionPolicy()).redact_all(scoped.kept)
        strict_endpoints = group_transactions(strict)
    else:
        strict, strict_endpoints = redacted, endpoints
    outcome = ai.run(
        strict,
        strict_endpoints,
        findings,
        options.scope,
        provider=options.ai_provider,
        model=options.ai_model,
        base_url=options.ai_base_url,
        budget=options.ai_budget,
        dry_run=options.ai_dry_run,
        use_cache=not options.ai_no_cache,
    )
    if outcome.dry_run_text:
        print(clean_text(outcome.dry_run_text))
        print()
    if outcome.section is not None:
        _note(f"AI ({outcome.section.label}): {outcome.section.message}")
    return outcome.section, outcome.findings


def _read_values(values: list[str]) -> list[str]:
    """Expand '-' into lines read from stdin."""
    out: list[str] = []
    for value in values:
        if value == "-":
            out.extend(line.strip() for line in sys.stdin.read().splitlines() if line.strip())
        else:
            out.append(value)
    return out


def _knowledge_mode(options: Options) -> int:
    """--check-jwt / --check-hashes: identification and guidance only, no capture, no AI."""
    blocks = []
    if options.check_jwt is not None:
        token = _read_values([options.check_jwt])
        if len(token) != 1:
            raise UsageError("--check-jwt expects exactly one token")
        record = Redactor().describe_jwt(token[0])
        if record is None:
            raise UsageError("--check-jwt: that value is not a JWT (expected header.payload.sig)")
        blocks.append(render_jwt_knowledge(record))
        tool = _detect_tools(options.use_external_tools, only="jwt_tool")["jwt_tool"]
        if tool.available:
            observed, problem = describe_jwt_tool(tool, record)
            blocks.append(
                clean_text(
                    f"Optional tool jwt_tool (decode only, redacted token): {observed or problem}",
                    keep_newlines=False,
                )
            )
    if options.check_hashes is not None:
        values = _read_values(options.check_hashes)
        blocks.append(render_hash_knowledge(values))
        tool = _detect_tools(options.use_external_tools, only="hashcat")["hashcat"]
        if tool.available:
            lines = ["Optional tool hashcat (--identify on a synthetic sample of each shape):"]
            for number, value in enumerate(values, 1):
                fmt = describe_format(value.strip())
                if hashcat.sample_for_format(fmt) is None:
                    lines.append(f"{number}. shape {fmt}: no sample for this shape; skipped")
                    continue
                observed, problem = describe_hashcat(tool, fmt)
                lines.append(f"{number}. {observed or problem}")
            blocks.append("\n".join(clean_text(line, keep_newlines=False) for line in lines))
    print("\n\n".join(blocks))
    return 0


def _detect_tools(enabled: bool, only: str | None = None) -> dict[str, ToolStatus]:
    """Detect optional tools and print one line for each that can't be used."""
    tools = detect_tools(enabled)
    if only is not None:
        tools = {only: tools[only]}
    hints = {"jwt_tool": jwt_tool.ENV_VAR, "hashcat": hashcat.ENV_VAR}
    for name, status in tools.items():
        if enabled and not status.available:
            _note(
                f"optional tool {name}: {status.detail}; continuing without it "
                f"(set {hints[name]} to its path to use it)"
            )
    return tools


def _note(message: str) -> None:
    """Print a sanitised informational line to stderr."""
    print(f"reqlens: {clean_text(message, keep_newlines=False)}", file=sys.stderr)


def _show_redaction(index: int, loaded, scoped, redactor: Redactor) -> int:
    """Print one transaction exactly as later stages will see it."""
    by_index = {tx.index: tx for tx in loaded.transactions}
    if index not in by_index:
        raise UsageError(
            f"--show-redaction {index}: no such transaction "
            f"(valid: 0-{len(loaded.transactions) - 1})"
        )
    kept = {tx.index: tx for tx in scoped.kept}
    if index not in kept:
        raise UsageError(
            f"--show-redaction {index}: transaction is on {by_index[index].host}, which is "
            "outside the scope, so it is never analysed"
        )
    label = (
        "body values kept for local report; secrets still removed"
        if redactor.policy.keep_body_values
        else "strict: values masked, the same view any AI provider would get"
    )
    print(render_transaction(redactor.redact(kept[index]), label))
    return 0


def _tolerant_streams() -> None:
    """Never crash on characters the console can't encode (e.g. cp1252 on Windows)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):
                reconfigure(errors="replace")


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``reqlens``, ``python -m reqlens`` and ``python reqlens.py``."""
    _tolerant_streams()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(options_from_args(args))
    except ReqlensError as exc:
        print(f"reqlens: error: {clean_text(str(exc), keep_newlines=False)}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("reqlens: interrupted", file=sys.stderr)
        return 130
