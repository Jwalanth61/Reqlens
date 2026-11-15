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
import sys
from dataclasses import dataclass
from pathlib import Path

from reqlens import __version__, config
from reqlens.errors import ReqlensError, UsageError
from reqlens.sanitize import clean_text


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
        nargs="+",
        metavar="CAPTURE",
        help="capture file, directory, or glob; several are merged into one analysis",
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
    return Options(
        inputs=list(args.inputs),
        input_format=args.input_format,
        scope=parse_scope(args.scope, args.scope_file),
        report_formats=parse_report_formats(args.report_format),
        output=args.output,
        keep_body_values=args.keep_body_values,
        show_redaction=args.show_redaction,
        use_external_tools=not args.no_external,
    )


def run(options: Options) -> int:
    """Run the pipeline in order. Returns the process exit code."""
    raise ReqlensError(
        "the analysis pipeline is not built yet (loaders arrive in phase 2); "
        "options were validated successfully"
    )


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``reqlens``, ``python -m reqlens`` and ``python reqlens.py``."""
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
