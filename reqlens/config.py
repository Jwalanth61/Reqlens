"""Limits and defaults shared across the pipeline."""

from __future__ import annotations

# --- Input --------------------------------------------------------------------------------
INPUT_FORMATS: tuple[str, ...] = ("har", "burp", "mitmproxy", "zap")
"""Capture formats reqlens can read. ``--input-format`` forces one of these."""

MAX_CAPTURE_BYTES = 512 * 1024 * 1024
"""Refuse capture files larger than this (512 MiB) instead of exhausting memory."""

MAX_BODY_CHARS = 2_000_000
"""Bodies longer than this are truncated before analysis; the truncation is recorded."""

MAX_INPUT_FILES = 1000
"""Upper bound on files expanded from a directory or glob."""

# --- Redaction ----------------------------------------------------------------------------
FINGERPRINT_HEX_CHARS = 8
"""Length of the sha256 prefix used in ``<redacted:xxxxxxxx>`` fingerprints."""

# --- Reports ------------------------------------------------------------------------------
REPORT_FORMATS: tuple[str, ...] = ("md", "html", "json")
DEFAULT_REPORT_FORMATS: tuple[str, ...] = ("md",)
DEFAULT_OUTPUT_PREFIX = "reqlens-report"

PASSIVE_BANNER = (
    "reqlens is a passive analyzer: it only read existing capture files and sent no "
    "requests to any target. Every finding below is a lead that requires manual "
    "verification, on targets and accounts you are authorized to test."
)
