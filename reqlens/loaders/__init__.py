"""Capture loaders. Each input format has its own module; this package expands the inputs,
detects each file's format, and merges everything into one numbered transaction list.

Loaders only read files. There is deliberately no live-capture or crawling code here.
A future "record mode" would be a separate producer of capture files, feeding this same
entry point, so the analyzer itself stays file-only.
"""

from __future__ import annotations

import glob
from pathlib import Path
from typing import Callable

from reqlens import config
from reqlens.errors import FormatDetectionError, InputError
from reqlens.loaders import har
from reqlens.loaders.base import LoadResult

Loader = Callable[[Path, int], LoadResult]

LOADERS: dict[str, Loader] = {"har": har.load}
"""Formats with a working loader. The rest arrive in a later build phase."""

_CAPTURE_SUFFIXES = {".har", ".json", ".xml", ".flow", ".mitm", ".zap"}
_SNIFF_BYTES = 8192


def expand_inputs(inputs: list[str]) -> list[Path]:
    """Resolve files, directories (recursively, capture-like suffixes only) and globs."""
    paths: list[Path] = []
    for raw in inputs:
        candidate = Path(raw)
        if candidate.is_file():
            found = [candidate]
        elif candidate.is_dir():
            found = sorted(
                p
                for p in candidate.rglob("*")
                if p.is_file() and p.suffix.lower() in _CAPTURE_SUFFIXES
            )
            if not found:
                raise InputError(f"no capture files (.har, .xml, .json, ...) found in {raw}")
        elif any(ch in raw for ch in "*?["):
            found = sorted(Path(p) for p in glob.glob(raw, recursive=True) if Path(p).is_file())
            if not found:
                raise InputError(f"no files match {raw!r}")
        else:
            raise InputError(f"capture not found: {raw}")
        for path in found:
            if path not in paths:
                paths.append(path)
    if len(paths) > config.MAX_INPUT_FILES:
        raise InputError(f"{len(paths)} files given; the limit is {config.MAX_INPUT_FILES}")
    return paths


def detect_format(path: Path) -> str:
    """Guess the capture format from the file's first bytes."""
    try:
        with path.open("rb") as handle:
            head = handle.read(_SNIFF_BYTES).decode("utf-8-sig", errors="replace")
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc.strerror}") from exc
    if har.looks_like_har(head):
        return "har"
    stripped = head.lstrip()
    if stripped.startswith("<") and "burpVersion" in head:
        return "burp"
    raise FormatDetectionError(
        f"cannot tell what format {path} is; pass --input-format ({'|'.join(config.INPUT_FORMATS)})"
    )


def load_captures(inputs: list[str], input_format: str | None = None) -> LoadResult:
    """Load and merge every capture. Transaction indices are unique across files."""
    merged = LoadResult()
    for path in expand_inputs(inputs):
        fmt = input_format or detect_format(path)
        loader = LOADERS.get(fmt)
        if loader is None:
            raise InputError(f"the {fmt} loader is not built yet (planned for phase 6): {path}")
        merged.extend(loader(path, len(merged.transactions)))
    if not merged.transactions:
        raise InputError("the capture(s) contain no HTTP transactions")
    return merged
