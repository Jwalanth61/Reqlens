"""Save AI answers on disk so re-running on an unchanged capture uses no tokens.

The cache key is a hash of everything that affects the answer: prompt version, provider,
model, base URL and the exact digest text. Digests use order-of-appearance aliases (T1, T2,
...) instead of per-run fingerprints, so the same capture gives the same digest every run.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from reqlens.ai.constants import PROMPT_VERSION


def cache_root() -> Path:
    """``$XDG_CACHE_HOME/reqlens`` or ``~/.cache/reqlens``."""
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "reqlens"


def cache_path(provider: str, model: str | None, base_url: str | None, digest_text: str) -> Path:
    """Return the cache file for this exact request."""
    fingerprint = json.dumps([PROMPT_VERSION, provider, model, base_url, digest_text])
    return cache_root() / f"ai-{hashlib.sha256(fingerprint.encode()).hexdigest()[:32]}.json"


def load(path: Path) -> dict[str, Any] | None:
    """Return the cached entry, or None if it is missing or unreadable."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def save(path: Path, data: dict[str, Any]) -> None:
    """Write a cache entry readable only by the current user. Failures are ignored."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
        os.chmod(path, 0o600)
    except OSError:
        pass  # caching is best-effort
