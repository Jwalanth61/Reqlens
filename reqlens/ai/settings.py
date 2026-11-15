"""Read and check the AI settings before any capture is loaded (mirrors Inicon)."""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
from urllib.parse import urlsplit

from reqlens.ai.constants import CLI_PROVIDERS, MIN_BUDGET
from reqlens.errors import AIError

_MODEL_NAME = re.compile(r"^[\w.:/@-]{1,100}$")

# Environment variables checked for an API key, in order. Keys never come from flags.
_KEY_VARIABLES = {
    "anthropic": ("REQLENS_AI_KEY",),  # otherwise the Anthropic package finds its own
    "openai": ("REQLENS_AI_KEY", "OPENAI_API_KEY"),
}


def api_key(provider: str) -> str | None:
    """Return the API key for a provider from the environment, or None."""
    for name in _KEY_VARIABLES.get(provider, ()):
        value = os.environ.get(name)
        if value:
            return value
    return None


def check_settings(
    provider: str,
    model: str | None,
    base_url: str | None,
    budget: int,
    dry_run: bool = False,
) -> None:
    """Check the AI settings can work, so a bad setting fails before analysis starts.

    Raises:
        AIError: describing the first problem found.
    """
    if budget < MIN_BUDGET:
        raise AIError(f"--ai-budget must be at least {MIN_BUDGET}.")
    if dry_run:
        return  # a dry run contacts no provider, so nothing else is needed

    if model and not _MODEL_NAME.match(model):
        raise AIError("--ai-model contains characters that aren't allowed in a model name.")
    if base_url and urlsplit(base_url).scheme not in ("http", "https"):
        raise AIError("--ai-base-url must start with http:// or https://.")

    if provider in CLI_PROVIDERS:
        _check_cli(provider)
    elif provider == "anthropic":
        _check_anthropic()
    else:
        _check_openai_compatible(provider, model, base_url)


def _check_cli(provider: str) -> None:
    if not shutil.which(provider):
        raise AIError(
            f"The '{provider}' command isn't installed or isn't on PATH. "
            "Install it and sign in first."
        )


def _check_anthropic() -> None:
    # find_spec checks the package is installed without importing it: network-capable
    # code is only ever imported inside ai/providers/.
    if importlib.util.find_spec("anthropic") is None:
        raise AIError(
            "The anthropic provider needs the Anthropic package: pip install anthropic "
            "(or pip install reqlens[ai])"
        ) from None


def _check_openai_compatible(provider: str, model: str | None, base_url: str | None) -> None:
    if not model:
        raise AIError(
            f"--ai-model is required for the {provider} provider (or set REQLENS_AI_MODEL)."
        )
    if provider == "openai" and not base_url and not api_key("openai"):
        raise AIError(
            "Set REQLENS_AI_KEY (or OPENAI_API_KEY) to your API key for the openai provider."
        )
