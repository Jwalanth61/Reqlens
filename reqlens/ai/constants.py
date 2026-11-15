"""Settings for the optional AI analysis step (mirrors Inicon's ai/constants.py)."""

from __future__ import annotations

from reqlens.knowledge.catalog import CATEGORIES as _CATALOG_CATEGORIES

# Bump when the prompt or digest format changes, so old cached answers are not reused.
PROMPT_VERSION = "1"

API_PROVIDERS = ("anthropic", "openai", "ollama")
CLI_PROVIDERS = ("codex", "claude", "gemini")
PROVIDERS = API_PROVIDERS + CLI_PROVIDERS

DEFAULT_MODELS = {"anthropic": "claude-opus-5-5"}
DEFAULT_BASE_URLS = {
    "openai": "https://api.openai.com/v1",
    "ollama": "http://localhost:11434/v1",
}

# Claude models that accept the server-side refusal fallback.
FALLBACK_MODELS = frozenset(
    {
        "claude-opus-5-5",
        "claude-opus-5",
        "claude-sonnet-5-5",
        "claude-fable-5-2",
        "claude-fable-5-1",
    }
)

# Token limits. Input is an estimate; output is a hard cap that includes model reasoning.
DEFAULT_BUDGET = 3000
MIN_BUDGET = 800
MAX_OUTPUT_TOKENS = 4096

HTTP_TIMEOUT_SECONDS = 120
CLI_TIMEOUT_SECONDS = 180

# Values the model may use in a finding. Anything else is normalised.
CATEGORIES = tuple(_CATALOG_CATEGORIES)
CONCERNS = ("high", "medium", "low", "info")
MAX_FINDINGS = 8
MAX_LIST_ITEMS = 5
