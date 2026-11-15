"""The ways reqlens can reach an AI model. This package holds the ONLY outbound network
code in reqlens, and it is imported only when ``--ai`` is set (a test enforces both).

anthropic_api      Claude API, through the official Anthropic package
openai_compatible  OpenAI, Ollama or any server with the same chat API
cli_tools          Official command-line tools you are already signed in to
"""

from __future__ import annotations

from reqlens.ai.providers.base import Answer, Usage

__all__ = ["Answer", "Usage", "call_model"]


def call_model(provider: str, model: str | None, base_url: str | None, digest_text: str) -> Answer:
    """Send the digest to the chosen provider and return its answer.

    Raises:
        AIError: the provider could not be reached or did not give a usable answer.
    """
    if provider == "anthropic":
        from reqlens.ai.providers import anthropic_api

        return anthropic_api.ask(model, base_url, digest_text)
    if provider in ("openai", "ollama"):
        from reqlens.ai.providers import openai_compatible

        return openai_compatible.ask(provider, model, base_url, digest_text)
    from reqlens.ai.providers import cli_tools

    return cli_tools.ask(provider, model, digest_text)
