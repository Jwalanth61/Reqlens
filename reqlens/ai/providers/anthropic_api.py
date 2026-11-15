"""Claude API provider, using the official Anthropic package (pip install anthropic)."""

from __future__ import annotations

from typing import Any

from reqlens.ai.constants import FALLBACK_MODELS, HTTP_TIMEOUT_SECONDS, MAX_OUTPUT_TOKENS
from reqlens.ai.prompt import RESULT_SCHEMA, SYSTEM_PROMPT
from reqlens.ai.providers.base import Answer, Usage
from reqlens.ai.settings import api_key
from reqlens.ai.text import one_line
from reqlens.errors import AIError

_FALLBACK_BETA = "server-side-fallback-2026-07-01"


def ask(model: str | None, base_url: str | None, digest_text: str) -> Answer:
    """Send the digest to the Claude API and return the answer.

    Raises:
        AIError: on any API, network or credential problem, or if the model declines.
    """
    import anthropic  # imported here so the package is only needed for this provider

    if not model:
        raise AIError("No model was given for the anthropic provider.")

    request: dict[str, Any] = {
        "model": model,
        "max_tokens": MAX_OUTPUT_TOKENS,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": digest_text}],
        # Low effort keeps reasoning, and so output tokens, small for this focused task.
        "output_config": {
            "effort": "low",
            "format": {"type": "json_schema", "schema": RESULT_SCHEMA},
        },
    }

    try:
        client = anthropic.Anthropic(**_client_options(base_url))
        if model in FALLBACK_MODELS:
            # Security data can trip a safety classifier by mistake.
            # This lets the API retry on its fallback model within the same call.
            response = client.beta.messages.create(
                betas=[_FALLBACK_BETA], fallbacks="default", **request
            )
        else:
            response = client.messages.create(**request)
    except anthropic.AuthenticationError:
        raise AIError(
            "Anthropic rejected the API key. Check REQLENS_AI_KEY or ANTHROPIC_API_KEY."
        ) from None
    except anthropic.PermissionDeniedError:
        raise AIError("This API key isn't allowed to use that model.") from None
    except anthropic.NotFoundError:
        raise AIError(f"Anthropic doesn't know the model '{model}'.") from None
    except anthropic.BadRequestError as error:
        raise AIError(f"Anthropic rejected the request: {one_line(error.message, 300)}") from None
    except anthropic.RateLimitError:
        raise AIError("Anthropic rate limit reached. Try again shortly.") from None
    except anthropic.APIStatusError as error:
        raise AIError(
            f"Anthropic API error {error.status_code}: {one_line(error.message, 300)}"
        ) from None
    except anthropic.APIConnectionError:
        raise AIError("Couldn't reach the Anthropic API. Check your network.") from None
    except anthropic.AnthropicError as error:
        raise AIError(f"Anthropic client error: {one_line(error, 300)}") from None

    return _to_answer(response)


def _client_options(base_url: str | None) -> dict[str, Any]:
    options: dict[str, Any] = {"timeout": HTTP_TIMEOUT_SECONDS}
    key = api_key("anthropic")
    if key:
        options["api_key"] = key
    if base_url:
        options["base_url"] = base_url
    return options


def _to_answer(response: Any) -> Answer:
    if response.stop_reason == "refusal":
        category = getattr(response.stop_details, "category", None) or "no category given"
        raise AIError(f"The model declined to analyse this data ({category}).")
    if response.stop_reason == "max_tokens":
        raise AIError("The model's answer was cut off at the output limit.")

    text = next((block.text for block in response.content if block.type == "text"), "")
    usage = response.usage
    tokens_in = (
        (usage.input_tokens or 0)
        + (getattr(usage, "cache_creation_input_tokens", 0) or 0)
        + (getattr(usage, "cache_read_input_tokens", 0) or 0)
    )
    return Answer(text, Usage(tokens_in, usage.output_tokens or 0), response.model)
