"""Provider for OpenAI, Ollama and any other server with the same chat API.

Uses only the standard library, so it needs no extra package.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from reqlens.ai.constants import DEFAULT_BASE_URLS, HTTP_TIMEOUT_SECONDS, MAX_OUTPUT_TOKENS
from reqlens.ai.prompt import SYSTEM_PROMPT
from reqlens.ai.providers.base import Answer, Usage
from reqlens.ai.settings import api_key
from reqlens.ai.text import one_line
from reqlens.errors import AIError


def ask(provider: str, model: str | None, base_url: str | None, digest_text: str) -> Answer:
    """Send the digest to an OpenAI-compatible chat endpoint and return the answer.

    Raises:
        AIError: on any HTTP, network or response-format problem.
    """
    if not model:
        raise AIError(f"No model was given for the {provider} provider.")

    base = (base_url or DEFAULT_BASE_URLS[provider]).rstrip("/")
    request = urllib.request.Request(
        f"{base}/chat/completions",
        data=json.dumps(_request_body(provider, model, digest_text)).encode(),
        headers=_request_headers(provider),
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            data = json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as error:
        if error.code in (401, 403):
            raise AIError(
                f"The API rejected the key (HTTP {error.code}). Check REQLENS_AI_KEY."
            ) from None
        detail = one_line(error.read(2000).decode("utf-8", errors="replace"), 300)
        raise AIError(f"API error HTTP {error.code}: {detail}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        reason = one_line(getattr(error, "reason", error), 200)
        raise AIError(f"Couldn't reach {base}: {reason}") from None
    except ValueError:
        raise AIError("The API returned something that isn't JSON.") from None

    return _to_answer(data, model)


def _request_body(provider: str, model: str, digest_text: str) -> dict[str, Any]:
    body: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": digest_text},
        ],
    }
    if provider == "openai":
        body["max_completion_tokens"] = MAX_OUTPUT_TOKENS
        body["response_format"] = {"type": "json_object"}
    else:
        body["max_tokens"] = MAX_OUTPUT_TOKENS
    return body


def _request_headers(provider: str) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    key = api_key(provider)
    if key:
        headers["Authorization"] = f"Bearer {key}"
    return headers


def _to_answer(data: Any, model: str) -> Answer:
    try:
        text = data["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError):
        raise AIError("The API response had an unexpected shape.") from None
    if not text.strip():
        raise AIError("The model returned an empty answer (it may have hit the output limit).")

    usage = None
    raw_usage = data.get("usage")
    if isinstance(raw_usage, dict):
        usage = Usage(
            raw_usage.get("prompt_tokens", 0) or 0,
            raw_usage.get("completion_tokens", 0) or 0,
        )
    return Answer(text, usage, data.get("model") or model)
