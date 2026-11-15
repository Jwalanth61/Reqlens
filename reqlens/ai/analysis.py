"""Run the whole AI step: condense, check the cache, ask the model, validate, report."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from reqlens.ai import cache
from reqlens.ai.constants import DEFAULT_BUDGET, DEFAULT_MODELS
from reqlens.ai.digest import build_digest
from reqlens.ai.report import render_dry_run, section, to_findings
from reqlens.ai.result import parse_result
from reqlens.errors import AIError
from reqlens.group import Endpoint
from reqlens.model import Finding, Transaction
from reqlens.report import AISection


@dataclass
class AIOutcome:
    """Everything the AI step produced."""

    findings: list[Finding] = field(default_factory=list)
    section: AISection | None = None
    dry_run_text: str = ""


def run(
    transactions: list[Transaction],
    endpoints: list[Endpoint],
    local_findings: list[Finding],
    scope: list[str],
    *,
    provider: str,
    model: str | None = None,
    base_url: str | None = None,
    budget: int = DEFAULT_BUDGET,
    dry_run: bool = False,
    use_cache: bool = True,
) -> AIOutcome:
    """Analyse the redacted capture. Never raises AIError: failures go in the section, so
    the local report is always written. (A SafetyViolation still stops the run.)"""
    model = model or DEFAULT_MODELS.get(provider) or f"{provider} default"
    try:
        digest = build_digest(transactions, endpoints, local_findings, scope, budget)
    except AIError as error:
        return AIOutcome(section=section(provider, model, "error", str(error)))
    if digest is None:
        return AIOutcome(
            section=section(
                provider, model, "nothing-to-send", "No endpoints to analyse, so nothing was sent."
            )
        )
    if dry_run:
        return AIOutcome(
            section=section(provider, model, "dry-run", "Dry run: nothing was sent.", digest),
            dry_run_text=render_dry_run(digest, provider),
        )

    ids = set(digest.endpoint_ids)
    cache_file = cache.cache_path(provider, model, base_url, digest.text)
    if use_cache:
        entry = cache.load(cache_file)
        if entry and isinstance(entry.get("result"), dict):
            try:
                # Re-validate: the cache file is on disk and could have been edited.
                result = parse_result(json.dumps(entry["result"]), ids)
            except AIError:
                result = None
            if result is not None:
                answered_by = str(entry.get("model") or model)
                return AIOutcome(
                    findings=to_findings(result, digest, endpoints),
                    section=section(
                        provider,
                        answered_by,
                        "cached",
                        "Answer came from the local cache: no tokens used this run.",
                        digest,
                        result,
                    ),
                )

    from reqlens.ai.providers import call_model  # network code is imported only here

    try:
        answer = call_model(
            provider, None if model.endswith(" default") else model, base_url, digest.text
        )
        result = parse_result(answer.text, ids)
    except AIError as error:
        return AIOutcome(
            section=section(provider, model, "error", f"AI analysis failed: {error}", digest)
        )

    if use_cache:
        saved = datetime.now(timezone.utc).isoformat(timespec="seconds")
        cache.save(cache_file, {"result": result, "model": answer.model, "saved": saved})
    usage = (
        f"Tokens used: {answer.usage.input} in, {answer.usage.output} out."
        if answer.usage
        else "This provider doesn't report token usage."
    )
    return AIOutcome(
        findings=to_findings(result, digest, endpoints),
        section=section(provider, answer.model, "answered", usage, digest, result),
    )
