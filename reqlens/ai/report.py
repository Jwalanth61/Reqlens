"""Turn the validated AI answer into report findings and a report section."""

from __future__ import annotations

from typing import Any

from reqlens.ai.constants import CLI_PROVIDERS
from reqlens.ai.digest import Digest
from reqlens.ai.prompt import SYSTEM_PROMPT
from reqlens.ai.text import estimate_tokens
from reqlens.group import Endpoint
from reqlens.knowledge.catalog import CATEGORY_REFERENCES
from reqlens.model import Concern, Confidence, Evidence, Finding
from reqlens.report import AISection


def to_findings(result: dict[str, Any], digest: Digest, endpoints: list[Endpoint]) -> list[Finding]:
    """One Finding per AI finding, with evidence pointing at the endpoints it named."""
    by_key = {endpoint.key: endpoint for endpoint in endpoints}
    findings = []
    for number, item in enumerate(result["findings"], 1):
        evidence = []
        for eid in item["endpoints"]:
            endpoint = by_key.get(digest.endpoint_ids.get(eid, ""))
            if endpoint is not None:
                tx = endpoint.representative
                evidence.append(Evidence(tx.index, endpoint.key, "endpoint", eid, ""))
        observed = item["observation"]
        if item["unknown_endpoints"]:
            observed += " (the model named endpoints that are not in the capture - verify)"
        concern = Concern(item["concern"])
        reference = CATEGORY_REFERENCES.get(item["category"])
        findings.append(
            Finding(
                check_id=f"AI-{number:02d}",
                title=item["title"],
                category=item["category"],
                concern=concern,
                why=item["why"] or "(no reason given by the model)",
                manual_test=item["manual_test"] or "(no manual test given by the model)",
                learning=item["learning"] or "(no lesson given by the model)",
                confidence=Confidence.INFORMATIONAL
                if concern is Concern.INFO
                else Confidence.POSSIBLE,
                evidence=evidence,
                references=[reference] if reference else [],
                source="ai",
                observed=observed,
                occurrences=len(evidence),
            )
        )
    return findings


def section(
    provider: str,
    model: str,
    status: str,
    message: str,
    digest: Digest | None = None,
    result: dict[str, Any] | None = None,
) -> AISection:
    """Build the report section describing the AI step."""
    return AISection(
        provider=provider,
        model=model,
        status=status,
        message=message,
        digest_tokens=digest.est_tokens if digest else 0,
        kept=digest.kept if digest else 0,
        dropped=digest.dropped if digest else 0,
        relationships=list(result["relationships"]) if result else [],
        anomalies=list(result["anomalies"]) if result else [],
        next_steps=list(result["next_steps"]) if result else [],
    )


def render_dry_run(digest: Digest, provider: str) -> str:
    """Terminal text showing exactly what would be sent, and its estimated size."""
    lines = [
        f"AI dry run: nothing was sent. Estimated input: about {digest.est_tokens} tokens "
        f"(instructions about {estimate_tokens(SYSTEM_PROMPT)}, the rest is the digest below).",
        f"{digest.kept} entries kept, {digest.dropped} left out for the budget.",
    ]
    if provider in CLI_PROVIDERS:
        lines.append(f"The {provider} CLI adds its own built-in instructions on top of this.")
    lines += ["", "--- digest ---", digest.text, "--- end ---"]
    return "\n".join(lines)
