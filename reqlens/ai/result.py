"""Turn the model's answer into validated data. Its shape and content are never trusted.

Besides Inicon's shape checks (types, enums, list and length caps, control characters),
reqlens removes anything that looks like runnable code: fenced code blocks, inline code,
and lines that read like shell commands or scripts. The AI may explain and suggest one
manual step; it may not hand over an exploit.
"""

from __future__ import annotations

import json
import re
from typing import Any

from reqlens.ai.constants import CATEGORIES, CONCERNS, MAX_FINDINGS, MAX_LIST_ITEMS
from reqlens.ai.text import clean, one_line
from reqlens.errors import AIError

_LIST_KEYS = ("relationships", "anomalies", "next_steps")
_TEXT_FIELDS = ("observation", "why", "manual_test", "learning")
CODE_REMOVED = "[code removed by reqlens]"

_FENCE = re.compile(r"```.*?(```|$)", re.DOTALL)
_INLINE_CODE = re.compile(r"`[^`\n]{25,}`")
_COMMAND_LINE = re.compile(
    r"^\s*(\$\s|>\s|#!|curl\s|wget\s|python3?\s|py\s|node\s|bash\s|sh\s|zsh\s|powershell\b|"
    r"pwsh\b|cmd\s|nc\s|ncat\s|sqlmap\b|ffuf\b|hydra\b|nmap\b|burp\w*\s|for\s+\w+\s+in\b|"
    r"while\s|import\s|from\s+\w+\s+import|def\s|function\s|<script|requests\.|fetch\(|"
    r"xhr\.|await\s)",
    re.IGNORECASE,
)
_INLINE_SCRIPT = re.compile(r"<\s*script\b|javascript:|on\w+\s*=\s*['\"]", re.IGNORECASE)


def strip_code(text: str) -> str:
    """Remove code blocks, long inline code and command-like lines from model text."""
    text = clean(text)
    text = _FENCE.sub(CODE_REMOVED, text)
    text = _INLINE_CODE.sub(CODE_REMOVED, text)
    kept = []
    for line in text.splitlines():
        if _COMMAND_LINE.match(line) or _INLINE_SCRIPT.search(line):
            if not kept or kept[-1] != CODE_REMOVED:
                kept.append(CODE_REMOVED)
            continue
        kept.append(line)
    return "\n".join(kept)


def _text(value: Any, limit: int) -> str:
    return one_line(strip_code(str(value if value is not None else "")), limit)


def parse_result(text: str, endpoint_ids: set[str] | None = None) -> dict[str, Any]:
    """Return the answer as a dict with a fixed shape.

    Unknown categories and concerns are normalised, lists and strings are capped, control
    characters and code are removed, and endpoint ids not in the digest are dropped.

    Raises:
        AIError: the answer contains no usable JSON object.
    """
    data = _load_json_object(text.strip())
    findings = []
    raw_findings = data.get("findings")
    for item in (raw_findings if isinstance(raw_findings, list) else [])[:MAX_FINDINGS]:
        if not isinstance(item, dict) or not str(item.get("title", "")).strip():
            continue
        category, concern = item.get("category"), item.get("concern")
        endpoints = _strings(item.get("endpoints"), 10, 20)
        unknown = [e for e in endpoints if endpoint_ids is not None and e not in endpoint_ids]
        finding = {
            "title": _text(item["title"], 160),
            "category": category if category in CATEGORIES else "OTHER",
            "concern": concern if concern in CONCERNS else "low",
            "endpoints": [e for e in endpoints if e not in unknown],
            "unknown_endpoints": unknown,
        }
        for field in _TEXT_FIELDS:
            finding[field] = _text(item.get(field, ""), 600)
        findings.append(finding)

    result: dict[str, Any] = {"findings": findings}
    for key in _LIST_KEYS:
        result[key] = [_text(item, 300) for item in _strings(data.get(key), MAX_LIST_ITEMS, 600)]
        result[key] = [item for item in result[key] if item]
    return result


def _load_json_object(text: str) -> dict[str, Any]:
    """Parse a JSON object, tolerating extra text or code fences around it."""
    try:
        data = json.loads(text)
    except ValueError:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            raise AIError("The model didn't return JSON.") from None
        try:
            data = json.loads(text[start : end + 1])
        except ValueError:
            raise AIError("The model returned invalid JSON.") from None
    if not isinstance(data, dict):
        raise AIError("The model's JSON wasn't an object.")
    return data


def _strings(value: Any, max_items: int, max_length: int) -> list[str]:
    if not isinstance(value, list):
        return []
    return [
        str(item)[:max_length]
        for item in value[:max_items]
        if isinstance(item, (str, int, float)) and str(item).strip()
    ]
