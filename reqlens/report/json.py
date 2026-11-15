"""Machine-readable JSON report for pipelines.

Schema ``reqlens.report/1``: ``tool``, ``generated_at``, ``passive_notice``, ``summary``,
``counts``, ``findings``. Every string is sanitised (control characters removed).
"""

from __future__ import annotations

import dataclasses
import enum
import json as _json
from typing import Any

from reqlens.report import ReportData
from reqlens.sanitize import clean_text

SCHEMA = "reqlens.report/1"


def _clean(value: Any) -> Any:
    """Recursively convert dataclasses/enums and sanitise every string."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _clean(getattr(value, field.name)) for field in dataclasses.fields(value)
        }
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, dict):
        return {_clean(str(k)): _clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clean(item) for item in value]
    if isinstance(value, str):
        return clean_text(value)
    return value


def to_dict(data: ReportData) -> dict:
    """The report as plain JSON-compatible data."""
    summary = _clean(data.summary)
    return {
        "schema": SCHEMA,
        "tool": {"name": "reqlens", "version": summary.pop("tool_version")},
        "generated_at": summary.pop("generated_at"),
        "passive_notice": data.banner,
        "summary": summary,
        "counts": {"by_concern": data.concern_counts, "by_category": data.category_counts},
        "findings": [_clean(finding) for finding in data.findings],
    }


def render(data: ReportData) -> str:
    """Render the JSON report (UTF-8, indented, stable key order)."""
    return _json.dumps(to_dict(data), ensure_ascii=False, indent=2) + "\n"
