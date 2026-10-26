"""JSON Schemas for structured outputs, derived from the pydantic models."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

# Keywords structured outputs does not accept, or that add noise.
_DROP = {"default", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "title"}


def _tighten(node: Any) -> Any:
    if isinstance(node, dict):
        cleaned = {k: _tighten(v) for k, v in node.items() if k not in _DROP}
        if cleaned.get("type") == "object" and "properties" in cleaned:
            cleaned["additionalProperties"] = False
            cleaned["required"] = list(cleaned["properties"].keys())
        return cleaned
    if isinstance(node, list):
        return [_tighten(item) for item in node]
    return node


def output_schema(model: type[BaseModel]) -> dict[str, Any]:
    """A strict schema: every property required, no extra properties."""
    return _tighten(model.model_json_schema())  # type: ignore[no-any-return]
