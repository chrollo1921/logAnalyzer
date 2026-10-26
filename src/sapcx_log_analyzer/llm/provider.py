"""The interface every LLM backend implements."""

from __future__ import annotations

from typing import Any, Protocol


class LLMError(RuntimeError):
    """The model call failed or returned something unusable."""


class LLMRefusalError(LLMError):
    """The model declined the request."""


class LLMTruncatedError(LLMError):
    """The response hit the output token limit before the JSON was complete."""


class LLMProvider(Protocol):
    """Returns one JSON object that conforms to ``schema``."""

    @property
    def model_name(self) -> str: ...

    def complete_json(
        self, *, system: str, prompt: str, schema: dict[str, Any]
    ) -> dict[str, Any]: ...
