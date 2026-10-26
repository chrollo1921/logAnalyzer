"""The interface every LLM backend implements."""

from __future__ import annotations

from dataclasses import dataclass
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


@dataclass
class ChatResponse:
    """One assistant turn, as plain API content blocks that can be sent back unchanged."""

    stop_reason: str
    content: list[dict[str, Any]]


class ChatProvider(Protocol):
    """Multi-turn chat with client-side tools, used by the interactive question mode.

    ``system`` blocks are sent in order and the last one is cached, so put stable text first.
    Raises LLMRefusalError on a decline and LLMTruncatedError when the output hit the cap.
    """

    @property
    def model_name(self) -> str: ...

    def chat(
        self,
        *,
        system: list[str],
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> ChatResponse: ...
