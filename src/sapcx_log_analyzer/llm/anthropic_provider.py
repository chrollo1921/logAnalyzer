"""Claude backend using the official Anthropic SDK."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, cast

import anthropic
from anthropic.types.beta import BetaMessageParam, BetaTextBlockParam, BetaToolUnionParam

from sapcx_log_analyzer.config import Settings
from sapcx_log_analyzer.llm.provider import (
    ChatResponse,
    LLMError,
    LLMRefusalError,
    LLMTruncatedError,
)

log = logging.getLogger(__name__)

FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AnthropicProvider:
    """Calls the Messages API with structured outputs.

    Credentials come from the environment (``ANTHROPIC_API_KEY`` or an ``ant auth``
    profile). The SDK retries 408/409/429/5xx and connection errors with backoff.
    Requests stream so large inputs and outputs never hit HTTP timeouts.
    """

    def __init__(self, settings: Settings, client: anthropic.Anthropic | None = None) -> None:
        self._settings = settings
        self._client = client or anthropic.Anthropic(
            timeout=settings.request_timeout_seconds,
            max_retries=settings.max_retries,
        )

    @property
    def model_name(self) -> str:
        return self._settings.model

    def complete_json(self, *, system: str, prompt: str, schema: dict[str, Any]) -> dict[str, Any]:
        settings = self._settings
        with (
            _api_errors(),
            self._client.beta.messages.stream(
                model=settings.model,
                max_tokens=settings.max_output_tokens,
                system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
                messages=[{"role": "user", "content": prompt}],
                output_config={
                    "effort": settings.effort,
                    "format": {"type": "json_schema", "schema": schema},
                },
                **self._fallback_args(),
            ) as stream,
        ):
            response = stream.get_final_message()

        _log_usage(response)
        if response.stop_reason == "refusal":
            raise LLMRefusalError(
                f"The model declined to analyze these logs (category={_refusal_category(response)})"
            )
        if response.stop_reason == "max_tokens":
            raise LLMTruncatedError(
                "The analysis hit max_output_tokens; raise SAPCX_LA_MAX_OUTPUT_TOKENS "
                "or lower SAPCX_LA_MAX_CHARS_PER_BATCH"
            )
        text = "".join(block.text for block in response.content if block.type == "text")
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise LLMError(f"Model returned invalid JSON: {exc.msg}") from exc
        if not isinstance(parsed, dict):
            raise LLMError("Model returned JSON that is not an object")
        return parsed

    def chat(
        self,
        *,
        system: list[str],
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> ChatResponse:
        settings = self._settings
        blocks: list[dict[str, Any]] = [{"type": "text", "text": text} for text in system]
        if blocks:
            # Tools render before system, so this breakpoint caches both for the session.
            blocks[-1]["cache_control"] = {"type": "ephemeral"}
        # Tool inputs stream as they are generated; the session validates every input.
        streamed_tools = [{**tool, "eager_input_streaming": True} for tool in tools]
        for attempt in range(2):
            try:
                with (
                    _api_errors(),
                    self._client.beta.messages.stream(
                        model=settings.model,
                        max_tokens=settings.max_output_tokens,
                        system=cast("list[BetaTextBlockParam]", blocks),
                        messages=cast("list[BetaMessageParam]", messages),
                        tools=cast("list[BetaToolUnionParam]", streamed_tools),
                        thinking={"type": "adaptive"},
                        output_config={"effort": settings.ask_effort},
                        # Caches the growing conversation, so each tool round re-reads it cheaply.
                        cache_control={"type": "ephemeral"},
                        **self._fallback_args(),
                    ) as stream,
                ):
                    response = stream.get_final_message()
                break
            except ValueError as exc:
                # The SDK could not parse a streamed tool input at all; ask again once.
                if attempt == 1:
                    raise LLMError(f"Model returned an unparseable tool call: {exc}") from exc
                log.warning("Retrying after an unparseable tool call: %s", exc)

        _log_usage(response)
        if response.stop_reason == "refusal":
            raise LLMRefusalError(
                f"The model declined to answer (category={_refusal_category(response)})"
            )
        if response.stop_reason == "max_tokens":
            raise LLMTruncatedError(
                "The answer hit max_output_tokens; raise SAPCX_LA_MAX_OUTPUT_TOKENS"
            )
        return ChatResponse(
            stop_reason=response.stop_reason or "end_turn",
            content=[block.to_dict(exclude_none=True) for block in response.content],
        )

    def _fallback_args(self) -> dict[str, Any]:
        if not self._settings.use_refusal_fallback:
            return {}
        # On a safety decline the API re-runs the request on a recommended model.
        return {"betas": [FALLBACK_BETA], "fallbacks": "default"}


@contextmanager
def _api_errors() -> Iterator[None]:
    """Turn SDK exceptions into LLMError with a message an operator can act on."""
    try:
        yield
    except anthropic.AuthenticationError as exc:
        raise LLMError(
            "Anthropic authentication failed. Set ANTHROPIC_API_KEY or run `ant auth login`."
        ) from exc
    except anthropic.RateLimitError as exc:
        raise LLMError(f"Rate limited by the Anthropic API after retries: {exc.message}") from exc
    except anthropic.APIStatusError as exc:
        raise LLMError(f"Anthropic API error {exc.status_code}: {exc.message}") from exc
    except anthropic.APIConnectionError as exc:
        raise LLMError(f"Could not reach the Anthropic API: {exc}") from exc
    except TypeError as exc:
        # The SDK raises a plain TypeError when it finds no credentials at all.
        if "authentication method" not in str(exc):
            raise
        raise LLMError(
            "No Anthropic credentials found. Set ANTHROPIC_API_KEY or run `ant auth login`."
        ) from exc


def _log_usage(response: Any) -> None:
    usage = response.usage
    log.debug(
        "LLM call done: model=%s stop=%s in=%s cache_read=%s out=%s request_id=%s",
        response.model,
        response.stop_reason,
        usage.input_tokens,
        getattr(usage, "cache_read_input_tokens", None),
        usage.output_tokens,
        getattr(response, "_request_id", None),
    )


def _refusal_category(response: Any) -> str | None:
    details = response.stop_details
    return getattr(details, "category", None) if details else None
