"""Claude backend using the official Anthropic SDK."""

from __future__ import annotations

import json
import logging
from typing import Any

import anthropic

from sapcx_log_analyzer.config import Settings
from sapcx_log_analyzer.llm.provider import LLMError, LLMRefusalError, LLMTruncatedError

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
        extra: dict[str, Any] = {}
        if settings.use_refusal_fallback:
            # On a safety decline the API re-runs the request on a recommended model.
            extra = {"betas": [FALLBACK_BETA], "fallbacks": "default"}
        try:
            with self._client.beta.messages.stream(
                model=settings.model,
                max_tokens=settings.max_output_tokens,
                system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
                messages=[{"role": "user", "content": prompt}],
                output_config={
                    "effort": settings.effort,
                    "format": {"type": "json_schema", "schema": schema},
                },
                **extra,
            ) as stream:
                response = stream.get_final_message()
        except anthropic.AuthenticationError as exc:
            raise LLMError(
                "Anthropic authentication failed. Set ANTHROPIC_API_KEY or run `ant auth login`."
            ) from exc
        except anthropic.RateLimitError as exc:
            raise LLMError(
                f"Rate limited by the Anthropic API after retries: {exc.message}"
            ) from exc
        except anthropic.APIStatusError as exc:
            raise LLMError(f"Anthropic API error {exc.status_code}: {exc.message}") from exc
        except anthropic.APIConnectionError as exc:
            raise LLMError(f"Could not reach the Anthropic API: {exc}") from exc

        log.debug(
            "LLM call done: model=%s stop=%s in=%s out=%s request_id=%s",
            response.model,
            response.stop_reason,
            response.usage.input_tokens,
            response.usage.output_tokens,
            getattr(response, "_request_id", None),
        )
        if response.stop_reason == "refusal":
            details = response.stop_details
            category = getattr(details, "category", None) if details else None
            raise LLMRefusalError(f"The model declined to analyze these logs (category={category})")
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
