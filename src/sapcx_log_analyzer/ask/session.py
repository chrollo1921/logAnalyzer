"""A conversation in which the model answers questions by calling the log tools.

The history is append-only: assistant turns are sent back exactly as the API returned
them (thinking blocks included), and a failed question is rolled back to the state
before it was asked, so the next request always extends a prefix the API has seen.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import resources
from typing import Any

from sapcx_log_analyzer.ask.store import LogStore
from sapcx_log_analyzer.ask.tools import TOOL_DEFINITIONS, ToolInputError, describe_call, run_tool
from sapcx_log_analyzer.config import Settings
from sapcx_log_analyzer.llm.provider import ChatProvider, ChatResponse, LLMError

log = logging.getLogger(__name__)

_REF = re.compile(r"(?<![\w&])#(\d{1,9})\b")
# Block types that belong to the attempt a mid-output fallback replaced.
_SUPERSEDED_BEFORE_FALLBACK = {"thinking", "redacted_thinking", "tool_use", "server_tool_use"}


def system_prompt() -> str:
    return (
        resources.files("sapcx_log_analyzer.ask")
        .joinpath("prompts/system.md")
        .read_text(encoding="utf-8")
    )


@dataclass
class ToolStep:
    name: str
    input: dict[str, Any]
    summary: str
    is_error: bool = False


@dataclass
class Answer:
    text: str
    steps: list[ToolStep] = field(default_factory=list)
    refs: list[int] = field(default_factory=list)
    complete: bool = True  # False when the tool budget ran out before a final answer


StepCallback = Callable[[ToolStep], None]


class AskSession:
    def __init__(self, store: LogStore, provider: ChatProvider, settings: Settings) -> None:
        self._store = store
        self._provider = provider
        self._settings = settings
        overview = json.dumps(store.overview(), indent=1, ensure_ascii=False)
        self._system = [
            system_prompt(),
            f"<export_overview>\n{overview}\n</export_overview>\n\n"
            f"<export_profile>\n{store.digest()}\n</export_profile>",
        ]
        self.messages: list[dict[str, Any]] = []

    @property
    def model_name(self) -> str:
        return self._provider.model_name

    def reset(self) -> None:
        self.messages = []

    def ask(self, question: str, on_step: StepCallback | None = None) -> Answer:
        """Answer one question, calling tools as the model asks for them."""
        checkpoint = len(self.messages)
        # The question may contain a pasted log line; mask it the same way as the logs so
        # session ids map to the same tokens.
        self.messages.append({"role": "user", "content": self._store.redact_question(question)})
        steps: list[ToolStep] = []
        try:
            return self._run(steps, on_step)
        except LLMError:
            del self.messages[checkpoint:]
            raise

    def _run(self, steps: list[ToolStep], on_step: StepCallback | None) -> Answer:
        rounds = 0
        warned = False
        while True:
            response = self._chat()
            content = _echo_content(response.content)
            self.messages.append({"role": "assistant", "content": content})
            calls = [block for block in content if block.get("type") == "tool_use"]
            if response.stop_reason != "tool_use" or not calls:
                text = _text_of(content)
                return Answer(text=text, steps=steps, refs=self._refs(text))
            rounds += 1
            exhausted = rounds > self._settings.ask_max_tool_rounds
            results = []
            for call in calls:
                step, result = self._run_call(call, run=not exhausted)
                steps.append(step)
                if on_step is not None:
                    on_step(step)
                results.append(result)
            # Every tool_use gets its result, so a follow-up question keeps the history valid.
            self.messages.append({"role": "user", "content": results})
            if exhausted:
                if warned:
                    text = _text_of(content) or (
                        "I could not finish the investigation within the lookup budget. "
                        "Ask a narrower question, or raise SAPCX_LA_ASK_MAX_TOOL_ROUNDS."
                    )
                    return Answer(text=text, steps=steps, refs=self._refs(text), complete=False)
                warned = True  # one more turn to answer with what it has

    def _chat(self) -> ChatResponse:
        return self._provider.chat(
            system=self._system, messages=self.messages, tools=TOOL_DEFINITIONS
        )

    def _run_call(self, call: dict[str, Any], run: bool) -> tuple[ToolStep, dict[str, Any]]:
        name = str(call.get("name", ""))
        raw = call.get("input") or {}
        step = ToolStep(
            name=name,
            input=raw if isinstance(raw, dict) else {},
            summary=describe_call(name, raw),
        )
        if not run:
            step.is_error = True
            return step, _budget_result(call)
        try:
            output = run_tool(self._store, name, raw, self._settings.ask_max_tool_result_chars)
        except ToolInputError as exc:
            log.info("Tool %s rejected input %r: %s", name, raw, exc)
            step.is_error = True
            return step, {
                "type": "tool_result",
                "tool_use_id": call["id"],
                "content": f"Error: {exc}",
                "is_error": True,
            }
        return step, {"type": "tool_result", "tool_use_id": call["id"], "content": output}

    def _refs(self, text: str) -> list[int]:
        refs: list[int] = []
        for match in _REF.finditer(text):
            ref = int(match.group(1))
            if 1 <= ref <= len(self._store) and ref not in refs:
                refs.append(ref)
        return refs


def _budget_result(call: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "tool_result",
        "tool_use_id": call["id"],
        "content": "Lookup budget for this question is used up. Answer now with what you have.",
        "is_error": True,
    }


def _echo_content(content: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop the parts of a declined attempt that a mid-output fallback replaced."""
    boundary = max(
        (i for i, block in enumerate(content) if block.get("type") == "fallback"), default=-1
    )
    if boundary < 0:
        return content
    return [
        block
        for i, block in enumerate(content)
        if i > boundary or block.get("type") not in _SUPERSEDED_BEFORE_FALLBACK
    ]


def _text_of(content: list[dict[str, Any]]) -> str:
    return "\n\n".join(
        str(block.get("text", "")).strip()
        for block in content
        if block.get("type") == "text" and str(block.get("text", "")).strip()
    )
