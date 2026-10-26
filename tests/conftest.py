from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from sapcx_log_analyzer.config import Settings
from sapcx_log_analyzer.models import LogLevel, LogRecord

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep developer env vars from leaking into tests."""
    import os

    for key in list(os.environ):
        if key.startswith("SAPCX_LA_") and key != "SAPCX_LA_LIVE_TESTS":
            monkeypatch.delenv(key)


@pytest.fixture
def csv_export() -> Path:
    return FIXTURES / "dynatrace_export.csv"


@pytest.fixture
def json_export() -> Path:
    return FIXTURES / "dynatrace_grail.json"


@pytest.fixture
def settings() -> Settings:
    return Settings()


class FakeProvider:
    """Records every call and answers from a callable, never touching the network."""

    def __init__(self, responder: Callable[[str, dict[str, Any]], dict[str, Any]]) -> None:
        self._responder = responder
        self.calls: list[dict[str, Any]] = []

    @property
    def model_name(self) -> str:
        return "fake-model"

    def complete_json(self, *, system: str, prompt: str, schema: dict[str, Any]) -> dict[str, Any]:
        self.calls.append({"system": system, "prompt": prompt, "schema": schema})
        return self._responder(prompt, schema)


def finding(cluster_ids: list[str], title: str = "Issue", severity: str = "high") -> dict[str, Any]:
    return {
        "title": title,
        "cluster_ids": cluster_ids,
        "component": "Database / Connection pool",
        "severity": severity,
        "confidence": 0.8,
        "summary": "Something broke.",
        "root_cause": "The pool is too small.",
        "recommended_actions": [{"type": "config", "description": "Raise db.pool.maxActive."}],
        "evidence": ["Connection is not available"],
    }


def responder_for_all_clusters(prompt: str, schema: dict[str, Any]) -> dict[str, Any]:
    """Answer with one finding that covers every cluster id in the prompt."""
    import json
    import re

    match = re.search(r"<clusters>\n(.*)\n</clusters>", prompt, re.S)
    ids = [c["id"] for c in json.loads(match.group(1))] if match else []
    props = schema["properties"]
    if "findings" in props and "summary" in props:
        return {
            "summary": "Database pool exhaustion caused API errors.",
            "overall_severity": "critical",
            "top_priorities": ["Fix the DB pool"],
            "findings": [finding(ids)],
        }
    if "findings" in props:
        return {"findings": [finding(ids)]}
    return {
        "summary": "Overall summary.",
        "overall_severity": "critical",
        "top_priorities": ["First", "Second"],
    }


@pytest.fixture
def fake_provider() -> FakeProvider:
    return FakeProvider(responder_for_all_clusters)


def make_record(message: str, **kwargs: Any) -> LogRecord:
    kwargs.setdefault("level", LogLevel.ERROR)
    return LogRecord(message=message, **kwargs)


class ScriptedChatProvider:
    """Plays back a list of assistant turns and records every request, offline.

    Each turn is either a ChatResponse, an exception to raise, or a callable that gets
    the request messages and returns a ChatResponse.
    """

    def __init__(self, turns: list[Any]) -> None:
        self._turns = list(turns)
        self.requests: list[dict[str, Any]] = []

    @property
    def model_name(self) -> str:
        return "fake-chat-model"

    def chat(
        self, *, system: list[str], messages: list[dict[str, Any]], tools: list[dict[str, Any]]
    ) -> Any:
        import copy

        self.requests.append(
            {"system": system, "messages": copy.deepcopy(messages), "tools": tools}
        )
        if not self._turns:
            raise AssertionError("the model was called more often than scripted")
        turn = self._turns.pop(0)
        if isinstance(turn, Exception):
            raise turn
        return turn(messages) if callable(turn) else turn


def tool_turn(*calls: tuple[str, dict[str, Any]], text: str | None = None) -> Any:
    from sapcx_log_analyzer.llm import ChatResponse

    content: list[dict[str, Any]] = [{"type": "thinking", "thinking": "", "signature": "sig"}]
    if text:
        content.append({"type": "text", "text": text})
    for index, (name, args) in enumerate(calls):
        content.append(
            {"type": "tool_use", "id": f"toolu_{name}_{index}", "name": name, "input": args}
        )
    return ChatResponse(stop_reason="tool_use", content=content)


def text_turn(text: str) -> Any:
    from sapcx_log_analyzer.llm import ChatResponse

    return ChatResponse(stop_reason="end_turn", content=[{"type": "text", "text": text}])
