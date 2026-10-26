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
