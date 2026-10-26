"""Opt-in smoke test against the real Anthropic API.

Run with ``SAPCX_LA_LIVE_TESTS=1 ANTHROPIC_API_KEY=... pytest -m live``. It sends the
redacted clusters and log lines of the synthetic fixture exports, never real data.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from sapcx_log_analyzer.config import Settings
from sapcx_log_analyzer.llm.anthropic_provider import AnthropicProvider
from sapcx_log_analyzer.pipeline import analyze

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("SAPCX_LA_LIVE_TESTS") != "1", reason="set SAPCX_LA_LIVE_TESTS=1 to run"
    ),
]


def test_real_model_analyses_fixture(csv_export: Path) -> None:
    settings = Settings(effort="low")
    report = analyze(csv_export, settings, AnthropicProvider(settings))
    assert report.analysis is not None
    assert report.analysis.findings
    covered = {cid for f in report.analysis.findings for cid in f.cluster_ids}
    assert covered <= {c.id for c in report.clusters}


def test_real_model_answers_a_transaction_question() -> None:
    from sapcx_log_analyzer.ask import AskSession, LogStore
    from tests.conftest import FIXTURES

    settings = Settings(ask_effort="low")
    store = LogStore.load(FIXTURES / "transactions.ndjson", settings)
    session = AskSession(store, AnthropicProvider(settings), settings)
    answer = session.ask("What went wrong with transaction tx-243232?")
    assert answer.steps, "the model should look the transaction up"
    assert "find_identifier" in {step.name for step in answer.steps}
    assert answer.refs
    assert "pool" in answer.text.lower() or "hikari" in answer.text.lower()
    follow_up = session.ask("Was tx-243233 affected too?")
    assert follow_up.text
