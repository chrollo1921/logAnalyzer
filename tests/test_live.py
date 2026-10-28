"""Opt-in smoke test against the real Anthropic API.

Run with ``SAPCX_LA_LIVE_TESTS=1 ANTHROPIC_API_KEY=... pytest -m live``. It sends the
redacted clusters and log lines of the synthetic fixture exports, never real data.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from sapcx_log_analyzer.ask import AskSession, LogStore
from sapcx_log_analyzer.config import Settings
from sapcx_log_analyzer.demo import write_demo_export
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


# Open questions about the whole export, against the synthetic demo and its planted
# incidents. Each entry lists groups of words; the answer must contain one word of
# every group. This is a check set to run when the prompt or the tools change.
OPEN_QUESTIONS = [
    ("What were the main problems in this file?", [("pool", "hikari"), ("payment", "psp")]),
    ("What happened just before the database outage?", [("sync", "catalog")]),
    ("Is checkout slower than usual at any point?", [("payment", "psp"), ("09:3",)]),
    ("Is there a pattern in the Solr problems?", [("solr", "index")]),
]


@pytest.fixture(scope="module")
def demo_store(tmp_path_factory: pytest.TempPathFactory) -> LogStore:
    path = tmp_path_factory.mktemp("live") / "demo.json"
    write_demo_export(path, size_mb=3, seed=7)
    return LogStore.load(path, Settings())


@pytest.mark.parametrize(("question", "expected"), OPEN_QUESTIONS)
def test_real_model_answers_open_questions(
    demo_store: LogStore, question: str, expected: list[tuple[str, ...]]
) -> None:
    settings = Settings(ask_effort="low")
    answer = AskSession(demo_store, AnthropicProvider(settings), settings).ask(question)
    text = answer.text.lower()
    for words in expected:
        assert any(word in text for word in words), (question, words, answer.text)
    assert answer.refs, "a broad answer still cites log lines"


def test_real_model_declines_an_unrelated_question(demo_store: LogStore) -> None:
    settings = Settings(ask_effort="low")
    answer = AskSession(demo_store, AnthropicProvider(settings), settings).ask(
        "What will the weather be in Munich tomorrow?"
    )
    assert "log" in answer.text.lower()
    assert len(answer.text) < 800
