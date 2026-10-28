from __future__ import annotations

from typing import Any

import pytest
from typer.testing import CliRunner

from sapcx_log_analyzer import cli
from sapcx_log_analyzer.config import Settings
from sapcx_log_analyzer.llm import LLMError
from tests.conftest import FIXTURES, ScriptedChatProvider, text_turn, tool_turn

runner = CliRunner()
EXPORT = str(FIXTURES / "transactions.ndjson")


def use_provider(monkeypatch: pytest.MonkeyPatch, turns: list[Any]) -> ScriptedChatProvider:
    provider = ScriptedChatProvider(turns)
    monkeypatch.setattr(cli, "build_chat_provider", lambda settings: provider)
    return provider


# --- ask command ----------------------------------------------------------------------


def test_ask_one_question(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = use_provider(
        monkeypatch,
        [tool_turn(("find_identifier", {"value": "tx-243232"})), text_turn("Pool exhausted, #11.")],
    )
    result = runner.invoke(cli.app, ["ask", EXPORT, "-q", "what went wrong with tx-243232?"])
    assert result.exit_code == 0, result.output
    assert "Pool exhausted, #11." in result.stdout
    assert "Looking up tx-243232" in result.stderr
    assert "Loaded 15 records" in result.stderr
    assert len(provider.requests) == 2


def test_ask_one_question_llm_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    use_provider(monkeypatch, [LLMError("No Anthropic credentials found.")])
    result = runner.invoke(cli.app, ["ask", EXPORT, "-q", "q", "--hide-steps"])
    assert result.exit_code == cli.EXIT_LLM_ERROR
    assert "No Anthropic credentials" in result.stderr


def test_ask_chat_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = use_provider(
        monkeypatch, [text_turn("First answer."), LLMError("boom"), text_turn("After reset.")]
    )
    session_input = "\n".join(
        ["first?", "", "second?", "/record 11", "/record nope", "/new", "third?", "/exit"]
    )
    result = runner.invoke(cli.app, ["ask", EXPORT, "--effort", "low"], input=session_input + "\n")
    assert result.exit_code == 0, result.output
    assert "what went wrong with tx-243232?" in result.stderr
    assert "First answer." in result.stdout
    assert "Claude could not answer: boom" in result.stderr
    assert "Failed to place order" in result.stdout  # /record 11
    assert "No record 'nope'" in result.stderr
    assert "After reset." in result.stdout
    assert len(provider.requests[-1]["messages"]) == 1  # /new cleared the history


def test_ask_ends_on_eof(monkeypatch: pytest.MonkeyPatch) -> None:
    use_provider(monkeypatch, [])
    result = runner.invoke(cli.app, ["ask", EXPORT], input="")
    assert result.exit_code == 0


def test_ask_rejects_bad_input(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    use_provider(monkeypatch, [])
    broken = tmp_path / "broken.json"
    broken.write_text("{not json")
    assert runner.invoke(cli.app, ["ask", str(broken)]).exit_code == cli.EXIT_INPUT_ERROR
    bad_effort = runner.invoke(cli.app, ["ask", EXPORT, "--effort", "extreme", "-q", "x"])
    assert bad_effort.exit_code != 0


def test_ask_provider_construction_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(settings: Settings) -> Any:
        raise LLMError("no client")

    monkeypatch.setattr(cli, "build_chat_provider", fail)
    result = runner.invoke(cli.app, ["ask", EXPORT, "-q", "x"])
    assert result.exit_code == cli.EXIT_LLM_ERROR
