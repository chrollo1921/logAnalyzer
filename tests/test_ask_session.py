from __future__ import annotations

from typing import Any

import pytest

from sapcx_log_analyzer.ask import AskSession, LogStore, ToolStep
from sapcx_log_analyzer.config import Settings
from sapcx_log_analyzer.llm import ChatResponse, LLMError, LLMRefusalError
from tests.conftest import FIXTURES, ScriptedChatProvider, text_turn, tool_turn

ANSWER = (
    "Checkout tx-243232 failed because the database pool was exhausted.\n\n"
    "**What happened**: #5 started the checkout, #11 failed. See also #999 and &#39;."
)


@pytest.fixture(scope="module")
def store() -> LogStore:
    return LogStore.load(FIXTURES / "transactions.ndjson", Settings())


def results_in(message: dict[str, Any]) -> list[dict[str, Any]]:
    return [b for b in message["content"] if b.get("type") == "tool_result"]


def test_question_runs_tools_and_returns_cited_answer(store: LogStore) -> None:
    provider = ScriptedChatProvider(
        [
            tool_turn(("find_identifier", {"value": "tx-243232"})),
            tool_turn(("get_context", {"record": 5}), ("list_issues", {}), text="Checking."),
            text_turn(ANSWER),
        ]
    )
    session = AskSession(store, provider, Settings())
    seen: list[ToolStep] = []
    answer = session.ask("What went wrong with tx-243232?", on_step=seen.append)

    assert answer.text == ANSWER
    assert answer.refs == [5, 11]  # #999 is not a record, &#39; is not a ref
    assert answer.complete
    assert [s.name for s in answer.steps] == ["find_identifier", "get_context", "list_issues"]
    assert seen == answer.steps
    assert answer.steps[0].summary == "Looking up tx-243232"

    # System prompt first, export overview second (the cached block).
    system = provider.requests[0]["system"]
    assert "SAP Commerce Cloud" in system[0]
    assert '"records": 15' in system[1]
    assert {t["name"] for t in provider.requests[0]["tools"]} >= {"find_identifier", "get_context"}

    # Parallel calls get their results in one user message, matched by id.
    second_results = results_in(provider.requests[2]["messages"][-1])
    assert [r["tool_use_id"] for r in second_results] == [
        "toolu_get_context_0",
        "toolu_list_issues_1",
    ]
    first_result = results_in(provider.requests[1]["messages"][-1])[0]
    assert "tx-243232" in first_result["content"]
    assert "is_error" not in first_result

    # History is append-only, assistant turns echo back unchanged (thinking included).
    assert provider.requests[1]["messages"][1]["content"][0]["type"] == "thinking"
    assert [m["role"] for m in session.messages] == [
        "user",
        "assistant",
        "user",
        "assistant",
        "user",
        "assistant",
    ]
    assert session.model_name == "fake-chat-model"


def test_follow_up_keeps_history_and_reset_clears_it(store: LogStore) -> None:
    provider = ScriptedChatProvider(
        [text_turn("First."), text_turn("Second."), text_turn("Third.")]
    )
    session = AskSession(store, provider, Settings())
    session.ask("one")
    session.ask("two")
    assert [m["content"] for m in provider.requests[1]["messages"] if m["role"] == "user"] == [
        "one",
        "two",
    ]
    session.reset()
    session.ask("three")
    assert len(provider.requests[2]["messages"]) == 1


def test_question_is_redacted_before_sending(store: LogStore) -> None:
    provider = ScriptedChatProvider([text_turn("ok")])
    session = AskSession(store, provider, Settings())
    session.ask("Why did jane.doe@example.com get JSESSIONID=8F3AC2D1E0B9A7F6 errors?")
    sent = provider.requests[0]["messages"][0]["content"]
    assert "jane.doe" not in sent and "8F3AC2D1E0B9A7F6" not in sent
    # The session id maps to the same token as in the logs, so the model can look it up.
    token = store.redactor.link_token("SESSION", "8F3AC2D1E0B9A7F6")
    assert token in sent
    assert store.find(token).total == 2


def test_bad_tool_input_is_reported_back_to_the_model(store: LogStore) -> None:
    provider = ScriptedChatProvider(
        [tool_turn(("get_context", {"record": 999}), ("nope", {})), text_turn("Sorry.")]
    )
    answer = AskSession(store, provider, Settings()).ask("q")
    results = results_in(provider.requests[1]["messages"][-1])
    assert all(r["is_error"] for r in results)
    assert "No record #999" in results[0]["content"]
    assert "Unknown tool" in results[1]["content"]
    assert [s.is_error for s in answer.steps] == [True, True]


def test_tool_budget_forces_an_answer(store: LogStore) -> None:
    lookup = tool_turn(("find_identifier", {"value": "tx-243232"}))
    provider = ScriptedChatProvider([lookup, lookup, text_turn("Best effort answer citing #5.")])
    answer = AskSession(store, provider, Settings(ask_max_tool_rounds=1)).ask("q")
    assert answer.text == "Best effort answer citing #5."
    assert answer.complete
    budget = results_in(provider.requests[2]["messages"][-1])[0]
    assert budget["is_error"] and "budget" in budget["content"]


def test_model_that_never_stops_calling_tools(store: LogStore) -> None:
    lookup = tool_turn(("find_identifier", {"value": "tx-243232"}))
    provider = ScriptedChatProvider([lookup, lookup, lookup])
    session = AskSession(store, provider, Settings(ask_max_tool_rounds=1))
    answer = session.ask("q")
    assert not answer.complete
    assert "lookup budget" in answer.text
    # Every tool_use has a result, so a follow-up question is still a valid request.
    assert session.messages[-1]["role"] == "user"
    provider_follow = ScriptedChatProvider([text_turn("ok")])
    session._provider = provider_follow
    session.ask("follow up")


def test_failed_question_is_rolled_back(store: LogStore) -> None:
    provider = ScriptedChatProvider(
        [
            text_turn("first answer"),
            tool_turn(("find_identifier", {"value": "tx-243232"})),
            LLMRefusalError("declined"),
            text_turn("third answer"),
        ]
    )
    session = AskSession(store, provider, Settings())
    session.ask("first")
    with pytest.raises(LLMError):
        session.ask("second")
    assert len(session.messages) == 2
    session.ask("third")
    assert [m["content"] for m in provider.requests[-1]["messages"] if m["role"] == "user"] == [
        "first",
        "third",
    ]


def test_mid_output_fallback_drops_superseded_blocks(store: LogStore) -> None:
    turn = ChatResponse(
        stop_reason="end_turn",
        content=[
            {"type": "thinking", "thinking": "", "signature": "a"},
            {"type": "text", "text": "Partial "},
            {"type": "tool_use", "id": "t1", "name": "find_identifier", "input": {}},
            {"type": "fallback", "from": {"model": "x"}, "to": {"model": "y"}},
            {"type": "thinking", "thinking": "", "signature": "b"},
            {"type": "text", "text": "answer"},
        ],
    )
    session = AskSession(store, ScriptedChatProvider([turn]), Settings())
    answer = session.ask("q")
    assert answer.text == "Partial\n\nanswer"
    echoed = [b["type"] for b in session.messages[-1]["content"]]
    assert echoed == ["text", "fallback", "thinking", "text"]
