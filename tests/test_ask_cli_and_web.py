from __future__ import annotations

import http.client
import json
import threading
from collections.abc import Iterator
from typing import Any

import pytest
from typer.testing import CliRunner

from sapcx_log_analyzer import cli
from sapcx_log_analyzer.ask import AskSession, LogStore
from sapcx_log_analyzer.ask.web import AskApp, create_server, is_loopback
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
    serve = runner.invoke(cli.app, ["serve", EXPORT])
    assert serve.exit_code == cli.EXIT_LLM_ERROR


def test_serve_command_starts_and_stops(monkeypatch: pytest.MonkeyPatch) -> None:
    use_provider(monkeypatch, [])
    started: dict[str, Any] = {}

    class FakeServer:
        server_address = ("127.0.0.1", 9999)

        def serve_forever(self) -> None:
            raise KeyboardInterrupt

        def server_close(self) -> None:
            started["closed"] = True

    def fake_create(app: AskApp, host: str, port: int) -> FakeServer:
        started.update(app=app, host=host, port=port)
        return FakeServer()

    monkeypatch.setattr("sapcx_log_analyzer.ask.web.create_server", fake_create)
    result = runner.invoke(
        cli.app, ["serve", EXPORT, "--host", "0.0.0.0", "--port", "9999", "--allow-host", "VM:9999"]
    )
    assert result.exit_code == 0, result.output
    assert started["closed"] and started["port"] == 9999
    assert "vm:9999" in started["app"].allowed_hosts
    assert "anyone who can reach this address" in result.stderr.lower()
    assert "http://0.0.0.0:9999/" in result.stderr


def test_serve_reports_busy_port(monkeypatch: pytest.MonkeyPatch) -> None:
    use_provider(monkeypatch, [])

    def busy(app: AskApp, host: str, port: int) -> Any:
        raise OSError("Address already in use")

    monkeypatch.setattr("sapcx_log_analyzer.ask.web.create_server", busy)
    result = runner.invoke(cli.app, ["serve", EXPORT])
    assert result.exit_code == cli.EXIT_INPUT_ERROR
    assert "Address already in use" in result.stderr


# --- web server -----------------------------------------------------------------------


@pytest.fixture
def web() -> Iterator[tuple[int, ScriptedChatProvider]]:
    store = LogStore.load(FIXTURES / "transactions.ndjson", Settings())
    provider = ScriptedChatProvider([])
    app = AskApp(store, lambda: AskSession(store, provider, Settings()))
    server = create_server(app, "127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1], provider
    server.shutdown()
    server.server_close()


def request(
    port: int,
    method: str,
    path: str,
    body: Any = None,
    host: str | None = None,
    content_type: str = "application/json",
) -> tuple[int, dict[str, str], bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Host": host or f"127.0.0.1:{port}"}
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        headers["Content-Type"] = content_type
    conn.request(method, path, body=data, headers=headers)
    response = conn.getresponse()
    payload = response.read()
    conn.close()
    return response.status, dict(response.getheaders()), payload


def test_page_and_overview(web: tuple[int, ScriptedChatProvider]) -> None:
    port, _ = web
    status, headers, body = request(port, "GET", "/")
    assert status == 200
    assert b"Ask the logs" in body
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    status, _, body = request(port, "GET", "/api/overview", host=f"localhost:{port}")
    overview = json.loads(body)
    assert overview["records"] == 15
    assert overview["examples"][0] == "tx-243232"
    assert request(port, "GET", "/nope")[0] == 404


def test_ask_streams_steps_then_answer(web: tuple[int, ScriptedChatProvider]) -> None:
    port, provider = web
    provider._turns.extend(
        [tool_turn(("find_identifier", {"value": "tx-243232"})), text_turn("Root cause in #11.")]
    )
    status, _, body = request(port, "POST", "/api/conversations", {})
    assert status == 201
    conversation = json.loads(body)["id"]
    status, headers, body = request(
        port, "POST", "/api/ask", {"conversation": conversation, "question": "tx-243232?"}
    )
    assert status == 200
    assert headers["Content-Type"] == "application/x-ndjson"
    events = [json.loads(line) for line in body.splitlines()]
    assert events[0] == {"type": "step", "summary": "Looking up tx-243232", "error": False}
    assert events[-1]["type"] == "answer"
    assert events[-1]["refs"] == [11]
    assert events[-1]["complete"] is True

    status, _, body = request(port, "GET", "/api/records/11?scope=pod")
    record = json.loads(body)
    assert record["level"] == "ERROR"
    assert any(item["ref"] == 11 for item in record["context"])
    assert request(port, "GET", "/api/records/999")[0] == 404
    assert request(port, "GET", "/api/records/5?scope=galaxy")[0] == 404

    assert request(port, "POST", "/api/reset", {"conversation": conversation})[0] == 200
    assert request(port, "POST", "/api/reset", {"conversation": "unknown"})[0] == 404


def test_ask_reports_llm_errors_in_the_stream(web: tuple[int, ScriptedChatProvider]) -> None:
    port, provider = web
    provider._turns.append(LLMError("No Anthropic credentials found."))
    conversation = json.loads(request(port, "POST", "/api/conversations", {})[2])["id"]
    _, _, body = request(port, "POST", "/api/ask", {"conversation": conversation, "question": "q"})
    assert json.loads(body) == {"type": "error", "message": "No Anthropic credentials found."}


@pytest.mark.parametrize(
    ("kwargs", "status"),
    [
        ({"host": "evil.example:80"}, 421),  # DNS rebinding
        ({"content_type": "text/plain"}, 415),  # simple cross-site POST
        ({"body": b"{not json"}, 400),
        ({"body": b"[1, 2]"}, 400),
        ({"body": b"x" * (64 * 1024 + 1)}, 413),
    ],
)
def test_requests_are_guarded(
    web: tuple[int, ScriptedChatProvider], kwargs: dict[str, Any], status: int
) -> None:
    port, provider = web
    body = kwargs.pop("body", {"conversation": "x", "question": "q"})
    assert request(port, "POST", "/api/ask", body, **kwargs)[0] == status
    assert provider.requests == []


def test_ask_validation(web: tuple[int, ScriptedChatProvider]) -> None:
    port, _ = web
    assert request(port, "POST", "/api/ask", {"conversation": "x", "question": "q"})[0] == 404
    conversation = json.loads(request(port, "POST", "/api/conversations", {})[2])["id"]
    empty = request(port, "POST", "/api/ask", {"conversation": conversation, "question": " "})
    assert empty[0] == 400
    assert request(port, "POST", "/api/nope", {})[0] == 404
    assert request(port, "GET", "/", host="evil.example")[0] == 421


def test_busy_conversation_is_rejected(web: tuple[int, ScriptedChatProvider]) -> None:
    port, provider = web
    gate = threading.Event()
    release = threading.Event()

    def slow(messages: list[dict[str, Any]]) -> Any:
        gate.set()
        release.wait(5)
        return text_turn("done")

    provider._turns.append(slow)
    conversation = json.loads(request(port, "POST", "/api/conversations", {})[2])["id"]
    first: dict[str, Any] = {}
    worker = threading.Thread(
        target=lambda: first.update(
            result=request(
                port, "POST", "/api/ask", {"conversation": conversation, "question": "a"}
            )
        )
    )
    worker.start()
    assert gate.wait(5)
    second = request(port, "POST", "/api/ask", {"conversation": conversation, "question": "b"})
    release.set()
    worker.join(5)
    assert second[0] == 409
    assert first["result"][0] == 200


def test_conversation_limit_evicts_oldest() -> None:
    store = LogStore.load(FIXTURES / "transactions.ndjson", Settings())
    app = AskApp(store, lambda: AskSession(store, ScriptedChatProvider([]), Settings()))
    first = app.new_conversation()
    for _ in range(50):
        app.new_conversation()
    assert app.conversation(first) is None


def test_is_loopback() -> None:
    assert is_loopback("127.0.0.1") and is_loopback("localhost") and is_loopback("127.1.2.3")
    assert not is_loopback("0.0.0.0")
