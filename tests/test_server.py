"""The shared web app: uploads, sign-in, privacy between users and concurrent questions."""

from __future__ import annotations

import json
import queue
import socket
import threading
from collections.abc import Callable, Iterator
from concurrent.futures import Executor, Future
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from fastapi import FastAPI
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from sapcx_log_analyzer import cli
from sapcx_log_analyzer.ask import AskSession, LogStore
from sapcx_log_analyzer.config import Settings
from sapcx_log_analyzer.llm import LLMError
from sapcx_log_analyzer.server import app as server_app
from sapcx_log_analyzer.server import auth
from sapcx_log_analyzer.server.app import CSRF_VALUE, create_app
from sapcx_log_analyzer.server.auth import SessionStore, header_user
from sapcx_log_analyzer.server.uploads import Conversation, UploadRegistry
from tests.conftest import FIXTURES, ScriptedChatProvider, text_turn, tool_turn

EXPORT = FIXTURES / "transactions.ndjson"
TOKEN = "correct-horse-battery-staple"
runner = CliRunner()


class InlineExecutor(Executor):
    """Runs work at once, so an upload is ready when the upload request returns."""

    def submit(self, fn: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Future[Any]:
        future: Future[Any] = Future()
        future.set_result(fn(*args, **kwargs))
        return future


class ManualExecutor(Executor):
    """Holds work until the test runs it, to look at an upload while it is processing."""

    def __init__(self) -> None:
        self.tasks: list[tuple[Callable[..., Any], tuple[Any, ...]]] = []

    def submit(self, fn: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Future[Any]:
        self.tasks.append((fn, args))
        return Future()

    def run_all(self) -> None:
        while self.tasks:
            fn, args = self.tasks.pop(0)
            fn(*args)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def make_app(
    provider: ScriptedChatProvider | None = None,
    executor: Executor | None = None,
    clock: Callable[[], float] | None = None,
    preload: Path | None = None,
    **overrides: Any,
) -> FastAPI:
    settings = Settings(**overrides)
    chat = provider or ScriptedChatProvider([])
    registry = UploadRegistry(
        settings,
        lambda store: AskSession(store, chat, settings),
        executor or InlineExecutor(),
        **({"clock": clock} if clock else {}),
    )
    return create_app(settings, chat, registry=registry, preload=preload)


def client(app: FastAPI, **headers: str) -> TestClient:
    return TestClient(
        app, base_url="http://localhost", headers={"X-Requested-With": CSRF_VALUE, **headers}
    )


def sign_in(c: TestClient, name: str = "Ann", token: str = "") -> None:
    response = c.post("/api/session", json={"name": name, "token": token})
    assert response.status_code == 200, response.text


def upload(c: TestClient, data: bytes | None = None, name: str = "export.ndjson") -> Any:
    return c.post(
        "/api/uploads",
        params={"name": name},
        content=EXPORT.read_bytes() if data is None else data,
        headers={"Content-Type": "application/octet-stream"},
    )


def events(body: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in body.splitlines()]


# --- one person -----------------------------------------------------------------------


def test_page_config_and_health() -> None:
    c = client(make_app())
    page = c.get("/")
    assert page.status_code == 200 and "Ask the logs" in page.text
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert c.get("/healthz").json() == {"status": "ok"}
    assert c.get("/api/config").json()["auth"] == "none"
    assert c.get("/api/uploads").status_code == 401  # no session yet


def test_upload_then_ask_with_evidence() -> None:
    provider = ScriptedChatProvider(
        [tool_turn(("find_identifier", {"value": "tx-243232"})), text_turn("Root cause in #11.")]
    )
    c = client(make_app(provider))
    sign_in(c, "  Ann\tLee\x00 ")
    assert c.get("/api/me").json() == {"name": "Ann Lee"}

    uploaded = upload(c, name="../../tmp/incident.ndjson")
    assert uploaded.status_code == 202
    file = uploaded.json()
    assert file["filename"] == "incident.ndjson"
    assert file["status"] == "ready" and file["mine"] and not file["shared"]
    assert file["overview"]["records"] == 15 and file["overview"]["examples"][0] == "tx-243232"
    assert [u["id"] for u in c.get("/api/uploads").json()["uploads"]] == [file["id"]]

    base = f"/api/uploads/{file['id']}"
    conversation = c.post(f"{base}/conversations").json()["id"]
    answer = c.post(f"{base}/ask", json={"conversation": conversation, "question": "tx-243232?"})
    assert answer.headers["content-type"] == "application/x-ndjson"
    assert answer.headers["x-accel-buffering"] == "no"
    stream = events(answer.text)
    assert stream[0] == {"type": "step", "summary": "Looking up tx-243232", "error": False}
    assert stream[-1]["type"] == "answer" and stream[-1]["refs"] == [11]

    record = c.get(f"{base}/records/11", params={"scope": "pod"}).json()
    assert record["level"] == "ERROR" and any(r["ref"] == 11 for r in record["context"])
    assert c.get(f"{base}/records/999").status_code == 404
    assert c.get(f"{base}/records/5", params={"scope": "galaxy"}).status_code == 422

    assert c.delete(base).json() == {"ok": True}
    assert c.get(base).status_code == 404
    assert (
        c.post(f"{base}/ask", json={"conversation": conversation, "question": "q"}).status_code
        == 404
    )


def test_upload_is_processed_in_the_background_and_then_deleted() -> None:
    executor = ManualExecutor()
    c = client(make_app(executor=executor))
    sign_in(c)
    file = upload(c).json()
    assert file["status"] == "processing" and file["overview"] is None
    raw = executor.tasks[0][1][1]
    assert isinstance(raw, Path) and raw.exists() and raw.suffix == ".ndjson"
    conversation = c.post(f"/api/uploads/{file['id']}/conversations")
    assert conversation.status_code == 409 and "still being processed" in conversation.text

    executor.run_all()
    assert not raw.exists()  # the unredacted export is gone once parsed
    assert c.get(f"/api/uploads/{file['id']}").json()["status"] == "ready"


@pytest.mark.parametrize(
    ("data", "name", "error"),
    [
        (b"{not json", "broken.json", "Could not read broken.json: Not valid JSON"),
        (b"[]", "empty.json", "no log records found"),
        (
            b"id,name,price\n1,Shirt,9.99\n",
            "products.csv",
            'no log message column (expected "content", "message" or "Log message"; '
            'found "id", "name", "price")',
        ),
    ],
)
def test_unreadable_upload_reports_why(data: bytes, name: str, error: str) -> None:
    c = client(make_app())
    sign_in(c)
    file = upload(c, data, name).json()
    assert file["status"] == "failed" and error in file["error"]
    blocked = c.post(f"/api/uploads/{file['id']}/conversations")
    assert blocked.status_code == 409 and error in blocked.json()["detail"]


def test_csv_with_log_message_column_uploads() -> None:
    # Column names as in a Dynatrace notebook table export the owner uploaded.
    data = (
        b"timestamp,env,blueprint,loglevel,Log message,k8s.container.name\n"
        b'2026-10-22T06:10:47.972Z,uat,api,ERROR,"[x] ""GET /cart HTTP/1.1"" 500",platform\n'
    )
    c = client(make_app())
    sign_in(c)
    file = upload(c, data, "dummy-table-data-10MB.csv").json()
    assert file["status"] == "ready", file


def test_console_log_uploads() -> None:
    data = (
        b"INFO   | jvm 1    | main    | 2026/09/02 10:03:00.001 | "
        b"[2026-09-02T10:03:00,000] ERROR [hybrisHTTP3] [DefaultCartService] boom\n"
        b"INFO   | jvm 1    | main    | 2026/09/02 10:03:00.002 | \tat a.b.C.d(C.java:1)\n"
    )
    c = client(make_app())
    sign_in(c)
    file = upload(c, data, "console-20260902.log").json()
    assert file["status"] == "ready", file


def test_a_crash_while_loading_still_finishes_the_upload(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*args: Any, **kwargs: Any) -> LogStore:
        raise RuntimeError("bug")

    monkeypatch.setattr(LogStore, "load", explode)
    c = client(make_app())
    sign_in(c)
    file = upload(c).json()
    assert file["status"] == "failed" and file["error"] == "Could not read export.ndjson."


def test_size_and_quota_limits() -> None:
    app = make_app(server_max_upload_mb=1, server_max_uploads_per_user=1, server_max_uploads=2)
    ann, bob, cy = client(app), client(app), client(app)
    for person, name in ((ann, "Ann"), (bob, "Bob"), (cy, "Cy")):
        sign_in(person, name)
    assert upload(ann, b"x" * (1024 * 1024 + 1)).status_code == 413
    streamed = ann.post(
        "/api/uploads",
        params={"name": "big.json"},
        content=iter([b"x" * 600_000, b"x" * 600_000]),  # no Content-Length
    )
    assert streamed.status_code == 413
    assert upload(ann, b"").status_code == 400
    assert upload(ann).status_code == 202
    second = upload(ann)
    assert second.status_code == 429 and "remove one first" in second.json()["detail"]
    assert upload(bob).status_code == 202
    assert upload(cy).status_code == 503


# --- several people -------------------------------------------------------------------


def test_files_are_private_until_shared() -> None:
    provider = ScriptedChatProvider([text_turn("Answer for Bob.")])
    app = make_app(provider)
    ann, bob = client(app), client(app)
    sign_in(ann, "Ann")
    sign_in(bob, "Bob")
    file = upload(ann).json()
    base = f"/api/uploads/{file['id']}"

    assert bob.get("/api/uploads").json()["uploads"] == []
    assert bob.get(base).status_code == 404
    assert bob.post(f"{base}/conversations").status_code == 404

    shared = ann.patch(base, json={"shared": True}).json()
    assert shared["shared"] is True
    seen = bob.get("/api/uploads").json()["uploads"]
    assert [(u["owner"], u["mine"]) for u in seen] == [("Ann", False)]

    bobs = bob.post(f"{base}/conversations").json()["id"]
    answer = bob.post(f"{base}/ask", json={"conversation": bobs, "question": "q"})
    assert events(answer.text)[-1]["text"] == "Answer for Bob."
    # Ann cannot read or continue Bob's conversation, and Bob cannot manage Ann's file.
    assert ann.post(f"{base}/ask", json={"conversation": bobs, "question": "q"}).status_code == 404
    assert bob.patch(base, json={"shared": False}).status_code == 403
    assert bob.delete(base).status_code == 403

    ann.patch(base, json={"shared": False})
    assert bob.get(base).status_code == 404


def test_one_conversation_answers_one_question_at_a_time() -> None:
    entered, release = threading.Event(), threading.Event()

    def slow(messages: list[dict[str, Any]]) -> Any:
        entered.set()
        release.wait(5)
        return text_turn("done")

    app = make_app(ScriptedChatProvider([slow]))
    c = client(app)
    sign_in(c)
    base = f"/api/uploads/{upload(c).json()['id']}"
    conversation = c.post(f"{base}/conversations").json()["id"]
    first: dict[str, Any] = {}
    worker = threading.Thread(
        target=lambda: first.update(
            response=c.post(f"{base}/ask", json={"conversation": conversation, "question": "a"})
        )
    )
    worker.start()
    assert entered.wait(5)
    busy = c.post(f"{base}/ask", json={"conversation": conversation, "question": "b"})
    release.set()
    worker.join(5)
    assert busy.status_code == 409
    assert events(first["response"].text)[-1]["text"] == "done"


def test_questions_wait_for_a_free_slot() -> None:
    store = LogStore.load(EXPORT, Settings())
    session = AskSession(store, ScriptedChatProvider([text_turn("ok")]), Settings())
    conversation = Conversation("someone", session)
    conversation.lock.acquire()
    slots = threading.BoundedSemaphore(1)
    slots.acquire()  # another question holds the only slot
    events: queue.Queue[dict[str, Any] | None] = queue.Queue()
    server_app.start_answer(conversation, "q", slots, events.put)
    first = events.get(timeout=5)
    assert first is not None and first["summary"] == "Waiting for other questions"
    slots.release()
    answer = events.get(timeout=5)
    assert answer is not None and answer["text"] == "ok"
    assert events.get(timeout=5) is None
    assert conversation.lock.acquire(blocking=False)  # released for the next question


@pytest.mark.parametrize(
    ("turn", "message"),
    [
        (LLMError("No Anthropic credentials found."), "No Anthropic credentials found."),
        (RuntimeError("bug"), "Something went wrong on the server."),
    ],
)
def test_failures_end_the_stream_with_an_error(turn: Exception, message: str) -> None:
    c = client(make_app(ScriptedChatProvider([turn])))
    sign_in(c)
    base = f"/api/uploads/{upload(c).json()['id']}"
    conversation = c.post(f"{base}/conversations").json()["id"]
    answer = c.post(f"{base}/ask", json={"conversation": conversation, "question": "q"})
    assert events(answer.text) == [{"type": "error", "message": message}]


def test_idle_files_expire_but_preloaded_ones_stay() -> None:
    clock = Clock()
    app = make_app(clock=clock, preload=EXPORT, server_upload_idle_hours=1)
    c = client(app)
    sign_in(c)
    upload(c)
    assert len(c.get("/api/uploads").json()["uploads"]) == 2
    clock.now += 3601
    remaining = c.get("/api/uploads").json()["uploads"]
    assert [(u["owner"], u["mine"], u["shared"]) for u in remaining] == [("server", False, True)]
    assert c.delete(f"/api/uploads/{remaining[0]['id']}").status_code == 403


# --- sign-in --------------------------------------------------------------------------


def test_sign_in_with_the_team_access_key() -> None:
    app = make_app(server_auth="token", server_access_token=TOKEN)
    c = client(app)
    assert c.get("/api/me").status_code == 401
    wrong = c.post("/api/session", json={"name": "Ann", "token": "guess"})
    assert wrong.status_code == 401
    sign_in(c, "Ann", TOKEN)
    cookie = c.cookies.get(auth.SESSION_COOKIE)
    assert cookie and c.get("/api/me").json() == {"name": "Ann"}
    assert c.post("/api/logout").json() == {"ok": True}
    c.cookies.set(auth.SESSION_COOKIE, cookie)  # a signed-out session stays dead
    assert c.get("/api/me").status_code == 401


def test_cookies_are_secure_behind_https() -> None:
    c = client(make_app(), **{"X-Forwarded-Proto": "https"})
    response = c.post("/api/session", json={})
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "secure" in cookie


def test_identity_from_the_company_login_header() -> None:
    app = make_app(server_auth="header")
    anonymous = client(app)
    assert anonymous.get("/api/me").status_code == 401
    assert anonymous.post("/api/session", json={}).status_code == 400
    ann = client(app, **{"X-Forwarded-Email": "ann@example.com"})
    ann_again = client(app, **{"X-Forwarded-Email": "ANN@example.com"})
    bob = client(app, **{"X-Forwarded-Email": "bob@example.com"})
    assert ann.get("/api/me").json() == {"name": "ann@example.com"}
    file = upload(ann).json()
    assert ann_again.get(f"/api/uploads/{file['id']}").status_code == 200  # same person
    assert bob.get(f"/api/uploads/{file['id']}").status_code == 404


def test_requests_are_guarded() -> None:
    app = make_app()
    c = client(app)
    sign_in(c)
    base = f"/api/uploads/{upload(c).json()['id']}"
    conversation = c.post(f"{base}/conversations").json()["id"]
    bare = TestClient(app, base_url="http://localhost", cookies=c.cookies)
    assert bare.post(f"{base}/conversations").status_code == 403  # cross-site request
    assert bare.get(base).status_code == 200  # reading needs no header
    evil = TestClient(app, base_url="http://evil.example")
    assert evil.get("/").status_code == 400  # DNS rebinding
    ask = f"{base}/ask"
    assert c.post(ask, json={"conversation": conversation, "question": " "}).status_code == 400
    too_long = {"conversation": conversation, "question": "x" * 4001}
    assert c.post(ask, json=too_long).status_code == 422
    extra = {"conversation": conversation, "question": "q", "admin": True}
    assert c.post(ask, json=extra).status_code == 422


def test_allowed_host_names() -> None:
    settings = Settings(server_allowed_hosts=["logs.example.com"])
    app = create_app(settings, ScriptedChatProvider([]), allowed_hosts=["vm.internal:8765"])
    for host in ("logs.example.com", "vm.internal"):
        assert TestClient(app, base_url=f"http://{host}").get("/healthz").status_code == 200


def test_session_store_expires_and_evicts(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = Clock()
    sessions = SessionStore(60, clock)
    first = sessions.create("Ann")
    user = sessions.get(first)
    assert user is not None and user.name == "Ann" and first not in user.key
    clock.now += 61
    assert sessions.get(first) is None
    monkeypatch.setattr(auth, "MAX_SESSIONS", 2)
    oldest = sessions.create("a")
    sessions.create("b")
    sessions.create("c")
    assert sessions.get(oldest) is None


def test_header_user_and_file_names() -> None:
    assert header_user("") is None and header_user("x" * 321) is None
    assert server_app._clean_filename("C:\\exports\\prod.json") == "prod.json"
    assert server_app._clean_filename("\x00") == "export"
    assert server_app._hostname("VM.internal:8765") == "vm.internal"
    assert server_app._hostname("*.example.com") == "*.example.com"


# --- the serve command ----------------------------------------------------------------


@pytest.fixture
def started(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, Any]]:
    seen: dict[str, Any] = {}
    monkeypatch.setattr(cli, "build_chat_provider", lambda settings: ScriptedChatProvider([]))

    def run(self: uvicorn.Server, sockets: list[socket.socket] | None = None) -> None:
        seen["app"] = self.config.app
        seen["port"] = sockets[0].getsockname()[1] if sockets else None
        for sock in sockets or []:
            sock.close()

    monkeypatch.setattr(uvicorn.Server, "run", run)
    yield seen


def test_serve_on_a_team_server(started: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SAPCX_LA_SERVER_ACCESS_TOKEN", TOKEN)
    result = runner.invoke(
        cli.app,
        [
            "serve",
            str(EXPORT),
            "--host",
            "0.0.0.0",
            "--port",
            "0",
            "--auth",
            "token",
            "--allow-host",
            "logs.example.com",
        ],
    )
    assert result.exit_code == 0, result.output
    assert f"Open http://localhost:{started['port']}/  (team access key" in result.stderr
    files = started["app"].state.registry.visible(auth.User("x", "x"))
    assert [f.filename for f in files] == [EXPORT.name]


def test_serve_without_a_file_warns_about_host_names(started: dict[str, Any]) -> None:
    result = runner.invoke(
        cli.app, ["serve", "--host", "0.0.0.0", "--port", "0", "--auth", "header"]
    )
    assert result.exit_code == 0, result.output
    assert "--allow-host" in result.stderr and "company login" in result.stderr


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--host", "0.0.0.0"], "anyone who can reach 0.0.0.0"),
        (["--auth", "token"], "SAPCX_LA_SERVER_ACCESS_TOKEN"),
        ([str(FIXTURES / "transactions.ndjson"), "--input-format", "csv"], "Error:"),
    ],
)
def test_serve_refuses_unsafe_or_broken_setups(
    started: dict[str, Any], monkeypatch: pytest.MonkeyPatch, args: list[str], message: str
) -> None:
    monkeypatch.delenv("SAPCX_LA_SERVER_ACCESS_TOKEN", raising=False)
    result = runner.invoke(cli.app, ["serve", "--port", "0", *args])
    assert result.exit_code == cli.EXIT_INPUT_ERROR, result.output
    assert message in result.stderr
    assert "app" not in started


def test_serve_reports_a_busy_port_and_bad_options(started: dict[str, Any]) -> None:
    with socket.create_server(("127.0.0.1", 0)) as busy:
        port = busy.getsockname()[1]
        result = runner.invoke(cli.app, ["serve", "--port", str(port)])
    assert result.exit_code == cli.EXIT_INPUT_ERROR and "cannot listen" in result.stderr
    assert runner.invoke(cli.app, ["serve", "--auth", "magic"]).exit_code != 0
    assert runner.invoke(cli.app, ["serve", "--effort", "extreme"]).exit_code != 0


def test_serve_without_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(settings: Settings) -> Any:
        raise LLMError("no client")

    monkeypatch.setattr(cli, "build_chat_provider", fail)
    assert runner.invoke(cli.app, ["serve"]).exit_code == cli.EXIT_LLM_ERROR
