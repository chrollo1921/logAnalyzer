"""A small local web chat for asking questions about one export.

It uses only the standard library HTTP server and is meant to run on the engineer's own
machine. Logs are only reachable by whoever can reach the port, so it binds to loopback by
default, rejects requests whose Host header is not the address it serves (DNS rebinding),
and accepts only JSON POSTs, which a foreign web page cannot send without a CORS preflight
that this server never approves.
"""

from __future__ import annotations

import json
import logging
import secrets
import threading
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import asdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Any
from urllib.parse import parse_qs, urlsplit

from sapcx_log_analyzer.ask.session import AskSession, ToolStep
from sapcx_log_analyzer.ask.store import LogStore, Scope
from sapcx_log_analyzer.ask.tools import format_record
from sapcx_log_analyzer.llm.provider import LLMError

log = logging.getLogger(__name__)

MAX_BODY_BYTES = 64 * 1024
MAX_SESSIONS = 50
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


class _Conversation:
    def __init__(self, session: AskSession) -> None:
        self.session = session
        self.lock = threading.Lock()


class AskApp:
    """State shared by all requests: the store and the open conversations."""

    def __init__(self, store: LogStore, session_factory: Callable[[], AskSession]) -> None:
        self.store = store
        self._factory = session_factory
        self._conversations: OrderedDict[str, _Conversation] = OrderedDict()
        self._lock = threading.Lock()
        self.allowed_hosts: set[str] = set()

    def new_conversation(self) -> str:
        conversation_id = secrets.token_urlsafe(16)
        with self._lock:
            self._conversations[conversation_id] = _Conversation(self._factory())
            while len(self._conversations) > MAX_SESSIONS:
                self._conversations.popitem(last=False)
        return conversation_id

    def conversation(self, conversation_id: str) -> _Conversation | None:
        with self._lock:
            conversation = self._conversations.get(conversation_id)
            if conversation is not None:
                self._conversations.move_to_end(conversation_id)
            return conversation

    def record_payload(self, ref: int, scope: Scope) -> dict[str, Any]:
        record = self.store.record(ref)
        context = self.store.context(ref, window_seconds=60, scope=scope, limit=40)
        return {
            "ref": ref,
            "text": format_record(self.store, ref, full=True),
            "level": record.level.value,
            "context": [
                {
                    "ref": r,
                    "text": format_record(self.store, r),
                    "level": self.store.record(r).level.value,
                }
                for r in context
            ],
        }


def make_handler(app: AskApp) -> type[BaseHTTPRequestHandler]:
    page = (
        resources.files("sapcx_log_analyzer.ask")
        .joinpath("static/index.html")
        .read_text(encoding="utf-8")
        .encode("utf-8")
    )

    class Handler(BaseHTTPRequestHandler):
        server_version = "sapcx-log-analyzer"

        def log_message(self, format: str, *args: Any) -> None:
            log.info("%s %s", self.address_string(), format % args)

        # --- routing ------------------------------------------------------------------

        def do_GET(self) -> None:
            if not self._host_ok():
                return
            url = urlsplit(self.path)
            if url.path == "/":
                self._send(HTTPStatus.OK, page, "text/html; charset=utf-8")
            elif url.path == "/api/overview":
                overview = app.store.overview()
                overview["examples"] = app.store.sample_identifiers()
                self._json(HTTPStatus.OK, overview)
            elif url.path.startswith("/api/records/"):
                self._record(url.path.removeprefix("/api/records/"), url.query)
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_POST(self) -> None:
            if not self._host_ok():
                return
            body = self._body()
            if body is None:
                return
            path = urlsplit(self.path).path
            if path == "/api/conversations":
                self._json(HTTPStatus.CREATED, {"id": app.new_conversation()})
            elif path == "/api/ask":
                self._ask(body)
            elif path == "/api/reset":
                conversation = app.conversation(str(body.get("conversation", "")))
                if conversation is None:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "unknown conversation"})
                    return
                with conversation.lock:
                    conversation.session.reset()
                self._json(HTTPStatus.OK, {"ok": True})
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        # --- endpoints ----------------------------------------------------------------

        def _record(self, ref_text: str, query: str) -> None:
            scope_name = parse_qs(query).get("scope", ["thread"])[0]
            try:
                ref = int(ref_text)
                scope = Scope(scope_name)
                payload = app.record_payload(ref, scope)
            except (ValueError, KeyError):
                self._json(HTTPStatus.NOT_FOUND, {"error": f"no record {ref_text}"})
                return
            self._json(HTTPStatus.OK, payload)

        def _ask(self, body: dict[str, Any]) -> None:
            question = str(body.get("question", "")).strip()
            conversation = app.conversation(str(body.get("conversation", "")))
            if conversation is None:
                self._json(HTTPStatus.NOT_FOUND, {"error": "unknown conversation"})
                return
            if not question or len(question) > 4000:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "ask a question of 1-4000 chars"})
                return
            if not conversation.lock.acquire(blocking=False):
                self._json(HTTPStatus.CONFLICT, {"error": "still answering the last question"})
                return
            try:
                # Newline-delimited JSON: progress events while tools run, then the answer.
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/x-ndjson")
                self.send_header("Cache-Control", "no-store")
                self._security_headers()
                self.end_headers()

                def on_step(step: ToolStep) -> None:
                    self._event({"type": "step", "summary": step.summary, "error": step.is_error})

                try:
                    answer = conversation.session.ask(question, on_step=on_step)
                except LLMError as exc:
                    self._event({"type": "error", "message": str(exc)})
                    return
                self._event(
                    {
                        "type": "answer",
                        "text": answer.text,
                        "refs": answer.refs,
                        "complete": answer.complete,
                        "steps": [asdict(step) for step in answer.steps],
                    }
                )
            except (BrokenPipeError, ConnectionResetError):
                log.info("Client went away before the answer was sent")
            finally:
                conversation.lock.release()

        # --- helpers ------------------------------------------------------------------

        def _host_ok(self) -> bool:
            host = (self.headers.get("Host") or "").lower()
            if host in app.allowed_hosts:
                return True
            self._json(HTTPStatus.MISDIRECTED_REQUEST, {"error": "unexpected Host header"})
            return False

        def _body(self) -> dict[str, Any] | None:
            content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip()
            if content_type != "application/json":
                self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "send application/json"})
                return None
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1
            if length < 0 or length > MAX_BODY_BYTES:
                self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "body too large"})
                return None
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid JSON"})
                return None
            if not isinstance(data, dict):
                self._json(HTTPStatus.BAD_REQUEST, {"error": "expected a JSON object"})
                return None
            return data

        def _event(self, payload: dict[str, Any]) -> None:
            self.wfile.write(json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n")
            self.wfile.flush()

        def _json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
            self._send(
                status, json.dumps(payload, ensure_ascii=False).encode("utf-8"), "application/json"
            )

        def _send(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self._security_headers()
            self.end_headers()
            self.wfile.write(body)

        def _security_headers(self) -> None:
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; "
                "frame-ancestors 'none'",
            )
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")

    return Handler


def create_server(app: AskApp, host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), make_handler(app))
    server.daemon_threads = True
    bound_port = server.server_address[1]
    names = {host, *LOOPBACK_HOSTS}
    app.allowed_hosts = {f"{name}:{bound_port}" for name in names} | {
        f"[{name}]:{bound_port}" for name in names if ":" in name
    }
    return server


def is_loopback(host: str) -> bool:
    return host in LOOPBACK_HOSTS or host.startswith("127.")
