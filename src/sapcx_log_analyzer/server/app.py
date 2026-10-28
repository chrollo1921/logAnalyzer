"""The shared web app: upload a Dynatrace export in the browser, then ask questions about it.

Several people can use one server at once. Each upload is parsed into its own redacted
store, each person has their own conversations, and answers run in worker threads, at
most ``server_max_concurrent_questions`` at a time so that a busy team cannot exhaust the
API rate limit. State lives in memory, so run one process (it serves many users).

Protections besides sign-in (see ``auth.py``):

- Only listed Host headers are served, which stops DNS rebinding.
- Requests that change anything must carry an ``X-Requested-With`` header. A foreign web
  page cannot send it without a CORS preflight, which this app never approves, so
  cross-site requests fail; session cookies are ``SameSite=Strict`` as well.
- Uploads are size-checked while they stream in, written to a private temporary folder
  and deleted as soon as they are parsed.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import shutil
import tempfile
import threading
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from contextlib import asynccontextmanager
from dataclasses import asdict
from importlib import resources
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from sapcx_log_analyzer.ask import AskSession, LogStore, Scope, ToolStep
from sapcx_log_analyzer.ask.tools import format_record
from sapcx_log_analyzer.config import Settings
from sapcx_log_analyzer.ingest import ExportFormat
from sapcx_log_analyzer.llm.provider import ChatProvider, LLMError
from sapcx_log_analyzer.server.auth import (
    SESSION_COOKIE,
    SessionStore,
    User,
    header_user,
    token_matches,
)
from sapcx_log_analyzer.server.uploads import Conversation, UploadError, UploadRegistry

log = logging.getLogger(__name__)

CSRF_HEADER = "X-Requested-With"
CSRF_VALUE = "sapcx-log-analyzer"
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
QUEUE_TIMEOUT_SECONDS = 300
_SUFFIXES = {".json", ".ndjson", ".jsonl", ".csv"}
_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
        "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; "
        "frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SessionIn(_Body):
    name: str = Field(default="", max_length=60)
    token: str = Field(default="", max_length=500)


class ShareIn(_Body):
    shared: bool


class ConversationIn(_Body):
    conversation: str = Field(max_length=100)


class AskIn(ConversationIn):
    question: str = Field(min_length=1, max_length=4000)


def current_user(request: Request) -> User:
    settings: Settings = request.app.state.settings
    if settings.server_auth == "header":
        user = header_user(request.headers.get(settings.server_user_header, ""))
        if user is None:
            raise HTTPException(401, "Sign in through your company login first.")
        return user
    sessions: SessionStore = request.app.state.sessions
    user = sessions.get(request.cookies.get(SESSION_COOKIE, ""))
    if user is None:
        raise HTTPException(401, "Sign in first.")
    return user


CurrentUser = Annotated[User, Depends(current_user)]


def create_app(
    settings: Settings,
    provider: ChatProvider,
    *,
    preload: Path | None = None,
    preload_format: ExportFormat | None = None,
    allowed_hosts: Iterable[str] = (),
    registry: UploadRegistry | None = None,
) -> FastAPI:
    """Build the app; ``preload`` is loaded now, shared with everyone and never expires."""
    sessions = SessionStore(settings.server_session_hours * 3600)
    registry = registry or UploadRegistry(
        settings, lambda store: AskSession(store, provider, settings)
    )
    if preload is not None:
        registry.preload(preload, preload_format)
    slots = threading.BoundedSemaphore(settings.server_max_concurrent_questions)
    page = (
        resources.files("sapcx_log_analyzer.server")
        .joinpath("static/index.html")
        .read_text(encoding="utf-8")
    )
    upload_dir = Path(tempfile.mkdtemp(prefix="sapcx-uploads-"))  # readable by us only
    max_bytes = settings.server_max_upload_mb * 1024 * 1024
    too_large = f"The file is larger than {settings.server_max_upload_mb} MB."

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield
        registry.shutdown()
        shutil.rmtree(upload_dir, ignore_errors=True)

    app = FastAPI(
        title="SAP Commerce log chat",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.registry = registry
    app.state.sessions = sessions

    @app.middleware("http")
    async def guard(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        safe = request.method in ("GET", "HEAD")
        if not safe and request.headers.get(CSRF_HEADER) != CSRF_VALUE:
            response: Response = JSONResponse(
                {"detail": f"Send the {CSRF_HEADER} header."}, status_code=403
            )
        else:
            response = await call_next(request)
        response.headers.update(_SECURITY_HEADERS)
        return response

    # Added last, so it runs first.
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=sorted(
            {*LOOPBACK_HOSTS, *map(_hostname, [*settings.server_allowed_hosts, *allowed_hosts])}
        ),
    )

    @app.exception_handler(UploadError)
    async def upload_error(request: Request, exc: UploadError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=exc.status)

    # --- page and sign-in -------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        return HTMLResponse(page, headers={"Cache-Control": "no-store"})

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/config")
    def config() -> dict[str, Any]:
        return {
            "auth": settings.server_auth,
            "max_upload_mb": settings.server_max_upload_mb,
            "max_uploads_per_user": settings.server_max_uploads_per_user,
            "idle_hours": settings.server_upload_idle_hours,
        }

    @app.get("/api/me")
    def me(user: CurrentUser) -> dict[str, str]:
        return {"name": user.name}

    @app.post("/api/session")
    def sign_in(body: SessionIn, request: Request, response: Response) -> dict[str, str]:
        if settings.server_auth == "header":
            raise HTTPException(400, "Sign-in is handled by your company login.")
        if settings.server_auth == "token":
            expected = settings.server_access_token
            if expected is None or not token_matches(body.token, expected.get_secret_value()):
                log.warning("Rejected a sign-in with a wrong access key")
                raise HTTPException(401, "That access key is not right.")
        name = " ".join("".join(c if c.isprintable() else " " for c in body.name).split())
        name = name or "Guest"
        session_id = sessions.create(name)
        response.set_cookie(
            SESSION_COOKIE,
            session_id,
            max_age=int(settings.server_session_hours * 3600),
            path="/",
            httponly=True,
            samesite="strict",
            secure=_is_https(request),
        )
        log.info("%s signed in", name)
        return {"name": name}

    @app.post("/api/logout")
    def sign_out(request: Request, response: Response) -> dict[str, bool]:
        sessions.drop(request.cookies.get(SESSION_COOKIE, ""))
        response.delete_cookie(SESSION_COOKIE, path="/")
        return {"ok": True}

    # --- uploads ----------------------------------------------------------------------

    @app.get("/api/uploads")
    def list_uploads(user: CurrentUser) -> dict[str, Any]:
        return {"uploads": [upload.describe(user) for upload in registry.visible(user)]}

    @app.post("/api/uploads", status_code=202)
    async def upload(
        request: Request,
        user: CurrentUser,
        name: Annotated[str, Query(min_length=1, max_length=255)],
    ) -> dict[str, Any]:
        """The raw file is the request body, so nothing has to parse multipart forms."""
        registry.check_quota(user)
        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > max_bytes:
            raise HTTPException(413, too_large)
        filename = _clean_filename(name)
        suffix = Path(filename).suffix.lower()
        handle, temp = tempfile.mkstemp(
            dir=upload_dir, suffix=suffix if suffix in _SUFFIXES else ""
        )
        path = Path(temp)
        size = 0
        try:
            with os.fdopen(handle, "wb") as out:
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > max_bytes:
                        raise HTTPException(413, too_large)
                    out.write(chunk)
            if size == 0:
                raise HTTPException(400, "The file is empty.")
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return registry.add(user, filename, path, size).describe(user)

    @app.get("/api/uploads/{upload_id}")
    def get_upload(upload_id: str, user: CurrentUser) -> dict[str, Any]:
        return registry.get(user, upload_id).describe(user)

    @app.patch("/api/uploads/{upload_id}")
    def share(upload_id: str, body: ShareIn, user: CurrentUser) -> dict[str, Any]:
        return registry.set_shared(user, upload_id, body.shared).describe(user)

    @app.delete("/api/uploads/{upload_id}")
    def remove(upload_id: str, user: CurrentUser) -> dict[str, bool]:
        registry.remove(user, upload_id)
        return {"ok": True}

    # --- questions --------------------------------------------------------------------

    @app.post("/api/uploads/{upload_id}/conversations", status_code=201)
    def new_conversation(upload_id: str, user: CurrentUser) -> dict[str, str]:
        return {"id": registry.new_conversation(user, upload_id)}

    @app.post("/api/uploads/{upload_id}/ask")
    async def ask(upload_id: str, body: AskIn, user: CurrentUser) -> StreamingResponse:
        question = body.question.strip()
        if not question:
            raise HTTPException(400, "Ask a question.")
        conversation = registry.conversation(user, upload_id, body.conversation)
        if not conversation.lock.acquire(blocking=False):
            raise HTTPException(409, "Still answering the last question.")
        log.info("%s asked about %s (%d characters)", user.name, upload_id, len(question))
        # The stream waits on an asyncio queue, not in a worker thread, so any number of
        # people can wait for an answer without using up the server's thread pool.
        loop = asyncio.get_running_loop()
        events: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()

        def emit(event: dict[str, Any] | None) -> None:
            with contextlib.suppress(RuntimeError):  # the server is shutting down
                loop.call_soon_threadsafe(events.put_nowait, event)

        start_answer(conversation, question, slots, emit)

        async def stream() -> AsyncIterator[str]:
            while (event := await events.get()) is not None:
                yield json.dumps(event, ensure_ascii=False) + "\n"

        return StreamingResponse(
            stream(),
            media_type="application/x-ndjson",
            # Proxies such as nginx would otherwise hold the progress events back.
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    @app.get("/api/uploads/{upload_id}/records/{ref}")
    def record(
        upload_id: str, ref: int, user: CurrentUser, scope: Scope = Scope.THREAD
    ) -> dict[str, Any]:
        _, store = registry.ready(user, upload_id)
        try:
            return _record_payload(store, ref, scope)
        except KeyError as exc:
            raise HTTPException(404, f"No record #{ref}.") from exc

    return app


def start_answer(
    conversation: Conversation,
    question: str,
    slots: threading.BoundedSemaphore,
    emit: Callable[[dict[str, Any] | None], None],
) -> None:
    """Answer in a worker thread, passing progress and the answer to ``emit``, then None.

    The caller holds the conversation's lock; the worker always releases it, so a browser
    that goes away cannot leave the conversation locked.
    """

    def on_step(step: ToolStep) -> None:
        emit({"type": "step", "summary": step.summary, "error": step.is_error})

    def run() -> None:
        try:
            if not slots.acquire(blocking=False):
                emit({"type": "step", "summary": "Waiting for other questions", "error": False})
                if not slots.acquire(timeout=QUEUE_TIMEOUT_SECONDS):
                    emit({"type": "error", "message": "The server is busy; ask again soon."})
                    return
            try:
                answer = conversation.session.ask(question, on_step=on_step)
            finally:
                slots.release()
            emit(
                {
                    "type": "answer",
                    "text": answer.text,
                    "refs": answer.refs,
                    "complete": answer.complete,
                    "steps": [asdict(step) for step in answer.steps],
                }
            )
        except LLMError as exc:
            emit({"type": "error", "message": str(exc)})
        except Exception:
            log.exception("Answering a question failed")
            emit({"type": "error", "message": "Something went wrong on the server."})
        finally:
            conversation.lock.release()
            emit(None)

    threading.Thread(target=run, name="answer", daemon=True).start()


def _record_payload(store: LogStore, ref: int, scope: Scope) -> dict[str, Any]:
    record = store.record(ref)
    context = store.context(ref, window_seconds=60, scope=scope, limit=40)
    return {
        "ref": ref,
        "text": format_record(store, ref, full=True),
        "level": record.level.value,
        "context": [
            {"ref": r, "text": format_record(store, r), "level": store.record(r).level.value}
            for r in context
        ],
    }


def _clean_filename(name: str) -> str:
    base = Path(name.replace("\\", "/")).name
    cleaned = "".join(c for c in base if c.isprintable()).strip()
    return cleaned[:120] or "export"


def _hostname(host: str) -> str:
    """Host names without a port, as the Host header check compares them."""
    host = host.strip().lower()
    return host if host.startswith(("*", "[")) else host.split(":")[0]


def _is_https(request: Request) -> bool:
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    return proto.lower() == "https"


def is_loopback(host: str) -> bool:
    return host in LOOPBACK_HOSTS or host.startswith("127.")
