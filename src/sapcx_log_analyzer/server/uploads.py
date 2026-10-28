"""Uploaded exports, each loaded into its own store, and the conversations about them.

Everything lives in memory: an upload is parsed and redacted in the background, the raw
file is deleted as soon as it has been read, and a file nobody has used for
``server_upload_idle_hours`` is dropped. Files are private to the person who uploaded
them until they share them with everyone signed in.
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from concurrent.futures import Executor, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from sapcx_log_analyzer.ask import AskSession, LogStore
from sapcx_log_analyzer.config import Settings
from sapcx_log_analyzer.ingest import ExportFormat
from sapcx_log_analyzer.server.auth import SYSTEM, User

log = logging.getLogger(__name__)

MAX_CONVERSATIONS_PER_UPLOAD = 200
NO_RECORDS = "no log records found; export JSON, NDJSON or CSV from Dynatrace"


class UploadStatus(StrEnum):
    PROCESSING = "processing"
    READY = "ready"
    FAILED = "failed"


class UploadError(Exception):
    """A request the registry refuses; ``status`` is the HTTP status to answer with."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class Conversation:
    owner: str
    session: AskSession
    lock: threading.Lock = field(default_factory=threading.Lock)


@dataclass
class Upload:
    id: str
    owner: User
    filename: str
    size: int
    created: datetime
    last_used: float
    status: UploadStatus = UploadStatus.PROCESSING
    shared: bool = False
    pinned: bool = False  # given on the command line: never expires
    error: str | None = None
    store: LogStore | None = None
    overview: dict[str, Any] | None = None
    conversations: OrderedDict[str, Conversation] = field(default_factory=OrderedDict)

    def visible_to(self, user: User) -> bool:
        return self.shared or self.owner.key == user.key

    def describe(self, user: User) -> dict[str, Any]:
        return {
            "id": self.id,
            "filename": self.filename,
            "size": self.size,
            "status": self.status.value,
            "error": self.error,
            "shared": self.shared,
            "mine": self.owner.key == user.key,
            "owner": self.owner.name,
            "created": self.created.isoformat(timespec="seconds"),
            "overview": self.overview,
        }


SessionFactory = Callable[[LogStore], AskSession]


class UploadRegistry:
    def __init__(
        self,
        settings: Settings,
        session_factory: SessionFactory,
        executor: Executor | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._settings = settings
        self._factory = session_factory
        # Parsing is CPU-bound, so more threads would not load files faster.
        self._executor = executor or ThreadPoolExecutor(max_workers=2, thread_name_prefix="load")
        self._clock = clock
        self._uploads: dict[str, Upload] = {}
        self._lock = threading.Lock()

    # --- adding -----------------------------------------------------------------------

    def check_quota(self, user: User) -> None:
        """Refuse before the upload is read, so a full server does not take the bytes."""
        with self._lock:
            self._check_quota(user)

    def add(
        self, user: User, filename: str, path: Path, size: int, fmt: ExportFormat | None = None
    ) -> Upload:
        """Register a received file and start loading it; the file is deleted afterwards."""
        with self._lock:
            try:
                self._check_quota(user)
            except UploadError:
                path.unlink(missing_ok=True)
                raise
            upload = Upload(
                secrets.token_urlsafe(12), user, filename, size, datetime.now(UTC), self._clock()
            )
            self._uploads[upload.id] = upload
        log.info("%s uploaded %s (%d bytes) as %s", user.name, filename, size, upload.id)
        self._executor.submit(self._load, upload, path, fmt)
        return upload

    def preload(self, path: Path, fmt: ExportFormat | None = None) -> Upload:
        """Load a file named on the command line, shared with everyone; errors propagate."""
        store = LogStore.load(path, self._settings, fmt)
        if not len(store):
            raise ValueError(f"{path.name}: {NO_RECORDS}")
        upload = Upload(
            secrets.token_urlsafe(12),
            SYSTEM,
            path.name,
            path.stat().st_size,
            datetime.now(UTC),
            self._clock(),
            shared=True,
            pinned=True,
        )
        self._finish(upload, store=store)
        with self._lock:
            self._uploads[upload.id] = upload
        return upload

    def _load(self, upload: Upload, path: Path, fmt: ExportFormat | None) -> None:
        started = time.monotonic()
        try:
            store = LogStore.load(path, self._settings, fmt)
            if not len(store):
                raise ValueError(NO_RECORDS)
        except (ValueError, OSError) as exc:  # includes ExportFormatError and decoding errors
            self._finish(upload, error=f"Could not read {upload.filename}: {exc}")
        except Exception:  # a bug must not leave the file "processing" forever
            log.exception("Loading upload %s failed", upload.id)
            self._finish(upload, error=f"Could not read {upload.filename}.")
        else:
            self._finish(upload, store=store)
            log.info(
                "Loaded %s: %d records in %.1f s", upload.id, len(store), time.monotonic() - started
            )
        finally:
            # The raw export is not redacted; only the redacted store is kept.
            path.unlink(missing_ok=True)

    def _finish(
        self, upload: Upload, store: LogStore | None = None, error: str | None = None
    ) -> None:
        overview = None
        if store is not None:
            overview = {**store.overview(), "examples": store.sample_identifiers()}
        with self._lock:
            upload.store, upload.overview, upload.error = store, overview, error
            upload.status = UploadStatus.READY if store is not None else UploadStatus.FAILED

    # --- access -----------------------------------------------------------------------

    def visible(self, user: User) -> list[Upload]:
        with self._lock:
            self._sweep()
            uploads = [u for u in self._uploads.values() if u.visible_to(user)]
        return sorted(uploads, key=lambda u: u.created, reverse=True)

    def get(self, user: User, upload_id: str) -> Upload:
        with self._lock:
            upload = self._uploads.get(upload_id)
            # Someone else's private file answers like a missing one.
            if upload is None or not upload.visible_to(user):
                raise UploadError(404, "No such file; it may have expired or been removed.")
            upload.last_used = self._clock()
            return upload

    def ready(self, user: User, upload_id: str) -> tuple[Upload, LogStore]:
        upload = self.get(user, upload_id)
        if upload.store is None:
            if upload.status is UploadStatus.PROCESSING:
                raise UploadError(409, "The file is still being processed.")
            raise UploadError(409, upload.error or "The file could not be read.")
        return upload, upload.store

    def remove(self, user: User, upload_id: str) -> None:
        upload = self._owned(user, upload_id)
        with self._lock:
            self._uploads.pop(upload.id, None)
        log.info("%s removed %s", user.name, upload.id)

    def set_shared(self, user: User, upload_id: str, shared: bool) -> Upload:
        upload = self._owned(user, upload_id)
        with self._lock:
            upload.shared = shared
        log.info("%s %s %s", user.name, "shared" if shared else "unshared", upload.id)
        return upload

    def new_conversation(self, user: User, upload_id: str) -> str:
        upload, store = self.ready(user, upload_id)
        conversation = Conversation(user.key, self._factory(store))
        conversation_id = secrets.token_urlsafe(16)
        with self._lock:
            upload.conversations[conversation_id] = conversation
            while len(upload.conversations) > MAX_CONVERSATIONS_PER_UPLOAD:
                upload.conversations.popitem(last=False)
        return conversation_id

    def conversation(self, user: User, upload_id: str, conversation_id: str) -> Conversation:
        upload, _ = self.ready(user, upload_id)
        with self._lock:
            conversation = upload.conversations.get(conversation_id)
            if conversation is None or conversation.owner != user.key:
                raise UploadError(404, "Unknown conversation; start a new one.")
            upload.conversations.move_to_end(conversation_id)
            return conversation

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    # --- helpers ----------------------------------------------------------------------

    def _owned(self, user: User, upload_id: str) -> Upload:
        upload = self.get(user, upload_id)
        if upload.owner.key != user.key:
            raise UploadError(403, "Only the person who uploaded a file can change or remove it.")
        return upload

    def _check_quota(self, user: User) -> None:
        self._sweep()
        mine = sum(1 for u in self._uploads.values() if u.owner.key == user.key)
        if mine >= self._settings.server_max_uploads_per_user:
            raise UploadError(429, f"You already have {mine} files loaded; remove one first.")
        if sum(1 for u in self._uploads.values() if not u.pinned) >= (
            self._settings.server_max_uploads
        ):
            raise UploadError(
                503, "The server holds as many files as it can; remove one or try again later."
            )

    def _sweep(self) -> None:
        cutoff = self._clock() - self._settings.server_upload_idle_hours * 3600
        idle = [
            u.id
            for u in self._uploads.values()
            if not u.pinned and u.status is not UploadStatus.PROCESSING and u.last_used < cutoff
        ]
        for upload_id in idle:
            log.info(
                "Dropping %s, unused for %s hours",
                upload_id,
                self._settings.server_upload_idle_hours,
            )
            del self._uploads[upload_id]
