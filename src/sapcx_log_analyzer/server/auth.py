"""Who is asking: identities and browser sessions for the shared web app.

Three modes, set with ``server_auth``:

- ``none``: anyone who can reach the server. Each browser still gets its own session, so
  people do not see each other's files unless they share them. Meant for one machine.
- ``token``: a team access key, entered once per browser, then a session cookie.
- ``header``: a company single sign-on proxy (oauth2-proxy, an identity-aware proxy or
  an API gateway) in front of the app sets a header with the signed-in user's email.
  The app must then only be reachable through that proxy.
"""

from __future__ import annotations

import hmac
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass

SESSION_COOKIE = "sapcx_session"
MIN_TOKEN_LENGTH = 16
MAX_SESSIONS = 10_000


@dataclass(frozen=True)
class User:
    key: str  # owns uploads and conversations; never shown to other users
    name: str  # shown next to files they share


SYSTEM = User("system", "server")


@dataclass
class _Session:
    user: User
    expires: float


class SessionStore:
    """Browser sessions in memory; a restart signs everyone out, like it drops uploads."""

    def __init__(
        self, lifetime_seconds: float, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._lifetime = lifetime_seconds
        self._clock = clock
        self._sessions: OrderedDict[str, _Session] = OrderedDict()
        self._lock = threading.Lock()

    def create(self, name: str) -> str:
        session_id = secrets.token_urlsafe(32)
        # The owner key is separate from the cookie value, so logs never contain a session.
        user = User(f"session:{secrets.token_hex(8)}", name)
        with self._lock:
            self._sessions[session_id] = _Session(user, self._clock() + self._lifetime)
            while len(self._sessions) > MAX_SESSIONS:
                self._sessions.popitem(last=False)
        return session_id

    def get(self, session_id: str) -> User | None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if session.expires < self._clock():
                del self._sessions[session_id]
                return None
            return session.user

    def drop(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)


def token_matches(given: str, expected: str) -> bool:
    return hmac.compare_digest(given.encode("utf-8"), expected.encode("utf-8"))


def header_user(value: str) -> User | None:
    """The user named by the SSO proxy's header, e.g. ``jane.doe@example.com``."""
    value = value.strip()
    if not value or len(value) > 320:
        return None
    return User(f"sso:{value.lower()}", value)
