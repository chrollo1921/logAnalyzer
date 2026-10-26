"""Masks personal data and secrets before anything leaves the machine.

Order matters: the more specific patterns (JWTs, URL credentials) run before the
generic ones so they are replaced whole.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

from sapcx_log_analyzer.config import RedactionPattern
from sapcx_log_analyzer.models import LogRecord

DEFAULT_PATTERNS: tuple[RedactionPattern, ...] = (
    RedactionPattern(
        name="jwt",
        pattern=r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b",
        replacement="<JWT>",
    ),
    RedactionPattern(
        name="bearer_token",
        pattern=r"(?i)\b(bearer|access_token|refresh_token)([\s=:\"']+)[A-Za-z0-9._~+/-]{8,}=*",
        replacement=r"\1\2<TOKEN>",
    ),
    RedactionPattern(
        name="url_credentials",
        pattern=r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@",
        replacement=r"\1<USER>:<PASSWORD>@",
    ),
    RedactionPattern(
        name="password_assignment",
        pattern=(
            r"(?i)\b(password|passwd|pwd|secret|client_secret|api[_-]?key)"
            r"([\"']?\s*[=:]\s*[\"']?)[^\s\"',;&]+"
        ),
        replacement=r"\1\2<SECRET>",
    ),
    RedactionPattern(
        name="email",
        pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        replacement="<EMAIL>",
    ),
    RedactionPattern(
        name="session_id",
        pattern=r"(?i)\b(?:jsessionid|sessionid|session_id)[=:]\s*(?P<value>[A-Za-z0-9._-]{8,})",
        link_label="SESSION",
    ),
    RedactionPattern(
        name="card_number",
        pattern=r"\b(?:\d[ -]?){14,18}\d\b",
        replacement="<CARD>",
        luhn=True,
    ),
    RedactionPattern(
        name="ipv4",
        pattern=r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
        replacement="<IP>",
    ),
)


# Context keys whose whole value is a session id and becomes a link token.
_SESSION_KEY = re.compile(r"(?i)session")


@dataclass(frozen=True)
class _Compiled:
    name: str
    regex: re.Pattern[str]
    replacement: str
    luhn: bool
    link_label: str | None


class Redactor:
    """Masks secrets and personal data.

    Link tokens are keyed with a random per-instance salt: the same value maps to the same
    token within one run, but tokens cannot be reversed or matched across runs.
    """

    def __init__(self, extra_patterns: Iterable[RedactionPattern] = ()) -> None:
        patterns = [*DEFAULT_PATTERNS, *extra_patterns]
        self._compiled = []
        for p in patterns:
            regex = re.compile(p.pattern)
            if p.link_label is not None and "value" not in regex.groupindex:
                raise ValueError(f"Redaction pattern {p.name!r} needs a (?P<value>...) group")
            self._compiled.append(_Compiled(p.name, regex, p.replacement, p.luhn, p.link_label))
        self._salt = secrets.token_bytes(16)
        self.counts: Counter[str] = Counter()

    def link_token(self, label: str, value: str) -> str:
        digest = hashlib.blake2b(value.encode("utf-8"), key=self._salt, digest_size=4)
        return f"<{label}#{digest.hexdigest()}>"

    def redact(self, text: str) -> str:
        for item in self._compiled:
            if item.luhn:
                text, hits = _subn_luhn(item, text)
            elif item.link_label is not None:
                text, hits = self._subn_link(item, item.link_label, text)
            else:
                text, hits = item.regex.subn(item.replacement, text)
            if hits:
                self.counts[item.name] += hits
        return text

    def redact_record(self, record: LogRecord) -> LogRecord:
        return record.model_copy(
            update={
                "message": self.redact(record.message),
                "stack": [self.redact(line) for line in record.stack],
                "thread": self.redact(record.thread) if record.thread else None,
                "context": {
                    key: self._redact_context(key, value) for key, value in record.context.items()
                },
            }
        )

    def _redact_context(self, key: str, value: str) -> str:
        if _SESSION_KEY.search(key):
            self.counts["session_id"] += 1
            return self.link_token("SESSION", value)
        return self.redact(value)

    def _subn_link(self, item: _Compiled, label: str, text: str) -> tuple[str, int]:
        hits = 0

        def replace(match: re.Match[str]) -> str:
            nonlocal hits
            hits += 1
            start, end = match.span("value")
            offset = match.start()
            whole = match.group(0)
            token = self.link_token(label, match.group("value"))
            return whole[: start - offset] + token + whole[end - offset :]

        return item.regex.sub(replace, text), hits


def luhn_valid(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value = value * 2 - 9 if value > 4 else value * 2
        total += value
    return total % 10 == 0


def _subn_luhn(item: _Compiled, text: str) -> tuple[str, int]:
    hits = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal hits
        digits = re.sub(r"\D", "", match.group(0))
        if luhn_valid(digits):
            hits += 1
            return item.replacement
        return match.group(0)

    return item.regex.sub(replace, text), hits
