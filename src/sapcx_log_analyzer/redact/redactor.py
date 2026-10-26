"""Masks personal data and secrets before anything leaves the machine.

Order matters: the more specific patterns (JWTs, URL credentials) run before the
generic ones so they are replaced whole.
"""

from __future__ import annotations

import re
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
        pattern=r"(?i)\b(jsessionid|sessionid|session_id)([=:]\s*)[A-Za-z0-9._-]{8,}",
        replacement=r"\1\2<SESSION>",
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


@dataclass(frozen=True)
class _Compiled:
    name: str
    regex: re.Pattern[str]
    replacement: str
    luhn: bool


class Redactor:
    def __init__(self, extra_patterns: Iterable[RedactionPattern] = ()) -> None:
        patterns = [*DEFAULT_PATTERNS, *extra_patterns]
        self._compiled = [
            _Compiled(p.name, re.compile(p.pattern), p.replacement, p.luhn) for p in patterns
        ]
        self.counts: Counter[str] = Counter()

    def redact(self, text: str) -> str:
        for item in self._compiled:
            if item.luhn:
                text, hits = _subn_luhn(item, text)
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
            }
        )


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
