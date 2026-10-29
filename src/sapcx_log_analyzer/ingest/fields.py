"""Column names used by the different Dynatrace export flavours.

The Logs viewer export, the Grail ``fetch logs`` result and the classic Log Monitoring
API all name the same fields slightly differently, and hand-made or re-exported tables
(Excel, Splunk, Kibana) add their own spellings such as "Log message" or "log_level".
Lookups ignore case, spaces, dots, dashes and underscores, and take the first non-empty
match.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from sapcx_log_analyzer.models import RawEntry

CONTENT_KEYS = (
    "content",
    "message",
    "log.content",
    "log message",
    "log.message",
    "msg",
    "body",
    "log",
    "log line",
    "raw",
    "text",
)
TIMESTAMP_KEYS = (
    "timestamp",
    "time",
    "@timestamp",
    "date",
    "datetime",
    "event.start",
    "start time",
    "ts",
    "log time",
    "event time",
)
LEVEL_KEYS = ("loglevel", "log.level", "level", "status", "severity", "priority")


def normalize_key(key: str) -> str:
    """Spelling-insensitive column name: "Log message", "log_message" and "logMessage" match."""
    return re.sub(r"[^0-9a-z]", "", key.lower())


_CONTENT = tuple(dict.fromkeys(normalize_key(k) for k in CONTENT_KEYS))
_TIMESTAMP = tuple(dict.fromkeys(normalize_key(k) for k in TIMESTAMP_KEYS))
_LEVEL = tuple(dict.fromkeys(normalize_key(k) for k in LEVEL_KEYS))
_USED = frozenset(_CONTENT + _TIMESTAMP + _LEVEL)


def has_content_column(columns: Iterable[str]) -> bool:
    """Whether a table header has a column ``to_raw_entry`` reads the log line from."""
    return any(normalize_key(c) in _CONTENT for c in columns if c)


def _lookup(normalized: Mapping[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = normalized.get(key)
        if value not in (None, ""):
            return str(value)
    return None


def to_raw_entry(row: Mapping[str, Any]) -> RawEntry | None:
    """Turn one export row into a RawEntry, or None if it has no log content."""
    lowered = {str(k).strip().lower(): v for k, v in row.items() if k is not None}
    normalized: dict[str, Any] = {}
    for key, value in lowered.items():
        normalized.setdefault(normalize_key(key), value)
    content = _lookup(normalized, _CONTENT)
    if content is None:
        return None
    attributes = {
        k: str(v)
        for k, v in lowered.items()
        if normalize_key(k) not in _USED and v not in (None, "") and not isinstance(v, (dict, list))
    }
    return RawEntry(
        timestamp=_lookup(normalized, _TIMESTAMP),
        content=content,
        level=_lookup(normalized, _LEVEL),
        attributes=attributes,
    )
