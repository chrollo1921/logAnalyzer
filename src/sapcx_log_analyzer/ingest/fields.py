"""Column names used by the different Dynatrace export flavours.

The Logs viewer export, the Grail ``fetch logs`` result and the classic Log Monitoring
API all name the same fields slightly differently. Lookups are case-insensitive and
take the first non-empty match.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from sapcx_log_analyzer.models import RawEntry

CONTENT_KEYS = ("content", "message", "log.content", "body", "log")
TIMESTAMP_KEYS = ("timestamp", "time", "@timestamp", "date", "event.start")
LEVEL_KEYS = ("loglevel", "log.level", "level", "status", "severity")


def _lookup(lowered: Mapping[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = lowered.get(key)
        if value not in (None, ""):
            return str(value)
    return None


def to_raw_entry(row: Mapping[str, Any]) -> RawEntry | None:
    """Turn one export row into a RawEntry, or None if it has no log content."""
    lowered = {str(k).strip().lower(): v for k, v in row.items() if k is not None}
    content = _lookup(lowered, CONTENT_KEYS)
    if content is None:
        return None
    used = set(CONTENT_KEYS + TIMESTAMP_KEYS + LEVEL_KEYS)
    attributes = {
        k: str(v)
        for k, v in lowered.items()
        if k not in used and v not in (None, "") and not isinstance(v, (dict, list))
    }
    return RawEntry(
        timestamp=_lookup(lowered, TIMESTAMP_KEYS),
        content=content,
        level=_lookup(lowered, LEVEL_KEYS),
        attributes=attributes,
    )
