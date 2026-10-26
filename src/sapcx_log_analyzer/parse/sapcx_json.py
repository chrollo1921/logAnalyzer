"""Parser for the log4j2 JSON layout that SAP Commerce Cloud (CCv2) writes to stdout."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class ParsedLine:
    message: str
    level: str | None = None
    logger: str | None = None
    thread: str | None = None
    timestamp: datetime | None = None
    stack: list[str] = field(default_factory=list)
    context: dict[str, str] = field(default_factory=dict)


def _timestamp(doc: dict[str, Any]) -> datetime | None:
    instant = doc.get("instant")
    if isinstance(instant, dict) and "epochSecond" in instant:
        seconds = float(instant["epochSecond"]) + float(instant.get("nanoOfSecond", 0)) / 1e9
        return datetime.fromtimestamp(seconds, tz=UTC)
    if "timeMillis" in doc:
        return datetime.fromtimestamp(float(doc["timeMillis"]) / 1000, tz=UTC)
    return None


def _frame(entry: Any) -> str:
    if isinstance(entry, dict):
        location = entry.get("file") or "Unknown Source"
        if entry.get("line"):
            location = f"{location}:{entry['line']}"
        return f"\tat {entry.get('class', '?')}.{entry.get('method', '?')}({location})"
    return f"\tat {entry}"


def _thrown_lines(thrown: dict[str, Any], prefix: str = "") -> list[str]:
    header = f"{prefix}{thrown.get('name', 'java.lang.Throwable')}"
    if thrown.get("message"):
        header = f"{header}: {thrown['message']}"
    lines = [header]
    trace = thrown.get("extendedStackTrace") or thrown.get("stackTrace")
    if isinstance(trace, str):
        lines.extend(line for line in trace.splitlines()[1:] if line.strip())
    elif isinstance(trace, list):
        lines.extend(_frame(entry) for entry in trace)
    cause = thrown.get("cause")
    if isinstance(cause, dict):
        lines.extend(_thrown_lines(cause, prefix="Caused by: "))
    return lines


def _context(doc: dict[str, Any]) -> dict[str, str]:
    """Scalar MDC values: log4j2 writes them as ``contextMap``, older layouts as ``mdc``."""
    result: dict[str, str] = {}
    for key in ("contextMap", "mdc", "context"):
        values = doc.get(key)
        if isinstance(values, dict):
            for name, value in values.items():
                if value not in (None, "") and not isinstance(value, (dict, list)):
                    result[str(name)] = str(value)
    return result


def parse_json_line(content: str) -> ParsedLine | None:
    """Parse one JSON log line, or return None if it is not one."""
    text = content.strip()
    if not text.startswith("{"):
        return None
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(doc, dict) or not ({"message", "level"} & doc.keys()):
        return None
    message = doc.get("message")
    if isinstance(message, dict):
        message = json.dumps(message, sort_keys=True)
    thrown = doc.get("thrown")
    return ParsedLine(
        message=str(message or ""),
        level=doc.get("level"),
        logger=doc.get("loggerName") or doc.get("logger"),
        thread=doc.get("thread") or doc.get("threadName"),
        timestamp=_timestamp(doc),
        stack=_thrown_lines(thrown) if isinstance(thrown, dict) else [],
        context=_context(doc),
    )
