"""Pieces shared by the lookup tools and the analysis tools: input validation, JSON schema
helpers and the notes that say when a time window reaches outside the export."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator

from sapcx_log_analyzer.models import LogLevel
from sapcx_log_analyzer.parse.log4j_pattern import parse_timestamp

if TYPE_CHECKING:
    from sapcx_log_analyzer.ask.store import LogStore

Level = Literal["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"]

MESSAGE_CHARS = 400
LEVELS_SCHEMA = {"type": "string", "enum": [level.value for level in LogLevel]}
TIME_SCHEMA = {"type": "string", "description": "ISO-8601 timestamp, e.g. 2026-10-20T09:15:00Z"}


class ToolInputError(ValueError):
    """The model called a tool with input it cannot run with."""


class ToolInput(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TimeWindowInput(ToolInput):
    start: str | None = None
    end: str | None = None

    @field_validator("start", "end")
    @classmethod
    def _iso(cls, value: str | None) -> str | None:
        return check_time(value)


def check_time(value: str | None) -> str | None:
    if value is not None and parse_timestamp(value) is None:
        raise ValueError("must be an ISO-8601 timestamp such as 2026-10-20T09:15:00Z")
    return value


def object_schema(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


def parse_time(value: str | None) -> datetime | None:
    return parse_timestamp(value) if value else None


def clip(text: str, limit: int = MESSAGE_CHARS) -> str:
    return text if len(text) <= limit else text[:limit] + " …"


def coverage(store: LogStore) -> str:
    span = store.time_range()
    if span is None:
        return "This export has no timestamps."
    first, last = (stamp.isoformat(timespec="seconds") for stamp in span)
    return f"This export covers {first} to {last}."


def window_note(store: LogStore, start: datetime | None, end: datetime | None) -> str:
    """Say when a time window reaches outside the export, so "nothing found" is not read
    as "nothing happened"."""
    span = store.time_range()
    if span is None or (start is None and end is None):
        return ""
    first, last = span
    if (start is not None and start > last) or (end is not None and end < first):
        return (
            f"\nThe requested time window is outside this export. {coverage(store)} "
            "These logs say nothing about that time."
        )
    if (start is not None and start < first) or (end is not None and end > last):
        return f"\nPart of the requested time window is outside this export. {coverage(store)}"
    return ""
