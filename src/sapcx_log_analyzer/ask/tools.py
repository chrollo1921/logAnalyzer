"""Tools the model uses to investigate the logs, and how their results are rendered.

Results are compact text rather than JSON: one line per record, prefixed with its ``#ref``
so the model can cite it and ask for more context around it. Every result is capped so a
broad search cannot flood the conversation.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from sapcx_log_analyzer.ask.store import LogStore, Scope
from sapcx_log_analyzer.models import LogLevel, LogRecord
from sapcx_log_analyzer.parse.log4j_pattern import parse_timestamp
from sapcx_log_analyzer.parse.stacktrace import frames

Level = Literal["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"]

_MESSAGE_CHARS = 400
_NOT_HEADER = ("at ", "...")
_FRAMEWORK_PREFIXES = ("java.", "javax.", "jakarta.", "jdk.", "sun.", "org.springframework.")


class ToolInputError(ValueError):
    """The model called a tool with input it cannot run with."""


class _Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FindIdentifierInput(_Input):
    value: str = Field(min_length=1, max_length=200)
    limit: int = Field(default=60, ge=1, le=200)


class GetContextInput(_Input):
    record: int = Field(ge=1)
    window_seconds: float = Field(default=30, gt=0, le=3600)
    scope: Scope = Scope.THREAD
    min_level: Level = "DEBUG"
    limit: int = Field(default=40, ge=1, le=150)


class GetRecordInput(_Input):
    record: int = Field(ge=1)


class ListIssuesInput(_Input):
    start: str | None = None
    end: str | None = None

    @field_validator("start", "end")
    @classmethod
    def _iso(cls, value: str | None) -> str | None:
        if value is not None and parse_timestamp(value) is None:
            raise ValueError("must be an ISO-8601 timestamp such as 2026-10-20T09:15:00Z")
        return value


class SearchLogsInput(ListIssuesInput):
    text: str | None = Field(default=None, max_length=200)
    min_level: Level = "TRACE"
    pod: str | None = None
    aspect: str | None = None
    limit: int = Field(default=50, ge=1, le=200)


def _object(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


_LEVELS = {"type": "string", "enum": [level.value for level in LogLevel]}
_TIME = {"type": "string", "description": "ISO-8601 timestamp, e.g. 2026-10-20T09:15:00Z"}

TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "find_identifier",
        "description": (
            "Find every log record that mentions an identifier: a transaction id such as "
            "tx-243232, an order or cart code, a trace id, correlation id, request id or a "
            "<SESSION#...> token. Returns the records in time order and the other identifiers "
            "that appear in them, which you can look up next. If nothing matches it suggests "
            "similar known identifiers."
        ),
        "input_schema": _object(
            {
                "value": {"type": "string", "description": "The identifier, as written."},
                "limit": {"type": "integer", "description": "Max records (default 60)."},
            },
            ["value"],
        ),
    },
    {
        "name": "get_context",
        "description": (
            "List the records around one record, by default on the same pod and thread within "
            "30 seconds. Use it to see what the request was doing just before and after a line "
            "that mentions the id, since the error itself often does not carry the id. Widen "
            "with scope 'pod' or 'all' to see what else was failing at that moment."
        ),
        "input_schema": _object(
            {
                "record": {"type": "integer", "description": "The #ref of the anchor record."},
                "window_seconds": {"type": "number", "description": "Seconds before and after."},
                "scope": {"type": "string", "enum": [s.value for s in Scope]},
                "min_level": _LEVELS,
                "limit": {"type": "integer"},
            },
            ["record"],
        ),
    },
    {
        "name": "get_record",
        "description": "Show one record in full, with its whole stack trace and context fields.",
        "input_schema": _object(
            {"record": {"type": "integer", "description": "The #ref of the record."}},
            ["record"],
        ),
    },
    {
        "name": "search_logs",
        "description": (
            "Search all records by case-insensitive text and filters (level, pod, aspect, time "
            "window). Use it for exception names, loggers, endpoints or anything else that is "
            "not an identifier."
        ),
        "input_schema": _object(
            {
                "text": {"type": "string"},
                "min_level": _LEVELS,
                "pod": {"type": "string", "description": "Substring of the pod name."},
                "aspect": {"type": "string", "description": "e.g. api, backgroundprocessing."},
                "start": _TIME,
                "end": _TIME,
                "limit": {"type": "integer"},
            },
            [],
        ),
    },
    {
        "name": "list_issues",
        "description": (
            "List the known SAP Commerce problem patterns (connection pool exhaustion, Solr, "
            "OOM, CronJob failures and so on) detected by the rule catalogue, with how often "
            "each occurred in an optional time window. Use it to check whether a failing "
            "transaction was a victim of a wider platform problem."
        ),
        "input_schema": _object({"start": _TIME, "end": _TIME}, []),
    },
]


def format_record(store: LogStore, ref: int, full: bool = False) -> str:
    record = store.record(ref)
    parts = [
        f"#{ref}",
        record.timestamp.isoformat(timespec="milliseconds") if record.timestamp else "-",
        record.level.value,
    ]
    if record.aspect:
        parts.append(record.aspect)
    if record.pod:
        parts.append(f"pod={record.pod}")
    if record.thread:
        parts.append(f"thread={record.thread}")
    if record.logger:
        parts.append(f"logger={record.logger}")
    classification = store.classification(ref)
    if classification:
        parts.append(f"[issue={classification.rule_id}]")
    message = (
        record.message if full else _clip(record.message.splitlines()[0] if record.message else "")
    )
    lines = [" ".join(parts) + " | " + message]
    if record.context:
        lines.append("    context: " + json.dumps(record.context, ensure_ascii=False))
    lines.extend(f"    {line}" for line in (record.stack[:80] if full else _stack_summary(record)))
    return "\n".join(lines)


def _stack_summary(record: LogRecord) -> list[str]:
    """Exception headers plus the first application frames."""
    headers = [
        line.strip() for line in record.stack if not line.lstrip().startswith(("at ", "..."))
    ]
    app = [f for f in frames(record.stack) if not f.startswith(_FRAMEWORK_PREFIXES)][:3]
    return [_clip(h, 300) for h in headers[:4]] + [f"at {f}" for f in app]


def _clip(text: str, limit: int = _MESSAGE_CHARS) -> str:
    return text if len(text) <= limit else text[:limit] + " …"


def _time(value: str | None) -> datetime | None:
    return parse_timestamp(value) if value else None


def _records_block(store: LogStore, refs: list[int]) -> str:
    return "\n".join(format_record(store, ref) for ref in refs)


def _find_identifier(store: LogStore, args: FindIdentifierInput) -> str:
    result = store.find(args.value, args.limit)
    if result.matched_by == "none":
        hint = (
            f" Similar identifiers in this export: {', '.join(result.suggestions)}."
            if result.suggestions
            else " No similar identifiers either; the transaction may be outside this export's "
            "time range or the id may not be logged."
        )
        return f"No record mentions {args.value!r}.{hint}"
    how = "as an identifier" if result.matched_by == "index" else "as text"
    lines = [
        f"{result.total} record(s) mention {args.value!r} ({how}); showing {len(result.refs)}."
    ]
    if result.related:
        related = ", ".join(f"{i.kind}:{i.value} ({n})" for i, n in result.related)
        lines.append(f"Identifiers seen in the same records: {related}")
    lines.append(_records_block(store, result.refs))
    if result.linked_refs:
        lines.append(
            f"\n{result.linked_total} more record(s) share a trace, correlation or request id "
            f"with them; showing {len(result.linked_refs)}:"
        )
        lines.append(_records_block(store, result.linked_refs))
    return "\n".join(lines)


def _get_context(store: LogStore, args: GetContextInput) -> str:
    refs = store.context(
        args.record, args.window_seconds, args.scope, LogLevel(args.min_level), args.limit
    )
    header = (
        f"{len(refs)} record(s) within {args.window_seconds:g}s of #{args.record} "
        f"(scope={args.scope.value}, min_level={args.min_level}):"
    )
    return header + "\n" + _records_block(store, refs)


def _get_record(store: LogStore, args: GetRecordInput) -> str:
    text = format_record(store, args.record, full=True)
    cluster = store.cluster_of(args.record)
    if cluster:
        text += (
            f"\nPart of issue cluster {cluster.id} '{cluster.title}' ({cluster.component}, "
            f"{cluster.severity.value}): {cluster.count} events between "
            f"{cluster.first_seen} and {cluster.last_seen} on {len(cluster.pods)} pod(s)."
        )
    return text


def _search_logs(store: LogStore, args: SearchLogsInput) -> str:
    refs, total = store.search(
        text=args.text,
        min_level=LogLevel(args.min_level),
        pod=args.pod,
        aspect=args.aspect,
        start=_time(args.start),
        end=_time(args.end),
        limit=args.limit,
    )
    if not refs:
        return "No records match."
    return f"{total} record(s) match; showing {len(refs)}.\n" + _records_block(store, refs)


def _list_issues(store: LogStore, args: ListIssuesInput) -> str:
    issues = store.issues(_time(args.start), _time(args.end))
    if not issues:
        return "No known problem patterns in this window."
    lines = []
    for issue in issues[:25]:
        c = issue.cluster
        lines.append(
            f"- {c.severity.value} | {c.title} ({c.component}) rule={c.rule_id} "
            f"events_in_window={issue.count_in_window} total={c.count} "
            f"first={c.first_seen} last={c.last_seen} pods={len(c.pods)} "
            f"aspects={','.join(c.aspects) or '-'}\n  template: {_clip(c.template, 250)}"
        )
    return "\n".join(lines)


_HANDLERS: dict[str, tuple[type[_Input], Callable[[LogStore, Any], str]]] = {
    "find_identifier": (FindIdentifierInput, _find_identifier),
    "get_context": (GetContextInput, _get_context),
    "get_record": (GetRecordInput, _get_record),
    "search_logs": (SearchLogsInput, _search_logs),
    "list_issues": (ListIssuesInput, _list_issues),
}


def run_tool(store: LogStore, name: str, raw_input: Any, max_chars: int) -> str:
    """Validate the input and run one tool. Raises ToolInputError for bad calls."""
    if name not in _HANDLERS:
        raise ToolInputError(f"Unknown tool {name!r}")
    model, handler = _HANDLERS[name]
    try:
        args = model.model_validate(raw_input)
    except ValidationError as exc:
        raise ToolInputError(f"Invalid input for {name}: {exc}") from exc
    try:
        text = handler(store, args)
    except KeyError as exc:
        raise ToolInputError(str(exc.args[0]) if exc.args else str(exc)) from exc
    if len(text) > max_chars:
        cut = text.rfind("\n#", 0, max_chars)
        text = text[: cut if cut > 0 else max_chars]
        text += "\n[result truncated: narrow the query, lower the limit or use a time window]"
    return text


def describe_call(name: str, raw_input: Any) -> str:
    """A short human-readable line for a tool call, for progress output."""
    data = raw_input if isinstance(raw_input, dict) else {}
    match name:
        case "find_identifier":
            return f"Looking up {data.get('value', '?')}"
        case "get_context":
            scope = data.get("scope", "thread")
            return f"Reading the lines around #{data.get('record', '?')} (same {scope})"
        case "get_record":
            return f"Opening record #{data.get('record', '?')}"
        case "search_logs":
            what = data.get("text") or "records"
            return f"Searching for {what!r}"
        case "list_issues":
            return "Checking which known platform issues were active"
    return f"Running {name}"
