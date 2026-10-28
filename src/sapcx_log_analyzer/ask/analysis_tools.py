"""Tools for questions about the whole export rather than one id: when did errors rise,
what changed before an outage, which endpoints are slow, what kinds of messages exist.

They read the profile in ``analysis.py``. Like the lookups, every result is compact text
and every example carries a ``#ref`` so answers stay citable.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Self, get_args

from pydantic import Field, field_validator, model_validator

from sapcx_log_analyzer.ask.analysis import (
    CALL_METRICS,
    Analysis,
    Change,
    Comparison,
    EndpointStats,
    Metric,
    Pattern,
    Window,
    alternatives,
)
from sapcx_log_analyzer.ask.store import LogStore
from sapcx_log_analyzer.ask.tooling import (
    LEVELS_SCHEMA,
    TIME_SCHEMA,
    Level,
    TimeWindowInput,
    ToolInput,
    ToolInputError,
    check_time,
    object_schema,
    parse_time,
    window_note,
)
from sapcx_log_analyzer.models import LogLevel, LogRecord

_MAX_ROWS = 240
_LINE_SPLITS = ("pattern", "level", "aspect", "pod", "logger")
_CALL_SPLITS = ("endpoint", "status", "aspect", "pod")
_NO_TIMESTAMPS = "This export has no timestamps, so there is no timeline to look at."


class TimelineInput(TimeWindowInput):
    metric: Metric = "lines"
    split_by: (
        Literal["pattern", "level", "aspect", "pod", "logger", "endpoint", "status"] | None
    ) = None
    bucket_minutes: int | None = Field(default=None, ge=1, le=1440)
    min_level: Level = "TRACE"
    aspect: str | None = Field(default=None, max_length=100)
    pod: str | None = Field(default=None, max_length=200)
    pattern: str | None = Field(default=None, max_length=200)
    text: str | None = Field(default=None, max_length=200)
    path: str | None = Field(default=None, max_length=300)

    @model_validator(mode="after")
    def _compatible(self) -> Self:
        if self.metric in CALL_METRICS:
            if self.split_by not in (None, *_CALL_SPLITS):
                raise ValueError(
                    f"split_by '{self.split_by}' needs metric 'lines'; request metrics split by "
                    "endpoint, status, aspect or pod"
                )
            if self.pattern or self.text or self.min_level != "TRACE":
                raise ValueError("pattern, text and min_level filter log lines: use metric 'lines'")
        else:
            if self.split_by not in (None, *_LINE_SPLITS):
                raise ValueError(f"split_by '{self.split_by}' needs a request metric")
            if self.path:
                raise ValueError("path filters requests: use a metric such as requests or p95_ms")
        return self


class CompareWindowsInput(ToolInput):
    target_start: str
    target_end: str
    baseline_start: str | None = None
    baseline_end: str | None = None
    dimension: Literal["pattern", "endpoint", "level", "aspect", "pod", "logger"] = "pattern"
    min_level: Level = "TRACE"
    limit: int = Field(default=15, ge=1, le=50)

    @field_validator("target_start", "target_end", "baseline_start", "baseline_end")
    @classmethod
    def _iso(cls, value: str | None) -> str | None:
        return check_time(value)


class EndpointStatsInput(TimeWindowInput):
    path: str | None = Field(default=None, max_length=300)
    method: str | None = Field(default=None, pattern=r"^[A-Za-z]{3,7}$")
    baseline_start: str | None = None
    baseline_end: str | None = None
    sort: Literal["requests", "5xx", "p95", "max"] = "requests"
    min_requests: int = Field(default=1, ge=1)
    limit: int = Field(default=20, ge=1, le=100)

    @field_validator("baseline_start", "baseline_end")
    @classmethod
    def _iso_baseline(cls, value: str | None) -> str | None:
        return check_time(value)


class ListPatternsInput(TimeWindowInput):
    min_level: Level = "TRACE"
    text: str | None = Field(default=None, max_length=200)
    logger: str | None = Field(default=None, max_length=200)
    aspect: str | None = Field(default=None, max_length=100)
    events_only: bool = False
    sort: Literal["level", "count", "first_seen"] = "level"
    limit: int = Field(default=40, ge=1, le=200)


_PATTERN_IDS = {
    "type": "string",
    "description": "One or more pattern ids, comma separated, e.g. 'P17,P40'.",
}
_ALTERNATIVES = "Case-insensitive substring; 'a|b' matches either."

ANALYSIS_TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "timeline",
        "description": (
            "A metric per time bucket, to see when something started, peaked and ended. "
            "metric 'lines' counts log lines (filter with min_level, aspect, pod, pattern, text; "
            "split by pattern, level, aspect, pod or logger); 'requests', '5xx', '4xx', "
            "'p50_ms' and 'p95_ms' measure HTTP requests (filter with path, aspect, pod; split "
            "by endpoint, status, aspect or pod). The bucket size is chosen for about 60 rows "
            "unless bucket_minutes is given. Rows inside a candidate incident are marked '!'."
        ),
        "input_schema": object_schema(
            {
                "metric": {"type": "string", "enum": list(get_args(Metric))},
                "split_by": {"type": "string", "enum": [*_LINE_SPLITS, "endpoint", "status"]},
                "start": TIME_SCHEMA,
                "end": TIME_SCHEMA,
                "bucket_minutes": {"type": "integer"},
                "min_level": LEVELS_SCHEMA,
                "aspect": {"type": "string"},
                "pod": {"type": "string", "description": "Substring of the pod name."},
                "pattern": _PATTERN_IDS,
                "text": {"type": "string", "description": _ALTERNATIVES},
                "path": {"type": "string", "description": "Request path. " + _ALTERNATIVES},
            },
            [],
        ),
    },
    {
        "name": "compare_windows",
        "description": (
            "Compare a target time window with a baseline window: which message patterns (or "
            "endpoints, levels, aspects, pods, loggers) rose, appeared, fell or stopped, with "
            "rates per minute and an example #ref. Use it for 'what changed before the "
            "outage' (target = the 15 minutes before it) or 'is it worse than this morning'. "
            "Without a baseline, the baseline is the rest of the export before the target "
            "(or after it, if the target starts the export). dimension 'endpoint' compares "
            "request rate, 5xx share and p95 latency per endpoint."
        ),
        "input_schema": object_schema(
            {
                "target_start": TIME_SCHEMA,
                "target_end": TIME_SCHEMA,
                "baseline_start": TIME_SCHEMA,
                "baseline_end": TIME_SCHEMA,
                "dimension": {
                    "type": "string",
                    "enum": ["pattern", "endpoint", "level", "aspect", "pod", "logger"],
                },
                "min_level": LEVELS_SCHEMA,
                "limit": {"type": "integer"},
            },
            ["target_start", "target_end"],
        ),
    },
    {
        "name": "endpoint_stats",
        "description": (
            "Request count, 4xx and 5xx share and latency percentiles (p50, p95, p99, max) per "
            "endpoint, ids replaced by {id}, with the slowest request and first 5xx as #refs. "
            "Filter by path (e.g. 'checkout|orders|paymentdetails') and method; sort by "
            "requests, 5xx, p95 or max. Give a baseline window to compare each endpoint with "
            "another period, e.g. for 'is checkout slower than usual'. For latency over time "
            "use timeline with metric p95_ms."
        ),
        "input_schema": object_schema(
            {
                "path": {"type": "string", "description": _ALTERNATIVES},
                "method": {"type": "string"},
                "start": TIME_SCHEMA,
                "end": TIME_SCHEMA,
                "baseline_start": TIME_SCHEMA,
                "baseline_end": TIME_SCHEMA,
                "sort": {"type": "string", "enum": ["requests", "5xx", "p95", "max"]},
                "min_requests": {"type": "integer"},
                "limit": {"type": "integer"},
            },
            [],
        ),
    },
    {
        "name": "list_patterns",
        "description": (
            "The catalogue of message patterns: lines with the same logger and message apart "
            "from ids and numbers, with level, count, first and last time, aspects, known "
            "issue, lifecycle event and an example #ref. Use it for broad questions ('what "
            "kinds of warnings are there', 'anything about payments or Solr?'), reading the "
            "patterns to pick the relevant ones, which beats guessing search words. Filter by "
            "min_level, text (matches template and logger), logger, aspect, time window, or "
            "events_only for deployments, restarts, CronJobs, syncs and indexing."
        ),
        "input_schema": object_schema(
            {
                "min_level": LEVELS_SCHEMA,
                "text": {"type": "string", "description": _ALTERNATIVES},
                "logger": {"type": "string"},
                "aspect": {"type": "string"},
                "start": TIME_SCHEMA,
                "end": TIME_SCHEMA,
                "events_only": {"type": "boolean"},
                "sort": {"type": "string", "enum": ["level", "count", "first_seen"]},
                "limit": {"type": "integer"},
            },
            [],
        ),
    },
]


# --- timeline ---------------------------------------------------------------------------


def _timeline(store: LogStore, args: TimelineInput) -> str:
    analysis = store.analysis
    if analysis.span is None:
        return _NO_TIMESTAMPS
    start, end = parse_time(args.start), parse_time(args.end)
    note = window_note(store, start, end)
    window = Window(start, end)
    if analysis.minutes(window) == 0:
        return "No data: the window does not overlap the export." + note
    if args.bucket_minutes:
        first, last = (
            max(start or analysis.span[0], analysis.span[0]),
            min(end or analysis.span[1], analysis.span[1]),
        )
        rows = (last - first).total_seconds() / 60 / args.bucket_minutes
        if rows > _MAX_ROWS:
            raise ToolInputError(
                f"bucket_minutes={args.bucket_minutes} gives {rows:.0f} rows; use a larger "
                "bucket or a shorter window"
            )
    patterns = _pattern_set(analysis, args.pattern)
    timeline = analysis.timeline(
        window,
        metric=args.metric,
        split_by=args.split_by,
        bucket_minutes=args.bucket_minutes,
        keep=_line_filter(store, args, patterns),
        path=args.path,
    )
    if all(row.total in (None, 0) for row in timeline.rows):
        return "Nothing matches these filters in this window." + note
    filters = ", ".join(
        f"{name}={value}"
        for name, value in (
            ("min_level", args.min_level if args.min_level != "TRACE" else None),
            ("aspect", args.aspect),
            ("pod", args.pod),
            ("pattern", args.pattern),
            ("text", args.text),
            ("path", args.path),
        )
        if value
    )
    lines = [
        f"{_metric_label(args.metric)} per {timeline.bucket_minutes} min, UTC"
        + (f" ({filters})" if filters else "")
        + ". '!' marks buckets inside a candidate incident."
        + note
    ]
    header = ["time  ", "total", *timeline.columns, "first"]
    lines.append(" | ".join(header))
    size = timedelta(minutes=timeline.bucket_minutes)
    for row in timeline.rows:
        flag = "!" if _in_incident(analysis, row.start, row.start + size) else " "
        cells = [
            f"{analysis.clock(row.start)}{flag}",
            _value(row.total),
            *(_value(row.split.get(c)) for c in timeline.columns),
            f"#{row.first_ref}" if row.first_ref else "-",
        ]
        lines.append(" | ".join(cells))
    if timeline.legend:
        lines.append("Columns:")
        lines += [f"- {key} = {label}" for key, label in timeline.legend.items()]
    return "\n".join(lines)


def _line_filter(
    store: LogStore, args: TimelineInput, patterns: set[str] | None
) -> Callable[[int, LogRecord], bool] | None:
    level = LogLevel(args.min_level)
    terms = alternatives(args.text)
    aspect = args.aspect.lower() if args.aspect else None
    pod = args.pod.lower() if args.pod else None
    if not (level.rank > LogLevel.TRACE.rank or terms or aspect or pod or patterns):
        return None
    analysis = store.analysis

    def keep(ref: int, record: LogRecord) -> bool:
        if record.level.rank < level.rank:
            return False
        if aspect and (record.aspect or "").lower() != aspect:
            return False
        if pod and pod not in (record.pod or "").lower():
            return False
        if patterns and analysis.pattern_of(ref).id not in patterns:
            return False
        if terms:
            text = "\n".join([record.message, *record.stack, record.logger or ""]).lower()
            if not any(term in text for term in terms):
                return False
        return True

    return keep


def _pattern_set(analysis: Analysis, value: str | None) -> set[str] | None:
    if not value:
        return None
    return {analysis.pattern(part).id for part in value.split(",") if part.strip()}


def _in_incident(analysis: Analysis, start: datetime, end: datetime) -> bool:
    return any(i.start < end and start < i.end for i in analysis.incidents)


_METRIC_LABELS = {
    "lines": "Log lines",
    "requests": "HTTP requests",
    "5xx": "HTTP 5xx responses",
    "4xx": "HTTP 4xx responses",
    "p50_ms": "Median request latency (ms)",
    "p95_ms": "p95 request latency (ms)",
}


def _metric_label(metric: str) -> str:
    # Also used to describe a call before its input is validated.
    return _METRIC_LABELS.get(metric, str(metric))


def _value(value: float | None) -> str:
    return "-" if value is None else f"{value:,.0f}"


# --- compare_windows --------------------------------------------------------------------


def _compare_windows(store: LogStore, args: CompareWindowsInput) -> str:
    analysis = store.analysis
    if analysis.span is None:
        return _NO_TIMESTAMPS
    target = Window(parse_time(args.target_start), parse_time(args.target_end))
    assert target.start is not None and target.end is not None
    if target.end <= target.start:
        raise ToolInputError("target_end must be after target_start")
    note = window_note(store, target.start, target.end)
    if analysis.minutes(target) == 0:
        return "The target window does not overlap the export." + note
    baseline, how = _baseline(analysis, target, args.baseline_start, args.baseline_end)
    if analysis.minutes(baseline) == 0:
        return (
            "The baseline window does not overlap the export, so there is nothing to compare "
            f"with. {_span(analysis)}"
        )
    header = (
        f"Target {_window(analysis, target)} ({analysis.minutes(target):.0f} min of data) "
        f"against baseline {_window(analysis, baseline)} ({analysis.minutes(baseline):.0f} "
        f"min{how}); rates per minute.{note}"
    )
    if args.dimension == "endpoint":
        return header + "\n" + _compare_endpoints(analysis, baseline, target, args.limit)
    comparison = analysis.compare(
        baseline, target, args.dimension, LogLevel(args.min_level), args.limit
    )
    return header + "\n" + _render_comparison(analysis, comparison, args.dimension)


def _baseline(
    analysis: Analysis, target: Window, start: str | None, end: str | None
) -> tuple[Window, str]:
    if start or end:
        return Window(parse_time(start), parse_time(end)), ""
    assert analysis.span is not None and target.start is not None and target.end is not None
    tick = timedelta(microseconds=1)
    if target.start > analysis.span[0]:
        return Window(analysis.span[0], target.start - tick), ", the export before the target"
    return Window(target.end + tick, analysis.span[1]), ", the export after the target"


def _render_comparison(analysis: Analysis, comparison: Comparison, dimension: str) -> str:
    lines = ["Rose or appeared:"]
    lines += [_change_line(analysis, c, comparison, dimension) for c in comparison.rising] or [
        "- nothing stands out"
    ]
    lines.append("Fell or stopped:")
    lines += [_change_line(analysis, c, comparison, dimension) for c in comparison.falling] or [
        "- nothing stands out"
    ]
    return "\n".join(lines)


def _change_line(analysis: Analysis, change: Change, comparison: Comparison, dimension: str) -> str:
    before = change.baseline / comparison.baseline_minutes if comparison.baseline_minutes else 0
    after = change.target / comparison.target_minutes if comparison.target_minutes else 0
    if change.status in ("new", "gone"):
        how = change.status
    else:
        ratio = after / before if before else math.inf
        how = f"x{ratio:.1f}" if ratio >= 1 else f"/{1 / ratio:.1f}" if ratio else "gone"
    label = change.key
    if dimension == "pattern":
        pattern = analysis.pattern(change.key)
        event = f" [{pattern.event.title}]" if pattern.event else ""
        label = f"{pattern.id} {pattern.level.value}{event} {pattern.label(120)}"
    example = f" e.g. #{change.example}" if change.example else ""
    return (
        f"- {how}: {change.baseline} ({before:.2f}/min) -> {change.target} ({after:.2f}/min) "
        f"{label}{example}"
    )


def _compare_endpoints(analysis: Analysis, baseline: Window, target: Window, limit: int) -> str:
    before = {s.endpoint: s for s in analysis.endpoint_stats(baseline)}
    after = {s.endpoint: s for s in analysis.endpoint_stats(target)}
    b_minutes, t_minutes = analysis.minutes(baseline), analysis.minutes(target)
    scored = []
    for endpoint in before.keys() | after.keys():
        b = before.get(endpoint) or EndpointStats(endpoint)
        t = after.get(endpoint) or EndpointStats(endpoint)
        if max(b.requests, t.requests) < 3:
            continue
        expected = b.requests * t_minutes / b_minutes
        rate = abs(t.requests - expected) / math.sqrt(expected + 1) / 2
        expected_5xx = b.server_errors * t.requests / b.requests if b.requests else 0
        errors = (t.server_errors - expected_5xx) / math.sqrt(expected_5xx + 1)
        b95, t95 = b.percentile(0.95), t.percentile(0.95)
        # Only getting slower counts here; an endpoint that recovered is not a lead.
        latency = (
            2 * math.log2(t95 / b95)
            if b95 and t95 and len(b.durations) >= 3 and len(t.durations) >= 3
            else 0
        )
        scored.append((max(rate, errors, latency), b, t))
    if not scored:
        return "No endpoint had at least 3 requests in either window."
    scored = [item for item in scored if item[0] >= 1]
    if not scored:
        return "No endpoint got notably slower, failed more or changed its request rate."
    scored.sort(key=lambda item: -item[0])
    lines = ["Endpoints that got slower, failed more or changed rate most (baseline -> target):"]
    for _, b, t in scored[:limit]:
        lines.append(
            f"- {t.endpoint or b.endpoint}: requests {b.requests / b_minutes:.2f}/min -> "
            f"{t.requests / t_minutes:.2f}/min; 5xx {_share(b.server_errors, b.requests)} -> "
            f"{_share(t.server_errors, t.requests)}; p95 {_ms(b.percentile(0.95))} -> "
            f"{_ms(t.percentile(0.95))}"
            + (f"; slowest #{t.slowest[1]}" if t.slowest else "")
            + (f"; first 5xx #{t.first_failure}" if t.first_failure else "")
        )
    return "\n".join(lines)


# --- endpoint_stats ---------------------------------------------------------------------


def _endpoint_stats(store: LogStore, args: EndpointStatsInput) -> str:
    analysis = store.analysis
    start, end = parse_time(args.start), parse_time(args.end)
    note = window_note(store, start, end)
    window = Window(start, end)
    stats = [
        s
        for s in analysis.endpoint_stats(window, args.path, args.method)
        if s.requests >= args.min_requests
    ]
    if not stats:
        return "No HTTP requests match." + note
    key: Callable[[EndpointStats], float] = {
        "requests": lambda s: -s.requests,
        "5xx": lambda s: -s.server_errors,
        "p95": lambda s: -(s.percentile(0.95) or -1),
        "max": lambda s: -(s.slowest[0] if s.slowest else -1),
    }[args.sort]
    stats.sort(key=key)
    baseline = (
        Window(parse_time(args.baseline_start), parse_time(args.baseline_end))
        if args.baseline_start or args.baseline_end
        else None
    )
    before = (
        {s.endpoint: s for s in analysis.endpoint_stats(baseline, args.path, args.method)}
        if baseline
        else {}
    )
    total = sum(s.requests for s in stats)
    lines = [
        f"{len(stats)} endpoint(s), {total:,} requests in {_window(analysis, window)}, sorted by "
        f"{args.sort}; showing {min(len(stats), args.limit)}."
        + (f" Baseline: {_window(analysis, baseline)}." if baseline else "")
        + note
    ]
    for s in stats[: args.limit]:
        lines.append(f"- {_stats_line(s)}")
        if baseline is not None:
            b = before.get(s.endpoint)
            if b is None:
                lines.append("  baseline: no requests")
            else:
                b95, t95 = b.percentile(0.95), s.percentile(0.95)
                change = f"; p95 x{t95 / b95:.1f}" if b95 and t95 else ""
                lines.append(f"  baseline: {_stats_line(b, short=True)}{change}")
    return "\n".join(lines)


def _stats_line(s: EndpointStats, short: bool = False) -> str:
    text = (
        f"{'' if short else s.endpoint + ': '}{_plural(s.requests, 'request')}; "
        f"5xx {s.server_errors} "
        f"({_share(s.server_errors, s.requests)}); 4xx {s.client_errors}"
    )
    if s.durations:
        text += (
            f"; p50 {_ms(s.percentile(0.5))}, p95 {_ms(s.percentile(0.95))}, "
            f"p99 {_ms(s.percentile(0.99))}"
        )
        if s.slowest and not short:
            text += f", max {_ms(s.slowest[0])} (#{s.slowest[1]})"
    else:
        text += "; no durations logged"
    if s.first_failure and not short:
        text += f"; first 5xx #{s.first_failure}"
    return text


# --- list_patterns ----------------------------------------------------------------------


def _list_patterns(store: LogStore, args: ListPatternsInput) -> str:
    analysis = store.analysis
    start, end = parse_time(args.start), parse_time(args.end)
    note = window_note(store, start, end)
    window = Window(start, end)
    counts: Counter[str] = Counter()
    if window.bounded:
        for ref in analysis.refs_in(window):
            counts[analysis.pattern_of(ref).id] += 1
    level = LogLevel(args.min_level)
    terms = alternatives(args.text)
    logger = args.logger.lower() if args.logger else None
    aspect = args.aspect.lower() if args.aspect else None

    def matches(p: Pattern) -> bool:
        if p.level.rank < level.rank or (args.events_only and p.event is None):
            return False
        if window.bounded and not counts[p.id]:
            return False
        if logger and logger not in (p.logger or "").lower():
            return False
        if aspect and aspect not in {a.lower() for a in p.aspects}:
            return False
        haystack = f"{p.logger or ''} {p.template}".lower()
        return not terms or any(term in haystack for term in terms)

    selected = [p for p in analysis.patterns if matches(p)]
    if not selected:
        return "No message patterns match." + note
    sort: Callable[[Pattern], tuple[Any, ...]] = {
        "level": lambda p: (-p.level.rank, -(counts[p.id] or p.count)),
        "count": lambda p: (-(counts[p.id] or p.count),),
        "first_seen": lambda p: (p.first is None, p.first or datetime.max.replace(tzinfo=UTC)),
    }[args.sort]
    selected.sort(key=sort)
    shown = selected[: args.limit]
    lines = [
        f"{len(selected)} of {len(analysis.patterns)} message patterns match"
        + (f" in {_window(analysis, window)}" if window.bounded else "")
        + f"; showing {len(shown)}, sorted by {args.sort.replace('_', ' ')}."
        + note
    ]
    for p in shown:
        count = f"x{counts[p.id]} in window (x{p.count} total)" if window.bounded else f"x{p.count}"
        extras = "".join(
            [
                f" [issue={p.rule_id}]" if p.rule_id else "",
                f" [event: {p.event.title}]" if p.event else "",
            ]
        )
        lines.append(
            f"- {p.id} {p.level.value} {count} {analysis.clock(p.first)}-{analysis.clock(p.last)}"
            f" {','.join(sorted(p.aspects)) or '-'} pods={len(p.pods)}{extras} "
            f"{p.label(200)} e.g. #{_example(analysis, p, window)}"
        )
    return "\n".join(lines)


def _example(analysis: Analysis, pattern: Pattern, window: Window) -> int:
    if not window.bounded:
        return pattern.refs[0]
    refs = analysis.refs_in(window)
    return next((ref for ref in pattern.refs if ref in refs), pattern.refs[0])


# --- shared -----------------------------------------------------------------------------


def _window(analysis: Analysis, window: Window | None) -> str:
    if window is None or analysis.span is None:
        return "the whole export"
    start = max(window.start or analysis.span[0], analysis.span[0])
    end = min(window.end or analysis.span[1], analysis.span[1])
    return f"{analysis.clock(start)}-{analysis.clock(end)} UTC"


def _span(analysis: Analysis) -> str:
    assert analysis.span is not None
    first, last = (stamp.isoformat(timespec="seconds") for stamp in analysis.span)
    return f"This export covers {first} to {last}."


def _plural(count: int, noun: str) -> str:
    return f"{count:,} {noun}" + ("" if count == 1 else "s")


def _share(part: int, whole: int) -> str:
    return f"{100 * part / whole:.1f}%" if whole else "-"


def _ms(value: int | None) -> str:
    return "-" if value is None else f"{value:,} ms"


def describe_analysis_call(name: str, data: dict[str, Any]) -> str | None:
    match name:
        case "timeline":
            what = _metric_label(data.get("metric", "lines")).lower()
            scope = data.get("path") or data.get("pattern") or data.get("text")
            return f"Charting {what} over time" + (f" for {scope}" if scope else "")
        case "compare_windows":
            return "Comparing two time windows"
        case "endpoint_stats":
            return f"Measuring requests, errors and latency for {data.get('path') or 'endpoints'}"
        case "list_patterns":
            topic = data.get("text")
            return "Listing message patterns" + (f" about {topic!r}" if topic else "")
    return None


ANALYSIS_HANDLERS: dict[str, tuple[type[ToolInput], Callable[[LogStore, Any], str]]] = {
    "timeline": (TimelineInput, _timeline),
    "compare_windows": (CompareWindowsInput, _compare_windows),
    "endpoint_stats": (EndpointStatsInput, _endpoint_stats),
    "list_patterns": (ListPatternsInput, _list_patterns),
}
