"""A profile of the whole export, computed once when it loads, for questions that do not
start from an id: "what were the main problems", "what happened before the outage", "is
checkout slower than usual".

Every line gets a message pattern: its logger plus its first line with the variable parts
masked, so 15,000 lines become a few hundred patterns that Claude can read as a
catalogue. Errors, 5xx responses and latency are counted per time bucket; buckets far
above the file's own median become candidate incidents, and the patterns that rose or
appeared just before each one are its precursors. Every number comes from here; the model
only chooses what to look at and explains it.
"""

from __future__ import annotations

import math
import re
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import cache
from importlib import resources
from statistics import median
from typing import TYPE_CHECKING, Literal, cast

import yaml
from pydantic import BaseModel, Field

from sapcx_log_analyzer.ask.http import HttpCall
from sapcx_log_analyzer.classify.engine import UNCLASSIFIED_ID
from sapcx_log_analyzer.cluster.fingerprint import template_of
from sapcx_log_analyzer.models import LogLevel, LogRecord

if TYPE_CHECKING:
    from sapcx_log_analyzer.ask.store import LogStore

LineDimension = Literal["pattern", "level", "aspect", "pod", "logger"]
CallDimension = Literal["endpoint", "status", "aspect", "pod"]
Metric = Literal["lines", "requests", "5xx", "4xx", "p50_ms", "p95_ms"]
CALL_METRICS: frozenset[str] = frozenset({"requests", "5xx", "4xx", "p50_ms", "p95_ms"})

# Bucket sizes in minutes; the profile uses the smallest that keeps a series readable.
_BUCKETS = (1, 2, 5, 10, 15, 30, 60, 120, 360, 720, 1440)
_PROFILE_ROWS = 180
_MIN_BUCKETS_FOR_INCIDENTS = 12
_LOOKBACK = timedelta(minutes=15)
# Tokens with two or more digits are ids (customer 23dsfd, unit b2b7x1), not message text,
# and so is whatever follows "customerId" or "userId", digits or not.
_MIXED_ID = re.compile(r"\b(?=(?:[A-Za-z_-]*\d){2})[A-Za-z0-9_-]{4,}\b")
_NAMED_ID = re.compile(
    r"(?i)\b((?:customer|user|account|unit|b2bunit|session)[ _-]?id|uid)\b([\s:=]+)[\w.@-]+"
)


def pattern_template(message: str) -> str:
    return _MIXED_ID.sub("<ID>", _NAMED_ID.sub(r"\1\2<ID>", template_of(message)))


# --- lifecycle events -------------------------------------------------------------------


class _EventRule(BaseModel):
    id: str
    title: str
    patterns: list[str] = Field(min_length=1)


@dataclass(frozen=True)
class EventRule:
    id: str
    title: str
    pattern: re.Pattern[str]


@cache
def lifecycle_rules() -> tuple[EventRule, ...]:
    text = (
        resources.files("sapcx_log_analyzer.classify")
        .joinpath("rules/events.yaml")
        .read_text(encoding="utf-8")
    )
    rules = [_EventRule.model_validate(item) for item in yaml.safe_load(text)["events"]]
    return tuple(
        EventRule(r.id, r.title, re.compile("|".join(f"(?:{p})" for p in r.patterns), re.I))
        for r in rules
    )


def lifecycle_event(message: str) -> EventRule | None:
    first_line = message.strip().splitlines()[0] if message.strip() else ""
    return next((rule for rule in lifecycle_rules() if rule.pattern.search(first_line)), None)


# --- results ----------------------------------------------------------------------------


@dataclass
class Pattern:
    id: str
    logger: str | None
    template: str
    level: LogLevel
    refs: list[int] = field(default_factory=list)
    first: datetime | None = None
    last: datetime | None = None
    aspects: set[str] = field(default_factory=set)
    pods: set[str] = field(default_factory=set)
    rule_id: str | None = None  # a rule-catalogue issue that matched lines of this pattern
    event: EventRule | None = None

    @property
    def count(self) -> int:
        return len(self.refs)

    @property
    def notable(self) -> bool:
        """Warnings, errors, known issues and lifecycle events, as opposed to routine lines."""
        return self.level.rank >= LogLevel.WARN.rank or bool(self.rule_id or self.event)

    def label(self, chars: int = 140) -> str:
        logger = short_logger(self.logger)
        template = self.template if len(self.template) <= chars else self.template[:chars] + " …"
        return f"{logger}: {template}" if logger else template


@dataclass(frozen=True)
class Window:
    start: datetime | None = None
    end: datetime | None = None

    @property
    def bounded(self) -> bool:
        return self.start is not None or self.end is not None


@dataclass
class Change:
    """How often something happened in a target window against a baseline window."""

    key: str
    baseline: int
    target: int
    expected: float  # the baseline rate scaled to the target window's length
    example: int | None

    @property
    def score(self) -> float:
        return (self.target - self.expected) / math.sqrt(self.expected + 1)

    @property
    def status(self) -> str:
        if self.baseline == 0:
            return "new"
        if self.target == 0:
            return "gone"
        return "up" if self.target > self.expected else "down"


@dataclass
class Comparison:
    baseline: Window
    target: Window
    baseline_minutes: float
    target_minutes: float
    rising: list[Change]
    falling: list[Change]


@dataclass
class EndpointStats:
    endpoint: str
    requests: int = 0
    client_errors: int = 0
    server_errors: int = 0
    durations: list[int] = field(default_factory=list)
    slowest: tuple[int, int] | None = None  # (duration, ref)
    first_failure: int | None = None

    def add(self, ref: int, call: HttpCall) -> None:
        self.requests += 1
        if 400 <= call.status < 500:
            self.client_errors += 1
        if call.status >= 500:
            self.server_errors += 1
            if self.first_failure is None:
                self.first_failure = ref
        if call.duration_ms is not None:
            self.durations.append(call.duration_ms)
            if self.slowest is None or call.duration_ms > self.slowest[0]:
                self.slowest = (call.duration_ms, ref)

    def percentile(self, q: float) -> int | None:
        return percentile(self.durations, q)


@dataclass
class Incident:
    start: datetime
    end: datetime
    errors: int
    server_errors: int
    requests: int
    signals: list[str]
    top: list[tuple[Pattern, int]]
    aspects: list[str]
    pods: list[str]
    first_error: int | None
    failing: bool = True  # errors or 5xx were abnormal, not only latency
    # Endpoints much slower than elsewhere in the file: (endpoint, p95, p95 elsewhere, slowest)
    slow_endpoints: list[tuple[str, int, int | None, int]] = field(default_factory=list)
    precursors: Comparison | None = None
    precursor_note: str | None = None
    # Lifecycle events in the lookback, as (first ref, count) per pattern.
    events_before: list[tuple[int, int]] = field(default_factory=list)


@dataclass
class LatencyShift:
    endpoint: str
    start: datetime
    end: datetime
    slow: int
    requests: int
    threshold_ms: int
    p95_ms: int
    usual_p95_ms: int | None
    example: int
    events_before: list[tuple[int, int]] = field(default_factory=list)


@dataclass
class TimelineRow:
    start: datetime
    total: float | None
    split: dict[str, float | None]
    first_ref: int | None


@dataclass
class Timeline:
    bucket_minutes: int
    columns: list[str]
    legend: dict[str, str]
    rows: list[TimelineRow]


@dataclass
class _Bucket:
    errors: int = 0
    requests: int = 0
    server_errors: int = 0
    durations: list[int] = field(default_factory=list)
    first_error: int | None = None


# --- the profile ------------------------------------------------------------------------


class Analysis:
    """Patterns, time series, incidents and comparisons over one loaded export."""

    def __init__(self, store: LogStore) -> None:
        self._store = store
        self.patterns: list[Pattern] = []
        self._pattern_index: list[int] = []
        self._by_id: dict[str, Pattern] = {}
        keys: dict[tuple[str, str], int] = {}
        templates: dict[str, str] = {}  # many lines repeat word for word
        stamps: list[float] = []
        for ref in range(1, len(store) + 1):
            record = store.record(ref)
            call = store.call_at(ref)
            if call is not None and call.access_log:
                # One pattern per endpoint and status class reads better than a masked
                # access log line, and skips the regexes for a third of the lines.
                template = f"{call.method} {call.endpoint} -> {call.status // 100}xx (access log)"
            elif record.message in templates:
                template = templates[record.message]
            else:
                template = templates[record.message] = pattern_template(record.message)
            key = (record.logger or "", template)
            index = keys.get(key)
            if index is None:
                index = keys[key] = len(self.patterns)
                pattern = Pattern(
                    f"P{index + 1}",
                    record.logger,
                    key[1],
                    record.level,
                    event=lifecycle_event(record.message),
                )
                self.patterns.append(pattern)
                self._by_id[pattern.id.lower()] = pattern
            pattern = self.patterns[index]
            self._add(pattern, ref, record)
            self._pattern_index.append(index)
            if record.timestamp is not None:
                stamps.append(record.timestamp.timestamp())
        # Records are sorted by time with untimed ones last, so refs 1..len(stamps) are
        # the timed ones, in order, and a time window is a contiguous range of refs.
        self._stamps = stamps
        self.calls: list[tuple[int, HttpCall]] = store.api_calls()[0]
        self._call_refs = [ref for ref, _ in self.calls]
        span = store.time_range()
        self.span = span
        self.bucket_minutes = pick_bucket(span, _PROFILE_ROWS)
        self._buckets = self._series()
        self.medians: dict[str, float | None] = {}
        self.incidents = self._detect_incidents()
        self.latency_shifts = self._latency_shifts()

    def _add(self, pattern: Pattern, ref: int, record: LogRecord) -> None:
        pattern.refs.append(ref)
        if record.level.rank > pattern.level.rank:
            pattern.level = record.level
        if record.timestamp is not None:
            if pattern.first is None:
                pattern.first = record.timestamp
            pattern.last = record.timestamp
        if record.aspect:
            pattern.aspects.add(record.aspect)
        if record.pod:
            pattern.pods.add(record.pod)
        classification = self._store.classification(ref)
        if classification and classification.rule_id != UNCLASSIFIED_ID and not pattern.rule_id:
            pattern.rule_id = classification.rule_id

    # --- lookups ------------------------------------------------------------------------

    def pattern_of(self, ref: int) -> Pattern:
        return self.patterns[self._pattern_index[ref - 1]]

    def pattern(self, pattern_id: str) -> Pattern:
        pattern = self._by_id.get(pattern_id.strip().lower())
        if pattern is None:
            raise KeyError(
                f"No pattern {pattern_id!r}; ids run from P1 to P{len(self.patterns)}. "
                "Use list_patterns to find them."
            )
        return pattern

    def refs_in(self, window: Window) -> range:
        """The refs inside a time window; an unbounded window includes untimed records."""
        if not window.bounded:
            return range(1, len(self._store) + 1)
        low = 0 if window.start is None else bisect_left(self._stamps, window.start.timestamp())
        high = (
            len(self._stamps)
            if window.end is None
            else bisect_right(self._stamps, window.end.timestamp())
        )
        return range(low + 1, high + 1)

    def calls_in(self, window: Window) -> list[tuple[int, HttpCall]]:
        refs = self.refs_in(window)
        low = bisect_left(self._call_refs, refs.start)
        high = bisect_left(self._call_refs, refs.stop)
        return self.calls[low:high]

    def minutes(self, window: Window) -> float:
        """How much of the export a window covers, in minutes (at least one if it overlaps)."""
        if self.span is None:
            return 0.0
        first, last = self.span
        start = max(window.start or first, first)
        end = min(window.end or last, last)
        if end < start:
            return 0.0
        return max((end - start).total_seconds() / 60, 1.0)

    def clock(self, stamp: datetime | None) -> str:
        if stamp is None:
            return "-"
        stamp = stamp.astimezone(UTC)
        if self.span and self.span[0].date() == self.span[1].date():
            return stamp.strftime("%H:%M")
        return stamp.strftime("%m-%d %H:%M")

    def endpoint_stats(
        self, window: Window, path: str | None = None, method: str | None = None
    ) -> list[EndpointStats]:
        terms = alternatives(path)
        stats: dict[str, EndpointStats] = {}
        for ref, call in self.calls_in(window):
            if method and call.method.upper() != method.upper():
                continue
            endpoint = f"{call.method} {call.endpoint}"
            if terms and not any(t in call.path.lower() or t in endpoint.lower() for t in terms):
                continue
            stats.setdefault(endpoint, EndpointStats(endpoint)).add(ref, call)
        return list(stats.values())

    # --- series and incidents -----------------------------------------------------------

    def _bucket_of(self, stamp: datetime, minutes: int) -> int:
        assert self.span is not None
        origin = floor_time(self.span[0], minutes)
        return int((stamp - origin).total_seconds() // (minutes * 60))

    def _series(self) -> list[_Bucket]:
        if self.span is None:
            return []
        buckets = [_Bucket() for _ in range(self._bucket_of(self.span[1], self.bucket_minutes) + 1)]
        for ref in self.refs_in(Window(*self.span)):
            record = self._store.record(ref)
            if record.level.rank >= LogLevel.ERROR.rank and record.timestamp is not None:
                bucket = buckets[self._bucket_of(record.timestamp, self.bucket_minutes)]
                bucket.errors += 1
                if bucket.first_error is None:
                    bucket.first_error = ref
        for ref, call in self.calls:
            stamp = self._store.record(ref).timestamp
            if stamp is None:
                continue
            bucket = buckets[self._bucket_of(stamp, self.bucket_minutes)]
            bucket.requests += 1
            if call.status >= 500:
                bucket.server_errors += 1
            if call.duration_ms is not None:
                bucket.durations.append(call.duration_ms)
        return buckets

    def _detect_incidents(self) -> list[Incident]:
        buckets = self._buckets
        if len(buckets) < _MIN_BUCKETS_FOR_INCIDENTS:
            return []
        errors = [float(b.errors) for b in buckets]
        server = [float(b.server_errors) for b in buckets]
        p95s = [percentile(b.durations, 0.95) if len(b.durations) >= 5 else None for b in buckets]
        timed = [float(p) for p in p95s if p is not None]
        self.medians = {
            "errors": median(errors),
            "5xx": median(server),
            "p95_ms": median(timed) if timed else None,
        }
        error_limit = _limit(errors, factor=3, floor=5)
        server_limit = _limit(server, factor=3, floor=3)
        p95_limit = _limit(timed, factor=2.5, floor=1000) if len(timed) >= 8 else math.inf
        failing = {
            i
            for i, b in enumerate(buckets)
            if b.errors > error_limit or b.server_errors > server_limit
        }
        slow = {
            i
            for i, b in enumerate(buckets)
            if (p95s[i] or 0) > p95_limit and _slow_enough(b.durations, p95_limit)
        }
        incidents = []
        for first, last in _runs(sorted(failing | slow), gap=1):
            run = set(range(first, last + 1))
            # A slow minute or two without errors is noise; per-endpoint shifts cover it.
            if run & failing or len(run & slow) >= 2:
                incidents.append(self._incident(first, last, p95s, failing=bool(run & failing)))
        return incidents

    def _incident(
        self, first: int, last: int, p95s: Sequence[int | None], failing: bool
    ) -> Incident:
        assert self.span is not None
        origin = floor_time(self.span[0], self.bucket_minutes)
        size = timedelta(minutes=self.bucket_minutes)
        start, end = origin + first * size, origin + (last + 1) * size
        window = Window(start, end - timedelta(microseconds=1))
        part = self._buckets[first : last + 1]
        per = "min" if self.bucket_minutes == 1 else f"{self.bucket_minutes} min"
        signals = []
        peak = max(range(first, last + 1), key=lambda i: self._buckets[i].errors)
        if self._buckets[peak].errors:
            signals.append(
                f"errors up to {self._buckets[peak].errors} per {per} at "
                f"{self.clock(origin + peak * size)} (median {self.medians['errors']:g})"
            )
        peak = max(range(first, last + 1), key=lambda i: self._buckets[i].server_errors)
        if self._buckets[peak].server_errors:
            signals.append(
                f"5xx responses up to {self._buckets[peak].server_errors} per {per} "
                f"(median {self.medians['5xx']:g})"
            )
        peak = max(range(first, last + 1), key=lambda i: p95s[i] or 0)
        usual = self.medians["p95_ms"]
        if p95s[peak] and usual and (p95s[peak] or 0) > 2 * usual:
            signals.append(f"p95 latency up to {p95s[peak]:,} ms (median {usual:,.0f} ms)")
        notable: Counter[int] = Counter()
        aspects: Counter[str] = Counter()
        pods: Counter[str] = Counter()
        slow = 2 * usual if usual else math.inf
        for ref in self.refs_in(window):
            record = self._store.record(ref)
            warning = record.level.rank >= LogLevel.WARN.rank
            if warning:
                notable[self._pattern_index[ref - 1]] += 1
            call = self._store.call_at(ref)
            affected = warning or (
                call is not None and (call.status >= 500 or (call.duration_ms or 0) > slow)
            )
            if affected and record.aspect:
                aspects[record.aspect] += 1
            if affected and record.pod:
                pods[record.pod] += 1
        incident = Incident(
            start=start,
            end=end,
            errors=sum(b.errors for b in part),
            server_errors=sum(b.server_errors for b in part),
            requests=sum(b.requests for b in part),
            signals=signals,
            top=[(self.patterns[i], n) for i, n in notable.most_common(5)],
            aspects=[a for a, _ in aspects.most_common()],
            pods=[p for p, _ in pods.most_common()],
            first_error=next((b.first_error for b in part if b.first_error), None),
            slow_endpoints=self._slow_endpoints(window),
            failing=failing,
        )
        lookback = max(_LOOKBACK, 3 * size)
        before = Window(self.span[0], start - lookback - timedelta(microseconds=1))
        if start - lookback - self.span[0] < lookback:
            incident.precursor_note = (
                "It starts too close to the beginning of the export to compare with what "
                "came before."
            )
        else:
            just_before = Window(start - lookback, start - timedelta(microseconds=1))
            incident.precursors = self.compare(before, just_before, limit=12)
            # Lifecycle events are listed on their own, however rare they are.
            incident.precursors.rising = [
                c for c in incident.precursors.rising if self._by_id[c.key.lower()].event is None
            ][:6]
            incident.events_before = self._events_in(just_before, before)
        return incident

    def _events_in(self, window: Window, baseline: Window) -> list[tuple[int, int]]:
        """(first ref, count) per lifecycle event pattern in ``window``, leaving out events
        that recur routinely, such as a CronJob that also ran twice in the baseline."""
        routine = Counter(
            self.pattern_of(ref).id
            for ref in self.refs_in(baseline)
            if self.pattern_of(ref).event is not None
        )
        found: dict[str, list[int]] = {}
        for ref in self.refs_in(window):
            pattern = self.pattern_of(ref)
            if pattern.event is not None and routine[pattern.id] < 2:
                found.setdefault(pattern.id, []).append(ref)
        return [(refs[0], len(refs)) for refs in found.values()][:8]

    def _in_outage(self, stamp: datetime) -> bool:
        return any(i.failing and i.start <= stamp < i.end for i in self.incidents)

    def _slow_endpoints(self, window: Window) -> list[tuple[str, int, int | None, int]]:
        """Endpoints whose p95 in the window is at least double their p95 elsewhere."""
        inside = {s.endpoint: s for s in self.endpoint_stats(window)}
        refs = self.refs_in(window)
        outside: dict[str, list[int]] = defaultdict(list)
        for ref, call in self.calls:
            if call.duration_ms is not None and ref not in refs:
                outside[f"{call.method} {call.endpoint}"].append(call.duration_ms)
        slow = []
        for endpoint, stats in inside.items():
            p95, usual = stats.percentile(0.95), percentile(outside.get(endpoint, []), 0.95)
            if (
                p95 is not None
                and stats.slowest is not None
                and len(stats.durations) >= 3
                and (usual is None or p95 >= 2 * usual)
                and p95 >= 1000
            ):
                slow.append((endpoint, p95, usual, stats.slowest[1]))
        return sorted(slow, key=lambda s: -s[1] / (s[2] or 1))[:3]

    def _latency_shifts(self) -> list[LatencyShift]:
        """Endpoints that were much slower than their own norm for a while, outside incidents."""
        if self.span is None:
            return []
        minutes = max(self.bucket_minutes, 5)
        size = timedelta(minutes=minutes)
        origin = floor_time(self.span[0], minutes)
        by_endpoint: dict[str, list[tuple[int, HttpCall, datetime]]] = defaultdict(list)
        for ref, call in self.calls:
            stamp = self._store.record(ref).timestamp
            if call.duration_ms is not None and stamp is not None:
                by_endpoint[f"{call.method} {call.endpoint}"].append((ref, call, stamp))
        shifts: list[LatencyShift] = []
        for endpoint, calls in by_endpoint.items():
            if len(calls) < 30:
                continue
            usual = median(c.duration_ms or 0 for _, c, _ in calls)
            threshold = int(max(4 * usual, usual + 1000))
            buckets: dict[int, list[tuple[int, int]]] = defaultdict(list)
            for ref, call, stamp in calls:
                buckets[self._bucket_of(stamp, minutes)].append((call.duration_ms or 0, ref))
            flagged = sorted(
                i
                for i, items in buckets.items()
                if (slow := sum(1 for d, _ in items if d > threshold)) >= 2
                and slow / len(items) >= 0.3
            )
            for first, last in _runs(flagged, gap=1):
                start, end = origin + first * size, origin + (last + 1) * size
                if any(i.failing and i.start < end and start < i.end for i in self.incidents):
                    continue  # part of an outage, where everything is slow
                inside = [item for i in range(first, last + 1) for item in buckets.get(i, [])]
                outside = [
                    c.duration_ms or 0
                    for _, c, s in calls
                    if not start <= s < end and not self._in_outage(s)
                ]
                shifts.append(
                    LatencyShift(
                        endpoint=endpoint,
                        start=start,
                        end=end,
                        slow=sum(1 for d, _ in inside if d > threshold),
                        requests=len(inside),
                        threshold_ms=threshold,
                        p95_ms=percentile([d for d, _ in inside], 0.95) or 0,
                        usual_p95_ms=percentile(outside, 0.95),
                        example=max(inside)[1],
                        events_before=self._events_in(
                            Window(start - _LOOKBACK, start),
                            Window(self.span[0], start - _LOOKBACK - timedelta(microseconds=1)),
                        ),
                    )
                )
        return sorted(shifts, key=lambda s: -s.slow)[:5]

    # --- comparisons and timelines ------------------------------------------------------

    def compare(
        self,
        baseline: Window,
        target: Window,
        dimension: LineDimension = "pattern",
        min_level: LogLevel = LogLevel.TRACE,
        limit: int = 15,
    ) -> Comparison:
        """What rose, appeared, fell or stopped in ``target`` against ``baseline``."""
        key_of = self._line_key(dimension)
        before: Counter[str] = Counter()
        after: Counter[str] = Counter()
        examples: dict[str, int] = {}  # first in the target window, else first in the baseline
        for counts, window in ((after, target), (before, baseline)):
            for ref in self.refs_in(window):
                record = self._store.record(ref)
                if record.level.rank < min_level.rank:
                    continue
                key = key_of(ref, record)
                counts[key] += 1
                examples.setdefault(key, ref)
        b_minutes, t_minutes = self.minutes(baseline), self.minutes(target)
        changes = [
            Change(
                key,
                before[key],
                after[key],
                before[key] * t_minutes / b_minutes if b_minutes else 0.0,
                examples.get(key),
            )
            for key in before.keys() | after.keys()
        ]
        rising = [c for c in changes if self._rose(c, dimension)]
        # Warnings, errors and events before routine lines; never seen before before more.
        rising.sort(key=lambda c: (-self._weight(c, dimension), c.status != "new", -c.score))
        falling = [c for c in changes if c.score <= -3 and c.baseline >= 3]
        falling.sort(key=lambda c: c.score)
        return Comparison(baseline, target, b_minutes, t_minutes, rising[:limit], falling[:5])

    def _rose(self, change: Change, dimension: LineDimension) -> bool:
        if change.status == "new":
            return change.target >= 3 or self._weight(change, dimension) > 0
        # Traffic rises and falls by a few percent all the time; ask for half again as much.
        return change.score >= 3 and change.target >= 3 and change.target >= 1.5 * change.expected

    def _weight(self, change: Change, dimension: LineDimension) -> int:
        if dimension != "pattern":
            return 0
        return 1 if self._by_id[change.key.lower()].notable else 0

    def _line_key(self, dimension: LineDimension) -> Callable[[int, LogRecord], str]:
        match dimension:
            case "pattern":
                return lambda ref, record: self.patterns[self._pattern_index[ref - 1]].id
            case "level":
                return lambda ref, record: record.level.value
            case "aspect":
                return lambda ref, record: record.aspect or "-"
            case "pod":
                return lambda ref, record: record.pod or "-"
            case "logger":
                return lambda ref, record: record.logger or "-"

    def timeline(
        self,
        window: Window,
        metric: Metric = "lines",
        split_by: LineDimension | CallDimension | None = None,
        bucket_minutes: int | None = None,
        keep: Callable[[int, LogRecord], bool] | None = None,
        path: str | None = None,
        columns: int = 5,
    ) -> Timeline:
        """A metric per time bucket, optionally split by one dimension (top ``columns``)."""
        assert self.span is not None
        start = max(window.start or self.span[0], self.span[0])
        end = min(window.end or self.span[1], self.span[1])
        minutes = bucket_minutes or pick_bucket((start, end), 60)
        items = list(self._timeline_items(Window(start, end), metric, split_by, keep, path))
        totals: Counter[str] = Counter()
        for _, key, _, _ in items:
            totals[key] += 1
        top = [key for key, _ in totals.most_common(columns)] if split_by else []
        origin = floor_time(start, minutes)
        size = timedelta(minutes=minutes)
        count = int((end - origin) // size) + 1
        values: list[list[tuple[str, int, int]]] = [[] for _ in range(count)]
        for stamp, key, value, ref in items:
            values[int((stamp - origin) // size)].append((key, value, ref))
        rows = []
        for i, bucket in enumerate(values):
            split: dict[str, float | None] = {}
            if split_by:
                for key in top:
                    split[key] = _aggregate(metric, [v for k, v, _ in bucket if k == key])
                if len(totals) > len(top):
                    split["other"] = _aggregate(metric, [v for k, v, _ in bucket if k not in top])
            rows.append(
                TimelineRow(
                    origin + i * size,
                    _aggregate(metric, [v for _, v, _ in bucket]),
                    split,
                    bucket[0][2] if bucket else None,
                )
            )
        legend = {key: self._legend(split_by, key) for key in top} if split_by else {}
        if split_by and len(totals) > len(top):
            top.append("other")
        return Timeline(minutes, top, legend, rows)

    def _timeline_items(
        self,
        window: Window,
        metric: Metric,
        split_by: LineDimension | CallDimension | None,
        keep: Callable[[int, LogRecord], bool] | None,
        path: str | None,
    ) -> Iterable[tuple[datetime, str, int, int]]:
        if metric in CALL_METRICS:
            terms = alternatives(path)
            for ref, call in self.calls_in(window):
                record = self._store.record(ref)
                endpoint = f"{call.method} {call.endpoint}"
                if record.timestamp is None:
                    continue
                if terms and not any(
                    t in call.path.lower() or t in endpoint.lower() for t in terms
                ):
                    continue
                if keep is not None and not keep(ref, record):
                    continue
                if metric in ("p50_ms", "p95_ms"):
                    if call.duration_ms is None:
                        continue
                    value = call.duration_ms
                elif metric == "5xx":
                    value = int(call.status >= 500)
                elif metric == "4xx":
                    value = int(400 <= call.status < 500)
                else:
                    value = 1
                yield record.timestamp, self._call_key(split_by, call, record), value, ref
            return
        key_of = (
            self._line_key(cast(LineDimension, split_by)) if split_by in _LINE_DIMENSIONS else None
        )
        for ref in self.refs_in(window):
            record = self._store.record(ref)
            if record.timestamp is None or (keep is not None and not keep(ref, record)):
                continue
            key = key_of(ref, record) if key_of else ""
            yield record.timestamp, key, 1, ref

    @staticmethod
    def _call_key(split_by: str | None, call: HttpCall, record: LogRecord) -> str:
        match split_by:
            case "endpoint":
                return f"{call.method} {call.endpoint}"
            case "status":
                return f"{call.status // 100}xx"
            case "aspect":
                return record.aspect or "-"
            case "pod":
                return record.pod or "-"
        return ""

    def _legend(self, split_by: str | None, key: str) -> str:
        if split_by == "pattern":
            pattern = self._by_id[key.lower()]
            return f"{pattern.level.value} {pattern.label(100)}"
        return key


_LINE_DIMENSIONS = frozenset({"pattern", "level", "aspect", "pod", "logger"})


# --- helpers ----------------------------------------------------------------------------


def short_logger(logger: str | None) -> str:
    return logger.rsplit(".", 1)[-1] if logger else ""


def alternatives(text: str | None) -> list[str]:
    """``a|b`` means a or b; terms are matched as lower-case substrings."""
    return [term.strip().lower() for term in (text or "").split("|") if term.strip()]


def percentile(values: Sequence[int], q: float) -> int | None:
    """Nearest-rank percentile, so the value is one that was actually measured."""
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(q * len(ordered)) - 1)]


def pick_bucket(span: tuple[datetime, datetime] | None, rows: int) -> int:
    if span is None:
        return 1
    minutes = (span[1] - span[0]).total_seconds() / 60
    return next((b for b in _BUCKETS if minutes / b <= rows), _BUCKETS[-1])


def floor_time(stamp: datetime, minutes: int) -> datetime:
    epoch = datetime(1970, 1, 1, tzinfo=stamp.tzinfo or UTC)
    size = timedelta(minutes=minutes)
    return epoch + ((stamp - epoch) // size) * size


def _limit(values: Sequence[float], factor: float, floor: float) -> float:
    """A robust "well above normal" threshold: median plus four scaled MADs, and at least
    ``factor`` times the median and ``floor`` above it."""
    if not values:
        return math.inf
    middle = median(values)
    spread = median(abs(v - middle) for v in values) * 1.4826
    return max(middle + 4 * spread, factor * middle, middle + floor)


def _slow_enough(durations: Sequence[int], limit: float) -> bool:
    """A latency spike needs several slow requests, not one slow call among few."""
    slow = sum(1 for d in durations if d > limit)
    return slow >= max(3, 0.1 * len(durations))


def _runs(indexes: Sequence[int], gap: int) -> list[tuple[int, int]]:
    """Merge sorted bucket indexes into (first, last) runs, bridging up to ``gap`` buckets."""
    runs: list[tuple[int, int]] = []
    for i in indexes:
        if runs and i - runs[-1][1] <= gap + 1:
            runs[-1] = (runs[-1][0], i)
        else:
            runs.append((i, i))
    return runs


def _aggregate(metric: Metric, values: Sequence[int]) -> float | None:
    if metric == "p95_ms":
        return percentile(values, 0.95)
    if metric == "p50_ms":
        return percentile(values, 0.5)
    return float(sum(values))
