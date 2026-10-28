"""The export profile as compact text for the system prompt.

It gives Claude the shape of the whole file before the first question: candidate
incidents and what came before them, the main problem patterns, endpoint traffic,
errors and latency, and lifecycle events. It is computed once per file and sent with
every conversation as part of the cached system prompt, so it stays short.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sapcx_log_analyzer.ask.analysis import Analysis, Change, Comparison, EndpointStats, Window
from sapcx_log_analyzer.models import LogLevel

if TYPE_CHECKING:
    from sapcx_log_analyzer.ask.store import LogStore

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_TOP_PROBLEMS = 10
_TOP_ENDPOINTS = 5
_MAX_EVENTS = 12


def render_digest(store: LogStore) -> str:
    analysis = store.analysis
    if not len(store):
        return "The export is empty."
    lines = ["Profile of this export, computed by code when it loaded (times are UTC)."]
    lines.append(_summary(store, analysis))
    lines += ["", *_incidents(store, analysis)]
    shifts = _latency_shifts(store, analysis)
    if shifts:
        lines += ["", "Endpoints much slower than their own norm for a while (outside incidents):"]
        lines += shifts
    lines += ["", "Main problem patterns (WARN and above, most frequent first):"]
    lines += _problems(analysis) or ["- none"]
    endpoints = _endpoints(analysis)
    if endpoints:
        lines += ["", *endpoints]
    events = _events(store, analysis)
    if events:
        lines += ["", "Lifecycle events (deployments, restarts, CronJobs, indexing, syncs):"]
        lines += events
    lines += [
        "",
        "Pattern ids (P…) work in list_patterns, timeline and compare_windows. The incidents "
        "are candidates found by thresholds; confirm them with timeline before relying on them.",
    ]
    return "\n".join(lines)


def _summary(store: LogStore, analysis: Analysis) -> str:
    notable = sum(1 for p in analysis.patterns if p.level.rank >= LogLevel.WARN.rank)
    calls = len(analysis.calls)
    failed = sum(1 for _, c in analysis.calls if c.status >= 500)
    span = analysis.span
    if span is None:
        when = "no timestamps"
    else:
        when = f"{span[0].isoformat(timespec='seconds')} to {span[1].isoformat(timespec='seconds')}"
    text = (
        f"- {len(store):,} lines, {when}; {len(analysis.patterns):,} message patterns "
        f"({notable} at WARN or above)"
    )
    if calls:
        text += f"; {calls:,} HTTP requests, {_share(failed, calls)} with 5xx"
    return text + "."


def _incidents(store: LogStore, analysis: Analysis) -> list[str]:
    if analysis.span is None:
        return ["Candidate incidents: none (the export has no timestamps)."]
    if not analysis.medians:
        minutes = (analysis.span[1] - analysis.span[0]).total_seconds() / 60
        return [
            f"Candidate incidents: none flagged. The export spans {minutes:.0f} min, too short "
            "to compare against its own baseline; use timeline to see how it develops."
        ]
    if not analysis.incidents:
        return [
            "Candidate incidents: none. No time bucket had errors, 5xx responses or latency "
            "well above this file's median."
        ]
    lines = [
        f"Candidate incidents ({analysis.bucket_minutes}-min buckets well above this file's "
        "median for errors, 5xx or p95 latency):"
    ]
    for number, incident in enumerate(analysis.incidents[:5], 1):
        minutes = (incident.end - incident.start).total_seconds() / 60
        where = ", ".join(incident.aspects[:3]) or "-"
        lines.append(
            f"{number}. {analysis.clock(incident.start)}-{analysis.clock(incident.end)} "
            f"({minutes:.0f} min): {'; '.join(incident.signals) or 'elevated errors'}. "
            f"{incident.errors} error lines, {incident.server_errors} of {incident.requests} "
            f"requests with 5xx. Aspects: {where}; pods: {len(incident.pods)}."
            + (f" First error #{incident.first_error}." if incident.first_error else "")
        )
        if incident.top:
            top = "; ".join(
                f"{p.id} {p.level.value} x{n}{_rule(p.rule_id)} {p.label(90)!r}"
                for p, n in incident.top[:4]
            )
            lines.append(f"   Main patterns: {top}")
        if incident.slow_endpoints:
            slow = "; ".join(
                f"{endpoint} p95 {p95:,} ms (elsewhere {_ms(usual)}), slowest #{ref}"
                for endpoint, p95, usual, ref in incident.slow_endpoints
            )
            lines.append(f"   Slower endpoints: {slow}")
        if incident.precursors is not None:
            lines.append("   " + _precursors(analysis, incident.precursors))
            if incident.events_before:
                events = _event_list(store, analysis, incident.events_before)
                lines.append(f"   Lifecycle events in those minutes: {events}")
        elif incident.precursor_note:
            lines.append(f"   {incident.precursor_note}")
    if len(analysis.incidents) > 5:
        lines.append(f"({len(analysis.incidents) - 5} smaller candidate incidents not shown.)")
    return lines


def _precursors(analysis: Analysis, comparison: Comparison) -> str:
    target, baseline = comparison.target, comparison.baseline
    head = (
        f"Rose or appeared in the {comparison.target_minutes:.0f} min before "
        f"({analysis.clock(target.start)}-{analysis.clock(target.end)}, against "
        f"{analysis.clock(baseline.start)}-{analysis.clock(baseline.end)}): "
    )
    if not comparison.rising:
        return head + "nothing stands out."
    return head + "; ".join(_change(analysis, c) for c in comparison.rising[:6])


def _change(analysis: Analysis, change: Change) -> str:
    pattern = analysis.pattern(change.key)
    if change.status == "new":
        how = f"new x{change.target}"
    else:
        how = f"x{change.target} (expected {change.expected:.0f})"
    event = f" [{pattern.event.title}]" if pattern.event else ""
    example = f" #{change.example}" if change.example else ""
    return f"{pattern.id} {pattern.level.value} {how}{event} {pattern.label(80)!r}{example}"


def _latency_shifts(store: LogStore, analysis: Analysis) -> list[str]:
    lines = []
    previous: list[tuple[int, int]] = []
    for s in analysis.latency_shifts:
        lines.append(
            f"- {s.endpoint}: {s.slow} of {s.requests} requests over {s.threshold_ms:,} ms in "
            f"{analysis.clock(s.start)}-{analysis.clock(s.end)} (p95 {s.p95_ms:,} ms, "
            f"elsewhere {_ms(s.usual_p95_ms)}), slowest #{s.example}"
        )
        if s.events_before and s.events_before == previous:
            lines.append("  Same lifecycle events before it as the line above.")
        elif s.events_before:
            lines.append(
                "  Lifecycle events in the 15 min before: "
                + _event_list(store, analysis, s.events_before)
            )
        previous = s.events_before
    return lines


def _event_list(store: LogStore, analysis: Analysis, events: list[tuple[int, int]]) -> str:
    return "; ".join(
        f"{analysis.clock(store.record(ref).timestamp)} "
        f"{_event_title(analysis, ref)}{f' x{count}' if count > 1 else ''} #{ref}"
        for ref, count in events
    )


def _problems(analysis: Analysis) -> list[str]:
    problems = sorted(
        (p for p in analysis.patterns if p.level.rank >= LogLevel.WARN.rank),
        key=lambda p: (-p.count, -p.level.rank),
    )
    return [
        f"- {p.id} {p.level.value} x{p.count} {analysis.clock(p.first)}-{analysis.clock(p.last)}"
        f" {','.join(sorted(p.aspects)) or '-'}{_rule(p.rule_id)} {p.label(110)!r} e.g. "
        f"#{p.refs[0]}"
        for p in problems[:_TOP_PROBLEMS]
    ] + (
        [f"- … {len(problems) - _TOP_PROBLEMS} more; use list_patterns."]
        if len(problems) > _TOP_PROBLEMS
        else []
    )


def _endpoints(analysis: Analysis) -> list[str]:
    stats = analysis.endpoint_stats(Window())
    if not stats:
        return []
    lines = ["Busiest endpoints:"]
    lines += [_endpoint(s) for s in sorted(stats, key=lambda s: -s.requests)[:_TOP_ENDPOINTS]]
    timed = [s for s in stats if len(s.durations) >= 20]
    if timed:
        lines.append("Slowest endpoints (p95, at least 20 timed requests):")
        lines += [
            _endpoint(s)
            for s in sorted(timed, key=lambda s: -(s.percentile(0.95) or 0))[:_TOP_ENDPOINTS]
        ]
    failing = [s for s in stats if s.server_errors]
    if failing:
        lines.append("Endpoints with the most 5xx responses:")
        lines += [
            _endpoint(s) for s in sorted(failing, key=lambda s: -s.server_errors)[:_TOP_ENDPOINTS]
        ]
    return lines


def _endpoint(stats: EndpointStats) -> str:
    text = f"- {stats.endpoint}: {stats.requests:,} requests"
    if stats.server_errors:
        text += f", 5xx {_share(stats.server_errors, stats.requests)}"
    if stats.client_errors:
        text += f", 4xx {_share(stats.client_errors, stats.requests)}"
    p95 = stats.percentile(0.95)
    if p95 is not None:
        text += f", p95 {p95:,} ms"
    return text


def _events(store: LogStore, analysis: Analysis) -> list[str]:
    events = sorted(
        (p for p in analysis.patterns if p.event is not None),
        key=lambda p: (p.first is None, p.first or _EPOCH),
    )
    lines = []
    for pattern in events[:_MAX_EVENTS]:
        assert pattern.event is not None
        where = ",".join(sorted(pattern.aspects)) or "-"
        if pattern.count <= 3:
            when = ", ".join(
                f"{analysis.clock(store.record(ref).timestamp)} #{ref}" for ref in pattern.refs
            )
        else:
            when = (
                f"x{pattern.count} from {analysis.clock(pattern.first)} to "
                f"{analysis.clock(pattern.last)}, e.g. #{pattern.refs[0]}"
            )
        lines.append(
            f"- {pattern.id} {pattern.event.title} on {where}: {when} {pattern.label(90)!r}"
        )
    if len(events) > _MAX_EVENTS:
        lines.append(f"- … {len(events) - _MAX_EVENTS} more; use list_patterns with events_only.")
    return lines


def _event_title(analysis: Analysis, ref: int) -> str:
    pattern = analysis.pattern_of(ref)
    title = pattern.event.title if pattern.event else ""
    return f"{title}: {pattern.label(70)!r}"


def _ms(value: int | None) -> str:
    return "-" if value is None else f"{value:,} ms"


def _rule(rule_id: str | None) -> str:
    return f" [issue={rule_id}]" if rule_id else ""


def _share(part: int, whole: int) -> str:
    if not whole:
        return "0%"
    share = 100 * part / whole
    return f"{share:.1f}%" if share < 10 else f"{share:.0f}%"
