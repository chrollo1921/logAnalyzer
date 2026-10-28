"""The export profile and the analysis tools, for questions about the whole file."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from sapcx_log_analyzer.ask import AskSession, LogStore, analysis_tools
from sapcx_log_analyzer.ask.analysis import Window, lifecycle_event, pattern_template
from sapcx_log_analyzer.ask.tools import ToolInputError, describe_call, run_tool
from sapcx_log_analyzer.config import Settings
from sapcx_log_analyzer.demo import write_demo_export
from sapcx_log_analyzer.models import LogLevel
from tests.conftest import FIXTURES, ScriptedChatProvider, make_record, text_turn, tool_turn

DAY = "2026-10-20T"


@pytest.fixture(scope="module")
def demo(tmp_path_factory: pytest.TempPathFactory) -> LogStore:
    # Big enough for the planted outage and the slow payment period to stand out.
    path = tmp_path_factory.mktemp("demo") / "demo.json"
    write_demo_export(path, size_mb=3, seed=7)
    return LogStore.load(path, Settings())


@pytest.fixture(scope="module")
def small() -> LogStore:
    return LogStore.load(FIXTURES / "transactions.ndjson", Settings())


def tool(store: LogStore, name: str, args: dict[str, object]) -> str:
    return run_tool(store, name, args, 50_000)


def at(clock: str) -> datetime:
    return datetime.fromisoformat(f"{DAY}{clock}:00+00:00")


def pattern_like(store: LogStore, text: str) -> str:
    return next(p.id for p in store.analysis.patterns if text in p.template)


# --- patterns and events ------------------------------------------------------------


@pytest.mark.parametrize(
    ("message", "template"),
    [
        ("Customer x logged in, customerId uhfkvm", "Customer x logged in, customerId <ID>"),
        ("userId=abc failed", "userId=<ID> failed"),
        ("Order 00012345 for b2b7x1 and 23dsfd", "Order <NUM> for <ID><NUM> and <ID>"),
        ("Failed to place order for user and cart", "Failed to place order for user and cart"),
    ],
)
def test_pattern_template(message: str, template: str) -> None:
    assert pattern_template(message) == template


@pytest.mark.parametrize(
    ("message", "event"),
    [
        ("Server startup in [88412] milliseconds", "server-start"),
        ("Stopping service [Catalina]", "server-stop"),
        ("Starting CronJob sync-electronicsProductCatalog-Staged-Online", "catalog-sync"),
        ("Starting CronJob update-electronicsIndex-cronJob", "cronjob-start"),
        ("CronJob x finished with result ERROR", "cronjob-end"),
        ("Full index operation started for electronicsIndex", "solr-index"),
        ("Switched to fallback region psp-eu2", "integration-failover"),
        ("Clearing region cache", "cache-clear"),
        ("Could not calculate cart", None),
        ("", None),
    ],
)
def test_lifecycle_events(message: str, event: str | None) -> None:
    rule = lifecycle_event(message)
    assert (rule.id if rule else None) == event


def test_patterns_group_lines(small: LogStore) -> None:
    analysis = small.analysis
    assert sum(p.count for p in analysis.patterns) == len(small)
    first = analysis.pattern_of(1)
    assert analysis.pattern(first.id.lower()) is first
    assert first.refs[0] == 1 and first.first is not None
    with pytest.raises(KeyError, match="No pattern 'P999'"):
        analysis.pattern("P999")
    assert analysis.refs_in(Window()) == range(1, len(small) + 1)
    assert analysis.minutes(Window(at("10:00"), at("11:00"))) == 0


def test_a_short_export_has_no_baseline(small: LogStore) -> None:
    assert small.analysis.incidents == []
    digest = small.digest()
    assert "too short to compare against its own baseline" in digest
    assert small.overview()["candidate_incidents"] == 0


def test_exports_without_timestamps_or_lines(small: LogStore) -> None:
    records = [
        make_record("Could not calculate cart 1"),
        make_record("Could not calculate cart 2"),
        make_record("Server startup in [9] milliseconds", logger="a", level=LogLevel.INFO),
        make_record("Server startup in [9] milliseconds", logger="b", level=LogLevel.INFO),
    ]
    untimed = LogStore("untimed", records, [None] * 4, [None] * 4, [], small.redactor)
    assert len(untimed.analysis.patterns) == 3 and untimed.analysis.pattern_of(2).count == 2
    digest = untimed.digest()
    assert "no timestamps" in digest and "Server started on -: - #3" in digest
    assert "no timeline" in tool(untimed, "timeline", {})
    assert "no timeline" in tool(
        untimed, "compare_windows", {"target_start": f"{DAY}09:00:00Z", "target_end": "2026-10-21"}
    )
    assert tool(untimed, "list_patterns", {}).startswith("3 of 3 message patterns match")
    empty = LogStore("empty", [], [], [], [], small.redactor)
    assert empty.digest() == "The export is empty."


# --- incidents and the digest ---------------------------------------------------------


def test_the_outage_and_what_came_before_it(demo: LogStore) -> None:
    analysis = demo.analysis
    outage = analysis.incidents[0]
    assert (
        outage.failing and outage.start == at("08:50") and outage.end in (at("08:57"), at("08:58"))
    )
    assert outage.server_errors > 20 and outage.aspects == ["api"]
    assert outage.top[0][0].rule_id == "db-connection-pool-exhausted"
    assert outage.precursors is not None
    rising = [analysis.pattern(c.key).template for c in outage.precursors.rising]
    assert any("HikariPool" in t for t in rising) and any("Slow query" in t for t in rising)
    events = [analysis.pattern_of(ref).template for ref, _ in outage.events_before]
    assert any("Starting CronJob sync-electronicsProductCatalog" in t for t in events)
    # The index CronJob runs every 15 minutes, so it is routine, not a precursor.
    assert not any("update-electronicsIndex" in t and "Starting" in t for t in events)


def test_slow_payments_are_a_latency_shift(demo: LogStore) -> None:
    analysis = demo.analysis
    shift = analysis.latency_shifts[0]
    assert shift.endpoint.endswith("/paymentdetails")
    assert (shift.start, shift.end) == (at("09:30"), at("09:45"))
    assert shift.slow == shift.requests and shift.p95_ms > 2500
    assert shift.usual_p95_ms is not None and shift.usual_p95_ms < 1000
    events = [analysis.pattern_of(ref).event for ref, _ in shift.events_before]
    assert any(e is not None and e.id == "integration-failover" for e in events)


def test_digest(demo: LogStore) -> None:
    digest = demo.digest()
    assert demo.digest() is digest  # computed once
    assert len(digest) < 12_000
    for expected in (
        "Candidate incidents",
        "1. 08:50-08:5",
        "Rose or appeared in the 15 min before (08:35-08:49",
        "HikariPool",
        "Catalog synchronization",
        "Endpoints much slower than their own norm",
        "paymentdetails",
        "Integration failover",
        "Same lifecycle events before it",
        "Main problem patterns",
        "[issue=db-connection-pool-exhausted]",
        "Busiest endpoints",
        "Slowest endpoints",
        "Endpoints with the most 5xx",
        "Server startup in",
    ):
        assert expected in digest, expected
    overview = demo.overview()
    assert overview["candidate_incidents"] == len(demo.analysis.incidents) >= 1
    assert overview["message_patterns"] == len(demo.analysis.patterns)


# --- timeline -----------------------------------------------------------------------


def test_timeline_of_errors(demo: LogStore) -> None:
    text = tool(
        demo,
        "timeline",
        {
            "min_level": "ERROR",
            "split_by": "pattern",
            "start": f"{DAY}08:45:00Z",
            "end": f"{DAY}09:00:00Z",
        },
    )
    lines = text.splitlines()
    assert lines[0].startswith("Log lines per 1 min, UTC (min_level=ERROR)")
    assert lines[1].startswith("time   | total | P")
    assert any(line.startswith("08:52!") for line in lines)
    assert any(line.startswith("08:45 ") for line in lines)
    assert "Columns:" in text and "Could not handle request" in text


def test_timeline_of_latency(demo: LogStore) -> None:
    text = tool(
        demo,
        "timeline",
        {
            "metric": "p95_ms",
            "path": "paymentdetails",
            "bucket_minutes": 5,
            "start": f"{DAY}09:20:00Z",
        },
    )
    rows = {line.split(" ")[0]: line for line in text.splitlines()[2:]}
    slow = int(rows["09:35"].split("|")[1].replace(",", ""))
    usual = int(rows["09:20"].split("|")[1].replace(",", ""))
    assert slow > 5 * usual
    split = tool(demo, "timeline", {"metric": "5xx", "split_by": "status"})
    assert "HTTP 5xx responses per 2 min" in split or "HTTP 5xx responses per 1 min" in split
    pods = tool(demo, "timeline", {"split_by": "pod", "aspect": "api", "text": "timed out|refused"})
    assert "other" not in pods.splitlines()[1] and "api-7d9f8c6b5" in pods
    patterns = tool(demo, "timeline", {"pattern": pattern_like(demo, "HikariPool")})
    assert "pattern=P" in patterns


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ({"metric": "requests", "split_by": "pattern"}, "needs metric 'lines'"),
        ({"metric": "p95_ms", "min_level": "ERROR"}, "filter log lines"),
        ({"split_by": "endpoint"}, "needs a request metric"),
        ({"path": "/cart"}, "path filters requests"),
        ({"bucket_minutes": 1, "start": "2026-10-19T00:00:00Z"}, None),
        ({"pattern": "P999"}, "No pattern 'P999'"),
        ({"bucket_minutes": 0}, "Invalid input"),
    ],
)
def test_timeline_input_errors(
    demo: LogStore, args: dict[str, object], message: str | None
) -> None:
    if message is None:  # 1-minute buckets over two hours of data are fine
        assert "Log lines per 1 min" in tool(demo, "timeline", args)
        return
    with pytest.raises(ToolInputError, match=message):
        tool(demo, "timeline", args)


def test_timeline_rows_are_capped(small: LogStore, monkeypatch: pytest.MonkeyPatch) -> None:
    text = tool(small, "timeline", {"bucket_minutes": 1})
    assert text.startswith("Log lines per 1 min")
    monkeypatch.setattr(analysis_tools, "_MAX_ROWS", 3)
    with pytest.raises(ToolInputError, match="gives 5 rows"):
        tool(small, "timeline", {"bucket_minutes": 1})
    nothing = tool(small, "timeline", {"start": "2027-01-01T00:00:00Z"})
    assert nothing.startswith("No data") and "outside this export" in nothing
    none = tool(small, "timeline", {"text": "no such words"})
    assert none.startswith("Nothing matches these filters")


# --- compare_windows ----------------------------------------------------------------


def test_compare_before_the_outage(demo: LogStore) -> None:
    text = tool(
        demo,
        "compare_windows",
        {"target_start": f"{DAY}08:35:00Z", "target_end": f"{DAY}08:50:00Z", "min_level": "INFO"},
    )
    assert "against baseline 08:00-08:34 UTC" in text and "the export before the target" in text
    rising = text.split("Fell or stopped:")[0]
    assert "HikariPool" in rising and "[Catalog synchronization]" in rising
    assert "new: 0 (0.00/min)" in rising


def test_compare_with_the_rest_and_explicit_baselines(demo: LogStore) -> None:
    after = tool(
        demo,
        "compare_windows",
        {"target_start": "2026-10-20T07:00:00Z", "target_end": f"{DAY}08:10:00Z"},
    )
    assert "the export after the target" in after and "Part of the requested" in after
    outside = tool(
        demo,
        "compare_windows",
        {
            "target_start": f"{DAY}09:00:00Z",
            "target_end": f"{DAY}09:10:00Z",
            "baseline_start": "2026-10-19T09:00:00Z",
            "baseline_end": "2026-10-19T10:00:00Z",
        },
    )
    assert outside.startswith("The baseline window does not overlap the export")
    by_pod = tool(
        demo,
        "compare_windows",
        {
            "target_start": f"{DAY}08:50:00Z",
            "target_end": f"{DAY}08:58:00Z",
            "dimension": "pod",
            "min_level": "WARN",
        },
    )
    assert "api-7d9f8c6b5" in by_pod
    missing = tool(
        demo,
        "compare_windows",
        {"target_start": "2027-01-01T00:00:00Z", "target_end": "2027-01-02T00:00:00Z"},
    )
    assert missing.startswith("The target window does not overlap the export")
    with pytest.raises(ToolInputError, match="after target_start"):
        tool(
            demo,
            "compare_windows",
            {"target_start": f"{DAY}09:00:00Z", "target_end": f"{DAY}08:00:00Z"},
        )


def test_compare_endpoints(demo: LogStore) -> None:
    text = tool(
        demo,
        "compare_windows",
        {
            "target_start": f"{DAY}09:30:00Z",
            "target_end": f"{DAY}09:45:00Z",
            "baseline_start": f"{DAY}09:00:00Z",
            "baseline_end": f"{DAY}09:29:59Z",
            "dimension": "endpoint",
        },
    )
    first = text.splitlines()[2]
    assert "paymentdetails" in first and "p95" in first
    calm = tool(
        demo,
        "compare_windows",
        {
            "target_start": f"{DAY}09:00:00Z",
            "target_end": f"{DAY}09:10:00Z",
            "baseline_start": f"{DAY}09:10:00Z",
            "baseline_end": f"{DAY}09:20:00Z",
            "dimension": "endpoint",
        },
    )
    assert "Endpoints that got slower" in calm or "No endpoint got notably slower" in calm


# --- endpoint_stats -----------------------------------------------------------------


def test_endpoint_stats(demo: LogStore) -> None:
    text = tool(
        demo,
        "endpoint_stats",
        {
            "path": "paymentdetails|orders",
            "start": f"{DAY}09:30:00Z",
            "end": f"{DAY}09:45:00Z",
            "baseline_start": f"{DAY}09:00:00Z",
            "baseline_end": f"{DAY}09:29:59Z",
            "sort": "p95",
        },
    )
    lines = text.splitlines()
    assert "sorted by p95" in lines[0] and "Baseline: 09:00-09:29 UTC" in lines[0]
    assert "paymentdetails" in lines[1] and "p95 x" in lines[2]
    assert "slowest" not in lines[2]
    everything = tool(demo, "endpoint_stats", {"sort": "5xx", "limit": 3, "method": "get"})
    assert everything.count("\n- GET ") == 3
    by_max = tool(demo, "endpoint_stats", {"sort": "max", "limit": 1})
    assert "max 30,000 ms" in by_max
    assert tool(demo, "endpoint_stats", {"path": "/nothing"}) == "No HTTP requests match."
    with pytest.raises(ToolInputError):
        tool(demo, "endpoint_stats", {"method": "GET /x"})


# --- list_patterns and grouped search -------------------------------------------------


def test_list_patterns(demo: LogStore) -> None:
    warnings = tool(demo, "list_patterns", {"min_level": "WARN", "limit": 3})
    assert warnings.splitlines()[1].startswith("- P") and " ERROR " in warnings.splitlines()[1]
    payments = tool(demo, "list_patterns", {"text": "psp|payment", "sort": "count"})
    assert "PspAuthorizationService" in payments and "[event: Integration failover]" in payments
    events = tool(demo, "list_patterns", {"events_only": True, "sort": "first_seen"})
    assert "[event: CronJob started]" in events and "[event: Server started]" in events
    window = tool(
        demo,
        "list_patterns",
        {"start": f"{DAY}08:46:00Z", "end": f"{DAY}08:50:00Z", "logger": "hikari", "aspect": "api"},
    )
    assert "in window (x" in window and "in 08:46-08:50 UTC" in window
    assert tool(demo, "list_patterns", {"text": "no such words"}) == "No message patterns match."


def test_grouped_search(demo: LogStore) -> None:
    text = tool(demo, "search_logs", {"text": "timed out|refused", "group_by_pattern": True})
    first = text.splitlines()[0]
    assert "message pattern(s)" in first
    assert "Could not handle request" in text and "Error while indexing" in text
    plain = tool(demo, "search_logs", {"text": "Server startup in|Stopping service"})
    assert plain.startswith("2 record(s) match")


def test_get_record_names_its_pattern(demo: LogStore) -> None:
    ref = demo.analysis.incidents[0].first_error
    assert ref is not None
    text = tool(demo, "get_record", {"record": ref})
    assert "lines like this one between" in text


def test_describe_analysis_calls() -> None:
    assert describe_call("timeline", {"metric": "p95_ms", "path": "/cart"}) == (
        "Charting p95 request latency (ms) over time for /cart"
    )
    assert describe_call("timeline", {}) == "Charting log lines over time"
    assert describe_call("timeline", {"metric": "nonsense"}) == "Charting nonsense over time"
    assert describe_call("compare_windows", {}) == "Comparing two time windows"
    assert describe_call("endpoint_stats", {}) == (
        "Measuring requests, errors and latency for endpoints"
    )
    assert (
        describe_call("list_patterns", {"text": "solr"}) == "Listing message patterns about 'solr'"
    )
    assert describe_call("list_patterns", {}) == "Listing message patterns"


# --- in a conversation --------------------------------------------------------------


def test_broad_question_in_a_chat(demo: LogStore) -> None:
    provider = ScriptedChatProvider(
        [
            tool_turn(
                ("timeline", {"min_level": "ERROR", "start": f"{DAY}08:30:00Z"}),
                (
                    "compare_windows",
                    {"target_start": f"{DAY}08:35:00Z", "target_end": f"{DAY}08:50:00Z"},
                ),
            ),
            text_turn("A catalog sync loaded the database before the pool ran out (#1)."),
        ]
    )
    session = AskSession(demo, provider, Settings())
    answer = session.ask("What happened just before the outage?")
    assert answer.complete and [s.name for s in answer.steps] == ["timeline", "compare_windows"]
    system = provider.requests[0]["system"]
    assert "How to investigate a broad question" in system[0]
    assert "<export_profile>" in system[1] and "Candidate incidents" in system[1]
    names = {t["name"] for t in provider.requests[0]["tools"]}
    assert {"timeline", "compare_windows", "endpoint_stats", "list_patterns"} <= names
    results = provider.requests[1]["messages"][-1]["content"]
    assert "08:52!" in results[0]["content"] and "Rose or appeared" in results[1]["content"]


def test_levels_and_windows_are_respected(demo: LogStore) -> None:
    analysis = demo.analysis
    window = Window(at("08:50"), at("08:51"))
    refs = analysis.refs_in(window)
    stamps = [demo.record(ref).timestamp for ref in refs]
    assert all(s is not None and at("08:50") <= s <= at("08:51") for s in stamps)
    calls = analysis.calls_in(window)
    assert calls and all(ref in refs for ref, _ in calls)
    comparison = analysis.compare(
        Window(at("08:00"), at("08:30")), Window(at("08:50"), at("08:58")), "level", LogLevel.WARN
    )
    assert {c.key for c in comparison.rising} <= {"WARN", "ERROR"}


def test_clock_shows_dates_across_days(tmp_path: Path) -> None:
    lines = [
        '{"timestamp": "2026-10-20T23:59:00Z", "loglevel": "ERROR", "content": "boom one"}',
        '{"timestamp": "2026-10-21T00:01:00Z", "loglevel": "ERROR", "content": "boom two"}',
    ]
    path = tmp_path / "two-days.ndjson"
    path.write_text("\n".join(lines), encoding="utf-8")
    store = LogStore.load(path, Settings())
    assert store.analysis.clock(store.record(1).timestamp) == "10-20 23:59"
    assert store.analysis.clock(None) == "-"
    assert store.analysis.clock(datetime(2026, 10, 21, 1, 0, tzinfo=UTC)) == "10-21 01:00"
