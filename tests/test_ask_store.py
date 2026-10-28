from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from sapcx_log_analyzer.ask.identifiers import identifiers_in, kind_of
from sapcx_log_analyzer.ask.store import LogStore, Scope
from sapcx_log_analyzer.ask.tools import (
    ToolInputError,
    describe_call,
    format_record,
    run_tool,
)
from sapcx_log_analyzer.config import Settings
from sapcx_log_analyzer.models import LogLevel
from tests.conftest import FIXTURES, make_record

TRACE_FAILED = "4bf92f3577b34da6a3ce929d0e0e4736"
COVERAGE = "This export covers 2026-10-20T09:39:40+00:00 to 2026-10-20T09:45:00+00:00."


@pytest.fixture(scope="module")
def store() -> LogStore:
    return LogStore.load(FIXTURES / "transactions.ndjson", Settings())


def ref_of(store: LogStore, text: str) -> int:
    refs, _ = store.search(text=text)
    assert refs, text
    return refs[0]


# --- identifiers --------------------------------------------------------------------


def test_identifiers_from_text_and_context() -> None:
    record = make_record(
        "Placing order for cart 00087123 (tx-243232) orderCode=00012399 "
        "X-Request-Id: 7f3a9c1e2b and trace 4bf92f3577b34da6a3ce929d0e0e4736 "
        "uuid 0b8e9f2a-1c3d-4e5f-8a9b-0c1d2e3f4a5b session <SESSION#1a2b3c4d>",
        context={"CorrelationId": "c0ffee01", "dt.span_id": "00f067aa0ba902b7"},
        stack=["com.example.PaymentException: capture failed for consignment a1234567"],
    )
    found = {i.value: i.kind for i in identifiers_in(record)}
    assert found["tx-243232"] == "transaction"
    assert found["00087123"] == "cart"
    assert found["00012399"] == "order"
    assert found["7f3a9c1e2b"] == "request"
    assert found[TRACE_FAILED] == "trace"
    assert found["0b8e9f2a-1c3d-4e5f-8a9b-0c1d2e3f4a5b"] == "uuid"
    assert found["<SESSION#1a2b3c4d>"] == "session"
    assert found["c0ffee01"] == "correlation"
    assert found["00f067aa0ba902b7"] == "span"
    assert found["a1234567"] == "consignment"


def test_words_after_id_keywords_are_not_identifiers() -> None:
    record = make_record("Failed to place order for user and cart calculation")
    assert identifiers_in(record) == []


def test_kind_of() -> None:
    assert kind_of("X-Request-Id") == "request"
    assert kind_of("Tenant") == "id"


# --- store --------------------------------------------------------------------------


def test_store_keeps_every_record_in_time_order(store: LogStore) -> None:
    assert len(store) == 15
    stamps = [store.record(r).timestamp for r in range(1, len(store) + 1)]
    assert stamps == sorted(stamps)  # type: ignore[type-var]
    levels = {store.record(r).level for r in range(1, len(store) + 1)}
    assert {LogLevel.DEBUG, LogLevel.INFO, LogLevel.WARN, LogLevel.ERROR} <= levels


def test_store_redacts_on_load(store: LogStore) -> None:
    text = "\n".join(format_record(store, r, full=True) for r in range(1, len(store) + 1))
    assert "jane.doe@example.com" not in text
    assert "<EMAIL#" in text
    assert "8F3AC2D1E0B9A7F6" not in text
    assert "<SESSION#" in text


def test_find_identifier_case_insensitive_with_linked_records(store: LogStore) -> None:
    result = store.find("TX-243232")
    assert result.matched_by == "index"
    assert result.total == 1
    assert "tx-243232" in store.record(result.refs[0]).message
    related = {identifier.value for identifier, _ in result.related}
    assert TRACE_FAILED in related
    assert "00087123" in related
    linked_messages = [store.record(r).message for r in result.linked_refs]
    assert "Failed to place order" in linked_messages
    assert result.linked_total == 3


def test_find_falls_back_to_text_and_suggests(store: LogStore) -> None:
    partial = store.find("tx-24323")
    assert partial.matched_by == "text"
    assert partial.total == 3
    missing = store.find("tx-243299")
    assert missing.matched_by == "none"
    assert missing.refs == []
    assert "tx-243232" in missing.suggestions
    assert store.suggest("") == []


def test_context_follows_thread_and_widens_to_pod_and_all(store: LogStore) -> None:
    anchor = store.find("tx-243232").refs[0]
    thread = [store.record(r) for r in store.context(anchor, window_seconds=60)]
    assert {r.thread for r in thread} == {"hybrisHTTP12"}
    assert any(r.message == "Failed to place order" for r in thread)
    assert all(r.message != "Cart 00099999 updated" for r in thread)  # outside the window

    pod = store.context(anchor, window_seconds=60, scope=Scope.POD)
    assert len({store.record(r).thread for r in pod}) > 1
    everywhere = store.context(anchor, window_seconds=60, scope=Scope.ALL)
    assert len({store.record(r).pod for r in everywhere}) == 3  # both API pods and bg

    errors_only = store.context(anchor, window_seconds=60, min_level=LogLevel.ERROR)
    assert anchor in errors_only  # the anchor always stays
    assert all(
        store.record(r).level.rank >= LogLevel.ERROR.rank for r in errors_only if r != anchor
    )
    limited = store.context(anchor, window_seconds=3600, scope=Scope.ALL, limit=3)
    assert len(limited) == 3 and anchor in limited


def test_context_without_timestamps_uses_neighbours(tmp_path: Path) -> None:
    export = tmp_path / "plain.csv"
    rows = ["content,k8s.pod.name"] + [f"ERROR [t1] [X] line {i},api-1" for i in range(10)]
    export.write_text("\n".join(rows) + "\n")
    store = LogStore.load(export, Settings())
    assert store.context(5, limit=5) == [3, 4, 5, 6, 7]


def test_search_filters(store: LogStore) -> None:
    refs, total = store.search(min_level=LogLevel.ERROR, aspect="backgroundprocessing")
    assert total == len(refs) == 1
    assert "Payment capture failed" in store.record(refs[0]).message
    refs, total = store.search(text="placing order", pod="fghij")
    assert total == 1
    start = datetime(2026, 10, 20, 9, 40, 30, tzinfo=UTC)
    end = datetime(2026, 10, 20, 9, 40, 31, tzinfo=UTC)
    refs, _ = store.search(start=start, end=end)
    assert {store.record(r).thread for r in refs} == {"hybrisHTTP12"}
    _, total = store.search(limit=2)
    assert total == len(store)


def test_issues_in_window(store: LogStore) -> None:
    everything = store.issues()
    assert {i.cluster.rule_id for i in everything} >= {"db-connection-pool-exhausted"}
    early = store.issues(end=datetime(2026, 10, 20, 9, 39, 50, tzinfo=UTC))
    assert sum(i.count_in_window for i in early) == 2
    assert store.issues(start=datetime(2030, 1, 1, tzinfo=UTC)) == []


def test_overview_and_examples(store: LogStore) -> None:
    overview = store.overview()
    assert overview["records"] == 15
    assert overview["aspects"] == ["api", "backgroundprocessing"]
    assert overview["identifiers_by_kind"]["transaction"] == 3  # type: ignore[index]
    assert store.sample_identifiers()[0] == "tx-243232"


def test_unknown_record(store: LogStore) -> None:
    with pytest.raises(KeyError, match="No record #99"):
        store.record(99)


# --- tools --------------------------------------------------------------------------


def test_find_identifier_tool_output(store: LogStore) -> None:
    text = run_tool(store, "find_identifier", {"value": "tx-243232"}, 50_000)
    assert "1 record(s) mention 'tx-243232' (as an identifier)" in text
    assert "3 more record(s) share a trace, correlation or request id" in text
    assert "Caused by: java.sql.SQLTransientConnectionException" in text
    assert "[issue=db-connection-pool-exhausted]" in text
    missing = run_tool(store, "find_identifier", {"value": "tx-243299"}, 50_000)
    assert "No record mentions 'tx-243299'" in missing and "tx-243232" in missing
    assert "which are different ids" in missing
    nothing = run_tool(store, "find_identifier", {"value": "zz"}, 50_000)
    assert COVERAGE in nothing and "outside that time range" in nothing


def test_other_tools(store: LogStore) -> None:
    failed = ref_of(store, "Failed to place order")
    context = run_tool(store, "get_context", {"record": failed, "scope": "pod"}, 50_000)
    assert f"of #{failed} (scope=pod" in context
    record = run_tool(store, "get_record", {"record": failed}, 50_000)
    assert "DefaultCalculationService.calculate" in record
    assert "Part of issue cluster" in record
    search = run_tool(store, "search_logs", {"text": "capture", "min_level": "ERROR"}, 50_000)
    assert "1 record(s) match" in search
    assert run_tool(store, "search_logs", {"text": "no such thing"}, 50_000) == "No records match."
    issues = run_tool(
        store,
        "list_issues",
        {"start": "2026-10-20T09:40:00Z", "end": "2026-10-20T09:41:00Z"},
        50_000,
    )
    assert "Database connection pool exhausted" in issues
    none = run_tool(store, "list_issues", {"start": "2030-01-01T00:00:00Z"}, 50_000)
    assert none.startswith("No known problem patterns in this window.")
    assert "The requested time window is outside this export" in none and COVERAGE in none


# --- questions outside the export -------------------------------------------------


def test_time_range(store: LogStore) -> None:
    first, last = store.time_range() or (None, None)
    assert first == datetime(2026, 10, 20, 9, 39, 40, tzinfo=UTC)
    assert last == datetime(2026, 10, 20, 9, 45, tzinfo=UTC)
    assert LogStore("empty", [], [], [], [], store.redactor).time_range() is None


@pytest.mark.parametrize(
    ("name", "args", "empty", "note"),
    [
        (
            "search_logs",
            {"text": "Hikari", "start": "2026-10-21T00:00:00Z"},
            "No records match.",
            "The requested time window is outside this export",
        ),
        (
            "list_issues",
            {"start": "2026-10-19T00:00:00Z", "end": "2026-10-19T23:59:59Z"},
            "No known problem patterns in this window.",
            "The requested time window is outside this export",
        ),
        (
            "list_issues",
            {"start": "2026-10-20T08:00:00Z", "end": "2026-10-20T09:41:00Z"},
            "- critical | Database connection pool exhausted",
            "Part of the requested time window is outside this export",
        ),
        (
            "search_logs",
            {"text": "capture", "end": "2026-10-20T23:00:00Z"},
            "1 record(s) match",
            "Part of the requested time window is outside this export",
        ),
    ],
)
def test_windows_outside_the_export_are_called_out(
    store: LogStore, name: str, args: dict[str, str], empty: str, note: str
) -> None:
    text = run_tool(store, name, args, 50_000)
    assert empty in text and note in text and COVERAGE in text


def test_windows_inside_the_export_have_no_note(store: LogStore) -> None:
    window = {"start": "2026-10-20T09:40:00Z", "end": "2026-10-20T09:41:00Z"}
    for name in ("search_logs", "list_issues", "list_api_calls"):
        assert "outside this export" not in run_tool(store, name, window, 50_000)


@pytest.mark.parametrize(
    ("name", "raw", "message"),
    [
        ("drop_tables", {}, "Unknown tool"),
        ("find_identifier", {}, "Invalid input"),
        ("find_identifier", {"value": "x", "extra": 1}, "Invalid input"),
        ("get_context", {"record": 0}, "Invalid input"),
        ("get_context", {"record": 999}, "No record #999"),
        ("search_logs", {"start": "yesterday"}, "ISO-8601"),
        ("get_record", "not an object", "Invalid input"),
    ],
)
def test_tool_input_errors(store: LogStore, name: str, raw: object, message: str) -> None:
    with pytest.raises(ToolInputError, match=message):
        run_tool(store, name, raw, 50_000)


def test_tool_results_are_capped(store: LogStore) -> None:
    text = run_tool(store, "search_logs", {}, 1500)
    assert len(text) < 1700
    assert text.endswith(
        "[result truncated: narrow the query, lower the limit or use a time window]"
    )


def test_describe_call() -> None:
    assert describe_call("find_identifier", {"value": "tx-1"}) == "Looking up tx-1"
    assert "#4" in describe_call("get_context", {"record": 4, "scope": "pod"})
    assert describe_call("get_record", {"record": 2}) == "Opening record #2"
    assert describe_call("search_logs", {"text": "Hikari"}) == "Searching for 'Hikari'"
    assert "known platform issues" in describe_call("list_issues", {})
    assert describe_call("other", None) == "Running other"
