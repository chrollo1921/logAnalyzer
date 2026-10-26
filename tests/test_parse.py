from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from sapcx_log_analyzer.models import LogLevel, RawEntry
from sapcx_log_analyzer.parse import normalize, stitch
from sapcx_log_analyzer.parse.log4j_pattern import parse_pattern_line, parse_timestamp
from sapcx_log_analyzer.parse.sapcx_json import parse_json_line
from sapcx_log_analyzer.parse.stacktrace import analyze_stack, exception_in, frames


def test_pattern_line_with_ip_bracket() -> None:
    parsed = parse_pattern_line(
        "ERROR [hybrisHTTP31] [10.1.2.3] [DefaultCartService] Could not calculate cart"
    )
    assert parsed is not None
    assert parsed.level == "ERROR"
    assert parsed.thread == "hybrisHTTP31"
    assert parsed.logger == "DefaultCartService"
    assert parsed.message == "Could not calculate cart"


def test_pattern_line_with_timestamp_and_stack() -> None:
    parsed = parse_pattern_line(
        "2026-10-20 10:15:30,123 WARN  [main] [de.hybris.Foo] msg\n\tat a.b.C.d(C.java:1)"
    )
    assert parsed is not None
    assert parsed.timestamp == datetime(2026, 10, 20, 10, 15, 30, 123000, tzinfo=UTC)
    assert parsed.logger == "de.hybris.Foo"
    assert parsed.stack == ["\tat a.b.C.d(C.java:1)"]


def test_pattern_line_rejects_free_text() -> None:
    assert parse_pattern_line("just some text") is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-10-20T09:00:00Z", datetime(2026, 10, 20, 9, tzinfo=UTC)),
        ("2026-10-20T09:00:00", datetime(2026, 10, 20, 9, tzinfo=UTC)),
        ("1792486800000", datetime(2026, 10, 20, 9, tzinfo=UTC)),
        ("1792486800", datetime(2026, 10, 20, 9, tzinfo=UTC)),
        ("yesterday", None),
        (None, None),
    ],
)
def test_parse_timestamp(value: str | None, expected: datetime | None) -> None:
    assert parse_timestamp(value) == expected


def test_json_layout_with_nested_cause() -> None:
    line = json.dumps(
        {
            "instant": {"epochSecond": 1792486800, "nanoOfSecond": 500000000},
            "thread": "hybrisHTTP7",
            "level": "ERROR",
            "loggerName": "de.hybris.Foo",
            "message": "boom",
            "thrown": {
                "name": "de.hybris.FooException",
                "message": "outer",
                "extendedStackTrace": [{"class": "de.hybris.Foo", "method": "run", "line": 3}],
                "cause": {"name": "java.sql.SQLException", "message": "inner"},
            },
        }
    )
    parsed = parse_json_line(line)
    assert parsed is not None
    assert parsed.timestamp == datetime(2026, 10, 20, 9, 0, 0, 500000, tzinfo=UTC)
    assert parsed.stack == [
        "de.hybris.FooException: outer",
        "\tat de.hybris.Foo.run(Unknown Source:3)",
        "Caused by: java.sql.SQLException: inner",
    ]


def test_json_layout_string_trace_and_time_millis() -> None:
    line = json.dumps(
        {
            "timeMillis": 1792486800000,
            "level": "WARN",
            "message": {"structured": True},
            "thrown": {"name": "x.YException", "extendedStackTrace": "x.YException\n\tat a.B.c()"},
        }
    )
    parsed = parse_json_line(line)
    assert parsed is not None
    assert parsed.message == '{"structured": true}'
    assert parsed.stack == ["x.YException", "\tat a.B.c()"]
    assert parsed.timestamp == datetime(2026, 10, 20, 9, tzinfo=UTC)


@pytest.mark.parametrize("line", ["not json", "{broken", '{"foo": 1}', "[1, 2]"])
def test_non_layout_json_is_ignored(line: str) -> None:
    assert parse_json_line(line) is None


def test_exception_detection() -> None:
    assert exception_in("java.lang.IllegalStateException: bad") == "java.lang.IllegalStateException"
    assert exception_in("Caused by: java.sql.SQLException") == "java.sql.SQLException"
    assert exception_in('Exception in thread "x" java.lang.OutOfMemoryError: heap') == (
        "java.lang.OutOfMemoryError"
    )
    assert exception_in("Nothing to see") is None


def test_root_cause_is_last_caused_by() -> None:
    info = analyze_stack(
        ["a.BException: x", "\tat a.B.c()", "Caused by: c.DError: y", "Caused by: e.FException"]
    )
    assert info.exception_class == "a.BException"
    assert info.root_cause_class == "e.FException"
    assert frames(info.lines) == ["a.B.c()"]


def test_stitch_joins_split_stack_lines_on_same_pod() -> None:
    entries = [
        RawEntry(content="java.lang.OutOfMemoryError: heap", attributes={"k8s.pod.name": "p1"}),
        RawEntry(content="\tat a.B.c()", attributes={"k8s.pod.name": "p1"}),
        RawEntry(content="\tat other.Pod()", attributes={"k8s.pod.name": "p2"}),
        RawEntry(content="... 3 more"),
    ]
    stitched = list(stitch(entries))
    assert [e.content for e in stitched] == [
        "java.lang.OutOfMemoryError: heap\n\tat a.B.c()",
        "\tat other.Pod()\n... 3 more",
    ]


def test_normalize_derives_aspect_pod_and_level() -> None:
    record = normalize(
        RawEntry(
            timestamp="2026-10-20T09:00:00Z",
            level="NONE",
            content="java.lang.OutOfMemoryError: heap\n\tat a.B.c()",
            attributes={"k8s.pod.name": "backgroundprocessing-5c6b-klmno"},
        )
    )
    assert record.level is LogLevel.ERROR  # bare traces count as errors
    assert record.aspect == "backgroundprocessing"
    assert record.pod == "backgroundprocessing-5c6b-klmno"
    assert record.exception_class == "java.lang.OutOfMemoryError"


def test_normalize_prefers_level_from_content() -> None:
    record = normalize(RawEntry(level="INFO", content="WARN  [t] [Logger] careful"))
    assert record.level is LogLevel.WARN
    assert record.aspect is None


def test_level_aliases() -> None:
    assert LogLevel.parse("warning") is LogLevel.WARN
    assert LogLevel.parse("SEVERE") is LogLevel.ERROR
    assert LogLevel.parse(None) is LogLevel.INFO
    assert LogLevel.parse("weird") is LogLevel.INFO


def test_correlation_context_from_attributes_and_mdc() -> None:
    from sapcx_log_analyzer.models import RawEntry
    from sapcx_log_analyzer.parse import normalize

    content = (
        '{"level": "INFO", "message": "hi", "thread": "t", "contextMap": '
        '{"CorrelationId": "c-1", "Tenant": "master", "nested": {"a": 1}, "empty": ""}}'
    )
    entry = RawEntry(
        content=content,
        attributes={
            "trace_id": "abc",
            "dt.span_id": "def",
            "k8s.pod.name": "api-1",
            "x-request-id": "r-9",
        },
    )
    record = normalize(entry)
    assert record.context == {
        "trace_id": "abc",
        "dt.span_id": "def",
        "x-request-id": "r-9",
        "CorrelationId": "c-1",
        "Tenant": "master",
    }
