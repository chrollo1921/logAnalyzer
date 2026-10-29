from __future__ import annotations

import json
from pathlib import Path

import pytest

from sapcx_log_analyzer.ingest import ExportFormat, detect_format, read_export
from sapcx_log_analyzer.ingest.dynatrace_json import ExportFormatError
from sapcx_log_analyzer.ingest.fields import to_raw_entry
from sapcx_log_analyzer.parse import normalize_all


def test_csv_export_is_read_with_attributes(csv_export: Path) -> None:
    entries = list(read_export(csv_export))
    assert len(entries) == 52  # before stitching split stack lines
    first = entries[0]
    assert first.timestamp == "2026-10-20T09:00:00.000Z"
    assert first.level == "INFO"
    assert first.attributes["k8s.pod.name"].startswith("api-")
    assert "content" not in first.attributes


def test_csv_keeps_quotes_and_multiline_cells(csv_export: Path) -> None:
    contents = [e.content for e in read_export(csv_export)]
    assert any('Exception in thread "TaskExecutor-3" java.lang' in c for c in contents)
    assert any("\nCaused by: java.sql.SQLTransientConnectionException" in c for c in contents)


def test_semicolon_csv(tmp_path: Path) -> None:
    path = tmp_path / "export.csv"
    path.write_text("timestamp;loglevel;content\n2026-10-20T09:00:00Z;ERROR;boom\n")
    entries = list(read_export(path))
    assert [(e.level, e.content) for e in entries] == [("ERROR", "boom")]


def test_csv_column_names_are_matched_loosely(tmp_path: Path) -> None:
    path = tmp_path / "table.csv"
    path.write_text(
        "Timestamp,env,Log Level,Log message,k8s.container.name\n"
        '2026-10-22T06:10:47.972Z,uat,ERROR,"[x] ""GET /cart"" 500",platform\n'
    )
    [entry] = read_export(path)
    assert (entry.timestamp, entry.level, entry.content) == (
        "2026-10-22T06:10:47.972Z",
        "ERROR",
        '[x] "GET /cart" 500',
    )
    assert entry.attributes == {"env": "uat", "k8s.container.name": "platform"}


@pytest.mark.parametrize(
    ("encoding", "delimiter"),
    [("utf-16", "\t"), ("cp1252", ";"), ("utf-8-sig", "|")],
)
def test_csv_encodings_and_delimiters(tmp_path: Path, encoding: str, delimiter: str) -> None:
    path = tmp_path / "export.csv"
    rows = [["timestamp", "level", "message"], ["2026-10-20T09:00:00Z", "WARN", "Café löst"]]
    path.write_bytes("\r\n".join(delimiter.join(r) for r in rows).encode(encoding))
    [entry] = read_export(path)
    assert (entry.level, entry.content) == ("WARN", "Café löst")


def test_csv_without_message_column_names_the_columns(tmp_path: Path) -> None:
    path = tmp_path / "products.csv"
    path.write_text("id,name,price\n1,Shirt,9.99\n")
    with pytest.raises(ExportFormatError, match=r'expected .*; found "id", "name", "price"'):
        list(read_export(path))


def test_grail_json_export(json_export: Path) -> None:
    entries = list(read_export(json_export))
    assert len(entries) == 6
    assert entries[0].level == "ERROR"
    assert entries[0].content.startswith("{")


@pytest.mark.parametrize(
    "document",
    [
        [{"content": "a"}, {"content": "b"}],
        {"records": [{"content": "a"}, {"content": "b"}]},
        {"results": [{"content": "a"}, {"content": "b"}]},
        {"result": {"records": [{"content": "a"}, {"content": "b"}]}},
    ],
)
def test_json_shapes(tmp_path: Path, document: object) -> None:
    path = tmp_path / "export.json"
    path.write_text(json.dumps(document, indent=2))
    assert [e.content for e in read_export(path)] == ["a", "b"]


def test_ndjson(tmp_path: Path) -> None:
    path = tmp_path / "export.ndjson"
    path.write_text('{"content": "a", "status": "WARN"}\n\n{"content": "b"}\n')
    entries = list(read_export(path))
    assert [(e.content, e.level) for e in entries] == [("a", "WARN"), ("b", None)]


def test_invalid_ndjson_line_reports_line_number(tmp_path: Path) -> None:
    path = tmp_path / "export.jsonl"
    path.write_text('{"content": "a"}\nnot json\n')
    with pytest.raises(ExportFormatError, match="Line 2"):
        list(read_export(path))


def test_json_without_records_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "export.json"
    path.write_text('{\n  "something": 1\n}')
    with pytest.raises(ExportFormatError):
        list(read_export(path))


def test_broken_json_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "export.json"
    path.write_text('[\n {"content": "a"},\n')
    with pytest.raises(ExportFormatError, match="Not valid JSON"):
        list(read_export(path))


@pytest.mark.parametrize(
    ("name", "content", "expected"),
    [
        ("a.csv", "x", ExportFormat.CSV),
        ("a.json", "x", ExportFormat.JSON),
        ("a.jsonl", "x", ExportFormat.JSON),
        ("a.txt", '  [{"content": 1}]', ExportFormat.JSON),
        ("a.txt", "timestamp,content", ExportFormat.CSV),
        (
            "console.log",
            "INFO   | jvm 1    | main    | 2026/09/02 00:27:23.140 | x",
            ExportFormat.TEXT,
        ),
        ("catalina.out", "INFO  [main] [Foo] started, ok", ExportFormat.TEXT),
        ("export", "id,name\n1,a", ExportFormat.TEXT),
    ],
)
def test_detect_format(tmp_path: Path, name: str, content: str, expected: ExportFormat) -> None:
    path = tmp_path / name
    path.write_text(content)
    assert detect_format(path) is expected


def test_row_without_content_is_skipped() -> None:
    assert to_raw_entry({"timestamp": "x", "status": "ERROR"}) is None


def test_field_lookup_is_case_insensitive_and_skips_nested() -> None:
    entry = to_raw_entry({"Content": "msg", "Log.Level": "warn", "nested": {"a": 1}, "pod": "p"})
    assert entry is not None
    assert entry.level == "warn"
    assert entry.attributes == {"pod": "p"}


def _wrapped(ts: str, payload: str, source: str = "jvm 1    ", level: str = "INFO  ") -> str:
    """A line as an on-premise server writes it through the Tanuki service wrapper."""
    return f"{level} | {source} | main    | 2026/09/02 {ts} | {payload}"


CONSOLE_LOG = "\n".join(
    [
        _wrapped(
            "00:27:23.140",
            "[2026-09-02T00:27:23,134] \x1b[32mINFO  [TaskExecutor-master-273-ProcessTask [88070]]"
            " [ProcessengineTaskRunner] Timeout occured",
        ),
        _wrapped("00:27:23.775", "\x1b[m"),
        _wrapped(
            "10:02:06.794", "Pinging the JVM took 37 seconds to respond.", "wrapper  ", "STATUS"
        ),
        _wrapped(
            "10:03:00.001",
            "64706622 [Task-master-poll] WARN  de.hybris.platform.jdbcwrapper.Pool"
            "  - Failed to establish JDBC connection.",
        ),
        _wrapped("10:03:00.002", "java.sql.SQLException: Communications link failure"),
        _wrapped("10:03:00.003", "The last packet was sent 10,563 milliseconds ago."),
        _wrapped("10:03:00.004", "\tat de.hybris.platform.jdbcwrapper.Pool.get(Pool.java:68)"),
        _wrapped("10:03:00.005", "Caused by: java.net.ConnectException: Connection refused"),
        _wrapped("15:36:16.100", "Sep 02, 2026 3:36:16 PM org.apache.coyote.AbstractProtocol init"),
        _wrapped("15:36:16.101", 'INFO: Initializing ProtocolHandler ["http-nio-9001"]'),
    ]
)


def test_console_log_with_wrapper_prefix(tmp_path: Path) -> None:
    path = tmp_path / "console-20260902.log"
    path.write_text(CONSOLE_LOG)
    assert detect_format(path) is ExportFormat.TEXT
    records = list(normalize_all(read_export(path)))
    assert [(r.level, r.thread, r.logger) for r in records] == [
        ("INFO", "TaskExecutor-master-273-ProcessTask [88070]", "ProcessengineTaskRunner"),
        ("INFO", "wrapper", None),
        ("WARN", "Task-master-poll", "de.hybris.platform.jdbcwrapper.Pool"),
        ("INFO", None, "org.apache.coyote.AbstractProtocol"),
    ]
    task, wrapper, jdbc, tomcat = records
    assert (
        task.timestamp is not None
        and task.timestamp.isoformat() == "2026-09-02T00:27:23.134000+00:00"
    )
    assert wrapper.message == "Pinging the JVM took 37 seconds to respond."
    assert jdbc.timestamp is not None and jdbc.timestamp.isoformat().startswith(
        "2026-09-02T10:03:00.001"
    )
    assert jdbc.exception_class == "java.sql.SQLException"
    assert jdbc.root_cause_class == "java.net.ConnectException"
    assert "The last packet was sent 10,563 milliseconds ago." in jdbc.stack
    assert tomcat.message == 'Initializing ProtocolHandler ["http-nio-9001"]'
    assert tomcat.timestamp is not None and tomcat.timestamp.hour == 15


def test_console_log_without_wrapper(tmp_path: Path) -> None:
    path = tmp_path / "catalina.out"
    path.write_text(
        "ERROR [hybrisHTTP3] [DefaultCartService] boom\n"
        "java.lang.IllegalStateException: no cart\n"
        "\tat a.b.C.d(C.java:1)\n"
        "INFO  [hybrisHTTP4] [DefaultCartService] fine\n"
    )
    entries = list(read_export(path))
    assert [e.content.splitlines()[0] for e in entries] == [
        "ERROR [hybrisHTTP3] [DefaultCartService] boom",
        "INFO  [hybrisHTTP4] [DefaultCartService] fine",
    ]
    assert entries[0].content.count("\n") == 2
