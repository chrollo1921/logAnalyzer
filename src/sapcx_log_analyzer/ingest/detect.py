"""Pick the right reader for an export file."""

from __future__ import annotations

import csv
from collections.abc import Iterator
from enum import StrEnum
from pathlib import Path

from sapcx_log_analyzer.ingest.console_log import read_console_log
from sapcx_log_analyzer.ingest.dynatrace_csv import read_csv, sniff_delimiter
from sapcx_log_analyzer.ingest.dynatrace_json import read_json
from sapcx_log_analyzer.ingest.encoding import detect_encoding
from sapcx_log_analyzer.ingest.fields import has_content_column
from sapcx_log_analyzer.models import RawEntry


class ExportFormat(StrEnum):
    CSV = "csv"
    JSON = "json"
    TEXT = "text"


def detect_format(path: Path) -> ExportFormat:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return ExportFormat.CSV
    if suffix in {".json", ".ndjson", ".jsonl"}:
        return ExportFormat.JSON
    # .log, .txt, .out or no extension: look at the content.
    with path.open(encoding=detect_encoding(path), errors="replace") as handle:
        head = handle.read(8192)
    if head.lstrip().startswith(("{", "[")):
        return ExportFormat.JSON
    header = head.lstrip().partition("\n")[0]
    try:
        columns = next(csv.reader([header], delimiter=sniff_delimiter(header)))
    except (csv.Error, StopIteration):
        columns = []
    return ExportFormat.CSV if has_content_column(columns) else ExportFormat.TEXT


def read_export(path: Path, export_format: ExportFormat | None = None) -> Iterator[RawEntry]:
    fmt = export_format or detect_format(path)
    if fmt is ExportFormat.CSV:
        return read_csv(path)
    if fmt is ExportFormat.TEXT:
        return read_console_log(path)
    return read_json(path)
