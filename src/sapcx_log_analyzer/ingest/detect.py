"""Pick the right reader for an export file."""

from __future__ import annotations

from collections.abc import Iterator
from enum import StrEnum
from pathlib import Path

from sapcx_log_analyzer.ingest.dynatrace_csv import read_csv
from sapcx_log_analyzer.ingest.dynatrace_json import read_json
from sapcx_log_analyzer.models import RawEntry


class ExportFormat(StrEnum):
    CSV = "csv"
    JSON = "json"


def detect_format(path: Path) -> ExportFormat:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return ExportFormat.CSV
    if suffix in {".json", ".ndjson", ".jsonl"}:
        return ExportFormat.JSON
    with path.open(encoding="utf-8-sig") as handle:
        head = handle.read(1024).lstrip()
    return ExportFormat.JSON if head.startswith(("{", "[")) else ExportFormat.CSV


def read_export(path: Path, export_format: ExportFormat | None = None) -> Iterator[RawEntry]:
    fmt = export_format or detect_format(path)
    if fmt is ExportFormat.CSV:
        return read_csv(path)
    return read_json(path)
