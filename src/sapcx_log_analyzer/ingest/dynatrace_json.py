"""Reader for JSON exports: a plain array, a Grail/DQL result, or NDJSON."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from sapcx_log_analyzer.ingest.fields import to_raw_entry
from sapcx_log_analyzer.models import RawEntry


class ExportFormatError(ValueError):
    """The file does not look like a Dynatrace log export."""


def _records(document: Any) -> list[Any]:
    if isinstance(document, list):
        return document
    if isinstance(document, dict):
        # Grail query API: {"result": {"records": [...]}}; Logs API v2: {"results": [...]}
        for path in (("result", "records"), ("records",), ("results",), ("logs",)):
            node: Any = document
            for key in path:
                node = node.get(key) if isinstance(node, dict) else None
            if isinstance(node, list):
                return node
    raise ExportFormatError("JSON export has no list of log records")


def _is_ndjson(path: Path) -> bool:
    with path.open(encoding="utf-8-sig") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            if not stripped.startswith("{"):
                return False
            try:
                json.loads(stripped)
            except json.JSONDecodeError:
                return False  # a pretty-printed object spanning several lines
            return True
    return False


def read_json(path: Path) -> Iterator[RawEntry]:
    if _is_ndjson(path):
        yield from _read_ndjson(path)
        return
    with path.open(encoding="utf-8-sig") as handle:
        try:
            document = json.load(handle)
        except json.JSONDecodeError as exc:
            raise ExportFormatError(f"Not valid JSON: {exc.msg} (line {exc.lineno})") from exc
    for row in _records(document):
        if isinstance(row, dict):
            entry = to_raw_entry(row)
            if entry is not None:
                yield entry


def _read_ndjson(path: Path) -> Iterator[RawEntry]:
    with path.open(encoding="utf-8-sig") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ExportFormatError(f"Line {number} is not valid JSON: {exc.msg}") from exc
            if isinstance(row, dict):
                entry = to_raw_entry(row)
                if entry is not None:
                    yield entry
