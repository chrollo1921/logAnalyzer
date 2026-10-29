"""Reader for CSV exports from the Dynatrace Logs viewer, and similar log tables."""

from __future__ import annotations

import csv
import sys
from collections.abc import Iterator
from pathlib import Path

from sapcx_log_analyzer.ingest.dynatrace_json import ExportFormatError
from sapcx_log_analyzer.ingest.encoding import detect_encoding
from sapcx_log_analyzer.ingest.fields import has_content_column, to_raw_entry
from sapcx_log_analyzer.models import RawEntry

# Stack traces make single cells very large; the csv default of 128 KiB is too small.
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))

_EXPECTED = '"content", "message" or "Log message"'


def sniff_delimiter(header_line: str) -> str:
    try:
        # Only trust the sniffer for the delimiter; its quoting guesses are unreliable
        # on stack traces full of quotes.
        return csv.Sniffer().sniff(header_line, delimiters=",;\t|").delimiter
    except csv.Error:
        return ","


def read_csv(path: Path) -> Iterator[RawEntry]:
    """Stream entries from a CSV export without loading the whole file."""
    # errors="replace": one stray byte deep in a 10 MB file must not lose the whole upload.
    with path.open(encoding=detect_encoding(path), errors="replace", newline="") as handle:
        header_line = handle.readline()
        handle.seek(0)
        reader = csv.DictReader(handle, delimiter=sniff_delimiter(header_line))
        columns = [c.strip() for c in reader.fieldnames or [] if c]
        if not has_content_column(columns):
            found = ", ".join(f'"{c}"' for c in columns[:12]) or "none"
            if len(columns) > 12:
                found += f" and {len(columns) - 12} more"
            raise ExportFormatError(
                f"the CSV has no log message column (expected {_EXPECTED}; found {found})"
            )
        for row in reader:
            entry = to_raw_entry(row)
            if entry is not None:
                yield entry
