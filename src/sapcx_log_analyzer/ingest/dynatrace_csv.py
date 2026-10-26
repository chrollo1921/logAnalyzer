"""Reader for CSV exports from the Dynatrace Logs viewer."""

from __future__ import annotations

import csv
import sys
from collections.abc import Iterator
from pathlib import Path

from sapcx_log_analyzer.ingest.fields import to_raw_entry
from sapcx_log_analyzer.models import RawEntry

# Stack traces make single cells very large; the csv default of 128 KiB is too small.
csv.field_size_limit(min(sys.maxsize, 2**31 - 1))


def read_csv(path: Path) -> Iterator[RawEntry]:
    """Stream entries from a CSV export without loading the whole file."""
    with path.open(encoding="utf-8-sig", newline="") as handle:
        sample = handle.read(8192)
        handle.seek(0)
        try:
            # Only trust the sniffer for the delimiter; its quoting guesses are unreliable
            # on stack traces full of quotes.
            delimiter = csv.Sniffer().sniff(sample.splitlines()[0], delimiters=",;\t").delimiter
        except (csv.Error, IndexError):
            delimiter = ","
        for row in csv.DictReader(handle, delimiter=delimiter):
            entry = to_raw_entry(row)
            if entry is not None:
                yield entry
