"""Guess the text encoding of an export or log file."""

from __future__ import annotations

import codecs
from pathlib import Path


def detect_encoding(path: Path) -> str:
    """UTF-8 (with or without BOM), UTF-16 from Excel's "Unicode text", else Windows-1252."""
    with path.open("rb") as handle:
        head = handle.read(64 * 1024)
    if head.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return "utf-16"
    try:
        # A multi-byte character cut at the end of the sample is not a decoding problem.
        codecs.getincrementaldecoder("utf-8-sig")().decode(head, final=False)
    except UnicodeDecodeError:
        return "cp1252"
    return "utf-8-sig"
