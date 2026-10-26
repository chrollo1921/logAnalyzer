"""Java stack trace helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_EXCEPTION_HEADER = re.compile(
    r"^(?:Caused by:\s*|Suppressed:\s*|Exception in thread \"[^\"]*\"\s+)?"
    r"(?P<cls>(?:[a-zA-Z_$][\w$]*\.)+[A-Z][\w$]*(?:Exception|Error|Throwable|Fault)[\w$]*)"
    r"(?::\s?(?P<msg>.*))?$"
)
_CONTINUATION = re.compile(r"^\s*(?:at\s|Caused by:|Suppressed:|\.\.\.\s*\d+\s+(?:more|common))")
_FRAME = re.compile(r"^\s*at\s+(?P<frame>\S.*)$")


def is_continuation(line: str) -> bool:
    """True for a line that only makes sense as part of the previous record's trace."""
    return bool(_CONTINUATION.match(line))


def exception_in(line: str) -> str | None:
    match = _EXCEPTION_HEADER.match(line.strip())
    return match.group("cls") if match else None


@dataclass
class StackInfo:
    exception_class: str | None = None
    root_cause_class: str | None = None
    lines: list[str] = field(default_factory=list)


def analyze_stack(lines: list[str], message: str = "") -> StackInfo:
    """Find the top-level and root-cause exception classes in a trace."""
    info = StackInfo(lines=[line.rstrip() for line in lines if line.strip()])
    candidates = [message.splitlines()[0]] if message else []
    candidates.extend(info.lines)
    for line in candidates:
        cls = exception_in(line)
        if cls is None:
            continue
        if info.exception_class is None:
            info.exception_class = cls
        if line.lstrip().startswith("Caused by:") or info.root_cause_class is None:
            info.root_cause_class = cls
    return info


def frames(lines: list[str]) -> list[str]:
    result = []
    for line in lines:
        match = _FRAME.match(line)
        if match:
            result.append(match.group("frame"))
    return result
