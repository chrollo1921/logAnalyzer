"""Parser for the classic SAP Commerce console pattern.

Typical lines::

    ERROR [hybrisHTTP31] [10.1.2.3] [DefaultCartService] Could not calculate cart
    2026-10-20 10:15:30,123 WARN  [update-backofficeIndex-cronJob::de.hybris...] [Indexer] ...
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from sapcx_log_analyzer.parse.sapcx_json import ParsedLine

_LINE = re.compile(
    r"^(?:(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}"
    r"(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?)\s+)?"
    r"(?:\|\s*)?(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|SEVERE)\s+"
    r"(?P<brackets>(?:\[[^\]]*\]\s*)*)"
    r"(?P<msg>.*)$"
)
_BRACKET = re.compile(r"\[([^\]]*)\]")
_LOGGER = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[\w$]+)*$")


def parse_timestamp(value: str | None) -> datetime | None:
    """Parse ISO-8601, log4j ``yyyy-MM-dd HH:mm:ss,SSS`` or epoch-millisecond values."""
    if not value:
        return None
    text = value.strip()
    if text.isdigit():
        number = int(text)
        seconds = number / 1000 if number > 10**11 else number
        return datetime.fromtimestamp(seconds, tz=UTC)
    text = text.replace(",", ".").replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def parse_pattern_line(content: str) -> ParsedLine | None:
    lines = content.splitlines() or [content]
    match = _LINE.match(lines[0].strip())
    if match is None:
        return None
    brackets = [b.strip() for b in _BRACKET.findall(match.group("brackets") or "")]
    thread = brackets[0] if brackets else None
    logger = next(
        (b for b in reversed(brackets[1:]) if _LOGGER.match(b) and not b[0].isdigit()),
        None,
    )
    return ParsedLine(
        message=match.group("msg").strip(),
        level=match.group("level"),
        logger=logger,
        thread=thread,
        timestamp=parse_timestamp(match.group("ts")),
        stack=lines[1:],
    )
