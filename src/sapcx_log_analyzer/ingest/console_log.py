"""Reader for raw SAP Commerce console logs: console.log, catalina.out or ``kubectl logs``.

On-premise servers write through the Tanuki service wrapper, which puts its own prefix on
every line::

    INFO   | jvm 1    | main    | 2026/09/02 00:27:23.140 | [2026-09-02T00:27:23,134] INFO  [...
    STATUS | wrapper  | main    | 2026/09/02 10:02:06.794 | Pinging the JVM took 37 seconds ...

After the prefix (when there is one) and the ANSI colour codes, a line is one of:

* the hybris Log4j2 pattern, ``[2026-09-02T00:27:23,134] INFO  [thread] [Logger] message``;
* the Log4j TTCC pattern used during startup, ``1905 [main] INFO  de.hybris.Foo  - message``;
* Tomcat's java.util.logging pair, ``Sep 02, 2026 3:36:16 PM org.apache.Foo init`` then
  ``INFO: message``;
* a continuation of the record above it: stack frames, ``Caused by:`` and the further
  lines of a multi-line message.

Every record is handed on in the Log4j2 pattern form, which the parser already reads.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from sapcx_log_analyzer.ingest.encoding import detect_encoding
from sapcx_log_analyzer.models import RawEntry
from sapcx_log_analyzer.parse.log4j_pattern import parse_pattern_line

_WRAPPER = re.compile(
    r"^(?P<level>[A-Z]+)\s*\|\s*(?P<source>[^|]+?)\s*\|(?:[^|]*\|)??\s*"
    r"(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:[.,]\d+)?)\s*\|\s?(?P<rest>.*)$"
)
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_TTCC = re.compile(
    r"^\s*\d+\s+\[(?P<thread>(?:[^\[\]]|\[[^\[\]]*\])*)\]\s+"
    r"(?P<level>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\s+(?P<logger>\S+)\s+-\s?(?P<msg>.*)$"
)
_JUL_HEADER = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2} \d{1,2}, \d{4} \d{1,2}:\d{2}:\d{2} [AP]M)\s+(?P<logger>\S+)(?:\s+\S+)?$"
)
_JUL_MESSAGE = re.compile(
    r"^(?P<level>SEVERE|WARNING|INFO|CONFIG|FINE|FINER|FINEST):\s?(?P<msg>.*)$"
)
_JUL_LEVELS = {"CONFIG": "DEBUG", "FINE": "DEBUG", "FINER": "TRACE", "FINEST": "TRACE"}
_WRAPPER_LEVELS = {"STATUS": "INFO", "ADVICE": "WARN", "NOTICE": "INFO"}

# A file that never matches a record start must not become one record of every line.
MAX_LINES_PER_RECORD = 1000


@dataclass
class _Record:
    first: str
    timestamp: str | None
    attributes: dict[str, str]
    more: list[str] = field(default_factory=list)
    jul_logger: str | None = None  # a Tomcat header line still waiting for its message

    def entry(self) -> RawEntry:
        content = "\n".join([self.first, *self.more]) if self.more else self.first
        return RawEntry(timestamp=self.timestamp, content=content, attributes=self.attributes)


def _iso(wrapper_ts: str) -> str:
    return wrapper_ts.replace("/", "-").replace(" ", "T", 1)


def _start(text: str, wrapper_ts: str | None, attributes: dict[str, str]) -> _Record | None:
    """The record this line starts, or None if it continues the one before."""
    ts = _iso(wrapper_ts) if wrapper_ts else None
    if parse_pattern_line(text) is not None:
        # The pattern's own timestamp, when it has one, is when the event happened.
        return _Record(text, None if re.match(r"^\[?\d{4}-", text) else ts, attributes)
    if match := _TTCC.match(text):
        level, thread, logger, msg = match.group("level", "thread", "logger", "msg")
        return _Record(f"{level:<5} [{thread}] [{logger}] {msg}", ts, attributes)
    if match := _JUL_HEADER.match(text):
        when = datetime.strptime(match.group("ts"), "%b %d, %Y %I:%M:%S %p")
        record = _Record(text, when.isoformat(), attributes)
        record.jul_logger = match.group("logger")
        return record
    return None


def read_console_log(path: Path) -> Iterator[RawEntry]:
    """Stream records from a console log, joining stack traces onto the line they belong to."""
    current: _Record | None = None
    with path.open(encoding=detect_encoding(path), errors="replace") as handle:
        for raw in handle:
            line = raw.rstrip("\r\n")
            wrapper_ts: str | None = None
            attributes: dict[str, str] = {}
            if match := _WRAPPER.match(line):
                line, wrapper_ts = match.group("rest"), match.group("ts")
                source = match.group("source")
                if source == "wrapper":
                    if current is not None:
                        yield current.entry()
                    current = None
                    level = match.group("level")
                    level = _WRAPPER_LEVELS.get(level, level)
                    text = _ANSI.sub("", line).strip()
                    if text:
                        yield RawEntry(
                            timestamp=_iso(wrapper_ts),
                            content=f"{level:<5} [wrapper] {text}",
                            attributes={"source": "wrapper"},
                        )
                    continue
                attributes = {"source": source}
            text = _ANSI.sub("", line).rstrip()
            if not text.strip():
                continue

            if current is not None and current.jul_logger:
                if jul := _JUL_MESSAGE.match(text):
                    level = _JUL_LEVELS.get(jul.group("level"), jul.group("level"))
                    current.first = f"{level:<5} [] [{current.jul_logger}] {jul.group('msg')}"
                    current.jul_logger = None
                    continue
                current.jul_logger = None

            record = _start(text, wrapper_ts, attributes)
            if record is None and current is not None and len(current.more) < MAX_LINES_PER_RECORD:
                current.more.append(text)
                continue
            if current is not None:
                yield current.entry()
            current = record or _Record(text, _iso(wrapper_ts) if wrapper_ts else None, attributes)
    if current is not None:
        yield current.entry()
