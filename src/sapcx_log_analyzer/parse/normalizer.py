"""Turn raw export entries into normalized LogRecords."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

from sapcx_log_analyzer.models import LogLevel, LogRecord, RawEntry
from sapcx_log_analyzer.parse.log4j_pattern import parse_pattern_line, parse_timestamp
from sapcx_log_analyzer.parse.sapcx_json import ParsedLine, parse_json_line
from sapcx_log_analyzer.parse.stacktrace import analyze_stack, is_continuation

# CCv2 aspects, in the order they are checked against pod and workload names.
KNOWN_ASPECTS = (
    "backgroundprocessing",
    "backoffice",
    "accstorefront",
    "jsapps",
    "api",
    "admin",
    "solr",
    "zookeeper",
)
_POD_KEYS = ("k8s.pod.name", "pod", "host.name", "dt.kubernetes.pod.name")
_ASPECT_KEYS = ("aspect", "k8s.workload.name", "k8s.deployment.name", "k8s.container.name")
# Export attributes that link records belonging to one request or business transaction.
_CORRELATION_KEY = re.compile(
    r"(?i)(?:^|[._-])(?:trace|span|correlation|request|transaction|txn?|session|order|cart)"
    r"(?:[._-]?(?:id|code|number))?$"
)


def stitch(entries: Iterable[RawEntry]) -> Iterator[RawEntry]:
    """Join stack trace lines that Dynatrace exported as separate records."""
    pending: RawEntry | None = None
    for entry in entries:
        if pending is not None and is_continuation(entry.content):
            same_pod = _pod(pending) == _pod(entry) or _pod(entry) is None
            if same_pod:
                pending = pending.model_copy(
                    update={"content": f"{pending.content}\n{entry.content}"}
                )
                continue
        if pending is not None:
            yield pending
        pending = entry
    if pending is not None:
        yield pending


def _pod(entry: RawEntry) -> str | None:
    for key in _POD_KEYS:
        if entry.attributes.get(key):
            return entry.attributes[key]
    return None


def _aspect(entry: RawEntry) -> str | None:
    names = [entry.attributes.get(key, "") for key in (*_ASPECT_KEYS, *_POD_KEYS)]
    for name in names:
        lowered = name.lower()
        for aspect in KNOWN_ASPECTS:
            if re.search(rf"(?:^|[-_.]){aspect}(?:$|[-_.])", lowered):
                return aspect
    return None


def _context(entry: RawEntry, parsed: ParsedLine) -> dict[str, str]:
    context = {
        key: value for key, value in entry.attributes.items() if _CORRELATION_KEY.search(key)
    }
    context.update(parsed.context)
    return context


def _parse_content(content: str) -> ParsedLine:
    first, _, rest = content.partition("\n")
    parsed = parse_json_line(first)
    if parsed is not None:
        parsed.stack.extend(line for line in rest.splitlines() if line.strip())
        return parsed
    parsed = parse_pattern_line(content)
    if parsed is not None:
        return parsed
    lines = content.splitlines() or [content]
    return ParsedLine(message=lines[0].strip(), stack=lines[1:])


def normalize(entry: RawEntry) -> LogRecord:
    parsed = _parse_content(entry.content)
    stack = analyze_stack(parsed.stack, parsed.message)
    level = LogLevel.parse(parsed.level) if parsed.level else LogLevel.parse(entry.level)
    if stack.exception_class and level.rank < LogLevel.WARN.rank and parsed.level is None:
        # Bare stack traces on stdout arrive without a level; treat them as errors.
        level = LogLevel.ERROR
    return LogRecord(
        timestamp=parse_timestamp(entry.timestamp) or parsed.timestamp,
        level=level,
        logger=parsed.logger,
        thread=parsed.thread,
        message=parsed.message,
        exception_class=stack.exception_class,
        root_cause_class=stack.root_cause_class,
        stack=stack.lines,
        aspect=_aspect(entry),
        pod=_pod(entry),
        context=_context(entry, parsed),
    )


def normalize_all(entries: Iterable[RawEntry]) -> Iterator[LogRecord]:
    for entry in stitch(entries):
        yield normalize(entry)
