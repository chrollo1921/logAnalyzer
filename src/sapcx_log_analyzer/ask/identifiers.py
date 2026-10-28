"""Find transaction, request and business identifiers in log records.

SAP Commerce rarely logs one universal transaction id. A request is usually traceable
through a mix of a Dynatrace trace id, an MDC correlation id, OCC request ids, order and
cart codes, session ids and project-specific ids such as ``tx-243232``. This module pulls
all of them out so the store can index them and the model can pivot between them.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from sapcx_log_analyzer.models import LogRecord

# Words that name an identifier, mapped to the kind reported to the model.
_KIND_WORDS: tuple[tuple[str, str], ...] = (
    ("trace", "trace"),
    ("span", "span"),
    ("correlation", "correlation"),
    ("request", "request"),
    ("transaction", "transaction"),
    ("txn", "transaction"),
    ("tx", "transaction"),
    ("session", "session"),
    ("consignment", "consignment"),
    ("payment", "payment"),
    ("order", "order"),
    ("cart", "cart"),
    ("b2bunit", "account"),
    ("unit", "account"),
    ("account", "account"),
    ("customer", "user"),
    ("user", "user"),
    ("uid", "user"),
)

# "orderCode=00012345", "cart 00001234", "X-Request-Id: 7f3a...", "tx_id: 99812".
# The value must contain a digit so ordinary words after "order" or "cart" are skipped.
_KEYED = re.compile(
    r"(?i)\b(?P<key>trace[_ -]?id|span[_ -]?id|correlation[_ -]?id|x-request-id|request[_ -]?id"
    r"|transaction(?:[_ -]?id)?|txn?[_ -]?id|order(?:[_ -]?(?:code|id|number|no))?"
    r"|cart(?:[_ -]?(?:code|id))?|consignment(?:[_ -]?code)?|payment[_ -]?transaction(?:[_ -]?id)?"
    r"|(?:b2b[_ -]?)?unit(?:[_ -]?id)?|account(?:[_ -]?id)?|customer(?:[_ -]?id)?|user(?:[_ -]?id)?"
    r"|uid)"
    r"\s*[=:#]?\s*['\"]?(?P<value>(?=[A-Za-z0-9._:-]*\d)[A-Za-z0-9][A-Za-z0-9._:-]{3,})"
)
# Self-describing ids: tx-243232, ORD-000123, REQ_88812.
_PREFIXED = re.compile(r"\b(?P<value>[A-Za-z]{2,6}[-_]\d{3,}(?:[-_][A-Za-z0-9]+)*)\b")
_UUID = re.compile(
    r"\b(?P<value>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b"
)
# W3C / Dynatrace trace ids are 32 hex characters.
_TRACE_HEX = re.compile(r"\b(?P<value>[0-9a-f]{32})\b")
# Placeholders such as <IP> carry no identity and would link unrelated records.
_PLACEHOLDER = re.compile(r"^<[A-Z?]+>$")
# Link tokens left by the redactor, e.g. <SESSION#1a2b3c4d>.
_LINK_TOKEN = re.compile(r"(?P<value><[A-Z]+#[0-9a-f]+>)")
_PREFIX_KIND = {"tx": "transaction", "txn": "transaction", "ord": "order", "req": "request"}


@dataclass(frozen=True)
class Identifier:
    kind: str
    value: str


def kind_of(name: str) -> str:
    lowered = name.lower()
    for word, kind in _KIND_WORDS:
        if word in lowered:
            return kind
    return "id"


def _scan(text: str) -> Iterator[Identifier]:
    for match in _KEYED.finditer(text):
        yield Identifier(kind_of(match.group("key")), match.group("value").rstrip(".:"))
    for match in _PREFIXED.finditer(text):
        value = match.group("value")
        prefix = re.split(r"[-_]", value, maxsplit=1)[0].lower()
        yield Identifier(_PREFIX_KIND.get(prefix, "id"), value)
    for match in _UUID.finditer(text):
        yield Identifier("uuid", match.group("value"))
    for match in _TRACE_HEX.finditer(text):
        yield Identifier("trace", match.group("value"))
    for match in _LINK_TOKEN.finditer(text):
        token = match.group("value")
        yield Identifier("user" if token.startswith("<EMAIL") else "session", token)


def identifiers_in(record: LogRecord) -> list[Identifier]:
    """Every identifier in a record, context values first, without duplicates."""
    found: dict[str, Identifier] = {}
    for key, value in record.context.items():
        if not _PLACEHOLDER.match(value):
            found.setdefault(value.lower(), Identifier(kind_of(key), value))
    texts = [record.message, *record.stack[:20]]
    for text in texts:
        for identifier in _scan(text):
            found.setdefault(identifier.value.lower(), identifier)
    return list(found.values())
