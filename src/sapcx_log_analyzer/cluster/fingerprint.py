"""Collapse log messages that differ only in variable parts into one template."""

from __future__ import annotations

import hashlib
import re

from sapcx_log_analyzer.models import Classification, LogRecord

# Applied in order; earlier, more specific masks protect values from later ones.
_MASKS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"<[A-Z?]+>"), "<*>"),  # placeholders left by the redactor
    (
        re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
        "<UUID>",
    ),
    (
        re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"),
        "<TS>",
    ),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<HEX>"),
    (re.compile(r"\b[0-9a-fA-F]{16,}\b"), "<HEX>"),
    (re.compile(r"(?i)\bPK\s*[=:]?\s*\d+"), "PK <NUM>"),
    (re.compile(r"'[^']{0,200}'"), "'<STR>'"),
    (re.compile(r'"[^"]{0,200}"'), '"<STR>"'),
    (re.compile(r"\b\d+(?:\.\d+)?\b"), "<NUM>"),
    (re.compile(r"(?<=[A-Za-z_-])\d+\b"), "<NUM>"),  # hybrisHTTP12, order00001234
    (re.compile(r"\s+"), " "),
)
_MAX_TEMPLATE = 300


def template_of(message: str) -> str:
    first_line = message.strip().splitlines()[0] if message.strip() else ""
    text = first_line
    for pattern, replacement in _MASKS:
        text = pattern.sub(replacement, text)
    return text.strip()[:_MAX_TEMPLATE]


def fingerprint(record: LogRecord, classification: Classification) -> tuple[str, str]:
    """Return a short stable id and the message template for a record."""
    template = template_of(record.message)
    key = "|".join(
        [
            classification.rule_id,
            record.logger or "",
            record.root_cause_class or record.exception_class or "",
            template,
        ]
    )
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    return digest, template
