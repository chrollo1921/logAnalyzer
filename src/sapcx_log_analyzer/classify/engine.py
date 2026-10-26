"""Rule-based classification of log records. No LLM involved."""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from sapcx_log_analyzer.models import Classification, LogLevel, LogRecord, Severity

UNCLASSIFIED_ID = "unclassified"

_SEVERITY_BY_LEVEL = {
    LogLevel.FATAL: Severity.HIGH,
    LogLevel.ERROR: Severity.MEDIUM,
    LogLevel.WARN: Severity.LOW,
}


class Rule(BaseModel):
    id: str
    title: str
    component: str
    severity: Severity
    patterns: list[str] = Field(min_length=1)
    loggers: list[str] = Field(default_factory=list)
    # Match records below the configured minimum level too (e.g. GC logs at INFO).
    any_level: bool = False


@dataclass(frozen=True)
class _CompiledRule:
    rule: Rule
    pattern: re.Pattern[str]
    logger: re.Pattern[str] | None

    def matches(self, record: LogRecord, text: str) -> bool:
        if self.logger is not None and not self.logger.search(record.logger or ""):
            return False
        return bool(self.pattern.search(text))


def _parse_rules(document: Any, source: str) -> list[Rule]:
    if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
        raise ValueError(f"{source}: expected a mapping with a 'rules' list")
    return [Rule.model_validate(item) for item in document["rules"]]


def load_default_rules() -> list[Rule]:
    text = (
        resources.files("sapcx_log_analyzer.classify")
        .joinpath("rules/sapcx_rules.yaml")
        .read_text(encoding="utf-8")
    )
    return _parse_rules(yaml.safe_load(text), "built-in rules")


def load_rules_file(path: Path) -> list[Rule]:
    return _parse_rules(yaml.safe_load(path.read_text(encoding="utf-8")), str(path))


class RuleEngine:
    """Applies rules in order; the first match wins."""

    def __init__(self, rules: list[Rule]) -> None:
        ids = [rule.id for rule in rules]
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        if duplicates:
            raise ValueError(f"Duplicate rule ids: {', '.join(duplicates)}")
        self.rules = rules
        self._compiled = [
            _CompiledRule(
                rule=rule,
                pattern=re.compile("|".join(f"(?:{p})" for p in rule.patterns), re.IGNORECASE),
                logger=(
                    re.compile("|".join(f"(?:{p})" for p in rule.loggers), re.IGNORECASE)
                    if rule.loggers
                    else None
                ),
            )
            for rule in rules
        ]

    @classmethod
    def default(cls, extra_rules_file: Path | None = None) -> RuleEngine:
        """Built-in rules, with project-specific rules from a file taking precedence."""
        extra = load_rules_file(extra_rules_file) if extra_rules_file else []
        return cls([*extra, *load_default_rules()])

    def classify(self, record: LogRecord) -> Classification | None:
        """Return the matching rule, a generic classification, or None for noise."""
        text = record.search_text()
        for compiled in self._compiled:
            if compiled.matches(record, text):
                rule = compiled.rule
                return Classification(
                    rule_id=rule.id,
                    component=rule.component,
                    severity=rule.severity,
                    title=rule.title,
                    any_level=rule.any_level,
                )
        severity = _SEVERITY_BY_LEVEL.get(record.level)
        if severity is None:
            return None
        return Classification(
            rule_id=UNCLASSIFIED_ID,
            component="Unclassified",
            severity=severity,
            title=record.exception_class or "Unclassified log event",
        )
