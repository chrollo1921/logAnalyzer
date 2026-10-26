"""Domain models shared across the pipeline."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class LogLevel(StrEnum):
    TRACE = "TRACE"
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    FATAL = "FATAL"

    @property
    def rank(self) -> int:
        return _LEVEL_RANK[self]

    @classmethod
    def parse(cls, value: str | None) -> LogLevel:
        """Map the many spellings Dynatrace and log4j use onto a level."""
        if not value:
            return cls.INFO
        key = value.strip().upper()
        return _LEVEL_ALIASES.get(key, cls.INFO)


_LEVEL_RANK = {
    LogLevel.TRACE: 0,
    LogLevel.DEBUG: 1,
    LogLevel.INFO: 2,
    LogLevel.WARN: 3,
    LogLevel.ERROR: 4,
    LogLevel.FATAL: 5,
}

_LEVEL_ALIASES = {
    "TRACE": LogLevel.TRACE,
    "DEBUG": LogLevel.DEBUG,
    "INFO": LogLevel.INFO,
    "INFORMATIONAL": LogLevel.INFO,
    "NOTICE": LogLevel.INFO,
    "NONE": LogLevel.INFO,
    "WARN": LogLevel.WARN,
    "WARNING": LogLevel.WARN,
    "ERROR": LogLevel.ERROR,
    "SEVERE": LogLevel.ERROR,
    "FATAL": LogLevel.FATAL,
    "CRITICAL": LogLevel.FATAL,
    "EMERGENCY": LogLevel.FATAL,
    "ALERT": LogLevel.FATAL,
}


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class RawEntry(BaseModel):
    """One record as it came out of the Dynatrace export, before parsing."""

    timestamp: str | None = None
    content: str
    level: str | None = None
    attributes: dict[str, str] = Field(default_factory=dict)


class LogRecord(BaseModel):
    """A normalized SAP Commerce log event."""

    timestamp: datetime | None = None
    level: LogLevel = LogLevel.INFO
    logger: str | None = None
    thread: str | None = None
    message: str
    exception_class: str | None = None
    root_cause_class: str | None = None
    stack: list[str] = Field(default_factory=list)
    aspect: str | None = None
    pod: str | None = None
    # Correlation values such as trace_id, span_id or CCv2 MDC entries, keyed by source name.
    context: dict[str, str] = Field(default_factory=dict)

    def search_text(self) -> str:
        """Text the classifier matches rules against."""
        parts = [self.logger or "", self.message, self.exception_class or ""]
        parts.extend(line for line in self.stack if not line.lstrip().startswith("at "))
        return "\n".join(parts)


class Classification(BaseModel):
    rule_id: str
    component: str
    severity: Severity
    title: str
    any_level: bool = False


class Cluster(BaseModel):
    """A group of records that share a fingerprint."""

    id: str
    rule_id: str
    component: str
    title: str
    severity: Severity
    level: LogLevel
    logger: str | None = None
    exception_class: str | None = None
    root_cause_class: str | None = None
    template: str
    count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    aspects: list[str] = Field(default_factory=list)
    pods: list[str] = Field(default_factory=list)
    samples: list[str] = Field(default_factory=list)
    top_frames: list[str] = Field(default_factory=list)


class ActionType(StrEnum):
    CONFIG = "config"
    CODE = "code"
    OPS = "ops"
    INVESTIGATE = "investigate"


class RecommendedAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: ActionType
    description: str


class Finding(BaseModel):
    """One issue as explained by the LLM."""

    model_config = ConfigDict(extra="forbid")

    title: str
    cluster_ids: list[str]
    component: str
    severity: Severity
    confidence: float = Field(description="0.0 to 1.0")
    summary: str
    root_cause: str
    recommended_actions: list[RecommendedAction]
    evidence: list[str]


class BatchFindings(BaseModel):
    """LLM output for one batch of clusters."""

    model_config = ConfigDict(extra="forbid")

    findings: list[Finding]


class IncidentSummary(BaseModel):
    """LLM output for the overall picture across all findings."""

    model_config = ConfigDict(extra="forbid")

    summary: str
    overall_severity: Severity
    top_priorities: list[str]


class IncidentAnalysis(BaseModel):
    """LLM output when every cluster fits in one request."""

    model_config = ConfigDict(extra="forbid")

    summary: str
    overall_severity: Severity
    top_priorities: list[str]
    findings: list[Finding]


class TimelineBucket(BaseModel):
    start: datetime
    counts: dict[Severity, int] = Field(default_factory=dict)


class ReportMetadata(BaseModel):
    source: str
    generated_at: datetime
    total_records: int
    analyzed_records: int
    time_range_start: datetime | None = None
    time_range_end: datetime | None = None
    model: str | None = None
    llm_used: bool = False
    extra: dict[str, Any] = Field(default_factory=dict)


class Report(BaseModel):
    metadata: ReportMetadata
    clusters: list[Cluster]
    timeline: list[TimelineBucket] = Field(default_factory=list)
    analysis: IncidentAnalysis | None = None
