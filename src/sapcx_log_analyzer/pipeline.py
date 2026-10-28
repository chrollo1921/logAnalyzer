"""Wires the pipeline together: ingest, normalize, redact, classify, cluster, analyse."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from sapcx_log_analyzer.classify import RuleEngine
from sapcx_log_analyzer.cluster import ClusterAggregator
from sapcx_log_analyzer.config import Settings
from sapcx_log_analyzer.ingest import ExportFormat, read_export
from sapcx_log_analyzer.llm import LLMAnalyzer, LLMProvider
from sapcx_log_analyzer.models import Report, ReportMetadata
from sapcx_log_analyzer.parse import normalize_all
from sapcx_log_analyzer.redact import Redactor

log = logging.getLogger(__name__)


@dataclass
class PreparedExport:
    """Everything the deterministic stages produce, before any LLM call."""

    report: Report
    redaction_counts: dict[str, int] = field(default_factory=dict)


def prepare(
    path: Path,
    settings: Settings,
    export_format: ExportFormat | None = None,
    engine: RuleEngine | None = None,
) -> PreparedExport:
    engine = engine or RuleEngine.default(settings.extra_rules_file)
    redactor = Redactor(settings.extra_redaction_patterns)
    aggregator = ClusterAggregator(
        samples_per_cluster=settings.samples_per_cluster,
        max_sample_chars=settings.max_sample_chars,
        top_frames=settings.top_frames_per_cluster,
        bucket_minutes=settings.timeline_bucket_minutes,
    )
    total = analyzed = 0
    start: datetime | None = None
    end: datetime | None = None

    for record in normalize_all(read_export(path, export_format)):
        total += 1
        if record.timestamp is not None:
            start = record.timestamp if start is None else min(start, record.timestamp)
            end = record.timestamp if end is None else max(end, record.timestamp)
        record = redactor.redact_record(record)
        classification = engine.classify(record, settings.min_level)
        if classification is None:
            continue
        if record.level.rank < settings.min_level.rank and not classification.any_level:
            continue
        analyzed += 1
        aggregator.add(record, classification)

    log.info("Read %d records, %d kept for analysis", total, analyzed)
    report = Report(
        metadata=ReportMetadata(
            source=path.name,
            generated_at=datetime.now(UTC),
            total_records=total,
            analyzed_records=analyzed,
            time_range_start=start,
            time_range_end=end,
            extra={
                "redactions": dict(redactor.counts),
                "timeline_bucket_minutes": settings.timeline_bucket_minutes,
            },
        ),
        clusters=aggregator.clusters(),
        timeline=aggregator.timeline(),
    )
    return PreparedExport(report=report, redaction_counts=dict(redactor.counts))


def analyze(
    path: Path,
    settings: Settings,
    provider: LLMProvider | None,
    export_format: ExportFormat | None = None,
) -> Report:
    """Run the full pipeline. With no provider the report has clusters but no analysis."""
    report = prepare(path, settings, export_format).report
    if provider is None:
        return report
    analysis = LLMAnalyzer(provider, settings).analyze(report.clusters, report.metadata)
    report.analysis = analysis
    report.metadata.llm_used = True
    report.metadata.model = provider.model_name
    return report
