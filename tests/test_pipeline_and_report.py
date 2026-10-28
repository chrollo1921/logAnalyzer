from __future__ import annotations

import json
from pathlib import Path

from sapcx_log_analyzer.config import Settings
from sapcx_log_analyzer.models import LogLevel, Report, Severity
from sapcx_log_analyzer.pipeline import analyze, prepare
from sapcx_log_analyzer.report import OutputFormat, render
from tests.conftest import FakeProvider


def test_prepare_csv_end_to_end(csv_export: Path, settings: Settings) -> None:
    prepared = prepare(csv_export, settings)
    report = prepared.report
    meta = report.metadata
    assert meta.total_records == 50
    assert meta.analyzed_records == 28
    rules = {c.rule_id: c for c in report.clusters}
    assert set(rules) == {
        "db-connection-pool-exhausted",
        "jvm-out-of-memory",
        "solr-indexing-failure",
        "occ-request-failure",
        "cronjob-failure",
        "jvm-gc-pause",
        "impex-failure",
        "occ-auth-failure",
    }
    pool = rules["db-connection-pool-exhausted"]
    assert pool.count == 12
    assert pool.aspects == ["api"]
    assert len(pool.pods) == 2
    assert pool.root_cause_class == "java.sql.SQLTransientConnectionException"
    assert report.clusters[0].severity is Severity.CRITICAL
    assert prepared.redaction_counts == {"email": 6, "bearer_token": 5, "password_assignment": 1}


def test_nothing_sensitive_survives(csv_export: Path, settings: Settings) -> None:
    report = prepare(csv_export, settings).report
    text = render(report, OutputFormat.JSON)
    for secret in ("jane.doe", "example.com", "abcDEF123456", "S3cr3tPass"):
        assert secret not in text


def test_min_level_error_drops_warnings_but_keeps_gc(csv_export: Path) -> None:
    report = prepare(csv_export, Settings(min_level=LogLevel.ERROR)).report
    rules = {c.rule_id for c in report.clusters}
    assert "occ-auth-failure" not in rules
    assert "jvm-gc-pause" in rules  # any_level rule


def test_prepare_json_layout(json_export: Path, settings: Settings) -> None:
    report = prepare(json_export, settings).report
    [rule_engine, checkout] = report.clusters
    assert rule_engine.rule_id == "rule-engine-failure"
    assert rule_engine.count == 4  # version numbers are masked
    assert rule_engine.root_cause_class == "java.lang.IllegalStateException"
    assert checkout.rule_id == "checkout-failure"


def test_analyze_with_provider(
    csv_export: Path, settings: Settings, fake_provider: FakeProvider
) -> None:
    report = analyze(csv_export, settings, fake_provider)
    assert report.metadata.llm_used
    assert report.metadata.model == "fake-model"
    assert report.analysis is not None
    assert len(report.analysis.findings[0].cluster_ids) == len(report.clusters)
    prompt = fake_provider.calls[0]["prompt"]
    assert "jane.doe" not in prompt and "<EMAIL#" in prompt


def test_analyze_without_provider(csv_export: Path, settings: Settings) -> None:
    report = analyze(csv_export, settings, None)
    assert report.analysis is None
    assert not report.metadata.llm_used


def test_render_markdown_with_analysis(
    csv_export: Path, settings: Settings, fake_provider: FakeProvider
) -> None:
    report = analyze(csv_export, settings, fake_provider)
    text = render(report, OutputFormat.MARKDOWN)
    assert text.startswith("# SAP Commerce log analysis: dynatrace_export.csv")
    assert "**Overall severity: CRITICAL**" in text
    assert "## Findings" in text
    assert "*config*: Raise db.pool.maxActive." in text
    assert "(28 events)" in text
    assert "## Timeline (5-minute buckets)" in text
    assert "| critical | Database / Connection pool |" in text


def test_render_markdown_without_analysis(csv_export: Path, settings: Settings) -> None:
    text = render(prepare(csv_export, settings).report, OutputFormat.MARKDOWN)
    assert "rules and clustering only" in text
    assert "## Findings" not in text


def test_render_json_round_trips(
    csv_export: Path, settings: Settings, fake_provider: FakeProvider
) -> None:
    report = analyze(csv_export, settings, fake_provider)
    parsed = Report.model_validate(json.loads(render(report, OutputFormat.JSON)))
    assert parsed == report


def test_render_html_escapes_log_content(tmp_path: Path, settings: Settings) -> None:
    export = tmp_path / "x.csv"
    export.write_text(
        "timestamp,status,content\n"
        '2026-10-20T09:00:00Z,ERROR,"ERROR [t] [L] <script>alert(1)</script>"\n'
    )
    text = render(prepare(export, settings).report, OutputFormat.HTML)
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;" in text
    assert text.startswith("<!doctype html>")


def test_empty_export(tmp_path: Path, settings: Settings, fake_provider: FakeProvider) -> None:
    export = tmp_path / "empty.csv"
    export.write_text("timestamp,status,content\n")
    report = analyze(export, settings, fake_provider)
    assert report.clusters == []
    assert fake_provider.calls == []
    assert "No warnings or errors" in render(report, OutputFormat.MARKDOWN)
