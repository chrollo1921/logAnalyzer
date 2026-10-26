from __future__ import annotations

from datetime import UTC, datetime

from sapcx_log_analyzer.cluster import ClusterAggregator, fingerprint, template_of
from sapcx_log_analyzer.models import Classification, LogLevel, Severity
from tests.conftest import make_record

CLS = Classification(rule_id="r", component="c", severity=Severity.HIGH, title="t")


def test_template_masks_variable_parts() -> None:
    message = (
        "Order order00001234 for <EMAIL> failed at 2026-10-20 09:00:00,123 PK 8796093054980 "
        "id 3f2b1c4e-1111-2222-3333-444455556666 code 'ABC' after 30000 ms 0xDEADBEEF"
    )
    assert template_of(message) == (
        "Order order<NUM> for <*> failed at <TS> PK <NUM> id <UUID> code '<STR>' "
        "after <NUM> ms <HEX>"
    )


def test_template_uses_first_line_only() -> None:
    assert template_of("first line 1\nsecond") == "first line <NUM>"
    assert template_of("   ") == ""


def test_same_issue_shares_fingerprint() -> None:
    a = fingerprint(make_record("Could not load PK 1", logger="L"), CLS)
    b = fingerprint(make_record("Could not load PK 2", logger="L"), CLS)
    c = fingerprint(make_record("Could not load PK 2", logger="Other"), CLS)
    assert a == b
    assert a[0] != c[0]


def test_aggregation_tracks_counts_times_aspects_and_samples() -> None:
    agg = ClusterAggregator(samples_per_cluster=2, bucket_minutes=5)
    for minute, pod, aspect in [
        (1, "api-1", "api"),
        (7, "api-2", "api"),
        (3, "bg-1", "backgroundprocessing"),
    ]:
        agg.add(
            make_record(
                f"Pool timeout {minute}",
                timestamp=datetime(2026, 10, 20, 9, minute, tzinfo=UTC),
                pod=pod,
                aspect=aspect,
                thread="hybrisHTTP1",
                logger="L",
                stack=["x.YException", "\tat java.util.X.y()", "\tat de.hybris.Foo.bar()"],
            ),
            CLS,
        )
    [cluster] = agg.clusters()
    assert cluster.count == 3
    assert cluster.first_seen == datetime(2026, 10, 20, 9, 1, tzinfo=UTC)
    assert cluster.last_seen == datetime(2026, 10, 20, 9, 7, tzinfo=UTC)
    assert cluster.aspects == ["api", "backgroundprocessing"]
    assert cluster.pods == ["api-1", "api-2", "bg-1"]
    assert len(cluster.samples) == 2
    assert cluster.top_frames == ["de.hybris.Foo.bar()"]
    timeline = agg.timeline()
    assert [b.start.minute for b in timeline] == [0, 5]
    assert timeline[0].counts == {Severity.HIGH: 2}


def test_level_escalates_and_samples_are_truncated() -> None:
    agg = ClusterAggregator(max_sample_chars=120)
    agg.add(make_record("x " + "a" * 200, level=LogLevel.WARN), CLS)
    agg.add(make_record("x " + "a" * 200, level=LogLevel.WARN), CLS)
    agg.add(make_record("x " + "a" * 200, level=LogLevel.FATAL), CLS)
    [cluster] = agg.clusters()
    assert cluster.level is LogLevel.FATAL
    assert cluster.samples[0].endswith("…[truncated]")
    assert len(cluster.samples) == 2  # the identical WARN sample is not repeated
    assert cluster.first_seen is None


def test_clusters_sorted_by_severity_then_count() -> None:
    agg = ClusterAggregator()
    low = Classification(rule_id="low", component="c", severity=Severity.LOW, title="t")
    for _ in range(5):
        agg.add(make_record("noise"), low)
    agg.add(make_record("rare"), CLS)
    agg.add(make_record("common"), CLS)
    agg.add(make_record("common"), CLS)
    assert [(c.rule_id, c.count) for c in agg.clusters()] == [("r", 2), ("r", 1), ("low", 5)]


def test_framework_only_stack_keeps_frames() -> None:
    agg = ClusterAggregator()
    agg.add(make_record("x", stack=["\tat java.lang.Thread.run()"]), CLS)
    assert agg.clusters()[0].top_frames == ["java.lang.Thread.run()"]
