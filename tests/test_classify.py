from __future__ import annotations

from pathlib import Path

import pytest

from sapcx_log_analyzer.classify import UNCLASSIFIED_ID, Rule, RuleEngine, load_default_rules
from sapcx_log_analyzer.models import LogLevel, Severity
from tests.conftest import make_record


@pytest.fixture(scope="module")
def engine() -> RuleEngine:
    return RuleEngine.default()


@pytest.mark.parametrize(
    ("message", "stack", "rule_id"),
    [
        ("java.lang.OutOfMemoryError: Java heap space", [], "jvm-out-of-memory"),
        ("java.lang.StackOverflowError", [], "jvm-stack-overflow"),
        (
            "Context initialization failed",
            ["o.s.BeanCreationException: x"],
            "spring-context-failure",
        ),
        (
            "Could not load product",
            [
                "Caused by: x.SQLTransientConnectionException: HikariPool-1 - Connection is not "
                "available, request timed out after 30000ms."
            ],
            "db-connection-pool-exhausted",
        ),
        ("Transaction was deadlocked on lock resources", [], "db-deadlock"),
        (
            "de.hybris.platform.servicelayer.search.exceptions.FlexibleSearchException: bad",
            [],
            "flexiblesearch-error",
        ),
        ("com.microsoft.sqlserver.jdbc.SQLServerException: Invalid column", [], "db-sql-error"),
        ("Error while indexing electronicsIndex", [], "solr-indexing-failure"),
        ("org.apache.solr.client.solrj.SolrServerException: refused", [], "solr-query-failure"),
        ("KieModule build failed", [], "rule-engine-failure"),
        ("Business process order-process-123 failed", [], "business-process-failure"),
        ("de.hybris.platform.order.exceptions.CalculationException: cart", [], "checkout-failure"),
        ("Cloud hot folder file products.csv could not be processed", [], "hot-folder-failure"),
        ("Outbound sync of Product failed", [], "integration-api-failure"),
        ("java.net.SocketTimeoutException: Read timed out", [], "outbound-http-failure"),
        (
            "java.util.concurrent.RejectedExecutionException: queue full",
            [],
            "tomcat-thread-exhaustion",
        ),
        ("JGroups cluster view changed, member lost", [], "cluster-messaging"),
        ("Cronjob 'cleanup-cronJob' finished with result ERROR", [], "cronjob-failure"),
        ("ImpEx import finished with 3 unresolved lines", [], "impex-failure"),
        (
            "de.hybris.platform.media.exceptions.MediaStorageException: x",
            [],
            "media-storage-failure",
        ),
        (
            "de.hybris.platform.servicelayer.exceptions.ModelSavingException: x",
            [],
            "model-saving-failure",
        ),
        ("Item has been modified by another transaction", [], "concurrency-conflict"),
        (
            "de.hybris.platform.servicelayer.exceptions.UnknownIdentifierException: no product",
            [],
            "data-lookup-failure",
        ),
        ("InvalidTokenException: Invalid access token", [], "occ-auth-failure"),
        ("Request /occ/v2/electronics/products failed with 500", [], "occ-request-failure"),
        ("[gc] GC(12) Pause Full (Allocation Failure) 8123.456ms", [], "jvm-gc-pause"),
        ("cache region productCacheRegion is full", [], "cache-warning"),
    ],
)
def test_builtin_rules(engine: RuleEngine, message: str, stack: list[str], rule_id: str) -> None:
    result = engine.classify(make_record(message, stack=stack))
    assert result is not None
    assert result.rule_id == rule_id


def test_specific_rule_beats_generic(engine: RuleEngine) -> None:
    record = make_record(
        "FlexibleSearchException: query failed",
        stack=["Caused by: HikariPool-1 - Connection is not available, request timed out"],
    )
    result = engine.classify(record)
    assert result is not None
    assert result.rule_id == "db-connection-pool-exhausted"


def test_stack_frames_are_not_matched(engine: RuleEngine) -> None:
    record = make_record(
        "plain failure", stack=["\tat de.hybris.platform.solr.SolrServerException()"]
    )
    result = engine.classify(record)
    assert result is not None
    assert result.rule_id == UNCLASSIFIED_ID


@pytest.mark.parametrize(
    ("level", "severity"),
    [
        (LogLevel.FATAL, Severity.HIGH),
        (LogLevel.ERROR, Severity.MEDIUM),
        (LogLevel.WARN, Severity.LOW),
    ],
)
def test_unmatched_records_get_level_based_severity(
    engine: RuleEngine, level: LogLevel, severity: Severity
) -> None:
    result = engine.classify(make_record("something odd", level=level, exception_class="a.BError"))
    assert result is not None
    assert (result.rule_id, result.severity, result.title) == (
        UNCLASSIFIED_ID,
        severity,
        "a.BError",
    )


def test_unmatched_info_is_noise(engine: RuleEngine) -> None:
    assert engine.classify(make_record("all fine", level=LogLevel.INFO)) is None


def test_gc_rule_marks_any_level(engine: RuleEngine) -> None:
    result = engine.classify(make_record("Pause Full 9000ms", level=LogLevel.INFO))
    assert result is not None
    assert result.any_level


def test_logger_filter() -> None:
    engine = RuleEngine(
        [
            Rule(
                id="r",
                title="t",
                component="c",
                severity=Severity.LOW,
                patterns=["boom"],
                loggers=["MyLogger$"],
            )
        ]
    )
    assert engine.classify(make_record("boom", logger="x.MyLogger")) is not None
    result = engine.classify(make_record("boom", logger="Other"))
    assert result is not None and result.rule_id == UNCLASSIFIED_ID


def test_extra_rules_take_precedence(tmp_path: Path) -> None:
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n  - id: project-oom\n    title: Ours\n    component: Custom\n"
        "    severity: low\n    patterns: [OutOfMemoryError]\n"
    )
    result = RuleEngine.default(rules).classify(make_record("java.lang.OutOfMemoryError"))
    assert result is not None
    assert result.rule_id == "project-oom"


def test_duplicate_ids_rejected() -> None:
    rule = Rule(id="dup", title="t", component="c", severity=Severity.LOW, patterns=["x"])
    with pytest.raises(ValueError, match="dup"):
        RuleEngine([rule, rule])


def test_bad_rules_file(tmp_path: Path) -> None:
    rules = tmp_path / "rules.yaml"
    rules.write_text("- just a list\n")
    with pytest.raises(ValueError, match="rules"):
        RuleEngine.default(rules)


def test_builtin_rules_are_valid_and_unique() -> None:
    rules = load_default_rules()
    assert len(rules) >= 25
    assert len({r.id for r in rules}) == len(rules)
