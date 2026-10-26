"""Regenerate the synthetic Dynatrace exports used by the tests.

Run with ``python tests/fixtures/make_fixtures.py``. All data is invented; nothing
here comes from a real system.
"""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

HERE = Path(__file__).parent
T0 = datetime(2026, 10, 20, 9, 0, 0, tzinfo=UTC)

API_PODS = ["api-7d9f8c6b5-abcde", "api-7d9f8c6b5-fghij"]
BG_POD = "backgroundprocessing-5c6b7d8e9-klmno"
BO_POD = "backoffice-6f7a8b9c0-pqrst"


def ts(minutes: float) -> str:
    return (T0 + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def row(minutes: float, status: str, content: str, pod: str) -> dict[str, str]:
    return {
        "timestamp": ts(minutes),
        "status": status,
        "content": content,
        "k8s.pod.name": pod,
        "k8s.container.name": "platform",
        "dt.entity.cloud_application": "CLOUD_APPLICATION-1234ABCD",
    }


def csv_rows() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    # Background noise that should be ignored.
    for i in range(20):
        rows.append(
            row(
                i,
                "INFO",
                f"INFO  [hybrisHTTP{i}] [DefaultCartFacade] Cart 0000{i} updated",
                API_PODS[i % 2],
            )
        )
    rows.append(
        row(
            1,
            "INFO",
            "INFO  [TaskExecutor-1] [IntegrationApiController] integrationservices request done",
            API_PODS[0],
        )
    )
    rows.append(
        row(2, "INFO", "INFO  [cronJob] [CronJobManager] Cronjob 'cleanup-cronJob' started", BG_POD)
    )

    # 1. Database pool exhaustion on both API pods, with multi-line stack traces.
    for i in range(12):
        rows.append(
            row(
                10 + i * 0.5,
                "ERROR",
                f"ERROR [hybrisHTTP{30 + i}] [10.2.3.{i}] [DefaultProductService] Could not load product PK 87960930{54980 + i}\n"
                "org.springframework.jdbc.CannotGetJdbcConnectionException: Failed to obtain JDBC Connection\n"
                "\tat org.springframework.jdbc.datasource.DataSourceUtils.getConnection(DataSourceUtils.java:84)\n"
                "\tat de.hybris.platform.jdbcwrapper.HybrisDataSource.getConnection(HybrisDataSource.java:120)\n"
                "\tat de.hybris.platform.product.impl.DefaultProductService.getProductForCode(DefaultProductService.java:61)\n"
                "Caused by: java.sql.SQLTransientConnectionException: HikariPool-1 - Connection is not available, request timed out after 30000ms.\n"
                "\tat com.zaxxer.hikari.pool.HikariPool.createTimeoutException(HikariPool.java:696)",
                API_PODS[i % 2],
            )
        )

    # 2. OCC errors carrying an email and a bearer token, to exercise redaction.
    for i in range(6):
        rows.append(
            row(
                11 + i,
                "WARN",
                f"WARN  [hybrisHTTP{40 + i}] [DefaultWebserviceErrorHandler] Request /occ/v2/electronics/users/jane.doe{i}@example.com/carts/0001234{i} failed with 500",
                API_PODS[i % 2],
            )
        )
    for i in range(5):
        rows.append(
            row(
                12 + i,
                "WARN",
                f"WARN  [hybrisHTTP{50 + i}] [OAuth2ExceptionHandler] InvalidTokenException: Invalid access token, Authorization: Bearer abcDEF123456ghiJKL{i}",
                API_PODS[0],
            )
        )

    # 3. Solr indexing failure on background processing.
    rows.append(
        row(
            15,
            "ERROR",
            "ERROR [solrIndexer-thread-1] [DefaultIndexerService] Error while indexing electronicsIndex\n"
            "de.hybris.platform.solrfacetsearch.indexer.exceptions.IndexerException: indexer operation failed\n"
            "\tat de.hybris.platform.solrfacetsearch.indexer.impl.DefaultIndexer.indexItems(DefaultIndexer.java:120)\n"
            "Caused by: org.apache.solr.client.solrj.SolrServerException: Server refused connection at: http://solr-master:8983/solr/master_electronics_Product",
            BG_POD,
        )
    )
    rows.append(
        row(
            15.2,
            "ERROR",
            "ERROR [cronJob] [CronJobManager] Cronjob 'full-electronicsIndex-cronJob' finished with result ERROR",
            BG_POD,
        )
    )

    # 4. OutOfMemoryError printed to stdout and exported as one record per line.
    rows.append(
        row(
            20,
            "NONE",
            'Exception in thread "TaskExecutor-3" java.lang.OutOfMemoryError: Java heap space',
            BG_POD,
        )
    )
    rows.append(row(20, "NONE", "\tat java.util.Arrays.copyOf(Arrays.java:3512)", BG_POD))
    rows.append(
        row(
            20,
            "NONE",
            "\tat de.hybris.platform.impex.jalo.imp.DefaultImportProcessor.processItemData(DefaultImportProcessor.java:200)",
            BG_POD,
        )
    )

    # 5. Long full GC pause logged at INFO, which a rule pulls in anyway.
    rows.append(
        row(
            19.5,
            "INFO",
            "[gc] GC(1234) Pause Full (Allocation Failure) 3900M->3850M(4096M) 8123.456ms",
            BG_POD,
        )
    )

    # 6. ImpEx failure with a password in the line, to exercise redaction.
    rows.append(
        row(
            25,
            "WARN",
            "WARN  [ImpExImportJob] [ImportProcessor] ImpEx import finished with 3 unresolved lines; connection jdbc:sqlserver://db;user=hybris;password=S3cr3tPass",
            BO_POD,
        )
    )
    return rows


def json_records() -> list[dict[str, str]]:
    def layout(
        minutes: float,
        level: str,
        logger: str,
        message: str,
        thrown: dict[str, object] | None = None,
    ) -> str:
        instant = T0 + timedelta(minutes=minutes)
        doc: dict[str, object] = {
            "instant": {"epochSecond": int(instant.timestamp()), "nanoOfSecond": 0},
            "thread": "hybrisHTTP7",
            "level": level,
            "loggerName": logger,
            "message": message,
            "endOfBatch": False,
            "loggerFqcn": "org.apache.logging.log4j.spi.AbstractLogger",
        }
        if thrown:
            doc["thrown"] = thrown
        return json.dumps(doc)

    records = []
    for i in range(4):
        records.append(
            {
                "timestamp": ts(30 + i),
                "loglevel": "ERROR",
                "content": layout(
                    30 + i,
                    "ERROR",
                    "de.hybris.platform.ruleengine.impl.DefaultPlatformRuleEngineService",
                    f"Rule engine module promotions-module failed to initialize, version {100 + i}",
                    {
                        "name": "de.hybris.platform.ruleengine.exception.RuleEngineRuntimeException",
                        "message": "KieModule build failed",
                        "extendedStackTrace": [
                            {
                                "class": "de.hybris.platform.ruleengine.impl.DefaultPlatformRuleEngineService",
                                "method": "initialize",
                                "file": "DefaultPlatformRuleEngineService.java",
                                "line": 210,
                            }
                        ],
                        "cause": {
                            "name": "java.lang.IllegalStateException",
                            "message": "Duplicate rule code",
                        },
                    },
                ),
                "k8s.pod.name": BG_POD,
                "k8s.container.name": "platform",
            }
        )
    records.append(
        {
            "timestamp": ts(31),
            "loglevel": "INFO",
            "content": layout(
                31,
                "INFO",
                "de.hybris.platform.servicelayer.internal.ServiceLayerFacade",
                "Startup complete",
            ),
            "k8s.pod.name": API_PODS[0],
            "k8s.container.name": "platform",
        }
    )
    records.append(
        {
            "timestamp": ts(32),
            "loglevel": "ERROR",
            "content": layout(
                32,
                "ERROR",
                "de.hybris.platform.commerceservices.order.impl.DefaultCommerceCheckoutService",
                "Failed to place order for user <customer>",
                {
                    "name": "de.hybris.platform.order.exceptions.CalculationException",
                    "message": "Could not calculate cart",
                },
            ),
            "k8s.pod.name": API_PODS[1],
            "k8s.container.name": "platform",
        }
    )
    return records


def main() -> None:
    rows = csv_rows()
    with (HERE / "dynatrace_export.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    (HERE / "dynatrace_grail.json").write_text(
        json.dumps({"result": {"records": json_records()}}, indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
