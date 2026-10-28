"""The synthetic demo export and the questions it was built for: users, accounts, APIs."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sapcx_log_analyzer import cli
from sapcx_log_analyzer.ask import AskSession, LogStore
from sapcx_log_analyzer.ask.http import HttpCall, http_call
from sapcx_log_analyzer.ask.identifiers import identifiers_in
from sapcx_log_analyzer.ask.tools import describe_call, run_tool
from sapcx_log_analyzer.classify import RuleEngine
from sapcx_log_analyzer.config import Settings
from sapcx_log_analyzer.demo import _Generator, write_demo_export
from sapcx_log_analyzer.models import LogLevel
from tests.conftest import ScriptedChatProvider, make_record, text_turn, tool_turn

SEED = 7
CUSTOMER_23DSFD = _Generator(SEED).customers[0]


@pytest.fixture(scope="module")
def demo_file(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("demo") / "demo.json"
    write_demo_export(path, size_mb=0.5, seed=SEED)
    return path


@pytest.fixture(scope="module")
def store(demo_file: Path) -> LogStore:
    return LogStore.load(demo_file, Settings())


def tool(store: LogStore, name: str, args: dict[str, object]) -> str:
    return run_tool(store, name, args, 50_000)


# --- HTTP requests in log lines ------------------------------------------------------


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        (
            '10.0.0.1 - - [20/Oct/2026:08:00:03 +0000] "GET /occ/v2/site/products/1?fields=FULL '
            'HTTP/1.1" 200 5988 280ms',
            HttpCall("GET", "/occ/v2/site/products/1", 200, 280, access_log=True),
        ),
        (
            '10.0.0.1 - - [20/Oct/2026:08:00:03 +0000] "POST /authorizationserver/oauth/token '
            'HTTP/1.1" 401 -',
            HttpCall("POST", "/authorizationserver/oauth/token", 401, None, access_log=True),
        ),
        (
            "Request PUT /occ/v2/site/users/current/carts/0001/deliverymode failed with 503",
            HttpCall("PUT", "/occ/v2/site/users/current/carts/0001/deliverymode", 503),
        ),
        ("GET /occ/v2/site/products/1 took a while", None),
    ],
)
def test_http_call(message: str, expected: HttpCall | None) -> None:
    assert http_call(make_record(message)) == expected


def test_endpoint_replaces_ids_but_keeps_the_api_version() -> None:
    path = "/occ/v2/electronics/users/<EMAIL#1a2b3c4d>/carts/00087123/entries"
    assert HttpCall("POST", path, 200).endpoint == (
        "/occ/v2/electronics/users/{id}/carts/{id}/entries"
    )
    call = HttpCall("GET", "/occ/v2/electronics/cart/323232/getDelivery", 504)
    assert call.endpoint == "/occ/v2/electronics/cart/{id}/getDelivery"


def test_user_and_account_identifiers() -> None:
    record = make_record(
        "Customer <EMAIL#1a2b3c4d> logged in, customerId 23dsfd, b2bUnitId=1234",
        context={"userId": "88kq2m", "b2bUnitId": "1234", "RemoteAddr": "<IP>"},
    )
    found = {i.value: i.kind for i in identifiers_in(record)}
    assert found == {
        "88kq2m": "user",
        "1234": "account",
        "<EMAIL#1a2b3c4d>": "user",
        "23dsfd": "user",
    }


def test_classify_below_min_level_only_checks_any_level_rules() -> None:
    engine = RuleEngine.default()
    hikari = make_record("HikariPool-1 - Connection is not available", level=LogLevel.INFO)
    assert engine.classify(hikari) is not None
    assert engine.classify(hikari, LogLevel.WARN) is None
    gc = make_record("Pause Full (Allocation Failure) 9123.456ms", level=LogLevel.INFO)
    classification = engine.classify(gc, LogLevel.WARN)
    assert classification is not None and classification.any_level
    error = make_record("something odd", level=LogLevel.ERROR)
    assert engine.classify(error, LogLevel.WARN) is not None


# --- the demo export ----------------------------------------------------------------


def test_demo_export_size_and_shape(demo_file: Path, store: LogStore) -> None:
    assert 0.4 < demo_file.stat().st_size / 1_048_576 < 0.6
    overview = store.overview()
    assert overview["aspects"] == ["api", "backgroundprocessing", "backoffice"]
    kinds = overview["identifiers_by_kind"]
    assert isinstance(kinds, dict)
    assert {"user", "account", "session", "trace", "cart"} <= kinds.keys()
    rules = {issue.cluster.rule_id for issue in store.issues()}
    assert {"db-connection-pool-exhausted", "solr-indexing-failure"} <= rules


def test_which_apis_did_account_1234_hit(store: LogStore) -> None:
    text = tool(store, "list_api_calls", {"identifier": "1234"})
    assert "GET /occ/v2/powertools/costcenters: 1 (403x1" in text
    assert "POST /occ/v2/powertools/users/current/orders: 1 (201x1" in text
    found = tool(store, "find_identifier", {"value": "1234"})
    assert "B2BOrderThresholdPermission" in found
    assert "user:b2b7x1" in found and "user:b2b7x2" in found


def test_why_did_the_transaction_fail_for_user_23dsfd(store: LogStore) -> None:
    text = tool(store, "list_api_calls", {"identifier": "23dsfd", "min_status": 400})
    # The application's "Request ... failed with 502" lines are folded into the access log.
    assert text.startswith("3 request(s) for '23dsfd', 2 endpoint(s):")
    assert "paymentdetails: 2 (502x2, max 20000 ms)" in text
    assert "POST /occ/v2/electronics/users/current/orders: 1 (400x1" in text
    refs = [int(r) for r in re.findall(r"^#(\d+) ", text, re.MULTILINE)]
    context = tool(store, "get_context", {"record": refs[0], "window_seconds": 25})
    assert "Caused by: java.net.SocketTimeoutException: Read timed out" in context


def test_reason_for_get_delivery_failure(store: LogStore) -> None:
    text = tool(store, "list_api_calls", {"path": "/cart/323232/getDelivery"})
    assert "GET /occ/v2/electronics/cart/{id}/getDelivery: 3 (504x3, max 10050 ms)" in text
    found = tool(store, "find_identifier", {"value": "/cart/323232/getDelivery"})
    assert "(as text)" in found
    assert "Carrier rate lookup failed" in found


def test_what_happened_in_a_session(store: LogStore) -> None:
    raw = CUSTOMER_23DSFD.sessions[0]
    question = store.redact_question(f"What happened in session {raw}? Not 0123456789abcdef.")
    assert raw not in question and "0123456789abcdef" in question
    token = re.findall(r"<SESSION#[0-9a-f]{8}>", question)[0]
    text = tool(store, "list_api_calls", {"identifier": token})
    assert "POST /authorizationserver/oauth/token" in text
    assert "paymentdetails: 2 (502x2" in text


def test_email_leads_to_the_user_id(store: LogStore) -> None:
    question = store.redact_question(f"What did {CUSTOMER_23DSFD.email.upper()} do?")
    assert "@" not in question
    token = re.findall(r"<EMAIL#[0-9a-f]{8}>", question)[0]
    found = tool(store, "find_identifier", {"value": token})
    assert "logged in, customerId 23dsfd" in found and "user:23dsfd" in found


def test_api_calls_filters_and_misses(store: LogStore) -> None:
    unknown = tool(store, "list_api_calls", {"identifier": "<EMAIL#00000000>"})
    assert unknown.startswith("No record mentions '<EMAIL#00000000>'. This export covers ")
    assert "Similar identifiers" not in unknown
    assert store.suggest("<SESSION#00000000>") == []
    none = tool(store, "list_api_calls", {"path": "/nothing/here"})
    assert none == "No HTTP requests match."
    errors = tool(store, "list_api_calls", {"min_status": 500, "limit": 2})
    assert "showing 2" in errors
    early = tool(
        store,
        "list_api_calls",
        {"start": "2026-10-20T08:00:00Z", "end": "2026-10-20T08:00:01Z"},
    )
    assert early.startswith("No HTTP requests match.\nThe requested time window is outside")
    assert describe_call("list_api_calls", {"identifier": "1234"}) == (
        "Listing the API calls of 1234"
    )
    assert describe_call("list_api_calls", {"path": "/x"}) == "Listing calls to /x"
    assert describe_call("list_api_calls", {}) == "Listing API calls"


def test_suggestions_are_ids_of_about_the_same_length(store: LogStore) -> None:
    # Trace ids that happen to contain "9999" are not near misses of a short id.
    assert all(len(s) <= 9 for s in store.suggest("99zz99"))
    assert "23dsfd" in store.suggest("23dsfe")
    missing = tool(store, "list_api_calls", {"identifier": "99zz99"})
    assert missing.startswith("No record mentions '99zz99'. This export covers ")


def test_chat_over_the_demo_export(store: LogStore) -> None:
    provider = ScriptedChatProvider(
        [
            tool_turn(("list_api_calls", {"identifier": "23dsfd"})),
            text_turn("Payment authorization timed out twice, so the order was rejected."),
        ]
    )
    session = AskSession(store, provider, Settings())
    answer = session.ask(f"Why did the order fail for {CUSTOMER_23DSFD.email}?")
    assert answer.complete
    question = provider.requests[0]["messages"][0]["content"]
    assert CUSTOMER_23DSFD.email not in str(question) and "<EMAIL#" in str(question)
    assert "list_api_calls" in {t["name"] for t in provider.requests[0]["tools"]}
    result = provider.requests[1]["messages"][-1]["content"][0]["content"]
    assert "paymentdetails: 2 (502x2" in result


def test_demo_export_command(tmp_path: Path) -> None:
    out = tmp_path / "demo.json"
    runner = CliRunner()
    result = runner.invoke(cli.app, ["demo-export", str(out), "--size-mb", "0.2"])
    assert result.exit_code == 0, result.output
    assert "records" in result.output and out.exists()
    report = runner.invoke(cli.app, ["analyze", str(out), "--no-llm"])
    assert report.exit_code == 0
    assert "Database connection pool exhausted" in report.output
