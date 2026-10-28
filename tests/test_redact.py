from __future__ import annotations

import re

import pytest

from sapcx_log_analyzer.config import RedactionPattern
from sapcx_log_analyzer.redact import Redactor
from sapcx_log_analyzer.redact.redactor import luhn_valid
from tests.conftest import make_record


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Authorization: Bearer abcDEF123456ghiJKL", "Authorization: Bearer <TOKEN>"),
        ("access_token=abcdefgh12345678&x=1", "access_token=<TOKEN>&x=1"),
        (
            "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlXzEyMw",
            "token <JWT>",
        ),
        ("https://admin:hunter2@host/path", "https://<USER>:<PASSWORD>@host/path"),
        (
            "jdbc:sqlserver://db;user=hybris;password=S3cr3t;x=1",
            "jdbc:sqlserver://db;user=hybris;password=<SECRET>;x=1",
        ),
        ('{"client_secret": "abc123"}', '{"client_secret": "<SECRET>"}'),
        ("from 10.1.2.3 to 192.168.0.1", "from <IP> to <IP>"),
        ("card 4111 1111 1111 1111 used", "card <CARD> used"),
    ],
)
def test_default_patterns(text: str, expected: str) -> None:
    assert Redactor().redact(text) == expected


def test_sap_pks_and_non_luhn_numbers_are_kept() -> None:
    text = "PK 8796093054980 order 1234567890123456"
    assert Redactor().redact(text) == text


def test_luhn() -> None:
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")


def test_counts_and_extra_patterns() -> None:
    redactor = Redactor(
        [RedactionPattern(name="customer_id", pattern=r"CUST-\d+", replacement="<CUSTOMER>")]
    )
    redacted = redactor.redact("CUST-42 and a@b.io and c@d.io")
    assert re.fullmatch(r"<CUSTOMER> and <EMAIL#[0-9a-f]{8}> and <EMAIL#[0-9a-f]{8}>", redacted)
    assert redactor.counts == {"customer_id": 1, "email": 2}


def test_redact_record_covers_message_stack_and_thread() -> None:
    record = make_record(
        "login failed for a@b.io",
        thread="hybrisHTTP1 a@b.io",
        stack=["x.YException: user c@d.io"],
    )
    redactor = Redactor()
    redacted = redactor.redact_record(record)
    token = redactor.link_token("EMAIL", "a@b.io")
    assert redacted.message == f"login failed for {token}"
    assert redacted.thread == f"hybrisHTTP1 {token}"
    assert redacted.stack == [f"x.YException: user {redactor.link_token('EMAIL', 'c@d.io')}"]
    assert record.message == "login failed for a@b.io"  # original untouched


def test_session_ids_become_stable_link_tokens() -> None:
    redactor = Redactor()
    first = redactor.redact("JSESSIONID=ABCDEF1234567890 then sessionId:ABCDEF1234567890")
    other = redactor.redact("JSESSIONID=ZZZZZZ1234567890")
    tokens = re.findall(r"<SESSION#[0-9a-f]{8}>", first)
    assert len(tokens) == 2 and tokens[0] == tokens[1]
    assert first.startswith("JSESSIONID=<SESSION#")
    assert "ABCDEF" not in first
    assert tokens[0] not in other
    assert redactor.counts["session_id"] == 3
    # A different run (salt) produces different tokens for the same value.
    assert tokens[0] not in Redactor().redact("JSESSIONID=ABCDEF1234567890")


def test_link_pattern_without_value_group_is_rejected() -> None:
    with pytest.raises(ValueError, match="value"):
        Redactor([RedactionPattern(name="bad", pattern=r"X-\d+", link_label="X")])


def test_redact_record_covers_context() -> None:
    record = make_record(
        "checkout failed",
        context={"trace_id": "4bf92f3577b34da6", "sessionId": "s3cr3tsession", "user": "a@b.io"},
    )
    redactor = Redactor()
    redacted = redactor.redact_record(record)
    assert redacted.context["trace_id"] == "4bf92f3577b34da6"
    assert redacted.context["sessionId"] == redactor.link_token("SESSION", "s3cr3tsession")
    assert redacted.context["user"] == redactor.link_token("EMAIL", "A@B.io")


def test_emails_become_case_insensitive_link_tokens() -> None:
    redactor = Redactor()
    text = redactor.redact("user Jane.Doe@Example.com logged in, then jane.doe@example.com paid")
    tokens = re.findall(r"<EMAIL#[0-9a-f]{8}>", text)
    assert len(tokens) == 2 and tokens[0] == tokens[1]
    assert "jane" not in text.lower()


def test_hints_skip_patterns_that_cannot_match() -> None:
    redactor = Redactor(
        [RedactionPattern(name="x", pattern=r"secretword", replacement="<X>", hints=["never"])]
    )
    assert redactor.redact("secretword") == "secretword"
