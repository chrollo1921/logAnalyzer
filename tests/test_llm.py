from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import anthropic
import httpx2
import pytest

from sapcx_log_analyzer.config import Settings
from sapcx_log_analyzer.llm import (
    LLMAnalyzer,
    LLMError,
    LLMRefusalError,
    LLMTruncatedError,
    batch_clusters,
    cluster_payload,
)
from sapcx_log_analyzer.llm.anthropic_provider import FALLBACK_BETA, AnthropicProvider
from sapcx_log_analyzer.llm.schema import output_schema
from sapcx_log_analyzer.models import (
    Cluster,
    IncidentAnalysis,
    LogLevel,
    ReportMetadata,
    Severity,
)
from tests.conftest import FakeProvider, finding, responder_for_all_clusters

META = ReportMetadata(
    source="x.csv",
    generated_at="2026-10-20T10:00:00Z",
    total_records=10,
    analyzed_records=5,
)


def make_cluster(cid: str, samples: int = 1, size: int = 50) -> Cluster:
    return Cluster(
        id=cid,
        rule_id="r",
        component="c",
        title="t",
        severity=Severity.HIGH,
        level=LogLevel.ERROR,
        template="tmpl",
        count=3,
        samples=["s" * size] * samples,
    )


# --- schema -------------------------------------------------------------------------


def test_output_schema_is_strict_everywhere() -> None:
    schema = output_schema(IncidentAnalysis)

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            assert "title" not in node or not isinstance(node["title"], str)
            assert "default" not in node
            if node.get("type") == "object" and "properties" in node:
                assert node["additionalProperties"] is False
                assert set(node["required"]) == set(node["properties"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(schema)
    assert "Finding" in schema["$defs"]


# --- analyzer -----------------------------------------------------------------------


def test_batching_respects_budget_and_trims_huge_clusters() -> None:
    payloads = [cluster_payload(make_cluster(str(i), size=400)) for i in range(5)]
    one = len(json.dumps(payloads[0]))
    batches = batch_clusters(payloads, max_chars=2 * one + 10)
    assert [len(b) for b in batches] == [2, 2, 1]
    huge = cluster_payload(make_cluster("h", samples=3, size=2000))
    [[trimmed]] = batch_clusters([huge], max_chars=3000)  # 3 samples would not fit
    assert len(trimmed["samples"]) == 1


def test_single_batch_uses_one_call(fake_provider: FakeProvider, settings: Settings) -> None:
    clusters = [make_cluster("a"), make_cluster("b")]
    result = LLMAnalyzer(fake_provider, settings).analyze(clusters, META)
    assert len(fake_provider.calls) == 1
    call = fake_provider.calls[0]
    assert "SAP Commerce" in call["system"]
    assert '"id": "a"' in call["prompt"]
    assert "all the clusters" in call["prompt"]
    assert result.overall_severity is Severity.CRITICAL
    assert result.findings[0].cluster_ids == ["a", "b"]


def test_map_reduce_for_large_inputs(fake_provider: FakeProvider) -> None:
    settings = Settings(max_chars_per_batch=1500)
    clusters = [make_cluster(str(i), size=600) for i in range(4)]
    result = LLMAnalyzer(fake_provider, settings).analyze(clusters, META)
    assert len(fake_provider.calls) == 5  # four batches plus the summary
    assert "batch 1 of 4" in fake_provider.calls[0]["prompt"]
    assert "<findings>" in fake_provider.calls[-1]["prompt"]
    assert result.summary == "Overall summary."
    assert sorted(cid for f in result.findings for cid in f.cluster_ids) == ["0", "1", "2", "3"]


def test_cluster_limit(fake_provider: FakeProvider) -> None:
    settings = Settings(max_clusters_for_llm=2)
    clusters = [make_cluster(str(i)) for i in range(5)]
    LLMAnalyzer(fake_provider, settings).analyze(clusters, META)
    assert '"id": "2"' not in fake_provider.calls[0]["prompt"]


def test_no_clusters_needs_no_call(fake_provider: FakeProvider, settings: Settings) -> None:
    result = LLMAnalyzer(fake_provider, settings).analyze([], META)
    assert fake_provider.calls == []
    assert result.overall_severity is Severity.INFO


def test_invented_cluster_ids_are_dropped_and_confidence_clamped(settings: Settings) -> None:
    def responder(prompt: str, schema: dict[str, Any]) -> dict[str, Any]:
        good = finding(["a", "ghost"], title="good")
        good["confidence"] = 7
        return {
            "summary": "s",
            "overall_severity": "high",
            "top_priorities": [],
            "findings": [good, finding(["ghost"], title="made up")],
        }

    result = LLMAnalyzer(FakeProvider(responder), settings).analyze([make_cluster("a")], META)
    assert [f.title for f in result.findings] == ["good"]
    assert result.findings[0].cluster_ids == ["a"]
    assert result.findings[0].confidence == 1.0


def test_schema_mismatch_raises(settings: Settings) -> None:
    provider = FakeProvider(lambda prompt, schema: {"unexpected": True})
    with pytest.raises(LLMError, match="IncidentAnalysis"):
        LLMAnalyzer(provider, settings).analyze([make_cluster("a")], META)


def test_dry_run_prompts_match_real_prompts(settings: Settings) -> None:
    provider = FakeProvider(responder_for_all_clusters)
    analyzer = LLMAnalyzer(provider, settings)
    clusters = [make_cluster("a")]
    prompts = analyzer.build_prompts(clusters, META)
    analyzer.analyze(clusters, META)
    assert prompts == [provider.calls[0]["prompt"]]


# --- Anthropic provider -------------------------------------------------------------


class _Stream:
    def __init__(self, response: Any) -> None:
        self._response = response

    def __enter__(self) -> _Stream:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def get_final_message(self) -> Any:
        return self._response


class _FakeClient:
    def __init__(self, response: Any = None, error: Exception | None = None) -> None:
        self.kwargs: dict[str, Any] = {}
        self._response = response
        self._error = error
        self.beta = SimpleNamespace(messages=SimpleNamespace(stream=self._stream))

    def _stream(self, **kwargs: Any) -> _Stream:
        self.kwargs = kwargs
        if self._error:
            raise self._error
        return _Stream(self._response)


def _response(text: str, stop_reason: str = "end_turn", stop_details: Any = None) -> Any:
    return SimpleNamespace(
        model="claude-opus-5-5",
        stop_reason=stop_reason,
        stop_details=stop_details,
        usage=SimpleNamespace(input_tokens=10, output_tokens=5),
        content=[
            SimpleNamespace(type="thinking", thinking=""),
            SimpleNamespace(type="text", text=text),
        ],
    )


def test_provider_sends_structured_output_request() -> None:
    client = _FakeClient(_response(json.dumps({"ok": True})))
    settings = Settings(effort="xhigh", max_output_tokens=1234)
    provider = AnthropicProvider(settings, client=client)  # type: ignore[arg-type]
    result = provider.complete_json(system="sys", prompt="hello", schema={"type": "object"})
    assert result == {"ok": True}
    kwargs = client.kwargs
    assert kwargs["model"] == "claude-opus-5-5"
    assert kwargs["max_tokens"] == 1234
    assert kwargs["output_config"] == {
        "effort": "xhigh",
        "format": {"type": "json_schema", "schema": {"type": "object"}},
    }
    assert kwargs["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert kwargs["messages"] == [{"role": "user", "content": "hello"}]
    assert kwargs["betas"] == [FALLBACK_BETA]
    assert kwargs["fallbacks"] == "default"
    assert "temperature" not in kwargs
    assert provider.model_name == "claude-opus-5-5"


def test_provider_without_fallback() -> None:
    client = _FakeClient(_response("{}"))
    AnthropicProvider(Settings(use_refusal_fallback=False), client=client).complete_json(  # type: ignore[arg-type]
        system="s", prompt="p", schema={}
    )
    assert "fallbacks" not in client.kwargs
    assert "betas" not in client.kwargs


@pytest.mark.parametrize(
    ("response", "error", "message"),
    [
        (_response("{}", "refusal", SimpleNamespace(category="cyber")), LLMRefusalError, "cyber"),
        (_response('{"a":', "max_tokens"), LLMTruncatedError, "max_output_tokens"),
        (_response("not json"), LLMError, "invalid JSON"),
        (_response("[1]"), LLMError, "not an object"),
    ],
)
def test_provider_bad_responses(response: Any, error: type[Exception], message: str) -> None:
    provider = AnthropicProvider(Settings(), client=_FakeClient(response))  # type: ignore[arg-type]
    with pytest.raises(error, match=message):
        provider.complete_json(system="s", prompt="p", schema={})


_REQUEST = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")


def _status_error(cls: type[anthropic.APIStatusError], status: int) -> anthropic.APIStatusError:
    return cls("boom", response=httpx2.Response(status, request=_REQUEST), body=None)


@pytest.mark.parametrize(
    ("exc", "message"),
    [
        (_status_error(anthropic.AuthenticationError, 401), "ANTHROPIC_API_KEY"),
        (_status_error(anthropic.RateLimitError, 429), "Rate limited"),
        (_status_error(anthropic.InternalServerError, 500), "error 500"),
        (anthropic.APIConnectionError(request=_REQUEST), "Could not reach"),
    ],
)
def test_provider_api_errors(exc: Exception, message: str) -> None:
    provider = AnthropicProvider(Settings(), client=_FakeClient(error=exc))  # type: ignore[arg-type]
    with pytest.raises(LLMError, match=message):
        provider.complete_json(system="s", prompt="p", schema={})


def test_provider_builds_default_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    provider = AnthropicProvider(Settings(max_retries=5, request_timeout_seconds=12))
    assert provider._client.max_retries == 5
    assert provider._client.timeout == 12
