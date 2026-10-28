from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sapcx_log_analyzer import __version__, cli, config
from sapcx_log_analyzer.config import Settings, load_env_file, load_settings
from sapcx_log_analyzer.llm import LLMError
from sapcx_log_analyzer.models import LogLevel
from tests.conftest import FakeProvider, responder_for_all_clusters

runner = CliRunner()


@pytest.fixture
def provider(monkeypatch: pytest.MonkeyPatch) -> FakeProvider:
    fake = FakeProvider(responder_for_all_clusters)
    monkeypatch.setattr(cli, "build_provider", lambda settings: fake)
    return fake


def test_version() -> None:
    result = runner.invoke(cli.app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_analyze_no_llm_to_stdout(csv_export: Path, provider: FakeProvider) -> None:
    result = runner.invoke(cli.app, ["analyze", str(csv_export), "--no-llm"])
    assert result.exit_code == 0, result.output
    assert "# SAP Commerce log analysis" in result.output
    assert provider.calls == []


def test_analyze_with_llm_to_file(tmp_path: Path, csv_export: Path, provider: FakeProvider) -> None:
    out = tmp_path / "reports" / "r.json"
    result = runner.invoke(
        cli.app, ["-v", "analyze", str(csv_export), "-f", "json", "-o", str(out), "--model", "m1"]
    )
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text())
    assert data["metadata"]["llm_used"] is True
    assert data["analysis"]["overall_severity"] == "critical"
    assert len(provider.calls) == 1


def test_dry_run_prints_prompt_and_calls_nothing(csv_export: Path, provider: FakeProvider) -> None:
    result = runner.invoke(cli.app, ["analyze", str(csv_export), "--dry-run"])
    assert result.exit_code == 0, result.output
    assert "===== request 1 of 1" in result.output
    assert "<clusters>" in result.output
    assert "jane.doe" not in result.output
    assert provider.calls == []


def test_llm_failure_exit_code(csv_export: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def failing(prompt: str, schema: dict[str, object]) -> dict[str, object]:
        raise LLMError("nope")

    monkeypatch.setattr(cli, "build_provider", lambda settings: FakeProvider(failing))
    result = runner.invoke(cli.app, ["analyze", str(csv_export)])
    assert result.exit_code == cli.EXIT_LLM_ERROR
    assert "--no-llm" in result.output


def test_bad_input_exit_code(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("[\n{")
    result = runner.invoke(cli.app, ["analyze", str(bad), "--no-llm"])
    assert result.exit_code == cli.EXIT_INPUT_ERROR
    assert "Not valid JSON" in result.output


def test_bad_effort(csv_export: Path) -> None:
    result = runner.invoke(cli.app, ["analyze", str(csv_export), "--effort", "huge"])
    assert result.exit_code != 0


def test_rules_command(tmp_path: Path) -> None:
    result = runner.invoke(cli.app, ["rules"])
    assert result.exit_code == 0
    assert "db-connection-pool-exhausted" in result.output
    broken = tmp_path / "rules.yaml"
    broken.write_text("nope: 1\n")
    result = runner.invoke(cli.app, ["rules", "--rules-file", str(broken)])
    assert result.exit_code == cli.EXIT_INPUT_ERROR


def test_build_provider_returns_anthropic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    provider = cli.build_provider(Settings())
    assert provider.model_name == "claude-opus-5-5"


# --- config -------------------------------------------------------------------------


def test_env_file_fills_unset_variables_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = tmp_path / ".env"
    env.write_text("SAPCX_LA_MODEL=from-env-file\nSAPCX_LA_EFFORT=low\n")
    monkeypatch.setenv("SAPCX_LA_EFFORT", "max")
    monkeypatch.setenv("SAPCX_LA_MODEL", "placeholder")  # so teardown removes the loaded value
    monkeypatch.delenv("SAPCX_LA_MODEL")
    assert load_env_file(env) is True
    settings = load_settings()
    assert (settings.model, settings.effort) == ("from-env-file", "max")


def test_env_file_default_is_optional(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert load_env_file() is False
    with pytest.raises(FileNotFoundError):
        load_env_file(tmp_path / "missing.env")


def test_cli_reads_env_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "load_env_file", config.load_env_file)
    env = tmp_path / "litellm.env"
    env.write_text("LITELLM_BASE_URL=https://proxy.example.com\n")
    monkeypatch.setenv("LITELLM_BASE_URL", "placeholder")
    monkeypatch.delenv("LITELLM_BASE_URL")
    result = runner.invoke(cli.app, ["--env-file", str(env), "rules"])
    assert result.exit_code == 0
    assert os.environ["LITELLM_BASE_URL"] == "https://proxy.example.com"
    missing = runner.invoke(cli.app, ["--env-file", str(tmp_path / "nope.env"), "rules"])
    assert missing.exit_code == cli.EXIT_INPUT_ERROR


def test_settings_precedence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "config.yaml"
    config.write_text(
        "model: from-file\neffort: low\nmin_level: ERROR\n"
        "extra_redaction_patterns:\n  - {name: cust, pattern: 'C-\\d+', replacement: '<C>'}\n"
    )
    settings = load_settings(config)
    assert (settings.model, settings.effort, settings.min_level) == (
        "from-file",
        "low",
        LogLevel.ERROR,
    )
    assert settings.extra_redaction_patterns[0].name == "cust"

    monkeypatch.setenv("SAPCX_LA_EFFORT", "max")
    settings = load_settings(config)
    assert settings.effort == "max"  # env beats file

    settings = load_settings(config, effort="medium", model=None)
    assert settings.effort == "medium"  # explicit override beats env
    assert settings.model == "from-file"  # None overrides are ignored


def test_settings_defaults() -> None:
    settings = load_settings()
    assert settings.model == "claude-opus-5-5"
    assert settings.use_refusal_fallback


def test_config_must_be_mapping(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("- a\n")
    with pytest.raises(ValueError, match="mapping"):
        load_settings(config)
