"""Runtime settings.

Precedence, highest first: explicit overrides (CLI flags), environment variables
prefixed ``SAPCX_LA_``, a YAML config file, then the defaults below. The Anthropic
API key is never part of these settings: the SDK reads ``ANTHROPIC_API_KEY`` itself.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import (
    BaseSettings,
    InitSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

from sapcx_log_analyzer.models import LogLevel

Effort = Literal["low", "medium", "high", "xhigh", "max"]


class RedactionPattern(BaseModel):
    name: str
    pattern: str
    replacement: str = ""
    luhn: bool = False  # only replace digit runs that pass the Luhn check
    # Replace the pattern's ``value`` group with a stable token such as ``<SESSION#1a2b3c4d>``
    # instead of ``replacement``, so redacted lines can still be linked to each other.
    link_label: str | None = None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SAPCX_LA_", extra="ignore")

    # LLM
    model: str = "claude-opus-5-5"
    effort: Effort = "high"
    max_output_tokens: int = Field(default=16000, gt=0)
    request_timeout_seconds: float = Field(default=300.0, gt=0)
    max_retries: int = Field(default=3, ge=0)
    use_refusal_fallback: bool = True

    # Token budget, approximated as characters (about 4 per token).
    max_chars_per_batch: int = Field(default=80_000, gt=1000)
    max_clusters_for_llm: int = Field(default=150, gt=0)

    # Pre-processing
    min_level: LogLevel = LogLevel.WARN
    samples_per_cluster: int = Field(default=3, ge=1, le=20)
    max_sample_chars: int = Field(default=1500, gt=100)
    top_frames_per_cluster: int = Field(default=8, ge=0)
    timeline_bucket_minutes: int = Field(default=5, gt=0)

    # Interactive questions (`ask` and `serve`)
    ask_effort: Effort = "medium"
    ask_max_tool_rounds: int = Field(default=12, ge=1, le=50)
    ask_max_tool_result_chars: int = Field(default=24_000, gt=1000)

    # Extensibility
    extra_rules_file: Path | None = None
    extra_redaction_patterns: list[RedactionPattern] = Field(default_factory=list)


def load_settings(config_file: Path | None = None, **overrides: Any) -> Settings:
    """Build settings from defaults, an optional YAML file, env vars and overrides."""
    file_values: dict[str, Any] = {}
    if config_file is not None:
        loaded = yaml.safe_load(config_file.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            raise ValueError(f"Config file {config_file} must contain a mapping")
        file_values = loaded

    class _FileBackedSettings(Settings):
        @classmethod
        def settings_customise_sources(
            cls,
            settings_cls: type[BaseSettings],
            init_settings: PydanticBaseSettingsSource,
            env_settings: PydanticBaseSettingsSource,
            dotenv_settings: PydanticBaseSettingsSource,
            file_secret_settings: PydanticBaseSettingsSource,
        ) -> tuple[PydanticBaseSettingsSource, ...]:
            return (
                init_settings,
                env_settings,
                InitSettingsSource(settings_cls, init_kwargs=file_values),
            )

    clean = {k: v for k, v in overrides.items() if v is not None}
    return _FileBackedSettings(**clean)
