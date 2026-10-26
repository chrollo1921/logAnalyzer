"""Opt-in smoke test against the real Anthropic API.

Run with ``SAPCX_LA_LIVE_TESTS=1 ANTHROPIC_API_KEY=... pytest -m live``. It sends the
redacted clusters of the synthetic fixture export, never real data.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from sapcx_log_analyzer.config import Settings
from sapcx_log_analyzer.llm.anthropic_provider import AnthropicProvider
from sapcx_log_analyzer.pipeline import analyze

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("SAPCX_LA_LIVE_TESTS") != "1", reason="set SAPCX_LA_LIVE_TESTS=1 to run"
    ),
]


def test_real_model_analyses_fixture(csv_export: Path) -> None:
    settings = Settings(effort="low")
    report = analyze(csv_export, settings, AnthropicProvider(settings))
    assert report.analysis is not None
    assert report.analysis.findings
    covered = {cid for f in report.analysis.findings for cid in f.cluster_ids}
    assert covered <= {c.id for c in report.clusters}
