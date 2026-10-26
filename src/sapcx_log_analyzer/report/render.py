"""Render a Report as Markdown, JSON or self-contained HTML."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

from sapcx_log_analyzer.models import Report, Severity


class OutputFormat(StrEnum):
    MARKDOWN = "md"
    JSON = "json"
    HTML = "html"


def _dt(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S %Z").strip() if value else "-"


def _cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _environment() -> Environment:
    env = Environment(
        loader=PackageLoader("sapcx_log_analyzer.report", "templates"),
        # HTML templates are escaped; Markdown output is plain text.
        autoescape=select_autoescape(enabled_extensions=("html.j2",), default=False),
        undefined=StrictUndefined,
        trim_blocks=False,
        lstrip_blocks=False,
        keep_trailing_newline=True,
    )
    env.filters["dt"] = _dt
    env.filters["cell"] = _cell
    return env


def _context(report: Report) -> dict[str, Any]:
    counts = {c.id: c.count for c in report.clusters}
    minutes = report.metadata.extra.get("timeline_bucket_minutes")
    return {
        "m": report.metadata,
        "a": report.analysis,
        "clusters": report.clusters,
        "timeline": report.timeline,
        "S": Severity,
        "bucket_label": f"{minutes}-minute buckets" if minutes else "time buckets",
        "event_count": counts,
    }


def render(report: Report, fmt: OutputFormat) -> str:
    if fmt is OutputFormat.JSON:
        return report.model_dump_json(indent=2) + "\n"
    env = _environment()
    context = _context(report)
    counts: dict[str, int] = context["event_count"]
    env.filters["event_count"] = lambda cid: counts.get(cid, 0)
    name = "report.html.j2" if fmt is OutputFormat.HTML else "report.md.j2"
    return env.get_template(name).render(**context)
