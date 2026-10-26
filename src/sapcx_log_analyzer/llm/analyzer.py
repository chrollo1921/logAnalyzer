"""Sends clusters to the LLM and turns the answers into an IncidentAnalysis.

Small inputs go out in one request. Larger inputs use map-reduce: each batch of
clusters is analysed on its own, then one more request writes the overall summary
from the batch findings.
"""

from __future__ import annotations

import json
import logging
from importlib import resources
from typing import Any

from pydantic import BaseModel, ValidationError

from sapcx_log_analyzer.config import Settings
from sapcx_log_analyzer.llm.provider import LLMError, LLMProvider
from sapcx_log_analyzer.llm.schema import output_schema
from sapcx_log_analyzer.models import (
    BatchFindings,
    Cluster,
    Finding,
    IncidentAnalysis,
    IncidentSummary,
    ReportMetadata,
    Severity,
)

log = logging.getLogger(__name__)


def system_prompt() -> str:
    return (
        resources.files("sapcx_log_analyzer.llm")
        .joinpath("prompts/system.md")
        .read_text(encoding="utf-8")
    )


def cluster_payload(cluster: Cluster) -> dict[str, Any]:
    """The subset of a cluster the model needs, in a compact, stable shape."""
    return {
        "id": cluster.id,
        "rule_id": cluster.rule_id,
        "component": cluster.component,
        "severity": cluster.severity.value,
        "level": cluster.level.value,
        "logger": cluster.logger,
        "exception_class": cluster.exception_class,
        "root_cause_class": cluster.root_cause_class,
        "template": cluster.template,
        "count": cluster.count,
        "first_seen": cluster.first_seen.isoformat() if cluster.first_seen else None,
        "last_seen": cluster.last_seen.isoformat() if cluster.last_seen else None,
        "aspects": cluster.aspects,
        "pods": cluster.pods[:10],
        "top_frames": cluster.top_frames,
        "samples": cluster.samples,
    }


def _metadata_payload(metadata: ReportMetadata) -> dict[str, Any]:
    return {
        "source": metadata.source,
        "total_records": metadata.total_records,
        "analyzed_records": metadata.analyzed_records,
        "time_range_start": (
            metadata.time_range_start.isoformat() if metadata.time_range_start else None
        ),
        "time_range_end": metadata.time_range_end.isoformat() if metadata.time_range_end else None,
    }


def batch_clusters(payloads: list[dict[str, Any]], max_chars: int) -> list[list[dict[str, Any]]]:
    """Split payloads into batches whose serialized size stays under ``max_chars``."""
    batches: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    size = 0
    for payload in payloads:
        item_size = len(json.dumps(payload, ensure_ascii=False))
        if item_size > max_chars:
            payload = {**payload, "samples": payload["samples"][:1]}
            item_size = len(json.dumps(payload, ensure_ascii=False))
        if current and size + item_size > max_chars:
            batches.append(current)
            current, size = [], 0
        current.append(payload)
        size += item_size
    if current:
        batches.append(current)
    return batches


class LLMAnalyzer:
    def __init__(self, provider: LLMProvider, settings: Settings) -> None:
        self._provider = provider
        self._settings = settings
        self._system = system_prompt()

    def build_prompts(self, clusters: list[Cluster], metadata: ReportMetadata) -> list[str]:
        """The user prompts that would be sent for the map step (used by --dry-run)."""
        selected = clusters[: self._settings.max_clusters_for_llm]
        batches = batch_clusters(
            [cluster_payload(c) for c in selected], self._settings.max_chars_per_batch
        )
        return [
            self._batch_prompt(batch, metadata, i, len(batches))
            for i, batch in enumerate(batches, start=1)
        ]

    def analyze(self, clusters: list[Cluster], metadata: ReportMetadata) -> IncidentAnalysis:
        if not clusters:
            return IncidentAnalysis(
                summary="No warnings or errors were found in the analyzed records.",
                overall_severity=Severity.INFO,
                top_priorities=[],
                findings=[],
            )
        selected = clusters[: self._settings.max_clusters_for_llm]
        if len(clusters) > len(selected):
            log.warning(
                "Sending the top %d of %d clusters to the model", len(selected), len(clusters)
            )
        known_ids = {c.id for c in selected}
        prompts = self.build_prompts(selected, metadata)

        if len(prompts) == 1:
            result = self._call(prompts[0], IncidentAnalysis)
            result.findings = _clean_findings(result.findings, known_ids)
            return result

        findings: list[Finding] = []
        for prompt in prompts:
            batch = self._call(prompt, BatchFindings)
            findings.extend(_clean_findings(batch.findings, known_ids))
        summary = self._call(self._reduce_prompt(findings, metadata), IncidentSummary)
        return IncidentAnalysis(
            summary=summary.summary,
            overall_severity=summary.overall_severity,
            top_priorities=summary.top_priorities,
            findings=sorted(findings, key=lambda f: -f.severity.rank),
        )

    def _call[T: BaseModel](self, prompt: str, model: type[T]) -> T:
        raw = self._provider.complete_json(
            system=self._system, prompt=prompt, schema=output_schema(model)
        )
        try:
            return model.model_validate(raw)
        except ValidationError as exc:
            raise LLMError(
                f"Model output did not match the {model.__name__} schema: {exc}"
            ) from exc

    @staticmethod
    def _batch_prompt(
        batch: list[dict[str, Any]], metadata: ReportMetadata, index: int, total: int
    ) -> str:
        scope = (
            "These are all the clusters from the export."
            if total == 1
            else f"This is batch {index} of {total}; analyse only the clusters below."
        )
        task = (
            "Analyse the clusters and return the incident summary, overall severity, "
            "top priorities and findings."
            if total == 1
            else "Analyse the clusters and return findings."
        )
        return (
            f"{scope}\n\n<export_metadata>\n{json.dumps(_metadata_payload(metadata), indent=1)}\n"
            f"</export_metadata>\n\n<clusters>\n{json.dumps(batch, indent=1, ensure_ascii=False)}\n"
            f"</clusters>\n\n{task}"
        )

    @staticmethod
    def _reduce_prompt(findings: list[Finding], metadata: ReportMetadata) -> str:
        compact = [
            {
                "title": f.title,
                "component": f.component,
                "severity": f.severity.value,
                "confidence": f.confidence,
                "cluster_ids": f.cluster_ids,
                "root_cause": f.root_cause,
            }
            for f in findings
        ]
        return (
            "The clusters of this export were analysed in batches. Below are the findings "
            "from every batch.\n\n"
            f"<export_metadata>\n{json.dumps(_metadata_payload(metadata), indent=1)}\n"
            "</export_metadata>\n\n"
            f"<findings>\n{json.dumps(compact, indent=1, ensure_ascii=False)}\n</findings>\n\n"
            "Write the overall incident summary: what happened end to end, how the findings "
            "relate (cause and symptom), the overall severity, and the top priorities in order."
        )


def _clean_findings(findings: list[Finding], known_ids: set[str]) -> list[Finding]:
    """Drop cluster ids the model invented and clamp confidence into [0, 1]."""
    cleaned = []
    for finding in findings:
        ids = [cid for cid in finding.cluster_ids if cid in known_ids]
        if not ids:
            log.warning("Dropping finding %r: it references no known cluster", finding.title)
            continue
        cleaned.append(
            finding.model_copy(
                update={"cluster_ids": ids, "confidence": min(1.0, max(0.0, finding.confidence))}
            )
        )
    return cleaned
