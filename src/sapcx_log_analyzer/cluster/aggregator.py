"""Group classified records into clusters and build the incident timeline."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from sapcx_log_analyzer.cluster.fingerprint import fingerprint
from sapcx_log_analyzer.models import (
    Classification,
    Cluster,
    LogRecord,
    Severity,
    TimelineBucket,
)
from sapcx_log_analyzer.parse.stacktrace import frames


class ClusterAggregator:
    def __init__(
        self,
        samples_per_cluster: int = 3,
        max_sample_chars: int = 1500,
        top_frames: int = 8,
        bucket_minutes: int = 5,
    ) -> None:
        self._samples = samples_per_cluster
        self._max_sample_chars = max_sample_chars
        self._top_frames = top_frames
        self._bucket = timedelta(minutes=bucket_minutes)
        self._clusters: dict[str, Cluster] = {}
        self._timeline: dict[datetime, dict[Severity, int]] = defaultdict(lambda: defaultdict(int))

    def add(self, record: LogRecord, classification: Classification) -> str:
        cluster_id, template = fingerprint(record, classification)
        cluster = self._clusters.get(cluster_id)
        if cluster is None:
            cluster = Cluster(
                id=cluster_id,
                rule_id=classification.rule_id,
                component=classification.component,
                title=classification.title,
                severity=classification.severity,
                level=record.level,
                logger=record.logger,
                exception_class=record.exception_class,
                root_cause_class=record.root_cause_class,
                template=template,
                top_frames=_app_frames(record.stack)[: self._top_frames],
            )
            self._clusters[cluster_id] = cluster
        cluster.count += 1
        if record.level.rank > cluster.level.rank:
            cluster.level = record.level
        if record.timestamp is not None:
            if cluster.first_seen is None or record.timestamp < cluster.first_seen:
                cluster.first_seen = record.timestamp
            if cluster.last_seen is None or record.timestamp > cluster.last_seen:
                cluster.last_seen = record.timestamp
            self._timeline[self._bucket_start(record.timestamp)][classification.severity] += 1
        if record.aspect and record.aspect not in cluster.aspects:
            cluster.aspects.append(record.aspect)
        if record.pod and record.pod not in cluster.pods:
            cluster.pods.append(record.pod)
        if len(cluster.samples) < self._samples:
            sample = self._sample(record)
            if sample not in cluster.samples:
                cluster.samples.append(sample)
        return cluster_id

    def clusters(self) -> list[Cluster]:
        """Most severe first, then most frequent."""
        return sorted(
            self._clusters.values(),
            key=lambda c: (
                -c.severity.rank,
                -c.count,
                c.first_seen.timestamp() if c.first_seen else float("inf"),
            ),
        )

    def timeline(self) -> list[TimelineBucket]:
        return [
            TimelineBucket(start=start, counts=dict(counts))
            for start, counts in sorted(self._timeline.items())
        ]

    def _bucket_start(self, ts: datetime) -> datetime:
        epoch = datetime(1970, 1, 1, tzinfo=ts.tzinfo)
        offset = (ts - epoch) // self._bucket
        return epoch + offset * self._bucket

    def _sample(self, record: LogRecord) -> str:
        header = " ".join(
            part
            for part in (
                record.timestamp.isoformat() if record.timestamp else None,
                record.level.value,
                f"[{record.thread}]" if record.thread else None,
                f"[{record.logger}]" if record.logger else None,
            )
            if part
        )
        body = "\n".join([f"{header} {record.message}", *record.stack[:12]])
        if len(body) > self._max_sample_chars:
            body = body[: self._max_sample_chars] + " …[truncated]"
        return body


_FRAMEWORK_PREFIXES = (
    "java.",
    "javax.",
    "jakarta.",
    "jdk.",
    "sun.",
    "com.sun.",
    "org.apache.",
    "org.springframework.",
    "org.eclipse.",
    "com.zaxxer.",
    "io.micrometer.",
)


def _app_frames(stack: list[str]) -> list[str]:
    """Frames from SAP Commerce and project code, skipping JDK and framework noise."""
    all_frames = frames(stack)
    app = [f for f in all_frames if not f.startswith(_FRAMEWORK_PREFIXES)]
    return app or all_frames
