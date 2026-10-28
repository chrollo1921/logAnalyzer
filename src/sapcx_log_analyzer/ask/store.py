"""An in-memory, searchable copy of one export for the interactive question mode.

Unlike the report pipeline, which keeps only warnings and errors, the store keeps every
record: the INFO line that says "starting checkout for tx-243232" is often the only line
that carries the id, and the error a few milliseconds later on the same thread does not.
Records are redacted on load, so nothing the store hands out contains raw secrets.
"""

from __future__ import annotations

import difflib
import logging
import re
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from sapcx_log_analyzer.ask.analysis import Analysis, alternatives
from sapcx_log_analyzer.ask.digest import render_digest
from sapcx_log_analyzer.ask.http import HttpCall, http_call
from sapcx_log_analyzer.ask.identifiers import Identifier, identifiers_in
from sapcx_log_analyzer.classify import RuleEngine
from sapcx_log_analyzer.cluster import ClusterAggregator
from sapcx_log_analyzer.config import Settings
from sapcx_log_analyzer.ingest import ExportFormat, read_export
from sapcx_log_analyzer.models import Classification, Cluster, LogLevel, LogRecord
from sapcx_log_analyzer.parse import normalize_all
from sapcx_log_analyzer.redact import Redactor

log = logging.getLogger(__name__)

# Identifier kinds that belong to exactly one request, so sharing one links two records.
# Sessions, carts and orders span several requests and are left for the model to follow.
LINK_KINDS = frozenset({"trace", "correlation", "request"})
_LINK_TOKEN = re.compile(r"^<[a-z]+#[0-9a-f]+>$")


class Scope(StrEnum):
    THREAD = "thread"
    POD = "pod"
    ALL = "all"


@dataclass
class FindResult:
    refs: list[int]
    total: int
    matched_by: str  # "index", "text" or "none"
    related: list[tuple[Identifier, int]] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    # Records that do not mention the value but share a trace, correlation or request id.
    linked_refs: list[int] = field(default_factory=list)
    linked_total: int = 0


@dataclass
class IssueSummary:
    cluster: Cluster
    count_in_window: int


class LogStore:
    def __init__(
        self,
        source: str,
        records: list[LogRecord],
        classifications: list[Classification | None],
        cluster_ids: list[str | None],
        clusters: list[Cluster],
        redactor: Redactor,
    ) -> None:
        self.source = source
        self._records = records
        self._classifications = classifications
        self._cluster_ids = cluster_ids
        self._clusters = {c.id: c for c in clusters}
        self.clusters = clusters
        self.redactor = redactor
        self._index: dict[str, list[int]] = defaultdict(list)
        self._display: dict[str, Identifier] = {}
        self._groups: dict[tuple[Scope, str], list[int]] = defaultdict(list)
        self._calls: dict[int, HttpCall] = {}
        self._overview: dict[str, object] | None = None
        stamps = [r.timestamp for r in records if r.timestamp is not None]
        self._range = (min(stamps), max(stamps)) if stamps else None
        # Values on more records than this (a tenant name, a shared IP) do not identify anything.
        self._common = max(100, len(records) // 20)
        for position, record in enumerate(records):
            ref = position + 1
            call = http_call(record)
            if call is not None:
                self._calls[ref] = call
            for identifier in identifiers_in(record):
                key = identifier.value.lower()
                self._index[key].append(ref)
                self._display.setdefault(key, identifier)
            if record.pod:
                self._groups[(Scope.POD, record.pod)].append(ref)
                if record.thread:
                    self._groups[(Scope.THREAD, f"{record.pod}\x00{record.thread}")].append(ref)
            elif record.thread:
                self._groups[(Scope.THREAD, f"\x00{record.thread}")].append(ref)
            self._groups[(Scope.ALL, "")].append(ref)
        self._digest: str | None = None
        # Patterns, time series and incidents; needs the indexes above.
        self.analysis = Analysis(self)

    # --- loading ----------------------------------------------------------------------

    @classmethod
    def load(
        cls,
        path: Path,
        settings: Settings,
        export_format: ExportFormat | None = None,
        engine: RuleEngine | None = None,
    ) -> LogStore:
        engine = engine or RuleEngine.default(settings.extra_rules_file)
        redactor = Redactor(settings.extra_redaction_patterns)
        aggregator = ClusterAggregator(
            samples_per_cluster=settings.samples_per_cluster,
            max_sample_chars=settings.max_sample_chars,
            top_frames=settings.top_frames_per_cluster,
            bucket_minutes=settings.timeline_bucket_minutes,
        )
        records = [
            redactor.redact_record(r) for r in normalize_all(read_export(path, export_format))
        ]
        # Chronological order makes refs and context windows easy to reason about.
        order = sorted(
            range(len(records)),
            key=lambda i: (records[i].timestamp is None, records[i].timestamp or 0, i),
        )
        records = [records[i] for i in order]
        classifications: list[Classification | None] = []
        cluster_ids: list[str | None] = []
        for record in records:
            classification = engine.classify(record, settings.min_level)
            cluster_id = None
            if classification is not None and (
                record.level.rank >= settings.min_level.rank or classification.any_level
            ):
                cluster_id = aggregator.add(record, classification)
            else:
                classification = None
            classifications.append(classification)
            cluster_ids.append(cluster_id)
        log.info("Loaded %d records from %s", len(records), path.name)
        return cls(
            path.name, records, classifications, cluster_ids, aggregator.clusters(), redactor
        )

    # --- lookups ----------------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._records)

    def record(self, ref: int) -> LogRecord:
        if not 1 <= ref <= len(self._records):
            raise KeyError(f"No record #{ref}; valid refs are 1 to {len(self._records)}")
        return self._records[ref - 1]

    def call_at(self, ref: int) -> HttpCall | None:
        """The HTTP request a record describes, if it is an access log or request line."""
        return self._calls.get(ref)

    def time_range(self) -> tuple[datetime, datetime] | None:
        """The first and last timestamp in the export, or None when no line has one."""
        return self._range

    def classification(self, ref: int) -> Classification | None:
        return self._classifications[ref - 1]

    def cluster_of(self, ref: int) -> Cluster | None:
        cluster_id = self._cluster_ids[ref - 1]
        return self._clusters.get(cluster_id) if cluster_id else None

    def find(self, value: str, limit: int = 50) -> FindResult:
        """Records that carry an identifier, chronologically, plus identifiers seen with it."""
        key = value.strip().lower()
        refs, matched_by = self._lookup(value)
        if not refs:
            return FindResult([], 0, "none", suggestions=self.suggest(value))
        related: Counter[str] = Counter()
        for ref in refs:
            for identifier in identifiers_in(self.record(ref)):
                other = identifier.value.lower()
                if other == key or identifier.kind == "span":
                    continue
                if len(self._index.get(other, ())) <= self._common:
                    related[other] += 1
        linked_refs = self._linked(refs)
        return FindResult(
            refs=refs[:limit],
            total=len(refs),
            matched_by=matched_by,
            related=[(self._display[k], n) for k, n in related.most_common(15)],
            linked_refs=linked_refs[: max(10, limit - len(refs))],
            linked_total=len(linked_refs),
        )

    def _lookup(self, value: str) -> tuple[list[int], str]:
        needle = value.strip()
        key = needle.lower()
        refs = list(self._index.get(key, []))
        if refs:
            return refs, "index"
        if len(needle) >= 4:
            refs = [ref for ref in self._iter_refs() if key in _haystack(self.record(ref))]
            if refs:
                return refs, "text"
        return [], "none"

    def _linked(self, refs: list[int]) -> list[int]:
        """Records that share a trace, correlation or request id with ``refs``."""
        direct = set(refs)
        linked: set[int] = set()
        seen: set[str] = set()
        for ref in refs:
            for identifier in identifiers_in(self.record(ref)):
                key = identifier.value.lower()
                if identifier.kind not in LINK_KINDS or key in seen:
                    continue
                seen.add(key)
                others = self._index.get(key, [])
                if len(others) <= self._common:
                    linked.update(r for r in others if r not in direct)
        return sorted(linked)

    def api_calls(
        self,
        identifier: str | None = None,
        path: str | None = None,
        min_status: int | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> tuple[list[tuple[int, HttpCall]], str]:
        """HTTP requests, optionally only those of one user, account, session or other id.

        For an identifier, requests are the records that mention it plus those that share
        a trace, correlation or request id with them, which is how an access log line that
        only knows the path is tied to the user or account in the application log.
        """
        matched_by = "all"
        if identifier:
            refs, matched_by = self._lookup(identifier)
            candidates = sorted({*refs, *self._linked(refs)})
        else:
            candidates = list(self._calls)
        needle = path.lower() if path else None
        selected: list[tuple[int, HttpCall]] = []
        for ref in candidates:
            call = self._calls.get(ref)
            if call is None:
                continue
            stamp = self.record(ref).timestamp
            if needle and needle not in call.path.lower():
                continue
            if min_status and call.status < min_status:
                continue
            if start and (stamp is None or stamp < start):
                continue
            if end and (stamp is None or stamp > end):
                continue
            selected.append((ref, call))
        return self._dedupe(selected), matched_by

    def _dedupe(self, calls: list[tuple[int, HttpCall]]) -> list[tuple[int, HttpCall]]:
        """Drop application-log mentions of a request that its access log line already covers."""
        logged = {
            (self._trace(ref), call.method, call.path) for ref, call in calls if call.access_log
        }
        return [
            (ref, call)
            for ref, call in calls
            if call.access_log
            or self._trace(ref) is None
            or (self._trace(ref), call.method, call.path) not in logged
        ]

    def _trace(self, ref: int) -> str | None:
        context = self.record(ref).context
        return next((v for k, v in context.items() if "trace" in k.lower()), None)

    def redact_question(self, text: str) -> str:
        """Mask a question like the logs, so pasted emails and session ids map to their tokens."""
        text = self.redactor.redact(text)
        for word in set(re.findall(r"[A-Za-z0-9._-]{8,}", text)):
            token = self.redactor.link_token("SESSION", word)
            if token.lower() in self._index:
                text = re.sub(rf"(?<![\w.-]){re.escape(word)}(?![\w.-])", token, text)
        return text

    def suggest(self, value: str, limit: int = 5) -> list[str]:
        """Known identifiers that look like ``value``, for typos and partial ids."""
        key = value.strip().lower()
        if not key or _LINK_TOKEN.match(key):
            # A token is a salted hash: one that is not in the index has no near misses.
            return []
        digits = re.sub(r"\D", "", key)
        # Only ids of about the same length: "99zz99" is not a near miss of a trace id that
        # happens to contain "9999".
        slack = max(3, len(key) // 2)
        index = [k for k in self._index if abs(len(k) - len(key)) <= slack]
        candidates = [
            k
            for k in index
            if (digits and len(digits) >= 3 and digits in k) or key in k or k in key
        ]
        if len(candidates) < limit:
            candidates.extend(difflib.get_close_matches(key, index, n=limit))
        seen: list[str] = []
        for candidate in candidates:
            display = self._display[candidate].value
            if candidate != key and display not in seen:
                seen.append(display)
        return seen[:limit]

    def context(
        self,
        ref: int,
        window_seconds: float = 30,
        scope: Scope = Scope.THREAD,
        min_level: LogLevel = LogLevel.DEBUG,
        limit: int = 40,
    ) -> list[int]:
        """Records near ``ref`` in time, on the same thread, the same pod or anywhere."""
        record = self.record(ref)
        group = self._groups.get(self._group_key(record, scope)) or [ref]
        if record.timestamp is None:
            position = group.index(ref)
            window = group[max(0, position - limit // 2) : position + limit // 2 + 1]
        else:
            stamps = [self._stamp(r) for r in group]
            low = bisect_left(stamps, record.timestamp.timestamp() - window_seconds)
            high = bisect_right(stamps, record.timestamp.timestamp() + window_seconds)
            window = group[low:high]
        selected = [r for r in window if r == ref or self.record(r).level.rank >= min_level.rank]
        if len(selected) > limit:
            # Keep the records closest to the anchor.
            position = selected.index(ref)
            start = max(0, min(position - limit // 2, len(selected) - limit))
            selected = selected[start : start + limit]
        return selected

    def search(
        self,
        text: str | None = None,
        min_level: LogLevel = LogLevel.TRACE,
        pod: str | None = None,
        aspect: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 50,
    ) -> tuple[list[int], int]:
        terms = alternatives(text)
        refs = []
        for ref in self._iter_refs():
            record = self.record(ref)
            if record.level.rank < min_level.rank:
                continue
            if pod and pod.lower() not in (record.pod or "").lower():
                continue
            if aspect and aspect.lower() != (record.aspect or "").lower():
                continue
            if start and (record.timestamp is None or record.timestamp < start):
                continue
            if end and (record.timestamp is None or record.timestamp > end):
                continue
            if terms and not any(term in _haystack(record) for term in terms):
                continue
            refs.append(ref)
        return refs[:limit], len(refs)

    def issues(
        self, start: datetime | None = None, end: datetime | None = None
    ) -> list[IssueSummary]:
        """Known problem clusters with events inside the window, most severe first."""
        counts: Counter[str] = Counter()
        for ref in self._iter_refs():
            cluster_id = self._cluster_ids[ref - 1]
            if cluster_id is None:
                continue
            stamp = self.record(ref).timestamp
            if (start or end) and stamp is None:
                continue
            if start and stamp is not None and stamp < start:
                continue
            if end and stamp is not None and stamp > end:
                continue
            counts[cluster_id] += 1
        return [IssueSummary(c, counts[c.id]) for c in self.clusters if counts[c.id]]

    def overview(self) -> dict[str, object]:
        # Every new conversation needs it, and the store never changes after loading.
        if self._overview is None:
            self._overview = self._compute_overview()
        return dict(self._overview)

    def _compute_overview(self) -> dict[str, object]:
        stamps = [r.timestamp for r in self._records if r.timestamp is not None]
        levels = Counter(r.level.value for r in self._records)
        kinds = Counter(identifier.kind for identifier in self._display.values())
        return {
            "source": self.source,
            "records": len(self._records),
            "time_range_start": min(stamps).isoformat() if stamps else None,
            "time_range_end": max(stamps).isoformat() if stamps else None,
            "records_by_level": dict(sorted(levels.items())),
            "aspects": sorted({r.aspect for r in self._records if r.aspect}),
            "pods": sorted({r.pod for r in self._records if r.pod})[:30],
            "identifiers_by_kind": dict(kinds.most_common()),
            "known_issue_clusters": len(self.clusters),
            "message_patterns": len(self.analysis.patterns),
            "candidate_incidents": len(self.analysis.incidents),
            "issues_by_severity": dict(
                Counter(c.severity.value for c in self.clusters).most_common()
            ),
        }

    def digest(self) -> str:
        """The export profile as text for the system prompt, computed once."""
        if self._digest is None:
            self._digest = render_digest(self)
        return self._digest

    def sample_identifiers(
        self, kinds: Iterable[str] = ("transaction", "order", "trace")
    ) -> list[str]:
        """A few identifiers to show in examples: preferred kinds first, then those in errors."""
        rank = {kind: position for position, kind in enumerate(kinds)}
        scored: list[tuple[int, int, str]] = []
        for key, identifier in self._display.items():
            if identifier.kind not in rank:
                continue
            refs = self._index[key]
            errors = sum(1 for ref in refs if self.record(ref).level.rank >= LogLevel.WARN.rank)
            scored.append((rank[identifier.kind], -errors, identifier.value))
        return [value for _, _, value in sorted(scored)[:5]]

    # --- helpers ----------------------------------------------------------------------

    def _iter_refs(self) -> range:
        return range(1, len(self._records) + 1)

    def _stamp(self, ref: int) -> float:
        stamp = self.record(ref).timestamp
        return stamp.timestamp() if stamp else float("inf")

    @staticmethod
    def _group_key(record: LogRecord, scope: Scope) -> tuple[Scope, str]:
        if scope is Scope.THREAD and record.thread:
            return (Scope.THREAD, f"{record.pod or ''}\x00{record.thread}")
        if scope in (Scope.THREAD, Scope.POD) and record.pod:
            return (Scope.POD, record.pod)
        return (Scope.ALL, "")


def _haystack(record: LogRecord) -> str:
    return "\n".join(
        [record.message, *record.stack, *record.context.values(), record.thread or ""]
    ).lower()
