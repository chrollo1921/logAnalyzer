"""Recognise HTTP requests (OCC and other API calls) in log records.

Two shapes are common in a CCv2 export: Tomcat or ingress access log lines such as
``10.0.0.1 - - [20/Oct/2026:08:00:03 +0000] "GET /occ/v2/site/products/1 HTTP/1.1" 200 5988 280ms``
and application lines such as ``Request POST /occ/v2/... failed with 500``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sapcx_log_analyzer.models import LogRecord

_METHODS = r"GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS"
_ACCESS = re.compile(
    rf'"(?P<method>{_METHODS}) (?P<path>/[^\s"?]*)(?:\?[^\s"]*)? HTTP/[\d.]+" (?P<status>\d{{3}})'
    r"(?:\s+(?:\d+|-))?(?:\s+(?P<ms>\d+)\s?ms)?"
)
_APP = re.compile(
    rf"\b(?P<method>{_METHODS})\s+(?P<path>/[^\s?\"']+)(?:\?\S*)?.*?"
    r"\b(?:status|failed with|returned|responded with|->)\s*[:=]?\s*(?P<status>[1-5]\d\d)\b"
)
# Path segments that are values rather than parts of the endpoint; "v2" is an API version.
_VALUE_SEGMENT = re.compile(r"^(?!v\d+$)(?:.*\d.*|<[A-Z]+(?:#[0-9a-f]+)?>|[0-9a-fA-F-]{16,})$")


@dataclass(frozen=True)
class HttpCall:
    method: str
    path: str
    status: int
    duration_ms: int | None = None
    access_log: bool = False  # True for access log lines, the authoritative record of a call

    @property
    def endpoint(self) -> str:
        """The path with ids replaced, e.g. ``/occ/v2/electronics/cart/{id}/getDelivery``."""
        return "/".join(
            "{id}" if segment and _VALUE_SEGMENT.match(segment) else segment
            for segment in self.path.split("/")
        )


def http_call(record: LogRecord) -> HttpCall | None:
    match = _ACCESS.search(record.message)
    if match:
        ms = match.group("ms")
        return HttpCall(
            match.group("method"),
            match.group("path"),
            int(match.group("status")),
            int(ms) if ms else None,
            access_log=True,
        )
    match = _APP.search(record.message)
    if match:
        return HttpCall(match.group("method"), match.group("path"), int(match.group("status")))
    return None
