"""The forensic data model.

Everything the engine learns about a capture lands in a :class:`Case`: the
hosts seen, the conversations between them, the metadata dissected out of the
payloads, and the findings raised by detectors. Rendering code consumes this
model and nothing lower, so new output formats never touch the parsing path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .evidence import Provenance


class Severity(str, Enum):
    """Ordered finding severities; the value doubles as a CSS/JSON token."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self)


@dataclass
class Host:
    """A single network endpoint observed in the capture."""

    ip: str
    mac: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    packets: int = 0
    bytes: int = 0
    services: set[int] = field(default_factory=set)      # local ports it served on
    talked_to: set[str] = field(default_factory=set)     # peer IPs
    protocols: set[str] = field(default_factory=set)
    role: str = "endpoint"                               # endpoint | server | scanner | external
    flagged: bool = False
    geo: dict[str, str] = field(default_factory=dict)

    @property
    def is_private(self) -> bool:
        return _is_private(self.ip)


@dataclass
class Flow:
    """A bidirectional conversation between two endpoints on one 5-tuple."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    first_seen: float = 0.0
    last_seen: float = 0.0
    packets: int = 0
    bytes: int = 0
    service: str = ""                    # dissected application protocol
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str, int, int, str]:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)


@dataclass
class Event:
    """A finding raised by a detector -- the 'this host did that' record."""

    ts: float
    severity: Severity
    detector: str
    title: str
    summary: str
    src_ip: str = ""
    dst_ip: str = ""
    technique: str = ""                  # MITRE ATT&CK id, when applicable
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class Case:
    """The complete result of analysing one capture."""

    source: str
    started: float = 0.0
    ended: float = 0.0
    total_packets: int = 0
    total_bytes: int = 0
    hosts: dict[str, Host] = field(default_factory=dict)
    flows: list[Flow] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    provenance: Provenance | None = None
    carved: list[dict[str, Any]] = field(default_factory=list)  # transient, not persisted
    tcp_health: dict[str, int] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        return max(0.0, self.ended - self.started)

    def sorted_events(self) -> list[Event]:
        return sorted(self.events, key=lambda e: (-e.severity.rank, e.ts))

    @property
    def case_id(self) -> str:
        """A stable identifier derived from the capture's identity."""
        import hashlib

        seed = f"{self.source}|{self.started}|{self.total_packets}"
        return "ATH-" + hashlib.sha1(seed.encode()).hexdigest()[:8].upper()


def _is_private(ip: str) -> bool:
    if ":" in ip:  # treat IPv6 link-local / ULA as private
        return ip.startswith(("fe80", "fc", "fd", "::1"))
    try:
        a, b, *_ = (int(p) for p in ip.split("."))
    except ValueError:
        return False
    return (
        a == 10
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
        or a == 127
        or (a == 169 and b == 254)
    )
