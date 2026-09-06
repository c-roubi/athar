"""Correlate scattered findings into a single attack narrative.

Individual detections — a scan here, a credential there, a beacon later — are
much stronger evidence when tied to the same host and ordered along the attack
lifecycle. This groups a case's findings by the internal host implicated in them,
maps each detector to an ATT&CK tactic (kill-chain phase), and produces a
per-host story an investigator can read top to bottom: what the host did first,
what it did next, how bad it looks overall.

This is interpretation on top of the raw findings, kept separate so the findings
themselves stay primary evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import Case, Event, Severity

# Detector -> (ATT&CK tactic, kill-chain order). Lower order = earlier phase.
_TACTIC: dict[str, tuple[str, int]] = {
    "port_scan": ("Discovery", 1),
    "port_anomaly": ("Discovery", 1),
    "plaintext_credentials": ("Credential Access", 2),
    "kerberoasting": ("Credential Access", 2),
    "admin_share_access": ("Lateral Movement", 3),
    "lateral_movement": ("Lateral Movement", 3),
    "beaconing": ("Command & Control", 4),
    "anonymizer": ("Command & Control", 4),
    "ioc_match": ("Command & Control", 4),
    "dns_tunneling": ("Exfiltration", 5),
    "data_exfiltration": ("Exfiltration", 5),
}

_SEV_WEIGHT = {
    Severity.CRITICAL: 40, Severity.HIGH: 20, Severity.MEDIUM: 8,
    Severity.LOW: 3, Severity.INFO: 1,
}


@dataclass
class AttackStage:
    tactic: str
    order: int
    events: list[Event] = field(default_factory=list)


@dataclass
class HostStory:
    host: str
    stages: list[AttackStage]
    first_ts: float
    last_ts: float
    score: int
    tactics: list[str]

    @property
    def span(self) -> float:
        return round(self.last_ts - self.first_ts, 1)


def _implicated_host(case: Case, event: Event) -> str:
    """Pick the internal host the finding is about (prefer a private address)."""
    for ip in (event.src_ip, event.dst_ip):
        host = case.hosts.get(ip)
        if host is not None and host.geo.get("scope") in ("private", "cgnat"):
            return ip
    return event.src_ip or event.dst_ip


def build_stories(case: Case) -> list[HostStory]:
    """Return per-host attack narratives, most serious first."""
    by_host: dict[str, list[Event]] = {}
    for event in case.events:
        host = _implicated_host(case, event)
        if host:
            by_host.setdefault(host, []).append(event)

    stories: list[HostStory] = []
    for host, events in by_host.items():
        # A lone, low-severity finding isn't a "story" — needs some substance.
        if len(events) < 2 and all(e.severity not in (Severity.CRITICAL, Severity.HIGH)
                                   for e in events):
            continue

        stages_map: dict[str, AttackStage] = {}
        for event in events:
            tactic, order = _TACTIC.get(event.detector, ("Other", 9))
            stage = stages_map.setdefault(tactic, AttackStage(tactic, order))
            stage.events.append(event)

        stages = sorted(stages_map.values(), key=lambda s: s.order)
        for stage in stages:
            stage.events.sort(key=lambda e: e.ts)

        timestamps = [e.ts for e in events if e.ts]
        score = sum(_SEV_WEIGHT.get(e.severity, 0) for e in events)
        # A multi-stage attack is worse than the sum of its parts.
        score += (len(stages) - 1) * 15
        stories.append(HostStory(
            host=host,
            stages=stages,
            first_ts=min(timestamps) if timestamps else 0.0,
            last_ts=max(timestamps) if timestamps else 0.0,
            score=score,
            tactics=[s.tactic for s in stages],
        ))

    stories.sort(key=lambda s: -s.score)
    return stories
