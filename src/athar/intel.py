"""Threat-intelligence matching.

Loads a local indicator feed and matches it against what a capture actually
observed -- destination IPs, looked-up or SNI domains, and JA3 client
fingerprints -- raising a finding for every hit. The feed is a small JSON file,
so it works offline and fits alongside the tool's dependency-free design:

    {"ips": ["1.2.3.4"], "domains": ["evil.example"], "ja3": ["<md5>"]}

Matching runs over the :class:`~athar.model.Case`, which means it works the same
on a freshly analysed capture and on one reloaded from the store.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .model import Case, Event, Severity


@dataclass
class Feed:
    """A set of indicators of compromise loaded from a feed file."""

    ips: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    ja3: set[str] = field(default_factory=set)
    source: str = ""

    def __bool__(self) -> bool:
        return bool(self.ips or self.domains or self.ja3)


def load_feed(path: str | Path) -> Feed:
    """Load indicators from a JSON feed file."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return Feed(
        ips=set(data.get("ips", [])),
        domains={d.lower() for d in data.get("domains", [])},
        ja3=set(data.get("ja3", [])),
        source=Path(path).name,
    )


def match(case: Case, feed: Feed) -> list[Event]:
    """Return one finding per distinct indicator hit in *case*."""
    events: list[Event] = []
    seen: set[tuple[str, str, str]] = set()  # (type, indicator, host) -- de-duplicate

    def add(kind: str, indicator: str, sev: Severity, title: str, summary: str,
            src: str, dst: str, ts: float) -> None:
        if (kind, indicator, src) in seen:
            return
        seen.add((kind, indicator, src))
        events.append(Event(
            ts=ts, severity=sev, detector="ioc_match", title=title, summary=summary,
            src_ip=src, dst_ip=dst, technique="T1071",
            evidence={"indicator": indicator, "type": kind, "feed": feed.source},
        ))

    # IP indicators: any observed host whose address is on the list.
    for host in case.hosts.values():
        if host.ip in feed.ips:
            peer = next((p for p in sorted(host.talked_to) if case.hosts.get(p)
                         and case.hosts[p].is_private), "")
            add("ip", host.ip, Severity.CRITICAL, "Traffic to a known-bad host",
                f"contact with flagged address {host.ip}", peer, host.ip, host.first_seen)

    # Domain and JA3 indicators come from the dissected flow metadata.
    for flow in case.flows:
        for q in flow.metadata.get("queries", []):
            hit = _domain_hit(q["name"], feed.domains)
            if hit:
                add("domain", hit, Severity.HIGH, "Lookup of a known-bad domain",
                    f"{q.get('by', flow.src_ip)} resolved {q['name']}",
                    q.get("by", flow.src_ip), "", flow.first_seen)
        for s in flow.metadata.get("sni", []):
            hit = _domain_hit(s["name"], feed.domains)
            if hit:
                add("domain", hit, Severity.HIGH, "TLS connection to a known-bad domain",
                    f"{s.get('by', flow.src_ip)} reached {s['name']} over TLS",
                    s.get("by", flow.src_ip), "", flow.first_seen)
        for j in flow.metadata.get("ja3", []):
            if j["hash"] in feed.ja3:
                by = j.get("by", flow.src_ip)
                peer = flow.dst_ip if flow.src_ip == by else flow.src_ip
                add("ja3", j["hash"], Severity.HIGH, "Known-bad TLS fingerprint",
                    f"{by} presented flagged JA3 {j['hash'][:12]}\u2026",
                    by, peer, flow.first_seen)

    return events


def _domain_hit(name: str, domains: set[str]) -> str | None:
    """Return the matched indicator if *name* is or is under a flagged domain."""
    name = name.lower().rstrip(".")
    for d in domains:
        if name == d or name.endswith("." + d):
            return d
    return None
