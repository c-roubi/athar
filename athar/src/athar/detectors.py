"""Rule-based detectors.

Each detector is a pure function over collected signals and returns a list of
:class:`~athar.model.Event`. Keeping them free of I/O and of the parsing model
makes them trivial to unit-test with hand-built inputs, and lets new detectors
drop in without touching the engine. Findings carry a MITRE ATT&CK id where one
applies, so reports can speak the language analysts already use.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from .model import Event, Severity


@dataclass
class Signals:
    """Everything the detectors need, collected once during the packet walk."""

    syn_attempts: list[tuple[float, str, str, int]] = field(default_factory=list)
    dns_queries: list[tuple[float, str, str, str]] = field(default_factory=list)
    http_requests: list[dict[str, Any]] = field(default_factory=list)
    credentials: list[dict[str, Any]] = field(default_factory=list)
    uploads: list[dict[str, Any]] = field(default_factory=list)
    lateral: list[dict[str, Any]] = field(default_factory=list)   # (ts, src, dst, service)
    kerberos_tgs: list[tuple[float, str, str]] = field(default_factory=list)
    admin_shares: list[dict[str, Any]] = field(default_factory=list)
    port_anomalies: list[dict[str, Any]] = field(default_factory=list)
    anonymizer: list[dict[str, Any]] = field(default_factory=list)
    suspicious_certs: list[dict[str, Any]] = field(default_factory=list)
    sessions: dict[tuple[str, str, int], list[float]] = field(
        default_factory=lambda: defaultdict(list)
    )


PORT_SCAN_MIN_PORTS = 15
DNS_TUNNEL_MIN_QUERIES = 20
DNS_TUNNEL_MIN_ENTROPY = 3.4
BEACON_MIN_HITS = 6
BEACON_MAX_JITTER = 0.25  # coefficient of variation of the interval
EXFIL_MIN_BYTES = 1 << 20  # 1 MiB uploaded to one external destination
LATERAL_MIN_TARGETS = 3    # one internal host reaching this many peers on admin services
KERBEROAST_MIN_TGS = 10    # TGS-REQ burst from one host suggesting Kerberoasting


def run_all(signals: Signals) -> list[Event]:
    events: list[Event] = []
    events += detect_port_scan(signals.syn_attempts)
    events += detect_plaintext_credentials(signals.credentials)
    events += detect_dns_tunneling(signals.dns_queries)
    events += detect_beaconing(signals.sessions)
    events += detect_data_exfiltration(signals.uploads)
    events += detect_lateral_movement(signals.lateral)
    events += detect_kerberoasting(signals.kerberos_tgs)
    events += detect_admin_share_access(signals.admin_shares)
    events += detect_port_anomaly(signals.port_anomalies)
    events += detect_anonymizer(signals.anonymizer)
    events += detect_suspicious_cert(signals.suspicious_certs)
    return events


def detect_port_scan(attempts: list[tuple[float, str, str, int]]) -> list[Event]:
    """A source touching many distinct ports on one target is scanning it."""
    by_pair: dict[tuple[str, str], set[int]] = defaultdict(set)
    first_ts: dict[tuple[str, str], float] = {}
    for ts, src, dst, port in attempts:
        pair = (src, dst)
        by_pair[pair].add(port)
        first_ts.setdefault(pair, ts)

    events = []
    for (src, dst), ports in by_pair.items():
        if len(ports) >= PORT_SCAN_MIN_PORTS:
            events.append(
                Event(
                    ts=first_ts[(src, dst)],
                    severity=Severity.HIGH,
                    detector="port_scan",
                    title="TCP port scan",
                    summary=f"{src} probed {len(ports)} ports on {dst}",
                    src_ip=src,
                    dst_ip=dst,
                    technique="T1046",  # Network Service Discovery
                    evidence={"ports_probed": len(ports),
                              "sample_ports": sorted(ports)[:12]},
                )
            )
    return events


def detect_plaintext_credentials(creds: list[dict[str, Any]]) -> list[Event]:
    """Any credential seen in cleartext -- HTTP Basic, FTP, ... -- is critical."""
    events = []
    for c in creds:
        user = c.get("username", "")
        password = c.get("password", "")
        proto = c.get("protocol", "cleartext")
        target = c.get("target", "")
        shown = f"'{user}'"
        if password:
            shown += f" / '{password}'"
        events.append(
            Event(
                ts=c["ts"],
                severity=Severity.CRITICAL,
                detector="plaintext_credentials",
                title="Credentials sent in the clear",
                summary=f"{proto} login {shown} to {target}",
                src_ip=c.get("src_ip", ""),
                dst_ip=c.get("dst_ip", ""),
                technique="T1040",  # Network Sniffing (exposure)
                evidence={"username": user, "password": password,
                          "protocol": proto, "target": target},
            )
        )
    return events


def detect_dns_tunneling(queries: list[tuple[float, str, str, str]]) -> list[Event]:
    """High volume of long, high-entropy names under one domain looks like a tunnel."""
    by_domain: dict[tuple[str, str], list[tuple[float, str]]] = defaultdict(list)
    for ts, src, name, _qtype in queries:
        by_domain[(src, _parent_domain(name))].append((ts, name))

    events = []
    for (src, domain), seen in by_domain.items():
        if len(seen) < DNS_TUNNEL_MIN_QUERIES:
            continue
        entropies = [_entropy(_leftmost_label(name)) for _, name in seen]
        avg_entropy = sum(entropies) / len(entropies)
        if avg_entropy >= DNS_TUNNEL_MIN_ENTROPY:
            events.append(
                Event(
                    ts=seen[0][0],
                    severity=Severity.HIGH,
                    detector="dns_tunneling",
                    title="Possible DNS tunneling",
                    summary=f"{src} made {len(seen)} high-entropy lookups under {domain}",
                    src_ip=src,
                    dst_ip="",
                    technique="T1071.004",  # Application Layer Protocol: DNS
                    evidence={"domain": domain, "queries": len(seen),
                              "avg_entropy": round(avg_entropy, 2)},
                )
            )
    return events


def detect_beaconing(sessions: dict[tuple[str, str, int], list[float]]) -> list[Event]:
    """Regular, low-jitter callbacks to one destination look like C2 beaconing."""
    events = []
    for (src, dst, port), stamps in sessions.items():
        if len(stamps) < BEACON_MIN_HITS:
            continue
        stamps = sorted(stamps)
        intervals = [b - a for a, b in zip(stamps, stamps[1:], strict=False) if b - a > 0]
        if len(intervals) < BEACON_MIN_HITS - 1:
            continue
        mean = sum(intervals) / len(intervals)
        if mean <= 0:
            continue
        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        jitter = math.sqrt(variance) / mean  # coefficient of variation
        if jitter <= BEACON_MAX_JITTER:
            events.append(
                Event(
                    ts=stamps[0],
                    severity=Severity.HIGH,
                    detector="beaconing",
                    title="Periodic beaconing",
                    summary=f"{src} called {dst}:{port} every ~{mean:.0f}s, {len(stamps)} times",
                    src_ip=src,
                    dst_ip=dst,
                    technique="T1071",  # Application Layer Protocol (C2)
                    evidence={"interval_s": round(mean, 1), "hits": len(stamps),
                              "jitter": round(jitter, 3)},
                )
            )
    return events


# --- helpers ---------------------------------------------------------------

def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = defaultdict(int)
    for ch in text:
        counts[ch] += 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _leftmost_label(name: str) -> str:
    return name.split(".", 1)[0] if name else ""


def _parent_domain(name: str) -> str:
    parts = name.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else name


def detect_data_exfiltration(uploads: list[dict[str, Any]]) -> list[Event]:
    """A host pushing a large volume of body data to one external destination.

    Works on reconstructed cleartext-HTTP request bodies, so it measures *sent
    application data* (uploads) rather than raw packet bytes. Encrypted transfers
    can't be measured this way and are out of scope here.
    """
    by_pair: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {"bytes": 0, "count": 0, "ts": 0.0, "names": []}
    )
    for up in uploads:
        pair = (up["src_ip"], up["dst_ip"])
        agg = by_pair[pair]
        agg["bytes"] += up["bytes"]
        agg["count"] += 1
        agg["ts"] = agg["ts"] or up["ts"]
        if up.get("filename"):
            agg["names"].append(up["filename"])

    events = []
    for (src, dst), agg in by_pair.items():
        if agg["bytes"] < EXFIL_MIN_BYTES:
            continue
        mb = agg["bytes"] / (1 << 20)
        named = f" (incl. {', '.join(agg['names'][:3])})" if agg["names"] else ""
        events.append(
            Event(
                ts=agg["ts"],
                severity=Severity.HIGH,
                detector="data_exfiltration",
                title="Large outbound data transfer",
                summary=f"{src} uploaded {mb:.1f} MB to {dst} over cleartext HTTP{named}",
                src_ip=src,
                dst_ip=dst,
                technique="T1048",  # Exfiltration Over Alternative Protocol
                evidence={"bytes": agg["bytes"], "objects": agg["count"],
                          "filenames": agg["names"][:10]},
            )
        )
    return events


def detect_lateral_movement(events_in: list[dict[str, Any]]) -> list[Event]:
    """One internal host fanning out to many peers over admin protocols.

    RDP/SMB/WinRM from a single source to several distinct internal targets is a
    classic lateral-movement pattern (T1021). Aggregated per source+service.
    """
    by_key: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {"targets": set(), "ts": 0.0})
    for e in events_in:
        key = (e["src"], e["service"])
        agg = by_key[key]
        agg["targets"].add(e["dst"])
        agg["ts"] = agg["ts"] or e["ts"]

    events = []
    for (src, service), agg in by_key.items():
        targets = agg["targets"]
        if len(targets) < LATERAL_MIN_TARGETS:
            continue
        sample = ", ".join(sorted(targets)[:5])
        events.append(Event(
            ts=agg["ts"], severity=Severity.HIGH, detector="lateral_movement",
            title="Possible lateral movement",
            summary=f"{src} opened {service.upper()} to {len(targets)} internal hosts ({sample})",
            src_ip=src, dst_ip="",
            technique="T1021",  # Remote Services
            evidence={"service": service, "targets": sorted(targets),
                      "target_count": len(targets)},
        ))
    return events


def detect_kerberoasting(tgs: list[tuple[float, str, str]]) -> list[Event]:
    """A burst of Kerberos TGS ticket requests from one host (T1558.003)."""
    by_src: dict[str, list[float]] = defaultdict(list)
    dst_of: dict[str, str] = {}
    for ts, src, dst in tgs:
        by_src[src].append(ts)
        dst_of.setdefault(src, dst)
    events = []
    for src, times in by_src.items():
        if len(times) < KERBEROAST_MIN_TGS:
            continue
        events.append(Event(
            ts=min(times), severity=Severity.HIGH, detector="kerberoasting",
            title="Possible Kerberoasting",
            summary=f"{src} requested {len(times)} Kerberos service tickets from {dst_of[src]}",
            src_ip=src, dst_ip=dst_of[src],
            technique="T1558.003",  # Kerberoasting
            evidence={"tgs_requests": len(times)},
        ))
    return events


def detect_admin_share_access(hits: list[dict[str, Any]]) -> list[Event]:
    """Access to hidden administrative shares (C$, ADMIN$) — T1021.002."""
    events = []
    seen: set[tuple[str, str, str]] = set()
    for h in hits:
        for share in h.get("shares", []):
            key = (h["src"], h["dst"], share)
            if key in seen:
                continue
            seen.add(key)
            events.append(Event(
                ts=h["ts"], severity=Severity.HIGH, detector="admin_share_access",
                title="Administrative share access",
                summary=f"{h['src']} accessed {share} on {h['dst']}",
                src_ip=h["src"], dst_ip=h["dst"],
                technique="T1021.002",  # SMB/Windows Admin Shares
                evidence={"share": share},
            ))
    return events


def detect_port_anomaly(anomalies: list[dict[str, Any]]) -> list[Event]:
    """A known service running on a non-standard port — an evasion signal."""
    events = []
    seen: set[tuple[str, str, str, int]] = set()
    for a in anomalies:
        key = (a["src"], a["dst"], a["service"], a["port"])
        if key in seen:
            continue
        seen.add(key)
        events.append(Event(
            ts=a["ts"], severity=Severity.MEDIUM, detector="port_anomaly",
            title="Service on a non-standard port",
            summary=f"{a['service'].upper()} to {a['dst']} on port {a['port']} "
                    f"(normally {a['expected']})",
            src_ip=a["src"], dst_ip=a["dst"],
            technique="T1571",  # Non-Standard Port
            evidence={"service": a["service"], "port": a["port"], "expected": a["expected"]},
        ))
    return events


def detect_anonymizer(hits: list[dict[str, Any]]) -> list[Event]:
    """Connections to Tor / anonymising infrastructure (possible C2 egress)."""
    events = []
    seen: set[tuple[str, str]] = set()
    for h in hits:
        key = (h["src"], h["dst"])
        if key in seen:
            continue
        seen.add(key)
        events.append(Event(
            ts=h["ts"], severity=Severity.HIGH, detector="anonymizer",
            title="Connection to anonymising network",
            summary=f"{h['src']} connected to {h['dst']}:{h['port']} ({h['reason']})",
            src_ip=h["src"], dst_ip=h["dst"],
            technique="T1090.003",  # Proxy: Multi-hop (Tor)
            evidence={"reason": h["reason"], "port": h["port"]},
        ))
    return events


SHORT_CERT_DAYS = 90  # certs valid for <= this on external hosts look throwaway


def detect_suspicious_cert(certs: list[dict[str, Any]]) -> list[Event]:
    """Self-signed or short-lived TLS certs on external hosts — C2 indicator."""
    events = []
    for c in certs:
        reasons = []
        if c.get("self_signed"):
            reasons.append("self-signed")
        life = c.get("lifetime_days")
        if isinstance(life, int) and 0 <= life <= SHORT_CERT_DAYS:
            reasons.append(f"short-lived ({life}d)")
        if not reasons:
            continue
        subject = c.get("subject", "?")
        events.append(Event(
            ts=c["ts"], severity=Severity.MEDIUM, detector="suspicious_certificate",
            title="Suspicious TLS certificate",
            summary=f"{c['dst']} served a {' and '.join(reasons)} certificate "
                    f"(subject {subject})",
            src_ip=c.get("src", ""), dst_ip=c["dst"],
            technique="T1587.003",  # Develop Capabilities: Digital Certificates
            evidence={"subject": subject, "issuer": c.get("issuer", ""),
                      "reasons": reasons, "lifetime_days": life},
        ))
    return events
