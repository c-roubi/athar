"""Labelled validation scenarios.

Each scenario is a small synthetic capture with a *known* ground truth: the set
of ``(detector, host)`` findings that should fire, or none for a benign control.
Clear positives sit well above each detector's threshold and clear negatives well
below, so they measure correctness unambiguously; the boundary cases sit near the
thresholds and are what an honest error-rate reflects.

Reuses the low-level packet builders from ``tools/make_sample_pcap.py``.
"""

from __future__ import annotations

import random
import struct
from dataclasses import dataclass, field

import make_sample_pcap as g


@dataclass
class Scenario:
    name: str
    label: str                                   # positive | negative | boundary
    pcap: bytes
    expected: set[tuple[str, str]] = field(default_factory=set)  # (detector, src_ip)


def _pcap(records: list[tuple[float, bytes]]) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # DLT_EN10MB
    for ts, frame in records:
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        out += struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame
    return out


def _syn(ts: float, src: str, dst: str, sport: int, dport: int) -> tuple[float, bytes]:
    return (ts, g.eth(src, dst, g.ipv4(src, dst, 6, g.tcp(sport, dport, 0x02))))


def _synack(ts: float, src: str, dst: str, sport: int, dport: int) -> tuple[float, bytes]:
    return (ts, g.eth(src, dst, g.ipv4(src, dst, 6, g.tcp(sport, dport, 0x12))))


def _udp(ts: float, src: str, dst: str, sport: int, dport: int, payload: bytes):
    return (ts, g.eth(src, dst, g.ipv4(src, dst, 17, g.udp(sport, dport, payload))))


def _http(ts: float, src: str, dst: str, payload: bytes) -> tuple[float, bytes]:
    return (ts, g.eth(src, dst, g.ipv4(src, dst, 6, g.tcp(44000, 80, 0x18, payload))))


def _rand_label(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


def _scan(src: str, dst: str, ports: list[int], t0: float = 1.0) -> bytes:
    return _pcap([_syn(t0 + i * 0.02, src, dst, 40000 + i, p) for i, p in enumerate(ports)])


def _beacon(src: str, dst: str, intervals: list[float], t0: float = 1.0) -> bytes:
    recs, t = [], t0
    for gap in [0.0, *intervals]:
        t += gap
        recs.append(_syn(t, src, dst, 45000, 443))
        recs.append(_synack(t + 0.03, dst, src, 443, 45000))
    return _pcap(recs)


def _dns(src: str, names: list[str], t0: float = 1.0) -> bytes:
    return _pcap([_udp(t0 + i * 0.3, src, "192.168.0.1", 51000, 53, g.dns_query(n, 16))
                  for i, n in enumerate(names)])


def scenarios() -> list[Scenario]:
    rng = random.Random(20260829)
    out: list[Scenario] = []

    # --- clear positives (well above threshold) ---------------------------
    out.append(Scenario("scan_clear", "positive",
        _scan("192.168.0.10", "192.168.0.1", list(range(1, 26))),
        {("port_scan", "192.168.0.10")}))

    creds = g.http_get("nas.local", "/admin", auth="admin:password123")
    out.append(Scenario("creds_clear", "positive",
        _pcap([_http(1.0, "192.168.0.11", "192.168.0.20", creds)]),
        {("plaintext_credentials", "192.168.0.11")}))

    out.append(Scenario("beacon_clear", "positive",
        _beacon("192.168.0.12", "8.8.8.8", [60.0] * 8),
        {("beaconing", "192.168.0.12")}))

    tunnel_names = [f"{_rand_label(rng, 30)}.tunnel.bad.example" for _ in range(30)]
    out.append(Scenario("tunnel_clear", "positive",
        _dns("192.168.0.13", tunnel_names),
        {("dns_tunneling", "192.168.0.13")}))

    # --- clear negatives (benign controls, must fire nothing) -------------
    out.append(Scenario("scan_small_benign", "negative",
        _scan("192.168.0.21", "192.168.0.1", list(range(1, 6)))))          # 5 ports < 15

    out.append(Scenario("beacon_jittery_benign", "negative",
        _beacon("192.168.0.22", "8.8.8.8", [5, 40, 300, 12, 200, 8, 90])))  # irregular

    normal_names = ["www.google.com"] * 30
    out.append(Scenario("dns_normal_benign", "negative",
        _dns("192.168.0.23", normal_names)))                                # low entropy

    plain_get = g.http_get("intranet.local", "/index.html")                 # no auth header
    out.append(Scenario("http_noauth_benign", "negative",
        _pcap([_http(1.0, "192.168.0.24", "192.168.0.20", plain_get)])))

    # --- boundary cases (near thresholds; define the error rate) ----------
    out.append(Scenario("scan_below_threshold", "boundary",
        _scan("192.168.0.31", "192.168.0.1", list(range(1, 15)))))          # 14 ports
    out.append(Scenario("scan_at_threshold", "boundary",
        _scan("192.168.0.32", "192.168.0.1", list(range(1, 16))),
        {("port_scan", "192.168.0.32")}))                                   # 15 ports

    out.append(Scenario("beacon_few_hits", "boundary",
        _beacon("192.168.0.33", "8.8.8.8", [60.0] * 4)))                    # 5 hits < 6
    out.append(Scenario("beacon_min_hits", "boundary",
        _beacon("192.168.0.34", "8.8.8.8", [60.0] * 6),
        {("beaconing", "192.168.0.34")}))                                   # 7 hits

    out.append(Scenario("tunnel_low_volume", "boundary",
        _dns("192.168.0.35", [f"{_rand_label(rng, 30)}.t.bad.example" for _ in range(19)])))
    out.append(Scenario("tunnel_min_volume", "boundary",
        _dns("192.168.0.36", [f"{_rand_label(rng, 30)}.t.bad.example" for _ in range(22)]),
        {("dns_tunneling", "192.168.0.36")}))

    return out


DETECTORS = ["port_scan", "plaintext_credentials", "beaconing", "dns_tunneling"]
