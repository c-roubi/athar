"""Differential validation against a reference tool (tshark).

The strongest answer to "can I trust this tool's parsing?" is agreement with an
independently-developed, widely-accepted implementation on the same input. This
harness runs athar and tshark (Wireshark's CLI) over the same capture and
compares the *objective* facts they should agree on — packet count, the set of
IP addresses, DNS query names, and the number of TCP conversations. Divergence is
reported so it can be investigated; agreement is evidence of correct parsing.

tshark must be installed. This is a cross-checking aid, not a claim of formal
validation — that still requires testing on labelled real-world corpora.

    python validation/differential.py <capture.pcap>
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from athar import analyze  # noqa: E402


@dataclass
class Comparison:
    name: str
    athar: object
    tshark: object
    agree: bool


@dataclass
class Report:
    capture: str
    comparisons: list[Comparison] = field(default_factory=list)

    @property
    def all_agree(self) -> bool:
        return all(c.agree for c in self.comparisons)


def _tshark(args: list[str]) -> str:
    out = subprocess.run(
        ["tshark", "-r", *args], capture_output=True, text=True, check=False,
    )
    return out.stdout


def _tshark_packet_count(pcap: str) -> int:
    return sum(1 for line in _tshark([pcap]).splitlines() if line.strip())


def _tshark_ips(pcap: str) -> set[str]:
    out = _tshark([pcap, "-T", "fields", "-e", "ip.src", "-e", "ip.dst"])
    ips: set[str] = set()
    for line in out.splitlines():
        for field_val in line.replace("\t", ",").split(","):
            v = field_val.strip()
            if v:
                ips.add(v)
    return ips


def _tshark_dns(pcap: str) -> set[str]:
    out = _tshark([pcap, "-Y", "dns.flags.response==0", "-T", "fields", "-e", "dns.qry.name"])
    return {line.strip() for line in out.splitlines() if line.strip()}


def _tshark_count(pcap: str, display_filter: str) -> int:
    out = _tshark([pcap, "-Y", display_filter])
    return sum(1 for line in out.splitlines() if line.strip())


def _tshark_tcp_convs(pcap: str) -> int:
    out = _tshark([pcap, "-q", "-z", "conv,tcp"])
    return sum(1 for line in out.splitlines() if "<->" in line)


def compare(pcap: str) -> Report:
    if not shutil.which("tshark"):
        raise RuntimeError("tshark is not installed; install Wireshark's CLI to cross-check")

    case = analyze(pcap)

    athar_ips = set(case.hosts)
    athar_dns = {q[2] for q in _athar_dns(case)}
    athar_tcp = sum(1 for f in case.flows if f.proto == "tcp")
    ath_reset = case.tcp_health.get("resets", 0)
    ath_zwin = case.tcp_health.get("zero_window", 0)
    ath_retx = case.tcp_health.get("retransmissions", 0)

    report = Report(capture=pcap)
    report.comparisons = [
        Comparison("packet count", case.total_packets, _tshark_packet_count(pcap),
                   case.total_packets == _tshark_packet_count(pcap)),
        Comparison("ip addresses", len(athar_ips), len(_tshark_ips(pcap)),
                   athar_ips == _tshark_ips(pcap)),
        Comparison("dns query names", len(athar_dns), len(_tshark_dns(pcap)),
                   athar_dns == _tshark_dns(pcap)),
        Comparison("tcp conversations", athar_tcp, _tshark_tcp_convs(pcap),
                   athar_tcp == _tshark_tcp_convs(pcap)),
        Comparison("tcp resets", ath_reset, _tshark_count(pcap, "tcp.flags.reset==1"),
                   ath_reset == _tshark_count(pcap, "tcp.flags.reset==1")),
        Comparison("tcp zero-window", ath_zwin, _tshark_count(pcap, "tcp.analysis.zero_window"),
                   ath_zwin == _tshark_count(pcap, "tcp.analysis.zero_window")),
        Comparison("tcp retransmissions", ath_retx,
                   _tshark_count(pcap, "tcp.analysis.retransmission"),
                   ath_retx == _tshark_count(pcap, "tcp.analysis.retransmission")),
    ]
    return report


def _athar_dns(case: object) -> list[tuple]:
    names = []
    for flow in case.flows:  # type: ignore[attr-defined]
        for q in flow.metadata.get("queries", []):
            names.append((0.0, q.get("by", ""), q["name"], q.get("qtype", "")))
    return names


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: differential.py <capture.pcap>", file=sys.stderr)
        return 2
    report = compare(argv[0])
    print(f"Differential validation — athar vs tshark\ncapture: {report.capture}\n")
    print(f"{'fact':<20} {'athar':>10} {'tshark':>10}  {'':<5}")
    print("-" * 50)
    for c in report.comparisons:
        mark = "OK" if c.agree else "DIFF"
        print(f"{c.name:<20} {str(c.athar):>10} {str(c.tshark):>10}  {mark}")
    print("-" * 50)
    print("all facts agree" if report.all_agree else "DIVERGENCE — investigate above")
    return 0 if report.all_agree else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
