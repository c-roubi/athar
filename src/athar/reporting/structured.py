"""Machine-readable exports: JSON (full model) and CSV (findings)."""

from __future__ import annotations

import csv
import io
import json

from ..model import Case
from .data import build_report_data


def render_data(case: Case) -> str:
    """Serialise the render-ready report data model (used by the dashboard)."""
    return json.dumps(build_report_data(case), indent=2)


def render_json(case: Case) -> str:
    """Serialise the whole case to indented JSON."""
    doc = {
        "source": case.source,
        "provenance": case.provenance.as_dict() if case.provenance else None,
        "started": case.started,
        "ended": case.ended,
        "packets": case.total_packets,
        "bytes": case.total_bytes,
        "hosts": [
            {
                "ip": h.ip, "mac": h.mac, "role": h.role, "packets": h.packets,
                "bytes": h.bytes, "services": sorted(h.services),
                "protocols": sorted(h.protocols), "peers": sorted(h.talked_to),
                "flagged": h.flagged,
            }
            for h in case.hosts.values()
        ],
        "flows": [
            {
                "src_ip": f.src_ip, "dst_ip": f.dst_ip, "src_port": f.src_port,
                "dst_port": f.dst_port, "proto": f.proto, "service": f.service,
                "packets": f.packets, "bytes": f.bytes, "metadata": f.metadata,
            }
            for f in case.flows
        ],
        "events": [
            {
                "ts": e.ts, "severity": e.severity.value, "detector": e.detector,
                "title": e.title, "summary": e.summary, "src_ip": e.src_ip,
                "dst_ip": e.dst_ip, "technique": e.technique, "evidence": e.evidence,
            }
            for e in case.sorted_events()
        ],
    }
    return json.dumps(doc, indent=2)


def render_csv(case: Case) -> str:
    """Write the findings table as CSV -- the row-per-alert analysts import."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ts", "severity", "detector", "technique", "src_ip", "dst_ip", "summary"])
    for e in case.sorted_events():
        writer.writerow([f"{e.ts:.3f}", e.severity.value, e.detector,
                         e.technique, e.src_ip, e.dst_ip, e.summary])
    return buf.getvalue()
