"""Build the report data model shared by every renderer.

Both the self-contained HTML report and the JSON export consumed by the React
dashboard read from :func:`build_report_data`, so the two views can never drift:
edges, per-host dossiers, relative timestamps and severity counts are computed
here, once, from a :class:`~athar.model.Case`.
"""

from __future__ import annotations

import datetime as _dt
from collections import defaultdict
from typing import Any

from ..model import Case, Severity

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def build_report_data(case: Case) -> dict[str, Any]:
    """Return the derived, render-ready data model for *case*."""
    from ..narrative import build_stories

    start = case.started or 0.0

    def rel(ts: float) -> float:
        return round(ts - start, 3) if ts else 0.0

    sev_counts = {s.value: 0 for s in _SEV_ORDER}
    for ev in case.events:
        sev_counts[ev.severity.value] += 1

    # Aggregate per-host application metadata for the dossier.
    dns_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    http_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    sni_by_host: dict[str, set[str]] = defaultdict(set)
    ja3_by_host: dict[str, set[str]] = defaultdict(set)
    ja3s_by_host: dict[str, set[str]] = defaultdict(set)
    objects_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    sessions_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    certs_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for flow in case.flows:
        for q in flow.metadata.get("queries", []):
            dns_by_host[q.get("by", flow.src_ip)].append(q)
        for r in flow.metadata.get("requests", []):
            http_by_host[r.get("by", flow.src_ip)].append(r)
        for s in flow.metadata.get("sni", []):
            sni_by_host[s.get("by", flow.src_ip)].add(s["name"])
        for j in flow.metadata.get("ja3", []):
            ja3_by_host[j.get("by", flow.src_ip)].add(j["hash"])
        for j in flow.metadata.get("ja3s", []):
            ja3s_by_host[j.get("by", flow.src_ip)].add(j["hash"])
        for o in flow.metadata.get("objects", []):
            objects_by_host[o.get("by", flow.src_ip)].append(o)
        for sess in flow.metadata.get("sessions", []):
            sessions_by_host[sess.get("by", flow.src_ip)].append(sess)
        for cert in flow.metadata.get("certificates", []):
            certs_by_host[cert.get("by", flow.src_ip)].append(cert)

    findings_by_host: dict[str, list[int]] = defaultdict(list)
    for i, ev in enumerate(case.sorted_events()):
        for ip in {ev.src_ip, ev.dst_ip}:  # set: never list a finding twice per host
            if ip:
                findings_by_host[ip].append(i)

    hosts = []
    for host in sorted(case.hosts.values(), key=lambda h: -h.bytes):
        hosts.append({
            "ip": host.ip,
            "mac": host.mac,
            "role": host.role,
            "packets": host.packets,
            "bytes": host.bytes,
            "peers": len(host.talked_to),
            "services": sorted(host.services)[:12],
            "protocols": sorted(host.protocols),
            "flagged": host.flagged,
            "private": host.is_private,
            "geo": host.geo,
            "dns": [{"name": q["name"], "type": q["qtype"]} for q in dns_by_host[host.ip][:40]],
            "http": [{"method": r.get("method"), "host": r.get("host", ""),
                      "path": r.get("path", ""), "creds": r.get("credentials", "")}
                     for r in http_by_host[host.ip][:40]],
            "sni": sorted(sni_by_host[host.ip])[:40],
            "ja3": sorted(ja3_by_host[host.ip])[:20],
            "ja3s": sorted(ja3s_by_host[host.ip])[:20],
            "objects": [{
                "kind": o.get("kind", ""), "method": o.get("method", ""),
                "host": o.get("host", ""), "path": o.get("path", ""),
                "filename": o.get("filename", ""), "content_type": o.get("content_type", ""),
                "declared_bytes": o.get("declared_bytes", o.get("body_bytes", 0)),
                "truncated": o.get("truncated", False), "sha256": o.get("body_sha256", ""),
                "body_kind": o.get("body_kind", ""),
                "preview": (o.get("body_preview") or o.get("body_preview_hex", ""))[:400],
            } for o in objects_by_host[host.ip][:20]],
            "certificates": [{"subject": c.get("subject", ""), "issuer": c.get("issuer", ""),
                              "self_signed": c.get("self_signed"), "expired": c.get("expired"),
                              "lifetime_days": c.get("lifetime_days"),
                              "not_after": c.get("not_after", "")}
                             for c in certs_by_host[host.ip][:5]],
            "sessions": [{"protocol": s.get("protocol", ""),
                          "detail": ", ".join(f"{k}={v}" for k, v in s.get("details", {}).items()
                                               if v and k != "commands")}
                         for s in sessions_by_host[host.ip][:20]],
            "findings": findings_by_host[host.ip],
        })

    # Conversation edges for the map, aggregated per unordered host pair.
    edge_map: dict[tuple[str, str], dict[str, Any]] = {}
    for flow in case.flows:
        a, b = sorted((flow.src_ip, flow.dst_ip))
        e = edge_map.setdefault((a, b), {"a": a, "b": b, "bytes": 0, "packets": 0})
        e["bytes"] += flow.bytes
        e["packets"] += flow.packets
    suspicious_pairs = {tuple(sorted((ev.src_ip, ev.dst_ip)))
                        for ev in case.events if ev.src_ip and ev.dst_ip}
    edges = []
    for (a, b), e in edge_map.items():
        e["suspicious"] = (a, b) in suspicious_pairs
        edges.append(e)

    events = [{
        "t": rel(ev.ts),
        "severity": ev.severity.value,
        "detector": ev.detector,
        "title": ev.title,
        "summary": ev.summary,
        "src": ev.src_ip,
        "dst": ev.dst_ip,
        "technique": ev.technique,
        "evidence": ev.evidence,
    } for ev in case.sorted_events()]

    flows = [{
        "src": f.src_ip, "dst": f.dst_ip, "sport": f.src_port, "dport": f.dst_port,
        "proto": f.proto, "service": f.service, "packets": f.packets,
        "bytes": f.bytes, "dur": round(f.duration, 1),
    } for f in sorted(case.flows, key=lambda f: -f.bytes)[:200]]

    return {
        "source": case.source,
        "started_iso": _iso(case.started),
        "ended_iso": _iso(case.ended),
        "duration": round(case.duration, 1),
        "packets": case.total_packets,
        "bytes": case.total_bytes,
        "host_count": len(case.hosts),
        "flow_count": len(case.flows),
        "case_id": case.case_id,
        "provenance": case.provenance.as_dict() if case.provenance else None,
        "tcp_health": case.tcp_health,
        "stories": [{
            "host": st.host, "score": st.score, "span": st.span,
            "tactics": st.tactics,
            "stages": [{
                "tactic": stage.tactic,
                "events": [{"severity": e.severity.value, "title": e.title,
                            "summary": e.summary, "detector": e.detector,
                            "technique": e.technique} for e in stage.events],
            } for stage in st.stages],
        } for st in build_stories(case)[:10]],
        "severity": sev_counts,
        "hosts": hosts,
        "edges": edges,
        "events": events,
        "flows": flows,
    }


def _iso(ts: float) -> str:
    if not ts:
        return "\u2014"
    return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
