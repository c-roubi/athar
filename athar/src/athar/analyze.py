"""The analysis engine: turn a capture file into a :class:`Case`.

One pass over the packets builds the host inventory and the flow table, runs
the dissectors to attach application metadata, and collects the signals the
detectors need. Detectors run at the end, and their findings are folded back
onto the hosts they implicate so the report can highlight them.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import (
    decode,
    detectors,
    dissectors,
    evidence,
    extract,
    geoip,
    intel,
    netknowledge,
    protocols,
    reassembly,
    tcphealth,
    tlscerts,
    tlsdecrypt,
    winproto,
)
from .backend import backend, iter_packets
from .evidence import Provenance
from .model import Case, Flow, Host
from .reassembly import reassemble

# A conversation key: (src_ip, dst_ip, src_port, dst_port, proto_name).
FlowKey = tuple[str, str, int, int, str]
# A directional TCP stream key: (src_ip, dst_ip, src_port, dst_port).
DirKey = tuple[str, str, int, int]

# TCP flag bits.
_SYN, _ACK = 0x02, 0x10

_WELL_KNOWN = {53: "dns", 80: "http", 443: "tls", 8080: "http", 8443: "tls", 21: "ftp"}


def analyze(
    path: str | Path,
    feed: intel.Feed | None = None,
    provenance: Provenance | None = None,
    keylog: tlsdecrypt.KeyLog | None = None,
    geo: geoip.GeoEnricher | None = None,
) -> Case:
    """Read *path* and return the fully populated forensic :class:`Case`.

    If a threat-intel *feed* is given, observed indicators are matched against it
    and any hits are added as findings before hosts are classified. A source hash
    and provenance record are always computed for evidence integrity; any
    *provenance* passed in (examiner, case number, authority) is preserved and
    completed with the source hash, tool version and backend. If a *keylog* of
    per-session TLS secrets is supplied, matching TLS streams are decrypted and
    their plaintext is dissected like cleartext HTTP.
    """
    from . import __version__

    case = Case(source=str(path))
    signals = detectors.Signals()
    flows: dict[FlowKey, Flow] = {}
    streams: dict[DirKey, list[tuple[int, bytes]]] = {}
    stream_ts: dict[DirKey, float] = {}
    stream_bytes: dict[DirKey, int] = {}
    health = tcphealth.TCPHealth()

    for ts, pkt in iter_packets(path):
        _account(case, ts, pkt)
        flow = _flow_for(flows, case, ts, pkt)
        _collect_signals(signals, ts, pkt, flow)
        if pkt.proto == decode.PROTO_TCP:
            health.observe(ts, pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port,
                           pkt.tcp_flags, pkt.seq, pkt.ack, pkt.window, len(pkt.payload))
        # Buffer TCP payloads per direction for stream reassembly, but bound each
        # direction so a huge transfer can't grow memory without limit (we only
        # reassemble up to the same cap anyway).
        if pkt.proto == decode.PROTO_TCP and pkt.payload:
            dk = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port)
            if stream_bytes.get(dk, 0) < reassembly.MAX_STREAM:
                streams.setdefault(dk, []).append((pkt.seq, pkt.payload))
                stream_bytes[dk] = stream_bytes.get(dk, 0) + len(pkt.payload)
                stream_ts.setdefault(dk, ts)

    _dissect_streams(streams, stream_ts, flows, signals, case, keylog)
    _attach_tcp_health(case, flows, health)
    case.flows = list(flows.values())
    case.events = detectors.run_all(signals)
    if feed is not None:
        case.events += intel.match(case, feed)
    classify_hosts(case)
    _enrich_geo(case, geo)

    meta = provenance or Provenance()
    case.provenance = evidence.build_provenance(
        path, examiner=meta.examiner, organization=meta.organization,
        case_number=meta.case_number, authority=meta.authority, notes=meta.notes,
        tool_version=__version__, backend=backend(),
    )
    return case


def _extract_http_content(
    data: bytes, src: str, dst: str, ts: float, flow: Flow,
    signals: detectors.Signals, case: Case,
) -> None:
    """Reconstruct cleartext-HTTP objects: record uploads, tally bytes, carve files."""
    for obj in extract.extract_http_objects(data):
        if "body_bytes" not in obj:
            continue
        summary: dict[str, object] = {k: obj[k] for k in (
            "kind", "method", "path", "host", "content_type", "filename",
            "body_bytes", "declared_bytes", "truncated", "body_sha256",
            "body_kind", "body_preview", "body_preview_hex", "start_line") if k in obj}
        summary["by"] = src
        flow.metadata.setdefault("objects", []).append(summary)

        is_request = obj["kind"] == "request"
        # A request body leaving an internal host is data it sent outward; the
        # declared Content-Length is the honest measure of how much was sent.
        if is_request and obj["body_bytes"] > 0:
            signals.uploads.append({
                "ts": ts, "src_ip": src, "dst_ip": dst,
                "bytes": obj.get("declared_bytes", obj["body_bytes"]),
                "filename": obj.get("filename", ""),
            })
        # Retain raw bytes for optional file carving (transient, never persisted).
        if obj.get("body"):
            case.carved.append({
                "direction": "upload" if is_request else "download",
                "origin": (f"{obj.get('host', dst)}{obj.get('path', '')}" if is_request
                           else f"{src}->{dst}"),
                "filename": obj.get("filename", ""),
                "content_type": obj.get("content_type", ""),
                "body_kind": obj.get("body_kind", ""),
                "body_sha256": obj.get("body_sha256", ""),
                "truncated": obj.get("truncated", False),
                "body": obj["body"],
            })


def _account(case: Case, ts: float, pkt: decode.Packet) -> None:
    size = len(pkt.payload) + 40  # payload plus a nominal header allowance
    case.total_packets += 1
    case.total_bytes += size
    case.started = ts if case.started == 0.0 else min(case.started, ts)
    case.ended = max(case.ended, ts)

    for ip, mac, peer in ((pkt.src_ip, pkt.src_mac, pkt.dst_ip),
                          (pkt.dst_ip, pkt.dst_mac, pkt.src_ip)):
        host = case.hosts.get(ip)
        if host is None:
            host = case.hosts[ip] = Host(ip=ip, mac=mac, first_seen=ts)
        host.mac = host.mac or mac
        host.first_seen = min(host.first_seen or ts, ts)
        host.last_seen = max(host.last_seen, ts)
        host.packets += 1
        host.bytes += size
        host.protocols.add(pkt.proto_name)
        if peer != ip:
            host.talked_to.add(peer)

    # A host offers a service only when it *sends from* a low port -- i.e. it
    # answered on a listening socket. Ports merely probed by a scan never count.
    if pkt.src_port and pkt.dst_port and pkt.src_port < pkt.dst_port:
        case.hosts[pkt.src_ip].services.add(pkt.src_port)


def _canon_key(src: str, dst: str, sport: int, dport: int, proto: str) -> FlowKey:
    """Canonicalise a directional 5-tuple so both halves share one key."""
    if (src, sport) <= (dst, dport):
        return (src, dst, sport, dport, proto)
    return (dst, src, dport, sport, proto)


def _flow_for(
    flows: dict[FlowKey, Flow], case: Case, ts: float, pkt: decode.Packet
) -> Flow:
    key = _canon_key(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.proto_name)
    flow = flows.get(key)
    if flow is None:
        flow = flows[key] = Flow(
            src_ip=key[0], dst_ip=key[1], src_port=key[2], dst_port=key[3],
            proto=key[4], first_seen=ts,
            service=_WELL_KNOWN.get(key[3]) or _WELL_KNOWN.get(key[2], ""),
        )
    flow.last_seen = max(flow.last_seen, ts)
    flow.packets += 1
    flow.bytes += len(pkt.payload) + 40
    return flow


def _collect_signals(
    signals: detectors.Signals, ts: float, pkt: decode.Packet, flow: Flow
) -> None:
    # SYN without ACK = a fresh connection attempt (port-scan signal).
    if pkt.proto == decode.PROTO_TCP and (pkt.tcp_flags & _SYN) and not (pkt.tcp_flags & _ACK):
        signals.syn_attempts.append((ts, pkt.src_ip, pkt.dst_ip, pkt.dst_port))
        signals.sessions[(pkt.src_ip, pkt.dst_ip, pkt.dst_port)].append(ts)
        # Egress to Tor / common C2 default ports (evasion / C2 signal).
        if netknowledge.is_tor_node(pkt.dst_ip):
            signals.anonymizer.append({"ts": ts, "src": pkt.src_ip, "dst": pkt.dst_ip,
                                       "port": pkt.dst_port, "reason": "known Tor relay"})
        elif pkt.dst_port in netknowledge.TOR_PORTS:
            signals.anonymizer.append({"ts": ts, "src": pkt.src_ip, "dst": pkt.dst_ip,
                                       "port": pkt.dst_port, "reason": "Tor ORPort"})
        elif pkt.dst_port in netknowledge.C2_DEFAULT_PORTS:
            signals.anonymizer.append({"ts": ts, "src": pkt.src_ip, "dst": pkt.dst_ip,
                                       "port": pkt.dst_port, "reason": "common C2 port"})

    # DNS is UDP and self-contained, so it is dissected per packet.
    if pkt.payload and (pkt.dst_port == 53 or pkt.src_port == 53):
        dns = dissectors.dissect_dns(pkt.payload)
        if dns:
            flow.service = "dns"
            if dns["is_query"]:  # attribute the lookup to the host that asked
                flow.metadata.setdefault("queries", []).append(
                    {"name": dns["name"], "qtype": dns["qtype"], "by": pkt.src_ip})
                signals.dns_queries.append((ts, pkt.src_ip, dns["name"], dns["qtype"]))

    # DHCP (UDP 67/68) is also self-contained — good for device inventory.
    if pkt.payload and (pkt.dst_port in (67, 68) or pkt.src_port in (67, 68)):
        dhcp = protocols.dissect_dhcp(pkt.payload)
        if dhcp:
            flow.service = "dhcp"
            flow.metadata.setdefault("sessions", []).append({**dhcp, "by": pkt.src_ip})

    # SNMP (UDP 161/162): recover the community string.
    if pkt.payload and (pkt.dst_port in (161, 162) or pkt.src_port in (161, 162)):
        snmp = protocols.dissect_snmp(pkt.payload)
        if snmp:
            flow.service = "snmp"
            flow.metadata.setdefault("sessions", []).append({**snmp, "by": pkt.src_ip})
            signals.credentials.append({
                "ts": ts, "src_ip": pkt.src_ip, "dst_ip": pkt.dst_ip,
                "protocol": "SNMP community",
                "username": snmp["details"]["community"], "password": "", "target": pkt.dst_ip})


def _collect_lateral(
    session: dict[str, Any], src: str, dst: str, dport: int, ts: float,
    signals: detectors.Signals,
) -> None:
    """Feed east-west protocol sessions into the lateral-movement detectors."""
    service: str = session.get("service", "")
    details: dict[str, Any] = session.get("details", {})
    # Remote-service fan-out (RDP/SMB) between internal hosts.
    if service in ("rdp", "smb") and _is_private(src) and _is_private(dst):
        signals.lateral.append({"ts": ts, "src": src, "dst": dst, "service": service})
    # Hidden admin-share access.
    if details.get("admin_shares"):
        signals.admin_shares.append({
            "ts": ts, "src": src, "dst": dst, "shares": details["admin_shares"]})
    # Kerberos ticket requests (TGS-REQ) for Kerberoasting counting.
    if service == "kerberos" and details.get("message_type") == "TGS-REQ":
        signals.kerberos_tgs.append((ts, src, dst))
    # Service running on a non-standard port (evasion).
    expected = netknowledge.SERVICE_PORTS.get(service)
    if expected and dport and dport != expected:
        signals.port_anomalies.append({
            "ts": ts, "src": src, "dst": dst, "service": service,
            "port": dport, "expected": expected})


def _is_private(ip: str) -> bool:
    return geoip.GeoEnricher().lookup(ip).scope in ("private", "cgnat", "link-local")


def _dissect_streams(
    streams: dict[DirKey, list[tuple[int, bytes]]],
    stream_ts: dict[DirKey, float],
    flows: dict[FlowKey, Flow],
    signals: detectors.Signals,
    case: Case,
    keylog: tlsdecrypt.KeyLog | None = None,
) -> None:
    """Reassemble each TCP direction and dissect the ordered application bytes."""
    reassembled: dict[DirKey, bytes] = {}
    for dk, segments in streams.items():
        data = reassemble(segments)
        if data:
            reassembled[dk] = data

    decrypted = _decrypt_tls(reassembled, keylog) if keylog else {}

    for dk, data in reassembled.items():
        src, dst, sport, dport = dk
        flow = flows.get(_canon_key(src, dst, sport, dport, "tcp"))
        if flow is None:
            continue
        ts = stream_ts[dk]

        # If this TLS direction was decrypted, dissect the recovered plaintext.
        if dk in decrypted:
            flow.service = "tls"
            flow.metadata["tls_decrypted"] = True
            plaintext = decrypted[dk]
            if (plaintext.startswith(extract.HTTP_METHODS)
                    or plaintext.startswith(extract.HTTP_RESPONSE)):
                _extract_http_content(plaintext, src, dst, ts, flow, signals, case)
                http = dissectors.dissect_http(plaintext)
                if http and http.get("credentials"):
                    user, _, pw = http["credentials"].partition(":")
                    signals.credentials.append({
                        "ts": ts, "src_ip": src, "dst_ip": dst, "protocol": "HTTPS (decrypted)",
                        "username": user, "password": pw,
                        "target": http.get("host") or dst,
                    })
            continue

        _dissect_plaintext(data, src, dst, sport, dport, ts, flow, signals, case)


def _decrypt_tls(
    reassembled: dict[DirKey, bytes], keylog: tlsdecrypt.KeyLog
) -> dict[DirKey, bytes]:
    """Pair the two directions of each TLS connection and decrypt what we can."""
    out: dict[DirKey, bytes] = {}
    seen: set[DirKey] = set()
    for dk, data in reassembled.items():
        if dk in seen or not data.startswith(b"\x16\x03"):  # TLS handshake record
            continue
        src, dst, sport, dport = dk
        rev = (dst, src, dport, sport)
        rev_data = reassembled.get(rev)
        if rev_data is None:
            continue
        # Orient client->server (ClientHello) vs server->client (ServerHello).
        if data[5:6] == b"\x01" or rev_data[5:6] == b"\x02":
            c2s, s2c, c_key, s_key = data, rev_data, dk, rev
        else:
            c2s, s2c, c_key, s_key = rev_data, data, rev, dk
        seen.update({dk, rev})
        result = tlsdecrypt.decrypt_connection(c2s, s2c, keylog)
        if not result:
            continue
        if result.get("client"):
            out[c_key] = result["client"]
        if result.get("server"):
            out[s_key] = result["server"]
    return out


def _dissect_plaintext(
    data: bytes, src: str, dst: str, sport: int, dport: int, ts: float,
    flow: Flow, signals: detectors.Signals, case: Case,
) -> None:
    """Dissect an unencrypted application stream."""
    if data.startswith(extract.HTTP_METHODS) or data.startswith(extract.HTTP_RESPONSE):
        http = dissectors.dissect_http(data)  # request line only (None for responses)
        flow.service = "http"
        if http:
            flow.metadata.setdefault("requests", []).append({**http, "by": src})
            signals.http_requests.append({**http, "ts": ts, "src_ip": src, "dst_ip": dst})
            if http.get("credentials"):
                user, _, pw = http["credentials"].partition(":")
                signals.credentials.append({
                    "ts": ts, "src_ip": src, "dst_ip": dst, "protocol": "HTTP Basic",
                    "username": user, "password": pw,
                    "target": http.get("host") or dst,
                })
        _extract_http_content(data, src, dst, ts, flow, signals, case)
        return

    session = protocols.dissect_stream(data, sport, dport)
    if session is None:
        session = winproto.dissect_binary(data, sport, dport)
    if session:
        flow.service = session["service"]
        flow.metadata.setdefault("sessions", []).append({**session, "by": src})
        for cred in session.get("credentials", []):
            signals.credentials.append({
                "ts": ts, "src_ip": src, "dst_ip": dst,
                "protocol": session["protocol"], "username": cred.get("username", ""),
                "password": cred.get("password", ""),
                "target": cred.get("target") or dst,
            })
        _collect_lateral(session, src, dst, dport, ts, signals)
        return

    tls = dissectors.dissect_tls_client_hello(data)
    if tls:
        flow.service = "tls"
        flow.metadata.setdefault("ja3", []).append({"hash": tls["ja3"], "by": src})
        if "sni" in tls:
            flow.metadata.setdefault("sni", []).append({"name": tls["sni"], "by": src})
        return

    server = dissectors.dissect_tls_server_hello(data)
    if server:
        flow.service = "tls"
        flow.metadata.setdefault("ja3s", []).append({"hash": server["ja3s"], "by": src})
        # The certificate follows the ServerHello in the same stream (cleartext).
        for cert in tlscerts.extract_certificates(data):
            flow.metadata.setdefault("certificates", []).append({**cert, "by": src})
            if cert.get("subject") or cert.get("self_signed") is not None:
                signals.suspicious_certs.append({
                    "ts": ts, "src": dst, "dst": src,  # src is the server here
                    "subject": cert.get("subject", ""), "issuer": cert.get("issuer", ""),
                    "self_signed": cert.get("self_signed"),
                    "lifetime_days": cert.get("lifetime_days"),
                })


def _attach_tcp_health(case: Case, flows: dict[FlowKey, Flow], health: tcphealth.TCPHealth) -> None:
    """Store the TCP-health summary on the case and per-flow anomaly counts."""
    case.tcp_health = health.summary()
    for flow in flows.values():
        canon = (flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port)
        anomalies = health.per_flow.get(canon)
        if anomalies:
            flow.metadata["tcp_anomalies"] = anomalies


def _enrich_geo(case: Case, geo: geoip.GeoEnricher | None) -> None:
    """Attach scope/geo/ASN metadata to every host (always sets scope)."""
    enricher = geo or geoip.GeoEnricher()
    for host in case.hosts.values():
        info = enricher.lookup(host.ip)
        host.geo = info.as_dict()


def classify_hosts(case: Case) -> None:
    """Assign each host a role and flag those implicated by any finding."""
    flagged: set[str] = set()
    for event in case.events:
        flagged.update(ip for ip in (event.src_ip, event.dst_ip) if ip)

    for host in case.hosts.values():
        host.flagged = host.ip in flagged
        if not host.is_private:
            host.role = "external"
        elif len(host.services) >= 2:
            host.role = "server"
        elif any(e.detector == "port_scan" and e.src_ip == host.ip for e in case.events):
            host.role = "scanner"
        else:
            host.role = "endpoint"
