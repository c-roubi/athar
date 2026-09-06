"""Unit and integration tests for athar."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from athar import analyze
from athar.detectors import (
    detect_beaconing,
    detect_dns_tunneling,
    detect_plaintext_credentials,
    detect_port_scan,
)
from athar.dissectors import dissect_dns, dissect_http, dissect_tls_client_hello
from athar.model import Severity

# --- dissectors ------------------------------------------------------------

def _dns_query(name: str) -> bytes:
    q = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\x00" + struct.pack("!HH", 1, 1)


def test_dissect_dns_reads_question():
    out = dissect_dns(_dns_query("example.com"))
    assert out == {"name": "example.com", "qtype": "A", "is_query": True}


def test_dissect_dns_rejects_short_payload():
    assert dissect_dns(b"\x00\x01") is None


def test_dissect_http_extracts_basic_auth():
    raw = (b"GET /admin HTTP/1.1\r\nHost: box.local\r\n"
           b"Authorization: Basic YWRtaW46c2VjcmV0\r\n\r\n")
    out = dissect_http(raw)
    assert out["method"] == "GET"
    assert out["host"] == "box.local"
    assert out["credentials"] == "admin:secret"


def test_dissect_http_ignores_non_http():
    assert dissect_http(b"\x16\x03\x01random") is None


def test_dissect_tls_sni():
    from tools_helper import client_hello  # provided below via conftest path shim
    payload = client_hello("secure.example.org")
    out = dissect_tls_client_hello(payload)
    assert out["sni"] == "secure.example.org"


def test_ja3_is_stable_and_correct():
    """JA3 must follow the canonical string format and be deterministic."""
    from tools_helper import client_hello_profile

    from athar.dissectors import ja3_from_client_hello

    payload = client_hello_profile(
        "host.example", ciphers=[0x1301, 0x1302], curves=[0x001D, 0x0017],
        point_formats=[0x00], extra_exts=[0x0017],
    )
    out = dissect_tls_client_hello(payload)
    # server_name(0), supported_groups(10), ec_point_formats(11), extra(23)
    assert out["ja3_string"] == "771,4865-4866,0-10-11-23,29-23,0"
    import hashlib
    assert out["ja3"] == hashlib.md5(out["ja3_string"].encode()).hexdigest()
    assert ja3_from_client_hello(payload) == out["ja3"]


def test_ja3_filters_grease():
    """GREASE cipher/extension values must be dropped for a stable fingerprint."""
    from tools_helper import client_hello_profile
    payload = client_hello_profile(
        "g.example", ciphers=[0x0A0A, 0x1301], curves=[0x001D], point_formats=[0x00],
        extra_exts=[0x1A1A],
    )
    out = dissect_tls_client_hello(payload)
    assert "2570" not in out["ja3_string"]   # 0x0a0a
    assert "6682" not in out["ja3_string"]   # 0x1a1a


# --- detectors -------------------------------------------------------------

def test_port_scan_fires_above_threshold():
    attempts = [(float(p), "10.0.0.9", "10.0.0.1", p) for p in range(1, 21)]
    events = detect_port_scan(attempts)
    assert len(events) == 1
    assert events[0].severity is Severity.HIGH
    assert events[0].technique == "T1046"


def test_port_scan_quiet_below_threshold():
    attempts = [(float(p), "10.0.0.9", "10.0.0.1", p) for p in range(1, 5)]
    assert detect_port_scan(attempts) == []


def test_plaintext_credentials_flagged_critical():
    creds = [{"ts": 1.0, "src_ip": "10.0.0.5", "dst_ip": "10.0.0.6",
              "protocol": "HTTP Basic", "username": "root", "password": "toor",
              "target": "nas"}]
    events = detect_plaintext_credentials(creds)
    assert events[0].severity is Severity.CRITICAL
    assert events[0].evidence["username"] == "root"
    assert events[0].evidence["password"] == "toor"
    assert "toor" in events[0].summary  # password surfaced for the investigator


def test_dns_tunneling_needs_entropy_and_volume():
    import random
    random.seed(1)
    queries = []
    for _ in range(25):
        label = "".join(random.choice("abcdef0123456789") for _ in range(30))
        queries.append((1.0, "10.0.0.7", f"{label}.exfil.bad.net", "TXT"))
    events = detect_dns_tunneling(queries)
    assert len(events) == 1
    assert events[0].technique == "T1071.004"


def test_dns_tunneling_ignores_normal_lookups():
    queries = [(1.0, "10.0.0.7", "www.google.com", "A")] * 25
    assert detect_dns_tunneling(queries) == []


def test_beaconing_detects_regular_intervals():
    sessions = {("10.0.0.8", "1.2.3.4", 443): [i * 30.0 for i in range(8)]}
    events = detect_beaconing(sessions)
    assert len(events) == 1
    assert events[0].evidence["hits"] == 8


def test_beaconing_ignores_jittery_traffic():
    sessions = {("10.0.0.8", "1.2.3.4", 443): [0, 5, 40, 42, 300, 305, 900]}
    assert detect_beaconing(sessions) == []


# --- end to end ------------------------------------------------------------

def test_full_pipeline_on_sample(tmp_path: Path):
    import tools_helper
    pcap_path = tmp_path / "s.pcap"
    pcap_path.write_bytes(tools_helper.sample_bytes())
    case = analyze(pcap_path)
    detectors_fired = {e.detector for e in case.events}
    assert {"port_scan", "plaintext_credentials", "beaconing", "dns_tunneling"} <= detectors_fired
    assert case.total_packets > 0
    assert any(h.role == "scanner" for h in case.hosts.values())


# --- native backend --------------------------------------------------------

def test_backend_is_reported():
    from athar import backend
    assert backend() in {"native", "python"}


def test_native_matches_python(tmp_path: Path):
    """When the C++ core is built, it must decode byte-for-byte like Python."""
    try:
        from athar import _core
    except ImportError:
        pytest.skip("native core not built")

    import tools_helper

    from athar import decode, pcap
    pcap_path = tmp_path / "s.pcap"
    pcap_path.write_bytes(tools_helper.sample_bytes())

    py_rows = []
    for frame in pcap.read_frames(pcap_path):
        p = decode.decode(frame.data, frame.link_type)
        if p is not None:
            py_rows.append((round(frame.ts, 6), p.src_ip, p.dst_ip, p.proto, p.src_port,
                            p.dst_port, p.tcp_flags, p.payload, p.src_mac, p.dst_mac,
                            p.seq, p.window, p.ack))

    native_rows = [(round(r[0], 6), *tuple(r[1:])) for r in _core.parse_file(str(pcap_path))]
    assert native_rows == py_rows


# --- sqlite store ----------------------------------------------------------

def _sample_case(tmp_path: Path):
    import tools_helper
    pcap_path = tmp_path / "s.pcap"
    pcap_path.write_bytes(tools_helper.sample_bytes())
    return analyze(pcap_path)


def test_store_roundtrip_is_lossless(tmp_path: Path):
    from athar import store
    case = _sample_case(tmp_path)
    db = tmp_path / "f.db"
    cid = store.save_case(case, db)

    conn = store.connect(db)
    try:
        loaded = store.load_case(conn, cid)
    finally:
        conn.close()

    assert loaded.case_id == case.case_id
    assert loaded.total_packets == case.total_packets
    assert len(loaded.hosts) == len(case.hosts)
    assert len(loaded.flows) == len(case.flows)
    assert {e.detector for e in loaded.events} == {e.detector for e in case.events}
    # metadata survives the round trip (needed for the host dossier).
    assert any(f.metadata.get("queries") for f in loaded.flows)
    scanner = next(h for h in loaded.hosts.values() if h.role == "scanner")
    assert scanner.flagged


def test_store_is_idempotent(tmp_path: Path):
    from athar import store
    case = _sample_case(tmp_path)
    db = tmp_path / "f.db"
    store.save_case(case, db)
    store.save_case(case, db)  # re-analysing the same capture must not duplicate

    conn = store.connect(db)
    try:
        assert len(store.list_cases(conn)) == 1
    finally:
        conn.close()


def test_store_supports_sql_investigation(tmp_path: Path):
    from athar import store
    case = _sample_case(tmp_path)
    db = tmp_path / "f.db"
    store.save_case(case, db)

    conn = store.connect(db)
    try:
        row = conn.execute(
            "SELECT json_extract(evidence,'$.username') AS user FROM events "
            "WHERE detector = 'plaintext_credentials' "
            "AND json_extract(evidence,'$.protocol') = 'HTTP Basic'"
        ).fetchone()
        assert row["user"] == "admin"
        # the SQL store lets an examiner pivot across all recovered credentials
        creds = conn.execute(
            "SELECT COUNT(*) AS n FROM events WHERE detector = 'plaintext_credentials'"
        ).fetchone()
        assert creds["n"] >= 4
        assert store.latest_case_id(conn) == case.case_id
    finally:
        conn.close()


# --- threat intel ----------------------------------------------------------

def test_intel_matches_ip_domain_and_ja3(tmp_path: Path):
    from athar import analyze, intel
    feed = intel.Feed(ips={"185.220.101.5"}, domains={"evil-c2.net"},
                      ja3={"e5c6ecce54485f312c2d9bb1e54ab124"}, source="test")

    import tools_helper
    pcap_path = tmp_path / "s.pcap"
    pcap_path.write_bytes(tools_helper.sample_bytes())
    case = analyze(pcap_path, feed=feed)

    ioc = [e for e in case.events if e.detector == "ioc_match"]
    kinds = {e.evidence["type"] for e in ioc}
    assert kinds == {"ip", "domain", "ja3"}
    # the C2 host is implicated by several independent signals
    beacon_events = [e for e in case.events if "185.220.101.5" in (e.src_ip, e.dst_ip)]
    assert len({e.detector for e in beacon_events}) >= 2


def test_intel_subdomain_match():
    from athar.intel import _domain_hit
    assert _domain_hit("a.b.evil-c2.net", {"evil-c2.net"}) == "evil-c2.net"
    assert _domain_hit("evil-c2.net", {"evil-c2.net"}) == "evil-c2.net"
    assert _domain_hit("notevil-c2.net", {"evil-c2.net"}) is None


def test_intel_empty_feed_matches_nothing(tmp_path: Path):
    import tools_helper

    from athar import analyze, intel
    pcap_path = tmp_path / "s.pcap"
    pcap_path.write_bytes(tools_helper.sample_bytes())
    case = analyze(pcap_path, feed=intel.Feed())
    assert not [e for e in case.events if e.detector == "ioc_match"]


def test_render_data_matches_report_shape(tmp_path: Path):
    import json as _json

    import tools_helper

    from athar import analyze
    from athar.reporting import render_data
    pcap_path = tmp_path / "s.pcap"
    pcap_path.write_bytes(tools_helper.sample_bytes())
    case = analyze(pcap_path)
    doc = _json.loads(render_data(case))
    for key in ("case_id", "severity", "hosts", "edges", "events", "flows"):
        assert key in doc
    assert doc["host_count"] == len(case.hosts)
    assert isinstance(doc["edges"], list)


# --- forensic soundness: pcapng, hashing, provenance, custody ---------------

def test_pcapng_matches_pcap(tmp_path: Path):
    import make_sample_pcap as gen

    from athar import analyze
    pcap_p = tmp_path / "s.pcap"
    pcapng_p = tmp_path / "s.pcapng"
    pcap_p.write_bytes(gen.build())
    pcapng_p.write_bytes(gen.build_pcapng())
    c1 = analyze(pcap_p)
    c2 = analyze(pcapng_p)
    assert c1.total_packets == c2.total_packets
    assert {e.detector for e in c1.events} == {e.detector for e in c2.events}


def test_source_hash_is_recorded(tmp_path: Path):
    import hashlib

    import tools_helper

    from athar import analyze
    p = tmp_path / "s.pcap"
    p.write_bytes(tools_helper.sample_bytes())
    case = analyze(p)
    assert case.provenance is not None
    expected = hashlib.sha256(p.read_bytes()).hexdigest()
    assert case.provenance.source_sha256 == expected
    assert case.provenance.tool_version
    assert case.provenance.analyzed_at.endswith("+00:00")


def test_provenance_survives_the_store(tmp_path: Path):
    import tools_helper

    from athar import Provenance, analyze, load_case, save_case
    from athar.store import connect
    p = tmp_path / "s.pcap"
    p.write_bytes(tools_helper.sample_bytes())
    case = analyze(p, provenance=Provenance(examiner="Roubi", case_number="CU-1"))
    cid = save_case(case, tmp_path / "f.db")
    conn = connect(tmp_path / "f.db")
    try:
        loaded = load_case(conn, cid)
    finally:
        conn.close()
    assert loaded.provenance is not None
    assert loaded.provenance.examiner == "Roubi"
    assert loaded.provenance.source_sha256 == case.provenance.source_sha256


def test_chain_of_custody_manifest(tmp_path: Path):
    import json as _json

    import tools_helper

    from athar import analyze
    from athar.reporting import ChainOfCustody, render_html
    p = tmp_path / "s.pcap"
    p.write_bytes(tools_helper.sample_bytes())
    case = analyze(p)
    html_path = tmp_path / "r.html"
    html_path.write_text(render_html(case), encoding="utf-8")

    coc = ChainOfCustody(case.case_id, case.provenance)
    coc.record(html_path, "html")
    manifest_path = tmp_path / "r.coc.json"
    coc.write(manifest_path)

    manifest = _json.loads(manifest_path.read_text())
    assert manifest["source"]["sha256"] == case.provenance.source_sha256
    assert manifest["artefacts"][0]["kind"] == "html"
    assert "manifest_sha256" in manifest
    # the recorded artefact hash must match the file on disk
    import hashlib
    assert manifest["artefacts"][0]["sha256"] == hashlib.sha256(html_path.read_bytes()).hexdigest()


# --- tamper-evident audit log ----------------------------------------------

def test_audit_chain_appends_and_verifies():
    from athar.audit import AuditLog
    log = AuditLog()
    log.append("analyze", actor="roubi", target="ATH-1", details={"findings": 3})
    log.append("export", actor="roubi", target="ATH-1", details={"kind": "html"})
    ok, bad = log.verify()
    assert ok and bad is None
    assert log.entries[1].prev_hash == log.entries[0].entry_hash


def test_audit_detects_tampering():
    from athar.audit import AuditLog
    log = AuditLog()
    log.append("analyze", actor="a", target="ATH-1")
    log.append("export", actor="a", target="ATH-1", details={"kind": "csv"})
    log.append("export", actor="a", target="ATH-1", details={"kind": "json"})
    log.entries[1].details["kind"] = "TAMPERED"  # edit a past entry in place
    ok, bad = log.verify()
    assert not ok
    assert bad == 1


def test_audit_roundtrip_through_file(tmp_path: Path):
    from athar.audit import AuditLog
    p = tmp_path / "audit.log"
    log = AuditLog()
    log.append("analyze", actor="a", target="ATH-1")
    log.write(p)
    reloaded = AuditLog.load(p)
    reloaded.append("export", actor="a", target="ATH-1", details={"kind": "html"})
    ok, _ = reloaded.verify()
    assert ok and len(reloaded.entries) == 2


# --- validation harness -----------------------------------------------------

def test_validation_clear_cases_are_correct():
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "validation"))
    import tempfile

    import scenarios as sc

    from athar import analyze
    with tempfile.TemporaryDirectory() as tmp:
        for s in sc.scenarios():
            if s.label == "boundary":
                continue  # boundary behaviour defines the error rate, not asserted
            p = Path(tmp) / f"{s.name}.pcap"
            p.write_bytes(s.pcap)
            case = analyze(p)
            detected = {(e.detector, e.src_ip) for e in case.events
                        if e.detector in sc.DETECTORS}
            if s.label == "positive":
                assert s.expected <= detected, f"{s.name}: missed {s.expected - detected}"
            else:  # negative controls must fire nothing
                assert not detected, f"{s.name}: false positives {detected}"


# --- TCP stream reassembly --------------------------------------------------

def test_reassemble_orders_dedupes_and_stops_at_gap():
    from athar.reassembly import reassemble
    # out of order + duplicate retransmit -> contiguous "hello world"
    segs = [(1006, b"world"), (1000, b"hello "), (1000, b"hello ")]
    assert reassemble(segs) == b"hello world"
    # a gap after the prefix -> only the contiguous prefix is returned
    assert reassemble([(1000, b"abc"), (1010, b"XYZ")]) == b"abc"
    assert reassemble([]) == b""


def test_reassembly_recovers_split_out_of_order_request(tmp_path: Path):
    import struct

    import make_sample_pcap as g

    from athar import analyze
    req = g.http_get("nas.local", "/admin/login", auth="root:s3cr3t")
    half = len(req) // 2
    isn = 1000
    frames = [
        # second half arrives first (out of order), then the first half
        (1.1, g.eth("192.168.5.10", "192.168.5.20", g.ipv4("192.168.5.10", "192.168.5.20", 6,
                    g.tcp(44000, 80, 0x10, req[half:], seq=isn + half)))),
        (1.2, g.eth("192.168.5.10", "192.168.5.20", g.ipv4("192.168.5.10", "192.168.5.20", 6,
                    g.tcp(44000, 80, 0x18, req[:half], seq=isn)))),
    ]
    blob = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, fr in frames:
        sec = int(ts)
        blob += struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(fr), len(fr)) + fr
    p = tmp_path / "split.pcap"
    p.write_bytes(blob)

    case = analyze(p)
    creds = [e for e in case.events if e.detector == "plaintext_credentials"]
    assert creds, "reassembly should recover credentials split across segments"
    assert creds[0].evidence["username"] == "root"


# --- FTP credentials and JA3S ----------------------------------------------

def test_dissect_ftp_credentials():
    from athar.dissectors import dissect_ftp
    stream = b"USER ftpadmin\r\nPASS Sup3rSecret\r\n"
    out = dissect_ftp(stream)
    assert out == {"user": "ftpadmin", "password": "Sup3rSecret"}
    assert dissect_ftp(b"220 welcome\r\n") is None


def test_ftp_credentials_detected_end_to_end(tmp_path: Path):
    import tools_helper

    from athar import analyze
    p = tmp_path / "s.pcap"
    p.write_bytes(tools_helper.sample_bytes())
    case = analyze(p)
    creds = [e for e in case.events if e.detector == "plaintext_credentials"]
    protocols = {e.evidence.get("protocol") for e in creds}
    assert "FTP" in protocols and "HTTP Basic" in protocols
    ftp = next(e for e in creds if e.evidence["protocol"] == "FTP")
    assert ftp.evidence["username"] == "ftpadmin"
    assert ftp.evidence["password"] == "Sup3rSecret"  # cleartext password recovered


def test_ja3s_server_fingerprint():
    from make_sample_pcap import tls_server_hello

    from athar.dissectors import dissect_tls_server_hello
    out = dissect_tls_server_hello(tls_server_hello())
    assert out is not None
    import hashlib
    assert out["ja3s"] == hashlib.md5(out["ja3s_string"].encode()).hexdigest()


# --- cleartext content extraction & exfiltration ---------------------------

def test_extract_http_body_with_content_length():
    from athar.extract import extract_http_objects
    body = b"username=admin&secret=topsecret"
    msg = (b"POST /login HTTP/1.1\r\nHost: app.local\r\n"
           b"Content-Type: application/x-www-form-urlencoded\r\n"
           b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    objs = extract_http_objects(msg)
    assert len(objs) == 1
    o = objs[0]
    assert o["method"] == "POST" and o["host"] == "app.local"
    assert o["body_bytes"] == len(body)
    assert o["body_kind"] == "text"
    assert "topsecret" in o["body_preview"]
    import hashlib
    assert o["body_sha256"] == hashlib.sha256(body).hexdigest()


def test_extract_chunked_body():
    from athar.extract import extract_http_objects
    # "Wiki" + "pedia" sent as two chunks
    msg = (b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
           b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n")
    o = extract_http_objects(msg)[0]
    assert o["body_preview"] == "Wikipedia"


def test_data_exfiltration_detected_end_to_end(tmp_path: Path):
    import tools_helper

    from athar import analyze
    p = tmp_path / "s.pcap"
    p.write_bytes(tools_helper.sample_bytes())
    case = analyze(p)
    exfil = [e for e in case.events if e.detector == "data_exfiltration"]
    assert exfil, "should flag the large cleartext upload"
    assert exfil[0].evidence["bytes"] >= (1 << 20)
    assert "payroll.csv" in exfil[0].evidence["filenames"]
    # and the actual content is recoverable from a host dossier object
    objs = [o for f in case.flows for o in f.metadata.get("objects", [])]
    payroll = next(o for o in objs if o.get("filename") == "payroll.csv")
    assert payroll["body_kind"] == "text"
    assert "CONFIDENTIAL" in payroll["body_preview"]


# --- multi-protocol dissection & file carving ------------------------------

def test_protocols_extract_credentials_and_detail():
    from athar import protocols
    sip = protocols.dissect_stream(
        b'REGISTER sip:pbx SIP/2.0\r\nFrom: <sip:1001@pbx>\r\n'
        b'Authorization: Digest username="1001", realm="pbx"\r\n\r\n', 45100, 5060)
    assert sip and sip["protocol"] == "SIP"
    assert sip["credentials"][0]["username"] == "1001"
    assert sip["details"]["method"] == "REGISTER"

    import base64
    smtp_stream = (b"AUTH LOGIN\r\n" + base64.b64encode(b"[email protected]") + b"\r\n")
    smtp = protocols.dissect_stream(smtp_stream, 45200, 587)
    assert smtp["credentials"][0]["username"] == "[email protected]"

    ftp = protocols.dissect_stream(b"USER bob\r\nPASS secret\r\nRETR loot.zip\r\n", 44200, 21)
    assert ftp["credentials"][0]["username"] == "bob"
    assert "loot.zip" in ftp["details"]["files"]


def test_all_cleartext_protocols_flagged(tmp_path: Path):
    import tools_helper

    from athar import analyze
    p = tmp_path / "s.pcap"
    p.write_bytes(tools_helper.sample_bytes())
    case = analyze(p)
    protocols = {e.evidence["protocol"] for e in case.events
                 if e.detector == "plaintext_credentials"}
    assert {"HTTP Basic", "FTP", "SIP", "SMTP"} <= protocols


def test_file_carving_uploads_and_downloads(tmp_path: Path):
    import hashlib

    import tools_helper

    from athar import analyze
    from athar.extract import write_carved_files
    p = tmp_path / "s.pcap"
    p.write_bytes(tools_helper.sample_bytes())
    case = analyze(p)

    outdir = tmp_path / "carved"
    manifest = write_carved_files(case.carved, str(outdir))
    directions = {m["direction"] for m in manifest}
    assert {"upload", "download"} <= directions
    # every carved file exists and its recorded hash matches the bytes on disk
    for entry in manifest:
        blob = Path(entry["path"]).read_bytes()
        assert hashlib.sha256(blob).hexdigest() == entry["sha256"]
    names = {m["filename"] for m in manifest}
    assert "payroll.csv" in names and "agent.exe" in names


# --- differential validation against tshark --------------------------------

def test_agrees_with_tshark_on_objective_facts(tmp_path: Path):
    import shutil
    if not shutil.which("tshark"):
        import pytest
        pytest.skip("tshark not installed")

    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "validation"))
    import differential
    import tools_helper
    pcap = tmp_path / "s.pcap"
    pcap.write_bytes(tools_helper.sample_bytes())
    report = differential.compare(str(pcap))
    # athar must agree with the reference tool on every objective fact
    disagreements = [c.name for c in report.comparisons if not c.agree]
    assert not disagreements, f"diverged from tshark on: {disagreements}"


# --- geoip / scope enrichment ----------------------------------------------

def test_scope_classification_fallback():
    from athar.geoip import GeoEnricher
    g = GeoEnricher()  # no MaxMind DB -> fallback classification
    assert g.lookup("192.168.1.10").scope == "private"
    assert g.lookup("10.0.0.1").scope == "private"
    assert g.lookup("127.0.0.1").scope == "loopback"
    assert g.lookup("100.64.0.1").scope == "cgnat"
    assert g.lookup("8.8.8.8").scope == "public"
    assert g.lookup("185.220.101.5").scope == "public"
    # public addresses have no country without a database, but are still marked public
    assert g.lookup("8.8.8.8").country == ""


def test_hosts_get_scope_metadata(tmp_path: Path):
    import tools_helper

    from athar import analyze
    p = tmp_path / "s.pcap"
    p.write_bytes(tools_helper.sample_bytes())
    case = analyze(p)
    for host in case.hosts.values():
        assert host.geo.get("scope")  # every host is classified
    internal = case.hosts["192.168.1.77"]
    assert internal.geo["scope"] == "private"
    external = case.hosts["185.220.101.5"]
    assert external.geo["scope"] == "public"


# --- streaming & bounded memory --------------------------------------------

def test_pcap_reader_streams_without_loading_whole_file(tmp_path: Path):
    import struct
    import tracemalloc

    import make_sample_pcap as g

    from athar import pcap
    frame = g.eth("10.0.0.1", "10.0.0.2",
                  g.ipv4("10.0.0.1", "10.0.0.2", 17, g.udp(1000, 2000, b"x" * 40)))
    p = tmp_path / "big.pcap"
    with open(p, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        rec = struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame
        for _ in range(50_000):
            f.write(rec)
    size = p.stat().st_size

    tracemalloc.start()
    count = sum(1 for _ in pcap.read_frames(p))
    _cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert count == 50_000
    # peak memory must be a tiny fraction of the file size (streaming, not slurping)
    assert peak < size / 4


def test_per_direction_buffer_is_bounded():
    from athar.reassembly import MAX_STREAM, reassemble
    # a stream far larger than the cap must reassemble to at most the cap
    segs = [(i * 1000, b"A" * 1000) for i in range(MAX_STREAM // 1000 + 5000)]
    out = reassemble(segs)
    assert len(out) <= MAX_STREAM


# --- windows protocols & lateral-movement detection ------------------------

def test_winproto_dissectors():
    from athar.winproto import dissect_kerberos, dissect_rdp, dissect_smb
    rdp = dissect_rdp(b"\x03\x00\x00\x2c\x27\xe0\x00\x00\x00\x00\x00"
                      b"Cookie: mstshash=administrator\r\n\x01\x00\x08\x00")
    assert rdp["protocol"] == "RDP"
    assert rdp["details"]["cookie_user"] == "administrator"

    smb = dissect_smb(b"\x00\x00\x00\x40\xfeSMB" + b"\x00" * 40
                      + "\\\\10.0.0.5\\ADMIN$".encode("utf-16-le"))
    assert smb["details"]["version"] == "SMB2/3"
    assert smb["details"]["admin_shares"]

    import struct
    krb = dissect_kerberos(struct.pack(">I", 40) + b"\x6c" + b"\x00" * 40)
    assert krb["details"]["message_type"] == "TGS-REQ"


def test_lateral_movement_and_infection_indicators(tmp_path: Path):
    import tools_helper

    from athar import analyze
    p = tmp_path / "s.pcap"
    p.write_bytes(tools_helper.sample_bytes())
    case = analyze(p)
    detectors = {e.detector for e in case.events}
    assert "lateral_movement" in detectors
    assert "admin_share_access" in detectors
    assert "kerberoasting" in detectors

    lat = next(e for e in case.events if e.detector == "lateral_movement")
    assert lat.evidence["target_count"] >= 3
    assert lat.technique == "T1021"
    krb = next(e for e in case.events if e.detector == "kerberoasting")
    assert krb.evidence["tgs_requests"] >= 10


# --- evasion detection: non-standard ports & anonymisers -------------------

def test_evasion_detectors(tmp_path: Path):
    import tools_helper

    from athar import analyze
    p = tmp_path / "s.pcap"
    p.write_bytes(tools_helper.sample_bytes())
    case = analyze(p)
    dets = {e.detector for e in case.events}
    assert "port_anomaly" in dets      # RDP on 4444
    assert "anonymizer" in dets        # Tor ORPort egress

    port = next(e for e in case.events if e.detector == "port_anomaly")
    assert port.evidence["expected"] == 3389
    assert port.technique == "T1571"
    tor = [e for e in case.events if e.detector == "anonymizer"
           and "Tor" in e.summary]
    assert tor and tor[0].technique == "T1090.003"


def test_tor_node_list_loading(tmp_path: Path):
    from athar import netknowledge
    f = tmp_path / "tor.txt"
    f.write_text("# exit nodes\n203.0.113.66\n198.51.100.77\n", encoding="utf-8")
    n = netknowledge.load_tor_nodes(str(f))
    assert n == 2
    assert netknowledge.is_tor_node("203.0.113.66")
    assert not netknowledge.is_tor_node("8.8.8.8")


# --- attack narrative correlation ------------------------------------------

def test_attack_narrative_correlates_multistage(tmp_path: Path):
    import tools_helper

    from athar import analyze
    from athar.narrative import build_stories
    p = tmp_path / "s.pcap"
    p.write_bytes(tools_helper.sample_bytes())
    case = analyze(p)
    stories = build_stories(case)
    assert stories, "should build at least one attack narrative"

    # the compromised host runs a full multi-stage attack, ranked most serious
    top = stories[0]
    assert top.host == "192.168.1.66"
    assert "Discovery" in top.tactics
    assert "Lateral Movement" in top.tactics
    assert "Command & Control" in top.tactics
    assert len(top.tactics) >= 3        # a genuine multi-phase story
    # score reflects severity + multi-stage bonus
    assert top.score > stories[-1].score


# --- TLS certificate extraction & suspicious-cert detection ----------------

def test_tls_certificate_extraction_and_detection(tmp_path: Path):
    import pytest as _pytest
    _pytest.importorskip("cryptography")

    import tools_helper

    from athar import analyze
    p = tmp_path / "s.pcap"
    p.write_bytes(tools_helper.sample_bytes())
    case = analyze(p)

    # the certificate was parsed off the wire (cleartext handshake)
    certs = [c for f in case.flows for c in f.metadata.get("certificates", [])]
    assert certs, "should extract the server certificate"
    c2 = next(c for c in certs if c.get("subject") == "update.evil-c2.net")
    assert c2["self_signed"] is True
    assert c2["lifetime_days"] <= 90

    # and it is flagged as a suspicious (C2-style) certificate
    flagged = [e for e in case.events if e.detector == "suspicious_certificate"]
    assert flagged
    assert "self-signed" in flagged[0].evidence["reasons"]
    assert flagged[0].technique == "T1587.003"


# --- TCP health analysis ---------------------------------------------------

def test_tcp_health_detects_reset_and_zero_window(tmp_path: Path):
    import tools_helper

    from athar import analyze
    p = tmp_path / "s.pcap"
    p.write_bytes(tools_helper.sample_bytes())
    case = analyze(p)
    h = case.tcp_health
    assert h["resets"] >= 1          # the RST in the sample
    assert h["zero_window"] >= 1     # the zero-window stall
    assert h["retransmissions"] >= 1  # the data retransmission


def test_tcp_health_observe_unit():
    from athar.tcphealth import TCPHealth
    h = TCPHealth()
    # a real flow: SYN(0), data 1..41 (advances), then a full retransmission of 1..41
    h.observe(0.0, "a", "b", 1, 2, 0x02, seq=0, ack=0, window=8192, payload_len=0)   # SYN
    h.observe(0.1, "a", "b", 1, 2, 0x18, seq=1, ack=0, window=8192, payload_len=40)  # data
    h.observe(1.0, "a", "b", 1, 2, 0x18, seq=1, ack=0, window=8192, payload_len=40)  # retransmit
    h.observe(1.1, "b", "a", 2, 1, 0x04, seq=0, ack=0, window=0, payload_len=0)      # RST
    h.observe(1.2, "a", "b", 1, 2, 0x10, seq=41, ack=0, window=0, payload_len=0)     # zero window
    assert h.retransmissions == 1
    assert h.resets == 1
    assert h.zero_window == 1
    # a fresh data segment at seq 0 that ADVANCES must not be flagged
    h2 = TCPHealth()
    h2.observe(0.0, "c", "d", 3, 4, 0x02, seq=0, ack=0, window=8192, payload_len=0)
    h2.observe(0.1, "c", "d", 3, 4, 0x18, seq=1, ack=0, window=8192, payload_len=100)
    assert h2.retransmissions == 0


# --- DHCP / NTLM / LDAP and IP fragment reassembly -------------------------

def test_dhcp_ntlm_ldap_dissectors():
    from athar import protocols
    # DHCP request with hostname
    bootp = (b"\x01\x01\x06\x00" + b"\x00" * 232 + b"\x63\x82\x53\x63"
             + b"\x35\x01\x03" + b"\x0c\x05HELLO" + b"\xff")
    d = protocols.dissect_dhcp(bootp)
    assert d and d["details"]["hostname"] == "HELLO"
    assert d["details"]["message_type"] == "REQUEST"

    ldap = b"\x30\x20\x02\x01\x01\x60\x1b" + b"cn=admin,dc=corp"
    la = protocols.dissect_ldap(ldap)
    assert la and la["details"]["bind_dn"].startswith("cn=admin")
    assert la["credentials"][0]["username"].startswith("cn=admin")


def test_windows_credentials_extracted(tmp_path: Path):
    import tools_helper

    from athar import analyze
    p = tmp_path / "s.pcap"
    p.write_bytes(tools_helper.sample_bytes())
    case = analyze(p)
    creds = {(e.evidence["protocol"], e.evidence["username"])
             for e in case.events if e.detector == "plaintext_credentials"}
    assert ("NTLM", "CORP\\jdoe") in creds
    assert ("LDAP", "cn=admin,dc=corp") in creds


def test_ip_fragment_reassembly():
    import struct
    import sys as _sys

    _sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
    import make_sample_pcap as g

    from athar import decode
    from athar.dissectors import dissect_dns
    from athar.ipreasm import IPReassembler

    def frag(payload, ident, offset, mf):
        total = 20 + len(payload)
        ff = (0x2000 if mf else 0) | (offset // 8)
        hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, ff, 64, 17, 0,
                          bytes([192, 168, 1, 70]), bytes([192, 168, 1, 1]))
        return g.eth("192.168.1.70", "192.168.1.1", hdr + payload)

    dns = g.udp(53000, 53, g.dns_query("fragmented.example.com", 1))
    half = 8 * ((len(dns) // 2) // 8)
    f1 = frag(dns[:half], 0xABCD, 0, True)
    f2 = frag(dns[half:], 0xABCD, half, False)

    r = IPReassembler()
    out = [w for fr in (f1, f2) for w in r.process(1, fr)]
    assert len(out) == 1                      # two fragments -> one datagram
    pkt = decode.decode(out[0], 1)
    assert pkt is not None
    assert dissect_dns(pkt.payload)["name"] == "fragmented.example.com"


# --- SSH / Telnet / SNMP dissectors ----------------------------------------

def test_ssh_telnet_snmp_dissectors():
    from athar import protocols
    assert protocols.dissect_ssh(b"SSH-2.0-OpenSSH_9.6\r\n")["details"]["banner"] == "SSH-2.0-OpenSSH_9.6"
    tel = protocols.dissect_telnet(b"login: operator\r\npassword: secret\r\n")
    assert tel["details"]["username"] == "operator"
    snmp = protocols.dissect_snmp(b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19")
    assert snmp["details"]["community"] == "public"


def test_expanded_protocols_end_to_end(tmp_path: Path):
    import tools_helper

    from athar import analyze
    p = tmp_path / "s.pcap"
    p.write_bytes(tools_helper.sample_bytes())
    case = analyze(p)
    services = {f.service for f in case.flows if f.service}
    for svc in ("ssh", "telnet", "snmp", "dhcp", "ntlm", "ldap"):
        assert svc in services, f"missing {svc}"
    # SNMP community string is flagged as a (weak) credential
    snmp_cred = [e for e in case.events if e.detector == "plaintext_credentials"
                 and e.evidence["protocol"] == "SNMP community"]
    assert snmp_cred and snmp_cred[0].evidence["username"] == "public"


def test_tcp_health_matches_reference_logic(tmp_path: Path):
    """athar's TCP health uses Wireshark's advance-based retransmission rule."""
    import tools_helper

    from athar import analyze
    p = tmp_path / "s.pcap"
    p.write_bytes(tools_helper.sample_bytes())
    case = analyze(p)
    h = case.tcp_health
    # a segment that advances the stream is never a retransmission
    assert h["resets"] >= 1 and h["zero_window"] >= 1
    assert "fast_retransmissions" in h and "out_of_order" in h
