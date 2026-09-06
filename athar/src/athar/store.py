"""A queryable SQLite forensic store.

Each analysed capture is persisted as a *case* in a normalised schema, so many
cases can share one database and be searched with ordinary SQL -- "every host
that leaked credentials", "the loudest talkers across all captures", and so on.
The store is lossless: a saved case can be loaded back and re-rendered without
the original pcap, which means captures can be archived while the investigation
stays live.

Only the standard-library :mod:`sqlite3` is used; there is no new dependency.
"""

from __future__ import annotations

import datetime as _dt
import json
import sqlite3
from collections import defaultdict
from pathlib import Path

from .backend import backend
from .evidence import Provenance
from .model import Case, Event, Flow, Host, Severity

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    case_id    TEXT PRIMARY KEY,
    source     TEXT NOT NULL,
    started    REAL,
    ended      REAL,
    packets    INTEGER,
    bytes      INTEGER,
    backend    TEXT,
    created_at TEXT NOT NULL,
    provenance TEXT
);
CREATE TABLE IF NOT EXISTS hosts (
    case_id    TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    ip         TEXT NOT NULL,
    mac        TEXT,
    role       TEXT,
    packets    INTEGER,
    bytes      INTEGER,
    first_seen REAL,
    last_seen  REAL,
    services   TEXT,
    protocols  TEXT,
    flagged    INTEGER,
    PRIMARY KEY (case_id, ip)
);
CREATE TABLE IF NOT EXISTS flows (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id    TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    src_ip     TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER,
    proto      TEXT, service TEXT, packets INTEGER, bytes INTEGER,
    first_seen REAL, last_seen REAL, metadata TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id   TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    ts        REAL, severity TEXT, detector TEXT, technique TEXT,
    src_ip    TEXT, dst_ip TEXT, title TEXT, summary TEXT, evidence TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_case ON events(case_id);
CREATE INDEX IF NOT EXISTS idx_events_detector ON events(detector);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_hosts_flagged ON hosts(case_id, flagged);
CREATE INDEX IF NOT EXISTS idx_flows_case ON flows(case_id);
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Open *db_path*, enabling foreign keys and ensuring the schema exists."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(_SCHEMA)
    return conn


def save_case(case: Case, db_path: str | Path) -> str:
    """Persist *case* into the store and return its case id.

    Re-saving the same capture replaces the previous rows, so analysis is
    idempotent -- the database never accumulates duplicates.
    """
    cid = case.case_id
    conn = connect(db_path)
    try:
        with conn:  # a single transaction
            conn.execute("DELETE FROM cases WHERE case_id = ?", (cid,))
            conn.execute(
                "INSERT INTO cases (case_id, source, started, ended, packets, bytes, "
                "backend, created_at, provenance) VALUES (?,?,?,?,?,?,?,?,?)",
                (cid, case.source, case.started, case.ended, case.total_packets,
                 case.total_bytes, backend(),
                 _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
                 json.dumps(case.provenance.as_dict()) if case.provenance else None),
            )
            conn.executemany(
                "INSERT INTO hosts (case_id, ip, mac, role, packets, bytes, first_seen, "
                "last_seen, services, protocols, flagged) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                [(cid, h.ip, h.mac, h.role, h.packets, h.bytes, h.first_seen, h.last_seen,
                  json.dumps(sorted(h.services)), json.dumps(sorted(h.protocols)),
                  int(h.flagged)) for h in case.hosts.values()],
            )
            conn.executemany(
                "INSERT INTO flows (case_id, src_ip, dst_ip, src_port, dst_port, proto, "
                "service, packets, bytes, first_seen, last_seen, metadata) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                [(cid, f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.proto, f.service,
                  f.packets, f.bytes, f.first_seen, f.last_seen, json.dumps(f.metadata))
                 for f in case.flows],
            )
            conn.executemany(
                "INSERT INTO events (case_id, ts, severity, detector, technique, src_ip, "
                "dst_ip, title, summary, evidence) VALUES (?,?,?,?,?,?,?,?,?,?)",
                [(cid, e.ts, e.severity.value, e.detector, e.technique, e.src_ip, e.dst_ip,
                  e.title, e.summary, json.dumps(e.evidence)) for e in case.events],
            )
        return cid
    finally:
        conn.close()


def list_cases(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    """Return one row per stored case, newest first."""
    return conn.execute(
        "SELECT case_id, source, packets, created_at, "
        "(SELECT COUNT(*) FROM events e WHERE e.case_id = c.case_id) AS findings "
        "FROM cases c ORDER BY created_at DESC"
    ).fetchall()


def latest_case_id(conn: sqlite3.Connection) -> str | None:
    row = conn.execute(
        "SELECT case_id FROM cases ORDER BY created_at DESC LIMIT 1"
    ).fetchone()
    return row["case_id"] if row else None


def load_case(conn: sqlite3.Connection, case_id: str) -> Case:
    """Reconstruct a full :class:`Case` from the store, ready to re-render."""
    row = conn.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
    if row is None:
        raise KeyError(f"no case {case_id!r} in store")

    cols = row.keys()
    prov_raw = row["provenance"] if "provenance" in cols else None
    provenance = Provenance(**json.loads(prov_raw)) if prov_raw else None
    case = Case(source=row["source"], started=row["started"] or 0.0,
                ended=row["ended"] or 0.0, total_packets=row["packets"] or 0,
                total_bytes=row["bytes"] or 0, provenance=provenance)

    for h in conn.execute("SELECT * FROM hosts WHERE case_id = ?", (case_id,)):
        case.hosts[h["ip"]] = Host(
            ip=h["ip"], mac=h["mac"] or "", role=h["role"] or "endpoint",
            packets=h["packets"] or 0, bytes=h["bytes"] or 0,
            first_seen=h["first_seen"] or 0.0, last_seen=h["last_seen"] or 0.0,
            services=set(json.loads(h["services"] or "[]")),
            protocols=set(json.loads(h["protocols"] or "[]")),
            flagged=bool(h["flagged"]),
        )

    peers: dict[str, set[str]] = defaultdict(set)
    for f in conn.execute("SELECT * FROM flows WHERE case_id = ?", (case_id,)):
        case.flows.append(Flow(
            src_ip=f["src_ip"], dst_ip=f["dst_ip"], src_port=f["src_port"],
            dst_port=f["dst_port"], proto=f["proto"], service=f["service"] or "",
            packets=f["packets"] or 0, bytes=f["bytes"] or 0,
            first_seen=f["first_seen"] or 0.0, last_seen=f["last_seen"] or 0.0,
            metadata=json.loads(f["metadata"] or "{}"),
        ))
        peers[f["src_ip"]].add(f["dst_ip"])
        peers[f["dst_ip"]].add(f["src_ip"])

    for ip, host in case.hosts.items():  # rebuild peer sets from the flow table
        host.talked_to = peers.get(ip, set())

    for e in conn.execute("SELECT * FROM events WHERE case_id = ?", (case_id,)):
        case.events.append(Event(
            ts=e["ts"] or 0.0, severity=Severity(e["severity"]), detector=e["detector"],
            title=e["title"] or "", summary=e["summary"] or "",
            src_ip=e["src_ip"] or "", dst_ip=e["dst_ip"] or "",
            technique=e["technique"] or "", evidence=json.loads(e["evidence"] or "{}"),
        ))

    return case
