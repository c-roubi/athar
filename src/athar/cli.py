"""Command-line interface for athar."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, analyze, intel, store
from .analyze import classify_hosts
from .audit import AuditLog
from .backend import backend
from .evidence import Provenance
from .extract import write_carved_files
from .model import Case, Severity
from .reporting import ChainOfCustody, render_csv, render_data, render_html, render_json
from .tlsdecrypt import load_keylog

_SEV_COLOR = {
    Severity.CRITICAL: "\033[91m", Severity.HIGH: "\033[93m",
    Severity.MEDIUM: "\033[33m", Severity.LOW: "\033[96m", Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="athar",
        description="Analyse a pcap capture and produce a forensic report.",
    )
    parser.add_argument("capture", nargs="?", help="path to a .pcap file")
    parser.add_argument("--html", metavar="FILE", help="write the interactive HTML report")
    parser.add_argument("--json", metavar="FILE", help="write the full JSON model")
    parser.add_argument("--csv", metavar="FILE", help="write findings as CSV")
    parser.add_argument("--data", metavar="FILE",
                        help="write the dashboard data model as JSON")
    parser.add_argument("--db", metavar="FILE",
                        help="persist the analysed case into a SQLite forensic store")
    parser.add_argument("--from-db", metavar="FILE",
                        help="load a stored case instead of analysing a capture")
    parser.add_argument("--case", metavar="ID",
                        help="case id to load with --from-db (default: most recent)")
    parser.add_argument("--list", metavar="FILE", dest="list_db",
                        help="list the cases stored in a database and exit")
    parser.add_argument("--iocs", metavar="FILE",
                        help="match observed indicators against a JSON threat-intel feed")
    parser.add_argument("--keylog", metavar="FILE",
                        help="NSS key-log file to decrypt matching TLS sessions")
    parser.add_argument("--geoip-city", metavar="MMDB", dest="geoip_city",
                        help="MaxMind City database for geolocation")
    parser.add_argument("--geoip-asn", metavar="MMDB", dest="geoip_asn",
                        help="MaxMind ASN database for network attribution")
    parser.add_argument("--tor-nodes", metavar="FILE", dest="tor_nodes",
                        help="file of known Tor relay IPs to flag egress to")
    sig = parser.add_argument_group("digital signatures")
    sig.add_argument("--gen-key", nargs=2, metavar=("PRIV", "PUB"), dest="gen_key",
                     help="generate an Ed25519 examiner keypair and exit")
    sig.add_argument("--sign-key", metavar="PRIV", dest="sign_key",
                     help="sign the chain-of-custody manifest with this private key")
    sig.add_argument("--verify-sig", nargs=3, dest="verify_sig",
                     metavar=("FILE", "SIG", "PUB"),
                     help="verify FILE against signature SIG with public key PUB, and exit")
    parser.add_argument("--coc", metavar="FILE",
                        help="write a chain-of-custody manifest hashing every output")
    parser.add_argument("--extract", metavar="DIR",
                        help="carve reconstructed cleartext files into DIR")
    parser.add_argument("--audit", metavar="FILE",
                        help="append this run to a tamper-evident audit log")
    parser.add_argument("--verify-audit", metavar="FILE", dest="verify_audit",
                        help="verify an audit log's integrity and exit")
    ev = parser.add_argument_group("case metadata (recorded for chain of custody)")
    ev.add_argument("--examiner", default="", help="examiner name")
    ev.add_argument("--org", default="", help="organization")
    ev.add_argument("--case-number", default="", help="case / reference number")
    ev.add_argument("--authority", default="", help="legal authority (e.g. warrant ref)")
    ev.add_argument("--notes", default="", help="free-text examiner notes")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    parser.add_argument("--version", action="version", version=f"athar {__version__}")
    args = parser.parse_args(argv)

    if args.list_db:
        return _list_cases(args.list_db)

    if args.verify_audit:
        return _verify_audit(args.verify_audit)

    if args.gen_key:
        return _gen_key(*args.gen_key)

    if args.verify_sig:
        return _verify_sig(*args.verify_sig)

    try:
        case = _load_or_analyse(parser, args)
    except (OSError, ValueError, KeyError) as exc:
        print(f"athar: {exc}", file=sys.stderr)
        return 1

    _print_summary(case, color=not args.no_color, live=not args.from_db)

    if args.db and not args.from_db:
        cid = store.save_case(case, args.db)
        print(f"\nstored case {cid} in {args.db}")
    _write_reports(case, args)
    if args.audit:
        _append_audit(case, args)
    return 0


def _load_or_analyse(parser: argparse.ArgumentParser, args: argparse.Namespace) -> Case:
    feed = intel.load_feed(args.iocs) if args.iocs else None
    if args.from_db:
        conn = store.connect(args.from_db)
        try:
            case_id = args.case or store.latest_case_id(conn)
            if case_id is None:
                raise KeyError(f"no cases stored in {args.from_db}")
            case = store.load_case(conn, case_id)
        finally:
            conn.close()
        if feed:  # re-run intel against the reloaded case
            case.events += intel.match(case, feed)
            classify_hosts(case)
        return case
    if not args.capture:
        parser.error("provide a capture file, or --from-db to load a stored case")
    meta = Provenance(examiner=args.examiner, organization=args.org,
                      case_number=args.case_number, authority=args.authority, notes=args.notes)
    keylog = load_keylog(args.keylog) if args.keylog else None
    if args.tor_nodes:
        from .netknowledge import load_tor_nodes
        n = load_tor_nodes(args.tor_nodes)
        print(f"loaded {n} Tor relay addresses")
    geo = None
    if args.geoip_city or args.geoip_asn:
        from .geoip import GeoEnricher
        geo = GeoEnricher(args.geoip_city, args.geoip_asn)
    if keylog is not None:
        from .tlsdecrypt import HAVE_CRYPTO
        if not HAVE_CRYPTO:
            print("athar: --keylog needs the 'cryptography' package "
                  "(pip install athar[tls]); TLS will stay encrypted", file=sys.stderr)
    return analyze(args.capture, feed=feed, provenance=meta, keylog=keylog, geo=geo)


def _write_reports(case: Case, args: argparse.Namespace) -> None:
    coc = ChainOfCustody(case.case_id, case.provenance) if args.coc else None

    def emit(path: str, text: str, kind: str, label: str) -> None:
        Path(path).write_text(text, encoding="utf-8")
        if coc is not None:
            coc.record(path, kind)
        print(f"{label} written to {path}")

    if args.html:
        emit(args.html, render_html(case), "html", "HTML report")
    if args.json:
        emit(args.json, render_json(case), "json", "JSON")
    if args.csv:
        emit(args.csv, render_csv(case), "csv", "CSV")
    if args.data:
        emit(args.data, render_data(case), "data", "dashboard data")
    if args.extract:
        manifest = write_carved_files(case.carved, args.extract)
        if manifest:
            import json as _json
            index = Path(args.extract) / "manifest.json"
            index.write_text(_json.dumps(manifest, indent=2), encoding="utf-8")
            if coc is not None:
                for entry in manifest:
                    coc.record(entry["path"], f"carved:{entry['direction']}")
                coc.record(str(index), "carve-manifest")
            up = sum(1 for m in manifest if m["direction"] == "upload")
            down = len(manifest) - up
            print(f"carved {len(manifest)} file(s) to {args.extract} "
                  f"({up} uploaded, {down} downloaded)")
        else:
            print("no cleartext files to carve")
    if coc is not None:
        coc.write(args.coc)
        print(f"chain-of-custody manifest written to {args.coc}")
        if args.sign_key:
            _sign_artifact(args.coc, args.sign_key)


def _sign_artifact(path: str, key_path: str) -> None:
    from .signing import SigningError, sign_file
    try:
        record = sign_file(path, key_path)
    except SigningError as exc:
        print(f"athar: {exc}", file=sys.stderr)
        return
    sig_path = f"{path}.sig"
    import json as _json
    Path(sig_path).write_text(_json.dumps(record, indent=2), encoding="utf-8")
    print(f"signed {path} -> {sig_path}")


def _append_audit(case: Case, args: argparse.Namespace) -> None:
    log = AuditLog.load(args.audit)
    actor = args.examiner or "unknown"
    prov = case.provenance
    log.append("analyze", actor=actor, target=case.case_id,
               details={"source": case.source,
                        "source_sha256": prov.source_sha256 if prov else "",
                        "findings": len(case.events)})
    for kind, path in (("html", args.html), ("json", args.json),
                       ("csv", args.csv), ("data", args.data), ("coc", args.coc)):
        if path:
            log.append("export", actor=actor, target=case.case_id,
                       details={"kind": kind, "path": path})
    log.write(args.audit)
    print(f"audit log updated ({len(log.entries)} entries) in {args.audit}")


def _verify_audit(path: str) -> int:
    try:
        log = AuditLog.load(path)
    except (OSError, ValueError) as exc:
        print(f"athar: {exc}", file=sys.stderr)
        return 1
    ok, bad = log.verify()
    if ok:
        print(f"audit log OK — {len(log.entries)} entries, chain intact")
        return 0
    print(f"audit log TAMPERED — chain breaks at entry {bad}", file=sys.stderr)
    return 1


def _gen_key(priv: str, pub: str) -> int:
    from .signing import SigningError, generate_keypair
    try:
        generate_keypair(priv, pub)
    except SigningError as exc:
        print(f"athar: {exc}", file=sys.stderr)
        return 1
    print(f"wrote private key {priv} and public key {pub}")
    print("keep the private key secret; distribute only the public key")
    return 0


def _verify_sig(file: str, sig: str, pub: str) -> int:
    import json as _json

    from .signing import SigningError, verify_file
    try:
        record = _json.loads(Path(sig).read_text())
        ok = verify_file(file, record["signature"], pub)
    except (SigningError, OSError, ValueError, KeyError) as exc:
        print(f"athar: {exc}", file=sys.stderr)
        return 1
    if ok:
        print(f"signature OK — {file} is intact and signed by the holder of {pub}")
        return 0
    print(f"signature INVALID — {file} does not match {sig}", file=sys.stderr)
    return 1


def _list_cases(db_path: str) -> int:
    try:
        conn = store.connect(db_path)
    except (OSError, ValueError) as exc:
        print(f"athar: {exc}", file=sys.stderr)
        return 1
    try:
        rows = store.list_cases(conn)
    finally:
        conn.close()
    if not rows:
        print(f"no cases stored in {db_path}")
        return 0
    print(f"{'case id':14} {'findings':>8}  {'packets':>9}  {'stored':20} source")
    for r in rows:
        print(f"{r['case_id']:14} {r['findings']:>8}  {r['packets']:>9}  "
              f"{r['created_at']:20} {r['source']}")
    return 0


def _print_summary(case: Case, color: bool, live: bool) -> None:
    def paint(text: str, sev: Severity) -> str:
        return f"{_SEV_COLOR[sev]}{text}{_RESET}" if color else text

    origin = f"decoded via {backend()} core" if live else "loaded from store"
    print(f"case {case.case_id}  ({case.source})")
    print(f"  {case.total_packets} packets  |  {len(case.hosts)} hosts  |  "
          f"{len(case.flows)} conversations  |  {len(case.events)} findings")
    print(f"  {origin}")
    if not case.events:
        print("  no suspicious activity detected")
        return
    print()
    for ev in case.sorted_events():
        tag = paint(f"[{ev.severity.value:>8}]", ev.severity)
        print(f"  {tag} {ev.title}: {ev.summary}{('  ' + ev.technique) if ev.technique else ''}")


if __name__ == "__main__":
    raise SystemExit(main())
