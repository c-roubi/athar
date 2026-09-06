# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project adheres to
semantic versioning.

## [0.24.0] - 2026-08-31

### Changed
- The React/TypeScript dashboard is now comprehensive: it renders the per-host
  attack narratives (kill-chain), a TCP-health panel, the evidence & chain-of-
  custody block, and an enriched dossier (network scope/geo, TLS certificates,
  protocol sessions, reconstructed content, JA3/JA3S). A subtle accent was added
  to the theme. The bundled sample case was regenerated to include every feature.
- Refreshed the GitHub launch pack for the mature project.

## [0.23.0] - 2026-08-30

### Added / Changed
- TCP health now uses Wireshark's actual sequence-analysis logic with an RTT
  threshold: a data/SYN/FIN segment that does not advance the sequence number is
  classified as retransmission, fast retransmission (>=3 duplicate ACKs), or
  out-of-order (arrived within the initial-RTT threshold, default 3 ms). The
  TCP acknowledgement number is now decoded (Python and native core at parity).
  On the sample, athar matches tshark **exactly** on retransmissions (7), resets
  (1) and zero-window (1).
- The differential harness now also cross-checks TCP resets, zero-window and
  retransmissions against tshark — athar agrees on all seven objective facts.
- Three more protocol dissectors: SSH (version banner), Telnet (cleartext login),
  and SNMP (community string, flagged as a weak credential). athar now dissects
  15 protocols.
- Expanded the service-port and C2/Tor port knowledge (Metasploit/Meterpreter
  defaults, more Tor ORPorts) and a broader known-port reference map.

## [0.22.0] - 2026-08-30

### Added
- TCP health analysis (`tcphealth.py`): counts retransmissions, resets and
  zero-window events per capture and per flow (what Wireshark shows as
  tcp.analysis.flags). On the sample, resets and zero-window match tshark exactly.
  The TCP window size is now decoded (Python and native C++ core at parity).
- Three more protocol dissectors (`protocols.py`): DHCP (hostname/IP for device
  inventory), NTLM (domain\user from the AUTHENTICATE message), and LDAP (bind
  DN). NTLM and LDAP logins feed the credential findings.
- IPv4 fragment reassembly (`ipreasm.py`): fragmented datagrams are reassembled
  before decoding, so a split DNS/UDP payload is dissected correctly.
- Tests for TCP health, the new dissectors, Windows credential extraction, and
  fragment reassembly.

### Notes
- IP defragmentation runs on the pure-Python decode path (pcapng always; classic
  pcap when the native core isn't built). The native fast-path does not yet
  defragment. TLS 1.2 certificate parsing is unaffected.

## [0.21.0] - 2026-08-30

### Added
- TLS certificate extraction (`tlscerts.py`): the server certificate is parsed
  off the cleartext handshake (subject, issuer, validity window, SAN, self-signed
  flag) even for sessions athar can't decrypt — closing part of the depth gap
  against Wireshark and adding a strong C2 signal.
- `suspicious_certificate` detector (T1587.003): flags self-signed or short-lived
  certificates on external hosts, a hallmark of throwaway malware C2 infra.
- Certificates appear in the host dossier; the sample's C2 now serves a
  self-signed, 14-day certificate that is detected.
- Test for certificate parsing and detection.

### Notes
- Certificate parsing covers TLS 1.2 (cleartext Certificate message). In TLS 1.3
  the certificate is encrypted, so it is only available when a key-log decrypts
  the session — the same limitation Wireshark has.

## [0.20.0] - 2026-08-30

### Added
- Attack-narrative correlation (`narrative.py`): scattered findings are grouped
  by the internal host they implicate, mapped to ATT&CK tactics (Discovery →
  Credential Access → Lateral Movement → Command & Control → Exfiltration), and
  scored, producing a per-host kill-chain story ranked most-serious-first. This
  turns a list of alerts into a readable account of what each host did.
- The HTML report now leads with an "Attack narratives" section (kill-chain
  phases + per-stage findings); the story model is in the case data export.
- Test asserting the compromised host's multi-stage story is correlated and
  ranked highest.

## [0.19.0] - 2026-08-30

### Added
- Evasion / suspicious-egress detection (`netknowledge.py` + detectors):
  - `port_anomaly` (T1571): a known service (RDP/SSH/SMB/...) running on a
    non-standard port — RDP is now identified by its X.224 signature, not just
    port 3389, so evasion is caught.
  - `anonymizer` (T1090.003): egress to Tor relays (a supplied node list via
    `--tor-nodes`, or a Tor ORPort) and to common C2 default ports (incl. Cobalt
    Strike 50050, 4444, 8443).
- Sample capture gains RDP-on-4444 and Tor-ORPort egress so both fire.
- Tests for the evasion detectors and Tor node-list loading.

## [0.18.0] - 2026-08-30

### Added
- Windows/enterprise binary-protocol dissectors (`winproto.py`): RDP (X.224
  connection request, `mstshash` cookie username), SMB/SMB2 (version, tree
  connects, hidden admin shares C$/ADMIN$/IPC$), and Kerberos (AS/TGS message
  type). They read only the cleartext negotiation, never decrypting.
- Behavioural detectors for compromise and lateral movement:
  - `lateral_movement` (T1021): one internal host fanning out over RDP/SMB to
    several internal peers.
  - `admin_share_access` (T1021.002): access to hidden administrative shares.
  - `kerberoasting` (T1558.003): a burst of Kerberos service-ticket requests.
- Sample capture now includes a lateral-movement chain (RDP + SMB to four hosts,
  ADMIN$ access, and a TGS-REQ burst) so the full attack story is visible.
- Tests for the dissectors and the new detectors.

### Notes
- These are *network-behavioural* indicators of compromise — athar infers that a
  host is acting like it's infected from its traffic; it does not scan endpoints
  for malware (that needs host access).

## [0.17.0] - 2026-08-30

### Added / Changed
- Streaming capture readers: both the pcap and pcapng readers now parse record by
  record straight from disk instead of loading the whole file, so memory stays
  flat regardless of capture size (200k packets from a 20 MB file read at ~0.01 MB
  peak in testing).
- Per-direction reassembly buffering is now bounded (`reassembly.MAX_STREAM`,
  8 MiB), so a single huge transfer can't grow memory without limit — the biggest
  win for large real-world evidence.
- Tests asserting the reader streams (peak memory << file size) and that the
  per-direction buffer is capped.

### Notes
- Full out-of-core processing of multi-GB captures is improved but not unlimited;
  very large numbers of concurrent flows still accumulate per-flow state.

## [0.16.0] - 2026-08-30

### Added
- Recovered passwords are now surfaced alongside usernames for every cleartext
  login (HTTP Basic, FTP, SMTP AUTH LOGIN/PLAIN, POP3, IMAP) — the finding shows
  `login 'user' / 'password' to target`, and the password is in the evidence
  record and exports. SIP Digest exposes the username only (the password is
  hashed), which is reported honestly.

### Notes
- Passwords appear only when they actually traversed the wire in the clear (or in
  a TLS session decrypted with supplied keys); this is the point of the finding.

## [0.15.0] - 2026-08-30

### Added
- GeoIP / ASN enrichment (`geoip.py`, `--geoip-city` / `--geoip-asn`): with a
  MaxMind GeoLite2/GeoIP2 database and the optional `geoip2` reader, external
  addresses are resolved to country/city/ASN/organization. A dependency-free
  fallback always classifies every host's network scope (private, loopback,
  link-local, CGNAT, multicast, reserved, public). All lookups are offline.
- Network scope and geolocation appear in the host dossier and the case data.
- Tests for scope classification and per-host enrichment.

## [0.14.0] - 2026-08-30

### Added
- Differential validation harness (`validation/differential.py`): runs athar and
  tshark (Wireshark's CLI) over the same capture and compares the objective facts
  they must agree on — packet count, IP set, DNS query names, TCP conversation
  count — reporting any divergence. Agreement with an independently-developed,
  widely-accepted tool is strong evidence of correct parsing.
- A test that cross-checks athar against tshark on the sample capture (skipped if
  tshark is absent). On the sample, all facts agree.

### Notes
- This is a cross-checking aid, not formal validation; testing on labelled
  real-world corpora is still required before evidentiary use.

## [0.13.0] - 2026-08-30

### Added
- Digital signatures for evidence (`signing.py`): an examiner can generate an
  Ed25519 keypair (`--gen-key`), sign the chain-of-custody manifest (`--sign-key`,
  writing a detached `.sig`), and anyone can verify it (`--verify-sig`). This
  binds the artefact hashes to the examiner's key, so a third party can confirm
  both integrity and attestation. Tampering or a wrong key fails verification.
- Signing/verification tests (roundtrip, tamper detection, wrong-key rejection).

### Notes
- Uses Ed25519 via the optional `cryptography` dependency (`pip install
  athar[tls]`); the rest of athar stays dependency-free.

## [0.12.0] - 2026-08-30

### Added
- TLS decryption from an NSS key-log file (`tlsdecrypt.py`, `--keylog FILE`):
  when an investigator supplies the per-session secrets (the same
  `SSLKEYLOGFILE` Wireshark uses, lawfully obtained from an endpoint), athar
  derives the record keys and decrypts the session, then runs the normal HTTP
  content, file-carving and credential extraction on the recovered plaintext.
  Supports TLS 1.2 (PRF) and TLS 1.3 (HKDF-Expand-Label) with AES-GCM suites.
- Decrypted logins are flagged as `HTTPS (decrypted)` credentials; decrypted
  flows are marked in the dossier.
- Optional `cryptography` dependency (`pip install athar[tls]`), used only for
  this feature; the rest of athar stays dependency-free.
- Tests driving real in-memory TLS 1.2 and 1.3 handshakes (via `ssl.MemoryBIO`
  with `keylog_filename`) and asserting end-to-end recovery of the plaintext.

### Notes
- athar does not break TLS: decryption requires investigator-supplied,
  lawfully-obtained session secrets. Without them, TLS stays opaque (JA3/JA3S,
  SNI, destination and volume only).

## [0.11.0] - 2026-08-30

### Added
- File carving (`--extract DIR`): reconstructed cleartext files — both uploads
  (HTTP request bodies) and downloads (HTTP response bodies) — are written to
  disk with a hashed `manifest.json`, and each carved file joins the
  chain-of-custody manifest.
- Multi-protocol session dissectors (`protocols.py`): FTP (login + transferred
  filenames), SIP (method, parties, user-agent, auth username), SMTP (envelope +
  AUTH LOGIN/PLAIN credentials), and POP3/IMAP logins. All feed the unified
  plaintext-credentials detector, so cleartext logins on any of them are flagged
  CRITICAL, and session details appear in the host dossier.
- HTTP responses are now dissected too, so downloads are reconstructed (not just
  uploads). Sample capture gains an HTTP download, a SIP REGISTER, and an SMTP
  AUTH LOGIN session.

### Notes
- All of this applies only to unencrypted traffic; TLS-wrapped variants (FTPS,
  SIPS, SMTPS, HTTPS) remain opaque and are never decrypted.

## [0.10.0] - 2026-08-30

### Added
- Cleartext content extraction (`extract.py`): reconstructs HTTP request/response
  bodies from the reassembled stream (honouring Content-Length and chunked
  encoding), so an examiner can see *what* was sent -- form data, JSON, and
  uploaded files -- with a SHA-256, size, and text/hex preview per object. Only
  ever applied to unencrypted HTTP; TLS payloads are never touched.
- `data_exfiltration` detector (T1048): flags a host pushing a large volume of
  body data to one destination over cleartext HTTP, using the declared
  Content-Length as the measure of data sent.
- Reconstructed objects appear in the host dossier (HTML report and dashboard);
  the sample capture now includes a ~1.3 MB cleartext file upload.

### Changed
- TCP reassembly cap raised to 8 MiB so realistic uploads reconstruct in full.

## [0.9.0] - 2026-08-29

### Added
- FTP cleartext credential dissection (`USER`/`PASS`) over the reassembled control
  stream; the plaintext-credentials detector now covers HTTP Basic and FTP.
- JA3S server-side TLS fingerprinting from the ServerHello, shown in the host
  dossier (HTML report and React dashboard).
- Sample capture now includes an FTP login and a TLS ServerHello.

### Changed
- Credential detection consumes a unified `Signals.credentials` list, so new
  cleartext-auth protocols can be added without touching the detector.

## [0.8.0] - 2026-08-29

### Added
- True TCP stream reassembly (`reassembly.py`): application-layer dissection now
  runs on the reordered, de-duplicated byte stream of each connection direction
  rather than on individual packets, so requests split across segments, arriving
  out of order, or retransmitted are handled. Sequence numbers are compared
  modulo 2**32 to tolerate the random ISN and wrap-around.
- TCP sequence number is now decoded (Python and the native C++ core, kept at
  byte-for-byte parity) and carried on `Packet`.

### Changed
- The engine buffers TCP payloads per direction during the pass and dissects the
  reassembled streams afterwards; DNS (UDP) is still dissected per packet.

## [0.7.0] - 2026-08-29

### Added
- Detector validation harness (`validation/`): labelled synthetic scenarios
  (clear positives, benign controls, near-threshold boundary cases) that measure
  per-detector precision, recall and false-positive rate, addressing the Daubert
  "known error rate" factor. Publishes `docs/validation-report.{md,json}`.
- Tamper-evident audit log (`audit.py`): a hash-chained, append-only record of
  every analyse/export action; `AuditLog.verify()` detects any after-the-fact
  edit. CLI `--audit FILE` appends to it and `--verify-audit FILE` checks it.
- Tests for the audit chain (append, tamper detection, file round-trip) and a
  validation gate asserting clear positives fire and benign controls stay silent.

## [0.6.0] - 2026-08-29

### Added
- pcapng reader: athar now ingests `.pcapng` (Wireshark/tshark's default) as
  well as classic `.pcap`, verified to decode identically.
- Evidence integrity: a SHA-256 of the source is computed at ingest, with a
  provenance record (examiner, organization, case number, legal authority, tool
  version, backend, UTC time) shown in reports and stored with the case.
- `ChainOfCustody` manifest (`--coc`): hashes every artefact produced in a run
  plus the source, sealed with the manifest's own digest and independently
  verifiable.
- CLI metadata flags: `--examiner`, `--org`, `--case-number`, `--authority`,
  `--notes`.
- `docs/FORENSIC_READINESS.md` documenting scope and current limitations.
- Tests for pcapng parity, source hashing, provenance round-trip through the
  store, and the chain-of-custody manifest.

## [0.5.0] - 2026-08-29

### Added
- React + TypeScript dashboard (`dashboard/`): interactive investigation map,
  per-host dossier, severity filtering, host search, and inventory/conversation
  tables. Loads any `athar --data` JSON and ships with a bundled sample case.
- `--data` CLI flag and `render_data()` that export the render-ready data model.
- Shared `reporting/data.py` so the HTML report and the dashboard build from one
  data model and cannot drift; added a test pinning the export shape.

### Changed
- `_build_data` moved out of the HTML renderer into `reporting.data`.

## [0.4.0] - 2026-08-28

### Added
- JA3 TLS client fingerprinting (RFC 8701 GREASE values excluded), surfaced in
  each host's dossier and stored with the case.
- Threat-intel matching (`intel.py`): match destination IPs, looked-up or SNI
  domains, and JA3 fingerprints against a local JSON feed; every hit is a finding.
- `--iocs` CLI flag, applied to both freshly analysed and store-reloaded cases.
- A bundled example feed (`feeds/example-iocs.json`) and a beaconing implant in
  the sample capture whose IP, C2 domain, and JA3 all match it.
- Enrichment tests: JA3 correctness and GREASE filtering, IP/domain/JA3 matching,
  subdomain matching, and empty-feed safety.

### Changed
- `analyze()` accepts an optional feed; host classification is now a public
  `classify_hosts()` so intel results can flag hosts on reloaded cases.

## [0.3.0] - 2026-08-28

### Added
- SQLite forensic store (`store.py`): persist analysed cases into a normalised,
  indexed schema and search them with plain SQL. Many cases share one database.
- Lossless save/load: a stored case can be re-opened and its full HTML report
  regenerated without the original capture (flow metadata is preserved).
- CLI: `--db` to persist a case, `--from-db`/`--case` to load a stored case,
  and `--list` to enumerate the cases in a database.
- `save_case` and `load_case` are exported from the package API.
- Store tests covering round-trip fidelity, idempotent re-saves, and SQL access.

### Changed
- The `case_id` is now a property of `Case`, shared by the report and the store.

## [0.2.0] - 2026-08-28

### Added
- Native C++ decode core (`core/athar_core.cpp`) exposed through pybind11,
  accelerating the pcap-read and Ethernet/IP/TCP/UDP decode hot path.
- Backend-selection layer that uses the native core when built and transparently
  falls back to the pure-Python decoder otherwise; both produce identical output.
- `benchmarks/bench.py` for comparing native and Python throughput.
- Native/Python parity test enforcing byte-for-byte identical decoding.
- Active backend is now shown in the console summary and the HTML report footer.

### Changed
- The analysis engine reads packets through the backend layer rather than the
  pcap reader directly.

## [0.1.0] - 2026-08-28

### Added
- Dependency-free classic-pcap reader and Ethernet/IPv4/IPv6/TCP/UDP decoder.
- Flow reassembly into bidirectional conversations keyed on the 5-tuple.
- Application dissectors for DNS, HTTP (including Basic-auth credentials) and
  TLS ClientHello SNI.
- Four rule-based detectors: TCP port scan, plaintext credentials, DNS
  tunneling, and periodic beaconing, each mapped to a MITRE ATT&CK technique.
- Interactive self-contained HTML forensic report with an investigation map,
  per-host dossier, findings panel, and timeline.
- JSON and CSV exporters and a `athar` command-line interface.
