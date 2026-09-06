# athar

**athar** (أثر — "trace") is an offline network-capture forensics tool. Point it
at a `.pcap` file and it reconstructs the conversations, dissects the metadata,
flags suspicious behaviour, and renders an interactive investigation report you
can hand to an analyst.

It is written in Python with an **optional native C++ core** for the parsing hot
path, reads both `.pcap` and `.pcapng` captures, and has **no third-party
runtime dependencies** — the detectors, the store, and the HTML report all run on
the standard library.

> **Authorised use only.** athar is a defensive tool for analysing captures you
> are permitted to inspect — your own labs, incident-response engagements, and
> CTF data. Do not use it on traffic you have no authority over.

---

## What it does

Given a capture, athar produces a single self-contained HTML report built around
an **investigation map**: every device is a node, every conversation an edge, and
anything a detector flagged glows. Click a device to open its dossier — the DNS
names it looked up, the HTTP requests it made, the TLS servers it reached, and
the findings that implicate it. The same case is also available as JSON (for
pipelines) and CSV (for the findings table).

The goal is a report that answers, at a glance: *which device is this, what
traffic passed through it, and what did it do.*

## Install

```bash
git clone https://github.com/c-roubi/athar
cd athar
pip install -e .
```

Python 3.10 or newer. If a C++ toolchain is present, an accelerated native
decode core is compiled automatically; if not, the install still succeeds and
athar uses its pure-Python backend. You can check which is active:

```bash
athar --version
python -c "import athar; print(athar.backend())"   # 'native' or 'python'
```

## The native core

The per-packet hot path — reading the capture and decoding Ethernet / IP / TCP /
UDP — is implemented in C++ (`core/athar_core.cpp`) and exposed to Python through
[pybind11](https://pybind11.readthedocs.io/). It is a drop-in accelerator: the
native and pure-Python backends produce **byte-for-byte identical** results, a
property the test suite enforces, so correctness never depends on which one ran.

Decoding a ~90 MB capture of one million packets end to end (`benchmarks/bench.py`):

| Backend | Throughput | Time |
|---|---|---|
| Pure Python | ~0.12 M pkt/s | 8.6 s |
| Native C++ | ~0.26 M pkt/s | 3.8 s |

Roughly a **2.3× speed-up** end to end; the raw byte parsing is far faster still,
with the remaining cost being the marshalling of one Python object per packet
across the boundary. Reproduce it with:

```bash
python benchmarks/bench.py 1000000
```

## Usage

```bash
# Console summary
athar capture.pcap

# Full interactive forensic report
athar capture.pcap --html report.html

# Machine-readable exports
athar capture.pcap --json case.json --csv findings.csv

# Persist the case into a SQLite forensic store
athar capture.pcap --db forensics.db

# Match observed indicators against a threat-intel feed
athar capture.pcap --iocs feeds/example-iocs.json

# Export the data model consumed by the React dashboard
athar capture.pcap --iocs feeds/example-iocs.json --data case-data.json
```

### Enrichment: JA3 and threat intel

athar fingerprints every TLS ClientHello with [JA3](https://github.com/salesforce/ja3),
so a client can be identified even when the traffic is encrypted — the
fingerprint appears in each host's dossier. Fingerprints, looked-up domains, and
destination IPs can then be matched against a local JSON feed of indicators:

```json
{
  "ips": ["185.220.101.5"],
  "domains": ["evil-c2.net"],
  "ja3": ["e5c6ecce54485f312c2d9bb1e54ab124"]
}
```

Every hit becomes a finding, so a single compromised host can be corroborated by
several independent signals at once — in the bundled sample, the beaconing host
is flagged by its callback pattern, its C2 domain, *and* its TLS fingerprint. The
feed is plain JSON, matched offline, and works the same on a live capture or one
reloaded from the store.

### The forensic store

Cases can be saved into a SQLite database and searched with plain SQL. Many
captures share one store, so questions can span an entire investigation:

```bash
athar monday.pcap    --db forensics.db
athar tuesday.pcap   --db forensics.db
athar --list forensics.db          # what's in the store
```

Because the store is lossless, a case can be re-opened and its full report
regenerated **without the original capture** — archive the pcap, keep the case:

```bash
athar --from-db forensics.db --case ATH-B7117E72 --html report.html
```

And any SQL tool can interrogate it directly — for example, every host that ever
leaked credentials, across every capture in the store:

```sql
SELECT c.source, e.src_ip, e.dst_ip,
       json_extract(e.evidence, '$.username') AS username
FROM   events e
JOIN   cases  c ON c.case_id = e.case_id
WHERE  e.detector = 'plaintext_credentials';
```

Example console output:

```
case capture.pcap
  76 packets  |  8 hosts  |  25 conversations  |  4 findings

  [critical] Credentials sent in the clear: HTTP Basic auth as 'admin' to nas.local  T1040
  [    high] TCP port scan: 192.168.1.66 probed 20 ports on 192.168.1.1  T1046
  [    high] Periodic beaconing: 192.168.1.77 called 185.220.101.5:443 every ~30s, 8 times  T1071
  [    high] Possible DNS tunneling: 192.168.1.88 made 25 high-entropy lookups under evil-c2.net  T1071.004
```

No capture handy? Generate a synthetic one that exercises every detector:

```bash
python tools/make_sample_pcap.py sample.pcap
athar sample.pcap --html report.html
```

## Evidence integrity & chain of custody

athar is built toward forensic soundness. On ingest it computes a **SHA-256** of
the source capture and records a provenance header — examiner, organization,
case number, legal authority, tool version, backend, and a UTC analysis time —
which appears in every report and is stored with the case. Pass the metadata on
the command line:

```bash
athar evidence.pcapng \
  --examiner "A. Examiner" --org "Cyber Unit" \
  --case-number "CU-2026-0042" --authority "Warrant 2026/17" \
  --html report.html --coc report.coc.json
```

`--coc` writes a **chain-of-custody manifest**: the source hash, the provenance,
and the SHA-256 of every artefact athar produced in the run, sealed with the
manifest's own digest. Any third party can recompute the hashes and confirm
nothing changed after acquisition — the technical backbone of a defensible chain
of custody under ISO/IEC 27037. This aids admissibility but does not by itself
guarantee it; see `docs/FORENSIC_READINESS.md` for scope and current limitations.

A **tamper-evident audit log** records every action as a hash-chained entry:

```bash
athar evidence.pcapng --examiner "A. Examiner" --html report.html --audit case.audit
athar --verify-audit case.audit    # "chain intact" or pinpoints the edited entry
```

Artefacts can also be **digitally signed** so a third party can confirm both
integrity and who attested to them (Ed25519):

```bash
athar --gen-key examiner.key examiner.pub          # one-time keypair
athar evidence.pcapng --coc case.coc.json --sign-key examiner.key
athar --verify-sig case.coc.json case.coc.json.sig examiner.pub
```

## Content recovery (cleartext only)

For **unencrypted** traffic, athar reconstructs what actually moved on the wire.
It carves HTTP uploads *and* downloads to disk with a hashed manifest, and pulls
session details and credentials from cleartext FTP, SIP, SMTP, and POP3/IMAP:

```bash
athar evidence.pcapng --extract ./carved --coc case.coc.json
# carved/  -> 0000_payroll.csv, 0001_agent.exe, manifest.json (with SHA-256s)
```

Every carved file is hashed and added to the chain-of-custody manifest. This
applies only to cleartext protocols; TLS-wrapped traffic (HTTPS, FTPS, SIPS,
SMTPS) stays opaque and is never decrypted — for those, athar still shows the
JA3/JA3S fingerprint, SNI, destination, and volume.

## Decrypting TLS (with supplied keys)

athar does **not** break TLS. But if you have the session secrets — the standard
`SSLKEYLOGFILE` an endpoint's browser writes, the same file Wireshark consumes —
athar decrypts the session and runs all of the above (content, file carving,
credentials) on the recovered plaintext:

```bash
athar evidence.pcapng --keylog sslkeys.log --extract ./carved
```

It supports TLS 1.2 and 1.3 with AES-GCM suites, deriving keys via the TLS 1.2
PRF and the TLS 1.3 HKDF schedule. This needs the optional `cryptography`
dependency (`pip install athar[tls]`); without keys, TLS stays opaque and athar
still reports JA3/JA3S, SNI, destination and volume. Session secrets are evidence
too — obtain and handle them lawfully.

## Detector validation

Detector accuracy is measured against labelled synthetic scenarios — clear
positives, benign controls, and near-threshold boundary cases — reporting
precision, recall and false-positive rate per detector (the *known error rate* a
Daubert analysis expects):

```bash
python validation/run.py     # writes docs/validation-report.md and .json
```

See [docs/validation-report.md](docs/validation-report.md) for the current
numbers. athar also **cross-checks its parsing against tshark** on the same
capture (`python validation/differential.py <pcap>`) — agreement with an
independent, widely-accepted tool is evidence of correct parsing. These come from
synthetic data and a cross-check; validation on real-world corpora is still
needed before evidentiary use.

## Detectors

Each finding is mapped to a [MITRE ATT&CK](https://attack.mitre.org/) technique
so the report speaks the language analysts already use.

| Detector | What it catches | Severity | ATT&CK |
|---|---|---|---|
| `plaintext_credentials` | Username **and password** in the clear (HTTP Basic, FTP, SMTP, POP3, IMAP) | Critical | T1040 |
| `port_scan` | One host probing many ports on a target | High | T1046 |
| `beaconing` | Regular, low-jitter callbacks to one destination (C2) | High | T1071 |
| `dns_tunneling` | High volume of long, high-entropy names under one domain | High | T1071.004 |
| `ioc_match` | Destination IP, domain, or JA3 fingerprint on a threat-intel feed | Critical / High | T1071 |

## The React dashboard

Alongside the self-contained HTML report, `dashboard/` is an interactive
React + TypeScript viewer for exploring a case: the investigation map, a
per-host dossier, severity filtering, host search, and sortable inventory and
conversation tables. It reads the JSON produced by `athar --data`, so it opens
any case — and both views share one data model (`reporting/data.py`), so they
never drift.

```bash
cd dashboard
npm install
npm run dev        # develop against the bundled sample case
npm run build      # production build into dashboard/dist
npm run typecheck  # strict TypeScript check
```

The app ships with a sample case so it renders out of the box; use the
**Load JSON** button to open any file written by `athar --data`.

## How it works

athar is a layered pipeline; each stage hands a clean model to the next, so
detectors and reports never touch the parsing path.

```
capture ─▶ pcap reader ─▶ packet decode ─▶ flow reassembly ─▶ dissectors
             (C++ core, Python fallback)                          │
                        findings ◀─ detectors ◀───────────────────┘
                            │
                            ▼
              console · JSON · CSV · HTML investigation report
```

- **`core/athar_core.cpp`** — native C++ decode core (pcap read + L2–L4),
  compiled via pybind11; optional, with a pure-Python fallback.
- **`backend.py`** — picks the native core when available, else pure Python;
  both yield identical `(timestamp, Packet)` streams.
- **`pcap.py`** — dependency-free reader for the classic pcap format (fallback).
- **`decode.py`** — Ethernet / IPv4 / IPv6 / TCP / UDP decoding; tolerant of
  malformed frames (one bad packet never aborts a capture).
- **`analyze.py`** — reassembles bidirectional flows and builds the host
  inventory in a single pass.
- **`dissectors.py`** — DNS, HTTP (with Basic-auth extraction), and TLS SNI.
- **`detectors.py`** — pure functions over collected signals; easy to unit-test
  and to extend.
- **`reporting/`** — console, structured (JSON/CSV), and the HTML report.

Application metadata is attributed to the host that actually initiated it (the
client that asked, not the server that answered), and a port only counts as a
"service" when a host answered on it — so a scan target never masquerades as a
server.

## Project layout

```
athar/
├── core/athar_core.cpp    # native C++ decode core (pybind11)
├── src/athar/
│   ├── backend.py         # native / pure-Python backend selection
│   ├── pcap.py            # classic pcap reader (fallback)
│   ├── pcapng.py          # pcapng reader
│   ├── decode.py          # link/transport decoding (fallback)
│   ├── evidence.py        # source hashing + provenance
│   ├── audit.py           # tamper-evident hash-chained audit log
│   ├── reassembly.py      # TCP stream reassembly
│   ├── extract.py         # cleartext HTTP content + file carving
│   ├── protocols.py       # FTP/SIP/SMTP/POP3/IMAP session dissectors
│   ├── tlsdecrypt.py      # TLS decryption via NSS key-log (optional)
│   ├── signing.py         # Ed25519 signing/verification of artefacts
│   ├── geoip.py           # GeoIP/ASN + network-scope enrichment
│   ├── winproto.py        # RDP/SMB/Kerberos dissectors
│   ├── netknowledge.py    # service ports, Tor/C2 knowledge
│   ├── narrative.py       # findings → per-host attack story
│   ├── tlscerts.py        # TLS certificate parsing (+ C2 signal)
│   ├── tcphealth.py       # Wireshark-style TCP sequence analysis
│   ├── ipreasm.py         # IPv4 fragment reassembly
│   ├── dissectors.py      # DNS / HTTP / TLS
│   ├── detectors.py       # rule-based detection
│   ├── analyze.py         # the analysis engine
│   ├── store.py           # SQLite forensic store (save / load / query)
│   ├── intel.py           # JA3 / IOC threat-intel matching
│   ├── model.py           # Case / Host / Flow / Event
│   ├── cli.py             # command-line interface
│   └── reporting/         # data model · console · json · csv · html
├── dashboard/             # React + TypeScript case viewer
├── validation/            # labelled scenarios + error-rate harness
├── docs/                  # architecture, forensic readiness, validation report
├── feeds/example-iocs.json
├── tools/make_sample_pcap.py
├── benchmarks/bench.py
├── tests/
├── setup.py               # optional native-extension build
└── .github/workflows/ci.yml
```

## Development

```bash
pip install -e ".[dev]"      # builds the native core if a compiler is present
ruff check .                 # lint
mypy                         # strict type checking
pytest -q                    # tests (native/python parity is verified here)
python setup.py build_ext --inplace   # rebuild just the native core
```

CI runs all three across Python 3.10–3.12 on every push.

## Roadmap

The parsing hot path now runs in native C++. Planned work, roughly in order:

1. ~~A C/C++ decode-and-reassembly core with Python bindings and benchmarks.~~ ✔ done
2. ~~A queryable SQLite forensic store, so cases can be searched with SQL.~~ ✔ done
3. ~~Enrichment: JA3 TLS fingerprints and IOC-feed matching.~~ ✔ done
4. ~~A React/TypeScript dashboard for exploring cases interactively.~~ ✔ done
5. ~~pcapng support, evidence hashing, chain of custody, audit log, detector
   validation.~~ ✔ done
6. Independent validation on real-world corpora; access control, encryption at
   rest, and RFC-3161/eIDAS trusted timestamping.
7. ~~True TCP stream reassembly.~~ ✔ done
8. ~~JA3S server fingerprints; FTP credential coverage.~~ ✔ done
9. GeoIP/ASN enrichment; independent validation on real-world corpora; access
   control, encryption at rest, RFC-3161/eIDAS timestamping.

## License

MIT — see [LICENSE](LICENSE).
