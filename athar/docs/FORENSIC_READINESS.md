# Forensic readiness — scope and limitations

athar aims to be *forensically sound*: to handle evidence in a way that supports
its admissibility. This document states honestly what the tool does today and
what it does **not** yet do, so it is used within its validated scope.

## What athar does today (v0.15)

Aligned with the preservation and documentation expectations of **ISO/IEC 27037**:

- **Source integrity.** A SHA-256 digest of the capture is computed at ingest and
  carried in every report and in the case store.
- **Provenance.** Each case records examiner, organization, case number, legal
  authority, tool name/version, decode backend, and a UTC analysis timestamp.
- **Chain-of-custody manifest.** `--coc` hashes every artefact produced in a run
  (report, JSON, CSV) alongside the source hash, sealed with the manifest's own
  digest, so an independent party can recompute and verify each hash.
- **Tamper-evident audit log.** `--audit` appends every analyse/export action to
  a hash-chained log; `--verify-audit` detects any after-the-fact edit.
- **Measured error rate.** A validation harness scores each detector against
  labelled scenarios (precision/recall/false-positive rate) and publishes
  `docs/validation-report.md` — the "known error rate" a Daubert analysis expects.
- **Repeatability.** Decoding is deterministic, and the native and pure-Python
  backends are verified to produce byte-for-byte identical output.
- **Format coverage.** Reads both classic `.pcap` and `.pcapng` (the modern
  default of Wireshark/tshark).
- **Methodology transparency.** Every finding maps to a MITRE ATT&CK technique;
  the code and detection thresholds are open and inspectable.

## What is still required before evidentiary use

These are known gaps. athar is currently a strong **triage and analysis** tool,
**not** a validated evidence-grade system.

- **Independent validation.** athar cross-checks its parsing against tshark
  (a differential harness confirms they agree on packet count, hosts, DNS names
  and TCP conversations), which supports correctness. But the detector error
  rates still come from athar's own synthetic scenarios; NIST CFTT-style testing
  on labelled real-world corpora and formal peer review are not yet done.
- **Access control.** No authentication, role-based access, or per-examiner
  identity beyond the recorded examiner name; no encryption at rest.
- **Trusted timestamping.** Artefacts can be digitally signed (Ed25519) and
  verified, binding hashes to an examiner key; however timestamps are still host
  UTC, not RFC-3161 / eIDAS *qualified* timestamps from a trusted authority.
- **Content recovery (cleartext only).** TCP reassembly, cleartext HTTP upload
  and download carving to disk with hashes, and FTP/SIP/SMTP/POP3/IMAP session
  and credential extraction are implemented. Encrypted (TLS) payloads are opaque
  and are not broken. With an investigator-supplied NSS key-log (lawfully
  obtained session secrets), TLS 1.2/1.3 AES-GCM sessions are decrypted and their
  content extracted. IP defragmentation and protocols beyond those listed are
  still partial.
- **Scale.** Capture readers stream from disk and per-flow buffering is bounded,
  so memory stays flat with capture size; a very large number of concurrent flows
  still accumulates per-flow state (full out-of-core is future work).

## Operating notes

- Analyse only captures you are **legally authorized** to inspect.
- Work on a **copy**; preserve the original read-only and record its hash.
- "Admissibility" is a legal determination that varies by jurisdiction. athar
  *supports* a defensible chain of custody; it does not guarantee admissibility.

## References

ISO/IEC 27037 (identification, collection, acquisition, preservation of digital
evidence) and ISO/IEC 27042 (analysis and interpretation); NIST Computer
Forensics Tool Testing (CFTT); the Daubert standard and US Federal Rules of
Evidence 702/901; and, in the EU, eIDAS 2.0 qualified timestamps/signatures with
GDPR-compliant handling.
