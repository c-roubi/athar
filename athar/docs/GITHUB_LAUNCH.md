# athar — GitHub launch pack

Everything needed to publish `athar` cleanly. Copy the sections into GitHub as noted.

---

## 1. Repository "About"

**Description (one line):**

> Forensically-sound network forensic analyzer for pcap/pcapng — a C++/Python/TypeScript pipeline that dissects 15+ protocols, decrypts TLS with supplied keys, carves files, detects 11 attack techniques, and reconstructs the attack story with a full chain of custody.

**Topics (tags):**

```
network-forensics  dfir  ndr  pcap  pcapng  incident-response  cybersecurity
threat-detection  mitre-attack  ja3  tls-decryption  tcp-reassembly  lateral-movement
chain-of-custody  python  cpp  react  typescript  blue-team  security-tools
```

---

## 2. Elevator description (README lead)

athar turns a packet capture into an investigation. It streams pcap/pcapng from
disk, decodes on an optional C++ core (with a byte-for-byte-identical pure-Python
fallback), reassembles TCP streams and IPv4 fragments, and dissects 15+ protocols
— HTTP, DNS, FTP, SIP, SMTP, POP3/IMAP, RDP, SMB, Kerberos, NTLM, LDAP, SSH,
Telnet, SNMP and TLS. Given an NSS key-log it decrypts TLS 1.2/1.3 and extracts
the plaintext. It flags 11 attack techniques mapped to MITRE ATT&CK, correlates
them into a per-host kill-chain narrative, and backs every case with SHA-256
hashing, a signed chain-of-custody manifest, and a tamper-evident audit log. Its
parsing agrees with tshark on every objective fact it cross-checks.

---

## 3. Feature highlights (for the README)

- **Multi-language pipeline** — C++ decode core (pybind11), Python analysis,
  React/TypeScript dashboard. Native and Python paths verified identical.
- **Depth** — 15+ protocol dissectors, TLS certificate parsing, Wireshark-style
  TCP health (retransmission/reset/zero-window with an RTT threshold), IPv4
  defragmentation, TCP stream reassembly.
- **Decryption** — TLS 1.2/1.3 via `SSLKEYLOGFILE`, then full content/credential
  extraction on the recovered plaintext.
- **Detection** — port scan, plaintext credentials (user *and* password), DNS
  tunneling, beaconing, data exfiltration, lateral movement, Kerberoasting, admin
  share access, non-standard-port evasion, Tor/C2 egress, suspicious TLS certs.
- **Correlation** — per-host attack narratives along the ATT&CK kill chain.
- **Forensic soundness** — source hashing, provenance, chain-of-custody manifest,
  Ed25519 signing, tamper-evident audit log, measured detector error rate, and a
  differential cross-check against tshark.
- **Presentation** — a self-contained interactive HTML report and a
  React/TypeScript dashboard.

---

## 4. Launch post

> **Introducing athar** — a network forensic analyzer I built to investigate
> pcap/pcapng the way a lab would.
>
> It streams captures from disk, decodes on a C++ core (with a byte-identical
> Python fallback), reassembles TCP and IP fragments, and dissects 15+ protocols
> — down to RDP/SMB/Kerberos/NTLM/LDAP. With a key-log it decrypts TLS 1.2/1.3
> and pulls the plaintext, files and credentials straight out.
>
> It flags 11 attack techniques (scans, cleartext creds, beaconing, exfiltration,
> lateral movement, Kerberoasting, Tor/C2 egress, dodgy certs…), all mapped to
> MITRE ATT&CK, and correlates them into a per-host kill-chain story.
>
> Everything is forensically sound: SHA-256 hashing, a signed chain-of-custody
> manifest, a tamper-evident audit log, a measured detector error rate — and its
> parsing agrees with tshark on every fact it cross-checks.
>
> Multi-language (C++/Python/TypeScript), typed, 68 tests, and honest about its
> limits.
>
> 🔗 github.com/c-roubi/athar

---

## 5. Pre-publish checklist

- [ ] `ruff check .`, `mypy`, and `pytest` (68 tests) all green.
- [ ] `cd dashboard && npm install && npm run build` succeeds.
- [ ] `python validation/run.py` and `python validation/differential.py <pcap>`
      regenerate the reports (tshark installed for the differential).
- [ ] Local artefacts removed (covered by `.gitignore`).
- [ ] `LICENSE` (MIT) holds your name.
- [ ] Tag releases and paste notes from `CHANGELOG.md` (v0.1.0 … v0.23.0).
