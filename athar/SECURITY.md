# Security & responsible use

## Reporting a vulnerability

If you find a security issue in athar — a parser crash on hostile input, a way to
forge a chain-of-custody manifest or audit log, or any integrity weakness —
please report it privately rather than opening a public issue. Open a GitHub
security advisory on the repository, or contact the maintainer directly. Please
allow reasonable time to address it before public disclosure.

## Parsing untrusted captures

athar parses attacker-controlled data by design. The readers are written
defensively (bounds-checked, tolerant of truncation) and reassembly is capped to
bound memory, but you should still analyse unknown captures in an isolated
environment.

## Responsible and lawful use

athar is a defensive analysis tool. Only analyse network captures you are
**legally authorized** to inspect. Network traffic frequently contains personal
data; handle it under the applicable law (e.g. GDPR in the EU) with appropriate
minimization, access control, and retention.

## Evidentiary status

athar is built toward forensic soundness but is **not** an independently
validated, evidence-grade system. The error rates in `docs/validation-report.md`
come from athar's own synthetic dataset. Before using output as evidence, review
`docs/FORENSIC_READINESS.md` for scope and known limitations — admissibility is a
legal determination that varies by jurisdiction, and the tool supports a
defensible chain of custody without guaranteeing admissibility.
