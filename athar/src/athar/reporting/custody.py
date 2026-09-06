"""Chain-of-custody manifest.

Every artefact athar writes for a case -- the HTML report, the JSON export, the
CSV -- is hashed after it is written, and those hashes are collected here next to
the source hash and provenance. An independent party can recompute each SHA-256
and confirm nothing changed, which is the technical backbone of a defensible
chain of custody (ISO/IEC 27037).
"""

from __future__ import annotations

import json
from pathlib import Path

from ..evidence import Provenance, sha256_file, sha256_text, utc_now


class ChainOfCustody:
    """Accumulates hashed artefacts for one analysis run."""

    def __init__(self, case_id: str, provenance: Provenance | None) -> None:
        self.case_id = case_id
        self.provenance = provenance
        self.artefacts: list[dict[str, object]] = []

    def record(self, path: str | Path, kind: str) -> None:
        """Hash a just-written artefact and add it to the manifest."""
        p = Path(path)
        self.artefacts.append({
            "kind": kind,
            "path": str(p),
            "sha256": sha256_file(p),
            "bytes": p.stat().st_size,
            "recorded_at": utc_now(),
        })

    def to_dict(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "generated_at": utc_now(),
            "provenance": self.provenance.as_dict() if self.provenance else None,
            "source": {
                "path": self.provenance.source_path if self.provenance else "",
                "sha256": self.provenance.source_sha256 if self.provenance else "",
                "bytes": self.provenance.source_bytes if self.provenance else 0,
            },
            "artefacts": self.artefacts,
        }

    def write(self, path: str | Path) -> None:
        """Write the manifest as JSON, self-sealing with its own digest."""
        body = self.to_dict()
        serialised = json.dumps(body, indent=2, sort_keys=True)
        body["manifest_sha256"] = sha256_text(serialised)
        Path(path).write_text(json.dumps(body, indent=2, sort_keys=True), encoding="utf-8")
