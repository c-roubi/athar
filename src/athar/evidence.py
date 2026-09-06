"""Evidence integrity and provenance.

Forensic soundness starts here: a cryptographic hash of the source capture taken
at ingest, plus a provenance record (who, when, which tool version, under what
authority). The same hashing is applied to every artefact athar writes, so a
chain-of-custody manifest can prove nothing changed after acquisition. Aligned
with ISO/IEC 27037's preservation requirements.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
from dataclasses import asdict, dataclass
from pathlib import Path

_CHUNK = 1 << 20  # 1 MiB


def sha256_file(path: str | Path) -> str:
    """Return the SHA-256 hex digest of a file, read in chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    """Return the SHA-256 hex digest of a string (utf-8)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def utc_now() -> str:
    """Current UTC time as an ISO-8601 string (second precision)."""
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


@dataclass
class Provenance:
    """Where a case came from and under whose hand -- the custody header."""

    examiner: str = ""
    organization: str = ""
    case_number: str = ""
    authority: str = ""          # warrant / legal-authority reference
    notes: str = ""
    source_path: str = ""
    source_sha256: str = ""
    source_bytes: int = 0
    tool: str = "athar"
    tool_version: str = ""
    backend: str = ""
    analyzed_at: str = ""        # UTC ISO-8601

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def build_provenance(
    path: str | Path,
    *,
    examiner: str = "",
    organization: str = "",
    case_number: str = "",
    authority: str = "",
    notes: str = "",
    tool_version: str = "",
    backend: str = "",
) -> Provenance:
    """Compute a :class:`Provenance` for *path*, hashing the source at ingest."""
    p = Path(path)
    return Provenance(
        examiner=examiner,
        organization=organization,
        case_number=case_number,
        authority=authority,
        notes=notes,
        source_path=str(path),
        source_sha256=sha256_file(path),
        source_bytes=p.stat().st_size if p.exists() else 0,
        tool_version=tool_version,
        backend=backend,
        analyzed_at=utc_now(),
    )
