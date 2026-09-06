"""Tamper-evident audit log.

Every action athar takes on a case -- analysing a capture, exporting a report --
is appended to a hash-chained log: each entry carries the hash of the entry
before it, so altering or removing any past entry breaks the chain and is
detectable by :meth:`AuditLog.verify`. This gives the auditability ISO/IEC 27037
expects: an independent party can confirm the record was not edited after the
fact.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .evidence import utc_now

GENESIS = "0" * 64


def _canonical(obj: dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


@dataclass
class AuditEntry:
    """One link in the audit chain."""

    seq: int
    ts: str
    actor: str
    action: str
    target: str
    details: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = GENESIS
    entry_hash: str = ""

    def compute_hash(self) -> str:
        body = {
            "seq": self.seq, "ts": self.ts, "actor": self.actor, "action": self.action,
            "target": self.target, "details": self.details, "prev_hash": self.prev_hash,
        }
        return hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq, "ts": self.ts, "actor": self.actor, "action": self.action,
            "target": self.target, "details": self.details, "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }


class AuditLog:
    """An append-only, hash-chained log persisted as JSON lines."""

    def __init__(self, entries: list[AuditEntry] | None = None) -> None:
        self.entries: list[AuditEntry] = entries or []

    @property
    def head(self) -> str:
        return self.entries[-1].entry_hash if self.entries else GENESIS

    def append(self, action: str, actor: str = "", target: str = "",
               details: dict[str, Any] | None = None) -> AuditEntry:
        entry = AuditEntry(
            seq=len(self.entries), ts=utc_now(), actor=actor or "unknown",
            action=action, target=target, details=details or {}, prev_hash=self.head,
        )
        entry.entry_hash = entry.compute_hash()
        self.entries.append(entry)
        return entry

    def verify(self) -> tuple[bool, int | None]:
        """Return ``(ok, first_bad_index)``; the chain is intact iff *ok*."""
        prev = GENESIS
        for i, e in enumerate(self.entries):
            if e.prev_hash != prev or e.entry_hash != e.compute_hash():
                return False, i
            prev = e.entry_hash
        return True, None

    def write(self, path: str | Path) -> None:
        lines = [json.dumps(e.as_dict(), sort_keys=True) for e in self.entries]
        Path(path).write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> AuditLog:
        p = Path(path)
        if not p.exists():
            return cls()
        entries = []
        for line in p.read_text(encoding="utf-8").splitlines():
            if line.strip():
                entries.append(AuditEntry(**json.loads(line)))
        return cls(entries)
