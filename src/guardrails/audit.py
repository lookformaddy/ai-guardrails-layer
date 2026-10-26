"""Append-only JSONL audit log with a hash chain.

Every screening decision is appended as one JSON line. Each record
carries ``prev_hash`` (the SHA-256 of the previous record's canonical
form) and its own ``hash``, so deleting or editing a middle record
breaks the chain — the property auditors actually need. The log never
stores the original text, only the sanitized text and finding metadata,
so the audit trail itself cannot leak the PII it screened.

Records are written with ``O_APPEND`` semantics via a plain file
append, which is atomic enough for a single-writer service; a
multi-writer deployment would put this behind a queue or a database.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .models import ScreenResult


def _canonical(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


class AuditLog:
    """Append-only JSONL log with SHA-256 hash chaining."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash = self._tail_hash()

    def _tail_hash(self) -> str:
        if not self.path.exists():
            return "0" * 64
        last = "0" * 64
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    last = json.loads(line)["hash"]
                except (KeyError, json.JSONDecodeError):
                    continue
        return last

    def append(self, result: ScreenResult) -> dict[str, Any]:
        record: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "request_id": result.request_id,
            "tenant": result.tenant,
            "action": result.action.value,
            "risk_score": round(result.risk_score, 2),
            "risk_band": result.risk_band,
            "rule_name": result.rule_name,
            "reasons": list(result.reasons),
            "finding_kinds": sorted({f.kind for f in result.findings}),
            "finding_count": len(result.findings),
            "sanitized_text": result.sanitized_text,
            "prev_hash": self._last_hash,
        }
        record["hash"] = hashlib.sha256(
            _canonical(record).encode("utf-8")).hexdigest()
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._last_hash = record["hash"]
        return record

    def read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        records = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records

    def verify_chain(self) -> tuple[bool, list[int]]:
        """Return (ok, broken_indices). Verifies hash linkage only."""
        records = self.read_all()
        broken: list[int] = []
        prev = "0" * 64
        for i, record in enumerate(records):
            if record.get("prev_hash") != prev:
                broken.append(i)
            stored = record.pop("hash", None)
            recomputed = hashlib.sha256(
                _canonical(record).encode("utf-8")).hexdigest()
            if stored != recomputed:
                broken.append(i)
            record["hash"] = stored
            prev = stored or prev
        return (not broken, sorted(set(broken)))


def iter_records(path: str | Path) -> Iterable[dict[str, Any]]:
    if not Path(path).exists():
        return
    with Path(path).open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)
