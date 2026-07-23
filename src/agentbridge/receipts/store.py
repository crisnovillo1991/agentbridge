"""Receipt persistence: content-addressed JSON blobs + sqlite index.

v0 keeps this deliberately boring: local filesystem + sqlite under a process
lock. Production swaps in Postgres (index) and S3/MinIO (blobs) behind the
same interface. Chain assignment (seq / prev hash) happens here, atomically.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from .canonical import canonical_json
from .signer import BridgeSigner, now_rfc3339, receipt_hash

_SCHEMA = """
CREATE TABLE IF NOT EXISTS receipts (
  hash TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  capability_id TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  UNIQUE (session_id, seq)
);
CREATE INDEX IF NOT EXISTS idx_receipts_session ON receipts (session_id, seq);
"""


class ReceiptStore:
    def __init__(self, data_dir: str | Path):
        self._dir = Path(data_dir)
        self._blobs = self._dir / "receipts"
        self._blobs.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self._dir / "index.db", check_same_thread=False)
        self._db.executescript(_SCHEMA)
        self._lock = threading.Lock()

    def record(self, session_id: str, core: dict, signer: BridgeSigner) -> tuple[dict, str]:
        """Assign chain position, sign, persist. Returns (receipt, hash).

        `core` is an entry-core dump (receipt or attachment) MINUS session_id/seq/prev_entry_hash/
        issued_at, which are filled here so chain integrity can't be bypassed.
        """
        with self._lock:
            row = self._db.execute(
                "SELECT hash, seq FROM receipts WHERE session_id=? ORDER BY seq DESC LIMIT 1",
                (session_id,),
            ).fetchone()
            prev_hash, seq = (row[0], row[1] + 1) if row else (None, 0)

            core = dict(core)
            core.update(
                session_id=session_id,
                seq=seq,
                prev_entry_hash=prev_hash,
                issued_at=now_rfc3339(),
            )
            signature = signer.sign_core(core)
            receipt = {**core, "signatures": [signature]}
            rhash = receipt_hash(receipt)

            (self._blobs / f"{rhash}.json").write_bytes(canonical_json(receipt))
            self._db.execute(
                "INSERT INTO receipts (hash, session_id, seq, capability_id, issued_at) VALUES (?,?,?,?,?)",
                (rhash, session_id, seq, core.get("capability_id", core.get("entry_type", "entry")), core["issued_at"]),
            )
            self._db.commit()
        return receipt, rhash

    def get(self, rhash: str) -> dict | None:
        path = self._blobs / f"{rhash}.json"
        if not path.exists():
            return None
        return json.loads(path.read_bytes())

    def session(self, session_id: str) -> list[dict]:
        rows = self._db.execute(
            "SELECT hash FROM receipts WHERE session_id=? ORDER BY seq", (session_id,)
        ).fetchall()
        return [r for (h,) in rows if (r := self.get(h)) is not None]
