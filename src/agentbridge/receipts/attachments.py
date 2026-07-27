"""Settlement attachments (spec §4.6, §8.4).

A receipt is immutable once signed and chained; late-arriving settlement
therefore attaches as a NEW signed entry in the same session chain,
referencing the original entry hash and digesting the VERBATIM facilitator
settle response — the artifact that proves what was claimed at settle time.
"""
from __future__ import annotations

import hashlib
import json

from .models import SettlementAttachmentCore, SettlementInfo
from .signer import now_rfc3339


def derive_x402(raw: bytes) -> tuple[str, str | None, str | None]:
    """Normative §8.4 mapping: verbatim settle response -> (final_status, tx_hash, network).

    settled iff the response parses as JSON with success == true and a
    non-empty string `transaction`; anything else — including a "processing"
    claim with no transaction — derives as failed. The verbatim digest, not
    an optimistic status, carries the facilitator's claim.
    """
    def _nodup(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise ValueError("duplicate key")
            d[k] = v
        return d
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_nodup)
    except Exception:  # unparseable OR duplicate keys: non-conforming (§8.4)
        return "failed", None, None
    if not isinstance(obj, dict):  # bare string/number/bool/null/array (§8.4)
        return "failed", None, None
    tx = obj.get("transaction")
    net = obj.get("network") if isinstance(obj.get("network"), str) else None
    if obj.get("success") is True and isinstance(tx, str) and tx:
        return "settled", tx, net
    return "failed", tx if isinstance(tx, str) and tx else None, net


def build_attachment_core(
    attaches_to: str,
    settle_response_raw: bytes,
    facilitator_id: str,
    response_timestamp: str | None = None,
    network_fallback: str | None = None,
) -> dict:
    """Build a chain-ready attachment core (session/seq/prev/issued_at are
    assigned by the store, exactly like receipts)."""
    status, tx, net = derive_x402(settle_response_raw)
    core = SettlementAttachmentCore(
        session_id="", seq=0, prev_entry_hash=None, issued_at="",
        attaches_to=attaches_to,
        settlement=SettlementInfo(
            final_status=status,
            tx_hash=tx,
            network=net or network_fallback,
            facilitator_id=facilitator_id,
            response_timestamp=response_timestamp or now_rfc3339(),
            settle_response_sha256=hashlib.sha256(settle_response_raw).hexdigest(),
            settle_response_len=len(settle_response_raw),
        ),
    ).model_dump(mode="json")
    for k in ("session_id", "seq", "prev_entry_hash", "issued_at"):
        core.pop(k)
    return core
