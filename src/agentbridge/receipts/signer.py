"""Signing, hashing and verification primitives (spec §5–§8)."""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonical_json


def now_rfc3339() -> str:
    """RFC 3339 UTC with millisecond precision, Z suffix (spec §4)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def receipt_hash(full_entry: dict) -> str:
    """Hash of the COMPLETE entry incl. signatures — used for chaining and
    attaches_to references (spec §5 'entry hash')."""
    return sha256_hex(canonical_json(full_entry))


entry_hash = receipt_hash  # spec v0.2 name


class BridgeSigner:
    """Holds the bridge's Ed25519 key and signs receipt cores."""

    def __init__(self, private_key_b64: str):
        seed = base64.b64decode(private_key_b64)
        if len(seed) != 32:
            raise ValueError("BRIDGE_PRIVATE_KEY must be base64 of a 32-byte Ed25519 seed")
        self._sk = Ed25519PrivateKey.from_private_bytes(seed)
        pub = self._sk.public_key().public_bytes_raw()
        self.public_key_b64 = base64.b64encode(pub).decode()
        self.key_id = "ed25519:" + self.public_key_b64[:12]

    def sign_core(self, core: dict) -> dict:
        """Return a Signature object (as dict) over the signing payload."""
        payload = canonical_json(core)
        sig = self._sk.sign(payload)
        return {
            "signer": "bridge",
            "alg": "ed25519",
            "key_id": self.key_id,
            "public_key": self.public_key_b64,
            "sig": base64.b64encode(sig).decode(),
        }


def verify_receipt_signatures(receipt: dict) -> bool:
    """Spec §8 step 2: every embedded signature must verify. Offline."""
    r = dict(receipt)
    sigs = r.pop("signatures", [])
    if not sigs:
        return False
    payload = canonical_json(r)
    for s in sigs:
        if s.get("alg") != "ed25519":
            return False
        try:
            pk = Ed25519PublicKey.from_public_bytes(base64.b64decode(s["public_key"]))
            pk.verify(base64.b64decode(s["sig"]), payload)
        except Exception:
            return False
    return True


def verify_chain_link(receipt: dict, prev_receipt: dict) -> bool:
    """Spec §8 step 3."""
    field = "prev_receipt_hash" if receipt.get("spec_version") == "0.1" else "prev_entry_hash"
    return (
        receipt.get(field) == receipt_hash(prev_receipt)
        and receipt.get("seq") == prev_receipt.get("seq", -2) + 1
        and receipt.get("session_id") == prev_receipt.get("session_id")
    )
