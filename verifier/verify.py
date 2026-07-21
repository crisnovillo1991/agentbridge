#!/usr/bin/env python3
"""Standalone receipt verifier — receipt-spec v0.1 §8.

Deliberately self-contained (stdlib + `cryptography` only, no agentbridge
import) so it can live in its own repo: the whole point is that verification
must not require trusting the issuer's code or database.

Usage:
  python verify.py receipt.json                      # signatures + spec checks
  python verify.py receipt.json --prev prev.json     # + chain link
  python verify.py receipt.json --body response.bin  # + response body digest
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical_json(obj) -> bytes:
    _check(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _check(obj):
    if isinstance(obj, float):
        raise ValueError("floats are forbidden by the spec")
    if isinstance(obj, dict):
        for v in obj.values():
            _check(v)
    elif isinstance(obj, list):
        for v in obj:
            _check(v)


def receipt_hash(receipt: dict) -> str:
    return hashlib.sha256(canonical_json(receipt)).hexdigest()


def verify(receipt: dict) -> list[str]:
    problems = []
    if receipt.get("spec") != "agent-interaction-receipt" or receipt.get("spec_version") != "0.1":
        problems.append("unknown spec/spec_version")
    core = {k: v for k, v in receipt.items() if k != "signatures"}
    try:
        payload = canonical_json(core)
    except ValueError as e:
        return [f"canonicalization failed: {e}"]
    sigs = receipt.get("signatures") or []
    if not sigs:
        problems.append("no signatures")
    for i, s in enumerate(sigs):
        try:
            pk = Ed25519PublicKey.from_public_bytes(base64.b64decode(s["public_key"]))
            pk.verify(base64.b64decode(s["sig"]), payload)
        except Exception:
            problems.append(f"signature {i} ({s.get('signer')}) INVALID")
    if receipt.get("seq") == 0 and receipt.get("prev_receipt_hash") is not None:
        problems.append("seq 0 must have prev_receipt_hash null")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("receipt", type=Path)
    ap.add_argument("--prev", type=Path, help="previous receipt in the session")
    ap.add_argument("--body", type=Path, help="disputed response body to check against the digest")
    args = ap.parse_args()

    receipt = json.loads(args.receipt.read_text())
    problems = verify(receipt)

    if args.prev:
        prev = json.loads(args.prev.read_text())
        if receipt.get("prev_receipt_hash") != receipt_hash(prev):
            problems.append("chain link BROKEN: prev_receipt_hash mismatch")
        if receipt.get("seq") != prev.get("seq", -2) + 1:
            problems.append("chain link BROKEN: seq not contiguous")
        if receipt.get("session_id") != prev.get("session_id"):
            problems.append("chain link BROKEN: session mismatch")

    if args.body:
        digest = hashlib.sha256(args.body.read_bytes()).hexdigest()
        if digest != receipt["response"]["body_sha256"]:
            problems.append("response body digest MISMATCH")

    print(f"receipt_hash: {receipt_hash(receipt)}")
    if problems:
        for p in problems:
            print(f"FAIL: {p}")
        return 1
    print("OK: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
