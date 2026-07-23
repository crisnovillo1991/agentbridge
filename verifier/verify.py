#!/usr/bin/env python3
"""Standalone AIR verifier — spec v0.1 and v0.2 (§8).

Self-contained (stdlib + `cryptography` only). Verification must not require
trusting the issuer's code or database.

Usage:
  verify.py entry.json                          # signatures + schema
  verify.py entry.json --prev prev.json         # + chain link (§8.1)
  verify.py att.json  --receipt receipt.json    # + attachment pair (§8.2)
  verify.py entry.json --settle-response raw    # + digest + re-derivation (§8.4)
  verify.py entry.json --body response.bin      # + response body digest
Exit 0 = all requested checks passed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SPEC = "agent-interaction-receipt"


def canonical(obj) -> bytes:
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


def entry_hash(entry: dict) -> str:
    return hashlib.sha256(canonical(entry)).hexdigest()


def prev_field(entry: dict) -> str:
    return "prev_receipt_hash" if entry.get("spec_version") == "0.1" else "prev_entry_hash"


def derive_x402(raw: bytes) -> tuple[str, str | None, str | None]:
    """§8.4 normative mapping: verbatim settle response -> (final_status, tx_hash, network)."""
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception:
        return "failed", None, None
    tx = obj.get("transaction")
    net = obj.get("network") if isinstance(obj.get("network"), str) else None
    if obj.get("success") is True and isinstance(tx, str) and tx:
        return "settled", tx, net
    return "failed", tx if isinstance(tx, str) and tx else None, net


def verify_entry(entry: dict) -> list[str]:
    problems: list[str] = []
    ver = entry.get("spec_version")
    if entry.get("spec") != SPEC or ver not in ("0.1", "0.2"):
        problems.append("unknown spec/spec_version")
        return problems

    core = {k: v for k, v in entry.items() if k != "signatures"}
    try:
        payload = canonical(core)
    except ValueError as e:
        return [f"canonicalization failed: {e}"]

    sigs = entry.get("signatures") or []
    if not sigs:
        problems.append("no signatures")
    for i, s in enumerate(sigs):
        try:
            pk = Ed25519PublicKey.from_public_bytes(base64.b64decode(s["public_key"]))
            pk.verify(base64.b64decode(s["sig"]), payload)
        except Exception:
            problems.append(f"signature {i} ({s.get('signer')}) INVALID")

    if entry.get("seq") == 0 and entry.get(prev_field(entry)) is not None:
        problems.append(f"seq 0 must have {prev_field(entry)} null")

    if ver == "0.2":
        etype = entry.get("entry_type")
        if etype not in ("receipt", "settlement-attachment"):
            problems.append("v0.2 entry_type missing or unknown")
        elif etype == "receipt":
            pay = entry.get("payment")
            if pay is not None and pay.get("settlement_status") not in ("settled", "pending", "failed"):
                problems.append("payment present without valid settlement_status (§4.3)")
            if pay is not None and pay.get("settlement_status") == "settled" and not pay.get("settlement_ref"):
                problems.append("settled at issuance requires settlement_ref (§8.4.10)")
        else:
            st = (entry.get("settlement") or {})
            if st.get("final_status") not in ("settled", "failed"):
                problems.append("attachment final_status must be settled|failed (§4.6)")
            if not entry.get("attaches_to"):
                problems.append("attachment missing attaches_to")
            if not st.get("settle_response_sha256"):
                problems.append("attachment missing settle_response_sha256")
    return problems


def verify_chain(entry: dict, prev: dict) -> list[str]:
    problems = []
    if entry.get(prev_field(entry)) != entry_hash(prev):
        problems.append(f"chain link BROKEN: {prev_field(entry)} mismatch")
    if entry.get("seq") != prev.get("seq", -2) + 1:
        problems.append("chain link BROKEN: seq not contiguous")
    if entry.get("session_id") != prev.get("session_id"):
        problems.append("chain link BROKEN: session mismatch")
    return problems


def verify_pair(att: dict, receipt: dict) -> list[str]:
    problems = []
    if att.get("entry_type") != "settlement-attachment":
        problems.append("--receipt given but entry is not a settlement-attachment")
        return problems
    if att.get("attaches_to") != entry_hash(receipt):
        problems.append("pair BROKEN: attaches_to does not match receipt entry hash (§8.2)")
    if att.get("session_id") != receipt.get("session_id"):
        problems.append("pair BROKEN: session mismatch")
    if not (isinstance(att.get("seq"), int) and isinstance(receipt.get("seq"), int)
            and att["seq"] > receipt["seq"]):
        problems.append("pair BROKEN: attachment seq must exceed receipt seq")
    if receipt.get("entry_type") != "receipt" or receipt.get("payment") is None:
        problems.append("pair BROKEN: target is not a paid receipt")
    return problems


def verify_settle_disclosure(entry: dict, raw: bytes) -> list[str]:
    problems = []
    d_status, d_tx, d_net = derive_x402(raw)
    digest = hashlib.sha256(raw).hexdigest()

    if entry.get("entry_type") == "settlement-attachment":
        st = entry.get("settlement") or {}
        if st.get("settle_response_sha256") != digest:
            return ["disclosure digest MISMATCH: bytes are not the digested settle response"]
        if st.get("final_status") != d_status:
            problems.append(f"re-derivation FAIL (§8.4): embedded final_status "
                            f"{st.get('final_status')!r} != derived {d_status!r}")
        if st.get("tx_hash") != d_tx:
            problems.append(f"re-derivation FAIL (§8.4): embedded tx_hash "
                            f"{st.get('tx_hash')!r} != derived {d_tx!r}")
        if d_net and st.get("network") and st["network"] != d_net:
            problems.append("FLAG (§8.4): attachment network differs from response network")
    else:
        pay = entry.get("payment") or {}
        if pay.get("settle_response_sha256") != digest:
            return ["disclosure digest MISMATCH: bytes are not the digested settle response"]
        if pay.get("settlement_status") == "settled" and (d_status != "settled"
                                                         or pay.get("settlement_ref") != d_tx):
            problems.append("re-derivation FAIL (§8.4): settled-at-issuance fields "
                            "do not re-derive from the disclosed response")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("entry", type=Path)
    ap.add_argument("--prev", type=Path, help="previous entry in the session (§8.1)")
    ap.add_argument("--receipt", type=Path, help="receipt an attachment resolves (§8.2)")
    ap.add_argument("--settle-response", type=Path, help="verbatim settle response bytes (§8.4)")
    ap.add_argument("--body", type=Path, help="disputed response body to check against digest")
    args = ap.parse_args()

    entry = json.loads(args.entry.read_text())
    problems = verify_entry(entry)

    if args.prev:
        problems += verify_chain(entry, json.loads(args.prev.read_text()))
    if args.receipt:
        problems += verify_pair(entry, json.loads(args.receipt.read_text()))
    if args.settle_response:
        problems += verify_settle_disclosure(entry, args.settle_response.read_bytes())
    if args.body:
        digest = hashlib.sha256(args.body.read_bytes()).hexdigest()
        if digest != (entry.get("response") or {}).get("body_sha256"):
            problems.append("response body digest MISMATCH")

    print(f"entry_hash: {entry_hash(entry)}")
    pay = entry.get("payment") or {}
    if entry.get("spec_version") == "0.2" and pay.get("settlement_status") == "pending":
        print("note (§8.3): pending — dispute-grade for content, NOT payment finality, "
              "until a matching settlement attachment is presented")
    if problems:
        for p in problems:
            print(f"FAIL: {p}")
        return 1
    print("OK: all requested checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
