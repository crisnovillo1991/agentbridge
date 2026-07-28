#!/usr/bin/env python3
"""Standalone AIR verifier — spec v0.1 and v0.2 (§8), round-3 hardened.

Self-contained (stdlib + `cryptography` only). Hardening from the
second-implementation review (reference-repo issues #6–#13):
- every field access on parsed input is type-guarded (no crash on hostile shapes)
- duplicate JSON keys are rejected at parse time (entry level) and derive
  non-conforming (settle-response level) — same bytes may never yield two verdicts
- canonical form follows the RFC 8785 profile: UTF-16 code-unit key ordering,
  floats forbidden, integers bounded to |n| <= 2^53-1
- Ed25519 public keys that are the identity or small-order points are rejected
  before any signature math (an entry "signed" with no secret must never pass)

Usage:
  verify.py entry.json [--prev prev.json] [--receipt receipt.json]
            [--settle-response raw] [--body response.bin]
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
INT_BOUND = 2**53 - 1


# ---------------- parsing: duplicate keys are a verification failure ----------
class DuplicateKeyError(ValueError):
    pass


def _no_dup_pairs(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise DuplicateKeyError(f"duplicate key {k!r}")
        d[k] = v
    return d


def loads_strict(text: str):
    return json.loads(text, object_pairs_hook=_no_dup_pairs)


# ---------------- canonical form: RFC 8785 profile (§5) -----------------------
def _check(obj):
    if isinstance(obj, str):
        try:
            obj.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("string is not UTF-8 encodable (lone surrogate) — "
                             "no canonical form exists (§5)")
        return
    if isinstance(obj, float):
        raise ValueError("floats are forbidden by the spec (§5)")
    if isinstance(obj, bool):
        return
    if isinstance(obj, int) and abs(obj) > INT_BOUND:
        raise ValueError("integer exceeds 2^53-1 bound (§5)")
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ValueError("object keys must be strings")
            _check(v)
    elif isinstance(obj, list):
        for v in obj:
            _check(v)


def _emit(v) -> str:
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_emit(k) + ":" + _emit(x) for k, x in items) + "}"
    if isinstance(v, list):
        return "[" + ",".join(_emit(x) for x in v) + "]"
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))


def canonical(obj) -> bytes:
    _check(obj)
    return _emit(obj).encode("utf-8")


def entry_hash(entry: dict) -> str:
    return hashlib.sha256(canonical(entry)).hexdigest()


def prev_field(entry: dict) -> str:
    return "prev_receipt_hash" if entry.get("spec_version") == "0.1" else "prev_entry_hash"


# ---------------- small-order rejection (§6) ---------------------------------
_P = 2**255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P


def _decompress(pk: bytes):
    if len(pk) != 32:
        return None
    y = int.from_bytes(pk, "little") & ((1 << 255) - 1)
    sign = pk[31] >> 7
    if y >= _P:
        return None  # non-canonical encoding
    x2num = (y * y - 1) % _P
    x2den = (_D * y * y + 1) % _P
    x2 = (x2num * pow(x2den, _P - 2, _P)) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = (x * pow(2, (_P - 1) // 4, _P)) % _P
        if (x * x - x2) % _P != 0:
            return None
    if x == 0 and sign == 1:
        return None
    if x & 1 != sign:
        x = _P - x
    return (x, y)


def _edwards_add(a, b):
    x1, y1 = a
    x2, y2 = b
    den = (_D * x1 * x2 * y1 * y2) % _P
    x3 = ((x1 * y2 + x2 * y1) * pow(1 + den, _P - 2, _P)) % _P
    y3 = ((y1 * y2 + x1 * x2) * pow(1 - den, _P - 2, _P)) % _P
    return (x3, y3)


def is_small_order(pk: bytes) -> bool:
    """True iff the encoded point is invalid, the identity, or small-order
    (8·P == identity). Such keys admit signatures made with no secret."""
    pt = _decompress(pk)
    if pt is None:
        return True
    for _ in range(3):  # multiply by 8 via three doublings
        pt = _edwards_add(pt, pt)
    return pt == (0, 1)


# ---------------- entry verification (§8.1) ----------------------------------
def verify_entry(entry: dict) -> list[str]:
    problems: list[str] = []
    if not isinstance(entry, dict):
        return ["entry is not a JSON object"]
    ver = entry.get("spec_version")
    if entry.get("spec") != SPEC or ver not in ("0.1", "0.2"):
        return ["unknown spec/spec_version"]

    core = {k: v for k, v in entry.items() if k != "signatures"}
    try:
        payload = canonical(core)
    except ValueError as e:
        return [f"canonicalization failed: {e}"]
    try:
        _check(entry)  # the FULL entry must canonicalize: entry_hash needs it (§5)
    except ValueError as e:
        problems.append(f"entry not canonicalizable (outside signed payload): {e}")

    sigs = entry.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        problems.append("signatures missing or not a list")
        sigs = []
    for i, s in enumerate(sigs):
        if not isinstance(s, dict):
            problems.append(f"signature {i} is not an object")
            continue
        try:
            pk_raw = base64.b64decode(s.get("public_key") or "")
            if is_small_order(pk_raw):
                problems.append(f"signature {i}: public key is identity/small-order "
                                f"or non-canonical — REJECTED (§6)")
                continue
            expected_kid = "ed25519:" + (s.get("public_key") or "")[:12]
            if s.get("key_id") != expected_kid:
                problems.append(f"signature {i}: key_id does not match public_key (§4.4)")
            Ed25519PublicKey.from_public_bytes(pk_raw).verify(
                base64.b64decode(s.get("sig") or ""), payload)
        except Exception:
            problems.append(f"signature {i} ({s.get('signer') if isinstance(s, dict) else '?'}) INVALID")

    if not isinstance(entry.get("meta"), dict):
        problems.append("meta missing or not an object (§4.0)")
    if entry.get("seq") == 0 and entry.get(prev_field(entry)) is not None:
        problems.append(f"seq 0 must have {prev_field(entry)} null")

    # version field exclusivity: an entry may not carry the other version's names
    if ver == "0.2" and "prev_receipt_hash" in entry:
        problems.append("v0.2 entry carries v0.1 field prev_receipt_hash (§4.0)")
    if ver == "0.1" and ("prev_entry_hash" in entry or "entry_type" in entry):
        problems.append("v0.1 entry carries v0.2 field names")

    if ver == "0.2":
        etype = entry.get("entry_type")
        if etype not in ("receipt", "settlement-attachment"):
            problems.append("v0.2 entry_type missing or unknown")
        elif etype == "receipt":
            problems += _verify_receipt_shape(entry)
        else:
            problems += _verify_attachment_shape(entry)
    return problems


def _verify_receipt_shape(entry: dict) -> list[str]:
    problems = []
    if not isinstance(entry.get("capability_id"), str):
        problems.append("receipt missing capability_id (§4.5)")
    if not isinstance(entry.get("parties"), list):
        problems.append("receipt missing parties (§4.5)")
    for f in ("request", "response"):
        if not isinstance(entry.get(f), dict):
            problems.append(f"receipt missing {f} (§4.5)")
    pay = entry.get("payment")
    if pay is not None and not isinstance(pay, dict):
        problems.append("payment must be object or null (§4.3)")
    elif isinstance(pay, dict):
        status = pay.get("settlement_status")
        if status not in ("settled", "pending", "failed"):
            problems.append("payment present without valid settlement_status (§4.3)")
        if status == "settled" and not pay.get("settlement_ref"):
            problems.append("settled at issuance requires settlement_ref (§8.4)")
        if status == "pending" and pay.get("settlement_ref") is not None:
            problems.append("pending must carry settlement_ref null (§4.3)")
    return problems


def _verify_attachment_shape(entry: dict) -> list[str]:
    problems = []
    st = entry.get("settlement")
    if not isinstance(st, dict):
        return ["attachment settlement missing or not an object (§4.6)"]
    fs = st.get("final_status")
    if fs not in ("settled", "failed"):
        problems.append("attachment final_status must be settled|failed (§4.6)")
    if fs == "settled" and not (isinstance(st.get("tx_hash"), str) and st.get("tx_hash")):
        problems.append("attachment settled requires non-empty tx_hash (§8.4) — "
                        "mirror of the receipt-leg guard")
    if not entry.get("attaches_to"):
        problems.append("attachment missing attaches_to")
    if not st.get("settle_response_sha256"):
        problems.append("attachment missing settle_response_sha256")
    if not isinstance(st.get("settle_response_len"), int):
        problems.append("attachment missing settle_response_len")
    return problems


# ---------------- chain / pair / disclosure (§8.1–8.4) ------------------------
def verify_chain(entry: dict, prev: dict) -> list[str]:
    problems = []
    if not isinstance(prev, dict):
        return ["--prev is not a JSON object"]
    try:
        ph = entry_hash(prev)
    except ValueError as e:
        return [f"--prev not canonicalizable: {e}"]
    if entry.get(prev_field(entry)) != ph:
        problems.append(f"chain link BROKEN: {prev_field(entry)} mismatch")
    pseq = prev.get("seq")
    if not isinstance(pseq, int) or entry.get("seq") != pseq + 1:
        problems.append("chain link BROKEN: seq not contiguous")
    if entry.get("session_id") != prev.get("session_id"):
        problems.append("chain link BROKEN: session mismatch")
    return problems


def verify_pair(att: dict, receipt: dict) -> list[str]:
    problems = []
    if att.get("entry_type") != "settlement-attachment":
        return ["--receipt given but entry is not a settlement-attachment"]
    if not isinstance(receipt, dict):
        return ["--receipt is not a JSON object"]
    try:
        rh = entry_hash(receipt)
    except ValueError as e:
        return [f"--receipt not canonicalizable: {e}"]
    if att.get("attaches_to") != rh:
        problems.append("pair BROKEN: attaches_to does not match receipt entry hash (§8.2)")
    if att.get("session_id") != receipt.get("session_id"):
        problems.append("pair BROKEN: session mismatch")
    if not (isinstance(att.get("seq"), int) and isinstance(receipt.get("seq"), int)
            and att["seq"] > receipt["seq"]):
        problems.append("pair BROKEN: attachment seq must exceed receipt seq")
    if receipt.get("entry_type") != "receipt" or not isinstance(receipt.get("payment"), dict):
        problems.append("pair BROKEN: target is not a paid receipt")
    return problems


def derive_x402(raw: bytes) -> tuple[str, str | None, str | None]:
    """§8.4 mapping. Non-object JSON, unparseable bytes AND duplicate keys are
    non-conforming: failed/null. Same bytes must never yield two verdicts."""
    try:
        obj = loads_strict(raw.decode("utf-8"))
    except Exception:  # includes DuplicateKeyError
        return "failed", None, None
    if not isinstance(obj, dict):
        return "failed", None, None
    tx = obj.get("transaction")
    net = obj.get("network") if isinstance(obj.get("network"), str) else None
    if obj.get("success") is True and isinstance(tx, str) and tx:
        return "settled", tx, net
    return "failed", tx if isinstance(tx, str) and tx else None, net


def verify_settle_disclosure(entry: dict, raw: bytes) -> list[str]:
    problems = []
    d_status, d_tx, d_net = derive_x402(raw)
    digest = hashlib.sha256(raw).hexdigest()

    if entry.get("entry_type") == "settlement-attachment":
        st = entry.get("settlement")
        if not isinstance(st, dict):
            return ["entry has no settlement object"]
        if st.get("settle_response_sha256") != digest:
            return ["disclosure digest MISMATCH: bytes are not the digested settle response"]
        if st.get("settle_response_len") != len(raw):
            problems.append("settle_response_len does not match disclosed byte length (§4.6)")
        if st.get("final_status") != d_status:
            problems.append(f"re-derivation FAIL (§8.4): embedded final_status "
                            f"{st.get('final_status')!r} != derived {d_status!r}")
        if st.get("tx_hash") != d_tx:
            problems.append(f"re-derivation FAIL (§8.4): embedded tx_hash "
                            f"{st.get('tx_hash')!r} != derived {d_tx!r}")
        if d_net and st.get("network") and st.get("network") != d_net:
            problems.append("FLAG (§8.4): attachment network differs from response network")
    else:
        pay = entry.get("payment")
        if not isinstance(pay, dict):
            return ["entry has no payment object"]
        if pay.get("settle_response_sha256") != digest:
            return ["disclosure digest MISMATCH: bytes are not the digested settle response"]
        if pay.get("settle_response_len") is not None and pay.get("settle_response_len") != len(raw):
            problems.append("settle_response_len does not match disclosed byte length (§4.3)")
        if pay.get("settlement_status") == "settled" and (d_status != "settled"
                                                         or pay.get("settlement_ref") != d_tx):
            problems.append("re-derivation FAIL (§8.4): settled-at-issuance fields "
                            "do not re-derive from the disclosed response")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("entry", type=Path)
    ap.add_argument("--prev", type=Path)
    ap.add_argument("--receipt", type=Path)
    ap.add_argument("--settle-response", type=Path)
    ap.add_argument("--body", type=Path)
    args = ap.parse_args()

    try:
        entry = loads_strict(args.entry.read_text(encoding="utf-8"))
    except DuplicateKeyError as e:
        print(f"FAIL: entry file contains a {e} — a file may not carry fields "
              f"no check ever sees (§5)")
        return 1
    except Exception as e:
        print(f"FAIL: entry unreadable: {e}")
        return 1

    problems = verify_entry(entry)
    if args.prev:
        try:
            problems += verify_chain(entry, loads_strict(args.prev.read_text(encoding="utf-8")))
        except Exception as e:
            problems.append(f"--prev unreadable: {e}")
    if args.receipt:
        try:
            problems += verify_pair(entry, loads_strict(args.receipt.read_text(encoding="utf-8")))
        except Exception as e:
            problems.append(f"--receipt unreadable: {e}")
    if args.settle_response:
        problems += verify_settle_disclosure(entry, args.settle_response.read_bytes())
    if args.body:
        digest = hashlib.sha256(args.body.read_bytes()).hexdigest()
        resp = entry.get("response")
        if not isinstance(resp, dict) or digest != resp.get("body_sha256"):
            problems.append("response body digest MISMATCH")

    # diagnosis first; the hash only when computable (issue #6, invalid/12 ordering)
    for p in problems:
        print(f"FAIL: {p}")
    try:
        print(f"entry_hash: {entry_hash(entry)}")
    except ValueError:
        pass
    if not problems:
        pay = entry.get("payment") if isinstance(entry.get("payment"), dict) else None
        if entry.get("spec_version") == "0.2" and pay and pay.get("settlement_status") == "pending":
            print("note (§8.3): pending — dispute-grade for content, NOT payment finality, "
                  "until a matching settlement attachment is presented")
        print("OK: all requested checks passed")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
