"""Canonical serialization per receipt-spec v0.2 §5 (round-3 revision).

RFC 8785 (JCS) profile: compact separators, object keys sorted by UTF-16
code units, raw UTF-8 for non-ASCII, nulls included — with two profile
restrictions on top: floats are forbidden (amounts are decimal strings) and
integers are bounded to |n| <= 2^53-1 so every conforming stack, including
double-backed JSON parsers, re-serializes them identically.

For ASCII keys UTF-16 code-unit order equals code-point order, so all
receipts emitted under the previous revision are byte-identical here.
"""
from __future__ import annotations

import json
from typing import Any

INT_BOUND = 2**53 - 1


def canonical_json(obj: Any) -> bytes:
    _reject_invalid(obj)
    return _emit(obj).encode("utf-8")


def _emit(v: Any) -> str:
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_emit(k) + ":" + _emit(x) for k, x in items) + "}"
    if isinstance(v, list):
        return "[" + ",".join(_emit(x) for x in v) + "]"
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))


def _reject_invalid(obj: Any) -> None:
    if isinstance(obj, bool) or obj is None or isinstance(obj, str):
        return
    if isinstance(obj, float):
        raise ValueError("floats are forbidden in receipts; use decimal strings")
    if isinstance(obj, int):
        if abs(obj) > INT_BOUND:
            raise ValueError("integer exceeds 2^53-1 bound (spec §5)")
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ValueError("object keys must be strings")
            _reject_invalid(v)
        return
    if isinstance(obj, list):
        for v in obj:
            _reject_invalid(v)
        return
    raise ValueError(f"unsupported type in receipt: {type(obj).__name__}")
