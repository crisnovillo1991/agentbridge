"""Canonical serialization per receipt-spec v0.1 §5.

Deterministic JSON: sorted keys, minimal separators, UTF-8, non-ASCII kept
raw, nulls included. Floats are forbidden by the spec (amounts are decimal
strings), which makes this a strict, trivially portable subset of RFC 8785.
"""
from __future__ import annotations

import json
from typing import Any


def canonical_json(obj: Any) -> bytes:
    _reject_invalid(obj)
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _reject_invalid(obj: Any) -> None:
    if isinstance(obj, bool) or obj is None or isinstance(obj, (int, str)):
        return
    if isinstance(obj, float):
        raise ValueError("floats are forbidden in receipts; use decimal strings")
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ValueError("object keys must be strings")
            _reject_invalid(v)
        return
    if isinstance(obj, (list, tuple)):
        for v in obj:
            _reject_invalid(v)
        return
    raise ValueError(f"type not allowed in receipts: {type(obj).__name__}")
