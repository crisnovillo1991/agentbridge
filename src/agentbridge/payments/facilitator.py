"""Facilitator abstraction (x402 verify/settle).

The facilitator layer is still moving, so it lives behind our own interface
from day one: the gateway only ever talks to `Facilitator`. Swapping
Coinbase's hosted facilitator for another (or for on-chain self-settlement)
is a config change, not a refactor.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Protocol

import httpx
from pydantic import BaseModel, Field


class PaymentRequirements(BaseModel):
    """One entry of an x402 `accepts` array (snake_case internally)."""

    scheme: str = "exact"
    network: str
    asset: str
    pay_to: str
    max_amount_required: str  # atomic units, decimal string
    resource: str
    description: str = ""
    mime_type: str = "application/json"
    max_timeout_seconds: int = 60
    extra: dict = Field(default_factory=dict)

    def to_wire(self) -> dict:
        """camelCase form used on the wire by x402 v1."""
        return {
            "scheme": self.scheme,
            "network": self.network,
            "asset": self.asset,
            "payTo": self.pay_to,
            "maxAmountRequired": self.max_amount_required,
            "resource": self.resource,
            "description": self.description,
            "mimeType": self.mime_type,
            "maxTimeoutSeconds": self.max_timeout_seconds,
            "extra": self.extra,
        }


class VerifyResult(BaseModel):
    valid: bool
    payer: str | None = None
    reason: str | None = None


class SettleResult(BaseModel):
    settled: bool
    tx_hash: str | None = None
    reason: str | None = None


class Facilitator(Protocol):
    async def verify(self, payment_b64: str, req: PaymentRequirements) -> VerifyResult: ...
    async def settle(self, payment_b64: str, req: PaymentRequirements) -> SettleResult: ...


class MockFacilitator:
    """Accepts X-PAYMENT = base64({"mock": true, "payer": "0x..."}).

    Lets the whole 402 → pay → serve → receipt loop run end-to-end in dev and
    tests with zero chain access.
    """

    async def verify(self, payment_b64: str, req: PaymentRequirements) -> VerifyResult:
        try:
            payload = json.loads(base64.b64decode(payment_b64))
        except Exception:
            return VerifyResult(valid=False, reason="X-PAYMENT is not base64 JSON")
        if payload.get("mock") is not True:
            return VerifyResult(valid=False, reason="mock facilitator requires {'mock': true}")
        return VerifyResult(valid=True, payer=payload.get("payer", "0xMOCKPAYER"))

    async def settle(self, payment_b64: str, req: PaymentRequirements) -> SettleResult:
        ref = hashlib.sha256(payment_b64.encode()).hexdigest()[:16]
        return SettleResult(settled=True, tx_hash=f"0xmock{ref}")


class HttpFacilitator:
    """Coinbase-style hosted facilitator over HTTP.

    TODO(v0): confirm exact request/response shapes against the current
    facilitator API docs before mainnet use; treat this as a sketch of the
    integration point, validated only against the interface above.
    """

    def __init__(self, base_url: str, client: httpx.AsyncClient | None = None):
        self._base = base_url.rstrip("/")
        self._client = client or httpx.AsyncClient(timeout=30)

    async def verify(self, payment_b64: str, req: PaymentRequirements) -> VerifyResult:
        body = {
            "x402Version": 1,
            "paymentPayload": json.loads(base64.b64decode(payment_b64)),
            "paymentRequirements": req.to_wire(),
        }
        r = await self._client.post(f"{self._base}/verify", json=body)
        data = r.json()
        return VerifyResult(
            valid=bool(data.get("isValid")),
            payer=data.get("payer"),
            reason=data.get("invalidReason"),
        )

    async def settle(self, payment_b64: str, req: PaymentRequirements) -> SettleResult:
        body = {
            "x402Version": 1,
            "paymentPayload": json.loads(base64.b64decode(payment_b64)),
            "paymentRequirements": req.to_wire(),
        }
        r = await self._client.post(f"{self._base}/settle", json=body)
        data = r.json()
        return SettleResult(
            settled=bool(data.get("success")),
            tx_hash=data.get("transaction"),
            reason=data.get("errorReason"),
        )
