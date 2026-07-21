"""Receipt data model — mirrors receipt-spec v0.1 §4.

The stored JSON document is the source of truth for canonicalization; these
models exist for construction and validation. `model_dump(mode="json")`
includes null fields, matching the spec's "nulls included" rule.
"""
from __future__ import annotations

from pydantic import BaseModel, Field

SPEC = "agent-interaction-receipt"
SPEC_VERSION = "0.1"


class Party(BaseModel):
    role: str  # "bridge" | "provider" | "payer"
    id: str | None = None
    key_id: str | None = None


class ExchangeDigest(BaseModel):
    kind: str  # "http-request" | "http-response"
    method: str | None = None
    target: str | None = None
    status: int | None = None
    media_type: str | None = None
    body_sha256: str
    body_len: int


class PaymentInfo(BaseModel):
    protocol: str = "x402"
    scheme: str = "exact"
    network: str
    asset: str
    amount: str  # atomic units, decimal string — never a float
    pay_to: str
    payer: str | None = None
    payment_payload_sha256: str
    settlement_ref: str | None = None


class Signature(BaseModel):
    signer: str
    alg: str = "ed25519"
    key_id: str
    public_key: str
    sig: str


class ReceiptCore(BaseModel):
    """Everything that gets signed (spec §6: receipt minus `signatures`)."""

    spec: str = SPEC
    spec_version: str = SPEC_VERSION
    session_id: str
    seq: int
    prev_receipt_hash: str | None
    issued_at: str
    capability_id: str
    parties: list[Party]
    request: ExchangeDigest
    response: ExchangeDigest
    payment: PaymentInfo | None = None
    meta: dict = Field(default_factory=dict)


class Receipt(ReceiptCore):
    signatures: list[Signature]
