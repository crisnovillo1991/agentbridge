"""x402 gate: builds 402 challenges and validates X-PAYMENT headers."""
from __future__ import annotations

import base64
import json

from fastapi.responses import JSONResponse

from ..config import Capability
from .facilitator import PaymentRequirements

X402_VERSION = 1
PAYMENT_HEADER = "x-payment"
PAYMENT_RESPONSE_HEADER = "X-PAYMENT-RESPONSE"


def requirements_for(cap: Capability, resource: str) -> PaymentRequirements:
    return PaymentRequirements(
        network=cap.network,
        asset=cap.asset,
        pay_to=cap.pay_to,
        max_amount_required=cap.price,
        resource=resource,
        description=cap.description,
    )


def challenge(cap: Capability, resource: str, error: str = "X-PAYMENT header is required") -> JSONResponse:
    """x402 v1-shaped 402 response with a single `accepts` entry."""
    return JSONResponse(
        status_code=402,
        content={
            "x402Version": X402_VERSION,
            "error": error,
            "accepts": [requirements_for(cap, resource).to_wire()],
        },
    )


def settlement_header(settled: bool, tx_hash: str | None, network: str, payer: str | None) -> str:
    payload = {
        "success": settled,
        "transaction": tx_hash,
        "network": network,
        "payer": payer,
    }
    return base64.b64encode(json.dumps(payload).encode()).decode()
