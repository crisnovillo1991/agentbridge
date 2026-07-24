"""agentbridge gateway — FastAPI wiring.

Flow per paid call (see specs/receipt-spec-v0.1.md):
  no X-PAYMENT → 402 challenge → client pays & retries → verify (facilitator)
  → forward to upstream MCP → settle (best effort) → sign receipt → respond
  with body + X-Receipt-Hash + X-PAYMENT-RESPONSE.
"""
from __future__ import annotations

import base64
import json
import os

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from .config import Capability, Settings, load_capabilities
from .gateway.a2a_adapter import build_agent_card
from .gateway.proxy import UpstreamClient
from .payments import x402
from .payments.facilitator import Facilitator, HttpFacilitator, MockFacilitator
from .receipts.attachments import derive_x402
from .receipts.canonical import canonical_json
from .receipts.models import ExchangeDigest, Party, PaymentInfo, ReceiptCore
from .receipts.signer import BridgeSigner, sha256_hex, verify_receipt_signatures
from .receipts.store import ReceiptStore


def create_app(
    settings: Settings,
    capabilities: dict[str, Capability],
    facilitator: Facilitator,
    signer: BridgeSigner,
    store: ReceiptStore,
    upstream: UpstreamClient,
) -> FastAPI:
    app = FastAPI(title="agentbridge", version="0.1.0")

    @app.get("/healthz")
    async def healthz():
        return {"ok": True, "bridge_key_id": signer.key_id}

    @app.get("/capabilities")
    async def list_capabilities():
        return [
            {
                "id": c.id,
                "description": c.description,
                "price": c.price,
                "asset": c.asset,
                "network": c.network,
                "endpoint": f"/mcp/{c.id}",
            }
            for c in capabilities.values()
        ]

    @app.get("/.well-known/agent-card.json")
    async def agent_card():
        return build_agent_card(settings.bridge_id, capabilities)

    @app.get("/receipts/{rhash}")
    async def get_receipt(rhash: str):
        receipt = store.get(rhash)
        if receipt is None:
            return JSONResponse(status_code=404, content={"error": "unknown receipt"})
        return {"receipt": receipt, "signature_valid": verify_receipt_signatures(receipt)}

    @app.post("/mcp/{cap_id}")
    async def bridged_call(cap_id: str, request: Request):
        cap = capabilities.get(cap_id)
        if cap is None:
            return JSONResponse(status_code=404, content={"error": f"unknown capability '{cap_id}'"})

        body = await request.body()
        resource = str(request.url)

        # Optional pre-action authorization binding (experiment issue #4):
        # X-AIR-Authorization: base64(JSON) -> signed into meta.authorization.
        authorization = None
        auth_hdr = request.headers.get("x-air-authorization")
        if auth_hdr:
            try:
                authorization = json.loads(base64.b64decode(auth_hdr))
                assert isinstance(authorization, dict)
                assert isinstance(authorization.get("scheme"), str)
                assert isinstance(authorization.get("decision_ref"), str)
                canonical_json(authorization)  # enforce the number rule early (§4)
            except Exception:
                return JSONResponse(status_code=400, content={
                    "error": "X-AIR-Authorization must be base64 JSON object with "
                             "string 'scheme' and 'decision_ref'; floats forbidden"})
        paid = cap.price != "0"
        payment_b64 = request.headers.get(x402.PAYMENT_HEADER)
        payer, payment_info, settle_hdr = None, None, None

        if paid:
            if not payment_b64:
                return x402.challenge(cap, resource)
            req_model = x402.requirements_for(cap, resource)
            vr = await facilitator.verify(payment_b64, req_model)
            if not vr.valid:
                return x402.challenge(cap, resource, error=vr.reason or "payment invalid")
            payer = vr.payer

        status, media_type, resp_body = await upstream.forward(
            cap, body, request.headers.get("content-type")
        )

        if paid:
            sr, settle_raw = await facilitator.settle(payment_b64, x402.requirements_for(cap, resource))
            settle_hdr = x402.settlement_header(sr.settled, sr.tx_hash, cap.network, payer)
            d_status, d_tx, _ = derive_x402(settle_raw)  # §8.4: status is derived, never asserted
            payment_info = PaymentInfo(
                network=cap.network,
                asset=cap.asset,
                amount=cap.price,
                pay_to=cap.pay_to,
                payer=payer,
                payment_payload_sha256=sha256_hex(payment_b64.encode()),
                settlement_status=d_status,
                settlement_ref=d_tx,
                settle_response_sha256=sha256_hex(settle_raw),
                settle_response_len=len(settle_raw),
            )

        core = ReceiptCore(
            session_id="",  # assigned by the store
            seq=0,
            prev_entry_hash=None,
            issued_at="",
            capability_id=cap.id,
            parties=[
                Party(role="bridge", id=settings.bridge_id, key_id=signer.key_id),
                Party(role="provider", id=cap.provider_id or cap.pay_to or None),
                Party(role="payer", id=payer),
            ],
            request=ExchangeDigest(
                kind="http-request",
                method="POST",
                target=f"/mcp/{cap.id}",
                media_type=(request.headers.get("content-type") or "").split(";")[0] or None,
                body_sha256=sha256_hex(body),
                body_len=len(body),
            ),
            response=ExchangeDigest(
                kind="http-response",
                status=status,
                media_type=media_type,
                body_sha256=sha256_hex(resp_body),
                body_len=len(resp_body),
            ),
            payment=payment_info,
            meta={"authorization": authorization} if authorization else {},
        ).model_dump(mode="json")
        for k in ("session_id", "seq", "prev_entry_hash", "issued_at"):
            core.pop(k)

        session_id = request.headers.get("x-bridge-session") or f"{cap.id}:{payer or 'anon'}"
        _, rhash = store.record(session_id, core, signer)

        headers = {"X-Receipt-Hash": rhash}
        if settle_hdr:
            headers[x402.PAYMENT_RESPONSE_HEADER] = settle_hdr
        return Response(
            content=resp_body, status_code=status, media_type=media_type, headers=headers
        )

    return app


def app_from_env() -> FastAPI:
    settings = Settings()
    capabilities = load_capabilities(settings.capabilities_file)
    facilitator: Facilitator
    if settings.facilitator == "http":
        facilitator = HttpFacilitator(settings.facilitator_url)
    else:
        facilitator = MockFacilitator()
    return create_app(
        settings=settings,
        capabilities=capabilities,
        facilitator=facilitator,
        signer=BridgeSigner(settings.bridge_private_key),
        store=ReceiptStore(settings.data_dir),
        upstream=UpstreamClient(),
    )


if os.getenv("BRIDGE_PRIVATE_KEY"):
    app = app_from_env()
