import base64
import hashlib
import json

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from agentbridge.config import Capability, Settings
from agentbridge.gateway.proxy import UpstreamClient
from agentbridge.main import create_app
from agentbridge.payments.facilitator import MockFacilitator
from agentbridge.receipts.signer import BridgeSigner, verify_receipt_signatures
from agentbridge.receipts.store import ReceiptStore
from tests.test_receipts import make_signer


def make_upstream() -> FastAPI:
    upstream = FastAPI()

    @upstream.post("/mcp")
    async def echo(request: Request):
        return {"echo": json.loads(await request.body())}

    return upstream


@pytest.fixture()
def client(tmp_path):
    settings = Settings(bridge_private_key="x" * 43 + "=", data_dir=str(tmp_path))
    signer: BridgeSigner = make_signer()
    caps = {
        "echo": Capability(
            id="echo", description="echo tool", upstream_url="http://upstream/mcp",
            price="1000", network="base-sepolia", asset="USDC", pay_to="0xPROVIDER",
        )
    }
    upstream_http = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=make_upstream()), base_url="http://upstream"
    )
    app = create_app(
        settings=settings,
        capabilities=caps,
        facilitator=MockFacilitator(),
        signer=signer,
        store=ReceiptStore(tmp_path),
        upstream=UpstreamClient(client=upstream_http),
    )
    return TestClient(app)


def mock_payment(payer="0xPAYER1") -> str:
    return base64.b64encode(json.dumps({"mock": True, "payer": payer}).encode()).decode()


def test_unpaid_request_gets_402_challenge(client):
    r = client.post("/mcp/echo", json={"tool": "ping"})
    assert r.status_code == 402
    body = r.json()
    assert body["x402Version"] == 1
    accept = body["accepts"][0]
    assert accept["maxAmountRequired"] == "1000"
    assert accept["payTo"] == "0xPROVIDER"
    assert accept["network"] == "base-sepolia"


def test_invalid_payment_rejected(client):
    r = client.post("/mcp/echo", json={"t": 1}, headers={"X-PAYMENT": "not-base64!!"})
    assert r.status_code == 402


def test_paid_flow_returns_body_and_verifiable_receipt(client):
    payload = {"tool": "ping", "args": {"n": 1}}
    r = client.post("/mcp/echo", json=payload, headers={"X-PAYMENT": mock_payment()})
    assert r.status_code == 200
    assert r.json() == {"echo": payload}

    settle = json.loads(base64.b64decode(r.headers["X-PAYMENT-RESPONSE"]))
    assert settle["success"] is True and settle["payer"] == "0xPAYER1"

    rhash = r.headers["X-Receipt-Hash"]
    rec = client.get(f"/receipts/{rhash}").json()
    assert rec["signature_valid"] is True
    receipt = rec["receipt"]
    assert verify_receipt_signatures(receipt)
    assert receipt["capability_id"] == "echo"
    assert receipt["payment"]["amount"] == "1000"
    assert receipt["payment"]["payer"] == "0xPAYER1"
    assert receipt["response"]["body_sha256"] == hashlib.sha256(r.content).hexdigest()
    assert receipt["seq"] == 0 and receipt["prev_entry_hash"] is None
    assert receipt["entry_type"] == "receipt" and receipt["spec_version"] == "0.2"
    assert receipt["payment"]["settlement_status"] == "settled"  # mock settles sync per §8.4
    assert receipt["payment"]["settlement_ref"].startswith("0xmock")
    assert receipt["payment"]["settle_response_sha256"] is not None


def test_session_chain_advances(client):
    h = {"X-PAYMENT": mock_payment(), "X-Bridge-Session": "sess-A"}
    r1 = client.post("/mcp/echo", json={"a": 1}, headers=h)
    r2 = client.post("/mcp/echo", json={"a": 2}, headers=h)
    rec1 = client.get(f"/receipts/{r1.headers['X-Receipt-Hash']}").json()["receipt"]
    rec2 = client.get(f"/receipts/{r2.headers['X-Receipt-Hash']}").json()["receipt"]
    assert rec1["seq"] == 0 and rec2["seq"] == 1
    assert rec2["prev_entry_hash"] == r1.headers["X-Receipt-Hash"]


def test_unknown_capability_404(client):
    assert client.post("/mcp/nope", json={}).status_code == 404
