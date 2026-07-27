import base64
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentbridge.receipts.models import ExchangeDigest, Party, ReceiptCore
from agentbridge.receipts.signer import (
    BridgeSigner,
    receipt_hash,
    verify_chain_link,
    verify_receipt_signatures,
)
from agentbridge.receipts.store import ReceiptStore

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "verifier"))
import verify as standalone_verifier  # noqa: E402


def make_signer() -> BridgeSigner:
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    return BridgeSigner(base64.b64encode(seed).decode())


def make_core() -> dict:
    core = ReceiptCore(
        session_id="", seq=0, prev_entry_hash=None, issued_at="",
        capability_id="cap-1",
        parties=[Party(role="bridge", id="https://b", key_id="k")],
        request=ExchangeDigest(kind="http-request", method="POST", target="/mcp/cap-1",
                               body_sha256="a" * 64, body_len=10),
        response=ExchangeDigest(kind="http-response", status=200,
                                body_sha256="b" * 64, body_len=20),
    ).model_dump(mode="json")
    for k in ("session_id", "seq", "prev_entry_hash", "issued_at"):
        core.pop(k)
    return core


def test_chain_and_signatures(tmp_path):
    signer = make_signer()
    store = ReceiptStore(tmp_path)

    r1, h1 = store.record("s1", make_core(), signer)
    r2, h2 = store.record("s1", make_core(), signer)

    assert r1["seq"] == 0 and r1["prev_entry_hash"] is None
    assert r2["seq"] == 1 and r2["prev_entry_hash"] == h1 == receipt_hash(r1)
    assert verify_receipt_signatures(r1) and verify_receipt_signatures(r2)
    assert verify_chain_link(r2, r1)
    assert store.get(h2) == r2
    assert [r["seq"] for r in store.session("s1")] == [0, 1]


def test_tamper_detection(tmp_path):
    signer = make_signer()
    store = ReceiptStore(tmp_path)
    r, h = store.record("s1", make_core(), signer)

    tampered = json.loads(json.dumps(r))
    tampered["response"]["body_sha256"] = "c" * 64
    assert not verify_receipt_signatures(tampered)
    assert receipt_hash(tampered) != h


def test_standalone_verifier_agrees(tmp_path):
    signer = make_signer()
    store = ReceiptStore(tmp_path)
    r1, _ = store.record("s1", make_core(), signer)
    r2, _ = store.record("s1", make_core(), signer)

    assert standalone_verifier.verify_entry(r1) == []
    assert standalone_verifier.verify_entry(r2) == []
    assert standalone_verifier.entry_hash(r1) == receipt_hash(r1)
    assert standalone_verifier.entry_hash(r1) == r2["prev_entry_hash"]

    bad = json.loads(json.dumps(r1))
    bad["capability_id"] = "evil"
    assert standalone_verifier.verify_entry(bad) != []


def test_attachment_flow_and_2814_case(tmp_path):
    """Pending receipt -> failed attachment digesting a verbatim 'processing'
    response (the x402#2814 false-assurance case), chained and pair-verified."""
    from agentbridge.receipts.attachments import build_attachment_core, derive_x402

    signer = make_signer()
    store = ReceiptStore(tmp_path)

    core = make_core()
    core["payment"] = {
        "protocol": "x402", "scheme": "exact", "network": "base-sepolia",
        "asset": "USDC", "amount": "1000", "pay_to": "0xP", "payer": "0xA",
        "payment_payload_sha256": "c" * 64,
        "settlement_status": "pending", "settlement_ref": None,
        "settle_response_sha256": None, "settle_response_len": None,
    }
    receipt, rhash = store.record("s-2814", core, signer)
    assert receipt["payment"]["settlement_status"] == "pending"

    raw = b'{"success":true,"transaction":null,"status":"processing","network":"base-sepolia"}'
    assert derive_x402(raw)[0:2] == ("failed", None)  # §8.4: processing derives failed

    att_core = build_attachment_core(rhash, raw, "https://facilitator.example")
    attachment, ahash = store.record("s-2814", att_core, signer)

    assert attachment["entry_type"] == "settlement-attachment"
    assert attachment["attaches_to"] == rhash
    assert attachment["settlement"]["final_status"] == "failed"
    assert attachment["settlement"]["tx_hash"] is None
    assert attachment["seq"] == 1 and attachment["prev_entry_hash"] == rhash
    assert verify_receipt_signatures(attachment)
    assert verify_chain_link(attachment, receipt)
    assert standalone_verifier.verify_entry(attachment) == []
    assert standalone_verifier.verify_pair(attachment, receipt) == []
    assert standalone_verifier.verify_settle_disclosure(attachment, raw) == []
    assert standalone_verifier.verify_settle_disclosure(attachment, raw + b" ") != []


def test_derive_x402_survives_hostile_inputs():
    """Dry-run finding (x402#2922): valid non-object JSON must derive failed,
    never raise. Plus the conservative behaviors confirmed on real probes."""
    from agentbridge.receipts.attachments import derive_x402

    hostile = [b'[1,2,3]', b'"ok"', b'null', b'true', b'42', b'', b'not json', b'<html>err</html>']
    for raw in hostile:
        status, tx, _ = derive_x402(raw)
        assert (status, tx) == ("failed", None), raw
    assert derive_x402(b'{"success":"true","transaction":"0x1"}')[0] == "failed"  # bool estricto
    assert derive_x402(b'{"success":true,"transaction":""}')[0] == "failed"       # tx vacío no liquida
    assert derive_x402(b'{"success":true,"transaction":"0xok"}')[0:2] == ("settled", "0xok")
    # ronda 3 (issue #7): duplicados no-conformes — mismos bytes, jamas dos veredictos
    assert derive_x402(b'{"success":true,"transaction":"0xFIRST","transaction":""}')[0:2] == ("failed", None)
    # vaaraio: una respuesta con forma de verify JAMAS cuenta como settlement
    assert derive_x402(b'{"isValid": true}')[0:2] == ("failed", None)


def test_canonical_integer_bound():
    import pytest
    from agentbridge.receipts.canonical import canonical_json
    with pytest.raises(ValueError):
        canonical_json({"body_len": 2**60})
    assert canonical_json({"n": 2**53 - 1})
