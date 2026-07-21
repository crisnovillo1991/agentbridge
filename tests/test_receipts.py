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
        session_id="", seq=0, prev_receipt_hash=None, issued_at="",
        capability_id="cap-1",
        parties=[Party(role="bridge", id="https://b", key_id="k")],
        request=ExchangeDigest(kind="http-request", method="POST", target="/mcp/cap-1",
                               body_sha256="a" * 64, body_len=10),
        response=ExchangeDigest(kind="http-response", status=200,
                                body_sha256="b" * 64, body_len=20),
    ).model_dump(mode="json")
    for k in ("session_id", "seq", "prev_receipt_hash", "issued_at"):
        core.pop(k)
    return core


def test_chain_and_signatures(tmp_path):
    signer = make_signer()
    store = ReceiptStore(tmp_path)

    r1, h1 = store.record("s1", make_core(), signer)
    r2, h2 = store.record("s1", make_core(), signer)

    assert r1["seq"] == 0 and r1["prev_receipt_hash"] is None
    assert r2["seq"] == 1 and r2["prev_receipt_hash"] == h1 == receipt_hash(r1)
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

    assert standalone_verifier.verify(r1) == []
    assert standalone_verifier.verify(r2) == []
    assert standalone_verifier.receipt_hash(r1) == receipt_hash(r1)
    assert standalone_verifier.receipt_hash(r1) == r2["prev_receipt_hash"]

    bad = json.loads(json.dumps(r1))
    bad["capability_id"] = "evil"
    assert standalone_verifier.verify(bad) != []
