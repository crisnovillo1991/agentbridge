# agentbridge

**Turn any MCP server into a paid, receipt-issuing agent endpoint.**

agentbridge sits in front of a capability (today: any Streamable-HTTP MCP
server) and gives it three things its author doesn't have to build:

1. **A paywall** — per-call payments via [x402] (HTTP 402 + stablecoins).
   Funds settle **directly** from payer to the provider's wallet; the bridge
   never holds customer money.
2. **A signed receipt for every call** — request/response digests, payment
   binding and a per-session hash chain, verifiable offline by anyone. See
   [`specs/receipt-spec-v0.1.md`](specs/receipt-spec-v0.1.md).(canonical home: [agent-receipt-spec](https://github.com/crisnovillo1991/agent-receipt-spec))
3. **(v0.5) An A2A face** — an auto-generated Agent Card and task-lifecycle
   mapping so A2A-speaking agents can hire the capability.

Status: **pre-alpha skeleton.** The 402 → verify → forward → receipt loop is
implemented and tested against a mock facilitator. Nothing here has touched
mainnet money.

## Quickstart

```bash
pip install -e ".[dev]"
python scripts/keygen.py          # paste output into .env (see .env.example)
cp capabilities.example.yaml capabilities.yaml   # edit upstreams & prices
uvicorn agentbridge.main:app --port 8402
```

Exercise the paid flow with the mock facilitator:

```bash
# 1. No payment → 402 challenge with x402 `accepts`
curl -s -X POST localhost:8402/mcp/vidainf-prices -d '{"q":"iphone 13 screen"}'

# 2. Pay (mock) and retry → 200 + X-Receipt-Hash + X-PAYMENT-RESPONSE
PAY=$(printf '{"mock": true, "payer": "0xME"}' | base64 -w0)
curl -si -X POST localhost:8402/mcp/vidainf-prices \
     -H "X-PAYMENT: $PAY" -d '{"q":"iphone 13 screen"}'

# 3. Fetch and independently verify the receipt
curl -s localhost:8402/receipts/<hash> | python -c \
  'import json,sys; open("r.json","w").write(json.dumps(json.load(sys.stdin)["receipt"]))'
python verifier/verify.py r.json
```

Or `docker compose up` (port 8402).

## Architecture

```
payer agent ──POST /mcp/{id}──▶ agentbridge ──▶ upstream MCP server
                 │  402 gate (x402)   │
                 │  facilitator ◀─────┘ verify / settle
                 ▼
          signed receipt ──▶ content-addressed store (+ sqlite index)
                              GET /receipts/{hash}   verifier/verify.py
```

- `src/agentbridge/payments/facilitator.py` — the **Facilitator interface**
  (verify/settle) with a mock and an HTTP (Coinbase-style) implementation.
  The moving x402 facilitator layer stays behind this seam.
- `src/agentbridge/receipts/` — canonicalization, Ed25519 signing, hash
  chaining, storage. The heart of the project.
- `verifier/verify.py` — standalone verifier, no agentbridge imports: proof
  that receipts don't require trusting us.
- `src/agentbridge/gateway/a2a_adapter.py` — v0.5 scope, documented stub.

## Honest TODO (the three known hard parts)

1. **Streaming**: MCP progress notifications ⇄ A2A task updates, plus
   incremental body hashing for SSE passthrough (v0 buffers).
2. **Upstream auth**: v0 supports static API keys only; OAuth passthrough later.
3. **Facilitator wire format**: `HttpFacilitator` must be validated against
   the current facilitator API before real funds; mock covers dev/tests.

Also: co-signed receipts (provider/payer), Merkle anchoring, RFC 3161
timestamps — spec'd in v0.1 §11, not yet built.

## License

Code: MIT. Receipt spec: CC-BY-4.0. The spec is meant to be implemented by
others — interoperable receipts are the point.

[x402]: https://www.x402.org
