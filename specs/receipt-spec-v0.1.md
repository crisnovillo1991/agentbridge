# Agent Interaction Receipt (AIR) — Specification v0.1 (draft)

Status: **draft** · License: CC-BY-4.0 · Reference implementation: `agentbridge`

## 1. Abstract

This document specifies a compact, verifiable **receipt** for a single
machine-to-machine interaction (typically one paid request/response between two
AI agents, or between an agent and a capability endpoint). A receipt binds
together, under a digital signature:

1. cryptographic digests of the request and the response,
2. the payment that authorized the exchange (if any),
3. the identities of the parties involved, and
4. a position in a tamper-evident hash chain per session.

Receipts are designed so that **any third party can verify them offline** with
open-source tooling, without trusting the issuer's database, and without the
issuer needing to store (or even see) plaintext message content.

## 2. Design goals

- **Content-free evidence.** The receipt commits to content by hash only.
  Plaintext bodies MAY be stored elsewhere (encrypted, content-addressed by the
  same hash) and disclosed selectively during a dispute.
- **Rail-agnostic.** Payment binding is defined generically; v0.1 profiles the
  [x402] protocol, but AP2 mandates, card-rail references or invoice IDs fit in
  the same structure.
- **Offline verifiability.** A receipt embeds every public key needed to check
  its signatures. Trust in *who controls* a key is out of band (see §9).
- **Append-only sessions.** Receipts within a session are hash-chained so that
  deletion or reordering is detectable.

## 3. Terminology

- **Bridge** — the intermediary that relays the interaction and issues the
  receipt (in the reference implementation, the agentbridge gateway).
- **Provider** — the party operating the capability being called.
- **Payer** — the party paying for and initiating the call.
- **Session** — an ordered sequence of receipts sharing a `session_id`.
- **Canonical form** — the deterministic byte serialization defined in §5.

Keywords MUST, SHOULD, MAY are to be interpreted as in RFC 2119.

## 4. Data model

A receipt is a JSON object. Top-level fields:

| Field | Type | Req | Description |
|---|---|---|---|
| `spec` | string | yes | Constant `"agent-interaction-receipt"`. |
| `spec_version` | string | yes | `"0.1"`. |
| `session_id` | string | yes | Opaque session identifier. |
| `seq` | integer | yes | 0-based position within the session. |
| `prev_receipt_hash` | string \| null | yes | Hex SHA-256 of the **full canonical form** (including signatures) of the previous receipt in the session; `null` iff `seq == 0`. |
| `issued_at` | string | yes | RFC 3339 UTC timestamp with millisecond precision, `Z` suffix. |
| `capability_id` | string | yes | Identifier of the capability/tool invoked. |
| `parties` | array of Party | yes | See §4.1. MUST contain exactly one `bridge` entry. |
| `request` | ExchangeDigest | yes | See §4.2. |
| `response` | ExchangeDigest | yes | See §4.2. |
| `payment` | PaymentInfo \| null | yes | See §4.3. `null` for unpaid/free calls. |
| `meta` | object | yes | Extension point. MAY be empty. Keys MUST be strings. |
| `signatures` | array of Signature | yes | See §4.4. At least the bridge signature. |

**Number rule.** Floating-point numbers are **forbidden** anywhere in a
receipt. Monetary amounts, rates and other decimals MUST be encoded as decimal
strings. Only integers (`seq`, `status`, `body_len`, …) may use JSON numbers.
This removes every cross-language number-serialization ambiguity from §5.

### 4.1 Party

| Field | Type | Req | Description |
|---|---|---|---|
| `role` | string | yes | `"bridge"`, `"provider"` or `"payer"`. |
| `id` | string \| null | yes | Stable identifier: URL, wallet address, agent ID, DID. |
| `key_id` | string \| null | yes | Key identifier if this party signs (see §6). |

### 4.2 ExchangeDigest

| Field | Type | Req | Description |
|---|---|---|---|
| `kind` | string | yes | `"http-request"` or `"http-response"`. |
| `method` | string \| null | yes | HTTP method (requests) or `null`. |
| `target` | string \| null | yes | Logical target (path or upstream URL, secrets stripped) or `null`. |
| `status` | integer \| null | yes | HTTP status (responses) or `null`. |
| `media_type` | string \| null | yes | `Content-Type`, parameters stripped. |
| `body_sha256` | string | yes | Lowercase hex SHA-256 of the exact body bytes. Empty body → hash of the empty string. |
| `body_len` | integer | yes | Body length in bytes. |

### 4.3 PaymentInfo (x402 profile)

| Field | Type | Req | Description |
|---|---|---|---|
| `protocol` | string | yes | `"x402"` in this profile. |
| `scheme` | string | yes | e.g. `"exact"`. |
| `network` | string | yes | e.g. `"base"`, `"base-sepolia"`. |
| `asset` | string | yes | Asset contract address or symbol. |
| `amount` | string | yes | Atomic units, decimal string. |
| `pay_to` | string | yes | Provider settlement address. |
| `payer` | string \| null | yes | Payer address as reported by verification. |
| `payment_payload_sha256` | string | yes | Hex SHA-256 of the raw `X-PAYMENT` header value. Binds the receipt to the signed payment authorization without embedding it. |
| `settlement_ref` | string \| null | yes | Transaction hash / facilitator reference, if settlement completed before issuance. |

### 4.4 Signature

| Field | Type | Req | Description |
|---|---|---|---|
| `signer` | string | yes | Role of the signing party (`"bridge"`, …). |
| `alg` | string | yes | `"ed25519"` in v0.1. |
| `key_id` | string | yes | `"ed25519:"` + first 12 chars of the base64 public key. |
| `public_key` | string | yes | Base64 of the raw 32-byte Ed25519 public key. |
| `sig` | string | yes | Base64 Ed25519 signature over the signing payload (§6). |

## 5. Canonical form

The canonical form of a JSON value is the UTF-8 encoding of its JSON
serialization with: object keys sorted lexicographically by Unicode code
point; separators `,` and `:` with no whitespace; no escaping of non-ASCII
characters; `null` values **included** (never omitted). Combined with the
number rule of §4 this is a strict subset of RFC 8785 (JCS) and is trivially
reproducible in any language.

- **Signing payload** = canonical form of the receipt object **without** the
  `signatures` field.
- **Receipt hash** = SHA-256 of the canonical form of the **complete** receipt
  object (including `signatures`). This is the value used for
  `prev_receipt_hash` chaining and for content-addressing stored receipts.

## 6. Signatures

The bridge MUST sign every receipt: `sig = Ed25519.sign(sk, signing_payload)`.
Additional co-signatures (provider, payer) MAY be appended; they sign the same
payload. Co-signing is the v0.2 upgrade path toward two-sided
non-repudiation; in v0.1 a receipt proves what **the bridge** attested.

## 7. Chaining

Within a session, receipt `n` MUST carry
`prev_receipt_hash = receipt_hash(receipt n−1)` and `seq = n`. A verifier
holding a contiguous run of receipts can prove no receipt in the run was
altered, inserted or removed. Periodic anchoring of the latest receipt hash
(or a Merkle root over many sessions) to an external timestamping authority —
a public blockchain, RFC 3161 TSA, or both — upgrades tamper-*evidence* to
tamper-*proof with a time bound*, and is intentionally out of scope for v0.1.

## 8. Verification procedure

Given a receipt `R` (and optionally its predecessor `P`):

1. Parse `R`; check `spec`/`spec_version`; enforce the number rule.
2. Remove `signatures`; compute the canonical form; for each signature, verify
   with the embedded `public_key`. All MUST verify.
3. If `P` is supplied: compute `receipt_hash(P)` and check it equals
   `R.prev_receipt_hash` and `R.seq == P.seq + 1`.
4. If disputed content is supplied (a request or response body, or an
   `X-PAYMENT` value): hash it and compare against the corresponding digest.

Steps 1–3 require no network access and no trust in the issuer's storage.

## 9. Security considerations

- **What a receipt proves:** that at issuance time the holder of the bridge
  key attested to this exact (request-hash, response-hash, payment) triple at
  this chain position. **What it does not prove:** that the response content
  is *true*, that the bridge is honest, or real-world identity of key holders.
- **Key trust** is out of band: publish the bridge public key at a well-known
  URL, in an on-chain identity registry (e.g. ERC-8004 style), or pin it
  contractually. Key rotation SHOULD start a new session.
- **Timestamps** are claims by the issuer until anchored (§7).
- **Privacy:** digests of low-entropy bodies can be brute-forced. Where bodies
  are guessable and sensitive, implementations SHOULD hash
  `body || per-receipt salt` and disclose the salt only with the body. A
  `meta.body_hash_salted: true` flag signals this mode.
- A bridge that colludes with one party can refuse to issue receipts, but it
  cannot forge a chain that verifiers already hold copies of. Countermeasure:
  parties SHOULD store their own copies of receipts as they receive them.

## 10. Example

```json
{
  "spec": "agent-interaction-receipt",
  "spec_version": "0.1",
  "session_id": "vidainf-prices:0xA1b2…",
  "seq": 3,
  "prev_receipt_hash": "9f2c…e1",
  "issued_at": "2026-07-21T14:03:22.117Z",
  "capability_id": "vidainf-prices",
  "parties": [
    {"role": "bridge", "id": "https://bridge.example", "key_id": "ed25519:mAxb12Qw9zKe"},
    {"role": "provider", "id": "0xProviderWallet…", "key_id": null},
    {"role": "payer", "id": "0xA1b2…", "key_id": null}
  ],
  "request": {"kind": "http-request", "method": "POST", "target": "/mcp/vidainf-prices",
              "status": null, "media_type": "application/json",
              "body_sha256": "3a91…", "body_len": 184},
  "response": {"kind": "http-response", "method": null, "target": null,
               "status": 200, "media_type": "application/json",
               "body_sha256": "b7ce…", "body_len": 2048},
  "payment": {"protocol": "x402", "scheme": "exact", "network": "base-sepolia",
              "asset": "USDC", "amount": "1000", "pay_to": "0xProviderWallet…",
              "payer": "0xA1b2…", "payment_payload_sha256": "77aa…",
              "settlement_ref": "0xTxHash…"},
  "meta": {},
  "signatures": [
    {"signer": "bridge", "alg": "ed25519", "key_id": "ed25519:mAxb12Qw9zKe",
     "public_key": "mAxb12Qw9zKe…", "sig": "Zk9s…"}
  ]
}
```

## 11. Versioning & extensibility

Unknown keys inside `meta` MUST be preserved and included in canonicalization.
Breaking changes bump `spec_version`. Planned for v0.2: provider/payer
co-signatures, Merkle anchoring profile, RFC 3161 timestamp attachment,
salted-digest mode as default.

[x402]: https://www.x402.org
