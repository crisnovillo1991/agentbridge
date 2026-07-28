# Agent Interaction Receipt (AIR) — Specification v0.2 (draft)

Status: **draft** · License: CC-BY-4.0 · Reference implementation: [agentbridge](https://github.com/crisnovillo1991/agentbridge)

Changes from v0.1 are listed in §11. The settlement-attachment model in this
version was designed in the open with the x402 community
([x402-foundation/x402#2922](https://github.com/x402-foundation/x402/issues/2922)),
driven by real facilitator failure data
([x402-foundation/x402#2814](https://github.com/x402-foundation/x402/issues/2814)).

## 1. Abstract

This document specifies compact, verifiable **chain entries** for
machine-to-machine interactions. v0.2 defines two entry types sharing one
envelope, one canonical form, one signing scheme and one hash chain:

1. **Receipt** — binds, under a digital signature: cryptographic digests of a
   request and its response, the payment that authorized the exchange (if
   any) with an explicit settlement status, the parties involved, and a
   position in a tamper-evident per-session chain.
2. **Settlement attachment** — a later entry in the same chain that resolves
   a receipt's pending settlement, preserving a digest of the **verbatim**
   facilitator settle response as evidence of what was claimed at settle
   time.

Entries are designed so that **any third party can verify them offline** with
open-source tooling, without trusting the issuer's database, and without the
issuer needing to store (or even see) plaintext message content.

## 2. Design goals

- **Content-free evidence.** Entries commit to content by hash only.
  Plaintext (bodies, payment payloads, settle responses) MAY be stored
  elsewhere and disclosed selectively during a dispute.
- **Rail-agnostic.** Payment binding is defined generically; v0.2 profiles
  the [x402] protocol, including a normative mapping from facilitator settle
  responses to normalized fields (§8.4).
- **Offline verifiability.** An entry embeds every public key needed to check
  its signatures. Trust in *who controls* a key is out of band (§9).
- **Append-only sessions.** Entries within a session are hash-chained so that
  deletion or reordering is detectable. Immutability is why late-arriving
  settlement is modeled as a *new* entry, never as mutation of a receipt.
- **Failure-first evidence.** Disputes concentrate exactly where transaction
  hashes come up empty or wrong; the format is designed around that case, not
  around the happy path.

## 3. Terminology

- **Entry** — a receipt or a settlement attachment; the unit of the chain.
- **Issuer** — the party that signs and emits an entry (a gateway/bridge, or
  an endpoint self-issuing).
- **Provider** — the party operating the capability being called.
- **Payer** — the party paying for and initiating the call.
- **Facilitator** — the service consulted to verify and settle a payment.
- **Session** — an ordered sequence of entries sharing a `session_id`.
- **Entry hash** — SHA-256 of the canonical form of a complete entry (§5).
- **Canonical form** — the deterministic byte serialization defined in §5.

Keywords MUST, SHOULD, MAY are to be interpreted as in RFC 2119.

## 4. Data model

Every entry is a JSON object. **Number rule (unchanged from v0.1):**
floating-point numbers are **forbidden** anywhere in an entry. Monetary
amounts and other decimals MUST be encoded as decimal strings; only true
integers (`seq`, `status`, lengths) may use JSON numbers.

### 4.0 Shared envelope (all entries)

| Field | Type | Req | Description |
|---|---|---|---|
| `spec` | string | yes | Constant `"agent-interaction-receipt"`. |
| `spec_version` | string | yes | `"0.2"`. |
| `entry_type` | string | yes | `"receipt"` or `"settlement-attachment"`. |
| `session_id` | string | yes | Opaque session identifier. |
| `seq` | integer | yes | 0-based position within the session. |
| `prev_entry_hash` | string \| null | yes | Hex SHA-256 entry hash of the previous entry in the session; `null` iff `seq == 0`. (v0.1 name: `prev_receipt_hash`.) |
| `issued_at` | string | yes | RFC 3339 UTC, millisecond precision, `Z` suffix. |
| `meta` | object | yes | Extension point. MAY be empty. Keys MUST be strings. |
| `signatures` | array of Signature | yes | See §4.4. At least the issuer signature. |

### 4.1 Party

| Field | Type | Req | Description |
|---|---|---|---|
| `role` | string | yes | `"bridge"`, `"provider"` or `"payer"`. |
| `id` | string \| null | yes | Stable identifier: URL, wallet address, agent ID, DID. |
| `key_id` | string \| null | yes | Key identifier if this party signs (§6). |

### 4.2 ExchangeDigest

| Field | Type | Req | Description |
|---|---|---|---|
| `kind` | string | yes | `"http-request"` or `"http-response"`. |
| `method` | string \| null | yes | HTTP method (requests) or `null`. |
| `target` | string \| null | yes | Logical target (secrets stripped) or `null`. |
| `status` | integer \| null | yes | HTTP status (responses) or `null`. |
| `media_type` | string \| null | yes | `Content-Type`, parameters stripped. |
| `body_sha256` | string | yes | Lowercase hex SHA-256 of the exact body bytes. |
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
| `payment_payload_sha256` | string | yes | Hex SHA-256 of the raw payment payload (v1: `X-PAYMENT` header value; v2: `PAYMENT-SIGNATURE`). Binds the receipt to the signed authorization without embedding it. |
| `settlement_status` | string | yes | `"settled"`, `"pending"` or `"failed"` **as of issuance** (§8.3). |
| `settlement_ref` | string \| null | yes | Transaction hash if settled at issuance, else `null`. MUST be `null` when `settlement_status` is `"pending"`. |
| `settle_response_sha256` | string \| null | no | Hex SHA-256 of the verbatim facilitator settle response bytes, when a settle was attempted at issuance. RECOMMENDED whenever `settlement_status != "pending"`. |
| `settle_response_len` | integer \| null | no | Length in bytes of that response. |

The embedded normalized fields (`payer`, and — when derived from a settle
response — `settlement_status`, `settlement_ref`) are bound by the
re-derivation invariant of §8.4.

### 4.4 Signature

| Field | Type | Req | Description |
|---|---|---|---|
| `signer` | string | yes | Role of the signing party (`"bridge"`, …). |
| `alg` | string | yes | `"ed25519"` in v0.2. |
| `key_id` | string | yes | `"ed25519:"` + first 12 chars of the base64 public key. |
| `public_key` | string | yes | Base64 of the raw 32-byte Ed25519 public key. |
| `sig` | string | yes | Base64 Ed25519 signature over the signing payload (§6). |

### 4.5 Receipt entry (`entry_type: "receipt"`)

Adds to the envelope:

| Field | Type | Req | Description |
|---|---|---|---|
| `capability_id` | string | yes | Identifier of the capability/tool invoked. |
| `parties` | array of Party | yes | MUST contain exactly one issuer (`bridge`) entry. |
| `request` | ExchangeDigest | yes | §4.2. |
| `response` | ExchangeDigest | yes | §4.2. |
| `payment` | PaymentInfo \| null | yes | §4.3. `null` for unpaid/free calls. |

### 4.6 Settlement attachment entry (`entry_type: "settlement-attachment"`)

Resolves — or documents the failure of — a prior receipt's settlement. Adds
to the envelope:

| Field | Type | Req | Description |
|---|---|---|---|
| `attaches_to` | string | yes | Entry hash of the receipt being resolved. MUST reference a receipt earlier in the same session. |
| `settlement.final_status` | string | yes | `"settled"` or `"failed"`. Never `"pending"` — a pending attachment is meaningless. Derived per §8.4. |
| `settlement.tx_hash` | string \| null | yes | On-chain transaction hash if present in the settle response, else `null`. Derived per §8.4. MUST be a non-empty string when `final_status` is `"settled"`. |
| `settlement.network` | string \| null | yes | Network as claimed by the response when present, else issuer context. |
| `settlement.facilitator_id` | string | yes | Identifier/URL of the facilitator consulted. Issuer-attested. |
| `settlement.response_timestamp` | string | yes | RFC 3339 UTC time the response was received. Issuer-attested. |
| `settlement.settle_response_sha256` | string | yes | Hex SHA-256 of the **full verbatim** facilitator settle response bytes. The core evidence of this entry. |
| `settlement.settle_response_len` | integer | yes | Length in bytes of that response. |

An issuer MAY emit multiple attachments for the same receipt if the
facilitator's story changes (e.g. `failed` followed later by `settled` when a
transaction lands late). Each is chained; verifiers take the highest-`seq`
attachment as current status, while every attachment permanently preserves
the response evidence it digested.

**Rationale (informative).** Transaction hash + final status cover the happy
path — anyone can reconcile a hash against the chain. Disputes concentrate
exactly where those come up empty or wrong: a facilitator answers
"processing" and no transaction ever lands. A hash-only attachment has
nothing to attach in that case, leaving the receipt holder asserting "the
facilitator told me it was fine" with no evidence. The digested verbatim
response is the only artifact that proves what the facilitator actually
claimed at settle time. Hash-only optimizes the case that needs the least
evidence.

## 5. Canonical form

The canonical form of a JSON value is its serialization per **RFC 8785
(JCS)** — compact separators, object keys sorted by **UTF-16 code units**,
JSON.stringify-style escaping, raw UTF-8 for non-ASCII, `null` values
**included** (never omitted) — with two profile restrictions and one
file-level rule on top:

- **Floats are forbidden** anywhere in an entry (unchanged since v0.1).
- **Integers MUST satisfy |n| ≤ 2^53 − 1**, so every conforming stack —
  including double-backed JSON parsers — re-serializes them identically.
- **Every string MUST be UTF-8 encodable.** JSON parsers admit lone
  surrogates that UTF-8 refuses; such an entry has **no canonical form and
  no entry hash**, so verifiers MUST reject it — anywhere in the entry,
  including outside the signed payload (issue #15: two conforming stacks
  must never disagree on whether a content address exists).
- **Duplicate keys are non-conforming.** Canonicalization is defined over
  the parsed value; a file whose parse must drop a duplicate key carries
  bytes no check can see. Verifiers MUST parse entry files with duplicate
  detection and fail on any duplicate.

(UTF-16 code-unit order and code-point order agree across the **entire Basic
Multilingual Plane** and diverge only above it — astral keys sort *before*
BMP keys that compare higher by code point. Every previously published
vector is ASCII and therefore byte-identical under this section; vector
valid/11 pins the astral boundary. With the
pre-action layer's `decision_ref` built on JCS and adjacent receipt formats
canonicalizing via JCS, this is convergence, not divergence.)

- **Signing payload** = canonical form of the entry **without** `signatures`.
- **Entry hash** = SHA-256 of the canonical form of the **complete** entry
  (including `signatures`) — which is why the **full entry** MUST be
  canonicalizable, not only the signed core. Used for `prev_entry_hash`
  chaining, for `attaches_to` references, and for content-addressing.

## 6. Signatures

The issuer MUST sign every entry: `sig = Ed25519.sign(sk, signing_payload)`.
Additional co-signatures MAY be appended over the same payload.

Public keys MUST be canonical encodings of points **outside the small-order
subgroup**: verifiers MUST reject the identity point and any point `P` with
`8·P = identity` **before** evaluating the signature equation, and MUST
check `key_id` consistency with `public_key` (§4.4). Without the
small-order rule, an entry "signed" with no secret at all (identity key,
zero scalar) satisfies the verification equation in mainstream libraries —
the §9 false-assurance threat wearing the format's own uniform. Co-signing
and algorithm agility (secp256k1, ERC-1271 contract signatures) remain on the
v0.3 list (§11).

## 7. Chaining

Within a session, entry `n` MUST carry
`prev_entry_hash = entry_hash(entry n−1)` and `seq = n`. Receipts and
settlement attachments interleave freely in one chain.

Chaining provides **no-rewriting**: a verifier holding a contiguous run of
entries can prove that nothing inside the run was altered, reordered, or
removed after issuance — any such edit breaks a link. That is what makes
"the attachment was swapped" a detectable claim rather than an assertion.

Chaining does **not** provide **no-omission**, and cannot in principle: an
interaction that occurred but was never receipted leaves no gap — the next
issued entry links to the previous one and the sequence reads as intact.
Absence of an entry is evidence about the tape, never about the world. The
same limit applies at a run's end: holding entries up to `seq n` proves
nothing about whether entries beyond `n` exist, which is why §8.3 scopes its
rules to attachments "in the holder's possession".

Closing no-omission requires a mechanism outside the chain — out of scope
for v0.2 and listed for v0.3: a declared issuance cadence (heartbeat
entries, so silence becomes distinguishable from idleness), or an
independently enumerable obligation set in which each covered interaction
obligates exactly one receipt. The x402 profile has a natural candidate:
settled payments are enumerable on-chain, and §4.3 binds each payment to its
receipt. Naming this limit is what makes the no-rewriting claim strong.

One further limit, stated rather than implied: chaining constrains a
*presented* run, and cannot prevent **equivocation** — an issuer signing two
different successors at the same `(session, seq)` with the same
`prev_entry_hash`. Each branch verifies independently. What the format does
give: two signed entries at the same position with different hashes are
**jointly self-incriminating**, cryptographic proof of equivocation the
moment both surface. Anchoring turns "detectable when surfaced" into
"concealable never".

Anchoring (Merkle root per epoch to a chain and/or RFC 3161) remains out of
scope for v0.2 (§11).

## 8. Verification procedure

### 8.1 Any entry

1. Parse; check `spec`; dispatch on `spec_version` (`"0.1"` entries use the
   v0.1 field names and rules; the remainder of §8 assumes `"0.2"`).
   Enforce the number rule and the presence of `entry_type`.
2. Remove `signatures`; compute the canonical form; verify every embedded
   signature. All MUST verify.
3. If the predecessor entry is supplied: check
   `prev_entry_hash == entry_hash(predecessor)`, `seq == predecessor.seq + 1`
   and equal `session_id`.

### 8.2 Attachment ↔ receipt pair

Given an attachment `A` and a receipt `R`:

4. `A.attaches_to == entry_hash(R)`; `A.session_id == R.session_id`;
   `A.seq > R.seq`; `R.entry_type == "receipt"`; `R.payment != null`.

### 8.3 Dispute-grade rules (normative)

5. A receipt with `payment.settlement_status == "pending"` and **no**
   matching attachment in the holder's possession is dispute-grade for
   **content** (what was asked and answered) but **NOT for payment
   finality**. Verifiers MUST NOT treat issuance as settlement.
6. A `settled` status — at issuance or via attachment — is reconciled
   against the chain by `tx_hash` / `settlement_ref`; the on-chain record is
   authoritative for value movement.
7. A `failed` attachment with its preserved response digest is itself
   evidence of what the facilitator claimed at settle time; the delta between
   that claim and the on-chain record is a finding, not a verification error.

### 8.4 Re-derivation invariant and the x402 facilitator profile (normative)

8. Whenever raw digested bytes are disclosed (a payment payload or a settle
   response), embedded normalized fields MUST re-derive from those exact
   bytes. A mismatch does not invalidate the signature — the entry still
   proves what the issuer attested — but the disclosure MUST be flagged as
   inconsistent, which is itself dispute-relevant.
9. For the x402 profile, the settle-response mapping is:
   - Parse the verbatim bytes as UTF-8 JSON. If parsing fails, **or the
     parsed value is not a JSON object** (a bare string, number, boolean,
     null or array), **or the object contains duplicate keys** (last-wins
     and first-wins parsers would otherwise derive opposite finality from
     identical bytes; RFC 8785 §3.1 precedent), the response is
     *non-conforming*: `final_status` MUST be `"failed"`, `tx_hash` MUST
     be `null`.
   - Verify-leg and settle-leg responses are **different evidence
     classes**. A verify-shaped reply — e.g. `{"isValid": true}` with no
     `transaction` — proves a payment was *verified*, never that it
     *settled*, and MUST NOT be treated as settlement evidence. The mapping
     already enforces this (`settled` requires `success` **and** a
     transaction); this names the rule.
   - `final_status = "settled"` **iff** the parsed object has
     `success == true` **and** `transaction` is a non-empty string.
     Otherwise `final_status = "failed"`. (Note: a response claiming
     `"processing"` therefore derives as `failed` for attachment purposes —
     the preserved verbatim digest, not an optimistic status, carries the
     claim.)
   - `tx_hash = transaction` when it is a non-empty string, else `null`.
   - When the parsed object carries a `network` string, the attachment's
     `settlement.network` SHOULD equal it; a mismatch MUST be flagged.
10. At receipt issuance, `settlement_status` is constrained the same way:
    `"settled"` MUST only be embedded when a settle response satisfying the
    mapping above was obtained (and SHOULD then be digested into
    `settle_response_sha256`). `"pending"` covers no-settle-attempted and
    non-terminal responses; `"failed"` covers terminal failures per the
    mapping.

Steps 1–7 require no network access. Rule 6's chain reconciliation (§8.3) is
the only check that touches a ledger, and it is optional for format validity.

## 9. Security considerations

- **What an entry proves:** that at issuance the holder of the issuing key
  attested to exactly this content at this chain position. **What it does
  not prove:** that a response is *true*, that the issuer is honest, or the
  real-world identity behind a key.
- **False assurance is the central threat this version addresses.** Treating
  an issued receipt as a settled payment turns facilitator latency into
  false assurance; §8.3 exists to make that misreading a specification
  violation rather than a plausible mistake.
- **Preserved claims cut both ways.** A digested verbatim settle response
  protects the receipt holder when settlement silently fails, and protects
  the facilitator against fabricated "it said it was fine" claims — neither
  side can retroactively edit what was said.
- **Key trust** is out of band: publish issuer keys at a well-known URL, in
  an on-chain identity registry (ERC-8004-style), or pin contractually. Key
  rotation SHOULD start a new session.
- **Timestamps** are issuer claims until anchored (§7).
- **Prose is not a transport.** Copies of signed artifacts pasted into
  comments, chats or docs are non-authoritative: rendering surfaces
  silently normalize whitespace and truncate fields, producing false
  "signature invalid" alarms indistinguishable from real signing bugs.
  Bindings to external artifacts (e.g. `meta.authorization`) SHOULD carry
  the exact content hash and a checksum-stable retrieval pointer (raw URL,
  relay event, content-addressed store); inline copies are illustrative
  only. Learned empirically: see `experiments/issue-4/REPORT.md`.
- **Non-repudiation, not recomputability.** Content-free digests prove what
  was recorded and that it is unaltered; a verifier without the underlying
  bytes cannot re-derive the request or response from the receipt. A
  deliberate privacy trade — but the two claims must not be conflated.
- **Privacy:** digests of low-entropy bodies can be brute-forced;
  implementations SHOULD use salted digests for guessable sensitive bodies
  (`meta.body_hash_salted: true`), disclosing the salt only with the body.
- Parties SHOULD store their own copies of entries as they receive them; an
  issuer can refuse to issue, but cannot rewrite entries others hold.

## 10. Examples

### 10.1 Receipt with pending settlement (v0.2)

```json
{
  "spec": "agent-interaction-receipt",
  "spec_version": "0.2",
  "entry_type": "receipt",
  "session_id": "vidainf-prices:0xA1b2…",
  "seq": 0,
  "prev_entry_hash": null,
  "issued_at": "2026-07-23T14:03:22.117Z",
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
              "settlement_status": "pending", "settlement_ref": null,
              "settle_response_sha256": null, "settle_response_len": null},
  "meta": {},
  "signatures": [{"signer": "bridge", "alg": "ed25519", "key_id": "ed25519:mAxb12Qw9zKe",
                  "public_key": "mAxb12Qw9zKe…", "sig": "Zk9s…"}]
}
```

### 10.2 Failed settlement attachment (the false-assurance case)

```json
{
  "spec": "agent-interaction-receipt",
  "spec_version": "0.2",
  "entry_type": "settlement-attachment",
  "session_id": "vidainf-prices:0xA1b2…",
  "seq": 1,
  "prev_entry_hash": "9f2c…e1",
  "issued_at": "2026-07-23T14:09:40.008Z",
  "attaches_to": "9f2c…e1",
  "settlement": {
    "final_status": "failed",
    "tx_hash": null,
    "network": "base-sepolia",
    "facilitator_id": "https://facilitator.example",
    "response_timestamp": "2026-07-23T14:09:39.612Z",
    "settle_response_sha256": "c41d…",
    "settle_response_len": 96
  },
  "meta": {"note": "settle answered processing; no transaction landed within policy window"},
  "signatures": [{"signer": "bridge", "alg": "ed25519", "key_id": "ed25519:mAxb12Qw9zKe",
                  "public_key": "mAxb12Qw9zKe…", "sig": "Qw3t…"}]
}
```

## 11. Versioning & changelog

Unknown keys inside `meta` MUST be preserved and included in
canonicalization. Breaking changes bump `spec_version` so verifiers can
dispatch.

**v0.2** (this document):
- New entry model: shared envelope + `entry_type`; `prev_receipt_hash`
  renamed `prev_entry_hash`; "receipt hash" generalized to "entry hash".
- `PaymentInfo.settlement_status` (settled | pending | failed) required;
  optional settle-response digest at issuance.
- New settlement-attachment entry (§4.6) with verbatim-digested facilitator
  responses; multiple attachments per receipt allowed.
- Normative dispute-grade rules (§8.3) and re-derivation invariant with the
  x402 facilitator mapping (§8.4).
- Resolves reference-repo issues #1 and #2; design credit to the
  contributors in x402-foundation/x402#2922, grounded in the failure data of
  x402-foundation/x402#2814.
- **Round 3.1** (third independent run — issue #15): strings MUST be UTF-8
  encodable anywhere in the entry (lone surrogates have no canonical form;
  the silent-accept regression found by a 13,244-mutation structural fuzz is
  fixed and pinned by invalid/22); the verify-leg-as-settlement rule gains
  its vector (invalid/21); the §5 BMP boundary is stated precisely and
  pinned by valid/11; §8.4's step numbering corrected.
- **Round 3** (second-implementation review — issues #6–#13, all fixes in
  one release): §5 adopts RFC 8785 outright with the profile restrictions
  (float ban, |int| ≤ 2^53−1) and makes duplicate keys non-conforming at
  both layers (#7, #8); §6 adds small-order/identity-point rejection and
  key_id consistency (#12); §7 names equivocation as an explicit limit
  (#11); §8.4 names the verify/settle evidence-class boundary and derives
  duplicate-key responses as non-conforming; the attachment leg gains the
  settled⇒tx_hash guard (#9); the verifier enforces every schema Req and
  never answers with a traceback (#6, #10); KEY.txt and every file
  read/write pin UTF-8 (#13 — the same class resurfaced read-side during
  the issue-4 close and is fixed repo-wide). The 31-entry hostile corpus
  behind these findings lives at `test-vectors/hostile-corpus/`
  (SHA256SUMS intact) as the permanent regression suite, credited to its
  author, SmartFlow Observatory (github.com/smartflowproai-lang). New vectors valid/10 and invalid/16–20 pin each class.
- §7 rewritten to separate **no-rewriting** (which chaining provides) from
  **no-omission** (which chaining cannot provide in principle); no-omission
  mechanisms (issuance cadence, enumerable obligation sets) are scoped to
  v0.3. §9 adds the non-repudiation-vs-recomputability distinction. Both
  precisions come from independent review in the ERC-8004 Ethereum
  Magicians thread.
- §8.4 non-object-JSON clarification and vector valid/09 come from an
  independent dry-run by SmartFlow Observatory (github.com/smartflowproai-lang) of the mapping against 610 archived production
  facilitator responses (same thread). Evidence formats should be hardened
  by real failures, not happy-path examples.

**Planned for v0.3:** first-class `authorization` field with transport
discipline (`authorization_uri`, `authorization_sha256`, `transport_hint`;
see issue #14); provider/payer co-signatures; algorithm agility
(secp256k1, ERC-1271 contract signatures); Merkle anchoring profile;
RFC 3161 timestamp attachment; salted-digest mode as default; x402 v2 wire
profile (`PAYMENT-REQUIRED` / `PAYMENT-SIGNATURE` headers, CAIP identifiers).

[x402]: https://www.x402.org

## Provenance of findings

Every normative change in this document traces to a source, in the same
spirit as every value in a receipt:

- **SmartFlow Observatory** (github.com/smartflowproai-lang): the #2814
  settlement failure data that shaped v0.2; three production dry-runs
  against a 610-response facilitator archive; the independent second
  implementation; the 31-entry hostile corpus behind issues #6–#13; the
  lone-surrogate find (#15).
- **invinoveritas** (github.com/babyblueviper1): the pre-action interop
  experiment (issue #4), the three transport failures that produced §9's
  "prose is not a transport" note, and the shipped `content_sha256`
  precedent for `authorization_sha256`.
- **pipavlo82** (github.com/pipavlo82/crystal-receipt): the
  no-rewriting/no-omission correction (§7, issue #5) and the
  obligation-record prior art scoped into v0.3.
- **0xbrainkid**: the transport-discipline schema for the v0.3
  `authorization` field (issue #14).
- **vaaraio**: the verify-leg/settle-leg evidence-class distinction (§8.4).
- **clai-mach** (ERC-8004 thread): the receipt-layer/reputation-layer
  boundary that scopes §7's omission mechanisms as interfaces.
