# External time anchors (`proofbundle.anchors`)

Status: **EXPERIMENTAL**, the `[anchors]` extra. API and wire format may change. This layer is optional:
the base install pulls only `cryptography`, and a receipt with no anchors verifies exactly as before.

A receipt's own Ed25519 signature and RFC 6962 Merkle structure prove *who signed these exact bytes* and
*that nothing changed*. What they cannot prove on their own is *when* — a self-emitted timestamp is
producer-clock testimony. An **anchor** adds external evidence of time, from a party the producer does
not control.

## Two targets, never mixed

| target | claim | why |
|---|---|---|
| `preRegistration` | the commitment existed **before** the run | backdating protection (the point raised in in-toto/attestation#565) |
| `receipt` | the receipt existed **from** time T | publication proof |

An anchor's `canonicalRoot` is the canonical root of its **own** target — for `receipt` the RFC 8785
(JCS) sha256 of the receipt bundle **excluding its own `anchors` field** (the anchors are detached
evidence; an anchor cannot attest a root that already contains itself, so a verifier recomputing the
receipt root MUST strip `anchors`), for `preRegistration` the sha256 of the raw protocol bytes (the
receipt's `prereg_sha256`). A `preRegistration` anchor can therefore never validate a `receipt` target,
and vice versa: the roots differ, and a mismatch is a FAIL.

## Schema

Each `anchors[]` entry:

```jsonc
{
  "type": "rfc3161-tsa" | "opentimestamps" | "<extension>/vN",
  "target": "receipt" | "preRegistration",
  "canonicalRoot": "<base64 of the target's canonical root>",
  "proof": "<base64 of the type-specific proof>",
  "anchoredAt": "<RFC 3339 Z, INFORMATIVE only>",
  "frozen": { /* OPTIONAL type-specific material bundled at emit time, e.g. the TSA cert chain */ }
}
```

`anchoredAt` is informative — the trusted time comes from the proof, never from this field.

## Verify contract (fail-closed)

- **Missing / empty `anchors` → SKIP**, not FAIL. This matches in-toto's Monotonic Principle: deny only
  when an attestation is present and wrong, not when it is absent.
- **Present → fail-closed.** A root mismatch, an unknown `type`, or a broken proof is a **FAIL**, never
  a silent pass. A verifier that raises is treated as FAIL.
- `verify --require-anchor` turns "no verifying anchor" into a FAIL — a relying-party gate OVER the
  crypto result (exit 3 when unmet, distinct from a crypto failure exit 1, exactly like `--policy`).
  `--anchor-type <type>` narrows it to a specific type; `--allow-pending` also accepts a **pending**
  anchor (weaker). Without the flag the receipt's anchors are not evaluated at all (default unchanged).
- Anchoring **writes a new file**. A network error while stamping never corrupts the local receipt.

## Built-in types

### `rfc3161-tsa`

An RFC 3161 timestamp token from a Time-Stamping Authority. Verification is **offline** (Trail of Bits
`rfc3161-client`, `VerifierBuilder`) against the TSA's root certificate. **Freeze the chain:** the TSA
certificate + chain are bundled in the anchor's `frozen` field, because a TSA can rotate its certificate
(FreeTSA rotated its TSA certificate in March 2026) — after a rotation an old token is only offline
re-verifiable against the chain that was frozen at emit time, not the TSA's current chain. Suggested
TSAs: the Sigstore TSA (`https://timestamp.sigstore.dev/api/v1/timestamp`) and FreeTSA as a second,
independent anchor.

**Verification time (cert expiration).** The chain is validated at the token's own `gen_time`, not at
the current wall clock — a frozen token therefore stays re-verifiable after the TSA certificate has
expired or rotated (the whole point of freezing), and a certificate that was not valid at `gen_time`
fails closed. **Policy OID.** By default no TSA policy OID is pinned (any policy is accepted). A relying
party who cares which TSA policy issued the timestamp sets `frozen.policyOid` to the expected
dotted-decimal OID; a token whose `TSTInfo.policy` differs then fails closed (a malformed OID string
fails closed too).

### `opentimestamps`

An OpenTimestamps proof anchored in the Bitcoin blockchain. Honest lifecycle: a fresh stamp goes to
public calendars and is initially **PENDING** (a pending proof is a WARN / its own status, never a
full-strength anchor). `ots upgrade` embeds the Bitcoin block-header path; only then is the proof
self-contained. Verifying an upgraded proof needs no calendar, but — per the documented client path — a
**local (pruned) Bitcoin node** for the block header. There is no documented "header-file instead of a
node" mode, and we do not claim one. Doc wording to reuse verbatim: *"offline verifiable given a local
(pruned) Bitcoin node; no calendar or account needed for verification."*

**Byte-order warning (for reimplementers).** A frozen `bitcoinBlockHeaderMerkleRootsByHeight` maps a
block height to that block's `hashMerkleRoot` in **internal (node) byte order** as returned by
`bitcoind` — NOT the byte-reversed order that block explorers display. Use the internal order or every
root comparison fails. (Confirmed correct on in-toto/attestation#565 · proofbundle#7.)

## Extension mechanism — bring your own anchor type

A third party can ship an anchor `type` without changing proofbundle:

```python
from proofbundle.anchors import register_anchor_type

def verify_my_anchor(proof: bytes, canonical_root: bytes, *, frozen: dict, now):
    # Return {"ok": bool, "detail": str}. MUST be fail-closed: return ok=False on any doubt,
    # never raise for an ordinary bad proof. `canonical_root` is already matched to the target;
    # your job is to prove `proof` anchors exactly those bytes at/for a time.
    ...
    return {"ok": True, "detail": "verified against <authority>"}

register_anchor_type("my-org/timebeacon/v1", verify_my_anchor)
```

The contract: a namespaced `type` (`<org>/<name>/vN`), a fail-closed verify callable, and the
canonicalRoot ↔ target binding enforced by the layer for you. Third-party types are welcome as
extensions with credit — see in-toto/attestation#565 and the reference-implementation tracking issue.

## First-party extension — `chia-datalayer/v1` (EXPERIMENTAL, the `[chia]` extra)

The first anchor type we ship as a first-party extension, to dogfood the interface above. It is
**experimental, optional, never a default**, and never part of the in-toto proposal narrative. It anchors a
canonical root as a key in a public Chia DataLayer store whose root is published on-chain.

**Three-level honesty — read this before trusting a `chia-datalayer` anchor.** The three levels prove
strictly different things; the word "offline verifiable" applies to **level i only**:

- **Level i — `merkle` (offline, no Chia software).** The anchor's `canonicalRoot` IS the DataLayer key.
  Pure SHA-256 checks the raw key equals `canonicalRoot` and hashes (`sha256(0x01‖key)`) to `key_clvm_hash`,
  recomputes the leaf `sha256(0x02 ‖ key_clvm_hash ‖ value_clvm_hash)`, and ascends `inclusion_layers` to the
  `published_root` (each layer's `combined_hash` must be self-consistent). This proves **only** "`canonicalRoot`
  is a key included under `published_root`". It does **NOT** prove the chain binding, and it does **NOT** prove
  `published_root` is on-chain (a self-fabricated tree passes level i — that is what levels ii/iii are for).
  Because the key carries the binding, an unrelated (even genuine) proof for a different key cannot be
  relabelled to this target. This is the level `proofbundle verify` runs; `=> OK` here means Merkle-consistent,
  nothing more. Registered verifier: `anchors_chia.verify_chia_datalayer`. Because level i is not external
  time evidence, the verifier reports it as **`warn`** (`ok=True, warn=True`), the same way an un-upgraded
  OpenTimestamps proof reports PENDING: it aggregates as WARN, never a clean PASS, and it does **not**
  satisfy `--require-anchor` (which demands a full anchor, gated on `ok and not warn`). A relying party who
  needs the chain binding runs level ii/iii.
- **Level ii — `chain-binding (light)` (needs a Chia light wallet).** Confirms `coin_id` exists with the
  expected singleton puzzle hash and that `published_root` is the current (unspent) root, plus its block
  height and timestamp. Requires Chia software → **SKIP** with a clear reason when unavailable, never FAIL,
  never a silent PASS.
- **Level iii — `chain-binding (own full node)`.** Full guarantee against your own node.

**Forbidden claims** (enforced by `tests/test_anchors_chia_claims.py`): "trustless" or "on-chain proven" for level i/ii without
the node-trust caveat; any "greener chain" comparison; any XCH price/cost claim in shipped docs. Root-update
cost is an observation (~0–0.001 XCH), never a price claim.

**Writing** an anchor (`anchors_chia_add.anchor_add` / `export_anchor`) needs the `[chia]` extra + a
reachable, cert-authed **local** DataLayer node (never expose the RPC); a network/node failure raises
cleanly and writes nothing partial. **Verifying** offline needs neither — the honesty of the extension must
never depend on the extra. The anchor is versioned (`chia-datalayer/v1`); a wire change becomes `v2`.

**Worked examples** (pinned by a verdict regression test in `tests/test_anchors_chia.py`, so a wire change
that flips them turns CI red): `examples/anchors/chia-datalayer-valid.json` (a real DataLayer proof that
verifies at level i) and `examples/anchors/chia-datalayer-invalid-root.json` (the same proof with a tampered
`published_root`, which MUST reject).

**Hard limit (documented, not hidden).** There is no per-tooling-exportable weight proof and no per-coin
Merkle-against-header via RPC, so a fully trustless "this root-coin was in the heaviest chain at height H"
proof from a file alone is **not producible with standard tooling** — the practical trust anchor is a full
node (your own = trustless). Closing that gap with a standalone weight-proof verifier is **Paket 4**, a
separate, grant-eligible work package ("to our knowledge no such tool exists"), tracked as a roadmap issue,
deliberately not built in this pass.

**Chia 3.0 hard fork (~Nov 2026, 256-day plot phase-out)** affects farming; by our reading it does not
invalidate historical blocks (marked INFERENCE), to be empirically confirmed before any mainnet showcase.
