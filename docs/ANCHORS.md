# External time anchors (`proofbundle.anchors`)

Status: **EXPERIMENTAL**, the `[anchors]` extra. API and wire format may change. This layer is optional:
the base install pulls only `cryptography`, and a receipt with no anchors verifies exactly as before.

A receipt's own Ed25519 signature and RFC 6962 Merkle structure prove *who signed these exact bytes* and
*that nothing changed*. What they cannot prove on their own is *when* — a self-emitted timestamp is
producer-clock testimony. An **anchor** adds external evidence of time, from a party the producer does
not control.

## Three targets, never mixed

| target | claim | why |
|---|---|---|
| `preRegistration` | the commitment existed **before** the run | backdating protection (the point raised in in-toto/attestation#565) |
| `receipt` | the receipt existed **from** time T | publication proof |
| `statement` | this in-toto Statement's content existed **from** time T | the content root of a DSSE Statement (used by decision receipts); kept **detached** — an anchor cannot live inside the signed bytes whose hash it commits (proofbundle#7 consensus, 2026-07-10) |

> **Note — `statement` is NOT a valid target inside a `proofbundle/v0.1` bundle's own `anchors[]`.** The
> bundle schema's `target` enum is `receipt` | `preRegistration` only (`schemas/proofbundle_v0_1.schema.json`;
> SPEC §7i lists `statement` as RESERVED there). The `statement` target applies exclusively to **decision
> receipts**, supplied as DETACHED evidence via `decision verify --anchors <file>` — never in a bundle's
> `anchors[]`. A bundle carrying `target: "statement"` is rejected as malformed (exit 2). The schema example
> and targets below therefore describe the anchor **layer**; a v0.1 bundle may only use `receipt` / `preRegistration`.

An anchor's `canonicalRoot` is the canonical root of its **own** target — for `receipt` the RFC 8785
(JCS) sha256 of the receipt bundle **excluding its own `anchors` field** (the anchors are detached
evidence; an anchor cannot attest a root that already contains itself, so a verifier recomputing the
receipt root MUST strip `anchors`), for `preRegistration` the sha256 of the raw protocol bytes (the
receipt's `prereg_sha256`), for `statement` the sha256 of the exact DSSE payload bytes (the
`statement_content_root`). A `preRegistration` anchor can therefore never validate a `receipt` or
`statement` target, and vice versa: the roots differ, and a mismatch is a FAIL.

## Schema

Each `anchors[]` entry:

```jsonc
{
  "type": "rfc3161-tsa" | "opentimestamps" | "<extension>/vN",
  "target": "receipt" | "preRegistration" | "statement",
  "canonicalRoot": "<base64 of the target's canonical root>",
  "proof": "<base64 of the type-specific proof>",
  "anchoredAt": "<RFC 3339 Z, INFORMATIVE only>",
  "frozen": { /* OPTIONAL type-specific material bundled at emit time, e.g. the TSA cert chain */ }
}
```

`anchoredAt` is informative — the trusted time comes from the proof, never from this field.

**Privacy.** An anchor publishes only a **digest / Merkle root** (the `canonicalRoot`) and its
type-specific `proof` — never the target's payload. A `statement` anchor timestamps the SHA-256 of the
signed payload bytes, so a decision predicate's contents (input digests, policy id, verdict, the
not-checked set) are committed-to without the anchor itself revealing any of them.

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

### Trust model (WP-A1) — trust comes from the relying party, never the bundle

Since revision 2026-07-11, an anchor's TRUST comes ONLY from the relying party, never from the bundle.
The `frozen` block is producer-controlled **evidence** (reported as `frozenEvidence`), never a trust
source: a malicious producer could freeze its OWN self-signed TSA root, or a self-committed backdated
Bitcoin block header, and self-certify a **backdated** timestamp. So a confirmed verdict requires the
relying party to supply the matching trust material out of band:

- `rfc3161-tsa`: `verify --trusted-tsa-root <PATH>` (repeatable, DER or PEM), or policy
  `anchors.trusted_tsa_roots`.
- `opentimestamps`: `verify --bitcoin-header <HEIGHT:MERKLEROOT_HEX>` (internal byte order, from your own
  Bitcoin node), or policy `anchors.bitcoin_block_headers`.

Without it a time anchor is `needs_rp_trust` (ok=False) and `--require-anchor` is **unmet → exit 3**,
never a silent pass. Per-entry results carry `rp_trusted` / `needs_rp_trust` / `frozenEvidence`. The
frozen material still travels with the receipt (TSA rotation evidence) and is reported — only its role as
a trust source is gone.

### `rfc3161-tsa`

An RFC 3161 timestamp token from a Time-Stamping Authority. Verification is **offline** (Trail of Bits
`rfc3161-client`, `VerifierBuilder`) against a TSA root certificate the **relying party supplies**
(`--trusted-tsa-root` / policy `anchors.trusted_tsa_roots`), NOT the anchor's own `frozen` root. The
producer still freezes the chain as EVIDENCE (a TSA can rotate its certificate — FreeTSA rotated in March
2026 — and the frozen intermediates/tsa-cert are path-building material validated up to the RP root), but
the trust anchor is the relying party's root. Suggested TSAs: the Sigstore TSA
(`https://timestamp.sigstore.dev/api/v1/timestamp`) and FreeTSA as a second, independent anchor.

**Verification time (cert expiration).** The chain is validated at the token's own `gen_time`, not at
the current wall clock — a token therefore stays re-verifiable after the TSA certificate has expired or
rotated, and a certificate that was not valid at `gen_time` fails closed. **Policy OID.** By default no
TSA policy OID is pinned. A relying party who cares which TSA policy issued the timestamp pins it via
`anchors.trusted_tsa_policy_oids`, or the producer declares a stricter-only `frozen.policyOid`; a token
whose `TSTInfo.policy` differs then fails closed (a malformed OID string fails closed too).

### `opentimestamps`

An OpenTimestamps proof anchored in the Bitcoin blockchain. Honest lifecycle: a fresh stamp goes to
public calendars and is initially **PENDING** (a pending proof is a WARN / its own status, never a
full-strength anchor). `ots upgrade` embeds the Bitcoin block-header path; only then is the proof
self-contained. Verifying an upgraded proof needs no calendar, but it needs the block's `hashMerkleRoot`
for the attested height — the **relying party** supplies it (`--bitcoin-header` / policy
`anchors.bitcoin_block_headers`) from their own **local (pruned) Bitcoin node**, never the bundle's frozen
header. There is no documented "header-file instead of a node" mode, and we do not claim one. Doc wording
to reuse verbatim: *"offline verifiable given a local (pruned) Bitcoin node; no calendar or account needed
for verification."*

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
node (run your own and no third-party trust remains). Closing that gap with a standalone weight-proof
verifier is **Paket 4**, a
separate, grant-eligible work package ("to our knowledge no such tool exists"), tracked as a roadmap issue,
deliberately not built in this pass.

**Chia 3.0 hard fork (~Nov 2026, 256-day plot phase-out)** affects farming; by our reading it does not
invalidate historical blocks (marked INFERENCE), to be empirically confirmed before any mainnet showcase.
