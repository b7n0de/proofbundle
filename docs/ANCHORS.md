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

**RFC 3161 as a first-class legal second anchor (the eIDAS hedge).** RFC 3161 is not a lesser cousin of
OpenTimestamps, it is the complementary trade-off: centralized and trust-bearing (you trust the TSA) but
immediate (no wait for a Bitcoin confirmation) and legally recognized. A timestamp from an eIDAS
QUALIFIED Time-Stamping Authority (profile ETSI EN 319 422, RFC 5816) carries a legal presumption of the
date and time it shows under eIDAS (Regulation 910/2014, Article 41), recognized across EU Member States.
So a receipt can carry BOTH anchors: OpenTimestamps for the neutral, trust-minimized, offline-verifiable
Bitcoin existence proof, and a qualified RFC 3161 token for an immediate, legally recognized second
opinion. They complement each other; neither replaces the other, and neither proves anything about the
correctness of the timestamped content. The anchor registry stays open and fail-closed: an unknown anchor
`type` is a FAIL, so adding a legal TSA anchor never weakens the verify contract.

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

**Library vs client (do not confuse the two).** The `[anchors]` extra installs the OpenTimestamps
`opentimestamps` LIBRARY (`python-opentimestamps`, the consensus-critical `opentimestamps.core`
modules), pinned on the 0.4.x line. The separate `opentimestamps-client` CLI tool is a DIFFERENT PyPI
package on the 0.7.x line and is not a dependency of proofbundle. proofbundle only needs the library to
deserialize and classify a proof; the actual stamping and the `ots upgrade` network step are done by the
client (or your own tooling) out of band.

### OTS lifecycle at the CLI, and calendar independence

The `proofbundle anchor` group turns the honest OTS lifecycle into a small offline toolset. The stamp and
the `ots upgrade` step are network and time gated (a Bitcoin confirmation takes time), so they live in the
OpenTimestamps client; proofbundle owns the two steps that need no calendar:

```bash
# 1. (out of band) stamp and, after a Bitcoin confirmation, upgrade with the OpenTimestamps client:
#    ots stamp receipt.canonical-root ; ... wait ... ; ots upgrade receipt.canonical-root.ots
# 2. bundle the UPGRADED proof into a self-contained, calendar-independent evidence pack:
proofbundle anchor upgrade --proof proof.ots --target-file target.bytes --out pack.json
# 3. verify the pack OFFLINE against a relying-party Bitcoin header (your own node or a trusted checkpoint):
proofbundle anchor verify-pack pack.json --bitcoin-header 800000:<MERKLEROOT_HEX_INTERNAL_ORDER>
# transparency, no crypto trust: show the lifecycle state and which calendars carry a proof:
proofbundle anchor inspect proof.ots
```

Exit contract: `anchor upgrade` exits 3 (never a fake pass) on a still-PENDING proof and writes no pack;
`anchor verify-pack` exits 0 confirmed, 3 pending or upgraded-without-a-relying-party-header (honest
not-pass), 1 hard fail (unbound / block mismatch / malformed pack), 2 malformed input. A calendar outage
or a calendar defunding therefore affects only STAMPING availability, never the verifiability of a proof
that is already upgraded: `verify-pack` opens no socket, and it never trusts the pack's own bundled header
(a producer could self-commit a backdated one), only a header the relying party supplies.

### Calendar transparency and running your own calendar (WP-B)

The default OpenTimestamps configuration submits to three calendar endpoints across at least two
independent operators (`a`/`b.pool.opentimestamps.org` operated by OpenTimestamps and
`a.pool.eternitywall.com` operated by Eternity Wall), and requires at least two to reply, so any single
calendar can be down with no effect.

**Proven vs declared (No-Fake, Berkeley audit 2026-07-16).** `anchor inspect` and the evidence pack
surface two clearly separated calendar classes, and only one of them is audit evidence:

- `provenCalendars` / `operatorRedundancy` are read from the PROOF ITSELF (its retained pending
  attestations). This is the only redundancy figure a reviewer may treat as evidence. An UPGRADED proof
  that retains no pending attestation honestly proves `operatorRedundancy: 0`: after upgrade the calendar
  dependency is discharged and which calendars carried the stamp is no longer recoverable from the proof.
- `declaredCalendars` are producer testimony recorded verbatim with `declaredCalendarsVerified: false`.
  They are documentation only, are NOT audit evidence, and never count toward operator redundancy (a
  producer could list calendars it never used).

`operatorRedundancy` counts distinct INDEPENDENT operators, because two URLs on one operator are one point
of failure, not two. **Heuristic blind spot (documented, not hidden).** The operator label is a
bare-hostname heuristic, not a verified-independent-entity claim: an unknown host falls back to its last
two labels, which does not know the public-suffix boundary, so a ccSLD host like `cal.example.co.uk`
collapses to `co.uk` (and `example.com.au` to `com.au`) and two genuinely independent operators under one
ccSLD would be undercounted as one. Treat it as a transparency hint; for a real independence claim, pin
the operators you trust (an optional `tldextract` dependency would resolve the boundary and is deliberately
not added, keeping this a heuristic).

A relying party who does not want to depend on the public calendars can run or pin their own. The
OpenTimestamps client reads a calendar allowlist (its `--calendar` flags and its `otsclient` config), and
a private or curated calendar server is the `opentimestamps-server` package pointed at your own Bitcoin
node. Record the calendars you used with `anchor upgrade --calendar-declared <url>` for documentation, but
they are stored as unverified testimony (`declaredCalendarsVerified: false`), never presented as redundancy
evidence. proofbundle imposes no calendar; it records the ones you declare and proves only what the proof
carries.

### Getting a trusted Bitcoin header for verification (WP-C)

Confirming an upgraded proof needs the attested block's Merkle root, and that value is the last trust
assumption. Three honest ways to obtain it, strongest first:

- **Your own (pruned) Bitcoin node.** `bitcoin-cli getblockheader <hash>` gives `merkleroot` in internal
  order; a pruned node keeps all headers, so this needs little disk. This removes third-party trust.
- **A trusted checkpoint you ship.** A relying party may bundle a small, offline set of height to
  Merkle-root pairs curated ahead of time. This trades the node for whoever curated the checkpoint, which
  is why we surface it as an explicit assumption rather than hiding it.
- **Several independent explorers, cross-checked.** Reading the same height from more than one public
  explorer and requiring agreement is a weaker fallback (explorers can collude or err); reverse the
  displayed big-endian root to internal order before use.

The bundle's own frozen header is never a substitute for any of these: it is producer-controlled evidence,
reported as `frozenEvidence`, never trusted.

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
