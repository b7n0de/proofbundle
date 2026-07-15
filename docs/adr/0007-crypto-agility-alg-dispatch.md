# ADR 0007: Crypto-agility `alg` dispatch — the shared per-key algorithm pattern

- **Status:** accepted. Documents an already-shipped mechanism (`trust_pack.py`, Welle 1 Finding 08
  / commit `PB-2026-0715-08`, 3.2.2) and generalizes it as a named, reusable pattern for the next
  consumer, mirroring how ADR 0002 named a primitive that already existed in `decision.py` before
  generalizing it. This ADR changes no shipped behavior.
- **Date:** 2026-07-15 (decision date; commit date live)
- **Deciders:** proofbundle maintainer (b7n0de)
- **Builds on:** ADR 0006 (anchor longevity — `renewal.py`'s `_SIG_ALGS` / `_verify_ats_signature`
  is where this pattern was first built, for the B3↔B5 renewal-signature migration); ADR 0003
  (post-quantum payload signatures — the deferred design this pattern would inform if/when a hybrid
  payload signature is chosen, see §Consequences)

## Context

`trust_pack.py` (`trust-pack/v0.1`, EXPERIMENTAL 3.2.0 O2) is a TUF-inspired root of trust: each
role (root, evalIssuers, decisionMakers, outcomeExecutors, timeAuthorities, witnesses) maps to a
set of key ids and a signature threshold. Welle 1's Finding 08 (`PB-2026-0715-08`, commit
`0e2e60d`) closed a real gap: the root/rotation keys had no declared signature algorithm, so a
future PQ-migrated root key had nowhere to say what it was, and — the sharper risk — nothing
stopped a hybrid key from being satisfied by only its (weaker, quantum-vulnerable) classical leg.

This is the **second** time this project has needed exactly this shape. ADR 0006 built it first,
for `renewal.py`'s `ArchiveTimeStamp` time-authority signatures (`_SIG_ALGS = ("ed25519",
"hybrid-ed25519-mldsa65", "mldsa65")`, `_verify_ats_signature`, the algorithm bound into
`_ats_content` so it cannot be relabeled after signing). The Finding 08 fix built the same shape
again for `trust_pack.py`'s root keys, independently, because ADR 0006 documented it as a solution
for the renewal chain specifically, not as a project-wide pattern. This ADR closes that gap: it
names the pattern once, so a third consumer (the next PQ extension point — see §Consequences)
reuses it instead of re-deriving it, or worse, inventing a subtly different and weaker variant.

**A note on the two different ML-DSA parameter sets in this codebase**, because a reviewer will
ask: `trust_pack.py` / `renewal.py` use **ML-DSA-65** (`_KEY_RAW_LEN["mldsa65"] = 1952`-byte public
key, FIPS 204 Category 3) for the root-of-trust / time-authority use case, while `checkpoint.py`'s
witness cosignatures (shipped since v1.3, STABLE, C2SP type `0x06`) use **ML-DSA-44**
(`_MLDSA44_PUB_LEN = 1312` bytes, FIPS 204 Category 2) for the witness-cosignature use case. This
is deliberate, not drift: C2SP's own spec names ML-DSA-44 as its SHOULD for witness deployments (a
witness signs many checkpoints, so the smaller/faster parameter set is the documented tradeoff),
while a root of trust and a decades-scale time-authority signature reasonably choose the higher
security margin. `checkpoint.py`'s ML-DSA-44 path is also architecturally SEPARATE — it imports
`cryptography.hazmat.primitives.asymmetric.mldsa` directly in its own `_mldsa_module()` capability
probe, not through `pqsig.py` — which is why `checkpoint.py` stays STABLE (`docs/AUDIT_SCOPE.md`)
even though `pqsig.py` (the module `trust_pack.py` and `renewal.py` share) is EXPERIMENTAL.

## Decision

Formalize the per-key/per-signer **crypto-agility `alg` dispatch** as the shape any future
algorithm-migratable signature surface in this codebase uses:

1. **A key or signer entry declares its algorithm explicitly**, `alg` ∈ `{"ed25519" (default),
   "mldsa65", "hybrid-<classical>-<pq>"}` (today: `"hybrid-ed25519-mldsa65"`). An absent `alg`
   defaults to `"ed25519"` — every pre-agility artifact (a `trust-pack/v0.1` pack with no `alg`
   field, an unsigned/legacy `ArchiveTimeStamp`) keeps verifying unchanged. This is additive, never
   a silent upgrade of an existing key's assumed strength.
2. **The `alg` label lives INSIDE the bytes the signature covers**, never in an unsigned envelope
   field read before verification. `trust_pack.py`'s `alg` is a field of the signed predicate
   (`keys[kid].alg`); `renewal.py`'s `sig_alg` is folded into `_ats_content(...)` before signing.
   This is what closes the JWT-`alg`-header class of downgrade attack: relabeling the algorithm
   after the fact invalidates every signature over the artifact, because the label was part of
   what was signed. There is no separate "trust the label, then dispatch" step where a label could
   be swapped without breaking the signature.
3. **A hybrid entry requires BOTH legs to independently verify** — never an OR. `trust_pack.py`'s
   `_verify_signature_for_alg` and `renewal.py`'s `_verify_ats_signature` both fail closed
   (return `False`) if either the classical (`sig`/`publicKey`) or the PQ (`sigPq`/`publicKeyPq`)
   leg is missing, malformed, or does not verify. A hybrid key's whole purpose — surviving a break
   of *either* algorithm alone — requires conjunctive verification; an either-leg design would let
   an attacker who breaks only the older/weaker leg forge the hybrid signature, which defeats the
   reason to add the PQ leg at all.
4. **A hybrid entry's PQ leg is a distinct, equally-sized wire field**, never encoded inside the
   classical signature's bytes: `sigPq` alongside `sig` (mirrors `publicKeyPq` alongside
   `publicKey`). Both are required together — `trust_pack.py`'s validator rejects a `publicKeyPq`
   present without `alg: hybrid-...` and rejects a hybrid entry missing `publicKeyPq`.
5. **Verification counts DISTINCT decoded key material, never keyId/name labels**, before it
   counts toward a threshold or quorum. `trust_pack.py::verify_trust_pack` dedups root signers by
   the decoded `publicKey` bytes; the same defense already exists in `checkpoint.py::witness_quorum`
   (documented there as closing a Sybil class: one physical key registered under many names must
   count once, not once per name). This ADR names it as a general rule for any future
   threshold/quorum surface, not a `checkpoint.py`-specific fix.
6. **An asymmetric fail-closed boundary, by design, not by oversight.** An unrecognized `alg` on
   the SIGNED, attacker-influenceable predicate field (`keys[kid].alg`) is a hard validation error
   — `validate_trust_pack_predicate` rejects the whole pack. An unrecognized `alg` on **caller-
   supplied, out-of-band trust material** (`prev_root_keys`, the previous pack's root role a
   relying party passes in for rotation vouching) safely *defaults* to `"ed25519"` rather than
   raising, because that value never came from the artifact under review — it is the relying
   party's own configuration, outside the predicate's schema gate. Conflating these two would
   either make the fail-closed rule too strict (breaking a legitimate caller integration) or too
   loose (accepting an attacker-chosen algorithm label inside signed bytes); keeping them distinct
   is the point.

### Options considered (why not the alternatives)

| Option | Shape | Why not chosen |
|---|---|---|
| **Unsigned `alg` header** (JWT-style, e.g. a top-level envelope field read before verification) | dispatch on a field outside the signed bytes | the exact algorithm-confusion class this project's own SPEC §4a Ed25519 edge-case work and the `_ats_content`/predicate-field placement above are designed to avoid; a label outside the signature can be swapped without breaking anything |
| **Either-leg hybrid** (classical OR PQ satisfies) | accept if either signature verifies | defeats the purpose of a hybrid leg: an attacker only needs to break the weaker of the two algorithms, so the "defense in depth" a hybrid design promises does not hold |
| **Separate out-of-band algorithm registry** (a detached file mapping keyId → alg) | key material and algorithm declared in different artifacts | extra indirection with no benefit over an inline declaration, and reopens exactly the "label lives outside the signed bytes" problem from the first row if the registry itself is not bound to the pack |
| **Per-key `alg` inside the signed artifact, hybrid-both-legs required, dedup by key material** (what ships) | this ADR's decision | closes the downgrade path, reuses a pattern proven in two independent consumers (`renewal.py`, `trust_pack.py`), and composes with the existing Sybil defense in `checkpoint.py` |

## Consequences

- **No wire-format break.** Every pre-agility `trust-pack/v0.1` pack (no `alg` field) and every
  unsigned/legacy `ArchiveTimeStamp` (`sig_alg = ""`) keeps verifying exactly as before.
- **The next PQ extension point has a starting shape.** ADR 0003 (deferred payload-level PQ
  signatures) names Option B — an Ed25519+ML-DSA-44 hybrid on the bundle's own `signature` block —
  as the leading future candidate, still blocked on a wire-format design. When that work resumes,
  it should reuse this ADR's three load-bearing rules (label inside the signed bytes, hybrid
  requires both legs, dedup by key material before any threshold) rather than re-deriving them a
  third time. This ADR does **not** itself extend to the bundle's top-level `signature` block —
  that remains ADR 0003's territory, unchanged and un-implemented by this document.
  `renewal.py`'s `ArchiveTimeStamp` signatures and `trust_pack.py`'s root keys stay the only two
  consumers of this dispatch shape today.
- **Scope stays EXPERIMENTAL.** `trust_pack.py` and `renewal.py` remain EXPERIMENTAL
  (`docs/AUDIT_SCOPE.md`); this ADR documents their shared internal contract, it does not graduate
  either module to STABLE. `checkpoint.py`'s separate, already-STABLE ML-DSA-44 witness path is
  unaffected — it does not use this dispatch shape and this ADR does not change it.
- **The next implementer has a starting point, not a design discussion.** Matching ADR 0003's own
  closing note: any change here still needs its own adversarial review before landing (matching
  how the Finding 08 fix and ADR 0006's B3↔B5 wiring were both reviewed) — this ADR records the
  contract, it does not exempt a future change from review.
