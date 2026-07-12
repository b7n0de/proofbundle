# ADR 0003: Post-quantum payload signatures — decision to defer, and the future path

- **Status:** accepted, as a decision **NOT to implement payload-level
  post-quantum (PQ) signatures yet**, plus a recorded design for when the
  ecosystem is ready. This ADR changes **no shipped behavior**: it is a
  forward-looking design record, not an implementation. Every option and
  policy mode below is PROPOSED unless explicitly marked implemented.
- **Date:** 2026-07-12
- **Deciders:** proofbundle maintainer (b7n0de)
- **Builds on:** ADR 0002 (universal content root — the content-root
  primitive is signature-scheme-agnostic and needs no change for any option
  below); the already-shipped ML-DSA-44 **witness cosignature** support
  (SPEC.md §7d, `checkpoint.py`, the `[pq]` extra) as the project's one
  existing PQ deployment.

## Context

**Current posture (unchanged by this ADR, restated for the record):** every
proofbundle *payload* signature — the bundle's `signature` block (SPEC.md
§4), every DSSE-signed in-toto Statement (`intoto.py`), the decision-
receipt predicate (`decision.py`) — is Ed25519 only. `docs/FAQ.md` already
states this plainly: *"Primary signatures are Ed25519 until the ecosystem
moves — a PQ adversary who breaks Ed25519 breaks the receipt. This is
stated, not hidden."* This ADR does not change that sentence; it records
*why*, compares the concrete options for changing it, and defines (without
building) the trust-policy surface a relying party would need once one is
chosen.

**The one PQ mechanism proofbundle already ships** is narrower and
different in kind: **witness cosignatures** on a C2SP tlog-checkpoint
(SPEC.md §7d) MAY use **ML-DSA-44** (FIPS 204, algorithm byte `0x06`)
alongside or instead of Ed25519 witnesses, verified when
`proofbundle[pq]` (`cryptography>=48`, OpenSSL 3.5+) is installed. This
protects the *transparency-log witness layer* — it says nothing about
whether the bundle's own Ed25519 payload signature can be forged by a
future quantum adversary. Conflating the two would itself be an overclaim;
this ADR exists partly to keep that boundary explicit as the two surfaces
inevitably get discussed together.

**Why this matters, stated conservatively:** a large enough
cryptographically-relevant quantum computer would let an adversary forge
Ed25519 signatures (via Shor's algorithm against the underlying discrete-
log problem). No such machine is known to exist today, and credible
timelines for one vary widely and are not this project's expertise to
adjudicate. What the project *can* control is: (a) not making a false
"quantum-safe" claim while relying on Ed25519 payload signatures, which it
already does not, and (b) having a considered, ready-to-execute design for
the day a payload-level PQ or hybrid signature becomes practical to ship —
which is what this ADR is.

## Library and standards maturity (as researched for this ADR)

- **FIPS 204 (ML-DSA, Module-Lattice-Based Digital Signature Standard)**
  was finalized by NIST in August 2024. It is the standardized successor to
  CRYSTALS-Dilithium and the algorithm proofbundle already uses for witness
  cosignatures.
- **pyca/`cryptography`** (the project's one runtime dependency) added
  ML-DSA support via its OpenSSL 3.5+ binding, available in `cryptography`
  builds from **48.0.0** onward — already the exact floor this project
  pins for its `[pq]` extra (`pyproject.toml`: `pq = ["cryptography>=48"]`).
  This is real, current, in-tree library support — not a hypothetical.
  What it does **not** yet give proofbundle "for free" is a payload-
  signature integration: `dsse.sign_envelope` / `verify_envelope`
  (`dsse.py`) and the bundle `signature` block (`emit.py`, `bundle.py`) are
  Ed25519-shaped by construction (a single `alg`/`public_key_b64`/`sig_b64`
  triple), not multi-algorithm.
- **Interop risk, honestly assessed:** ML-DSA-44 signatures and public keys
  are far larger than Ed25519's (order of kilobytes vs. 32/64 bytes),
  which changes the size profile of every artifact carrying one (a bundle,
  a DSSE envelope, a decision receipt). No SD-JWT / JOSE PQ algorithm
  registration is broadly deployed yet for the SD-JWT layer specifically.
  This is exactly the kind of ecosystem-readiness gap `docs/FAQ.md`
  gestures at with "until the ecosystem moves," and is the concrete reason
  this ADR defers implementation rather than shipping a bespoke, likely-
  to-be-incompatible scheme now.

## Decision

**Defer payload-level PQ signatures.** Do not implement any of options A–D
below in this change. Record the comparison and the trust-policy design so
a future PR has a considered starting point instead of a from-scratch
design discussion, and so the project's PQ posture stays exactly as
truthful as it is today: real where it exists (witness cosignatures),
explicitly absent where it does not (payload signatures).

### Options compared

| Option | Shape | Pro | Con | Verdict |
|---|---|---|---|---|
| **A. Ed25519 only + hash-based external anchors** (today's shipped state) | No payload PQ signature at all; a `receipt`/`preRegistration`-target external time anchor (SPEC.md §7i) at least gives a hash-based, algorithm-agnostic *existence-before-time-T* proof that does not depend on Ed25519 remaining unforgeable going forward for that narrower claim | Zero new complexity, zero size overhead, zero new dependency; the anchor layer already exists and is unaffected by which payload-signature scheme is used | The payload SIGNATURE itself (who signed, that it is unmodified) stays exactly as vulnerable to a future quantum break as it is today | **Status quo** — this ADR does not change it |
| **B. Ed25519 + ML-DSA-44 hybrid payload signatures** | Every payload carries BOTH an Ed25519 signature AND an ML-DSA-44 signature over the same bytes; a verifier can require either or both | Forward-compatible without a hard cutover; mirrors the already-shipped witness-cosignature pattern (proven pattern in this codebase); classical verifiers that don't understand ML-DSA can still check the Ed25519 half if the wire format degrades gracefully | Roughly doubles (or more) the signature material size; needs a NEW bundle/DSSE wire shape (today's `signature` block is single-algorithm); no established SD-JWT/JOSE PQ algorithm registration to lean on yet for the SD-JWT layer | **Most promising**, but genuinely blocked on the wire-format design + a settled SD-JWT-layer story, not on library availability |
| **C. DSSE multi-signature envelope** | DSSE already supports multiple `signatures[]` entries per envelope (the in-toto/DSSE spec's native multi-sig shape) — add an ML-DSA-44 entry alongside the Ed25519 one, no new envelope shape | Reuses an EXISTING, already-standard mechanism (`dsse.py` already emits a `signatures` array, currently with one entry) for the DSSE-exported paths (`intoto.py`, `decision.py`) | Only covers the DSSE-exported attestations, NOT the native `proofbundle/v0.1` bundle's own single-signature `signature` block (SPEC.md §4), which is the format most receipts actually ship as | Real, low-friction option for the DSSE-export surface specifically; does not by itself solve the native-bundle case (still needs A/B-style thinking there) |
| **D. COSE/JWS multi-signature profile** | Adopt a COSE (RFC 9052) or JWS (RFC 7515) multi-signature structure as an alternative wire format entirely, with native multi-algorithm support in the standard itself | Leans on an existing IETF standard's own multi-sig mechanics rather than inventing one | A wholesale wire-format change away from proofbundle's deliberately minimal, bespoke JSON bundle format (SPEC.md §1) — the highest-disruption option, and duplicates much of what B/C already cover with less new machinery | Not preferred; noted for completeness because the audit's WP9 explicitly asked the comparison to include it |

**No option is implemented by this ADR.** If and when one is chosen, it is
a wire-format change to the signed bytes — the same category of change
ADR 0002's content-root migration was, and it would need the same
treatment: a declared, versioned algorithm field (mirroring
`merkle.hash_alg` and `contentRootAlg`'s anti-confusion pattern — never a
silent default), an explicit legacy/compatibility mode, and its own P0
activation test.

### Future trust-policy modes (design only, not implemented)

If/when a hybrid or PQ payload-signature option ships, the natural
trust-policy surface (extending `policy.py`'s `signature` section) is four
modes a relying party selects, mirroring how `signature.allowed_algs`
already pins acceptable classical algorithms:

```text
require_classical            — only the Ed25519 signature is required to verify (today's implicit behavior)
require_pq                   — only the PQ (e.g. ML-DSA-44) signature is required to verify
require_hybrid_both          — BOTH signatures must independently verify (defense in depth: a break of
                                either algorithm alone does not forge the receipt)
allow_legacy_with_confirmed_hash_anchor
                              — accept an Ed25519-only (pre-hybrid) receipt IF it also carries a CONFIRMED
                                external time anchor (SPEC.md §7i) proving the receipt existed before a
                                relying-party-chosen cutover date — an honest bridge for data signed before
                                a hybrid rollout, not a claim that the old signature itself became stronger
```

None of these four modes exist in `policy.py`'s schema today (`_SIG_KEYS =
{"allowed_algs", "require_expected_signer"}`); they are recorded here as
the shape a future PR would extend that schema with, not as something
`load_policy` accepts.

## Consequences

- **No shipped behavior changes.** Every payload signature proofbundle
  emits or verifies today remains Ed25519-only, exactly as `docs/FAQ.md`
  already states.
- **The project's PQ posture stays fully honest** either way: this ADR
  does not assert that proofbundle is quantum-safe as a whole, and does
  not claim the existing Ed25519-only payload signature became
  post-quantum secure by virtue of this document existing — only the
  already-shipped witness-cosignature layer (SPEC.md §7d) carries an
  optional ML-DSA-44 path today, and this ADR does not change that
  boundary.
- **The next implementer has a starting point.** When wire-format design
  work on option B (the leading candidate) or C (the lower-friction DSSE-
  only partial answer) begins, it starts from this comparison and the four
  policy modes above, rather than re-deriving them; it will still need its
  own 6-lens adversarial review before landing (matching how ADR 0002's
  activation was gated, and how every prior crypto/policy change in
  `CHANGELOG.md` was reviewed).
- **This ADR itself carries no expiration or automatic re-trigger.** A
  future decision to implement should re-check library/standards maturity
  at that time — the "library and standards maturity" section above is a
  snapshot as researched in 2026-07, not a claim that stays current
  indefinitely.
