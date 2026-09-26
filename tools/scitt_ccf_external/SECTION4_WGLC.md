# Section 4 of draft-ietf-scitt-receipts-ccf-profile-05, measured for the focused last call

Section 4 (consistency proofs) was read rule by rule, implemented as a fail-closed verifier behind
`proofbundle[scitt]`, measured on real signed states of a local scitt-ccf-ledger and on every tree
pair up to 257 leaves, and cross-checked with a third-party RFC 9162 implementation. The section is
implementable, and its RFC 9162 equivalence claim holds on every pair measured, for the positions of
the digests under this document's hashing (G8). Eight places are not enough for an independent
implementation. The two that change a verdict are the anchor rule, which
4.2 does not check, and the multiple-proof rule, which 4.2 does not check either.

## SOURCE READ

- Text: https://github.com/ietf-wg-scitt/draft-ietf-scitt-receipts-ccf-profile
- Commit: `e729c2ec037ac763d0cf422bb58a219f8d6a02f4`, tag `draft-ietf-scitt-receipts-ccf-profile-05`
- File: `draft-ietf-scitt-receipts-ccf-profile.md`, sha256 `7efdb7aa934ab0cfc1093e99932f7d2efd39bb66f5bf43594806d7b282ca0077`
- Retrieved: 2026-09-25
- Section numbers below follow the heading order of that file (4 = CCF Consistency Proofs, 4.1 = CCF
  Consistency Proof Signature, 4.2 = Consistency Proof Verification Algorithm, 5 = Usage in COSE
  Receipts, 7.3 = Security Considerations, Consistency Receipts).
- NOT MEASURABLE here: the last-call mail and the datatracker page; the proxy of this environment
  refuses both hosts. The mail was not read. Neither was the rendered text, so its section numbers
  are not measured.
  https://mailarchive.ietf.org/arch/msg/scitt/mV6rwaJ3doCJDjK0zo9Y2IcGS60/
  https://datatracker.ietf.org/doc/draft-ietf-scitt-receipts-ccf-profile/

## THE MUSTS OF SECTIONS 4, 4.1 AND 4.2

Counted in the file: section 4 has 1 MUST, 4.1 has 4, 4.2 has none; no other BCP 14 keyword in the three.

| row | section | sentence | proofbundle status when violated |
|---|---|---|---|
| M1 | 4 | "The `anchor` MUST be the root of the subtree covering transactions `T[m - 2^t], ..., T[m - 1]`, where `2^t` is the largest power of two dividing `m`; when `m` is a power of two, the anchor is `R_m`." | `consistency_anchor_not_canonical` (see G1) |
| M2 | 4.1 | "Its unprotected header MUST include: `vdp` (label 396): map." | `consistency_proof_missing`; not a map, or a map with neither -1 nor -2: `malformed` |
| M3 | 4.1 | "It MUST contain the `consistency-proof` (-2) key, whose value is an array of one or more `ccf-consistency-proof` values, each relating one older root to the newer root." | no -2: `consistency_proof_missing`; an empty array: `malformed` |
| M4 | 4.1 | "The payload is the newer root `R_n`, and MUST be detached." | `consistency_payload_attached` |
| M5 | 4.1 | "When the array contains more than one consistency proof, every proof MUST compute to the same newer root." | `consistency_newer_roots_differ` (see G2) |

Inherited by 4.1 ("the same protected header requirements as an inclusion proof signature"):

| row | section | sentence | proofbundle status when violated |
|---|---|---|---|
| M6 | 3.1 | "The protected header parameters for the CCF inclusion proof signature MUST include the following:" | `outside_profile` |
| M7 | 3.1 | "`vds` (label 395): `int`. This header MUST be set to the verifiable data structure algorithm identifier for `CCF_LEDGER_SHA256` (`TBD_1`)." | `outside_profile` |

Section 4.2 has no BCP 14 keyword. Its normative content is the pseudo-code; each assert, as proofbundle maps it:

| row | assert | proofbundle status |
|---|---|---|
| A1 | `assert(VDP_LABEL in consistency_receipt.unprotected_header)` | `consistency_proof_missing` |
| A2 | `assert(CONSISTENCY_PROOF_LABEL in vdp)` | `consistency_proof_missing` |
| A3 | `assert(len(proofs) > 0)` | `malformed`: an empty array is outside the -05 CDDL, which the reader checks before any status (ADR 0009, Decision 16) |
| A4 | `assert(consistency_receipt.payload == nil)` | `consistency_payload_attached` |
| A5 | `assert(len(payloads) > 0)`, "At least one proof must start from older_root" | `consistency_older_root_mismatch` |
| A6 | `assert(verify_cose(consistency_receipt, payload))` for each payload | `signature_invalid`; no key: `needs_rp_trust` |

Outside section 4, and binding on its verifiers:

| row | section | sentence |
|---|---|---|
| R1 | 5 | "At least one of `inclusion-proof` and `consistency-proof` MUST be present." |
| R2 | 7.3 | "Verifiers MUST compare the recomputed older root with a root they have already verified, not with one supplied alongside the receipt." |

## WHAT WAS MEASURED, 2026-09-25

Exhaustive, random leaves, every pair 0 < m < n <= 257 (`consistency_result.json`, `exhaustive`):
- pairs: 32896
- canonical proof built from RFC 9162 section 2.1.4.1, anchor equal to the M1 anchor: 32896 of 32896
- the digests equal the RFC 9162 proof, anchor first when m is not a power of two: 32896 of 32896
- the 4.2 fold reaches both roots: 32896 of 32896
- first path element a right sibling: 32896 of 32896
- proofs with an anchor below the M1 anchor on the same edge: 31871, over 16384 distinct (m, n)
  pairs, every pair with an even m; the counts here are proofs, not pairs
- of those, the 4.2 `compute_roots` fold reaches both expected roots: 31871; this is the fold alone,
  not a receipt and not a signature check
- of those, first path element a left sibling: 31871

Third-party oracle, every pair with n <= 64:
- oracle: https://github.com/transparency-dev/merkle
- commit: `fbbcd741c3d1c69d8498487baa8edc9e5824847c` (2026-09-21), Apache-2.0
- used: `testonly.Tree.ConsistencyProof` and `proof.VerifyConsistency`, with CCF hashing (no RFC 9162 prefixes), driver `rfc9162_oracle.go`
- pairs: 2016
- oracle proof equals ours: 2016
- canonical -05 digests accepted by the oracle's verifier: 2016
- deeper-anchor proofs rejected by the oracle's verifier: 1824 of 1824, over 992 distinct pairs ("wrong proof size")

Real ledger:
- service: https://github.com/microsoft/scitt-ccf-ledger at `00101f769d872711356e080fbb089ac48589c60a`
- CCF 7.0.17, virtual mode, one node, built and run locally, no account
- run 1: three signed states at tree sizes 13, 15, 17
- run 2: three signed states at tree sizes 19, 22, 24; the middle one takes two statements at once, so
  its size is even and a deeper anchor exists
- each state: a hash envelope over the root of `examples/example_bundle.json`, its inclusion receipt
  verified by `proofbundle.scitt_ccf` (`confirmed`)
- the ledger's own files, read with the ccf package 7.0.17 (PyPI, Apache-2.0, third-party): run 2, 24
  transactions, 9 signed roots verified by its validator, 25 leaves
- the three receipt roots equal the roots the ccf package verified at the same seqnos
- no service emits a consistency receipt, so the receipt measured is the service's own COSE_Sign1 over
  the newer root, taken from the newer inclusion receipt, with a proof computed from the ledger's
  leaves in its unprotected header
- oracle on the canonical proofs 19 to 24, 22 to 24 and 19 to 22, computed from the ledger's leaves:
  accepted, 3 of 3

Variants on constructed receipts over the run 2 states (the service's own COSE_Sign1 over the newer
root, proofs computed from the ledger's leaves, no receipt the service emitted), proofbundle against
a literal transcription of the 4.2 pseudo-code, its signature check included:

| variant | proofbundle | 4.2 as written |
|---|---|---|
| control: older state to newer state | `confirmed` | accepts |
| control: middle state to newer state | `confirmed` | accepts |
| wrong older root: the middle root held, the older proof carried | `consistency_older_root_mismatch` | A5 fails |
| wrong older root: one bit of the older root | `consistency_older_root_mismatch` | A5 fails |
| swapped states: the newer root held as the older one | `consistency_older_root_mismatch` | A5 fails |
| swapped states: the older-to-middle proof under the newer signature | `signature_invalid` | A6 fails |
| altered anchor: one bit | `consistency_older_root_mismatch` | A5 fails |
| altered path: one tag flipped | `consistency_anchor_not_canonical` | A5 fails |
| multiple proofs: older and middle, both to the newer root | `confirmed` | accepts |
| multiple proofs: the same proof twice | `confirmed` | accepts |
| multiple proofs: a valid one and one to another newer root | `consistency_newer_roots_differ` | A6 fails |
| multiple proofs: a valid one and a corrupted one | `consistency_newer_roots_differ` | **accepts** |
| anchor deeper than M1 requires (22 to 24) | `consistency_anchor_not_canonical` | **accepts** |
| detached payload missing: the newer root attached | `consistency_payload_attached` | A4 fails |
| detached payload not recomputable: -2 an empty array | `malformed` | A3 fails |
| inclusion and consistency proofs in one receipt | `confirmed` | accepts |

Two more, proofbundle only:
- older root verified from another service's receipt: `consistency_issuer_mismatch`, proofbundle's own rule, not a requirement of -05
- no relying-party key set: `needs_rp_trust`

Run 1 gave the same outcome in every row, except the deeper-anchor row. That row does not exist in
run 1, because 13 is odd and no deeper anchor exists.

## WHERE THE TEXT IS NOT ENOUGH

G1. Is the anchor rule M1 a rule for verifiers, or for generation only?
- Sentence, 4: M1 above.
- Sentence, 4.2: "It also confirms that the anchor is a node of that state, but not that it is the anchor required in {{ccf-consistency-proofs}}, which cannot be checked without knowing `m`."
- Measured, fold only: 31871 proofs with an anchor below the M1 anchor, over 16384 distinct (m, n) pairs with 0 < m < n <= 257; for each, the 4.2 `compute_roots` fold reaches both expected roots, `R_m` and `R_n`. The counts are proofs, not pairs, and none of them is a receipt or a signature check.
- Measured, fold only: every one of those 31871 proofs starts with a left sibling; all 32896 canonical proofs start with a right sibling.
- Measured, full acceptance, one case only: the constructed 22-to-24 receipt with a deeper anchor (the service's own COSE_Sign1 over `R_24`, the proof computed from the ledger's leaves) passes 4.2 as written, signature check included. The third-party RFC 9162 verifier rejects the same proof. No other deeper-anchor receipt was built.
- Why the first tag decides: the M1 anchor is the largest complete subtree ending at T[m-1], so its sibling in the newer tree lies to its right; a smaller node on the same edge first meets its left sibling inside that subtree. This is the argument; the counts above are the measurement.
- Question: should a verifier reject a proof whose first path element is a left sibling, and should 4.2 then say so and drop "cannot be checked without knowing m"? Or is the anchor MUST for generation only, so that a verifier accepts a deeper anchor, and the RFC 9162 sentence of section 4 then describes what a producer emits, not every proof a verifier accepts?

G2. The multiple-proof rule M5 is not checked by 4.2.
- Sentence, 4.1: "When the array contains more than one consistency proof, every proof MUST compute to the same newer root."
- Sentence, 4.2: the loop runs `compute_roots` on every proof but keeps the newer root only of proofs whose older root equals `older_root`; the newer roots of the others are dropped.
- Measured, one case: a constructed receipt over the measured 19-to-24 states (the service's own COSE_Sign1 over `R_24`, the 19-to-24 proof computed from the ledger's leaves, not a proof the service emitted), with a corrupted second proof beside it (one anchor bit flipped), passes 4.2 as written, signature check included, and violates M5.
- The missing step: compare the newer roots that `compute_roots` returns for all proofs, including proofs whose older root does not equal `older_root`, and fail unless they are all equal. 4.2 compares none of them with each other.
- Question: should 4.2 add that step before the signature check? Or may a verifier ignore proofs it cannot relate to its own older root, in which case M5 binds producers only?

G3. The text does not say which trust rule authorizes the signer of a consistency receipt.
- Sentence, 4.1: "The older root `R_m` is not carried by the receipt: the verifier already holds it, typically as the root recomputed from an inclusion receipt ({{ccf-inclusion-receipt-verification}}), and checks that the proof recomputes it."
- Sentence, 4.2: "The comparison with `older_root` binds the receipt to a state the verifier already trusts".
- Sentence, 7.3: R2 above.
- Read: the older root is bound. 4.2 binds the receipt to a previously verified root, and 7.3 requires that root's prior verification.
- Sentence, 7.2: "An operator has the ability to start successor networks with a distinct identity."
- Open: which trust rule authorizes the key that signs the consistency receipt. 4.2 calls `verify_cose` and does not name the key it verifies with: the key behind the older root's receipt, any key the verifier trusts for the service, or also a successor network with a distinct identity under 7.2.
- Measured: proofbundle refuses an older root verified from another service's receipt (`consistency_issuer_mismatch`). That same-issuer rule is proofbundle's own policy, not a requirement of -05.
- Question: which keys may sign a consistency receipt for an older root the verifier already holds, and does a successor network with a distinct identity under 7.2 qualify?

G4. `0 < m < n` is stated, and 4.2 does not check it.
- Sentence, 4: "where `0 < m < n`".
- Measured: a proof whose path holds only left siblings folds older and newer to the same root; 4.2 accepts it whenever the service signed that root. The first-tag check of G1 refuses it.
- Question: is a consistency receipt for m = n invalid, and should 4.2 say so?

G5. Tree sizes and CCF transaction IDs are not related by the text.
- Sentence, 4: "Neither tree size is needed for verification."
- Sentence, 2.1: "The Merkle Tree encodes an ordered list of `n` transactions T_n = \{T\[0\], ..., T\[n-1\]\}."
- Measured, ccf package 7.0.17 and 9 signed states: leaf 0 is 32 zero bytes, not a transaction; a signature at seqno s signs the tree of s leaves.
- A verifier does not need this. A second producer of consistency receipts from a CCF ledger does, and "n transactions" suggests T[0] is one.
- Question: should the draft state how m and n relate to transaction IDs, including leaf 0?

G6. There is nothing to test an implementation against.
- Sentence: section 4 defines the format; the repository's `samples/` holds one inclusion receipt only.
- Measured: no code emits a -05 consistency proof in CCF 7.0.17, CCF main at `9f9ba74b` (2026-09-25) or scitt-ccf-ledger at `00101f76`; merklecpp in CCF main has `past_root` and `past_path` only.
- Question: is there an implementation that emits consistency receipts, and can a sample be added before the call closes?

G7. A receipt carrying both proof types is checked by neither algorithm as a whole.
- Sentence, 5: "All proofs in a receipt recompute the same root (the newer root, for consistency proofs), which is the detached payload." This is not written as a MUST.
- Read: 3.2 ignores -2 and 4.2 ignores -1, so an inclusion proof to another root beside a valid consistency proof passes 4.2.
- Measured: proofbundle refuses that receipt (`consistency_newer_roots_differ`, synthetic); with the service's inclusion proof beside the consistency proof computed from the ledger's leaves, in one constructed receipt, both accept. The other direction, a consistency proof to another root beside a valid inclusion proof, is refused by proofbundle's inclusion reader as `root_mismatch` (synthetic, `test_every_proof_family_in_the_vdp_is_parsed_and_computes_the_receipt_root`).
- Question: is that sentence normative, and which algorithm checks it?

G8. Does "the same digests" in section 4 mean the same nodes, or the same values under RFC 9162's hashing?
- Sentence, 4.2: "older := HASH(hash || older)", "newer := HASH(hash || newer)" and "newer := HASH(newer || hash)". This is the node rule of 2.1 ("MTH(D_n) = HASH(MTH(D[0:k]) || MTH(D[k:n]))") over 64 bytes, without the 0x01 node prefix of RFC 9162; 2.1 also hashes a leaf without 0x00 ("MTH({d[0]}) = HASH(d[0]).").
- Sentence, 4: "Apart from the tags, `path` holds the same digests in the same order as the consistency proof of {{Section 2.1.4.1 of RFC9162}} for the same sizes, with the anchor as the first element of that proof when `m` is not a power of two."
- Measured, run-2 ledger, pairs 19 to 24, 22 to 24 and 19 to 22: the RFC 9162 section 2.1.4.1 proof equals the -05 anchor and path in 14 of 14 digests under this document's hashing, and in 0 of 14 under RFC 9162's own hashing, 0x00 leaf and 0x01 node (`leafhash/same_digests_result.json`).
- Measured, same ledger: the service's COSE signature verifies 9 of 9 roots computed without prefixes, and 0 of 9 roots computed with RFC 9162 prefixes (`leafhash/result.json`).
- NOT MEASURABLE here: the RFC 9162 text itself. The prefix values are those of https://github.com/transparency-dev/merkle at `fbbcd741c3d1c69d8498487baa8edc9e5824847c`, `rfc6962/rfc6962.go` lines 25 and 26, retrieved 2026-09-25.
- Question: should section 4 say that "the same digests" means the digests of the same nodes under this document's hash, since under RFC 9162's own tree hash none of the values is equal? And should section 2.1 state that the tree has no 0x00 and 0x01 prefixes, unlike RFC 9162 section 2.1.1?

## WHAT THE READER DOES, AS BUILT

- Function: `proofbundle.scitt_ccf.verify_consistency_receipt(consistency_receipt, *, older_root, older_issuer, rp_trust)`
- Status set: `CONSISTENCY_STATUS_ORDER`, separate from the statement statuses, first match decides.
- Not an anchor type and not reachable from any verify path (AP5 comes after 6.3.0).
- Rust parity: registered `PENDING` in `scripts/rust_parity_registry.json`.
- Tests: `tests/test_scitt_ccf_consistency.py`, synthetic and on the committed run-2 vector; seven single-rule mutants of the verifier each fail at least one test.

## NOT MEASURED

- The mail that opened the last call, the datatracker page and the rendered draft.
- Any consistency receipt produced by a service: none exists in the code measured.
- A production CCF service.
- Trees larger than 257 leaves (exhaustive), or larger than 64 against the oracle.
- The argument in G1, beyond the proofs counted: it is reasoned, not proved.
- Full receipt acceptance of a deeper anchor, beyond the one constructed 22-to-24 receipt.

---

Prepared with AI agent involvement, reviewed and submitted under human oversight.
