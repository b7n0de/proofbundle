# Content Root Contract (Phase 1 / R51)

Generated 2026-08-24 (order `20260824T071500Z`; source document sha256
`1bfc06cefd284867271862808e4929bf7070aa8c3eb5b1ad168356a3e9891709`). This document states the
contract; the normative single source for the definition is **ADR 0002**
(`docs/adr/0002-universal-content-root.md`) and the implementation is
`src/proofbundle/canonical.py` — this file cites them and adds the measured per-path table and
the conformance vector set. It deliberately does NOT restate the definition in different words:
a second wording would be a second truth.

Carried onto main on 2026-10-18. Sections 2 to 4 were measured again then, on main 570dd164: each line
the August text cited at c669d39e3d8e was found again by its text, not by its number, and the lines of
`src/proofbundle` that match one of five patterns (`rfc8785.dumps`, `sort_keys=True`,
`sha256(_rfc8785_bytes`, `statement_content_root(`, `canonicalize_statement(`) were counted on both
commits: 53 at c669d39e3d8e, 67 at 570dd164, docstring lines included. Each line new on 570dd164 was
read where it stands. Section 7 is the record of August and keeps its numbers.

## 1. The one primitive

| What | Where |
|---|---|
| Definition (normative) | ADR 0002 — SHA-256 over the RFC 8785 (JCS) canonical bytes of the FULL in-toto Statement, computed BEFORE signing; signature bytes are never part of the preimage |
| Implementation | `src/proofbundle/canonical.py` — `canonicalize_statement()` (producer bytes) and `statement_content_root()` (both sides) |
| Algorithm id | `jcs-sha256-v1` (`canonical.CONTENT_ROOT_ALG`) |
| Two-part rule | producer canonicalizes and signs exactly those bytes; verifier hashes the EXACT transmitted bytes and never re-canonicalizes |
| Missing canonicalizer | fail-closed `CanonicalizerUnavailable` (install `proofbundle[eval]`), never a silent fallback |

## 2. Measured state per predicate path (main `570dd164`, measured 2026-10-18)

Every emit/verify path of the predicate classes named in R28 delegates to the one primitive:

| Predicate class | Evidence (file:line) | Serialization |
|---|---|---|
| decision-receipt | `decision.py:425-437` (canonical delegate), `:409,773,992` (root recompute in verify); `policy.py:972` binds a verify result to the same root through that delegate | jcs-sha256-v1 |
| action-outcome | `outcome.py:505-510`, `:445,955` | jcs-sha256-v1 |
| relation | `relation.py:109` (`jcs-sha256-v1` the only accepted alg) | jcs-sha256-v1 |
| relation-statement | `relation_statement.py:111,302` | jcs-sha256-v1 |
| trust-pack | `trust_pack.py:332` | jcs-sha256-v1 |
| verification-summary | `verification_summary.py:149`; SVR DSSE export `intoto.py:1751-1849` (default `CONTENT_ROOT_ALG` at `:1754`) | jcs-sha256-v1 (default) |
| run-ledger | `run_ledger.py:211` | jcs-sha256-v1 |
| eval-result / test-result DSSE exports | `intoto.py:281-296` (`_serialize_statement`, default `CONTENT_ROOT_ALG`) | jcs-sha256-v1 (default), named legacy opt-in |
| subject-binding (statement scope) | `subject_binding.py:43` (canonical delegate) — the module ALSO hosts the predicate-scope subject-digest derivation at `:52`, which is NOT a statement root (see §4) | jcs-sha256-v1 |
| agent-review (on main since August, not named in R28) | `agent_review.py:1347-1352` (canonical delegate) | jcs-sha256-v1 |
| test-result statement of the verifier block (on main since August, not named in R28) | `verifier_block.py:456-470` (canonical delegate; `statement_digest`, the value a receipt cites, is sha256 over those bytes) | jcs-sha256-v1 |

**Gate verdict (R51): on the same statement bytes every relevant existing predicate path produces
the same root** — the verifier side hashes exact bytes everywhere, and every producer path
canonicalizes through the same function. The conformance vectors below pin this executably.

## 3. The named legacy algorithm — and the deliberate HALT

The released 2.0.0 wire (`json.dumps(sort_keys=True)`) survives as the NAMED algorithm
`legacy-sortkeys-json-v0` (`intoto.py:67,234-359`):

* a Statement DECLARES `contentRootAlg` inside the signed payload; **absent ⇒ legacy** — that is
  how already-signed 2.0.0 receipts keep verifying on a base install;
* absence is NEVER silently treated as jcs; an unknown algorithm id fails closed;
* the verifier re-serializes under the payload's OWN declared algorithm and byte-compares — a
  sortkeys body offered AS `jcs-sha256-v1` is rejected (algorithm-confusion guard).

**Removing or re-defaulting this legacy acceptance would be a backwards-incompatible change to a
public predicate surface. That is stop condition 2 of the source document and an owner decision.
It is explicitly NOT taken in this phase.** The unification the source's P3 called for happened in
the 2.1.0 migration (ADR 0002); what remains is a declared, named compatibility mode — not an
unlabeled divergence.

## 4. Distinct quantities that are NOT statement content roots

To keep future audits from miscounting, these digest sites are different quantities by design and
out of scope for this contract: subject binder digests (`intoto.py:484-489,1000-1005` — flat
fixed-key scalar objects), per-sample disclosure hashes (`persample.py:124`), the hf bundle digest
(`hf_evals.py:85`), and the LABELED config-digest fallbacks in the adapters
(`adapters/_provenance.py:55`, `adapters/eee.py:150`, `adapters/promptfoo.py:101-103`).

**Added in iteration 2 (deep-gate lens 2 refuted the first enumeration as incomplete):**

* **The `sha256(JCS(predicate))` subject-digest family** — seven sites, one per predicate module
  (`decision.py:482`, `outcome.py:549`, `relation_statement.py:150`, `run_ledger.py:247`,
  `verification_summary.py:185`, `trust_pack.py:397`, `subject_binding.py:52`), and since August two
  verify-side recomputations of it (`outcome.py:619-629` for a trust-pack predicate, `trust_pack.py:602`
  for the genesis pin). This is a PREDICATE-scope commitment used as the Statement's `subject.digest` —
  deliberately NOT the full-Statement content root (a subject cannot contain the hash of the statement it
  is part of). Both values are 64-hex and both travel in fields named `digest.sha256`. Measured on the
  predicate of the shipped cross-impl fixture `conformance/decision/crossimpl/schema-conformant`: the
  statement `build_decision_statement` makes of it with the default subject has the root
  `19d6c23eecc9…` and the subject digest `f8f27c96d173…`. The fixture's own statement, whose subject
  the other implementation set, has the root `97e1d74b810a…` and the subject digest `2f0aea2dae36…`, a
  third value. Any audit counting "roots" must keep these families apart.
* **The relation edge-digest sharpness:** `relation.py:202-204` validates `targetReceiptDigest`
  (a statement root) and `targetSubjectDigest` (a predicate-scope subject digest) with one
  `_validate_edge_digest` under the single alg id of `relation.py:109`. The two fields carry
  different preimages under the same label — semantically distinguished by FIELD NAME, not by
  algorithm id. Recorded here as a documented sharpness; changing the wire (separate alg ids or
  a scope marker) would be a public-surface decision, not a Phase-1 act.
* **`anchors.receipt_canonical_root`** (bundle-scope receipt-anchor root) — was a second inline
  rfc8785+budget implementation (the duplication had already cost the same structural-budget fix
  twice, rounds 5 and 7); since iteration 2 it delegates to the one canonicalizer home while
  keeping its anchor-layer `BundleFormatError` contract. The QUANTITY stays distinct
  (bundle scope, no Statement shape requirement).

**Added on 2026-10-18, sites that reached main after August** (found by the count in the header, each
read where it stands):

* **The agent-review subject digest** (`agent_review.py:1374-1381`): sha256 over the JCS form of
  `subjectContext` alone, not of the predicate, so that a receipt copied onto another pull request fails
  its subject check. A member of the subject-digest family with a different preimage under the same
  field name.
* **The agent-review `findingsRoot`** (`agent_review.py:323-339`): sha256 over the sorted
  concatenation of one JCS digest per finding, a root over a set.
* **The relation lineage edges digest** (`relation.py:50-58`): sha256 over
  `json.dumps(edges, sort_keys=True, default=str)`, an in-process binding for an origin token; it is
  not written to a receipt.
* **The AGT receipt form** (`adapters/agt_receipt.py:266`): AGT's own `json.dumps(sort_keys=True,
  ensure_ascii=False)` form, kept on purpose because those are the bytes AGT signs; the module names the
  divergence from RFC 8785.
* **The attested-inference evidence digest** (`experimental/attested_inference.py:116-127`): sha256 over
  sorted-key JSON of the provider's evidence after credential removal.
* **The eval-claim bytes** (`evalclaim.py:296`): `rfc8785.dumps` called outside the one canonicalizer
  home, under the claim's own emit profile and its own copy (`_plain_value.plain_json`). An eval claim is
  not an in-toto Statement, so this is a distinct quantity; whether it should share the home's
  structural budget was not measured here.

## 5. Conformance vectors

`conformance/action_chain_content_roots/` — 10 cases, kind `content_root_vector`, run by
`conformance/run_conformance.py` (same harness, same manifest, no second runner):

* canonical: key order · unicode · number formatting (1.0→1, 100.0→100, −0.0→0) · nested arrays ·
  unknown top-level field (root MUST change) · **UTF-16 code-unit ordering (RFC 8785 §3.2.3's
  hard part: an astral-plane key sorts before a BMP key under UTF-16 code units and after it
  under code points/UTF-8 — added in iteration 2 after lens 2 measured that no vector
  discriminated this axis; a second implementation using its language's default sort passes
  every other vector and diverges exactly here)**;
* pair_reference: a decision statement binds an evidence statement by its root, recomputed from
  pinned bytes;
* binding: algorithm confusion rejected / named legacy accepted — the declared-alg gate as data;
* envelope_invariance: differing signature blocks over the same payload never move the root
  (counter-signing / key rotation).

Catch proofs live in `tests/test_conformance_content_root_vectors.py`: a flipped root pin, a
mutated canonical byte, an under-declared expected block and an unknown mode each FAIL the
handler; the corpus rules (no in-place fixture edits) are respected by tampering only on copies.

## 6. Cross-language status, stated plainly

The vectors are language-neutral data (input JSON + pinned canonical bytes + pinned roots) and are
**golden pins generated by this implementation**. The Rust verifier `pb_verify_rs` (serde_jcs, no
canonicalization code shared with Python) recomputes the eight roots they pin through its
`content-root` subcommand, in `tools/pb_verify_rs/crosscheck.py`: the six `canonical` vectors, both
statements of `pair_reference`, and the payload of both envelopes of `envelope_invariance`. Measured
2026-10-18, all eight agree. The two `binding` vectors pin a verdict of the Python content-root
binding (`bindingOk` and the declared algorithm), and `pb_verify_rs` has no subcommand for that
verdict, so they are Python-only and named so in the differential. The `decision_crossimpl` cases
(a second independent implementation, MarkovianProtocol) prove cross-implementation agreement for
the decision pair. (Until the second reading of this change, this section called the whole set open:
the first form read `pb_verify_rs coverage-report`, which lists its verify subcommands only, and
missed the `content-root` subcommand the differential already used.)

## 7. Iteration 2 — what the adversarial gate refuted, and what changed

The deep-gate jury (three diverse lenses + one non-Claude local reviewer) ran against the
iteration-1 commit and REFUTED five claims. Every refutation is fixed and bound by a catch proof
in `tests/test_conformance_content_root_vectors.py`:

| Lens finding | Fix |
|---|---|
| a bare predicate passed as a "statement" vector (ADR 0002 §2 context-confusion class) | `require_statement_shape=True` in the canonical and pair modes; catch proof `test_catch_proof_bare_predicate_fails` |
| the pair-mode evidence binding was expectation-switchable, with a PASS line claiming a binding it had measured as absent | binding is an unconditional floor and the declaration must be literally true; catch proof `test_catch_proof_nonbinding_pair_fails` |
| `bool("false") is True` — a JSON-string expectation satisfied a boolean axis (handler AND schema were open) | literal-boolean floors in the handler + `const: true` / `type: boolean` in the schema; catch proof `test_catch_proof_string_false_is_not_a_boolean` |
| no vector discriminated RFC 8785 §3.2.3's UTF-16 code-unit ordering (a code-point-sorting second implementation passed everything) | 10th vector `utf16-order` (astral-vs-BMP key pair), property test `test_property_utf16_order_vector_discriminates` |
| §4's distinct-quantities list was incomplete (subject-digest family, relation edge-digest sharpness, promptfoo site) and `anchors.receipt_canonical_root` was a second inline canonicalizer implementation | §4 extended above; `receipt_canonical_root` now delegates to the one canonicalizer home (call-spy test `test_property_receipt_root_delegates_to_the_one_canonicalizer`) |

The 9 iteration-1 pins themselves WITHSTOOD independent recomputation (rfc8785+hashlib only, no
proofbundle import): every `.jcs` byte-identical, every root reproduced, and both `binding`
vectors genuinely discriminate (the payloads are valid sortkeys AND invalid JCS, with
`1.0` vs `1` as the measured divergence).
