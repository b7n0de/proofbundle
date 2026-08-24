# Content Root Contract (Phase 1 / R51)

Generated 2026-08-24 (order `20260824T071500Z`; source document sha256
`1bfc06cefd284867271862808e4929bf7070aa8c3eb5b1ad168356a3e9891709`). This document states the
contract; the normative single source for the definition is **ADR 0002**
(`docs/adr/0002-universal-content-root.md`) and the implementation is
`src/proofbundle/canonical.py` — this file cites them and adds the measured per-path table and
the conformance vector set. It deliberately does NOT restate the definition in different words:
a second wording would be a second truth.

## 1. The one primitive

| What | Where |
|---|---|
| Definition (normative) | ADR 0002 — SHA-256 over the RFC 8785 (JCS) canonical bytes of the FULL in-toto Statement, computed BEFORE signing; signature bytes are never part of the preimage |
| Implementation | `src/proofbundle/canonical.py` — `canonicalize_statement()` (producer bytes) and `statement_content_root()` (both sides) |
| Algorithm id | `jcs-sha256-v1` (`canonical.CONTENT_ROOT_ALG`) |
| Two-part rule | producer canonicalizes and signs exactly those bytes; verifier hashes the EXACT transmitted bytes and never re-canonicalizes |
| Missing canonicalizer | fail-closed `CanonicalizerUnavailable` (install `proofbundle[eval]`), never a silent fallback |

## 2. Measured state per predicate path (pinned commit `c669d39e3d8e`)

Every emit/verify path of the predicate classes named in R28 delegates to the one primitive:

| Predicate class | Evidence (file:line) | Serialization |
|---|---|---|
| decision-receipt | `decision.py:346-358` (canonical delegate), `:330,637,730` (root recompute in verify) | jcs-sha256-v1 |
| action-outcome | `outcome.py:379-384`, `:320,630` | jcs-sha256-v1 |
| relation | `relation.py:48` (`jcs-sha256-v1` the only accepted alg) | jcs-sha256-v1 |
| relation-statement | `relation_statement.py:103,254` | jcs-sha256-v1 |
| trust-pack | `trust_pack.py:293` | jcs-sha256-v1 |
| verification-summary | `verification_summary.py:141`; SVR DSSE export `intoto.py:562-614` (default `CONTENT_ROOT_ALG`) | jcs-sha256-v1 (default) |
| run-ledger | `run_ledger.py:190` | jcs-sha256-v1 |
| eval-result / test-result DSSE exports | `intoto.py:140-155` (`_serialize_statement`, default `CONTENT_ROOT_ALG`) | jcs-sha256-v1 (default), named legacy opt-in |
| subject-binding (statement scope) | `subject_binding.py:38` (canonical delegate) — the module ALSO hosts the predicate-scope subject-digest derivation at `:46`, which is NOT a statement root (see §4) | jcs-sha256-v1 |

**Gate verdict (R51): on the same statement bytes every relevant existing predicate path produces
the same root** — the verifier side hashes exact bytes everywhere, and every producer path
canonicalizes through the same function. The conformance vectors below pin this executably.

## 3. The named legacy algorithm — and the deliberate HALT

The released 2.0.0 wire (`json.dumps(sort_keys=True)`) survives as the NAMED algorithm
`legacy-sortkeys-json-v0` (`intoto.py:50,120-201`):

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
out of scope for this contract: subject binder digests (`intoto.py:279-284,394-399` — flat
fixed-key scalar objects), per-sample disclosure hashes (`persample.py:104`), the hf bundle digest
(`hf_evals.py:56`), and the LABELED config-digest fallbacks in the adapters
(`adapters/_provenance.py:53`, `adapters/eee.py:139`, `adapters/promptfoo.py:96-98`).

**Added in iteration 2 (deep-gate lens 2 refuted the first enumeration as incomplete):**

* **The `sha256(JCS(predicate))` subject-digest family** — seven sites, one per predicate module
  (`decision.py:387`, `outcome.py:407`, `relation_statement.py:126`, `run_ledger.py:210`,
  `verification_summary.py:161`, `trust_pack.py:313`, `subject_binding.py:46`). This is a
  PREDICATE-scope commitment used as the Statement's `subject.digest` — deliberately NOT the
  full-Statement content root (a subject cannot contain the hash of the statement it is part of).
  Both values are 64-hex and both travel in fields named `digest.sha256`; measured on the shipped
  cross-impl fixture they differ (statement root `19d6c23eecc9…` vs subject digest
  `f8f27c96d173…`). Any audit counting "roots" must keep these two families apart.
* **The relation edge-digest sharpness:** `relation.py:131-133` validates `targetReceiptDigest`
  (a statement root) and `targetSubjectDigest` (a predicate-scope subject digest) with one
  `_validate_edge_digest` under the single alg id of `relation.py:48`. The two fields carry
  different preimages under the same label — semantically distinguished by FIELD NAME, not by
  algorithm id. Recorded here as a documented sharpness; changing the wire (separate alg ids or
  a scope marker) would be a public-surface decision, not a Phase-1 act.
* **`anchors.receipt_canonical_root`** (bundle-scope receipt-anchor root) — was a second inline
  rfc8785+budget implementation (the duplication had already cost the same structural-budget fix
  twice, rounds 5 and 7); since iteration 2 it delegates to the one canonicalizer home while
  keeping its anchor-layer `BundleFormatError` contract. The QUANTITY stays distinct
  (bundle scope, no Statement shape requirement).

## 5. Conformance vectors

`conformance/action_chain_content_roots/` — 10 cases, kind `content_root_vector`, run by
`conformance/run_conformance.py` (same harness, same manifest, no second runner):

* canonical: key order · unicode · number formatting (1.0→1, 1e2→100, −0→0) · nested arrays ·
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

## 6. Cross-language status — OPEN, stated plainly

The vectors are language-neutral data (input JSON + pinned canonical bytes + pinned roots) and are
**self-generated golden pins from this implementation**. They catch regressions and give a second
implementation a concrete target, but cross-implementation agreement is NOT yet proven by them.
The existing `decision_crossimpl` cases (second independent implementation, MarkovianProtocol)
prove cross-impl agreement for the decision pair; extending that to this vector set is the open
follow-up (R51 gate wording: "Cross Language Vektoren werden vorbereitet oder als offen markiert"
— they are prepared, and marked open).

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
