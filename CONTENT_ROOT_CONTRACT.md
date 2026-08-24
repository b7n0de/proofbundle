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
| subject-binding | `subject_binding.py:38` | jcs-sha256-v1 |

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
(`adapters/_provenance.py:53`, `adapters/eee.py:139`).

## 5. Conformance vectors

`conformance/action_chain_content_roots/` — 9 cases, kind `content_root_vector`, run by
`conformance/run_conformance.py` (same harness, same manifest, no second runner):

* canonical: key order · unicode · number formatting (1.0→1, 1e2→100, −0→0) · nested arrays ·
  unknown top-level field (root MUST change);
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
