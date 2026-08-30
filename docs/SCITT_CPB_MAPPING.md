# Mapping: proofbundle against RFC 9943 and the SCITT payload-binding draft

Status: **measurement record.** Clause by clause, our source location beside the draft's clause. This
page states where we agree, where we differ, and why. It is not a comment on any other party's work
and contains no judgement about one — a divergence recorded here is a fact about two constructions,
not about anyone's intent.

**Measured 2026-08-30** against tag `v5.0.0` (commit `840a0a6bf4`) and the working branch head
`bd0161ab0ce6` (`pyproject` 5.0.0). The draft side was read the same day **from the draft itself**
(`https://www.ietf.org/archive/id/draft-mih-sokolov-scitt-payload-binding-02.txt`), not from a
summary: every section number below (4.1, 7.1, 8, 1.1) was checked against it, and one claim did not
survive that check — see G4. **Re-measured the same day** after G3 and G4 were closed
additively; the G3 entry below carries a correction to this document's own first pass. Subject on the other side:
`draft-mih-sokolov-scitt-payload-binding-02`, 24 Aug 2026, an individual submission with no standing
in the IETF process, sitting on top of [RFC 9943](https://www.rfc-editor.org/rfc/rfc9943) — the
published SCITT architecture, Standards Track, IETF stream, SCITT working group, June 2026. Both were
checked at their source on 2026-08-30; the asymmetry between them (a Standards-Track RFC and an
unaffiliated individual draft) is stated because it changes what a divergence from each one means.

Where a fact was not measured, this page says **NOT MEASURED** and does not fill the gap.

## Summary

| | Subject | Verdict |
|---|---|---|
| **G1** | canonicalization | behaviour congruent, **token differs**, one exception open |
| **G2** | Merkle leaf input | **hard divergence**, declared here, not rebuilt |
| **G3** | typed digest reference | was **internally inconsistent**; conformant shape now available additively |
| **G4** | coverage | was **absent on our side** in all nine schemas; now carried, optionally |

G1 and G2 stand as measured. G3 and G4 were closed additively on 2026-08-30 — nothing existing
became mandatory, and no version was forced.

## G1 — canonicalization

| | |
|---|---|
| **Our side** | `src/proofbundle/canonical.py:43` — `CONTENT_ROOT_ALG = "jcs-sha256-v1"`. The real canonicalizer is called (`rfc8785.dumps`), imported lazily from the `[eval]` extra; `statement_content_root` returns 32 raw SHA-256 bytes, `.hex()` gives the 64-character identifier. |
| **Draft** | section 4.1 registers `jcs` as *plain RFC 8785 JCS, no normalization pass; SHA-256; lowercase hex output*. |
| **Verdict** | **The behaviour is identical. The token differs**, `jcs-sha256-v1` here against `jcs` in the registry. That is a mapping question, not a contradiction. The token is **mapped, not renamed** — renaming it would invalidate every receipt that carries it. |

**The open exception, and it stands in our own source.** `canonical.py:27` states verbatim that
migrating the released `intoto` export paths off `json.dumps(sort_keys=True)` is *a separate T3 /
SemVer owner-gated step*. Measured on the working branch: 11 occurrences of `sort_keys=True` in
`src/proofbundle/*.py`, among them `intoto.py:126` and `:284` and `hf_evals.py:57`. So paths on a
different serialization remain, and that is the same divergence class we measured elsewhere on
2026-08-20.

**What is already in place, and it belongs in the record:** `intoto.py:145` carries the token
`legacy-sortkeys-json-v0` as an algorithm in its own right, and `intoto.py:178` **rejects** a
`sort_keys` body offered *as* `jcs-sha256-v1`. The declaration and the guard exist; what is missing is
the migration itself. It is owner-gated and tracked as its own item, not done here.

## G2 — Merkle leaf input

| | |
|---|---|
| **Our side** | `src/proofbundle/merkle.py:34` computes RFC 6962 correctly, leaf hash `SHA-256(0x00 ‖ data)`. `src/proofbundle/bundle.py:770` passes the **payload** as leaf data: `merkle.leaf_hash(payload)`, where the payload is the base64url part of the issuer JWT. |
| **Draft** | section 7.1 requires, for a derived identifier `D` given as 64-character hex, `leaf_input = bytes.fromhex(D)` — the **raw 32 bytes** — and explicitly names `D.encode("utf-8")` (64 ASCII bytes) as the wrong alternative. |
| **Verdict** | **Two different constructions, and ours is a THIRD thing rather than the draft's named error.** We bind the log to the payload itself, not to the identifier in either of its forms — so the hex-as-text mistake the draft warns about is not the one we make. A verifier following the draft still computes a different leaf over our bundle. Neither is wrong; without a declaration neither is interoperable. |

**Declared, not rebuilt.** A rebuild would void every receipt already issued. The draft's own
requirement is that a class declares its choice and a verifier does not guess — this page is that
declaration.

## G3 — typed digest reference

**Correction to this document's first pass.** The first version of this entry measured
`schemas/eval_claim_v0_1.schema.json:105` and generalized from it. That was one site, not the
picture. `schemas/decision-receipt-v0.1.schema.json` carries **both** shapes at once:

| Definition | Shape | Used by |
|---|---|---|
| `sha256Digest` (line 13) | algorithm in the KEY NAME: `{"sha256": "<hex>"}` | `evidenceRefs[].digest`, `inputSnapshot[].digest`, … |
| `relationDigest` (line 20) | algorithm in a FIELD: `{"digestAlgorithm": "jcs-sha256-v1", "digest": "<hex>"}` | `relationships[]` |

`relationDigest` is the draft-conformant construction, and it carries the draft's own reasoning
verbatim in its description: *"digestAlgorithm is EXPLICIT and REQUIRED — never defaulted (a missing
value is exactly where algorithm confusion hides)."* Two of the draft's four fields also already
existed on the `evidenceRefs[]` entry itself: `predicateType` and `relation`.

**So the gap was never absence. It was internal inconsistency** — we had the conformant shape and
the argument for it, and used it in one place out of several.

| | |
|---|---|
| **Draft** | section 8 requires four fields: `type`, `digest_alg`, `digest` mandatory, `purpose` conditional. |
| **Closed 2026-08-30, additively** | `$defs/typedDigest` plus an optional `typedDigest` on `evidenceRefs[]`. Required `type`, `digestAlgorithm`, `digest`; optional `purpose`. It replaces nothing: an entry may carry `digest` alone, `typedDigest` alone, or both, and `digest` stays required. |
| **Naming** | the draft writes `digest_alg`; we write `digestAlgorithm`, because that field already exists in `relationDigest` with the same meaning and these schemas are lowerCamelCase throughout (ITE-9). Two names for one quantity inside one file would be the next drift, so the correspondence is recorded here instead — the same mapping question as G1. `type` and `purpose` are the draft's names unchanged. |
| **Enforced** | `src/proofbundle/decision.py::_typed_digest_error`, one definition, mirrored by the docs schema and held together by `tests/test_evidence_typed_digest.py` (16 tests, incl. 8 parity cases). |

## G4 — coverage

| | |
|---|---|
| **Our side, as first measured** | across **all nine** schemas under `schemas/`: **no `population_size`, no `evaluated_count`, no `unresolved_count`** — zero occurrences. The nearest relative is `notChecked` in the decision receipt, which records what was *not* examined. Same spirit, different level, and it does not answer the question about the examined set. |
| **Draft** | coverage does not appear anywhere in the draft. Its section 1.1 lists what is out of scope — payload content formats, artifact types, application meaning, registration policy, transports — and does **not** name evaluation coverage. So this is absence, not an explicit exclusion; the two are different and only the first is supported by the text. |
| **Verdict** | **Was absent on both sides.** R5 of our profile was the second rule we asked of others while not carrying it ourselves. The first is R6. |
| **Closed 2026-08-30, additively** | optional `coverage` on the eval claim: optional as a whole, **complete when present** — a missing denominator invites the reader to assume the ratio is 1. |

**Two design decisions worth stating, because both could have gone the lazy way.**

`evaluated_count` MUST equal the claim's `n`. `n` is already the size the aggregate was computed
over (`intoto.py:426` exports it as `sampleSize`), so a second free-floating number would have been
a second truth about one quantity. The binding mirrors the existing `samples.n == n` rule and its
stated reason. The three counts are **disjoint** subsets: `evaluated + unresolved <= population`,
and the remainder is the deliberately excluded set.

Enforced on **all three** paths — build, emit and verify — from one definition. A rule enforced only
at emit is bypassed by a hand-signed claim, which is the emit-vs-verify asymmetry class
`evalclaim.py` already guards for `samples` and `assurance_level`.
`tests/test_eval_claim_coverage.py` (14 tests) covers it, and six planted defects were each caught.

**A measured limit that belongs here, not in a footnote.** These schemas run
`additionalProperties: false`, so "additive" holds in **one direction only**. Measured: an old
receipt validates under the new schema; a new receipt carrying `coverage` **fails** under the old
one — and fails as *invalid*, not as *unknown*. That is exactly the distinction R2 of our own
profile demands of a verifier, and our schema form does not make it. Recorded as an executable fact
in `test_gemessene_grenze_additiv_ist_nur_eine_richtung`, not as a claim.

## What is NOT measured

Whether the `intoto` export paths are reachable from outside or only internally. How many receipts
are already out there with today's leaf construction. Whether the draft is adopted by the working
group — it is an individual submission. Whether RFC 9943 considers evaluation receipts in scope. And
whether SCITT already carries work on coverage that we have missed.

## Honest limit of this page

This is a measurement record of **our** artefacts against a **published** text. It confers nothing,
certifies nothing, and appoints no one to judge anyone's conformance. Whoever claims the profile runs
its counter-proofs and publishes the result.
