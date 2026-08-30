# Mapping: proofbundle against RFC 9943 and the SCITT payload-binding draft

Status: **measurement record.** Clause by clause, our source location beside the draft's clause. This
page states where we agree, where we differ, and why. It is not a comment on any other party's work
and contains no judgement about one — a divergence recorded here is a fact about two constructions,
not about anyone's intent.

**Measured 2026-08-30** against tag `v5.0.0` (commit `840a0a6bf4`) and the working branch head
`bd0161ab0ce6` (`pyproject` 5.0.0). Subject on the other side:
`draft-mih-sokolov-scitt-payload-binding-02`, 24 Aug 2026, an individual submission with no standing
in the IETF process, sitting on top of the published [RFC 9943](https://www.rfc-editor.org/rfc/rfc9943).

Where a fact was not measured, this page says **NOT MEASURED** and does not fill the gap.

## Summary

| | Subject | Verdict |
|---|---|---|
| **G1** | canonicalization | behaviour congruent, **token differs**, one exception open |
| **G2** | Merkle leaf input | **hard divergence**, declared here, not rebuilt |
| **G3** | typed digest reference | **partial** — the information is there, the shape is not |
| **G4** | coverage | **absent on our side**, in all nine schemas |

Two of four match. The two that do not are exactly the two where we would have something to
contribute.

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
| **Draft** | section 7.1 requires, for a derived identifier `D` given as 64-character hex, `leaf_input = bytes.fromhex(D)` — the **raw 32 bytes**, not the text form. |
| **Verdict** | **Two different constructions.** We bind the log to the payload; the draft binds it to the content-addressed identifier. A verifier following the draft computes a different leaf over our bundle. Neither is wrong; without a declaration neither is interoperable. |

**Declared, not rebuilt.** A rebuild would void every receipt already issued. The draft's own
requirement is that a class declares its choice and a verifier does not guess — this page is that
declaration.

## G3 — typed digest reference

| | |
|---|---|
| **Our side** | `evidenceRefs[].digest.sha256`, and in the in-toto statement `subject[0].digest.sha256` (e.g. `schemas/eval_claim_v0_1.schema.json:105`). |
| **Draft** | section 8 requires four fields: `type`, `digest_alg`, `digest` mandatory, `purpose` conditional. |
| **Verdict** | **Partial.** The algorithm sits inside the key name rather than in a field of its own; `type` and `purpose` are absent. The information is partly present, the shape is a different one. |

Additive resolution: carry the draft's shape as an **additional** form beside today's
`digest.sha256`, which stays valid. Nothing existing becomes mandatory.

## G4 — coverage

| | |
|---|---|
| **Our side** | Measured across **all nine** schemas under `schemas/`: **no `population_size`, no `evaluated_count`, no `unresolved_count`** — zero occurrences. The nearest relative is `notChecked` in the decision receipt, which records what was not examined. Same spirit, different level, and it does not answer the question about the examined set. |
| **Draft** | coverage does not appear. Its section 1.1 lists what it does not cover. |
| **Verdict** | **Absent on both sides.** This is R5 of our profile, and it is the second rule we ask of others while not carrying it ourselves. The first is R6. |

Additive resolution: take the three fields as **optional** fields. Nothing existing becomes
mandatory, no version bump is forced.

## What is NOT measured

Whether the `intoto` export paths are reachable from outside or only internally. How many receipts
are already out there with today's leaf construction. Whether the draft is adopted by the working
group — it is an individual submission. Whether RFC 9943 considers evaluation receipts in scope. And
whether SCITT already carries work on coverage that we have missed.

## Honest limit of this page

This is a measurement record of **our** artefacts against a **published** text. It confers nothing,
certifies nothing, and appoints no one to judge anyone's conformance. Whoever claims the profile runs
its counter-proofs and publishes the result.
