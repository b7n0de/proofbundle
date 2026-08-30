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
| **G2** | Merkle leaf input | **out of scope of 7.1** (its `MUST` is conditional and the condition does not hold here); the 5.1 duty to declare is discharged on this page |
| **G3** | typed digest reference | was **internally inconsistent**; conformant shape now available additively |
| **G4** | coverage | **absent on our side, and staying absent** — the field form was withdrawn on 2026-08-30 after CAP-1 was measured to rule it out |

G1 and G2 stand as measured. G3 was closed additively on 2026-08-30 — nothing existing became
mandatory, and no version was forced. G4 was **opened again on the same day**: a field form had been
added and was withdrawn hours later, see G4.

## G1 — canonicalization

| | |
|---|---|
| **Our side** | `src/proofbundle/canonical.py:43` — `CONTENT_ROOT_ALG = "jcs-sha256-v1"`. The real canonicalizer is called (`rfc8785.dumps`), imported lazily from the `[eval]` extra; `statement_content_root` returns 32 raw SHA-256 bytes, `.hex()` gives the 64-character identifier. |
| **Draft** | section 4.1 defines algorithm `jcs` as RFC 8785 JCS applied directly to the payload, **with no normalization pass** (no member removed for being `null`, `[]` or `{}`), then SHA-256, then lowercase hex -- a 64-character ASCII string. Paraphrase, not a quotation. Two details that matter here: exclusion-set removal is **not part of the algorithm** (section 5's derived-identifier construction strips the payload class's declared exclusion set *before* invoking it), and `jcs` places no restriction on JSON numbers beyond RFC 8785 itself. |
| **Verdict** | **Scope first, because the claim is narrower than it reads.** For statements canonicalized under the declared `jcs-sha256-v1` -- the path `canonicalize_statement` takes -- the behaviour is identical to the registry entry and only the token differs, which is a mapping question and not a contradiction. It is **mapped, not renamed**; renaming would invalidate every receipt carrying it. **It is not a statement about the whole library.** Released `intoto` export paths run a different serialization; they are declared under their own token and are the open exception below, not a silent part of this verdict. |

**The open exception, and it stands in our own source.** `canonical.py:27` states verbatim that
migrating the released `intoto` export paths off `json.dumps(sort_keys=True)` is *a separate T3 /
SemVer owner-gated step*. Measured on the working branch: 11 occurrences of `sort_keys=True` in
`src/proofbundle/*.py`, among them `intoto.py:126` and `:284` and `hf_evals.py:57`. So paths on a
different serialization remain, and that is the same divergence class we measured elsewhere on
2026-08-20.

**One consequence of 4.1 that was not connected before.** The draft's derived identifier is
`CANONICAL-DIGEST(A, payload minus exclusion_set)`; ours is the digest over the **whole** statement --
`statement_content_root` removes nothing, and `canonical.py` carries no exclusion-set concept at all
(measured: zero occurrences). The two agree exactly when the payload class declares an **empty**
exclusion set. We do not declare one either way, so this is the same duty section 5.1 imposes: state it
rather than leave it to be inferred. Named here; the declaration itself is a profile decision, not a code
change.

**What is already in place, and it belongs in the record:** `intoto.py:145` carries the token
`legacy-sortkeys-json-v0` as an algorithm in its own right, and `intoto.py:178` **rejects** a
`sort_keys` body offered *as* `jcs-sha256-v1`. The declaration and the guard exist; what is missing is
the migration itself. It is owner-gated and tracked as its own item, not done here.

## G2 — Merkle leaf input

| | |
|---|---|
| **Our side** | `src/proofbundle/merkle.py:34` computes RFC 6962 correctly, leaf hash `SHA-256(0x00 ‖ data)`. `src/proofbundle/bundle.py:770` passes the **payload** as leaf data: `merkle.leaf_hash(payload)`, where the payload is the base64url part of the issuer JWT. |
| **Draft** | section 7.1 opens *"This profile imposes no leaf construction on a Verifiable Data Structure"*, then makes one conditional requirement: **where a Transparency Service's VDS keys its log on the derived identifier**, a 64-character hex `D` MUST enter the tree as `bytes.fromhex(D)` (raw 32 bytes) and never as `D.encode("utf-8")` (64 ASCII bytes). Section 5.1 separately makes representation normative: a payload class **MUST specify which representation it uses** for each field containing or referencing a derived identifier, and a verifier **MUST NOT silently coerce** between them. |
| **Verdict** | **Section 7.1 does not reach our construction, and saying it does was my own overcorrection.** Read at source on 2026-08-30 (`draft-mih-sokolov-scitt-payload-binding-02.txt`, 92428 B, sha256 `47ab6757...`), the section opens: *"This profile imposes no leaf construction on a Verifiable Data Structure."* The `MUST` that follows is **conditional** -- *"Where a Transparency Service's VDS keys its log on the derived identifier"* -- and names the hex-as-text mistake as the failure that requirement exists to prevent. **We do not key on the derived identifier; we bind the payload.** So we are neither conformant with 7.1 nor in violation of it: the conditional does not reach us, and there is no defect here to declare. |

**What does reach us is section 5.1, and it is an obligation to declare rather than to change.** 5.1 makes
representation *normative*: a payload class **MUST specify which representation it uses for each field
containing or referencing a derived identifier**, and a verifier **MUST NOT silently coerce** among the three
listed forms. That duty applies to us whether or not 7.1 does, and this page is where we discharge it: our
log leaf is the payload, not the derived identifier in any of its representations.

**A rebuild is still not proposed, and now the reason is measured rather than asserted.** "A rebuild would
void every receipt already issued" stood here as a justification while the count behind it had never been
taken. Measured 2026-08-30: **91 bundles carrying both `merkle` and `payload_b64` in this tree** (of 3000 JSON
files examined), across **44 released versions on PyPI**, 0.3.0 through 5.0.0. Receipts issued by third
parties using this library are **NICHT MESSBAR** from here -- we cannot see them, so the true total is a lower
bound and not a figure.

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
| **Our side** | measured across all nine schemas under `schemas/`: no `population_size`, no `evaluated_count`, no `unresolved_count`. The nearest relative is `notChecked` in the decision receipt, which records what was *not* examined — same spirit, different level, and it does not answer the question about the examined set. |
| **CPB draft** | coverage does not appear anywhere in it. Its section 1.1 lists what is out of scope — payload content formats, artifact types, application meaning, registration policy, transports — and does **not** name evaluation coverage. Absence, not an explicit exclusion. |
| **Verdict** | **Absent on both sides — and it stays absent on ours for now.** |

**This entry was rewritten on 2026-08-30, and the reason matters more than the conclusion.** An
earlier version of it recorded that we had closed the gap additively with three fields
(`population_size`, `evaluated_count`, `unresolved_count`) and treated that as our contribution.

Measured the same day in the `scitt@ietf.org` archive: **`draft-hillier-coverage-attestation-00`**,
*The Coverage Attestation Profile* (CAP-1), 20 August 2026 — **older than our proposal** — specifies
this exact question. Its normative line requires, per stratum, that eligible units equal checked
units plus **individually justified** unchecked ones, and that **a remainder which only balances by
subtraction be rejected**. Three numbers whose third follows from the other two are precisely such a
remainder.

**So the fields were removed again rather than left standing.** Shipping a shape we had measured a
live draft to reject would be the overclaim this whole exercise exists against — and it would sit in
a document whose subject is not overclaiming. The removal is in the branch; the fields were never on
a remote (the branch had not been pushed when the correction arrived).

**Not replaced by a guess.** No CAP-1-shaped field set was rebuilt here: what has been read is CAP-1's
summary and two of the thread's 129 messages, and **the draft itself is unread**. The field form
proofbundle will carry is **undecided**, and deciding it is scheduled work, not something to infer
from an abstract.

**Untouched by any of this:** the RT-10 triple our own gates already emit
(`scripts/findings_register.py`, `scripts/audit_candidate_matrix.py`) carries `population_size` and
`evaluated_count` in exactly the shape discussed above. It is pre-existing, internal, and outside the
scope of this correction — noted here because it is the same shape and a reader will otherwise find
it and wonder.

## Which draft claims were checked at source

The draft side of this page was originally written from a reading that was not retained. On 2026-08-30
the draft was fetched and every claim this page makes about it was re-checked against the text:
`draft-mih-sokolov-scitt-payload-binding-02.txt`, **92428 bytes**, sha256
`47ab675797d7edfe...`, from `ietf.org/archive/id`.

| Claim | Section | Result |
|---|---|---|
| `jcs` = RFC 8785, no normalization pass, SHA-256, lowercase hex | 4.1 | **holds**; was set in italics as if quoted -- now marked as paraphrase, and two omitted details added |
| exclusion-set removal happens outside the algorithm | 4.1 / 5 | **new**, not previously connected; we carry no exclusion-set concept |
| representation is normative and must be declared | 5.1 | **holds**; this is the duty that actually reaches us |
| leaf construction rule | 7.1 | **did NOT hold as stated** -- the section imposes no leaf construction, its `MUST` is conditional, and the condition does not apply to us |
| typed digest reference: `type`, `purpose`, `digest_alg`, `digest` | 8 | **holds exactly**, including which are REQUIRED and which CONDITIONAL |
| coverage does not appear | whole draft | **holds, and stronger than stated**: `coverage`, `population`, `evaluated_count`, `unresolved` and `sample` have **0 occurrences in the entire document**, not merely in 1.1 |

One of six did not survive. That is the reason this table exists: a claim about someone else's normative
text, carried forward from our own earlier summary, is not a measurement.

## What is NOT measured

Whether the `intoto` export paths are reachable from outside or only internally. How many receipts
exist **outside this tree** with today's leaf construction -- the in-tree count is now measured under G2
and is a lower bound; the total is not knowable from here. Whether the draft is adopted by the working
group — it is an individual submission. Whether RFC 9943 considers evaluation receipts in scope. And
whether SCITT already carries work on coverage that we have missed.

## Honest limit of this page

**Review round 2026-08-30, and it went wrong twice in opposite directions.**
An adversarial reading rejected the G1 and G2 verdicts as too favourable. Two of its three reasons did
not survive contact with the source: it read `intoto.py:178` as *using* a `sort_keys` body under the `jcs`
token when that function **rejects** exactly that, and it called the G2 distinction sophistry. Its third
point landed: a justification ("a rebuild would void every receipt") rested on a number nobody had counted.

**Then I made the mirror-image mistake.** Having rejected two of the three reasons, I still accepted the
*framing* -- that G2 was too soft -- and rewrote the verdict to "not interoperable" **without re-reading
section 7.1**. Reading it afterwards: its first sentence is *"This profile imposes no leaf construction on
a Verifiable Data Structure"* and its `MUST` is conditional on a VDS keying its log on the derived
identifier, which ours does not. There was no defect to state. Overclaiming a fault in our own artefact is
the same failure as concealing one, and it is the harder of the two to notice, because it feels like rigour.

Both verdicts now quote the draft text they rest on, the scope of each claim precedes the claim, the count
was taken, and the obligation that *does* reach us -- section 5.1, declare your representation -- is named
and discharged. Recorded here because a page about not overclaiming should show where it overclaimed.

This is a measurement record of **our** artefacts against a **published** text. It confers nothing,
certifies nothing, and appoints no one to judge anyone's conformance. Whoever claims the profile runs
its counter-proofs and publishes the result.
