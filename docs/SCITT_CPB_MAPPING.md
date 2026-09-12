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

## Mapping 2 — draft-dawkins-scitt-ai-article50-00 against our predicates

Status: **measurement record**, same rules as the page above: field by field, our source location beside
the draft's field, no judgement about the other side.

**Measured 2026-09-04** against `origin/main` at `bde6c8692ba33052acae19b0ae962032329224d1` (merge of #182,
`pyproject` 5.1.0), working branch `docs/scitt-mapping-artikel50-permit-cedulon` on the same commit. The
draft side was read **from the draft itself**:
`https://www.ietf.org/archive/id/draft-dawkins-scitt-ai-article50-00.txt`, fetched 2026-09-04T20:38:30Z,
26273 bytes, sha256 `9b00c51450441ad2…`. An individual submission by one author (LedgerProof Foundation),
intended status Standards Track, dated May 25 2026, expiring November 25 2026. Whether the working group
has adopted it was NOT MEASURED (the datatracker state was not queried; the draft header alone was read).

Our side: `src/proofbundle/decision.py` (required fields lines 37–40, nested closure lines 65–93),
`src/proofbundle/agent_review.py` (required fields lines 112–123, declaration fields 104–109, v0.2 time
claims 1573–1577, the `disclosureCoreDigest` rule 1644–1648), `docs/AGENT_REVIEW_PREDICATE.md`.

Vocabulary of the last column, used in Mappings 2 to 4: **same** (same meaning and construction),
**similar** (same purpose, different construction or scope), **different** (a field of that role exists but
means something else), **NO COUNTERPART**.

### Table 1a — `ai/article-50/v1` (synthetic content receipt), REQUIRED fields (§3.1)

The nearest predicate on our side is `decision-receipt/v0.1`: it is the only one that names an AI system, a
responsible party and a digest-bound object in one signed statement. It is a decision record, not a
content-provenance record, and the rows say so where it matters.

| draft field | draft status | our counterpart | meaning |
|---|---|---|---|
| `ai_system_id` | REQUIRED | `agent.id` (`decision.py:66`), a string identifying the acting AI system | similar — free-form at ours; `<provider>/<model>/<version>` recommended at theirs |
| `ai_system_version` | OPTIONAL | `agent.version`, `agent.configurationDigest` (`decision.py:66`) | similar |
| `deployer_id` | REQUIRED, a legal-entity identifier, never a natural person | `principal.id` (`decision.py:67`) names the party on whose behalf the action is proposed; `decisionMaker.id` (`:65`) names who decided | different — neither is constrained to a legal-entity identifier, neither carries the deployer role of Article 50 |
| `deployer_name` | REQUIRED | — | NO COUNTERPART |
| `deployer_country` | REQUIRED, ISO 3166-1 alpha-2 | — | NO COUNTERPART |
| `content_category` | REQUIRED enum | — | NO COUNTERPART |
| `artifact_hash` | REQUIRED, SHA-256 of the artifact, artifact never included | the in-toto `subject[].digest.sha256` of the Statement commits to the decision (`docs/predicates/decision-receipt.md` §4, e.g. `decision:<decisionId>`); `inputSnapshot[].digest` (`decision.py:92`) digests inputs | different — our subject commits to the decision, not to a generated artifact |
| `artifact_content_type` | REQUIRED, IANA media type | `inputSnapshot[].mediaType` (`decision.py:92`), inputs only | similar for inputs, NO COUNTERPART for the produced artifact |
| `artifact_bytes` | REQUIRED, > 0 | — | NO COUNTERPART |
| `generation_type` | RECOMMENDED enum | — | NO COUNTERPART |
| `transparency_marker` | REQUIRED, default `LPR-EU-AI-ACT-50` | — | NO COUNTERPART |
| `enforcement_date` | REQUIRED, default `2026-08-02` | — | NO COUNTERPART |
| `profile_version` | REQUIRED, default `EU-AI-ACT-50-v1.1` | `schemaVersion` plus the version inside `predicateType` (`decision-receipt.md` §5.3) | similar — both pin a receipt to a profile revision |
| `is_public_interest`, `supervisory_authority`, `source_content_hash`, `perceptual_hash` | OPTIONAL | — | NO COUNTERPART |

Count for 1a, REQUIRED fields only (11): same 0 · similar 2 · different 2 · NO COUNTERPART 7.

### Table 1b — `ai/human-review/v1` (editorial review receipt), REQUIRED fields (§3.2), against `agent-review/v0.1` and `v0.2`

| draft field | draft status | our counterpart | meaning |
|---|---|---|---|
| `original_entry_hash` | REQUIRED, hash of the registered original `ai/article-50/v1` statement | `subjectContext.reviewedDiffDigest`, `headSha`, `bodyCoreDigest` (`agent_review.py:117-118`) bind the reviewed object; `supersession` (`:114`, optional) binds a predecessor receipt; decision-receipt `evidenceRefs[].digest` binds a cited statement's content root | similar — both bind the review to exact bytes of what was reviewed; ours binds a pull request or an issue, not a registered statement |
| `original_sequence` | REQUIRED, log sequence number | — | NO COUNTERPART (no transparency-log position in the predicate; checkpoints live in the public-transparency layer, `docs/predicates/README.md`) |
| `reviewer_role` | REQUIRED, a role identifier, never a name | `declaration.authoring[].assertedBy` and `declaration.reviewRuns[].assertedBy` (`agent_review.py:104-105`; free text such as `"an agent"`), each with an `assurance` rung | similar — both name who reviewed without a personal identifier; theirs a role string, ours a free-text assertion carrying its assurance |
| `reviewer_country` | REQUIRED | — | NO COUNTERPART |
| `review_timestamp` | REQUIRED, ISO 8601 | v0.1 `times.declaredAt` (`:123`); v0.2 `declaration.timeClaims[]` with `kind: reviewCompleted`, `assertedBy`, `assurance` (`:1575-1577`) | similar — both issuer-declared; ours states the assurance of the time claim, `selfDeclared` being the only rung emitted today |
| `review_type` | REQUIRED enum: SUBSTANTIAL_EDIT, FACTUAL_REVIEW, APPROVAL_ONLY | `declaration.reviewRuns[]` (the runs) and `findings[].disposition` (`fixed`, `dismissed`, `deferred`, `open`, `:101`) | different — ours records what was found and what became of it, not a class of review |
| `reviewed_artifact_hash` | REQUIRED, post-review content | `subjectContext.reviewedDiffDigest` (`:118`) | similar — digest of the reviewed diff at ours, of the post-review content at theirs |
| `is_public_interest` | REQUIRED | — | NO COUNTERPART |
| `review_rationale` | OPTIONAL | `findings[].title`; the one-sentence reason a `dismissed` finding must carry (`docs/AGENT_REVIEW_PREDICATE.md`, Findings) | similar |

Count for 1b, REQUIRED fields only (8): same 0 · similar 4 · different 1 · NO COUNTERPART 3.

### Table 1c — `ai/chatbot-session/v1` (interactive AI receipt), REQUIRED fields (§3.3)

| draft field | draft status | our counterpart | meaning |
|---|---|---|---|
| `session_id_hash` | REQUIRED | `traceContext.traceparent` (`decision.py:81`, W3C Trace Context) | different — a trace correlation id, not a hashed session commitment |
| `ai_system_id` | REQUIRED | `agent.id` | similar, as in 1a |
| `deployer_id`, `deployer_name`, `deployer_country` | REQUIRED | as in 1a | different · NO COUNTERPART · NO COUNTERPART |
| `notification_timestamp` | REQUIRED | — | NO COUNTERPART |
| `notification_method` | REQUIRED enum | — | NO COUNTERPART |
| `notification_text_hash` | REQUIRED | — | NO COUNTERPART |
| `obvious_exemption_claimed` | REQUIRED | — | NO COUNTERPART |

Count for 1c, REQUIRED fields (9): same 0 · similar 1 · different 2 · NO COUNTERPART 6.

### What a reader could do with an agent-review receipt under Article 50, and what not

Can: check offline that a named key signed a self-declaration that an agent took part in a review of exactly
these bytes (`reviewedDiffDigest`, `bodyCoreDigest`), how many review runs were declared, which findings
were declared with which disposition, and that the receipt has not changed since.

Negation list:

- It is not an `ai/article-50/v1` receipt: no `content_category`, no `transparency_marker`, no `deployer_*`,
  no `artifact_bytes`. It cannot serve as the machine-readable marking of Article 50(2).
- It is not an `ai/human-review/v1` receipt: no `review_type`, no `is_public_interest`, no
  `original_entry_hash` to a registered statement, no same-deployer check (§4.1 step 6). It cannot by itself
  support the Article 50(4) editorial-review exemption.
- It is not registered with a Transparency Service and carries no `original_sequence`; §4.2 steps 1 and 7
  (registration, substrate anchoring) have no object to act on.
- It does not identify a legal entity; `assertedBy` is free text at `selfDeclared` assurance, and the
  predicate's own text says a strong signature must not optically harden a weak self-report.
- It says nothing about content generation: the reviewed object is a pull request or an issue, not
  synthetic media.

NOT MEASURED: the draft's Appendix A (C2PA mapping) is announced in §1.3, but the fetched -00 text ends at
the author's address without an appendix; whether a later revision carries it was not checked.

## Mapping 3 — draft-munoz-scitt-permit-profile-01 and the override thread against decision-receipt, action-outcome and relation

Status: measurement record. Measured 2026-09-04 against the same commit as Mapping 2. Draft side read from
the draft itself: `https://www.ietf.org/archive/id/draft-munoz-scitt-permit-profile-01.txt`, fetched
2026-09-04T20:38:30Z, 72262 bytes, sha256 `1dbcbd215445b86e…`; an individual submission, Informational,
18 July 2026, expiring 19 January 2027. Its own Section 11 states that the reference implementation emits no
COSE_Sign1 today and that Closure Records are best-effort; those statements are the draft's, repeated here
because they bound what the mapping below can mean.

The override sentence of the list thread "Escalation and hold-window semantics" (4 September 2026) is taken
**as relayed in our order of the same day**: an override is a subsequent attested statement with a reference
to the subject. A search of the `scitt` list archive for `hold-window` on 2026-09-04 returned nothing
through the archive's search page, so the thread text itself is **NOT MEASURED** here and the sentence is not
quoted as the authors' words.

Our side: `src/proofbundle/decision.py` as above; `src/proofbundle/outcome.py` (required fields lines
41–52, `decision_bound` 608–609, `role_separation_ok` 617–618, `execution_proven` 647, aggregate `ok` 817);
`src/proofbundle/relation.py` (vocabulary line 39, edge fields 64–66, caps 52–53); `docs/predicates/relation.md`.

### Table 2a — the Permit object (§2, §3.1) against `decision-receipt/v0.1`

| Permit element | our counterpart | meaning |
|---|---|---|
| `id` | `decisionId` (`decision.py:38`) | same |
| `project_id`, tenancy scope | — | NO COUNTERPART |
| `decision`: `allow` / `deny` / `challenge` | `decision.verdict`: `ALLOW` / `DENY` / `REFUSE` / `ESCALATE` / `DEFER` / `OBSERVE` (`:33`) | similar — `challenge` has no single counterpart, `ESCALATE` and `DEFER` are the nearest; ours carries three more values |
| `subject_type` + `subject_id`, e.g. the agent's SPIFFE URI | `agent.id` (`:66`) for the acting agent; `principal.id` (`:67`) for the party on whose behalf | similar — the acting agent maps to `agent`; there is no type discriminator |
| resource identifier and action label (`resource_provider`, `resource_model`, `action_name`) | `proposedAction.actionType`, `.target{name,uri,digest}`, `.method` (`:69-72`) | similar |
| `policy_id` + `policy_version` | `policyBoundary.policyId`, `.bundleRevision`, `.policyDigest`, `.policyEngine`, `.decisionPath` (`:73-74`) | same for `policy_id`; similar for the version, which we pin by digest and bundle revision |
| `request_fingerprint`, SHA-256 over stripped request semantics, for replay correlation | `proposedAction.parametersDigest` (`:69`) | similar — a digest of the parameters, without the draft's strip-and-canonicalize pipeline |
| `binding_request_hash`, SHA-256 over the canonical wire bytes after volatile-key and credential-key stripping (§4) | `proposedAction.parametersDigest`, `inputSnapshot[].digest` (`:92`) | different — ours digests declared parameters or inputs with the algorithm in the key name; the draft commits to the canonical dispatched bytes under a documented pipeline |
| parent Permit id plus lineage evidence for Authority Attenuation (§3.7) | `delegationRefs[]` (`:51`, optional) and a `relationships[]` edge `derivedFrom` (`relation.py:39`) | similar for the reference; NO COUNTERPART for attenuation: no Authority Representation, no Comparator Profile, no narrower-or-equal check |
| `created_at` | `decidedAt` (`:38`) | same |
| `decision_details`, `constraints` (optional) | `decision.reasonCodes`, `.humanReadableSummary`, `.obligations`, `.allowedScope` (`:83`) | similar |

Count for 2a (11 elements): same 3 · similar 5 · different 1 · NO COUNTERPART 2, one of them the attenuation half of a shared row.

### Table 2b — the Closure Record (§3.2) and the verifier duties (§3.6) against `action-outcome/v0.1`

| draft element | our counterpart | meaning |
|---|---|---|
| Closure Record, a second Signed Statement paired to the Permit | an `action-outcome` Statement citing the decision by `decisionRef.sha256` (`outcome.py:42`) | similar — both are second signed objects; ours is signed by the executor, theirs by the Issuer (§3.5 permits Issuer and Transparency Service to be one operator) |
| `dispatch_request_digest_v1` | `requestedActionDigest.sha256` (`:42`) | similar |
| `provider_response_digest_v1` | `responseDigest.sha256` (`:45`) | same |
| `client_response_digest_v1` | `effectDigest.sha256`, `actualActionDigest.sha256` (`:45`) | similar |
| status, timing | `status` (`executed` / `refused` / `failed` / `partial`), `performedAt` (`:43`) | similar |
| accounting fields | — | NO COUNTERPART |
| §3.6 step 3: `dispatch_request_digest_v1` equals `binding_request_hash` | `decision_bound` (`outcome.py:608-609`): `decisionRef.sha256` equals the content root the caller expects | different — ours binds the outcome to the whole decision statement, not to request bytes; no verifier check compares `requestedActionDigest` with the decision's `proposedAction.parametersDigest` (measured: the outcome verify path never reads the decision predicate) |
| §3.6 step 4: response digests present for `closed` | `execution_proven` (`:647`, `outcome_execution_proven` `:224`): `executed` plus an effect or actual-action digest | similar — both are digest-presence checks; ours labels the legacy boolean as attacker-choosable content and points to `evidence_levels` (`:714-730`) |
| §3.6 step 5: Authority Attenuation | — | NO COUNTERPART |
| executor distinct from decision maker | `role_separation_ok` (`:617-618`, when `decision_maker_id` is supplied) | the draft has no such check; recorded because it is the one axis on which our check is the stricter one |
| Receipt: per-scope linked chain plus signed checkpoint (§3.3) | detached anchors (RFC 3161, OpenTimestamps, chia-datalayer; `decision-receipt.md` §8) and C2SP checkpoints with witness cosignatures (`SPEC.md` §7c–7d) | different construction, same purpose: inclusion and existence before a time |

### Table 2c — the override against `relation/v0.1`

Override semantics, as relayed: a subsequent attested statement that references the subject. At ours that
is a **new** decision-receipt or action-outcome carrying a typed, signed back-edge in `relationships[]`
(`relation.py:39,64-66`; `docs/predicates/relation.md` §2) to the predecessor's content root, or a standalone
`relation-statement/v0.1` when no successor result is emitted.

Real bytes from the conformance corpus, not invented:
`conformance/relation/declared-supersedes-verified/receipt.json`, predicate `relationships[0]`:

```json
{"relation": "supersedes",
 "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1",
                         "digest": "12a292f7217cb61832a1080007d99a4ab0cc6c109214ec5da98ddf4c64546fa1"},
 "reasonCode": "correction",
 "declaredAt": "2026-07-16T00:00:00Z"}
```

Measured 2026-09-04 with proofbundle 5.1.0: `statement_content_root` over the predecessor `related_b.json`
(subject `decision:d-predecessor`) is `12a292f7217cb61832a1080007d99a4ab0cc6c109214ec5da98ddf4c64546fa1`,
equal to the edge digest; the corpus case expects exit 0 and lineage `VERIFIED`.

| what the relayed sentence asks of an override | `relation/v0.1` | meaning |
|---|---|---|
| a subsequent statement | a new receipt carrying the edge, or a relation-statement | same |
| attested | DSSE-signed; the edge sits inside the signed bytes (`relation.md` §2) | same |
| references the subject | `targetReceiptDigest`, the content root of the exact predecessor bytes; optional `targetSubjectDigest`, binding when present (`relation.md` §5) | similar — the reference is to the predecessor statement, and optionally to its subject |
| replaces or narrows what was permitted | `supersedes` / `corrects` / `revises` / `retracts` (`relation.py:39`); who may declare it and which parent is admissible are trust-policy pins (`relation_signer`, `require_relation_target`) | similar — the relation is typed; whether the successor's authority is narrower is NOT compared |
| a hold window in which an override is admissible | — | NO COUNTERPART — `declaredAt` is informative only (`relation.md` §2); the format has no time window |

What `relation` can: express change as a declared, signed back-edge over exact bytes; report four lineage
states; let a relying party require resolution, reject a superseded or retracted target, pin the signer
and the parent. What it cannot: revoke the predecessor's cryptography; show that the successor is better,
correct or authorized; compare scopes; express a time window. The profile's own boundary, verbatim:
*relationship declared by issuer, not a statement of correctness.*

## Mapping 4 — draft-dogru-cedulon-decision-profile-02 against decision-receipt and action-outcome

Status: measurement record. Measured 2026-09-04 against the same commit. Draft side read from the draft
itself: `https://www.ietf.org/archive/id/draft-dogru-cedulon-decision-profile-00.txt`, fetched
2026-09-04T20:38:30Z, 55082 bytes, sha256 `d44c50eaaa28101c…`; an individual submission, Informational,
4 September 2026, expiring 8 March 2027. Its own text calls its requirement language provisional (§1) and
reports one companion implementation with eighteen conformance cases in -00, twenty in -01 and -02, and no
independent implementation (§11; -02 §11, lines 1256–1258, records the companion as published at 0.13.0 on
4 September 2026). The companion repository (`dogrucanemek-alt/cedulon`) was NOT read; two pins the author
named were checked by API on 2026-09-05 (see "Verifying pairs on record" below).

**Revision 3, 2026-09-05.** The -00 text was fetched at 2026-09-04T20:38:30Z; -01 was posted at 20:38Z the
same day, the minute of that fetch, and -02 followed on 2026-09-05. The author read Revision 2 row by row
against -00 and named two cells that read the draft differently from what it says (`requestHash` in 3a, the
extract root in 3b) and three overtaken by -01 (`effectClass`, the Decider's chain, the missing media type).
Exactly those five were re-measured against -02, read from the draft itself:
`https://www.ietf.org/archive/id/draft-dogru-cedulon-decision-profile-02.txt`, fetched
2026-09-05T12:07:34Z, 72041 bytes, sha256 `0051d9924b4c4e98…`, 5 September 2026, expiring 9 March 2027.
Line numbers below for -02 refer to that text file. -01 (fetched 2026-09-05T11:55:36Z, 65797 bytes, sha256
`555d2fe2294670d4…`) was read for comparison: of the five, -02 tightens the wording of two (`requestHash`,
MUST-DP-9, its own "Changes from -01": "two sentences tightened after a reader's mapping") and leaves three
unchanged. Every other row stands as measured against -00; the author's reading says the rest is as written,
and the change logs of -01 and -02 list nothing that reaches another row except the one -02 statement noted
under Table 3c. -02 cites this page as `[B7N0DE]` (§8.1 lines 993–1001, reference lines 1405–1409, by the
URL of this file on `main`), which is why this file keeps its path and name.

### Table 3a — the Decision Record claim set (§4.1, all thirteen labels always present since -01; a twelve-label record is refused, -02 lines 373–377) against `decision-receipt/v0.1`

| claim (label) | our counterpart | meaning |
|---|---|---|
| `decider` (-70501) | `decisionMaker.id` (`decision.py:65`) | same |
| `subject` (-70502), opaque identifier of the requesting party | `principal.id` (`:67`); `agent.id` (`:66`) when the requester is the agent | similar |
| `requestHash` (-70503), SHA-256 of the evaluated request; the encoding is fixed by the draft (§4.1, -02 lines 398–402: *"The encoding is fixed: the canonical encoding of Section 7 of [CEDULON] when the request is a JSON document, and its UTF-8 octets when it is text. The request's fields are not fixed by this document, and a deployment MUST state what it hashes."*) | `proposedAction.parametersDigest` (`:69`), `inputSnapshot[].digest` (`:92`) | similar — the fields are open on both; the draft fixes the hashed encoding and ours does not, ours offers `parametersSchemaRef` (`:69-70`) as the place to state the fields. Revision 3: the earlier cell said neither format fixes the encoding, which is true of ours only; -02 tightened the sentence after this mapping |
| `policyHash` (-70504) | `policyBoundary.policyDigest` (`:73`, required in strict mode) | same |
| `inputsHash` (-70505), or null | `inputSnapshot[]`, one digest per input (`:92`) | similar — one hash over further context at theirs, one per input at ours |
| `decision` (-70506): `allow` / `deny` / `defer` | `decision.verdict` (`:33`): `ALLOW`; `DENY` or `REFUSE`; `DEFER` or `ESCALATE`; plus `OBSERVE` | similar |
| `reasonCode` (-70507), carried not interpreted | `decision.reasonCodes[]` (`:83`) | same, a list instead of one |
| `ref` (-70508), the channel reference under which the allowed effect will appear | `proposedAction.target.name` / `.uri` (`:70`) names the target of the action | different — ours names what is acted on, not the reference an effect will carry on a channel |
| `effectHash` (-70509), content hash of the effect the decider allowed; null on a refusal | — on the decision side | NO COUNTERPART — the decision-receipt carries no commitment to the content of the effect; `effectDigest` exists only on the executor's `action-outcome` (`outcome.py:45`) |
| `timestampMs` (-70510) | `decidedAt` (`:38`, RFC 3339 `Z`) | same |
| `nonce` (-70511), identifies the record | `decisionId` (`:38`); `validity.nonce` (`:88`) is a relying-party freshness nonce | similar |
| `prevRecordHash` (-70512), the Decider's chain | — | NO COUNTERPART — no per-decider chain; `relationships[]` edges are optional and typed (`relation.py:39`); `run-ledger` chains the runs of one study, not decisions |
| `effectClass` (-70513), the class of the allowed effect in the channel's vocabulary, required on an `allow`, carried and not measured on a refusal (§4.1 lines 418–425, §4.2 lines 461–468; new in -01, unchanged in -02) | — | NO COUNTERPART — `proposedAction.actionType` (`:69`) classes the proposed action, not the effect that occurred on a channel, and no verifier compares it with anything on the outcome side |
| epoch checkpoint totals per decision kind (§4.4) | — | NO COUNTERPART |

Count for 3a (13 claims since -01): same 4 · similar 4 · different 1 · NO COUNTERPART 4.

### Table 3b — the Effect Extract (§5.1) against `action-outcome/v0.1` with `execution_proven`

| draft element | our counterpart | meaning |
|---|---|---|
| extract body: `deciderId`, `channelId`, `windowStartMs`, `windowEndMs`; one decider, one channel, one window. The extract carries no media type, and since -01 the reason is restated (§5.2, -02 lines 700–706): *"which population a presented document belongs to is the verifier's call, made by the profile it applies and by the decider, channel, and window it declares (MUST-DP-1, MUST-DP-7), and never the document's. That declaration is the typed outer context a media type would otherwise supply."* The protected-header test of -00 is withdrawn as the reason | — | NO COUNTERPART — there is no population object; a `verification-summary` lists levels, not a window (`docs/predicates/README.md`). Our receipts carry their population in the predicate type and the subject, which is the document's own declaration, the opposite choice |
| row `ref`, the match key | `decisionRef.sha256` (`outcome.py:42`) is our match key | similar — both bind a row to a decision; theirs by channel reference, ours by the decision statement's content root |
| row `effectHash` | `effectDigest.sha256` / `actualActionDigest.sha256` (`:45`) | same in meaning; both sides must state the hashed octets, neither format fixes them |
| row `effectClass`, in the vocabulary the record's `effectClass` claim uses (§5.1 Table 4, -02 lines 630–632); a class that differs with the hash equal is `effect-class-mismatch` (§6.1 lines 755–762) | — | NO COUNTERPART — no class name on the outcome. Revision 3: -00 named the unbound class as its own gap D6; -01 closed D6 (§8.6, -02 lines 1072–1084) by putting the class under the Decider's signature, so the earlier note is out of date |
| row `timestampMs` | `performedAt` (`:43`) | same |
| row `actor`, optional | `receiverRefs[].receiverId` (`:50`, optional) | similar |
| extract signed by the effect-extract root, Ed25519 over the RFC 8785 body, key held out of band (§5.2, §7). MUST-DP-9 does not require that root to be independent of the decider root; it requires a statement plus a downgrade (§7, -02 lines 962–969): *"The rule is not that the two roots be independent; it is that the deployment say which case it is in, and that the guarantee fall when independence is absent or unknown. A deployment MUST state which of the two it has, and a verifier MUST treat the guarantee as conditional where the extract root and the decider root are, or may be, the same party (MUST-DP-9). The companion cannot measure that from the keys alone; two keys can be held by one hand."* | the outcome is DSSE-signed by the **executor**; `executor_role_trusted` against a Trust Pack role when supplied (`docs/predicates/action-outcome.md` §5.8); `role_separation_ok` (`outcome.py:617-618`) when both identities are supplied | similar — both hold the key outside the record; ours checks that executor and decision maker are different identities when it is told both, theirs asks the deployment to state which root it has and downgrades the guarantee where they may coincide, and neither can prove independence from keys alone. Revision 3: the earlier row described the strong form as the rule; -02 added the first sentence of the quotation after this mapping. Ours documents that a receipt about an effect is not an observation of it (`action-outcome.md` §7) |
| binding of an `allow` to a row with equal `effectHash` (§6.1) | `execution_proven` (`:647`) | similar — ours is digest presence on the executor's own record, self-asserted unless `receiverRefs` corroborate; theirs requires an independent row |

### Table 3c — the reconciliation rule (§6.1) against what our verifier checks between a decision and an outcome

| draft rule | our verifier | meaning |
|---|---|---|
| an `allow` and a row bind when `effectHash` is equal; a difference is `effect-mismatch` | no comparison between a decision's declared parameters and an outcome's effect digest exists; the outcome verify path (`outcome.py:493-833`) reads only the outcome predicate, and `decision_bound` (`:608-609`) compares `decisionRef` with a caller-supplied root | NO COUNTERPART |
| a row whose `effectClass` differs from the allow's with the hash equal: `effect-class-mismatch`, the fifth code since -01 (§6.1 -02 lines 755–762, Table 5 lines 879–882); the hash is compared first | no class on the outcome and no comparison (Table 3b) | NO COUNTERPART |
| an `allow` with no row: `decision-without-effect` | — a decision that no outcome cites is invisible to every verify path | NO COUNTERPART |
| a row with no record: `effect-without-decision` | an outcome whose `decisionRef` resolves to nothing: `decision_bound` stays `None` unless the caller supplies the expected root (`:608`) | similar, in the caller-supplied case only |
| a row whose `ref` a refusal names: `effect-against-refusal` (D1, §8.1). -02 cites the measurement in this cell as `[B7N0DE]` (§8.1 lines 993–1001: *"That is D1 as a verifying pair rather than a finding, recorded by the reader as a measurement of that artefact and cited here as one."*; reference lines 1405–1409) | **measured 2026-09-04 on proofbundle 5.1.0**: a decision-receipt with `verdict: DENY` and an action-outcome with `status: executed` citing it by content root verify with `ok: true`, exit 0, `decision_bound: true`, `role_separation_ok: true`, `execution_proven: true`, and no warning about the verdict; the verdict is never read on the outcome path | NO COUNTERPART |
| conservation counts published with the population (§6.2, MUST-DP-8) | — | NO COUNTERPART (see G4 above and the CAP-1 discussion there) |
| the Decider's chain names a break within one reader's population; a fork shown to two readers is the core's witness comparison, and a report over an unwitnessed chain claims no more (§4.4 -02 lines 543–569, §8.5 lines 1039–1070; -00 line 499 still called the chain the profile's equivocation control) | `run-ledger` is a local chain and says so since `6692561` (2026-09-04): a silently dropped run is detectable to a reader who holds this ledger, not to a reader shown another one; detecting that needs a witnessed checkpoint (`docs/predicates/run-ledger.md` lines 8–12, `SPEC.md` §7d) | similar — the same bound, stated on both sides; ours has no per-decider chain to walk (Table 3a) |

Finding name `effect-against-refusal`: **no** — no finding, reason code or test with that meaning exists at
ours (grep over `src/`, `docs/`, `README.md`, `SPEC.md` on 2026-09-04: the only `refusal` hits are
validator refusals of malformed input).

Count for 3c (6 rules of §6.1 and §6.2 since -01): same 0 · similar 1 · different 0 · NO COUNTERPART 5; the chain row from §4.4 is counted apart as similar. One statement new in -02 is not a row here and was not asked for: the binding does not order the two clocks (§6.1, -02 lines 807–816), a row dated before its record binds as if it had followed it; ours compares nothing between the two timestamps either, and that is recorded, not measured, in this revision.

### Verifying pairs on record

- Ours, measured 2026-09-04 with proofbundle 5.1.0 (Table 3c): a `decision-receipt` with `verdict: DENY` and an
  `action-outcome` with `status: executed` citing it by content root verify with `ok: true`. In the author's
  reading of 2026-09-05 this pair is exactly D1 of the profile (§8.1), recorded here as a verifying pair and not
  argued about; -02 cites it as `[B7N0DE]` (lines 993–1001 and 1405–1409).
- The author's, named for whoever writes an adapter: the frozen fixture two other readers have run,
  `interop/mizan-ig/fixtures/leaked-refusal` at `06c3119` in `dogrucanemek-alt/cedulon` (checked by API on
  2026-09-05: three files, `decisions.jsonl`, `policy.txt`, `sent.jsonl`; commit dated 2026-09-04T20:39:00Z),
  and the entry it sits in, `docs/EXTERNAL_REVIEW.md` Round 10 at `e26f50f` (heading "Round 10 — one fixture,
  two readers, 5 Sep 2026"; commit dated 2026-09-04T23:28:10Z). -02 §11 (lines 1278–1294) describes that run
  and its limits without naming the commits; the commits are the author's, from the mail of 2026-09-05. No
  adapter exists on our side and the fixture was not run here; the pins are recorded so that a later run has
  something to be measured against.
- **Kind: adapter-reproduction, measured 2026-09-05 on the frozen head `049b3195` of 6.0.0.** The pins above
  were used: `scripts/interop/cedulon_leaked_refusal_adapter.py` reads the three fixture files, refuses any
  bytes whose sha256 is not the pinned one, and translates the single decision line (`verdict: silent`,
  ref `leak-1`) and the single sent line under the same ref into a `decision-receipt/v0.1` and an
  `action-outcome/v0.1` with `execution_proven`, cell by cell after Tables 3a and 3b, with two throwaway
  test keys so that role separation is a real check. Seven cells fall on NICHT MESSBAR because those tables
  say NO COUNTERPART, and the adapter records them instead of inventing a value. Result: `decision verify`
  exit 0 (`CRYPTO: OK`, `STRUCTURE: OK`), `outcome verify --strict --expected-decision-ref … --decision-maker-id …`
  exit 0 with `ok: true`, `decision_bound: true`, `role_separation_ok: true`, `execution_proven: true`, and no
  field or warning of the twenty-one in the JSON result naming the bound decision's verdict. The same D1
  picture as our own pair of 2026-09-04, now on someone else's frozen bytes; the one reading the adapter adds,
  that this channel's `silent` is a refusal, rests on the companion's own reader reporting
  `effect-against-refusal` on this row (`EXTERNAL_REVIEW.md` Round 10 at `e26f50f`) and is recorded as an
  assumption in the adapter's report. The two other readers' verdicts are theirs and are not re-stated here.
- **Interop row, offered in the form used for a foreign implementation report, not sent anywhere.** Text as it
  would read: *"b7n0de, adapter reproduction. It wrote a third adapter for the frozen `leaked-refusal` fixture
  at `06c3119`, mapping the two lines onto its own signed decision and outcome predicates cell by cell against
  its published mapping, and measured its own verifier on the pair on 5 September 2026: the pair verifies
  clean, exit 0, with the bound decision carrying a refusal, because that verifier does not read the verdict on
  the outcome path. Prior art: none claimed."* Whether this row is offered to anyone is an owner decision and
  has not been taken.

### What a reader could do with our pair of receipts under the Cedulon profile, and what not

Can: verify that an executor signed an outcome that cites one specific decision statement by content root,
that the executor is not the decision maker when both identities are supplied, and that the outcome
carries an effect digest.

Negation list:

- It is not a Decision Record: no `ref`, no `effectHash` on the decision side, no `prevRecordHash`, no
  checkpoint totals, not COSE_Sign1, not `application/cedulon-decision-record+cbor`.
- It is not an Effect Extract: no decider, channel or window scope, no row list, no extract root.
- It is not a reconciliation: nothing on our side pairs the population of decisions with the population of
  effects; an effect against a refusal is not a finding here, it is a verifying pair (measured above).
- `execution_proven` is a self-asserted digest presence, which our own verifier labels as such; it is not an
  independent row.

### Which draft claims were checked at source, Mappings 2 to 4

| Claim | Draft | Section | Result |
|---|---|---|---|
| three content types, field lists and REQUIRED/OPTIONAL status | dawkins-00 | 3.1–3.3 | holds, read at source |
| validation step 6 requires the same deployer for human-review | dawkins-00 | 4.1 | holds |
| an Appendix A with a C2PA mapping exists | dawkins-00 | 1.3 | **not in the fetched text**; the document ends without an appendix |
| Permit minimum content | munoz-01 | 2 | holds |
| Closure digest equality is a MUST for verifiers | munoz-01 | 3.2, 3.6 | holds; the draft itself states the reference implementation copies the value rather than re-measuring (8.3) |
| no COSE_Sign1 emitted today | munoz-01 | 5, 11 | holds |
| twelve claims, labels -70501 to -70512 | dogru-00 | 4.1 | holds |
| an allow needs `ref` and `effectHash`, a refusal carries `effectHash` null | dogru-00 | 4.2 | holds |
| four new finding codes including `effect-against-refusal` | dogru-00 | 6.3 | holds |
| thirteen claims, labels -70501 to -70513, `effectClass` required on an allow, a twelve-label record refused | dogru-02 | 4.1, 4.2 | holds, read at source 2026-09-05 |
| five finding codes, `effect-class-mismatch` added, D6 closed | dogru-02 | 6.3, 8.6 | holds |
| the chain is no longer called the equivocation control; an unwitnessed chain claims no more than one reader's population | dogru-02 | 4.4, 8.5, Changes from -00 | holds |
| the request encoding is fixed, the fields are not; MUST-DP-9 is statement plus downgrade | dogru-02 | 4.1, 7, Changes from -01 | holds; both sentences tightened in -02 after this mapping |
| D1 cites this page as `[B7N0DE]` by the URL of this file on `main` | dogru-02 | 8.1, references | holds; the file keeps its path |
| override is a subsequent attested statement with a reference | list thread, 4 Sep 2026 | — | **NOT MEASURED** at source; taken from our order's wording |

### Honest limit of Mappings 2 to 4

These are field-level and rule-level correspondences read from three individual drafts against our code and
docs on one day. They confer nothing and certify nothing. A "similar" is a similarity of purpose, not of
bytes; a "NO COUNTERPART" is a fact about our artefacts on 2026-09-04, not a plan. The one measurement that
goes beyond reading, a `DENY` decision paired with an `executed` outcome verifying cleanly, is reproducible
with `proofbundle decision init|emit` and `proofbundle outcome init|emit|verify` on 5.1.0 and is recorded
here so that it cannot be mistaken for a rule the verifier enforces.
