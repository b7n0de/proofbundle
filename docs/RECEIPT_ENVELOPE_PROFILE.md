# Receipt envelope profile

Status: **DRAFT, house proposal.** Not standardized, not agreed with any second party, not published
anywhere but this repository. Nothing here changes the native receipt or what it proves — see
[NON_CLAIMS.md](NON_CLAIMS.md).

**Proposed identifier: `proofbundle/receipt-envelope-profile/v0.1`.**
The identifier is an **Owner decision** and is deliberately marked as such: it is proposed here, not
adopted. A name settles because citing it is easier than renaming it, not because it exists.

This profile is **a profile to a standard, not a format beside one.** IETF
[RFC 9943](https://www.rfc-editor.org/rfc/rfc9943) is the published SCITT architecture, and
`draft-mih-sokolov-scitt-payload-binding-02` (24 Aug 2026, individual submission, no standing in the
IETF process) sits on top of it. R1 to R4 are stated **against** that draft, by reference. R5 and R6
are our addition, and they exist because the draft says in its own section 1.1 that it does not
cover them.

## The one sentence everything follows from

**A reported field is the report of a check that was carried out.** If a verifier reports
`binding_checked`, it checked that binding. If it reports `valid`, it did so against the schema the
receipt names. What was not checked is not reported, not even in a weakened form.

## R1 — one normative canonicalization

RFC 8785, one serializer, pinned in the schema. Both sides compute the same `content_id` before any
signature is checked. The serializer is reached through a public interface, not a private module.

**Counter-proof.** The three divergence vectors from the issue thread: UTF-16 key ordering over the
pair U+1F600 and U+FFFF, `1e-7`, and the integer `2`. Each must produce a differing `content_id`
under a non-conformant canonicalization and must turn the check red.

**Two of those three cannot arise in this format, and saying so is part of the rule.** Measured
2026-08-30: the claim profile refuses Python floats outright (`_reject_non_jcs`) and requires decimal
STRINGS, so `1e-7` and `2.0` never reach a serializer here. A byte-comparison vector for them would
be theatre — it would compare two renderings of a value this format does not accept. **The honest
counter-proof for those two axes is the refusal itself**, and it ships as one: both objects must be
refused, and a planted defect that accepts a float turns the case red with the serialized value
printed. So R1 is carried by three vectors, not one: the ordering-and-escaping divergence (a single
object that gets *both* wrong under a non-conformant serializer), the refusal, and a positive
control. The two axes are **removed rather than resolved**, which is a weaker claim than resolving
them and the true one.

**Provenance.** Measured 2026-08-26 and corrected 2026-08-28 against `inspect-receipts@397ae3ad`;
basis `office/handoff_journal/20260828T104501Z`. The first pass reported "no finding" and was wrong
because it measured `jcs.canonicalize` and `rfc8785.dumps` rather than the alias that signing and
verification actually run. That alias builds `JSONEncoder(sort_keys=True, ensure_ascii=True, …)`, so
non-ASCII is escaped to `\uXXXX` while RFC 8785 emits raw UTF-8 outside the mandatory escapes. The
divergence is string escaping alone; ordering and numbers are RFC-8785-correct and the UTF-16 key
sort holds. ASCII-only receipts stay identical, `{"café":1}` does not. The three vectors in the
thread do not isolate escaping, which is how the first pass missed it.

## R2 — the schema id is read

The verifier reads `schema` and decides before it checks anything else. If it does not know the
schema id, it refuses to answer. It does not fall back to best effort and it does not ignore the
field.

The refusal is **its own outcome, not `invalid`.** A consumer must be able to distinguish *this
receipt is invalid* from *I cannot judge this receipt.*

**Counter-proof.** An otherwise valid receipt carrying a foreign schema id. Refusal is expected.

**Provenance.** Measured 2026-08-26 against `inspect-receipts@397ae3ad`: the same probe returns
`valid=True`.

**Carried since 2026-08-30, and it was the third one.** Measured on our own path first:
`decode_eval_claim` returned `None` for a foreign schema id AND for a broken receipt — the same
collapse of the two outcomes that this rule exists against. That contract is released and callers
depend on it, so it is unchanged; `classify_eval_claim` adds the distinction as a new function.
**The ordering is part of the rule:** authenticity is decided FIRST, because a broken signature *is*
judgeable and answering "I cannot judge this" would let a forger buy silence by renaming the schema
field. That ordering was documented and unproven until a planted defect removing it left the whole
corpus green; the vector that discriminates it exists because the meta-test found the hole, not
because writing the vectors found it.

## R3 — a reported binding is a binding that was performed

`binding_checked` is set only when the binding was complete. A binding of type content-hash without
the digest it is supposed to bind is not a binding but an empty declaration, and it fails closed.

A verifier that ran a weaker check never reports the stronger one. It may **reject** a stronger
binding; that is permitted and honest.

**Counter-proof.** `{"type": "content-hash", "digest_alg": "sha256"}` without `eval_log_sha256`
while the receipt carries that field. Fail-closed is expected.

**Provenance.** Measured 2026-08-26 against `inspect-receipts@397ae3ad`: the same probe returns
`valid=True, binding_checked=content-hash`.

## R4 — key resolution fails closed

An unresolvable `kid` is invalid, not valid-with-reservation. A key shipped inside the receipt alone
never carries a `valid=True`.

**Counter-proof.** Three cases: no anchor, unknown kid, embedded key differs from the published one.
All three must come out invalid.

**Provenance.** Measured 2026-08-26 against `inspect-receipts@397ae3ad`: holds in all three cases.

## R5 — coverage does not follow from integrity

The envelope carries what the receipt examined, not only that it is unaltered. Three numbers are
enough and they are machine-readable.

```
population_size    how large was the set that should have been examined
evaluated_count    how many of them were examined
unresolved_count   how many remained open
```

Without these three, a receipt that verifies cleanly and whose scope never contained the operation
in question is indistinguishable from one that contained it and found nothing.

**Counter-proof.** Two receipts, both cryptographically clean, one with
`evaluated_count == population_size`, one with `population_size == 0`. A consumer must be able to
tell them apart without opening the subject.

**Provenance.** The idea is not ours. It surfaced 2026-08-26 in the OpenTelemetry thread on
`semantic-conventions-genai` issue 470, as a proposed non-goal "No coverage claim". We measured the
same failure class in our own gates on the same day, one level down. `draft-mih-sokolov-scitt-payload-binding-02`
likewise does not cover coverage, which is why R5 is stated here rather than by reference.

**Carried since 2026-08-30.** Until that date R5 was a rule we asked of others and did not carry
ourselves: measured across all nine schemas, none of the three fields appeared. The optional
`coverage` block on the eval claim now carries them — optional as a whole, complete when present,
with `evaluated_count` bound to the claim's existing `n` so the same quantity does not acquire a
second, free-floating number. Enforced on build, emit **and** verify from one definition;
`tests/test_eval_claim_coverage.py`. **Honest limit:** these are issuer-DECLARED counts. The
signature makes them tamper-evident and attributable; it does not make them correct.

## R6 — every rule brings its own counter-proof

Whoever claims this profile ships the executable counter-proofs for R1 to R5, plus one positive
control each. Detection rate 100 percent, otherwise the profile counts as unmet.

A profile without shipped counter-proofs is a statement of intent.

**Shipped since 2026-08-30.** `conformance/envelope_profile/` — twelve vectors, at least one
counter-proof and one positive control per rule R1 to R5, all running through our own emit and verify
path rather than a purpose-built mock. Detection rate is MEASURED, not asserted: eight planted
defects, eight caught. THREE of them initially escaped, and each escape bought a vector that had been
missing — the authenticity ordering under R2, a hand-signed coverage block under R5, and R1's second
and third divergence axes, which the shipped counter-proof did not cover although this document
claimed all three. A fourth planted defect turned out to be ineffective rather than escaped (removing
the float branch left the value refused by the next clause anyway); it was replaced with one that
mutates the property instead of the message. **An escaped defect is worth more than a caught one
here** — the caught ones confirm what was already believed, the escaped ones name what was not. R6 has no vector of its
own on purpose: a case asserting "the cases exist" would be the tautology this rule warns about.

**Provenance.** House governance rule, first written in the 2026-08-26 draft. It has **no external
source**, and we do not claim one. Its standing against us is recorded: at the time of writing this
page our own `mutation` gate is not green, which is precisely the state R6 declares unmet.

## What this profile deliberately does NOT say

```
no mandated signature algorithm
no mandated trust anchor; did:web and trust-anchor stay the issuer's choice
no mandated time anchor
no field for honesty or for the quality of an evaluation
no shared file extension and no shared media type
```

The envelope governs what a verifier may **say**. It does not govern whom to believe.

**Anchor neutrality is an Owner decision and a red line, not a bargaining position.** A shared format
carrying a foreign did:web root as its default is not supported. The anchor is a field of the issuer,
never a property of the format. This applies to our own anchor as well.

**The profile creates no certifying authority.** Conformance is demonstrated, not conferred. No party
certifies it to another, and no party is appointed to judge another's conformance. Whoever claims the
profile runs the counter-proofs and publishes the result. *(Owner decision 2026-08-30; wording
submitted for approval.)*

## Relationship to RFC 9943 and the SCITT payload-binding draft

Read clause by clause in [SCITT_CPB_MAPPING.md](SCITT_CPB_MAPPING.md). Summary, nothing asserted here
that is not measured there:

| Rule | Relation to the draft |
|---|---|
| R1 | **congruent** — the draft's canonicalization registry entry `jcs` is plain RFC 8785 JCS, SHA-256, lowercase hex. Our behaviour matches; our token is `jcs-sha256-v1`. A mapping question, not a contradiction. |
| R2 | **congruent** — the draft requires a verifier to distinguish "type in no registry" from "not in my copy"; that is R2's separate outcome. |
| R3 | **congruent since 2026-08-30, additively** — the draft requires `type`, `digest_alg`, `digest` as mandatory and `purpose` conditionally. The optional `typedDigest` on `evidenceRefs[]` carries that shape (`digestAlgorithm` for `digest_alg`, see the mapping). It adds to the existing `digest`, which stays required and unchanged. Correction to this table's first pass: the conformant shape already existed in the same schema as `relationDigest`; the gap was internal inconsistency, not absence. |
| R4 | **addition** — the draft requires only that the protected header carry `kid` or `x5chain`. Resolution, trust anchors and fail-closed do not appear in it. |
| R5 | **addition** — coverage does not appear in the draft at all. |
| R6 | **addition** — a governance rule; it appears in neither document. |

**One divergence is declared here rather than changed.** Our bundle passes the *payload* as Merkle
leaf input (`src/proofbundle/bundle.py`, `merkle.leaf_hash(payload)`), while the draft's section 7.1
requires `leaf_input = bytes.fromhex(D)` for a 64-character hex identifier `D`, i.e. the raw 32
bytes. Both are RFC 6962-correct leaf hashing; they are two different constructions. A verifier
following the draft computes a different leaf over our bundle. **We declare the choice instead of
rebuilding it:** a rebuild would void every receipt already issued, and the draft's own requirement
is that a class declares its choice so a verifier does not have to guess.

## How to cite this profile

```
Receipt envelope profile
Identifier: proofbundle/receipt-envelope-profile/v0.1   (proposed; Owner decision pending)
Version:    0.1
Repository: https://github.com/b7n0de/proofbundle
File:       docs/RECEIPT_ENVELOPE_PROFILE.md
Retrieved:  <date you read it>
```

No DOI field appears until a deposit exists. There is no placeholder that looks like an identifier
and no invented number.

## Version rule

A change to a normative rule raises the version; older versions stay readable and are not
overwritten. A version without a rule for how it changes is half a version.
