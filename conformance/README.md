# proofbundle conformance corpus

Versioned, digest-pinned test vectors that a proofbundle verifier (this one, or an
independent implementation) must agree on. Every case is verified **offline** by
`run_conformance.py`: no calendar contact, no network — the specific Bitcoin block
**merkle root** a case needs is frozen inside its `case.json`, independently sourced and
byte-reproducible.

Run it:

```bash
make conformance                       # skips anchor sub-checks if opentimestamps is absent
python conformance/run_conformance.py --require-anchors   # full run (needs the [anchors] extra)
```

The summary reports the **executed scope**, not a pass ratio. The shape, with placeholders rather
than a snapshot of one branch's case count — a number printed here goes stale the moment the corpus
grows, and a stale example is exactly the quotable half-truth rule 7 exists against:

```
[conformance] <N> cases · <full> fully checked · <partial> partially checked · <not run> not run · <failed> failed
  <k> check(s) in <m> case(s) did NOT run in this environment:
    - <caseId>: <why this check could not run here>
    to execute them: pip install -e '.[anchors]' && python conformance/run_conformance.py --require-anchors
```

A case that did not run is labelled `NOT RUN`, one whose anchor sub-check skipped is `PARTIAL`.
Neither is ever counted as a pass. `scope` and `skipped` bind each other in both directions: only a
fully checked case may name no skip, and anything else must name what it skipped — which is what
makes the disclosure hold for any missing optional dependency, not just for `opentimestamps`.
See CONFORMANCE.md rule 7.

## Case format

`manifest.json` lists case directories. Each holds a `case.json`:

```
{caseId, kind, input, expected: {...}, specRefs[], rationale, attribution}
```

`expected` is the whole point of the corpus: a case declares what it proves **and what it
does not**. A green run therefore never overclaims — a case that is canonicalization-correct
but not schema-conformant records the exact finding count as an *expected-fail*, it does not
hide it.

## Kinds

### `decision_crossimpl`

A decision-receipt statement pair (decision + referenced evidence) produced by a **second,
independent implementation**, checked for cross-implementation agreement. A case directory holds the two
in-toto Statements `decision_receipt.json` and `evidence_eval_result.json`, their `.jcs` bytes, the
producer's `MANIFEST.json` and, when anchored, the OpenTimestamps proof `decision_receipt.jcs.ots`. The
axes:

- `jcs_byte_identical`: each `.jcs` file is byte-identical with the RFC 8785 bytes of its `.json`
  Statement;
- `decision_content_root`, `evidence_content_root`: the `jcs-sha256-v1` content roots of the two
  Statements (ADR 0002), 64 lowercase hex; `content_roots_match_manifest`: they equal
  `decision_content_root_sha256` and `evidence_content_root_sha256` of `MANIFEST.json`;
- `evidence_ref_binds_content_root`: at least one `predicate.evidenceRefs[].digest.sha256` of the
  decision equals the evidence content root (`docs/predicates/decision-receipt.md` §3);
- `decision_predicate_findings`: the number of findings of the default-mode validation of the decision's
  predicate (`docs/predicates/decision-receipt.md` §6, *Default mode*; an expected-fail when the external
  predicate does not yet match `decision-receipt/v0.1`), and `schema_conformant`: whether that number is 0;
- `anchor`, when the case ships a proof: the verdict of `decision_receipt.jcs.ots` against the SHA-256 of
  `decision_receipt.jcs` (`docs/ANCHORS.md`, *The proof format and the verdict, exactly*), with the
  relying-party header the case supplies in `anchor.rpTrust.bitcoinBlockHeaderMerkleRootsByHeight`; that
  header is an input, and `anchor.frozen` is producer evidence that never enters the verdict. The value is
  the status, `confirmed` or `pending`. A confirmation is not a blind pass: a wrong relying-party root gives
  `block_mismatch`, a negative exercised by `tests/test_anchors_ots.py`; the corpus itself runs the
  positive check.

### `native_bundle`

A native proofbundle bundle checked against the CLI **verify exit-code contract**
(`0` crypto OK · `1` verification failure · `2` malformed · `3` policy unmet). The exit code is
the conformance contract, so each case declares the exact code it must produce; the fail-closed
floor requires a `native_bundle` case to declare `exitCode`. A verifier reports `rejected` as `true`
exactly when its verify exit code is not `0`, so an exit `3` (a relying-party gate unmet over a
crypto-OK bundle) is a rejection; a case that declares `rejected` holds when that value equals the
declared one, which pins the exit contract a second time. These lock core verifier properties
onto the gate — a valid bundle verifies, a **duplicate JSON key** is rejected as malformed (the C1
Bishop-Fox parser-differential defense), a single flipped payload byte fails the signature.

### `agent_review_predicate`

Agent-review vectors (`agent_review/`) are read against `docs/AGENT_REVIEW_PREDICATE.md` and
`docs/VERIFIER_BLOCK.md`. The corpus test key is the Ed25519 key with the 32 seed bytes 0x00, 0x01, …,
0x1f; it must never sign anything a reader takes as evidence, and its raw public key, hex-encoded, is
`agent_review/publickey.hex`. To *issue* a predicate is to build its in-toto Statement, refuse it when it
breaks a rule of its version, and sign it as a DSSE envelope with the corpus key; to *verify as* a version
is that version's verification under the corpus public key. A case reads only its own `input`, and its one
axis decides the use:

- `classification`, input `predicate.json`: the version is the case's `predicateVersion`, `v0.1` when it
  names none; a `v0.2` predicate that carries `producer.verifier` is a `v0.3` predicate. A predicate that
  breaks a rule of its version is `refused`. Otherwise it is issued and verified as its version, with the
  predicate's own subject digest as the expected subject digest and, for `v0.2` and `v0.3`, the default
  policy `agent_review/policies/default_v1.json`; it is `valid` when that verification is ok, else `invalid`.
- `classification`, input `body.json`: `refused` when the body core digest of the file's `body` cannot be
  computed (a malformed or duplicated disclosure block), else `valid`.
- `classification`, input `envelope.json`: the envelope is verified as `v0.1`, with `params.expectedSubjectDigest`
  as the expected subject digest when the case gives one; `valid` when ok, else `invalid`.
- `bodyCoreStable`: the input holds `bodyBefore` and `bodyAfter`; the value is true exactly when both have
  the same body core digest.
- `subjectExpectation`: the envelope is verified as `v0.1` without an expected subject digest; the value is
  the reported subject expectation, and an absent expectation is reported as a warning that names
  `expected_subject_digest`.
- `currentReceipt`, `chainIntegrity`, `unverifiedSupersessionClaim`: the input holds `envelopes`; each is
  verified as `v0.1`, the receipt digests of those whose signature verifies form the verified set, and the
  receipt chain of all envelopes is resolved with that set: `currentReceipt` is the receipt digest of the
  current receipt, 64 lowercase hex, or `null` when there is none; `chainIntegrity` is a boolean, `false`
  when the chain's integrity fails. For `unverifiedSupersessionClaim` a verifier reports two lists of
  receipt digests, each empty when there is none: under `unverifiedSupersessionClaim` the unverified
  supersession claims, and under `correctedReceipts` the receipts marked corrected: each digest once, in
  any order, that an envelope in the verified set names as `priorDigest` under `supersedes`, `corrects` or
  `withdraws`, also a digest that no envelope of the input has (`docs/AGENT_REVIEW_PREDICATE.md`,
  *Supersession*). The axis holds when the receipt digest the vector names is in the first list and the
  second list is empty.
- `versionStatus`: the envelope goes through the version dispatcher with `params.expectedSubjectDigest` when
  given; the value is its `predicateVersionStatus` (`legacy`, `current` or `unknown`). `legacy` carries
  `AGENT_REVIEW_LEGACY_V01` as an advisory code, never as a reason code, with the same `ok` the `v0.1`
  verification gives; `current` never carries it; `unknown` is not ok and carries
  `AGENT_REVIEW_PREDICATE_TYPE_UNKNOWN` as a reason code.
- `policyDecision`: a `v0.2` or `v0.3` case; the predicate is issued and verified as its version with its own
  subject digest and the policy `params.policy` names: `default`, or no value, is the default policy, `none`
  is no policy, any other value is that file in the case directory. The value is the policy decision:
  `accept`, `reject`, `insufficient_evidence`, or `null` without a policy. `null` carries `POLICY_NOT_EVALUATED`
  as an advisory code and not as a reason code; every other decision reports the digest of its policy;
  `accept` comes with ok, `reject` and `insufficient_evidence` without.

### `cap1_document`

A coverage-attestation document of `draft-hillier-coverage-attestation-00` (profile `cap/1`),
checked through `proofbundle.cap1`. The single axis is `expected.cap1Rules`: the exact set of rule
ids (R0 to R8) that must fire, `[]` for a conformant document. A verifier reports the rules that fire,
each by its id as the corpus writes it: `R0-shape`, `R1-no-silent-remainder`, `R2-closed-disposition`,
`R3-withholding-digest-bound`, `R4-denominator-basis`, `R5-counts-well-formed`, `R6-absence-is-scoped`,
`R7-incomplete-not-clean`, `R8-supports-bounds-citation`; the axis holds when that set equals
`expected.cap1Rules`. The fifteen cases under
`conformance/cap1/` are the draft author's own vectors (PV-01 to PV-05, NC-01 to NC-10; Apache-2.0,
`conformance/cap1/vectors/LICENSE.author`), and the expected sets come from the author's recorded
conformance run, including NC-05 firing R1 and R5 together. They are generated by
`conformance/cap1/_generator/build_cases.py`; a test keeps the generated bytes and the committed
ones identical. The draft's text is vendored byte for byte as
`conformance/cap1/draft-hillier-coverage-attestation-00.txt`, under CC BY 4.0 (SPEC.md §7l).

The members the rules read and their forms are those of the draft's JSON Schema, vendored as
`conformance/cap1/CAP-1.schema.json` (SPEC.md §7l): `subject` with `ref`; `strata`, each with `id`, `basis`
(`kind`, `catalogue_digest`, `enumeration_method`), `eligible`, `examined`, `unexamined` (each entry with `unit`,
`disposition`, `withheld_digest`) and `supports`; `absence_assertions`, each with `stratum`; and `integrity` with
`complete` and `capped_to`. A verifier judges the rules R0 to R8 and nothing else of the schema: a part of it that
no rule reads (an unknown member, a missing `population`, `statement` or `assertion`, the pattern of a stratum
`id`, `subject.kind`, `subject.digest`) fires no rule. Where the draft's prose leaves a form open, the corpus reads
the schema's, outside the fifteen cases as well: a `withheld_digest` or `catalogue_digest` that is not 32 to 128
lowercase hexadecimal characters fires R3 or R4; a stratum whose `unexamined` is missing or not an array fires R1;
an entry of `unexamined` without a non-empty string `unit` fires R2 and is not an accounted unit of R1; a `subject`
that is not an object with a non-empty string `ref` fires R0; an `absence_assertions` that is present and not an
array of objects fires R6; and a `capped_to` that is `null` or empty states no verdict, so it fires R7 when
`complete` is false.

Every rule is judged on every document on its own, and the set holds every rule the document breaks, so one
document can fire several rules; a document that is not a JSON object fires R0 alone. For R1 the accounted units of
a stratum are the distinct non-empty strings its `unexamined` entries name as `unit`, whatever R2 and R3 judge of an
entry's disposition or digest; a unit named twice counts once and fires R1; when `eligible` and `examined` are both
integers, `eligible` must equal `examined` plus the number of accounted units. R8 is judged only for a stratum that
exists and that an absence assertion names as its `stratum`: its `supports` must be a non-empty array of strings
that are neither empty nor white space; an absence assertion that names no existing stratum fires R6 alone.

## Cases today

| caseId | proves | does NOT prove |
|---|---|---|
| `decision-crossimpl-schema-conformant` | **full end-to-end `decision-receipt/v0.1` conformance cross-impl**: RFC 8785 canonicalization + content-root binding, the predicate validates clean in NORMAL **and** STRICT mode (0 findings), **and** a confirmed Bitcoin anchor at block 958761 (OTS-committed root matches the real block merkle root, independently fetched from blockstream.info + blockchain.info, verified offline) | that the decision was *correct* — the anchor fixes existence and evidence binding, never correctness |
| `decision-crossimpl-confirmed-anchor-lifecycle` | RFC 8785 canonicalization + content-root binding cross-impl, **and** a confirmed Bitcoin anchor at block 957504 (OTS proof committed root matches the real block merkle root, independently fetched, verified offline) | `decision-receipt/v0.1` schema conformance (predicate reports 12 findings) |
| `decision-crossimpl-canonicalization-root-binding` *(historical — superseded by `decision-crossimpl-schema-conformant`)* | RFC 8785 canonicalization + content-root binding cross-impl | schema conformance (12 findings, expected-fail) **and** a confirmed anchor (still pending) |

All three vectors are contributed by MarkovianProtocol / Colin (audit-anchor), vendored digest-pinned
as pure data, credited (MIT / SigmaSynth LLC). The gap between "canonicalization proven" and "full v0.1
conformance", recorded in `audit_artifacts/crossimpl_fixture_gap_20260711.md`, is now closed: **full
decision-receipt/v0.1 conformance: done (graduated 2026-07-19, block 958761)** with
`decision-crossimpl-schema-conformant`. The canonicalization-only iteration is retained as a historical
case (CONFORMANCE.md rule 5, no silent changes: a regeneration is a new case, the old one kept, so its
historical green run stays reproducible).

### `decision_relation`, `outcome_relation`, `relation_statement`

Relation vectors (`relation/`) run the `decision verify`, `outcome verify` or `relation-statement
verify` path of SPEC.md §7j and §7k on `input`, with `--pub` read from the file named by `pub`, one
`--with-related` per entry of `related` (each followed by `--related-pub` with the key at the same
position of `relatedPubs`, when given), and `--policy` when `policy` is given. A `decision_relation`
case is evaluated at the receipt's own `predicate.recordedAt` (else `decidedAt`) as
`--verification-time`, so a fixed-date `validity.expiresAt` in a fixture cannot move the verdict as
the wall clock advances. `exitCode` is the CLI exit contract; `lineage` is the reported lineage
state, where `null` and `NOT_EVALUATED` are the same observation; `errorContains` holds when the
string occurs in the verifier's JSON report or its error output.

### `content_root_vector`

Action-chain content-root vectors (`action_chain_content_roots/`, Phase 1 / R51): language-neutral
golden pins for the ONE statement content-root primitive (ADR 0002, `jcs-sha256-v1`). Four modes —
`canonical` (pinned .jcs bytes + root on both sides of the two-part rule), `pair_reference`
(a decision binds an evidence statement by its root: at least one `predicate.evidenceRefs[].digest.sha256`
of the decision equals the evidence content root, see `docs/predicates/decision-receipt.md` §3; the
`*JcsFile` and `secondEnvelope` members of `expected` name fixtures and are not compared), `binding` (algorithm confusion rejected,
named legacy `legacy-sortkeys-json-v0` accepted when undeclared; the declaration is the top-level
`contentRootAlg` of the payload, `expected.alg` is the algorithm the payload was judged under, and
`expected.bindingOk` is whether the payload bytes equal that algorithm's serialization, both as
defined in [ADR 0002](../docs/adr/0002-universal-content-root.md) §Activation), `envelope_invariance` (signature
blocks never move the root). Honest scope: these pins are **generated by this implementation**; the
Rust verifier `pb_verify_rs` recomputes the ten pinned roots through its `content-root` subcommand
(`tools/pb_verify_rs/crosscheck.py`), and the two `binding` vectors pin a verdict of the Python binding
that has no Rust subcommand, so they are Python-only.
Catch proofs: `tests/test_conformance_content_root_vectors.py`.

## Adding a case

Never edit an accepted vector's bytes in place — a fixture change must be a new case (or an
explicit, reviewed re-pin), so accepted expectations cannot drift silently. Add the directory,
its `case.json`, and a line in `manifest.json`.
