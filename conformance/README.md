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
independent implementation**, checked for cross-implementation agreement:

- `.jcs` bytes are byte-identical with proofbundle's RFC 8785 canonical output;
- both content roots (`statement_content_root`, jcs-sha256-v1) recompute to the `MANIFEST.json`
  values and to `expected`;
- `decision.evidenceRefs[*].digest` binds the evidence **content root**;
- `validate_decision_predicate` returns exactly `expected.decision_predicate_findings` (an
  expected-fail when the external predicate does not yet match `decision-receipt/v0.1`);
- the OpenTimestamps anchor, when present, resolves to the expected status offline
  (`confirmed` against a frozen merkle root, or `pending`). The verifier rejects a wrong
  frozen root (`block_mismatch`), so confirmation is not a blind pass — that negative is
  exercised by `tests/test_anchors_ots.py`; the corpus itself runs the positive check.

### `native_bundle`

A native proofbundle bundle checked against the CLI **verify exit-code contract**
(`0` crypto OK · `1` verification failure · `2` malformed · `3` policy unmet). The exit code is
the conformance contract, so each case declares the exact code it must produce; the fail-closed
floor requires a `native_bundle` case to declare `exitCode`. These lock core verifier properties
onto the gate — a valid bundle verifies, a **duplicate JSON key** is rejected as malformed (the C1
Bishop-Fox parser-differential defense), a single flipped payload byte fails the signature.

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

## Adding a case

Never edit an accepted vector's bytes in place — a fixture change must be a new case (or an
explicit, reviewed re-pin), so accepted expectations cannot drift silently. Add the directory,
its `case.json`, and a line in `manifest.json`.
