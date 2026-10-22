# Independent reading of draft-abak-agent-control-delivery-evidence-02

This directory holds an implementation of the verification side of
draft-abak-agent-control-delivery-evidence-02, derived from the text of that draft alone, together
with the requirement table it was built from, derived test vectors and a run record. It is an
interoperability exercise. It is not part of the proofbundle library, it defines no proofbundle
format, and proofbundle does not adopt the draft's representation as its own.

Release 0.1.0 of this reader followed revision -01 (SHA-256
`2f0356fcb834ba6b80970721273cd8e2e0b2cc19ef1f89a0205a78991653fabf`, 2576 lines). Section 12 of
-02 cites that release at commit `19c3b0b909639d2b6e4cfff04d9434c878be3616`; that commit stays as
it was. Release 0.2.0, in this directory now, follows -02. The directory keeps its name.

## Input, and what was not used

The only normative input is the plain-text rendering of revision -02:

- source: https://www.ietf.org/archive/id/draft-abak-agent-control-delivery-evidence-02.txt
- form: txt, 2856 lines, 123860 bytes
- SHA-256: `fe3baeb08c8e0979ca64efece098c972827fab483debe0b2bcbfd697bb714782`

Every line number in this directory refers to that copy. The copy itself is not stored here;
`tools/extract_requirements.py` refuses any other bytes. Revision -01 was read again only to list
the changes.

Not read and not used: the AIREP repository and its evidence records, the phionyx-research probe,
the ACDER probe, the contributed EMILIA fixture itself, the Cedulon probes and case drivers, the
author-side regression suite RT-01 to RT-14 that Section 14 mentions, any vectors or expected results
of the author, and any correspondence or other interpretation. The draft's own appendices (the
illustrative record, the fixture summary and the Minimum Conformance Cases) are part of the text and
were read as such. Where the text allows more than one reading, the readings considered and the one
implemented are written down below and in `requirements_map.json`; no ambiguity was resolved by
looking at another implementation.

## What was derived

1. `requirements.json`, `REQUIREMENTS.md`: every sentence that carries a BCP 14 key word in upper
   case, outside Section 1.2 and the references, with section and line range. 161 sentences;
   key-word occurrences MUST 97, MUST NOT 53, SHOULD 16, SHOULD NOT 1, MAY 20.
2. `acde01/`: the verification side, Python standard library only.
   - `profile.py`: the declarations the draft leaves to "the applicable protocol or profile",
     each checked. New for -02: the frozen positive FAIL conditions, the permitted inputs of the
     exclusion rules, a version and a reason for every exclusion rule, whether an all-target
     exclusion may be covered by a structural PASS, and the resolution classes of Section 5.12.
   - `reconcile.py`: one bounded run following the twelve steps of Section 6.3. Target resolution
     from frozen inputs gives C_i, E_i and T_i per instruction before any record is read; an
     unclosed resolution goes to the class `target_resolution_unclosed` with its reason and creates
     no obligation; dispatch is `DISPATCHED` or `NOT_ESTABLISHED`; FAIL comes only from a disposition
     the profile names as a positive condition.
   - `report_check.py`: checks a report without its inputs, and checks a text rendering for the
     co-exposure of claim scope and claim support.
3. `vectors/acde01_vectors.json`: 198 derived vectors, each naming the requirement ids it tests,
   its polarity, the Minimum Conformance Case of -02 it exercises, and the expected result. Every
   one of the 30 cases has at least one vector. `vectors/build.py` writes them;
   `vectors/generate_vectors.py --check` confirms the committed file equals a fresh generation.
4. `tests/check_abak02_changes.py`: one test per rule that changed from -01 to -02. 26 of them
   failed on the 0.1.0 reader before the change; 4 name a -02 rule the 0.1.0 reader already met.
5. `run_record.json`, `RUN_RECORD.md`: the command, the head, the environment, the digest of every
   input file, and per requirement its category and the vectors behind it.

## What changed from -01 to -02, and what the reader does now

Sentence by sentence: 112 requirement sentences are unchanged, 11 changed, 7 left the text and 38
are new. The rules that change what a verifier does:

| section | -02 rule | reader 0.2.0 |
|---|---|---|
| 2, 4.2, 5.1 | one base obligation per instruction and required target; attempts are lossless subaccounting; a later success does not erase an earlier failed attempt | as in 0.1.0; each obligation now lists every attempt that carries evidence, and the report check refuses a second obligation for one pair or an attempt dropped from that list |
| 4.2, 5.10, 5.11, 6.4 | frozen, versioned exclusion rules over permitted issuer-side or target-resolution inputs; C_i, E_i, T_i; every excluded candidate with reason, version and count; exclusion-induced zero is not terminal-empty | target-level exclusions added; every exclusion carries rule, version and reason; zero-obligation instructions say `terminal_empty` or `exclusion_induced`; an exclusion-induced zero blocks PASS unless the profile permits it |
| 5.4 | missing issuer observation is dispatch `NOT_ESTABLISHED`, obligation INDETERMINATE by default, never dispatched=false; a failed emission fans out only where attempt, target and boundary are bound | `dispatched` (Boolean) replaced by `dispatch`; the receiver fact stays correlated, not orphan; an unscoped failed emission stays an instruction diagnostic; a bound one is EXPLICIT_FAILURE for its target only |
| 5.8, 9.1 | deadline elapsed leaves UNCONFIRMED with a diagnostic | as in 0.1.0 |
| 5.10, 6.1 | SUBSTITUTION covers issuer-issuer reuse within one uniqueness scope, with the records visible; equal strings from distinct scopes are not merged | the substitution diagnostic names its records; an optional `identifier_scope` keeps scopes apart |
| 5.11, 6.1, 6.4 | each receiver record has one primary class; matched means correlated, not CONFIRMED; ORPHAN only without any correlatable obligation | a receiver record of an attempt the issuer never emitted is now matched (non-confirming), not orphan; the report check compares the counts with the class of every record |
| 5.11, 6.4 | `target_resolution_unclosed` is the third instruction class; |I| = with + zero + unclosed | the class replaces `not_closed`; no obligations for such an instruction; one instruction equation |
| 5.12 | unresolved, ambiguous and stale references are INDETERMINATE; malformed or missing binding INVALID; irreconcilable CONFLICT | the profile can no longer map unresolved, ambiguous or stale to INVALID |
| 6.2 | a terminal empty set gives NOT_APPLICABLE or absent parent confirmation | as in 0.1.0 (`null`) |
| 6.5 | the positive FAIL conditions are published and frozen by the profile; no universal mapping | `fail_conditions` in the profile; SUBSTITUTION is FAIL only where the profile says so |
| 6.6 | the default claim is the minimal structural statement under the named profile, cutoff and rules | the default claim scope names the profile; zero-obligation instructions appear in every claim scope with their cause |

One defect of the 0.1.0 reader that is not a change of the draft was found while reading: an
emission recorded at a boundary other than the declared issuer boundary counted as dispatch
(Sections 4.1 and 5.4, the same in -01). It no longer does.

## What was found

Per requirement sentence: agreement 145, contradiction 0, ambiguity 4, not implemented 12.

All fourteen ambiguities found in -01 are settled by the text of -02. The four open in -02, with
the readings considered and the one implemented, are in `RUN_RECORD.md`. In short:

| id | finding |
|---|---|
| S5.4-8 | Disposition of the obligations of an instruction whose only issuer record is an unscoped failed emission: INDETERMINATE or UNCONFIRMED. |
| S5.10-8 | How a record names the uniqueness scope of its identifier, and which scopes are valid. |
| S5.12-1 | Class of an issuer binding that contradicts the frozen Required Target Set: INVALID or CONFLICT. |
| S6.5-2 | How an exclusion-rule violation becomes a positive FAIL condition. |

No contradiction was found, meaning no two requirement sentences were found that cannot both hold.

Not implemented, because nothing in a verifier corresponds to them: S4-1, S5.4-7 (issuer-side
recording), S5.8-3 and S9.1-3 (optional timely-delivery claim), S5.11-6 (re-running with a changed
rule), S5.14-2, S7-1, S9.1-1, S9.3-1, S11-1 to S11-3.

## Representation

The JSON shapes here are this implementation's own descriptive representation, not a wire format,
and not the draft's illustrative record. The dispositions, enforcement meanings, coverage
conditions, claim-support meanings, `NOT_ESTABLISHED` and `target_resolution_unclosed` use the
draft's names unchanged, so the lossless mapping Sections 5.10, 5.15 and 6.6 ask for is the
identity. The control-effect results EFFECT_OBSERVED, NO_EFFECT and UNKNOWN are the conceptual
values Section 4.5 names.

In the vector file, `base_profile` and `base_frozen` are given once; each vector's input is a JSON
Merge Patch (RFC 7396) against them plus its own records and claims. Report-check vectors give a
run and a list of edit operations applied to its report. The selector syntax of the `expect`
objects is described at the top of `vectors/evaluate.py`.

## Comparing against other vectors

The vectors are self-contained and carry the conformance case numbers of the -02 appendix, so
another implementation can compare case by case: for each case number, `run_record.json` lists the
vector ids, and each vector states the expected dispositions, structural result and claim support.
The case numbers of -01 and -02 differ; the vectors of release 0.1.0 carry the -01 numbers.
Nothing here depends on any other implementation's vectors, and none were seen.

## Not done

- No native verifier: signatures, attestations and transport acknowledgements are not verified
  here; their native results are consumed as stated in each record (Section 8.1).
- No timely-delivery claim kind (Sections 5.8 and 9.1 make it optional).
- No wire format, transport, SCITT registration or deployment integration.
- No claim about the correctness of the draft, of any deployment, or of any other implementation.
- Only the Python versions named in the run record were run.

## Running

```
python -m pytest interop/acde_01/tests
python interop/acde_01/vectors/generate_vectors.py --check
ACDE01_DRAFT_TXT=<path to the pinned copy> python -m pytest interop/acde_01/tests
```

The third form also re-extracts the requirement table from the draft copy and compares it. The
test files are named `check_*.py` and `interop/acde_01/pytest.ini` collects them, so they run when
this directory is named and stay out of the repository's own test collection.

## Run record

See `RUN_RECORD.md`; its machine-readable form is `run_record.json`.

- head of the run: `72dd1686e588297cd9aacb77317c30769c665b1c`
- run_record.json SHA-256: `9937de374497587b5cc2c3e8fb223a3340dd23f8f959a99ee9673e780a19e37b`
