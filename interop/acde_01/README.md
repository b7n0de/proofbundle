# Independent reading of draft-abak-agent-control-delivery-evidence-01

This directory holds an implementation of the verification side of
draft-abak-agent-control-delivery-evidence-01, derived from the text of that draft alone, together
with the requirement table it was built from, derived test vectors and a run record. It is an
interoperability exercise. It is not part of the proofbundle library, it defines no proofbundle
format, and proofbundle does not adopt the draft's representation as its own.

## Input, and what was not used

The only normative input is the plain-text rendering of revision -01:

- source: https://www.ietf.org/archive/id/draft-abak-agent-control-delivery-evidence-01.txt
- form: txt, 2576 lines, 108147 bytes
- SHA-256: `2f0356fcb834ba6b80970721273cd8e2e0b2cc19ef1f89a0205a78991653fabf`

Every line number in this directory refers to that copy. The copy itself is not stored here;
`tools/extract_requirements.py` refuses any other bytes.

Not read and not used: the AIREP repository and its evidence records, the phionyx-research probe,
the ACDER probe, the contributed EMILIA fixture itself, the Cedulon probes and case drivers, any
vectors or expected results of the author, and any correspondence or other interpretation. The
draft's own appendices (the illustrative record, the fixture summary and the Minimum Conformance
Cases) are part of the text and were read as such. Where the text allows more than one reading,
the readings considered and the one implemented are written down below and in
`requirements_map.json`; no ambiguity was resolved by looking at another implementation.

## What was derived

1. `requirements.json`, `REQUIREMENTS.md`: every sentence that carries a BCP 14 key word in upper
   case, outside Section 1.2, with section and line range. 130 sentences; key-word occurrences
   MUST 78, MUST NOT 39, SHOULD 17, SHOULD NOT 1, MAY 14. Each R-CD section 5.1 to 5.16 is in it,
   including R-CD-15 (target-set closure and coverage) and R-CD-16 (semantic preservation).
2. `acde01/`: the verification side, Python standard library only.
   - `profile.py`: the declarations the draft leaves to "the applicable protocol or profile"
     (identifier scope, attempt rule, content binding, ordering basis, empty-set semantics,
     resolution failure, acknowledgement point, enforcement mapping, reduction rule, claim
     predicates, intermediary mappings, exclusion rules, freeze semantics), each checked.
   - `reconcile.py`: one bounded run following the twelve steps of Section 6.3: frozen inputs,
     expected population from issuer inclusion and target resolution, every record parsed and
     kept, native verification results consumed, one disposition per Delivery Obligation by a
     published precedence with every applicable diagnostic kept, receiver-record accounting,
     separate enforcement and control-effect dimensions, parent results, the conservation
     equations of Section 6.4, the structural result of Section 6.5, claim support of Section 6.6
     in the same result context, operations against control activation (Section 9.4), and
     intermediary paths (R-CD-16).
   - `report_check.py`: checks a report without its inputs (co-exposure of claim scope and
     support, conservation, PASS and FAIL conditions, parent results, scoped failures, freeze
     facts), and checks a text rendering for the same co-exposure.
3. `vectors/acde01_vectors.json`: 146 derived vectors, each naming the requirement ids it tests,
   whether it shows the conforming path (positive) or the defect that must be caught (negative),
   the Minimum Conformance Case it exercises, and the expected result. Every one of the 30 cases
   has at least one vector. `vectors/build.py` writes them; `vectors/generate_vectors.py --check`
   confirms the committed file equals a fresh generation.
4. `run_record.json`, `RUN_RECORD.md`: the command, the head, the environment, the digest of every
   input file, and per requirement its category and the vectors behind it.

## What was found

Per requirement sentence: agreement 108, contradiction 0, ambiguity 14, not implemented 8.

No contradiction was found, meaning no two requirement sentences were found that cannot both
hold. The ambiguities, each with the readings considered and the one implemented, are listed in
`RUN_RECORD.md`. In short:

| id | finding |
|---|---|
| S6.4-1 | A Delivery Obligation is defined over "a control instruction or delivery attempt", while Section 6.4 counts O over instructions only. |
| S5.8-1 | Case 10 reads as if a deadline-elapsed record could turn UNCONFIRMED into EXPLICIT_FAILURE; Sections 5.8 and 9.1 keep it UNCONFIRMED. |
| S6.4-3 | The instruction-level equation has no class for an instruction whose target resolution fails or stays open, though Section 5.11 requires every instruction to stay accounted for. |
| S6.5-4 | An obligation can be "excluded before population construction" only by a rule that does not depend on its disposition, which exists only afterwards. |
| S5.11-3 | A receiver record that addresses an expected obligation but does not confirm it fits "matched" and "orphan" depending on the meaning of "match". |
| S6.1-1 | Identifier reuse on the issuer side alone: Section 9.1 calls it SUBSTITUTION, Section 6.1 defines SUBSTITUTION between issuer and receiver records. |
| S5.4-5 | An emission that failed before the issuer boundary applies to all targets at once, while EXPLICIT_FAILURE is per attempt, target and boundary. |
| S6.2-1 | The parent result of an instruction with zero obligations is not defined. |
| S5.7-3 | NO_EFFECT appears as an enforcement outcome and as a control-effect result; the control-effect vocabulary is not given. |
| S9.4-2 | "Occurred before control activation" needs an ordering basis that Section 5.9 may not provide. |
| S5.4-1 | No issuer-side record at all for an instruction in the population fits neither INVALID nor INDETERMINATE exactly. |
| S6.6-3 | Which claim "corresponds" to a structural result when no relying-party claim is requested. |
| S6.5-3 | Which dispositions count as positive failing conditions for FAIL. |
| S5.12-1 | Section 6.1 places an unresolved required target under INDETERMINATE; case 15 and Section 5.12 leave INDETERMINATE or INVALID to the profile. |

Not implemented, because nothing in a verifier corresponds to them: S4-1 (packaging permission),
S5.14-2 (relying-system operational policy), S7-1 (protocol attachment points), S9.1-1 and S9.3-1
(deployment practice), S11-1 to S11-3 (privacy practice).

## Representation

The JSON shapes here are this implementation's own descriptive representation, not a wire format,
and not the draft's illustrative record. The dispositions, enforcement meanings, coverage
conditions and claim-support meanings use the draft's conceptual names unchanged, so the lossless
mapping Sections 5.10, 5.15 and 6.6 ask for is the identity. The control-effect results
EFFECT_OBSERVED, NO_EFFECT and UNKNOWN are this implementation's names (see S5.7-3).

In the vector file, `base_profile` and `base_frozen` are given once; each vector's input is a JSON
Merge Patch (RFC 7396) against them plus its own records and claims. Report-check vectors give a
run and a list of edit operations applied to its report. The selector syntax of the `expect`
objects is described at the top of `vectors/evaluate.py`.

## Comparing against other vectors

The vectors are self-contained and carry the conformance case numbers of the draft's appendix, so
another implementation can compare case by case: for each case number, `run_record.json` lists the
vector ids, and each vector states the expected dispositions, structural result and claim support.
Nothing here depends on any other implementation's vectors, and none were seen.

## Not done

- No native verifier: signatures, attestations and transport acknowledgements are not verified
  here; their native results are consumed as stated in each record (Section 8.1).
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
