# Residual risk, proofbundle 6.1.0 — full register

GENERATED from the signed register. Do not edit.

> Judged by: release_600_autonom_fail_closed 2026-09 (`a7b8582f4d9a…`), jeder_riegel_traegt_seinen_fangnachweis 2026-09 (`3b3c64097e98…`), modellvielfalt_gate 2026-09 (`c4b7c1f8f6d9…`)

## N22 — Our own receipts carry no proof of when they existed

**Role** finding · **Kind** quality · **Severity** P2
**Origin** owner order 20260911T2132Z line one; measured 2026-09-12 on tag v6.0.0
**Class** `EIGENE-QUITTUNGEN-OHNE-ZEITANKER-01`

**Quality assessment** `open` / `defect_confirmed` — about: the nine receipts proofbundle 6.0.0 ships

Measured field by field, through the DSSE payload: one of nine carries a time anchor and it is three pending calendar promises with no block attestation; zero carry a log registration. The pre-tag receipt states produced_at as self-report. The house can do better and proves it in its own conformance corpus, where two fixtures carry confirmed bitcoin attestations.

**Funnel** reaches user: yes · verdict: `does_not_block_release` · `accepted_known_risk`

A reader of the receipt takes produced_at for evidence when it is a self-report. No verification verdict changes, so it does not block; it is accepted and named.

**Remediation** `none_available` / `planned` · target 6.1.0

scripts/receipt_anchor.py attaches, upgrades and verifies; what is missing is the run over every issued receipt and the verifier binding on the signature axis.

**Evidence**

* `audit_artifacts/restrisiko_610/anker_je_quittung.txt` — measurement, sha256 `40f35e2d88c489d8…`
* `audit_artifacts/restrisiko_610/ots_attestierungen.txt` — measurement, sha256 `12f8e3ebab214f9c…`
* `tests/test_receipt_anchor.py` — catch_proof, sha256 `735fd2c8d23bab9e…`

*first seen 2026-09-12 · last measured 2026-09-12 · revision 1*

## N23 — No receipt of 6.0.0 is registered in a transparency log

**Role** finding · **Kind** quality · **Severity** P2
**Origin** owner order 20260911T2132Z line two; measured 2026-09-12
**Class** `KEINE-LOG-REGISTRIERUNG-NULL-VON-NEUN-01`

**Quality assessment** `open` / `defect_confirmed` — about: the nine receipts proofbundle 6.0.0 ships

Zero of nine carry a log registration, measured on field names rather than on text. The tool has verified a foreign log proof since 5.1.0 and submitted one entry of its own; the gap is the use for our own receipts, not the capability.

**Funnel** reaches user: yes · verdict: `does_not_block_release` · `accepted_known_risk`

A receipt with no third-party witness rests on the issuer alone. No shipped verification changes, so it does not block. A real submission is permanent and stays an owner gate.

**Remediation** `none_available` / `planned` · target 6.1.0

Dry run and independent RFC 6962 recomputation are built and green against the frozen fixture; the submission itself is deliberately unreachable from code.

**Evidence**

* `audit_artifacts/restrisiko_610/markovian_trockenlauf.txt` — measurement, sha256 `19e590eea799988d…`
* `tests/test_markovian_submit.py` — catch_proof, sha256 `1ad1154b84390aa0…`

*first seen 2026-09-12 · last measured 2026-09-12 · revision 1*

## N24 — The twelve model-seal conditions have no mapping onto TRACE

**Role** limitation · **Kind** quality · **Severity** P3
**Origin** owner order 20260911T2132Z line three; TRACE v0.2 retrieved 2026-09-12
**Class** `MODELLSIEGEL-OHNE-ABBILDUNG-AUF-TRACE-01`

**Quality assessment** `under_investigation` / `measurement_incomplete` — about: the model identity our gate records today

Mapped condition by condition: four are fillable with existing TRACE fields, one needs a TEE we do not run, two are partial, one is near, and four have no TRACE field. Our own level is unchanged by the mapping — the model name still comes from response data.

**Funnel** reaches user: no · verdict: `does_not_block_release` · `separate_release_subject`

This is about how our own review evidence is labelled, not about a shipped property of the package. It reaches no user of proofbundle.

**Remediation** `none_available` / `undecided`

TRACE v0.2 calls itself an RFC; building against a draft is a decision, not a task.

**Measurement** `NOT_MEASURABLE` — the magnitude of the gap depends on a TEE this house does not operate; it cannot be measured from here, only named

**Evidence**

* `docs/trace_modellsiegel_abbildung.md` — measurement, sha256 `80d7c85b01e57fd4…`

*first seen 2026-09-12 · last measured 2026-09-12 · revision 1*

## N25 — The residual-risk record is a report, not a register: its prose is the source

**Role** finding · **Kind** quality · **Severity** P2
**Origin** owner order 20260911T2142Z, superseded in parts by 20260911T2226Z after the external review
**Class** `PROSA-IST-DIE-QUELLE-STATT-DER-ABZUG-01`

**Quality assessment** `open` / `defect_confirmed` — about: RESTRISIKO_600.md at tag v6.0.0

5039 lines, 50605 words, 355042 bytes, 202 headings, and every measurement embedded in prose. No checker can enforce the record's own promise that each open finding is named with its proof, because there is no field to check.

**Funnel** reaches user: yes · verdict: `does_not_block_release` · `accepted_known_risk`

It reaches every reader of the repository and no user of the package.

**Remediation** `none_available` / `planned` · target 6.1.0

The generator exists; what remains is the migration of 139 identifiers.

**Evidence**

* `audit_artifacts/restrisiko_610/registerform_vorher.txt` — measurement, sha256 `be1ba3e9665c7b84…`
* `schemas/findings_register_v2.schema.json` — decision, sha256 `0f44dd89eed4cc23…`

*first seen 2026-09-11 · last measured 2026-09-12 · revision 1*

## N26 — The signed carrier binds 20 of 139 identifiers and is read as binding all of them

**Role** finding · **Kind** quality · **Severity** P2
**Origin** owner order 20260911T2151Z finding one; figure corrected by the external review of 2026-09-11
**Class** `TRAEGER-DECKT-20-VON-139-KENNUNGEN-01`

**Quality assessment** `open` / `defect_confirmed` — about: audit_artifacts/findings_register_361.json at tag v6.0.0

The signed carrier holds 20 entries, N1 to N20. The prose carries 139 main identifiers in four series plus four subordinate ones inside S58. Direct structured coverage is 20/139, 14.4 percent. N21 is in the prose and NOT in the carrier, although it states that a release-deciding check turns red on a calendar date.

**Funnel** reaches user: yes · verdict: `does_not_block_release` · `accepted_known_risk`

The assurance '0 open P0/P1' is true of the carrier and is read as true of the record. The prose is bound as a whole file by the pre-tag receipt, so it is tamper-evident but not machine-readable per entry.

**Remediation** `none_available` / `planned` · target 6.1.0

The coverage check is built and refuses a prose-only identifier; the migration of the 119 uncovered identifiers is the work that remains.

**Evidence**

* `audit_artifacts/restrisiko_610/traeger_deckung.txt` — measurement, sha256 `7cc48bf4358913a5…`
* `tests/test_restrisiko_render.py` — catch_proof, sha256 `1fba1e7cb20dafeb…`

*first seen 2026-09-11 · last measured 2026-09-12 · revision 1*

## N27 — Internal identifiers appear on a published surface

**Role** finding · **Kind** quality · **Severity** P2
**Origin** owner order 20260911T2151Z finding two; measured 2026-09-12
**Class** `INTERNE-BEZEICHNER-AUF-DER-AUSSENFLAECHE-01`

**Quality assessment** `open` / `defect_confirmed` — about: RESTRISIKO_600.md at tag v6.0.0

37 overlap-free hits on 35 lines with identifiers DERIVED from the environment, against 48 with the owner's full word list. The derived figure is a lower bound; the difference is the list, not the text. The file itself stays byte-identical because its receipt binds it.

**Funnel** reaches user: yes · verdict: `does_not_block_release` · `accepted_known_risk`

It reaches every reader of the repository and no user of the package. Reputational, not technical.

**Remediation** `workaround` / `planned` · target 6.1.0

The generator carries the check; the word list is read from OUTSIDE the repository and a list inside it is refused. The archive under audit_artifacts/600/restrisiko is an explicitly stated exempt area, never a silent exception.

**Evidence**

* `audit_artifacts/restrisiko_610/bezeichner_zahl.txt` — measurement, sha256 `57d72ac8fa9114b1…`
* `tests/test_restrisiko_render.py` — catch_proof, sha256 `1fba1e7cb20dafeb…`

*first seen 2026-09-11 · last measured 2026-09-12 · revision 1*

## N28 — The S series is issued independently in two divergent trees, and neither carries all of it

**Role** finding · **Kind** quality · **Severity** P2
**Origin** owner order 20260911T2151Z step 12; the external review left this open for lack of the second tree
**Class** `S-REIHE-IN-ZWEI-DIVERGENTEN-BAEUMEN-01`

**Quality assessment** `open` / `defect_confirmed` — about: the identifier sequence of RESTRISIKO_600.md across both trees

The tag carries S1-S85 and S102-S120; the work branch carries S1-S85 and S86-S101. United they are S1-S120 with no free number, and NO tree carries all of them. The two are divergent: branch point 1b2adc2, eleven commits on the tag side, seven on the branch side, and the tag is not an ancestor of the branch. This ANSWERS the gap the external review had to leave open, because the other work state was not supplied to it.

**Funnel** reaches user: no · verdict: `does_not_block_release` · `separate_release_subject`

Bookkeeping of our own record. It reaches no user, and it reaches a reader only as a seeming gap where none is.

**Remediation** `none_available` / `planned` · target 6.1.0

The next free identifier must be derived across ALL trees carrying the record. Deriving it from the tree one happens to stand in is how S86-S89 were issued twice on 2026-09-11.

**Evidence**

* `audit_artifacts/restrisiko_610/nummernlage.txt` — measurement, sha256 `48b7a468c7a87752…`

*first seen 2026-09-12 · last measured 2026-09-12 · revision 1*
