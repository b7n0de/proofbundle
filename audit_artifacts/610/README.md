# Audit artefacts for the 610 cut

## What this directory is, and what it is not

This is the findings register of the **610 cut**, version 6.1.0. It is
NOT a released version and it is NOT a pre-tag audit of one: no tag `v6.1.0`
exists, no receipt was produced here, and the carrier states its own signature state as
`UNSIGNED`. The neighbouring directory `audit_artifacts/600/` holds the artefacts of
the released 6.0.0 and is the document to read for that release.

A cut is a question asked of the risk sheets: which identifiers do they promise a register entry
for, and does that entry exist. The answer is the carrier below. Everything in it is either cut out
of a named source at a named byte range, carried over from the signed v1 register, or marked as a
gap with a reason.

**The carrier, named by digest so the sentence cannot drift:**

    audit_artifacts/610/findings_register_v2.json   sha256 d05df9850238e074ea98a652a8bda6f27afd8ee57b9cf9d87381ab031c31117b
                                                    15982 bytes · schema proofbundle.findings_register.v2
                                                    document_id urn:b7n0de:findings-register:610
                                                    register_revision 0 · issued_at 2026-09-21 · 5 records

NO REVISION IS NAMED HERE, and that is a correction rather than an omission. An earlier version of
this document named the head that `git rev-parse` returned while it was being written, which is the
head BEFORE the commit that introduces the bytes it describes. A review round measured it: the
carrier named here was 16,562 bytes, the file at that head was 16,160, so the line attributed an
exact measurement to a revision that cannot reproduce it. A digest identifies bytes on its own, and
`tests/test_der_610_beleg_nennt_die_bytes_die_dastehen.py` recomputes every digest below against the
tree this file sits in and asks git whether any token here is a revision, so neither can drift.

## The sources it was cut from

    RESTRISIKO_600.md   sha256 27e3ef54d0d7d13b8d3ec4893f591bff7e52831d5c9244b3c9a65ad8194102af   1 identifier(s)
    RESTRISIKO_610.md   sha256 c9ced1fbb218ba1770f48f0d42e97b4920bbabae173cc6b8645122038b245468   4 identifier(s)
    RESTRISIKO_610_OBJEKTKLASSEN.json   sha256 7c426bcde1976dd1fbf4535f9d6b35700ed263dd64904db67a16d8ca5dd5aacc   5 identifier(s)

## How a title relates to its source

A title here is DERIVED, not quoted verbatim, and the rule differs per find form. The carrier
declares each rule as DATA under `language_scope.title_derivation`, with the sentence below
rendered from that data rather than written beside it; the form of a single record stands in
`evidence[].fundart`. Applying the rule of that form to the bytes of that record's evidence
reproduces its title exactly, and `tests/test_die_sprachangabe_deckt_was_sie_sagt.py` executes the
DECLARED rule rather than a copy of it, so changing the declaration moves the verdict.

- `prosa_zusage` — the paragraph; flattened to single spaces; reduced to its first sentence of which the first 200 characters are kept, cut at a word boundary and marked with a trailing ellipsis beyond that

## The records

| Identifier | Find form | Severity | State | Source |
|---|---|---|---|---|
| `COMMIT-PATTERN-DOMAIN-NOT-AT-VERIFY-BOUNDARY-01` | prosa_zusage | P2 | open | `RESTRISIKO_610.md` |
| `SMALL-ORDER-KEY-AT-CARRIER-SIGNATURE-01` | prosa_zusage | P2 | open | `RESTRISIKO_610.md` |
| `SHIPPED-TOOL-VERDICT-NOT-RE-RUN-01` | prosa_zusage | P3 | open | `RESTRISIKO_610.md` |
| `DREI-VERBRAUCHER-COERCEN-PASSED-DOKUMENTIERT-IST-EINER-01` | prosa_zusage | P2 | open | `RESTRISIKO_610.md` |
| `ZAHL-IM-TEXT-STATT-PLATZHALTER-VERALTET-STILL-01` | prosa_zusage | P3 | open | `RESTRISIKO_600.md` |

## The signed v1 register of this cut

The structured, signed carrier the release gate reads is `audit_artifacts/findings_register_361.json`,
scoped to `6.1.0` since 2026-09-21 — 26 entries, 14 closed, 12 open, **0 open P0/P1** (counted, not
quoted): the 21 findings carried from the 6.0.0 register, of which `N16` is closed for this tree
and open in the published Action tag, plus the five class entries the risk sheets promise, each
with the severity the producer assigned and the note that says so. `C12.2` reads and counts that
register, not any prose here, and `tests/test_die_zahlen_neben_dem_register_werden_nachgerechnet.py`
recomputes the three figures in this paragraph from the register on every run.

| check | state on this cut |
|---|---|
| findings register, 0 open P0/P1 | NOT MEASURED via C12.2 — 26 findings in the signed, version-bound register (`6.1.0`); the pre-tag round that runs the audit matrix on the frozen head has not run yet, so the gate's own verdict is not quoted here |

## The limits of this document, named rather than left out

- The carrier is **unsigned**. treat this as an unauthenticated record; a coordinated change of register and evidence cannot be detected from the document alone
- Severity and state of the five records are read from `FINDINGS` in
  `scripts/gen_findings_register.py`, the list the owner signs as the v1 register of this cut. The
  sources carry no severity column, so the producer ASSIGNED each severity from the reach the sheet
  states and says so in the entry's note; no tool rated anything, and the owner's signature over the
  v1 register is what endorses the assignment.
- `NOT MEASURED` for the cross-count against an independent tally:
  the input carries no list `sollliste_kennungen`; without it there is nothing to COMPUTE against the independent tally, and the historical block would be a quotation from an earlier state
- The assessment cutoff is 2026-09-21, taken from the state the object class file records, not from
  the clock of the run that produced this file.

Generated from measured values of the carrier named above. The carrier itself is produced by
`scripts/gen_findings_register.py --v2 --linie 610` and is not edited by hand.

## The pre-tag receipt and the closing round of 6.1.0

The sentence above that says no receipt was produced here describes the state of this directory
when the register was cut. The ceremony of 6.1.0 files the pre-tag receipt beside this file as
`pre_tag_receipt_v6.1.0.json`; that receipt binds the tree without itself and without the
mutable evidence paths, so its arrival changes no digest named in this document.

The closing gate round does not run for 6.1.0. Owner word of 2026-09-21 (card `OA-ac65eda888`,
option B): the DEEP mode requires three qualified model families and the operator's qualification
register carries two (measured on 2026-09-21), so the round is not run rather than run below its
floor. The consequences, named here
so that a reader of the receipt sees them without opening the matrix:

- the audit-candidate cells C6.2, C6.3 and C8.2 stay red, as they did for 6.0.0. The soak and
  the differential matrix are re-run against the receipt head and signed by the owner, so their
  measurements are bound to the candidate; their gate line names the run that did not happen,
  and the matrix refuses a gate line whose verdict is not `WITHSTANDS_DEEPGATE`;
- C6.3 additionally lacks the 24-hour soak at the candidate head; that run starts at the freeze
  and is recorded after the tag in a dated addendum next to `RESTRISIKO_610.md`;
- `RESTRISIKO_610.md` carries the same state in its own words, in the section on the closing
  round, and the receipt binds that file.

None of this is a claim that the six lenses would have found nothing. A round that did not run
makes no statement about the tree.
