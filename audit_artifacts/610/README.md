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

    audit_artifacts/610/findings_register_v2.json   sha256 086612b7c92d83bd4f0cf1508f3b29267f6c7fa2e6f7147a254b8b77462aa319
                                                    16610 bytes · schema proofbundle.findings_register.v2
                                                    document_id urn:b7n0de:findings-register:610
                                                    register_revision 0 · issued_at 2026-09-20 · 5 records

NO REVISION IS NAMED HERE, and that is a correction rather than an omission. An earlier version of
this document named the head that `git rev-parse` returned while it was being written, which is the
head BEFORE the commit that introduces the bytes it describes. A review round measured it: the
carrier named here was 16,562 bytes, the file at that head was 16,160, so the line attributed an
exact measurement to a revision that cannot reproduce it. A digest identifies bytes on its own, and
`tests/test_der_610_beleg_nennt_die_bytes_die_dastehen.py` recomputes every digest below against the
tree this file sits in and asks git whether any token here is a revision, so neither can drift.

## The sources it was cut from

    RESTRISIKO_600.md   sha256 27e3ef54d0d7d13b8d3ec4893f591bff7e52831d5c9244b3c9a65ad8194102af   1 identifier(s)
    RESTRISIKO_610.md   sha256 9b802088132bee817232fbb0bece02d63ef5b77d479bcfef2ba3ed24ef66d455   4 identifier(s)
    RESTRISIKO_610_OBJEKTKLASSEN.json   sha256 b35e0733bd082c3608fcb5362a1d7976196d15de6bae183913dcbfcacf217bfc   5 identifier(s)

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
| `COMMIT-PATTERN-DOMAIN-NOT-AT-VERIFY-BOUNDARY-01` | prosa_zusage | NOT MEASURED | open | `RESTRISIKO_610.md` |
| `SMALL-ORDER-KEY-AT-CARRIER-SIGNATURE-01` | prosa_zusage | NOT MEASURED | open | `RESTRISIKO_610.md` |
| `SHIPPED-TOOL-VERDICT-NOT-RE-RUN-01` | prosa_zusage | NOT MEASURED | open | `RESTRISIKO_610.md` |
| `DREI-VERBRAUCHER-COERCEN-PASSED-DOKUMENTIERT-IST-EINER-01` | prosa_zusage | NOT MEASURED | open | `RESTRISIKO_610.md` |
| `ZAHL-IM-TEXT-STATT-PLATZHALTER-VERALTET-STILL-01` | prosa_zusage | NOT MEASURED | NOT MEASURED | `RESTRISIKO_600.md` |

## The limits of this document, named rather than left out

- The carrier is **unsigned**. treat this as an unauthenticated record; a coordinated change of register and evidence cannot be detected from the document alone
- Severity and state are read from a named source or left as a gap with a reason; nothing here is
  rated by the tool that produced it.
- `NOT MEASURED` for the cross-count against an independent tally:
  the input carries no list `sollliste_kennungen`; without it there is nothing to COMPUTE against the independent tally, and the historical block would be a quotation from an earlier state
- The assessment cutoff is 2026-09-20, taken from the state the object class file records, not from
  the clock of the run that produced this file.

Generated from measured values of the carrier named above. The carrier itself is produced by
`scripts/gen_findings_register.py --v2 --linie 610` and is not edited by hand.
