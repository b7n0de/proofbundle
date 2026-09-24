# Addendum to RESTRISIKO_610, 2026-09-24 — where the fifty-four live now

`RESTRISIKO_610.md` is frozen. Its own closing section says so: a finding of the closing round is a
new iteration with a new freeze, never an edit to that file, and what comes after the tag is
"recorded after the tag in a dated addendum file next to this one". This is that file.

**AND IT EXISTS BECAUSE I BROKE THAT RULE FIRST.** On 2026-09-24 I rewrote the heading and the
opening paragraph of the section "Open — the 54 lines moved to 6.2.0" directly in the frozen
document, to say that the lines now live in two files. A test caught it, not a reading:
`tests/test_der_610_beleg_nennt_die_bytes_die_dastehen.py` recomputes every digest that
`audit_artifacts/610/README.md` names, and it reported `RESTRISIKO_610.md: document says
869bda7b3ac0…, the file is b5cdec8260e3…`. The same digest stands in
`RESTRISIKO_610_OBJEKTKLASSEN.json` and four times in `audit_artifacts/610/findings_register_v2.json`.
The edit is reverted, the digest matches again, and the statement I wanted to make stands here
instead. The frozen file is unchanged from the tagged tree.

That test was written on 2026-09-20 against exactly this class, a provenance statement drifting from
the bytes it names while nothing notices because a document is not executed. It worked.

## The fifty-four are in two files now, not one

The cast of 2026-09-19 moved all 54 into `docs/release_scope/6.2.0.md` unchanged, because the cut had
to happen faster than the reading; byte equality was checked then, 54 expected, 54 present, none
missing, none foreign. The recast of 2026-09-23 read them against the code and the register and split
them, so the full text now stands in `docs/release_scope/6.2.0.md` AND
`docs/release_scope/6.3.0.md`, each moved line carrying the sentence saying why it went where it did.

Counted from the rows of those files rather than asserted:

| | Count |
|---|---|
| Scope rows in 6.2.0 | 24 |
| Scope rows in 6.3.0 | 34 |
| Of the 54 identifiers, in 6.2.0 | 18 |
| Of the 54 identifiers, in 6.3.0 | 35 |
| Without a row of its own | 1 · S62, delivered in 6.1.0 |
| Sum against the 54 | 18 + 35 + 1 = **54** |
| New rows, not part of the 54 | **7** · P29, P30, Z146 from the four outcomes; R-B1 to R-B4 from the entries the frozen file targets at 6.2.0 by name |

The frozen file's own sentence, that the full text sits in `docs/release_scope/6.2.0.md`, was true
when it was written and is now half of the truth. That is what an addendum is for, and it is why the
file must not be edited to keep it current: a frozen document that gets corrected is no longer
evidence of what was known at the freeze.

## The split is enforced, not merely recorded

`tests/test_release_scope_title_gate.py` reads the identifier list out of the frozen file — the list
line itself is untouched by any of this — and requires each of the 54 to sit in a scope row of exactly
one of the two files, or to be named as a rider in BOTH of their accounting tables. A line in two
scopes and a line in none are the two questions the release rule of 2026-09-09 asks about a move, and
the guard answers both by name rather than as a count that got smaller.

Four register entries the frozen file targets at 6.2.0 by name were in NEITHER scope file until
2026-09-23: `COMMIT-PATTERN-DOMAIN-NOT-AT-VERIFY-BOUNDARY-01`,
`SMALL-ORDER-KEY-AT-CARRIER-SIGNATURE-01`, `SHIPPED-TOOL-VERDICT-NOT-RE-RUN-01` and
`DREI-VERBRAUCHER-COERCEN-PASSED-DOKUMENTIERT-IST-EINER-01`. A counter-reading measured their absence,
each with zero hits. They are the `R-B` rows of the 6.2.0 scope now. They are open work there, not
closed by being written down.

## What this addendum does NOT do

It does not change the frozen file, the pre-tag receipt, or any digest recorded about them. It does
not claim the 54 are complete or correctly placed; it states where they are and names the guard that
holds them to exactly one place each. And it makes no statement about the closing round, which did
not run for 6.1.0 for the reason the frozen file gives.
