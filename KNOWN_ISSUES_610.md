# Known issues — proofbundle 6.1.0

**Assessment cutoff 2026-09-12 · register revision 1 · profile 2026-09-12.1**

GENERATED from the signed register. Do not edit.

## What this covers, and what it does not

The source record carries **139 main identifiers**; this register holds **7** of them as structured entries. That is the honest coverage figure, not a claim about the tree — and the count below speaks only about findings already made, at the cutoff above.

Known coverage gaps, stated rather than closed:

* **S86-S101 in the published prose at tag v6.0.0** — `NOT_APPLICABLE`. RESOLVED for this register, with evidence rather than assertion. The external review could not close this because the other work state was not supplied to it. It was supplied here: the sixteen identifiers stand on arbeit/601-nachzug, whose digest is listed above, and entry N28 carries the measurement. NOT APPLICABLE means: this is not an unresolved gap of THIS register, not that nothing was missing.
* **the three-word rule STANDARD_nicht_gemessen_nicht_messbar_nicht_anwendbar_20260911** — `NOT_MEASURED`. Owner decision of 2026-09-11 names this file with sha256 8cdc9889 and 2946 bytes. It is not present in this repository and was not found on the authoring workstation under the paths checked, so its digest is absent from policy_refs. Entering the announced digest without measuring the file would be exactly the placeholder this profile forbids.

## What needs a decision

**0 blocking · 6 open · 0 unresolved.**

Nothing here blocks the release. Every open entry is an accepted, named risk with a target; none of them changes a verification verdict.

## Every entry, in one line each

| Id | Sev | Role | Status | Reaches user | Remediation | Title |
|---|---|---|---|---|---|---|
| N22 | P2 | finding | open | yes | none_available/planned | Our own receipts carry no proof of when they existed |
| N23 | P2 | finding | open | yes | none_available/planned | No receipt of 6.0.0 is registered in a transparency log |
| N24 | P3 | limitation | under_investigation | no | none_available/undecided | The twelve model-seal conditions have no mapping onto TRACE |
| N25 | P2 | finding | open | yes | none_available/planned | The residual-risk record is a report, not a register: its prose is the source |
| N26 | P2 | finding | open | yes | none_available/planned | The signed carrier binds 20 of 139 identifiers and is read as binding all of them |
| N27 | P2 | finding | open | yes | workaround/planned | Internal identifiers appear on a published surface |
| N28 | P2 | finding | open | no | none_available/planned | The S series is issued independently in two divergent trees, and neither carries all of it |

The full assessment of each entry, with its evidence paths and digests, is in `audit_artifacts/findings_register_610.json`. That file is the source; this page is a rendering of it.
