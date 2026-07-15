# Audit Scope v1

Status: **PROPOSAL** — the candidate scope-freeze deliverable for
[`docs/GRANT_MILESTONES.md`](GRANT_MILESTONES.md) M1 ("Audit scope frozen"). A document alone
cannot freeze anything; freezing is an Owner decision (a tag or version commitment held for the
engagement window). Until the Owner marks M1 done against this document, treat it as the current
candidate scope, dated `v3.2.2` (2026-07-15).

This document exists because Finding 12 of the audit-readiness review (external audit +
institutional independence) is **not something this project can close by itself**: an audit run
or simulated by the same person/AI who wrote the code is not independent — it would just be
another self-review, the exact limitation Finding 12 is about. What CAN be prepared in advance is
the groundwork a real external reviewer needs on day one: a scope that will not have moved out
from under them by the time they finish, and an honest map of what is safe to review now versus
what is still preview.

## Why the scope has to be coupled to a freeze

An audit against a moving target produces a report that is stale before it is published.
proofbundle ships fast (see `CHANGELOG.md`: 20+ releases in a few weeks) and is explicit that its
3.2.x attestation-chain predicates are a "v3 preview: API and wire format may change without
deprecation" (`docs/predicates/README.md`). Auditing that preview surface now would either (a)
force the audit to re-run every time the wire format shifts, or (b) produce findings against bytes
nobody signs by the time the report lands. Neither serves the goal. **Finding 13** names this
directly: freeze the format of what is in scope before starting.

## What "frozen" means here

For the duration of an engagement against Audit Scope v1:

- No breaking change to the signed-byte shape of an **in-scope** module below without (a) a new
  PyPI minor/major version per `RELEASE.md`'s ordering rules, and (b) an explicit amendment to
  this document naming the change.
- `THREAT_MODEL.md` and `SPEC.md` both now carry a `Revision:` date header (this change adds one
  to `THREAT_MODEL.md`, matching the pattern `SPEC.md` already used); a freeze pins both revisions
  alongside the module table below, so a report can cite exact document versions rather than "the
  docs as of some day."
- **Out-of-scope (EXPERIMENTAL)** modules are explicitly exempt from the freeze — they are already
  documented project-wide as free to change without notice, so there is nothing to freeze there
  yet. They graduate into a future Audit Scope v2 individually, as each leaves preview status (the
  same "graduates ... as it leaves EXPERIMENTAL" language `.github/CODEOWNERS` already uses for
  code-review routing).
- This document does not itself add CI enforcement of the freeze (that would be a code change, out
  of scope for this readiness pass). A mechanical pin — mirroring how `no_false_pass_gate.py` or
  the mutation-gate baseline pin other invariants in this repo — is a reasonable follow-up once the
  Owner confirms the freeze point, tracked as an open item below.

## In scope (STABLE) — audit against these first

Classification source: each module's own docstring maturity marker, cross-checked against
`SPEC.md`'s per-field `EXPERIMENTAL` tags, `docs/predicates/README.md`'s status column, and
`CHANGELOG.md`'s shipped-release entries — not guessed from file location.

| Module | Shipped | Role | Doc |
|---|---|---|---|
| `signature.py` | v0.1 | Ed25519 verify (delegated to `cryptography`) | `docs/REVIEWERS.md` |
| `merkle.py` | v0.1 | RFC 6962/9162 Merkle hashing, inclusion + consistency proofs | `docs/REVIEWERS.md` |
| `bundle.py` | v0.1 | the `proofbundle/v0.1` verifier: signature, Merkle, strict unknown-field rejection | `SPEC.md` |
| `_strict_json.py` | v0.9 (WP-C1) | duplicate-key-rejecting JSON parser shared by every verify path | `THREAT_MODEL.md` (parser differential row) |
| `dsse.py` | v0.9 | DSSE/PAE envelope over Ed25519, the in-toto export signing layer | `SPEC.md` §7b |
| `canonical.py` | 2.1.0 (ADR 0002) | RFC-8785 content-root primitive shared by decision/eval/SVR Statements | [ADR 0002](adr/0002-universal-content-root.md) |
| `intoto.py` | v0.9 | `eval-result/v0.1`, `test-result/v0.1`, SVR DSSE export/verify | `SPEC.md` §7b |
| `decision.py` | 2.1.0 (ADR 0001) | `decision-receipt/v0.1` — DSSE-signed agent-decision predicate | [ADR 0001](adr/0001-decision-receipt-separate-predicate.md) |
| `policy.py` | 2.0.0 (v0.1 policy), 2.1.0 (v0.2) | offline trust-policy evaluation over a completed crypto verdict | `docs/TRUST_ANCHORS.md` |
| `kbjwt.py` | v1.2 | RFC 9901 §4.3 Key Binding JWT verification | `SPEC.md` §6/§7 |
| `sdjwt.py` | v0.1 | RFC 9901 selective-disclosure verify (issuer signature + digest commitments) | `docs/SD_JWT_VC_PROFILE.md` |
| `sdjwt_issue.py` | v0.5 | RFC 9901 selective-disclosure issuance | `docs/SD_JWT_VC_PROFILE.md` |
| `checkpoint.py` | v0.9 (notes), v1.2–v1.3 (cosignatures) | C2SP tlog-checkpoint + Ed25519/ML-DSA-44 witness cosignatures | `SPEC.md` §7c/§7d |
| `tlogproof.py` | v1.3 | C2SP `.tlog-proof` portable transparency-log proof files | `SPEC.md` §7e |
| `statuslist.py` | v1.3 | Token Status List (draft-ietf-oauth-status-list) offline revocation | `SPEC.md` §7f |
| `persample.py` | v1.5 | per-sample Merkle receipts + auditor spot-check protocol | `docs/DEMO.md` |
| `evalclaim.py` | v0.4 | the `proofbundle/eval-claim/v0.1` codec (`build_eval_claim`/`decode_eval_claim`) | `EVAL_CLAIM.md` |
| `emit.py` | v0.2 | the bundle emitter (sign + Merkle-anchor) | `SPEC.md` |
| `hashalg.py` | 3.2.0 (ADR 0006, "BUILT") | hash-algorithm registry with fail-closed resolution | [ADR 0006](adr/0006-anchor-longevity.md) — note below |

**Note on `hashalg.py`:** its own docstring and ADR 0006's status table mark it "BUILT" (not
EXPERIMENTAL), and it introduces no wire-format change of its own. In this branch its only actual
caller is the EXPERIMENTAL `renewal.py`. It is listed IN-SCOPE as a primitive on its own merits
(a plain registry + resolver), with the honest caveat that it currently has no STABLE consumer to
audit it *through* — an auditor reviewing it in isolation should know that.

## Out of scope for v1 (EXPERIMENTAL) — do not freeze yet

Every module below is explicitly marked `EXPERIMENTAL` in its own docstring and/or in `SPEC.md`,
and is documented project-wide (`docs/predicates/README.md`) as free to change wire format without
deprecation. Auditing these now would audit a moving target; they graduate into Audit Scope v2
individually as each stabilizes.

| Module / predicate | Preview since | Why it moves |
|---|---|---|
| `trust_pack.py` (`trust-pack/v0.1`) | 3.2.0 (O2) | crypto-agility `alg` dispatch just changed under it (Welle 1 Finding 08); rotation semantics are still being red-teamed (Welle 2 Finding 11, `release/v3.2.3-audit-welle2`, not in this branch) |
| `outcome.py` (`action-outcome/v0.1`) | 3.2.0 (O1) | third link of an eval → decision → outcome chain still forming |
| `public_transparency.py` | 3.2.0 (O3) | a policy layer over `checkpoint.py`; not yet wired into the reference CLI's `--policy` |
| `verification_summary.py` (`verification-summary/v0.1`) | 3.2.0 (O4) | roll-up predicate over the still-moving chain above |
| `run_ledger.py` (`run-ledger/v0.1`) | 3.2.0 (O5) | new predicate, no external cross-implementation vectors yet |
| `subject_binding.py` | 3.2.0 (O6) | cross-cutting helper for the modules above |
| `sdjwt_vc.py` | 3.2.0 (O7) | SD-JWT VC is itself a pre-IESG IETF draft (`draft-ietf-oauth-sd-jwt-vc-17`) |
| `renewal.py` | 3.2.0 (ADR 0006, B3) | ASN.1/XMLERS export and real external RFC-3161/OTS-token binding stay OPEN by the ADR's own status table |
| `evidence_pack.py` | 3.2.0 (ADR 0006, B6) | a real confirmed-receipt pack (calendar submit + Bitcoin confirmation) is human-gated, OPEN |
| `pqsig.py` | 3.2.0 (ADR 0006, B5) | its own docstring marks it EXPERIMENTAL; note it is a *separate* code path from `checkpoint.py`'s stable ML-DSA-44 witness cosignatures — see [ADR 0007](adr/0007-crypto-agility-alg-dispatch.md) §Context for why two ML-DSA parameter sets exist in this codebase |
| `anchors.py` + `anchors_rfc3161.py` + `anchors_ots.py` + `anchors_chia.py` + `anchors_chia_add.py` + `anchors_markovian.py` | 2.0.0b3 | `SPEC.md` §7i states the `anchors[]` wire format itself is EXPERIMENTAL |
| `experimental/enclave.py` | 2.0.0b1 | doubly-gated v2.0 preview (pre-release channel + `[experimental]` extra) by design |

**CLI (`cli.py`) and `adapters/`** are thin wiring over the modules above, not independent
crypto-trust surface — `docs/REVIEWERS.md`'s own framing already excludes them from the "trusted
core," and this document does not change that.

## Known gaps this document surfaces (not fixed here — reine Doku, no code change)

- **`.github/CODEOWNERS`** lists a "trusted core" review-required path set that is broader than
  the STABLE table above (it includes the whole EXPERIMENTAL `anchors[]` family, correctly — code
  review and audit scope are different axes) but is also **missing** three files that this
  document's cross-check found carry real signature-verification logic: `checkpoint.py`,
  `renewal.py`, and `anchors_chia_add.py`. Worth an Owner-reviewed CODEOWNERS PR; not changed here
  because this increment is documentation-only and CODEOWNERS is CI/review wiring.
- `GRANT_MILESTONES.md` M1 currently reads "pending scope-freeze PR" — this document is that
  candidate; see the cross-reference note added there.

## Non-claims

This document does **not** assert that an audit has taken place, that any module listed above has
been independently reviewed, or that the STABLE set is free of defects — the mutation gate,
fuzzing, and vendored external-vector tests referenced in `docs/REVIEWERS.md` and
`docs/AUDIT_READINESS.md` are the project's own instruments, not a substitute for an outside
reviewer. It states a scope and a freeze mechanism so that when an independent audit does happen,
it starts from a target that holds still.

## Cross-references

`docs/REVIEWERS.md` (the 30-minute self-review path) · `docs/AUDIT_READINESS.md` (the funding /
OSTIF briefing) · `docs/GRANT_MILESTONES.md` (M1–M6 tracker) · `THREAT_MODEL.md` · `SPEC.md` ·
[ADR 0002](adr/0002-universal-content-root.md) · [ADR 0006](adr/0006-anchor-longevity.md) ·
[ADR 0007](adr/0007-crypto-agility-alg-dispatch.md) · `.github/CODEOWNERS` ·
`docs/predicates/README.md`.
