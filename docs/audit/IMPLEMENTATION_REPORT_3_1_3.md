# Implementation Report — proofbundle 3.1.3 (P0 remediation of the 3.1.1 audit round)

Scope: the remaining P0 findings A-P0-1 … A-P0-5, verified live against the published 3.1.2.
Per-finding closeout in the §24 shape (Finding · Root Cause · Implementation · Tests · Security
Effect · Compatibility · Remaining Limitation · Release · Evidence). Branch
`p0/3.1.3-correctness`, base `v3.1.2` (`bdea353`), work commit `2962b29`.

Status of this document: the 6-lens adversarial review has CLOSED and its confirmed findings are
folded back in (see "6-lens review closeout" below). 989 tests green, ruff clean.

---

## A-P0-1 — Root and tree size authenticated atomically (the sharp core)

- **Finding.** A root-BYTES pin (`--expected-root` / policy `trusted_roots`) let a forged tree
  context pass as `rootAuthenticity: PASS` + `safeForAutomation: true`.
- **Root cause.** An RFC 6962 inclusion proof constrains `(leaf_index, tree_size)` only up to
  path-shape equivalence. A real 2-leaf receipt at index 1 relabelled as `(index 2, tree_size 3)`
  verifies with the SAME payload, signature, root and proof — both labelings share the root, so a
  bytes-only comparison cannot separate them.
- **Implementation.** New `TREE_CONTEXT_AUTHENTICITY` layer. `safeForAutomation` now additionally
  requires it. It is `PASS` only when root AND tree size are authenticated from ONE source:
  (a) a signed C2SP checkpoint — CLI `--trusted-checkpoint FILE` + `--checkpoint-vkey VKEY`, or a
  policy `merkle.trusted_checkpoints[]` entry (`policy.py::_authenticate_trusted_checkpoint`
  reconstructs the exact note text and verifies the pinned signature under the pinned vkey; expiry,
  `hashAlg` and the atomic (root,size) match are all enforced); or (b) an `--expected-root` +
  `--expected-tree-size` PAIR that both passed. A naked root pin reaches at most
  `rootTrustLevel: ROOT_BYTES_ONLY`, never automation-safe. New verdict keys `rootBytesAuthenticity`
  (legacy `rootAuthenticity` stays as its wire-compat alias), `treeContextAuthenticity`,
  `checkpointAuthenticity`, `rootTrustLevel` (`CHECKPOINT` / `ROOT_AND_TREE_SIZE_PINNED` /
  `ROOT_BYTES_ONLY` / `NONE`). New blocker `TREE_CONTEXT_NOT_AUTHENTICATED`.
- **Tests.** `tests/test_tree_context_authenticity.py`: the relabel reproduction, the mandatory
  §5.6 corpus (`two_leaf_proof_relabelled_as_three_leaf_tree_fails`,
  `root_match_tree_size_mismatch_fails`, `leaf_index_relabel_fails`, checkpoint origin / signer /
  expired / hash-alg mismatch, `legacy_root_pin_never_sets_tree_context_pass`), the summary trust
  levels, and the CLI checkpoint path (match, relabel fails, wrong vkey fails closed, flag conflicts).
  E2E CLI smoke confirmed: honest bundle + checkpoint → rc 0 / `rootTrustLevel CHECKPOINT`; relabelled
  bundle + checkpoint → rc 1 / `treeContextAuthenticity FAIL`.
- **Security effect.** The relabel attack no longer reaches automation trust.
- **Compatibility.** Additive wire format. The one behaviour change (safeForAutomation now needs the
  atomic pair) is deliberate and security-motivated; a bytes-only pin still verifies and still reports
  `rootBytesAuthenticity: PASS`.
- **Remaining limitation.** A verifying checkpoint is trusted via its pinned vkey; the vkey's own
  provenance (which log you trust) is the relying party's out-of-band decision, as with every trust
  anchor here. Public-transparency witness quorum over the checkpoint is the 3.2.0 §12 profile.

## A-P0-2 — Expired eval policy fails the policy evaluation (path parity)

- **Finding.** The decision path rejected an expired policy (exit 3); the eval path did not — it
  produced `POLICY: OK` / exit 0 while only `safeForAutomation` went false.
- **Root cause.** Lifecycle lived only in the automation verdict, not in `evaluate_policy`.
- **Implementation.** `evaluate_policy` now runs `policy:not_template` / `policy:not_expired` /
  `policy:not_before` (new additive `valid_from`) → `POLICY: FAIL`, exit 3. `policy_not_yet_valid`
  added; `evaluate_decision_policy` gains the not-before + purpose siblings. Historical verification
  is explicit-only: `verify --verification-time <ISO-8601> --policy …` evaluates the lifecycle AS OF
  that instant with labelled output (`VERIFICATION_TIME: HISTORICAL`, `CURRENT_POLICY_STATUS`,
  `HISTORICAL_POLICY_STATUS`); an expired-today policy keeps `safeForAutomation: false`.
- **Tests.** `tests/test_policy_lifecycle_purpose.py::TestExpiredEvalPolicy` +
  `TestHistoricalVerification` (expired/not-yet-valid/raw-template fail, exit 3, historical labelled
  pass, `--verification-time` without `--policy` and malformed → exit 2).
- **Security effect.** An expired signer pin can no longer authorise via the eval path.
- **Compatibility.** Policies without `valid_from`/`valid_until` are unaffected. An existing policy
  that WAS already expired flips from a silent exit-0 to exit 3 — intended (it was unsafe).
- **Remaining limitation.** `valid_from`/`valid_until` are policy-level; decision-receipt/v0.1
  `validity` carries no predicate-level time window (only audience+nonce) — a predicate-level window
  is a next-breaking-version format change.

## A-P0-4 — policyPurpose binds a policy to one verifier path

- **Finding.** Eval / decision / outcome / transparency policies were not purpose-bound; any policy
  could be pointed at any path.
- **Implementation.** New additive `policyPurpose` ∈ `eval`/`decision`/`outcome`/`trust-pack`/
  `public-transparency`. Eval path accepts only `eval` (`policy:purpose`), decision path only
  `decision`; the wrong purpose is exit 3. Missing field = transitional legacy default;
  `policy lint --strict` requires it. All five shipped profiles declare their purpose.
- **Tests.** `TestPolicyPurpose` (eval rejects every foreign purpose, decision rejects eval, matching
  passes on both paths, unknown/typed value rejected at load, strict-lint requires it,
  `test_templates_carry_purpose`).
- **Security effect.** Purpose-confusion (a decision policy silently reused as an eval policy) closed.
- **Compatibility.** Legacy policies without the field keep working.

## A-P0-5 — Hardened policy metadata

- **Finding.** `trusted_roots` malformed entries were a silent never-matches; instantiate overlays
  could set reserved metadata; `deploymentReady` could be asserted.
- **Implementation.** `_validate_root_b64` hard-validates every pinned root at load (standard base64,
  32 bytes) with its own error. `_validate_checkpoint_entry` structurally validates checkpoint pins.
  Reserved metadata (`deploymentReady`, `requiresIdentityOverlay`, `policyPurpose`, `schema`,
  `generatedFromTemplate`) is not overlay-writable (loud `PolicyError`). `deploymentReady` is DERIVED
  from the final instance (identity pinned AND trust material valid AND purpose defined AND lifecycle
  valid AND not a template); instances stamp `generatedFromTemplate`. Contradictory metadata
  (`deploymentReady:true` + `requiresIdentityOverlay:true`) refused at load.
- **Tests.** `TestPolicyMetadataHardening` (invalid-base64 / wrong-length root, checkpoint entry
  unknown/missing field, contradictory metadata, every reserved overlay key, derived deploymentReady).
- **Compatibility.** A previously-tolerated malformed `trusted_roots` entry now fails at load —
  intended (it never authenticated anything).

## A-P0-3 — Decision audience/nonce fail-closed (closed in 3.1.2, regression secured)

- Regression corpus added (`TestDecisionAudNonceRegression`, the §7.3 named vectors). One real defect
  found by the new corpus and fixed: a wrong-TYPE `validity.audience` (a string) satisfied a requested
  audience binding via Python substring matching — now requires a real JSON array (fail-closed).

---

## Cross-cutting

- **SPEC.** SPEC.md revision `2026-07-13`: new verification-order checks 8/9, the "Atomic tree
  context" normative section, the lifecycle/purpose paragraph, and the extended blocker list.
- **Schema.** `schemas/trust_policy_v0_1.schema.json` gains `valid_from`, `policyPurpose`,
  `generatedFromTemplate`, `merkle.trusted_checkpoints`; schema↔parser parity tests green.
- **Version truth.** `pyproject.toml`, `__init__.py` (version 3.1.3 + SPEC_REVISION 2026-07-13),
  `CITATION.cff`, README example, CHANGELOG entry — all consistent; `test_docs_truth.py` green.
- **Suite.** 977 tests green (57 new named regressions), ruff clean.

## 6-lens review closeout

6 independent adversarial lenses (crypto core, policy lifecycle, RP output, normative consistency,
backward-compat, edge/fuzz) reviewed the committed diff, each reproducing every hypothesis in the venv.
Lens 1 (crypto core) and Lens 5 (backward-compat) found no defect / no accidental regression. The rest
converged on one release-blocker plus several precision fixes, ALL folded back:

- **CONVERGENT release-blocker (Lens 2/3/4/6) — historical fail-open.** `safeForAutomation` is now a
  present-tense verdict: `--verification-time` restricted to a past instant; `POLICY_NOT_YET_VALID`
  blocker added (mirrors `POLICY_EXPIRED`); the policy is evaluated twice in historical mode (historical
  instant for exit code + label, current time for the safety verdict), so a not-yet-valid policy or an
  expired-today checkpoint never reads automation-safe. `CURRENT_POLICY_STATUS` surfaces `NOT_YET_VALID`.
- **Lens 3/4 — no CHECKPOINT / checkpointAuthenticity overclaim.** The field reports authenticated-AND-
  matched, not merely signature-verified; a non-matching checkpoint never labels a pair-derived context
  CHECKPOINT.
- **Lens 6 — require_authenticated_root satisfied by a matching checkpoint** (checkpoint match evaluated
  before the authenticated-root check); **evaluate_policy fails closed (no traceback) on a non-string
  checkpointSigner** in a raw dict.
- **Lens 3 — treeSizeExpectation FAIL (not NOT_REQUESTED) on a badsig checkpoint.**
- **Lens 4 — policyPurpose:null treated as absent (schema⟺parser parity); SPEC LIVE-blocker list
  completed** (TREE_CONTEXT_NOT_AUTHENTICATED, POLICY_NOT_YET_VALID).
- **Lens 2 — explain lists the raw-template pin** so lint no longer calls a minimal template vacuous.
- **Lens 1 — cli.py F1** (a disagreeing policy checkpoint dominates a passing RP pair, fail-closed).
- Migration notes (Lens 5) added to CHANGELOG: mixed-pin-list load flip, strict-lint purpose
  requirement, mixed-fleet policy-artifact caveat, reserved-overlay-key rejection.

Regression corpus for the fixes: `tests/test_lens_review_fixes_3_1_3.py` (11 named tests).

**Both-directions verification of the historical-mode fix (No-Fake, verify-before-landing).** The
two-evaluation split was confirmed to close the fail-open AND preserve the legitimate case:
- Negative (fail-open closed): a not-yet-valid policy with a past `--verification-time` →
  `safeForAutomation: NO`, `CURRENT_POLICY_STATUS: NOT_YET_VALID`, exit 3; a future
  `--verification-time` → exit 2.
- Positive (legit case intact): a currently-valid policy (`valid_from` past, `valid_until` future) +
  a matching signed checkpoint, verified with a past `--verification-time` → exit 0,
  `safeForAutomation: YES`, `rootTrustLevel: CHECKPOINT`, `automationBlockers: []`,
  `CURRENT_POLICY_STATUS: VALID`, `HISTORICAL_POLICY_STATUS: PASS` — bit-identical to the same run
  without `--verification-time`. The tightening is strictly stricter only where a lifecycle bound is
  actually violated at the current time.

## Open before Owner-GO release

- Website-SSOT release manifest + CI drift gate (A-P0-6 / §10) = separate website increment after
  3.1.3 release + facts refresh.
- Release itself (tag, PyPI publish, homepage sync) = Owner actions, not agent actions.
