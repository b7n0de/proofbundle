**A patch release following 6.3.0, with stricter verification and changed result reporting.** Statement validation is reported separately from DSSE signature checks, and reference-check results and executed-outcome evidence levels change as described below. The release also improves handling of specific invalid inputs, extends the inspect_ai adapter and updates repository tools. Review the changed fields and remaining exception paths when upgrading.

```
python -m pip install --upgrade proofbundle==6.3.1
```

## Highlights

- **Statement validation is separate from DSSE signature verification.** The eval-result, in-toto and SVR verifiers require the in-toto Statement v1 layer and report `statement_ok` separately from `signature_ok`. These and the decision, outcome, relation statement, verification summary, run ledger and trust pack verifiers require subjects that identify artifacts by digest. A successful DSSE signature check alone does not establish that the Statement passes validation.
- **Reference reporting changes for callers upgrading from 6.3.0.** `automation.referencesResolved` is `None` when no reference was checked; `safeForAutomation` and `automationBlockers` are unchanged. Executed-outcome evidence levels use `REFERENCE_WELL_FORMED` for a well-formed digest reference, or `CONTENT_RESOLVED` when the evidence resolver confirms it, instead of always reporting `CLAIMED`. `action_outcome_proven` and `ok` are unchanged. Review code that depends on these fields.
- **Stricter validation and more specific errors for the corrected cases.** The decision validator rejects JSON null in required fields that do not allow it. The validators named below enforce the corrected digit restrictions and closed `sha256Digest` objects. The corrected error paths return reason codes, blocking verdicts or module-specific errors. Eight public functions remain open for the formatting cases described below, and the two `canonical` primitives still propagate canonicalization errors.
- **The inspect extra admits inspect_ai up to 0.3.281.** Version 0.3.281 is the latest version measured in a fresh environment. The adapter includes sample counts and early-stopping metadata when supplied by the log, allowing a reported early stop to be distinguished from a completed run. The reported `n` is unchanged.

## Verify this release yourself

Use the checksums and build provenance to check the downloaded files. To check the signed pre-tag audit receipt, use a clone at the source commit identified by the build attestation. The commands, prerequisites and limits are in [Verifying a published release](https://github.com/b7n0de/proofbundle/blob/9f19f9d31d598c7ebd6d80b3d3e296e1c7e9d61e/RELEASE.md#verifying-a-published-release-anyone).

## What a receipt still does not prove

A valid signature binds the signed content to the signing key. It does not make a reported result true.

## Measured on the reference machine

The budget cost axis was measured on the reference machine on 2026-10-21. All 12 axes and all 7 combinations passed, and none was skipped. The calibration factor `maschinenfaktor_schnellstes_ende` is 1.0, the ratio of the fastest recorded calibration time in this run to the median of the earlier reference recording. The timing limits used the fastest-sample setting, recorded as `latte_aus_der_klammer=schnellstes_ende`. The [measurement record](https://github.com/b7n0de/proofbundle/blob/9f19f9d31d598c7ebd6d80b3d3e296e1c7e9d61e/audit_artifacts/360/budget_axis_latest.json) lists every axis and combination.

## Details

<details>
<summary>All 30 entries, one line each, as in the CHANGELOG</summary>

### Added

- Add ten conformance vectors of the kind `content_root_vector` under `conformance/action_chain_content_roots/`. They pin the content root of ADR 0002 as data, and `CONTENT_ROOT_CONTRACT.md` states the contract. The Rust verifier `pb_verify_rs` recomputes the eight pinned roots through its `content-root` subcommand.
- Add `tools/scitt_ccf_external/pr31_strict_reader`, a strict reader of a CCF inclusion receipt written to the text of pull request 31 to the CCF receipt profile, with 24 probes and 42 vectors.
- Document in `THREAT_MODEL.md` that a caller's own Python objects passed to the API are code in the same process, outside the verification boundary, and where `RESTRISIKO_620.md` lists the sites where such an object makes a never-raise surface raise.

### Changed

- `automation.referencesResolved` is `None`, no longer `True`, when every reference field it reads is `None` or absent, because no reference check ran. `safeForAutomation` and `automationBlockers` do not change.
- `anchors.receipt_canonical_root` takes its RFC 8785 bytes from the package's one canonicalizer. A value of a subclass of `int` or `float`, an `IntEnum` among them, is refused with `BundleFormatError`; each of the 689 JSON objects tracked in the repository keeps its root.
- The `inspect` extra admits `inspect_ai` up to 0.3.281, the last version measured in a fresh environment.
- The limit of one run of the mutation gate follows the measured baseline of its selection, 1.5 times the baseline and never less than 3600 s. A run past its limit stays not measurable and counts as a gap.

### Fixed

- `verify_eval_result_dsse`, `verify_intoto_dsse` and `verify_svr_dsse`, and with them `proofbundle intoto --verify` and `proofbundle svr --verify`, no longer verify a signed statement without the in-toto Statement v1 layer. `_type` must be `https://in-toto.io/Statement/v1`, and every subject entry must carry a digest. The result reports this as `statement_ok` and the DSSE check alone as `signature_ok`. Statements written by this package's exporters keep their verdict.
- The decision, outcome, relation statement, verification summary, run ledger and trust pack verifiers, and the matching commands of the Rust verifier, no longer accept a signed statement whose subject names no artifact by digest. Their emitters and `emit_agent_review` raise their own error for a subject override they would not verify, such as a `subject_sha256` in capitals. The conformance case `relation/target-subject-missing` expects `RELATION_TARGET_MALFORMED`.
- The decision validator now rejects JSON null in required fields that do not allow null under `schemas/decision-receipt-v0.1.schema.json`; `decision verify --strict` could previously report `safeForAutomation=true` for such a receipt. A `notChecked` entry written as a bare string remains accepted as a deprecated form.
- The decision, outcome, run ledger, verification summary and trust pack validators correct the affected pattern checks to use ASCII digit classes and reject additional members in `sha256Digest` objects, matching the corresponding schema constraints. `verify_trust_pack` no longer raises `TypeError` for a key whose `alg` is a list.
- agent-review v0.1, v0.2 and v0.3 restrict digits in timestamps to ASCII, as required by RFC 3339. Their `schemaVersion` checks also use ASCII digits. By maintainer decision these changes apply to all three existing predicate versions rather than introducing a new version; the receipts and vectors in the repository retain their verdicts.
- The eval-result v0.2 checks read the digits of `evaluatedAt` as ASCII.
- `verify_decision_receipt` reads the evidence level of `actionOutcome.outcomeRef` from the digest inside the reference. A well-formed digest reads `REFERENCE_WELL_FORMED`, or `CONTENT_RESOLVED` when the evidence resolver confirms it, where 6.3.0 read every executed outcome as `CLAIMED`. `action_outcome_proven` and `ok` do not change.
- The inspect_ai adapter tells a run stopped early from a complete one with the same counts. The signed provenance carries `total_samples`, `completed_samples` and, from inspect_ai 0.3.266, `logged_samples`, each only when the log sets it, and `early_stopping_manager` and `early_stopped_samples`. `n` is unchanged.
- The agent-review verifiers answer a correctly signed receipt that carries a value of the wrong type, a number RFC 8785 cannot represent or a lone surrogate with a reason code or a verdict that blocks, instead of `internal_error`. The new reason codes are `STATEMENT_NOT_CANONICALIZABLE` and `PREDICATE_NOT_OBJECT`. `emit_agent_review` raises `AgentReviewError` for such a value.
- The modules that canonicalize a statement through the package's canonicalizer map its refusal, and the refusal of the structural budget in front of it, to their own typed error, instead of letting a bare `ValueError`, `BundleFormatError` or `BudgetExceeded` out. The two primitives of `canonical` pass the refusal on, as documented.
- The corrected public entry points handle failures while formatting values for messages, subject names or serialization, including large integers, deeply nested lists and objects whose `__repr__` raises. This does not establish a never-raise guarantee for every public API. Eight public functions in `intoto`, `_verdict`, `sdjwt_issue` and `evalclaim` remain open for these cases and are tracked in the residual-risk record.
- `verify_decision_receipt` and `verify_outcome_receipt` no longer raise `UnboundLocalError` for a signed statement whose predicate is not an object under a policy with a `relations` section. `experimental.attested_inference.binding_present` answers `False` for signed material without a JSON form.
- `sdjwt.issuer_key_fingerprint` no longer raises for a `str` subclass whose hash raises, and `agent_review.validate_time_claim` answers an `assurance` that cannot be hashed with the error every wrong assurance gets, instead of `TypeError`.
- `verify_sdjwt_vc` and `verify_bundle` no longer accept a presentation in which two committed disclosures give the same claim different values. A claim name stands once in its SD-JWT object.
- A test-result statement of the verifier block names at least one case. One with all three case lists missing no longer validates, and `join_test_result` no longer reports it as `PASSED`.
- A command-line mode refuses the options it does not read instead of dropping them, among them the writing options of `proofbundle intoto --verify`.
- `bundle.load_bundle`, `emit.load_signer` and `agent_review.load_policy` read a path-like argument once at the call. A `__fspath__` that raises or answers something else is refused with a `ProofBundleError`; a `RecursionError` is raised as it is. `load_bundle` read `__fspath__` twice, so the checked file and the opened file could differ. `public_transparency.evaluate_public_transparency` asks for `validate` inside its guard.
- The data-hash vector tool and the pilot GitHub write profile refuse a duplicated map key or JSON member name, CBOR that is not valid under RFC 8949 Section 5.3.1 and bytes after the value, instead of keeping the last value. The public API does not change.
- Remove the machine-local paths identified in files included in the package.
- Repository tools and checks, outside the installed package. The pilot reads one copy of each input for verification and for judgement. The pre-tag tooling refuses a tree that names a path twice and reads its envelope, the findings register and the readiness self-receipt strictly. The test-manifest gate reads its lock strictly and requires both floors. The audit matrix reads an artifact and its anchor once and recomputes the agreement of the differential cell. Within parsed code and recognized operations, the core-layer gate checks the bindings its analysis identifies within one module, and counts writes to `TYPE_CHECKING` by assignment and through `__dict__`, `vars()` and `setattr`. Bindings imported from other package modules, writes through `getattr(module, "__dict__")`, `module.__setattr__`, `object.__setattr__` or a renamed `setattr`, and code it does not parse remain outside that analysis. The Rust parity gate refuses a coverage report that is not evidence, and the pull-request form judges one rendered sequence.
- Repository examples and interoperability code. The verdict-contract example pins the key it trusts, reads its JSON strictly and names what its parser accepts. An ACDE-01 claim over members the population does not hold is not supported, and the ACDE-01 report check recomputes conservation. The accumulator refuses a signed empty state whose frontier is not a list. `conformance/common_vocabulary.compare` compares every axis either side fills when both labels are observations.
- Repository release and measurement scripts. `scripts/budget_axis_measurement.py` ends a successful run with exit 0. `scripts/render_release.py` extends its link binding and validation. The memory test for run 11 is updated.
- Repository guards. The guard over lookups and writes on constant containers, the membership scanner and the guard against machine-local paths see more spellings of what they look for.

</details>

[Full changelog](https://github.com/b7n0de/proofbundle/blob/9f19f9d31d598c7ebd6d80b3d3e296e1c7e9d61e/CHANGELOG.md) · [Known limitations for 6.3.1](https://github.com/b7n0de/proofbundle/blob/9f19f9d31d598c7ebd6d80b3d3e296e1c7e9d61e/RESTRISIKO_631.md) · [Earlier risk record](https://github.com/b7n0de/proofbundle/blob/9f19f9d31d598c7ebd6d80b3d3e296e1c7e9d61e/RESTRISIKO_630.md) · [Release scope](https://github.com/b7n0de/proofbundle/blob/9f19f9d31d598c7ebd6d80b3d3e296e1c7e9d61e/docs/release_scope/6.3.1.md) · [proofbundle.dev](https://proofbundle.dev)

Assisted by little helpers.
