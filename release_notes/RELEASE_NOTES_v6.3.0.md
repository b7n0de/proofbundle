**A feature release following 6.2.1.** The installed package adds opt-in eval-result v0.2 export and verification, changes the default DSSE key ID handling, and fixes two pytest receipt behaviours. The repository also adds SCITT statement identification material, a pilot profile and contract, and an incremental Merkle accumulator.

```
python -m pip install --upgrade proofbundle==6.3.0
```

## Highlights

- **DSSE key IDs are included by default when available.** Envelopes created by `dsse.sign_envelope`, including in-toto exports, carry the signer's OpenSSH SHA256 fingerprint as an unsigned `keyid` by default when the signer exposes its Ed25519 public key. Use `keyid=""` to omit it; signers without an exposed Ed25519 public key omit it unless supplied explicitly.
- **eval-result v0.2 for the revised in-toto draft.** An opt-in export and verification under its own predicate type; exports still default to v0.1, and `--verify` accepts both.
- **Statement identification material for SCITT.** The repository includes requirements and a verification package in `docs/scitt/statement_identification/`.
- **Repository pilot material and an incremental accumulator.** A profile and vectors for the shipped decision and outcome predicates, the first pilot contract, and an incremental Merkle accumulator with a restart rule are provided under `docs/` and `tools/`.

## Verify this release yourself

Use the checksums and build provenance to check the downloaded files. To check the signed pre-tag audit receipt, use a clone at the source commit identified by the build attestation. The commands, prerequisites and limits are in [Verifying a published release](https://github.com/b7n0de/proofbundle/blob/25b352019ce2dceb0f2492447389029e3c5e2c6e/RELEASE.md#verifying-a-published-release-anyone).

## What a receipt still does not prove

A valid signature binds the signed content to the signing key. It does not make a reported result true.

## Measured on the reference machine

The budget cost axis was measured on the reference machine on 2026-10-13. All 12 axes and all 7 combinations passed, and none was skipped. The calibration factor `maschinenfaktor_schnellstes_ende` is 1.0581, the ratio of the fastest recorded calibration time in this run to the median of the earlier reference recording. The timing limits used the fastest-sample setting, recorded as `latte_aus_der_klammer=schnellstes_ende`. The [measurement record](https://github.com/b7n0de/proofbundle/blob/25b352019ce2dceb0f2492447389029e3c5e2c6e/audit_artifacts/360/budget_axis_latest.json) lists every axis and combination.

## Details

<details>
<summary>All 11 entries, one line each, as in the CHANGELOG</summary>

### Added

- Add opt-in eval-result v0.2 export and verification under `https://b7n0de.com/attestation/eval-result/v0.2` for the revised in-toto draft. Export with `proofbundle intoto --predicate-version v0.2 --evaluator <URI>`. v0.2 requires an `evaluator`, identifies each model and dataset by exactly one of a salted commitment or a digest-bearing ResourceDescriptor, and records artifact digests in `evidence[]`. Receipt evidence uses the SHA-256 of the receipt file's exact bytes. Exports still default to v0.1; `--verify` accepts both versions. See `docs/IN_TOTO_PROFILE.md` for mappings and migration details.
- **An independent reading of draft-abak-agent-control-delivery-evidence-01.** Adds `interop/acde_01`, a verifier-side implementation derived from our reading of the text of -01 alone, with 130 requirement sentences, 146 vectors and a run record with agreement 108, contradiction 0, ambiguity 14 and not implemented 8. Nothing outside `interop/acde_01` changes.
- Add SCITT statement identification requirements and a package verifiable against them.
- Add a pilot profile and vectors for the shipped decision and outcome predicates.
- Document which capabilities ship in 6.1.0 and which are available only on the main branch at the documented comparison point.
- Add an incremental Merkle accumulator alongside the bundle emitter, with a restart rule and before-and-after run records.
- Add the first pilot contract for comparing approved agent actions with GitHub evidence.

### Changed

- DSSE envelopes created by `dsse.sign_envelope`, including in-toto exports, now include the signer's OpenSSH SHA256 fingerprint as `keyid` by default. Use `keyid=""` to omit it; signers without an exposed Ed25519 public key omit it unless supplied explicitly. The key ID is unsigned. The pinned-key DSSE and in-toto verifiers, including `pb_verify_rs verify-dsse`, do not use it to select a key; the trust pack retains its key-selection rules. Archived receipts and regression fixtures may still omit it and be rejected by consumers that require it. See `docs/IN_TOTO_PROFILE.md` for interoperability notes.
- Pull-request label changes no longer restart the main CI workflow. The `landung` label starts mutation checks in a separate workflow; new commits rerun them while the label is present, and removing the label cancels them.

### Fixed

- The pytest plugin now skips receipt generation and reports why when `PROOFBUNDLE_METRIC` is set to a value other than `pass_rate`, preventing pass-rate values from being labelled as another metric. Unset or `pass_rate` continues to select the pass-rate metric.
- The pytest plugin now decides `passed` from the exact counts of passed and run tests instead of from the pass rate rounded to six decimal places. With the `>=` comparator, two passes out of three no longer pass a threshold of `0.666667`.

</details>

[Full changelog](https://github.com/b7n0de/proofbundle/blob/25b352019ce2dceb0f2492447389029e3c5e2c6e/CHANGELOG.md) · [Known limitations for 6.3.0](https://github.com/b7n0de/proofbundle/blob/25b352019ce2dceb0f2492447389029e3c5e2c6e/RESTRISIKO_630.md) · [Earlier risk record](https://github.com/b7n0de/proofbundle/blob/25b352019ce2dceb0f2492447389029e3c5e2c6e/RESTRISIKO_620.md) · [Release scope](https://github.com/b7n0de/proofbundle/blob/25b352019ce2dceb0f2492447389029e3c5e2c6e/docs/release_scope/6.3.0.md) · [proofbundle.dev](https://proofbundle.dev)

Created with AI assistance. Reviewed and published by me.
