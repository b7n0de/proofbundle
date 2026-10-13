**A feature release for everyone on 6.2.1.** It adds the eval-result v0.2 export, a SCITT statement identification package, a pilot profile with its contract and an incremental Merkle accumulator, and DSSE envelopes now name their signing key by default.

```
python -m pip install --upgrade proofbundle==6.3.0
```

## Highlights

- **DSSE envelopes name their signing key.** Envelopes created by `dsse.sign_envelope`, in-toto exports included, carry the signer's OpenSSH SHA256 fingerprint as an unsigned `keyid` by default, and `keyid=""` omits it.
- **eval-result v0.2 for the revised in-toto draft.** An opt-in export and verification under its own predicate type; exports still default to v0.1, and `--verify` accepts both.
- **Statement identification for SCITT.** Requirements and a package that can be verified against them.
- **A pilot profile, its contract and an incremental accumulator.** A profile with vectors over the shipped decision and outcome predicates, the first pilot contract, and a Merkle accumulator beside the bundle emitter with a restart rule.

## Verify this release yourself

Use the checksums and build provenance to check the downloaded files, and check the signed pre-tag audit receipt from a clone. The commands and their limits are in [Verifying a published release](https://github.com/b7n0de/proofbundle/blob/7aae76509e2a5a15c367255003f5385a63cc1677/RELEASE.md#verifying-a-published-release-anyone).

## What a receipt still does not prove

A valid signature binds the signed content to the signing key. It does not make a reported result true.

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
- The pytest plugin now decides `passed` from the exact counts of passed and run tests instead of from the pass rate rounded to six decimal places. Two passes out of three no longer pass a threshold of `0.666667`.

</details>

[Full changelog](https://github.com/b7n0de/proofbundle/blob/7aae76509e2a5a15c367255003f5385a63cc1677/CHANGELOG.md) · [Known limitations](https://github.com/b7n0de/proofbundle/blob/7aae76509e2a5a15c367255003f5385a63cc1677/RESTRISIKO_620.md) · [Release scope](https://github.com/b7n0de/proofbundle/blob/7aae76509e2a5a15c367255003f5385a63cc1677/docs/release_scope/6.3.0.md) · [proofbundle.dev](https://proofbundle.dev)

Created with AI assistance. Reviewed and published by me.
