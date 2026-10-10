**A security update for everyone on 6.2.0.** It tightens checks on policy validity, timestamps, key algorithms and log inclusion proofs, and rejects ambiguous input on additional paths.

```
python -m pip install --upgrade proofbundle==6.2.1
```

## Highlights

- **Policy checks use one time for both validity limits.** Decision-policy lifetime checks keep fractions of a second, and claim-age checks no longer truncate the calculated age to whole seconds.
- **One signature method cannot stand in for another.** An old root key cannot approve a rotation using an unsupported algorithm, and an Ed25519 outcome signature alone cannot meet a hybrid-key requirement. Empty log-key or origin lists reject the respective trust check.
- **A proof counts only where it was checked.** Trust in a transparency log inclusion applies only to the inclusion context the verifier checked, including its position, tree size, proof path and root.
- **Duplicate fields and unsupported requirements are rejected.** Agent-review policy files and Chia node replies with duplicate JSON keys are rejected. The credential profile check also rejects unsupported or malformed critical-extension fields.

## Verify this release yourself

Use the checksums and build provenance to check the downloaded files, and check the signed pre-tag audit receipt from a clone. The commands and their limits are in [Verifying a published release](https://github.com/b7n0de/proofbundle/blob/e4304822f187656d4a091d91dd4e00a6f7e20d29/RELEASE.md#verifying-a-published-release-anyone).

## What a receipt still does not prove

A valid signature binds the signed content to the signing key. It does not make a reported result true.

## Details

<details>
<summary>All 15 fixes, one line each, as in the CHANGELOG</summary>

- **Repeated field names are rejected in review policies.** `agent_review.load_policy` refuses a policy file that carries the same JSON key twice (`AgentReviewError`) instead of reading the last value.
- **Replies from Chia with repeated field names are rejected.** The Chia RPC reader in `anchors_chia_add` refuses a node answer that carries the same JSON key twice (`ChiaRpcError`) instead of reading the last value.
- **Credential checks reject unsupported requirements.** `sdjwt_vc.check_vc_profile` refuses an issuer JWT header with an unsupported or malformed `crit` field (RFC 7515 §4.1.11), including when the issuer signature is not required.
- **A policy is checked at the same time as the receipt, including fractions of a second.** `verify_decision_receipt` judges a decision policy's lifetime at the receipt's evaluation instant with its fraction of a second, not at that instant cut to the whole second.
- **These verification commands require whole seconds.** `--verification-time` of `decision verify` and `verify-enclave` refuses a time whose fractional seconds are not all zero, however many digits are written.
- **These commands label results at a supplied time as HISTORICAL.** With `--verification-time`, `decision verify` labels verification results HISTORICAL even without `--policy`, and `verify-enclave` labels its JSON and text results HISTORICAL.
- **One clock reading judges both ends of a policy's validity.** A policy lifecycle evaluation without an explicit instant reads the wall clock once and judges both ends of the policy's validity window at that one instant.
- **Policy time checks do not silently replace a supplied time with the current time.** For their time comparisons, `policy_expired`, `policy_not_yet_valid` and the trusted-checkpoint check of `evaluate_policy` no longer replace a malformed non-`None` `now` with the wall clock; `None` retains the default clock behaviour, and naive datetimes are treated as UTC.
- **An enclave check rejects an invalid supplied time.** `verify_enclave_attestation` refuses an evaluation time `now` other than `None` unless its type is exactly `int`.
- **Fractions of a second count when checking a claim's age.** `check_freshness` compares parsed timestamps without truncating their age to whole seconds; with `max_age_seconds` set, a negative age or an age above the bound is not fresh.
- **The time is checked before it reaches the proof verifier.** Before dispatching an anchor verifier, `verify_anchor` and `verify_anchors` reject a supplied `now` other than `None` unless its type is exactly `int`.
- **A log entry must match the proof that was checked.** `evaluate_policy` treats a trusted checkpoint, the tree context and the root as authenticated only when the bundle states the same inclusion context (hash algorithm, leaf index, tree size, audit path and root) that `verify_bundle` verified for it.
- **An old key cannot approve its replacement using an unsupported signing method.** `verify_trust_pack` no longer treats an explicit unsupported or invalid `alg` on an old-root pin as Ed25519; an absent `alg` and the legacy bare-key form still mean Ed25519.
- **When two signature methods are required, one alone is not enough.** `pack_key_binds_signer` binds an Ed25519 outcome signature only to an Ed25519 pack key; a hybrid or ML-DSA key never binds it, so a role declared hybrid is not met by the classical half alone.
- **An empty list of permitted log keys or sources grants no permission.** `evaluate_public_transparency` treats a present `trustedLogKeys` list as an allowlist when `requireSignedCheckpoint` is enabled, and a present `trustedLogOrigins` list as an allowlist; an empty list accepts no key or origin in the respective check.

</details>

[Full changelog](https://github.com/b7n0de/proofbundle/blob/e4304822f187656d4a091d91dd4e00a6f7e20d29/CHANGELOG.md) · [Known limitations](https://github.com/b7n0de/proofbundle/blob/e4304822f187656d4a091d91dd4e00a6f7e20d29/RESTRISIKO_620.md) · [Release scope](https://github.com/b7n0de/proofbundle/blob/e4304822f187656d4a091d91dd4e00a6f7e20d29/docs/release_scope/6.2.1.md) · [proofbundle.dev](https://proofbundle.dev)

Created with AI assistance. Reviewed and published by me.
