Verifier build identity, CAP-1 coverage rules and stricter claim validation. **Beta. Closing audit not run.**

[Changelog](https://github.com/b7n0de/proofbundle/blob/dcac5aeec92e850443cf34d9c07ab5cd277fabe1/CHANGELOG.md) · [Known limitations](https://github.com/b7n0de/proofbundle/blob/dcac5aeec92e850443cf34d9c07ab5cd277fabe1/RESTRISIKO_610.md) · [Release scope](https://github.com/b7n0de/proofbundle/blob/dcac5aeec92e850443cf34d9c07ab5cd277fabe1/docs/release_scope/6.1.0.md)

## What changed

| Area | Change | Evidence |
|---|---|---|
| **Verifier identity** | agent-review/v0.3 can include a build digest, vector set digest and test result reference. The block is self-declared and does not change the verification verdict. | [#224](https://github.com/b7n0de/proofbundle/pull/224) · [Detail](https://github.com/b7n0de/proofbundle/blob/dcac5aeec92e850443cf34d9c07ab5cd277fabe1/docs/VERIFIER_BLOCK.md) |
| **Coverage checks** | CAP-1 rules and 15 conformance vectors are included. Partial or skipped conformance runs are distinguished from fully passed runs. | [#209](https://github.com/b7n0de/proofbundle/pull/209) · [#214](https://github.com/b7n0de/proofbundle/pull/214) · [Detail](https://github.com/b7n0de/proofbundle/blob/dcac5aeec92e850443cf34d9c07ab5cd277fabe1/CHANGELOG.md) |
| **Claim validation** | Malformed claim values are refused. A string such as passed: "false" is no longer treated as a true verdict by the affected exporters. | [#231](https://github.com/b7n0de/proofbundle/pull/231) · [Detail](https://github.com/b7n0de/proofbundle/blob/dcac5aeec92e850443cf34d9c07ab5cd277fabe1/CHANGELOG.md) |

## Before upgrading

- **Receipt versions.** The default emitted format is unchanged from 6.0.0. Use a compatible reader for agent-review/v0.3. A 6.0.0 reader refuses a v0.2 receipt carrying the new verifier field. [Details](https://github.com/b7n0de/proofbundle/blob/dcac5aeec92e850443cf34d9c07ab5cd277fabe1/CHANGELOG.md).
- **Stricter input handling.** Previously accepted malformed claims can now be refused. Check callers that relied on implicit type coercion. [Details](https://github.com/b7n0de/proofbundle/blob/dcac5aeec92e850443cf34d9c07ab5cd277fabe1/CHANGELOG.md).
- **Separate Action release.** The Action input fix is in this source tree. That does not update the documented action@v1.0.0 tag. Its version and extras inputs retain the documented restriction on untrusted values. [Details](https://github.com/b7n0de/proofbundle/blob/dcac5aeec92e850443cf34d9c07ab5cd277fabe1/docs/release_scope/6.1.0.md).

<details>
<summary>Audit status and known limitations</summary>

The closing adversarial round was not run because the required model family floor was not met. C6.2, C6.3 and C8.2 remain red. The full 24 hour soak was not included at tag time. The v2 findings register is unsigned. A separate signed pre-tag receipt does not sign that register.

[Audit record](https://github.com/b7n0de/proofbundle/blob/dcac5aeec92e850443cf34d9c07ab5cd277fabe1/audit_artifacts/610/README.md#the-pre-tag-receipt-and-the-closing-round-of-610) · [Residual risks](https://github.com/b7n0de/proofbundle/blob/dcac5aeec92e850443cf34d9c07ab5cd277fabe1/RESTRISIKO_610.md) · [README status](https://github.com/b7n0de/proofbundle/blob/3be557575793c3ab402c866b4a3c7fcee04d2fd0/README.md#current-release)

The published package and a passed closing audit are separate facts.

</details>

## All changes

48 pull requests, grouped by area. Shortened descriptions link to the original discussions.

<details>
<summary>Verifier and receipt formats · 3 pull requests</summary>

- Add optional verifier build identity in agent-review/v0.3. [#224](https://github.com/b7n0de/proofbundle/pull/224).
- Add CAP-1 coverage rules and conformance vectors. [#209](https://github.com/b7n0de/proofbundle/pull/209).
- Validate decoded claim types at the verification boundary. [#231](https://github.com/b7n0de/proofbundle/pull/231).

</details>

<details>
<summary>Build, CI and test infrastructure · 19 pull requests</summary>

- Reject package builds that would include key material. [#200](https://github.com/b7n0de/proofbundle/pull/200).
- Fix shell interpolation of Action inputs in this source tree. [#235](https://github.com/b7n0de/proofbundle/pull/235).
- Revise CI queue handling at four points. [#202](https://github.com/b7n0de/proofbundle/pull/202).
- Correct CI change records and time budget figures. [#203](https://github.com/b7n0de/proofbundle/pull/203).
- Handle queue entries that produce no required check. [#204](https://github.com/b7n0de/proofbundle/pull/204).
- Run the complete set of budget assertions. [#205](https://github.com/b7n0de/proofbundle/pull/205).
- Refresh the conformance ratchet baseline. [#206](https://github.com/b7n0de/proofbundle/pull/206).
- Bind the baseline case count to tests. [#208](https://github.com/b7n0de/proofbundle/pull/208).
- Test the ADR 0008 rule as a property. [#210](https://github.com/b7n0de/proofbundle/pull/210).
- Fix pinned Rust formatting and clippy checks. [#211](https://github.com/b7n0de/proofbundle/pull/211).
- Name required checks that no workflow can produce. [#213](https://github.com/b7n0de/proofbundle/pull/213).
- Distinguish skipped checks from executed checks. [#214](https://github.com/b7n0de/proofbundle/pull/214).
- Bind marked PR titles to a release scope entry. [#215](https://github.com/b7n0de/proofbundle/pull/215).
- Evaluate check reachability on the live pull request. [#219](https://github.com/b7n0de/proofbundle/pull/219).
- Run the full test matrix on repository pull requests. [#220](https://github.com/b7n0de/proofbundle/pull/220).
- Add a required check collector that always reports. [#222](https://github.com/b7n0de/proofbundle/pull/222).
- Declare both required collector contexts. [#225](https://github.com/b7n0de/proofbundle/pull/225).
- Check whether required contexts exist on the current head. [#230](https://github.com/b7n0de/proofbundle/pull/230).
- Run the English text gate against the requested tree. [#234](https://github.com/b7n0de/proofbundle/pull/234).

</details>

<details>
<summary>Audit and evidence · 12 pull requests</summary>

- Add findings register object classes and evidence binding tests. [#198](https://github.com/b7n0de/proofbundle/pull/198).
- Document register extraction rules for Migration 1A. [#218](https://github.com/b7n0de/proofbundle/pull/218).
- Report PASS, FAIL and NOT_MEASURED separately. [#221](https://github.com/b7n0de/proofbundle/pull/221).
- Assign identifiers to three residual risk entries. [#228](https://github.com/b7n0de/proofbundle/pull/228).
- Derive three published figures from the tree. [#232](https://github.com/b7n0de/proofbundle/pull/232).
- Record the agent review receipt for PR 236. [#237](https://github.com/b7n0de/proofbundle/pull/237).
- Add a carrier for a promised register entry. [#238](https://github.com/b7n0de/proofbundle/pull/238).
- Run the pre-tag audit between two clean tree measurements. [#239](https://github.com/b7n0de/proofbundle/pull/239).
- Record seven signed review reply receipts. [#240](https://github.com/b7n0de/proofbundle/pull/240).
- Document readiness and the closing audit that was not run. [#241](https://github.com/b7n0de/proofbundle/pull/241).
- Make the register test assert its specific claim. [#243](https://github.com/b7n0de/proofbundle/pull/243).
- Record owner-signed pre-tag receipt and readiness evidence. [#244](https://github.com/b7n0de/proofbundle/pull/244).

</details>

<details>
<summary>Documentation and interoperability · 11 pull requests</summary>

- Remeasure five Cedulon mapping cells. [#188](https://github.com/b7n0de/proofbundle/pull/188).
- Document the Cedulon refusal fixture and its implications. [#189](https://github.com/b7n0de/proofbundle/pull/189).
- Document the release scope and research programme. [#197](https://github.com/b7n0de/proofbundle/pull/197).
- Consolidate the contributor identity mapping. [#201](https://github.com/b7n0de/proofbundle/pull/201).
- Update the SCITT mapping to architecture draft 05. [#207](https://github.com/b7n0de/proofbundle/pull/207).
- Correct four CPB draft claims against their evidence. [#212](https://github.com/b7n0de/proofbundle/pull/212).
- Record two Merkle roots from two document interpretations. [#226](https://github.com/b7n0de/proofbundle/pull/226).
- Update the research coverage record after CAP-1 landed. [#227](https://github.com/b7n0de/proofbundle/pull/227).
- Document the shipped Merkle interpretation with vectors. [#229](https://github.com/b7n0de/proofbundle/pull/229).
- Limit 6.1.0 to the cut and defer the remaining scope to 6.2.0. [#233](https://github.com/b7n0de/proofbundle/pull/233).
- Remove duplicated and outdated README release notes. [#236](https://github.com/b7n0de/proofbundle/pull/236).

</details>

<details>
<summary>Dependencies · 3 pull requests</summary>

- Update the supported inspect-ai requirement. [#195](https://github.com/b7n0de/proofbundle/pull/195).
- Update two GitHub Actions dependencies. [#196](https://github.com/b7n0de/proofbundle/pull/196).
- Update three GitHub Actions dependencies. [#217](https://github.com/b7n0de/proofbundle/pull/217).

</details>

## Contributors

Thanks to [@b7n0de](https://github.com/b7n0de) and [@dependabot](https://github.com/apps/dependabot).

[Full comparison v6.0.0...v6.1.0](https://github.com/b7n0de/proofbundle/compare/v6.0.0...v6.1.0)
