Stricter input checks at verification boundaries, hardened Ed25519 trust-anchor handling, and offline AGT receipt verification. **Beta. Locations of the closing records are listed under Audit status.**

[Changelog](https://github.com/b7n0de/proofbundle/blob/5c65e536e6ad6923dfed5f0bb7996abbadc7a9b4/CHANGELOG.md) · [Known limitations](https://github.com/b7n0de/proofbundle/blob/5c65e536e6ad6923dfed5f0bb7996abbadc7a9b4/RESTRISIKO_620.md) · [Release scope](https://github.com/b7n0de/proofbundle/blob/5c65e536e6ad6923dfed5f0bb7996abbadc7a9b4/docs/release_scope/6.2.0.md)

## Findings addressed in 6.2.0

6.2.0 closes five findings in the released 6.0.0 and 6.1.0, eight further findings of one class in pull request 312, six release-preparation findings in pull request 313, and two findings of the last gate round before the closing one in pull request 311, both present in the released 6.0.0 and 6.1.0. The group of pull request 313 includes a pre-release regression. The rows below summarize affected surfaces, representative effects and fixes; their measurement baselines are named separately where they differ.

| Finding | Affected | Effect | Fixed by |
|---|---|---|---|
| **Truthy non-boolean callback results promoted verification evidence** | 6.0.0, 6.1.0; Python API resolver and registered-anchor-verifier paths | For example, an evidence resolver returning `"false"` lifted a digest from `REFERENCE_WELL_FORMED` to `CONTENT_RESOLVED` | Boolean success decisions now require exact `True`; documented receiver-key results remain supported ([#293](https://github.com/b7n0de/proofbundle/pull/293), which carries [#291](https://github.com/b7n0de/proofbundle/pull/291)) |
| **A low-order Ed25519 key as a trusted key** | 6.0.0, 6.1.0; `verify_ed25519`, `dsse.verify_envelope` | With the identity point supplied as the key, `R = identity, S = 0` verifies without a private key | Trust-anchor paths now reject weak keys, including `dsse.verify_envelope`; bare `verify_ed25519` and the bundle's in-band key retain the §4a profile ([#280](https://github.com/b7n0de/proofbundle/pull/280), [#293](https://github.com/b7n0de/proofbundle/pull/293)) |
| **A low-order Ed25519 key as the holder key of an SD-JWT key binding** | 6.0.0, 6.1.0; CLI included | an SD-JWT bound to the identity point and a Key Binding JWT signed by nobody (R = identity, S = 0) gave "key binding valid" | 6.2.0: `issue_sd_jwt` raises `ValueError`, its documented refusal for a bad holder key, and the verifier refuses the presentation ([#280](https://github.com/b7n0de/proofbundle/pull/280), [#293](https://github.com/b7n0de/proofbundle/pull/293)) |
| **A related map that says it is empty hid an attached retraction** | 6.0.0, 6.1.0; Python API | With `reject_superseded` enabled, a dict subclass reporting length 0 hid a verified attached retraction. `verify_decision_receipt` and `verify_outcome_receipt` returned `ok=True`; the same entries in a plain dict returned `ok=False` | 6.2.0 reads the map by what it stores ([#300](https://github.com/b7n0de/proofbundle/pull/300)) |
| **An edge's `declaredAt` accepted non-ASCII decimal digits** | 6.0.0, 6.1.0 in `validate_relationships`; signed CLI comparison measured on main `86671552` | On that main head, the package emitted such a signed edge; `decision verify` returned exit 0 with `ok=True`, while `pb_verify_rs verify-relation` refused the same bytes with exit 2 | The edge's `declaredAt` now accepts ASCII digits only; both verifiers refuse the tested non-ASCII cases ([#300](https://github.com/b7n0de/proofbundle/pull/300)) |
| **Eight findings involved caller-controlled inputs** | 6.0.0, 6.1.0; Python API | For example, `verify_decision_receipt` reported `signer_trusted`, `ok` and `safeForAutomation` True for a receipt signed by an untrusted key | 6.2.0 uses a fixed reading of the affected inputs, or refuses their types ([#312](https://github.com/b7n0de/proofbundle/pull/312)) |
| **Wrong-typed policy fields, callback mutation and malformed containers affected verification** | 6.0.0, 6.1.0 for these cases; Python API, plus malformed falsy `--anchors` input on the CLI | Python API example: a wrong-typed `trusted_decision_makers` let an untrusted signer pass. On the CLI, malformed falsy `anchors` were read as absent | 6.2.0 shares policy-field validation, rejects the affected malformed containers, and snapshots affected inputs before callbacks ([#313](https://github.com/b7n0de/proofbundle/pull/313)) |
| **An attached target's subject state outside the four words of its resolver was read as present** | 6.0.0, 6.1.0; Python API | A target labelled `AMBIGUOUS` or `multiple` bound a declared `targetSubjectDigest` to its first subject, and `verify_decision_receipt`, `verify_outcome_receipt` and `verify_relation_statement` returned lineage `VERIFIED` and `ok=True` | When binding a declared `targetSubjectDigest`, states other than `None` must be `present`, `absent`, `ambiguous` or `malformed`; other values fail on direct edges and attached hops. Missing or `None` states remain inferred from the digest ([#311](https://github.com/b7n0de/proofbundle/pull/311)) |
| **A restricting CLI option given an empty value was read as absent** | 6.0.0, 6.1.0; CLI | Nine command/option combinations, including `verify --policy ''`, `verify --anchor-type ''` and `decision verify --anchors ''`, exited 0 when their empty values were ignored | These options are read with `is not None`; empty paths and an empty nonce are refused with exit 2, while `verify --anchor-type ''` exits 3 ([#311](https://github.com/b7n0de/proofbundle/pull/311)) |

The measurements behind each row are in [RESTRISIKO_620.md](https://github.com/b7n0de/proofbundle/blob/5c65e536e6ad6923dfed5f0bb7996abbadc7a9b4/RESTRISIKO_620.md). A security advisory is a separate outward act.

## What changed

| Area | Change | Evidence |
|---|---|---|
| **Verify boundary** | The affected verify paths reject malformed inputs or read fixed copies of their stored values. | [#300](https://github.com/b7n0de/proofbundle/pull/300) · [#312](https://github.com/b7n0de/proofbundle/pull/312) · [#313](https://github.com/b7n0de/proofbundle/pull/313) · [Detail](https://github.com/b7n0de/proofbundle/blob/5c65e536e6ad6923dfed5f0bb7996abbadc7a9b4/CHANGELOG.md) |
| **Keys** | Ed25519 trust-anchor paths reject low-order and non-canonical keys; the core §4a verification profile remains unchanged. | [#280](https://github.com/b7n0de/proofbundle/pull/280) · [#293](https://github.com/b7n0de/proofbundle/pull/293) · [Detail](https://github.com/b7n0de/proofbundle/blob/5c65e536e6ad6923dfed5f0bb7996abbadc7a9b4/CHANGELOG.md) |
| **Callbacks** | Truthy non-boolean callback results no longer grant success; documented key-returning resolver results remain supported. | [#293](https://github.com/b7n0de/proofbundle/pull/293) · [Detail](https://github.com/b7n0de/proofbundle/blob/5c65e536e6ad6923dfed5f0bb7996abbadc7a9b4/CHANGELOG.md) |
| **Relation timestamps** | An edge's `declaredAt` takes ASCII digits only, as the Rust verifier does. | [#300](https://github.com/b7n0de/proofbundle/pull/300) · [Detail](https://github.com/b7n0de/proofbundle/blob/5c65e536e6ad6923dfed5f0bb7996abbadc7a9b4/CHANGELOG.md) |
| **AGT receipts** | Offline verification of Agent Governance Toolkit (AGT) governance receipts. | [#255](https://github.com/b7n0de/proofbundle/pull/255) · [Detail](https://github.com/b7n0de/proofbundle/blob/5c65e536e6ad6923dfed5f0bb7996abbadc7a9b4/CHANGELOG.md) |
| **Build timestamp** | The release build's default timestamp is the commit time of the first commit `git log` finds from HEAD back that changes a path outside `audit_artifacts/` and `release_notes/`. It skips commits confined to those two paths and a merge whose tree outside them equals one of its parents. 6.1.0 used HEAD's commit time. | [#311](https://github.com/b7n0de/proofbundle/pull/311) · [Detail](https://github.com/b7n0de/proofbundle/blob/5c65e536e6ad6923dfed5f0bb7996abbadc7a9b4/CHANGELOG.md) |

## Before upgrading

- **Stricter verify boundary.** Some inputs accepted by 6.1.0 are now refused. Review the affected API and input rules before upgrading. [Details](https://github.com/b7n0de/proofbundle/blob/5c65e536e6ad6923dfed5f0bb7996abbadc7a9b4/CHANGELOG.md).
- **Python API and CLI.** The CLI passes no callbacks and builds plain values; of the findings of pull request 313 it reaches only a falsy `anchors` from `--anchors <file>`. A restricting option given an empty value, such as `--policy ''`, is refused or applied where 6.1.0 exited 0. [Details](https://github.com/b7n0de/proofbundle/blob/5c65e536e6ad6923dfed5f0bb7996abbadc7a9b4/CHANGELOG.md).
- **Keys a producer writes.** Ed25519 holder-key, log-vkey and witness-vkey producers reject the weak encodings their verifiers reject. [Details](https://github.com/b7n0de/proofbundle/blob/5c65e536e6ad6923dfed5f0bb7996abbadc7a9b4/CHANGELOG.md).

<details>
<summary>Audit status and known limitations</summary>

These notes describe the package-source commit linked above; the closing record identifies the head actually checked. In the `v6.2.0` tagged tree, consult `gate_zeile.head` and `gate_zeile.verdict` in `audit_artifacts/360/fuzz_soak_latest.json` and `audit_artifacts/360/rust_differential_matrix.json`; the separate `audit_artifacts/620/pre_tag_receipt_v6.2.0.json` records its own audit command and result. A short soak does not satisfy C6.3's full 24-hour requirement; a full run after the tag is planned.

[Residual risks](https://github.com/b7n0de/proofbundle/blob/5c65e536e6ad6923dfed5f0bb7996abbadc7a9b4/RESTRISIKO_620.md) · [README status](https://github.com/b7n0de/proofbundle/blob/5c65e536e6ad6923dfed5f0bb7996abbadc7a9b4/README.md#current-release)

The published package and a passed closing audit are separate facts.

</details>

## All changes

45 pull requests, grouped by area. Shortened descriptions link to the original discussions.

<details>
<summary>Verifier and receipt formats · 16 pull requests</summary>

- Apply the loader's field rules, reject malformed containers, and protect affected inputs from callback mutation. [#313](https://github.com/b7n0de/proofbundle/pull/313).
- Use one stored reading for the affected verify inputs. [#312](https://github.com/b7n0de/proofbundle/pull/312).
- Parse the bytes a signature covers, and hold commitment patterns at the verify boundary. [#300](https://github.com/b7n0de/proofbundle/pull/300).
- Extend small-order key refusal to the affected carrier and producer paths. [#293](https://github.com/b7n0de/proofbundle/pull/293).
- Refuse low-order and non-canonical Ed25519 keys that a verifier relies on. [#280](https://github.com/b7n0de/proofbundle/pull/280).
- Give an ES256 signature one identity and never rewrite a foreign signer's bytes. [#288](https://github.com/b7n0de/proofbundle/pull/288).
- Make the Rust policy reader judge the relations section like load_policy. [#284](https://github.com/b7n0de/proofbundle/pull/284).
- Treat an empty container as malformed in both verifiers, with a named reason. [#272](https://github.com/b7n0de/proofbundle/pull/272).
- Require each zlib field to contain one complete stream with no trailing bytes. [#283](https://github.com/b7n0de/proofbundle/pull/283).
- Require the in-toto Statement type, fail on missing promised sdist paths, and cap OTS proofs. [#286](https://github.com/b7n0de/proofbundle/pull/286).
- Refuse a bundle that names another format, instead of judging it invalid. [#268](https://github.com/b7n0de/proofbundle/pull/268).
- Require a verdict in the verdict field at five public exporters. [#257](https://github.com/b7n0de/proofbundle/pull/257).
- Split the SD-JWT refusals into three disjoint forms. [#260](https://github.com/b7n0de/proofbundle/pull/260).
- Tell an absent contentRootAlg from a present but unusable one. [#254](https://github.com/b7n0de/proofbundle/pull/254).
- Count distinct CAP-1 units, validate each element and run the alias check on both branches. [#252](https://github.com/b7n0de/proofbundle/pull/252).
- Verify AGT governance receipts offline. [#255](https://github.com/b7n0de/proofbundle/pull/255).

</details>

<details>
<summary>Build, CI and test infrastructure · 13 pull requests</summary>

- Prepare 6.2.0: version, release block, notes renderer and register producer. [#311](https://github.com/b7n0de/proofbundle/pull/311).
- Render the release body from a versioned source. [#256](https://github.com/b7n0de/proofbundle/pull/256).
- Run each mutant against the test files that reach it, and count only confirmed kills. [#285](https://github.com/b7n0de/proofbundle/pull/285).
- Cap the mutation gate's test child at 6 GiB of address space. [#289](https://github.com/b7n0de/proofbundle/pull/289).
- Degrade a bare install to clean skips, and run the gate that claims it. [#253](https://github.com/b7n0de/proofbundle/pull/253).
- Choose a test file list by its project, not by its sort order. [#264](https://github.com/b7n0de/proofbundle/pull/264).
- Treat a fallen high-water mark in the tests as a refuted premise. [#259](https://github.com/b7n0de/proofbundle/pull/259).
- Test that a fail-closed verdict is False, not merely not True. [#273](https://github.com/b7n0de/proofbundle/pull/273).
- Add three negative cases on a real receipt for a Codex answer. [#276](https://github.com/b7n0de/proofbundle/pull/276).
- Add an advisory check that measures the Codex review loop. [#275](https://github.com/b7n0de/proofbundle/pull/275).
- Read each file once per run in the English gate. [#281](https://github.com/b7n0de/proofbundle/pull/281).
- Cover every curve and the signing call in the ECDSA inventory test. [#295](https://github.com/b7n0de/proofbundle/pull/295).
- Generate the house form for pull requests and issues from data. [#261](https://github.com/b7n0de/proofbundle/pull/261).

</details>

<details>
<summary>Audit and evidence · 6 pull requests</summary>

- Guard every caller of the pre-tag cleanliness gate, with the Rust dependency audit. [#249](https://github.com/b7n0de/proofbundle/pull/249).
- Let a pre-tag verifier judge a tree without installing it. [#274](https://github.com/b7n0de/proofbundle/pull/274).
- Pin only the current release in the README, and run the gate on prose. [#266](https://github.com/b7n0de/proofbundle/pull/266).
- Bind the PR 259 receipt to the comment as GitHub stores it. [#265](https://github.com/b7n0de/proofbundle/pull/265).
- Check a declared error marker against both implementations. [#270](https://github.com/b7n0de/proofbundle/pull/270).
- State in the parity registry what the verifier does when no policy is named. [#271](https://github.com/b7n0de/proofbundle/pull/271).

</details>

<details>
<summary>Documentation and interoperability · 8 pull requests</summary>

- Cut 6.2.0 to main and its frozen fixes, and move the rest to 6.3.0. [#294](https://github.com/b7n0de/proofbundle/pull/294).
- Recast the 6.2.0 scope against its four outcomes and open 6.3.0. [#251](https://github.com/b7n0de/proofbundle/pull/251).
- Rewrite the README from the current-release block on, for 6.1.0. [#245](https://github.com/b7n0de/proofbundle/pull/245).
- Add two readings of the SCITT CCF receipt draft and check the checker with planted defects. [#258](https://github.com/b7n0de/proofbundle/pull/258).
- Compare SCITT vector bytes rather than lengths, and add a digest-checked fallback for the unavailable pinned source. [#263](https://github.com/b7n0de/proofbundle/pull/263).
- Record the ToBeSigned inputs per SCITT vector case. [#267](https://github.com/b7n0de/proofbundle/pull/267).
- Correct the SCITT vectors' attribution to Nicholas Templeman. [#269](https://github.com/b7n0de/proofbundle/pull/269).
- Give every site value its source and every gap its reason. [#262](https://github.com/b7n0de/proofbundle/pull/262).

</details>

<details>
<summary>Dependencies · 2 pull requests</summary>

- Raise the inspect-ai ceiling to 0.3.266. [#246](https://github.com/b7n0de/proofbundle/pull/246).
- Update three GitHub Actions dependencies. [#247](https://github.com/b7n0de/proofbundle/pull/247).

</details>

## Contributors

Thanks to [@b7n0de](https://github.com/b7n0de) and [@dependabot](https://github.com/apps/dependabot).

[Full comparison v6.1.0...v6.2.0](https://github.com/b7n0de/proofbundle/compare/v6.1.0...v6.2.0)
