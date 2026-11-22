# Residual risk, release 6.6.1

This file records findings for the 6.6.1 release and their stated status. It does not claim that the release is free of defects. Earlier findings and their recorded status remain documented in [the residual-risk record of 6.6.0](RESTRISIKO_660.md) and the records before it.

Each line names where it comes from, a file and its lines in the tree of this release.

## The record of 6.6.0 in this release

6.6.1 is a patch release. The findings that stay open after 6.6.0 are listed in [the 6.6.0 record](RESTRISIKO_660.md), and this record does not measure them again. Each keeps the state that record gives it until a measurement on the release candidate records another one here. The findings that record assigns to the first cycle after its tag and to 6.7.0 (RESTRISIKO_660.md lines 43, 57, 70, 78 and 82) are not part of 6.6.1.

One entry changes. The 6.6.0 record names `PIN-CASE-RED-FROM-TAG-UNTIL-PIN-COMMIT-02` (RESTRISIKO_660.md line 118). That window closed when pull request 533, which moves the plugins' pins to 6.6.0, was merged into main on 2026-11-17 (plugins/proofbundle/server/proofbundle_mcp.py line 3), and the register of this release records the entry as closed.

Two entries stand beside code that 6.6.1 changes. Neither is measured again here:

- A Trust Pack anchored by its digest alone, in which a second key entry carries the public key of an entry with `executorIds` (RESTRISIKO_660.md line 69). 6.6.1 widens the validator's rule from the public key to every key part (CHANGELOG.md line 20). The 6.6.0 record says that the digest anchor does not run the validator; whether that still holds is not measured here.
- `pb_verify_rs verify-trust-pack-threshold`, which a review of 6.6.0 named from its source as a command that leaves further words unread (RESTRISIKO_660.md line 43). 6.6.1 changes which packs the command refuses (CHANGELOG.md lines 32 and 33). Whether it refuses a word it does not read is not measured here.

## Open after this release

### Releases through 6.6.0 accept a signature under a weak own key

6.6.1 refuses a bundle whose own Ed25519 key is a point of small order or a non-canonical encoding, in `proofbundle verify`, in `show-eval` and in `pb_verify_rs verify-bundle` (CHANGELOG.md line 19; SPEC.md line 131, section 4b). A release is not changed after it is published: without a trust policy, 6.6.0 and the releases before it read a signature made with no private key under such a key as `[PASS] ed25519-signature: payload signed by stated key` with exit 0, as that CHANGELOG line describes. Their verdict says `SAFE_FOR_AUTOMATION: NO` and `POLICY: NOT_EVALUATED` there; the signature line alone says more than was shown. The finding concerns a key of small order or a non-canonical encoding; no forgery under an ordinary key was shown.

### The tree size and the leaf index of a bundle are stated, not signed

The signature of a bundle covers its payload. The root, the tree size and the leaf index of its `merkle` block are not under it (src/proofbundle/bundle.py lines 597 to 599), and one audit path verifies under a band of tree sizes (src/proofbundle/merkle.py lines 213 to 222). Since 6.6.1 `verify` says so where nothing binds the size: the inclusion line names a stated index and a stated tree size (src/proofbundle/bundle.py line 577), and `verify --json` carries `treeSizeExpectation.actualSource` (CHANGELOG.md lines 24 and 28). The verdict and the exit code do not change. A bundle without a matching `--expected-tree-size` and without a verified `--trusted-checkpoint` still passes, and its pass says that the key signed this payload and that the payload hashes to a leaf under the stated root. It does not say that the size or the index is that of a log.

### Findings of a reading of tree size and consistency at 19cadafc

A reading of the structures that carry a Merkle proof ran on 2026-11-21 at 19cadafc, three merges before the head this release was prepared on. One reader ran its probes, and they are not run again on the release candidate; the lines below are read in the tree of this release. The reader staged the findings by the usual reading of the levels, without a third reader. By the owner's choice of 2026-11-21 the first is closed first in 6.7.0; the others are items for 6.7.0.

- `evaluate_public_transparency` reports `CONSISTENCY` as `PASS` on the caller's word. With `requireConsistencyProof`, a bare `consistency_confirmed=True` gives `PASS` (src/proofbundle/public_transparency.py lines 393 to 394), and so does a typed `ConsistencyVerificationResult` whose `confirmed` is true and whose new side names the checkpoint (lines 374 to 383). `strict_consistency` refuses only the bare boolean (lines 387 to 392). The function computes no consistency proof (lines 234 to 236), and the old side of a typed result is compared with no state the caller holds. Under src/proofbundle nothing calls `merkle.verify_consistency`; it is exported (src/proofbundle/__init__.py lines 33 and 89). The module is marked EXPERIMENTAL (src/proofbundle/public_transparency.py line 1). P2.
- A policy's `merkle.trusted_roots` pins a root by its bytes, without a tree size (src/proofbundle/policy.py lines 1530 to 1536). Read, not measured with a probe. P3.
- `restore` of the Merkle accumulator restores an older state the same key signed and cannot tell two states of diverging histories apart. The module says so and leaves continuity to the caller (tools/merkle_accumulator/accumulator.py lines 38 to 42). P3.
- An RFC 9162 consistency proof does not fix its second tree size: for first sizes 1 to 16 and second sizes up to 32, 368 pairs verified under another second size. This is a property of the proof. It matters where the sizes do not come from a signed source. P3.
- `pb_verify_rs verify-scitt-consistency-receipt` takes no tree sizes and ends at best with `confirmed_without_tree_sizes`, and its verdict names the gap (tools/pb_verify_rs/src/scitt_consistency.rs lines 12 to 15 and 34). P3.

### The Rust verifier counts only Ed25519 root keys of a Trust Pack

`pb_verify_rs verify-trust-pack-threshold` now applies the role rules and the rule that a key part occurs in one key, and it still counts only Ed25519 root keys toward the threshold (CHANGELOG.md lines 32 and 33). `mldsa65` and hybrid root keys, `not_expired`, the version chain, the two-stage rotation and the full shape of the predicate stay with the Python verifier (CROSS_IMPLEMENTATION_REPORT.md lines 142 to 148). A reading of the signature verification paths on 2026-11-21 at bb018ea6 measured this on the built programs; the probe is not run again on the release candidate. For a pack with one root key at threshold 1, Python met the threshold for an `mldsa65` key and for a hybrid key, and the Rust verifier ended with `FAIL root_threshold_met=false signers=0 threshold=1 skipped_non_ed25519=1` and exit 1 (tools/pb_verify_rs/src/main.rs lines 1659 to 1663). The Rust verifier refuses here what Python accepts, and its output names the skipped key. P3. No release is set for ML-DSA in the Rust verifier. Register entry `RUST-TRUST-PACK-PQ-ROOT-NOT-COUNTED-01`.

### Findings of a reading of the signature verification paths at bb018ea6

A reading of the places that verify a signature ran on 2026-11-21 at bb018ea6, the last commit before this preparation. One reader ran its probes on the built programs, and they are not run again on the release candidate; the lines below are read in the tree of this release. The Trust Pack finding of that reading stands in the section above.

- An SD-JWT issuer that signs with ES256 passes in Python and fails in the Rust verifier. Python accepts `EdDSA` and `ES256` as issuer algorithms (src/proofbundle/sdjwt.py line 69); `pb_verify_rs verify-bundle` accepts only `EdDSA` (tools/pb_verify_rs/src/main.rs line 1063). Measured with one bundle: `proofbundle verify` ended with exit 0, and `pb_verify_rs verify-bundle` with `FAIL` and exit 1. The Rust verifier refuses here what Python accepts; in the fourteen cases of the probe it accepted nothing Python refused. The comparison of the two implementations lists the SD-JWT issuer signature among the parts the second one does not reproduce in full (CROSS_IMPLEMENTATION_REPORT.md line 149). P3, planned for 6.7.0. Register entry `RUST-SDJWT-ISSUER-ES256-REFUSED-01`.
- `proofbundle scitt match` checks the signature of a candidate with Ed25519, whatever algorithm its protected header names. The module is EXPERIMENTAL and says that nothing in it is a verify path (src/proofbundle/scitt_statement_id.py lines 1 and 5 to 6). It verifies the signature under the supplied key with Ed25519 and does not read the algorithm of the protected header (lines 226 to 231). Measured: a candidate whose header names -7 or -35 and whose signature is an Ed25519 signature under the supplied key reports `signature` as true, and a candidate with a real ES256 signature reports it as false. By the owner's choice of 2026-11-21 the fix follows in 6.7.0: the algorithm of the protected header has to match the key.

### Two caller flags put a property into a signed SVR

`intoto.svr_properties` and `export_svr_dsse` take `prereg_verified` and `anchor_verified` from the caller and verify neither an anchor nor a preregistration themselves (src/proofbundle/intoto.py lines 1997 to 2000 and 2088). Both docstrings call the two properties caller-attested (lines 1902 to 1907 and 2017 to 2020), and no other file under src/proofbundle names the two flags. Measured on 2026-11-22 on the preparation of this release, where that file is as it was at bb018ea6: for a receipt whose claim carries no anchor, `export_svr_dsse` with `anchor_verified=True` signed an SVR whose properties include `PROOFBUNDLE_ANCHOR_VALID`. With `prereg_verified=True` it signed `PROOFBUNDLE_PREREG_BOUND` when the claim carried a `prereg_sha256` and not without one; the function does not check that hash against a preregistration. Without the flags neither property appeared. By the owner's choice of 2026-11-22 this record names the finding without a register entry; it enters the register with 6.7.0, which closes it in a pull request of its own.

### Three cases from an outside reading of the own-key fix follow after the tag

An outside reading of pull request 544 gave three further cases and the correction of one docstring: a refused key gives out no verified metadata, and a matching root and tree size do not make a refused key good, in Python and in Rust. They were measured red at v6.6.0 and green on main, and a planted revert of the fix turned them red again. They close two gaps in the test coverage and change no behaviour, and they land as a pull request of their own after the tag. The tree of this release holds the fourteen encodings of the fix as fixtures (tests/fixtures/ed25519_small_order_inband/); the three cases are not in it.

### main may fail the plugin pin case from the tag until the pin commit

Expected from the rule the test states, not measured. `tests/test_plugin_pin_is_the_newest_release.py` accepts pins to the preceding release only while the clone holds no tag of the version of the tree (lines 16 to 22). The plugins pin 6.6.0 in the tree of this release (plugins/proofbundle/server/proofbundle_mcp.py line 3, landed with pull request 533). Once the tag v6.6.1 stands, the same window as in RESTRISIKO_660.md line 118 opens until the commit that moves the pins, a pull request of its own after 6.6.1 is on PyPI. Register entry `PIN-CASE-RED-FROM-TAG-UNTIL-PIN-COMMIT-03`.

### Repository tools

- The `pypi` environment admits only tags `v*` and has no required reviewer, so no further approval stands between the push of the tag and the upload: the tag push is the release decision (RELEASE.md lines 116 to 120).
- The release workflow stops before the build in two more places, when the audit output its signed receipt names is not a tracked file and when the tag does not fall in UTC on the date of its CHANGELOG section (CHANGELOG.md lines 29 and 35). The second check reads the tag, so it is not applicable before the tag exists; it runs in the workflow of the tag.
- The release workflows pin the build frontend and the build backend through `PIP_CONSTRAINT` and `.github/build-constraints.txt`; the constraints file is unchanged since 6.6.0 (`git diff --stat v6.6.0 bb018ea6 -- .github/build-constraints.txt` printed nothing, exit 0). The limits RESTRISIKO_660.md line 122 names stay.

### Not measured at this snapshot

The mutation run for 6.6.1 runs at bb018ea6, the last commit before this preparation, and not as one process. Sixty of the 118 operators run in four parts on the reference machine (`scripts/mutation_check.py --shard i/8`, parts 1 to 4). The other 58 run one operator each in separate containers (`--shard i/118`). There a start script outside this tree passes the build-host marker `JENKINS_URL` to the test runs, so the suite skips the 20 tests that are bound to the reference machine, 19 in tests/test_budget_kostenkurve.py (line 526 names the markers) and 1 in tests/test_structural_budget_reachability.py; `scripts/mutation_check.py` itself is unchanged. An operator that survives under the marker runs again on the reference machine without it, and that run decides. docs/PRE_TAG_AUDIT.md says that a tag is never cut on a sharded run alone (line 160); this run is sharded, by the owner's choices of 2026-11-21. The preparation changes no module that run mutates and no file under `tests/`; under `src` it changes the version line of `src/proofbundle/__init__.py`, which the full suite at the release candidate carries.

The run had not reported when this record was written, and its result is not recorded in this tree. By the owner's choice of 2026-11-22 it is stated in the message of the tag v6.6.1, as for 6.6.0, and a gap it finds stops the tag. The pre-tag audit runs on the release candidate when its signed receipt is produced (audit_artifacts/661/README.md), which is after this record.

## What 6.6.1 does not claim

The negative list of docs/NON_CLAIMS.md stands for this release as it stood for 6.6.0 (`git diff --stat v6.6.0 bb018ea6 -- docs/NON_CLAIMS.md` printed nothing, exit 0). A receipt does not prove the semantic truth of a result, fairness, safety, generalization, the right threshold or metric, or that a model or dataset is what its name suggests (lines 20 to 34). It does not replace an audit, in-toto, SLSA or a transparency log (lines 36 to 42). A verified decision receipt is not an authorization token and does not prove that a decision was correct or that an action happened (lines 51 to 64). A verified enclave Attestation Result does not prove that the enclave is genuine (lines 126 to 129).

## What this file does not say

It does not say that the findings above are the only open ones. A finding that is not listed here is not shown to be absent.
