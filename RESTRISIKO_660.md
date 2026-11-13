# Residual risk, release 6.6.0

This file records findings for the 6.6.0 release and their stated status. It does not claim that the release is free of defects. Earlier findings and their recorded status remain documented in [the residual-risk record of 6.5.0](RESTRISIKO_650.md) and the records before it.

Each line names where it comes from, a file and its lines in the tree of this release.

## The record of 6.5.0 in this release

The findings that stay open after 6.5.0 are listed in [the 6.5.0 record](RESTRISIKO_650.md). This record does not measure them again. Where a line of the 6.6.0 changelog touches one of them, its state stays as the 6.5.0 record gives it until a measurement on the release candidate records another one here.

The 6.5.0 record names `EXPIRED-RECEIPT-OUTSIDE-POLICY-EXITS-3-01` (RESTRISIKO_650.md lines 15 to 19). The 6.6.0 scope row PR507 says that the decision receipt contract now states the order of the exit codes of `decision verify` (docs/release_scope/6.6.0.md line 21). Whether that closes the entry is not measured here.

The 6.5.0 record also names `PIN-CASE-RED-FROM-TAG-UNTIL-PIN-COMMIT-01` (RESTRISIKO_650.md line 23). That window closed when pull request 494, which moves the plugin's pins to 6.5.0, was merged into main on 2026-11-08, and the register of this release records the entry as closed.

## Open after this release

### The 24-hour soak runs beside the release

Row C6.3 of the audit matrix, the full 24-hour soak, is informative since this release and does not withhold readiness; C6.2, the short soak on the same artefact, stays release-deciding (CHANGELOG.md line 26). The short soak at the 6.6.0 release candidate, row C6.2, had not reported when this record was written. Until the 24-hour run reports, it remains a named residual risk of this release, as in RESTRISIKO_650.md line 13.

### decision verify and outcome verify are not a complete implementation of the draft

`decision verify` and `outcome verify` take the inputs of the offline verification of draft-gruszka-audit-decision-receipts, and the draft's stricter field rules stay a named limit (docs/release_scope/6.6.0.md line 16). Without an input its check is not performed, and Section 3.1 requires the expected `executor.id` and, for Case 1, the approval record bytes, so a pass without them is not a pass of the draft's procedure (docs/NON_CLAIMS.md lines 87 to 95). Even with every input supplied, a receipt the draft rejects can pass them (docs/NON_CLAIMS.md lines 97 to 99). The measured examples, not a complete list:

- an evaluation time before `decidedAt` outside Case 1 (docs/NON_CLAIMS.md lines 101 to 103);
- a `decisionType` other than `preActionAuthorization`, an audience entry that is no non-empty string, and a JSON null inside `decision.obligations` or inside an outcome's `validity.audience` (docs/NON_CLAIMS.md lines 104 to 106);
- a declined decision without `validity.expiresAt` with the declined case (docs/NON_CLAIMS.md lines 107 to 108);
- timestamps with more than six fraction digits or second 60 in a field read only for its RFC 3339 form, such as `recordedAt` (docs/NON_CLAIMS.md lines 109 to 112);
- an evaluation time with a fraction of a second, since `--verification-time` takes a whole past second (docs/NON_CLAIMS.md lines 113 to 114; CHANGELOG.md line 22).

### executor.id is attested only where a Trust Pack names it

A Trust Pack key attests only the `executor.id` values its `executorIds` name; a key entry without `executorIds` binds no identifier and says so with `EXECUTOR_ID_NOT_BOUND` (docs/release_scope/6.6.0.md line 17). Without `executorIds` an anchored executor key can still write any `executor.id`, and even a named identifier is a permission the pack grants to the key, not proof that the signer is that executor or observed its effect (docs/NON_CLAIMS.md lines 70 to 76). A trust policy for `executor.id` other than the relying party's own statement stays outside (docs/NON_CLAIMS.md lines 115 to 119).

### Honouring an approval at most once stays with the relying party

proofbundle reads a supplied consumption state and never writes it. Marking an approval consumed durably, and keeping the state, stay with the relying party; a pass says only that the approval identity is not in the state given (docs/NON_CLAIMS.md lines 120 to 122; CHANGELOG.md line 21).

### The Rust verifier differs in two places

- `pb_verify_rs` still reads an abbreviated long option as argparse with `allow_abbrev=True` does. CROSS_IMPLEMENTATION_REPORT.md names this difference R3, and the Rust verifier follows as an item of its own (docs/release_scope/6.6.0.md line 18; CROSS_IMPLEMENTATION_REPORT.md lines 116 to 120).
- `pb_verify_rs` applies the rule of B22 as the three Python commands do, but does not apply the structure check of its type to an attached receipt. CROSS_IMPLEMENTATION_REPORT.md names this difference R4, and the Rust verifier follows as an item of its own (CHANGELOG.md line 40; CROSS_IMPLEMENTATION_REPORT.md lines 122 to 133).

### proofbundle scitt match is experimental

`proofbundle scitt match` is EXPERIMENTAL. It reports `sig_valid` as not evaluated, because it does not apply rule 2 of Section 6 of draft-gruszka-scitt-statement-identification-03; `WholeBytes` is a local experimental scheme; input the strict CBOR reader does not read gets no verdict (docs/release_scope/6.6.0.md line 19; CHANGELOG.md line 19).

### What the producer rules do not cover

- The rule that a producer writes only a signer's output of 64 bytes covers the Ed25519 producers. The ML-DSA signatures of `cosign_checkpoint_mldsa` and `pqsig.sign_mldsa` are not part of it (CHANGELOG.md line 66).
- `emit_bundle` applies the structural budget of `verify_bundle` before it signs. The byte limit of a serialized file is not part of this check (CHANGELOG.md line 64).
- `sign_trust_pack` does not sign with a `hybrid-ed25519-mldsa65` key. It writes one signature per key, and `verify_trust_pack` counts a hybrid key only with both legs, so the producer refuses such a signer before anything is signed, also one the other signers would not need. A pack may still declare a hybrid key that does not sign; where its signature must count, the pack is built with both legs outside the producer (CHANGELOG.md line 84).

### Three findings of the deep gate at c71eeb12 stay open

The deep gate at c71eeb12 confirmed five counterexamples in its first iteration. Two are fixed before the tag (CHANGELOG.md lines 42 and 84). By the owner's choice on that run, the three below stay open for the first cycle after the tag. Each gives the same result at c71eeb12, at c3472f6f and at v6.5.0, so none came with 6.6.0:

- `present_with_key_binding` signs a KB-JWT presentation with an empty `aud` or an empty `nonce` (src/proofbundle/sdjwt_issue.py line 401), which `verify_key_binding` refuses as "KB-JWT aud missing or not a single string" and "KB-JWT nonce missing" (src/proofbundle/kbjwt.py lines 255 and 258). The producer gives out what its own verifier refuses; the verifier refuses it.
- `verify_trace_record` reports an unknown JWS header member of 300 characters as a path of 307 characters in `unknown_fields`, past the bound of 257 characters that its other reported paths keep, because this one path is built without that bound (src/proofbundle/adapters/trace_record.py line 923). The token is refused.
- `measure_vector_set` accepts a manifest whose named case is itself a link to a directory the manifest does not name, and measures the files of that directory (src/proofbundle/verifier_block.py line 349); a link below a named case is refused.

Their severity under the rule that P0 and P1 are reserved for the wheel on PyPI is being read a third time, because the lens and the release author read it differently; a P0 or P1 among them goes to the owner before the tag.

### Pre-tag receipts of earlier releases

The receipt library now refuses a member outside the nine signed fields, `signature` and `signer_pubkey`. The receipt of 5.0.0 carries such a member, and the gate of this release, run against the v5.0.0 tree, rejects it; the gate of the v5.0.0 tag still verifies it. Because the gate source changes, a receipt of 5.1.0 or later bound to an earlier gate reads as `other_tree` (CHANGELOG.md line 76).

### main may fail the plugin pin case from the tag until the pin commit

Expected from the rule the test states, not measured. `tests/test_plugin_pin_is_the_newest_release.py` accepts pins to the preceding release only while the clone holds no tag of the version of the tree (lines 9 to 22). The plugins pin 6.5.0 in the tree of this release (`plugins/proofbundle/server/proofbundle_mcp.py`, landed with pull request 494). Once the tag v6.6.0 stands, the same window as in RESTRISIKO_650.md line 23 would open until the commit that moves the pins. By the owner choice of 2026-11-12, plugin 0.4.1 follows the main tag, so the plugins keep pinning 6.5.0 until 6.6.0 is on PyPI and this window is open by design. Register entry `PIN-CASE-RED-FROM-TAG-UNTIL-PIN-COMMIT-02`.

### Repository tools

- The release workflows pin the build frontend and the build backend through `PIP_CONSTRAINT` and `.github/build-constraints.txt`, unchanged since 6.5.0 (`git diff --stat v6.5.0 82411560 -- .github/build-constraints.txt .github/workflows/release.yml` printed nothing, exit 0). The limits RESTRISIKO_650.md line 27 names stay: only the setuptools version is read back from the built wheel, the pins name versions, not hashes, and the Python interpreter of the build is not pinned.

### Not measured at this snapshot

The findings register in this tree is signed for version `6.6.0` (audit_artifacts/findings_register_361.json, field `version`). The deep gate ran at d8881edc, and its four findings are fixed in pull request 519 (CHANGELOG.md lines 40, 42, 54 and 68). It ran again at c3472f6f and ended in its first iteration with seven findings: six are fixed as classes with their neighbours (CHANGELOG.md lines 80 to 90), and the seventh names the new `executorIds` member of a Trust Pack key, the format extension of this release (CHANGELOG.md line 44). It ran a third time at c71eeb12, the head with those fixes, and ended in its first iteration with five findings: two are fixed (CHANGELOG.md lines 42 and 84), and three stay open as named above. The deep gate at the head that carries these two fixes, the canonical mutation run and the pre-tag audit have not run when this record was written. Their findings are recorded here before the tag.

## What 6.6.0 does not claim

The negative list of docs/NON_CLAIMS.md stands for this release; 6.6.0 changes its point on `executor.id` and the section on the steps of the decision receipt draft, as above. A receipt does not prove the semantic truth of a result, fairness, safety, generalization, the right threshold or metric, or that a model or dataset is what its name suggests (lines 20 to 34). It does not replace an audit, in-toto, SLSA or a transparency log (lines 36 to 42). A verified decision receipt is not an authorization token and does not prove that a decision was correct or that an action happened (lines 51 to 64). A verified enclave Attestation Result does not prove that the enclave is genuine (lines 126 to 129).

## What this file does not say

It does not say that the findings above are the only open ones. A finding that is not listed here is not shown to be absent.
