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

### The Rust verifier differs in three places

- `pb_verify_rs` still reads an abbreviated long option as argparse with `allow_abbrev=True` does. CROSS_IMPLEMENTATION_REPORT.md names this difference R3, and the Rust verifier follows as an item of its own (docs/release_scope/6.6.0.md line 18; CROSS_IMPLEMENTATION_REPORT.md lines 116 to 120).
- `pb_verify_rs` applies the rule of B22 as the three Python commands do, but does not apply the structure check of its type to an attached receipt. CROSS_IMPLEMENTATION_REPORT.md names this difference R4, and the Rust verifier follows as an item of its own (CHANGELOG.md line 40; CROSS_IMPLEMENTATION_REPORT.md lines 122 to 133).
- `pb_verify_rs verify-dsse` reads its envelope and the first key and leaves every further word unread: with a valid envelope and key it exits 0 also when a second key, `--with-related` with `--related-pub`, or any other word follows, measured at the head of this release with the binary built from its source. CROSS_IMPLEMENTATION_REPORT.md says the Rust verifier refuses an option it does not read instead of dropping it (lines 103 to 106); this command does not. The pairing check of `--related-pub` holds in both relation commands (CHANGELOG.md line 42). A review of this release named `verify-trust-pack-threshold` and two SCITT commands as the same form, from their source, not measured. Under the rule for this release a difference in the Rust cross-verifier is a register row; it is open for the first cycle after the tag.

### proofbundle scitt match is experimental

`proofbundle scitt match` is EXPERIMENTAL. It reports `sig_valid` as not evaluated, because it does not apply rule 2 of Section 6 of draft-gruszka-scitt-statement-identification-03; `WholeBytes` is a local experimental scheme; input the strict CBOR reader does not read gets no verdict (docs/release_scope/6.6.0.md line 19; CHANGELOG.md line 19).

### What the producer rules do not cover

- The rule that a producer writes only a signer's output of 64 bytes covers the Ed25519 producers. The ML-DSA signatures of `cosign_checkpoint_mldsa` and `pqsig.sign_mldsa` are not part of it (CHANGELOG.md line 66).
- `emit_bundle` applies the structural budget of `verify_bundle` before it signs. The byte limit of a serialized file is not part of this check (CHANGELOG.md line 64).
- `sign_trust_pack` does not sign with a `hybrid-ed25519-mldsa65` key. It writes one signature per key, and `verify_trust_pack` counts a hybrid key only with both legs, so the producer refuses such a signer before anything is signed, also one the other signers would not need. A pack may still declare a hybrid key that does not sign; where its signature must count, the pack is built with both legs outside the producer (CHANGELOG.md line 84).

### Three findings of the deep gate at c71eeb12 stay open

The deep gate at c71eeb12 confirmed five counterexamples in its first iteration. Two are fixed before the tag (CHANGELOG.md lines 42 and 84). By the owner's choice on that run, the three below stay open for the first cycle after the tag. Each gives the same result at c71eeb12, at c3472f6f and at v6.5.0, so none came with 6.6.0:

- `present_with_key_binding` signs a KB-JWT presentation with an empty `aud` or an empty `nonce` (src/proofbundle/sdjwt_issue.py line 401), which `verify_key_binding` refuses as "KB-JWT aud missing or not a single string" and "KB-JWT nonce missing" (src/proofbundle/kbjwt.py lines 255 and 258). The producer gives out what its own verifier refuses; the verifier refuses it.
- `verify_trace_record` reports an unknown JWS header member of 300 characters as a path of 307 characters in `unknown_fields`, past the bound of 257 characters that its other reported paths keep, because this one path is built without that bound (src/proofbundle/adapters/trace_record.py line 923). The token is refused. Two readings of it stand: the lens read the bound as one of the shipped verifier for every reported path; the shipped source and CHANGELOG.md line 46 declare 257 characters only for the paths of the structure check (src/proofbundle/adapters/trace_record.py lines 176 to 187), and the header reader documents its entries as `("header.<name>", False)` with the whole name (lines 891 to 892). Beside it, not measured: the message of the same check names those members without shortening them (line 925).
- `measure_vector_set` accepts a manifest whose named case is itself a link to a directory the manifest does not name, and measures the files of that directory (src/proofbundle/verifier_block.py line 349); a link below a named case is refused.

Under the rule that P0 and P1 are reserved for the wheel on PyPI, the lens and the release author read their severity differently, so a third reader, who knew neither reading, staged them: all three P2. None changes a verdict, an exit code, a declared bound or a security property of the shipped verifier.

### Two findings of a reading of the targets at c71eeb12

A separate reading of five targets at c71eeb12, before the next deep gate, measured two findings, both P3 and both with the same result at c3472f6f and at v6.5.0:

- `verify_outcome_receipt` with a Trust Pack anchored by its digest alone trusts an outcome under a second key entry that carries the same public key as an entry with `executorIds` but no `executorIds` of its own: `executor_role_trusted` is true for an `executor.id` the first entry does not name, with the warning `EXECUTOR_ID_NOT_BOUND` (src/proofbundle/outcome.py line 1219). `validate_trust_pack_predicate` refuses such a pack because the two entries share key material (src/proofbundle/trust_pack.py line 280), and the digest anchor does not run it. The limit above, that a key entry without `executorIds` binds no identifier, covers the result; only the holders of the root keys can build such a pack.
- `outcome verify` without `--expected-decision-ref` and without `--decision` ends with exit 0 and the sentence "This proves who signed what happened, bound to the referenced decision." (src/proofbundle/cli.py line 3225), although no binding to a decision was checked. Its exit code and verdict are right; the sentence says more than was checked, the class of the closing sentence the deep gate at c3472f6f found (CHANGELOG.md line 82). Every closing sentence against what its command checked is an item for the first cycle after the tag.

### A neighbour of the save_signer fix in the guard plugin

The deep gate at 41959070 measured that `save_signer` set mode 0600 only on a file it created, followed a symbolic link at its path and let `--new-key` replace an existing key file; this release fixes it (CHANGELOG.md line 92). The key tool of the guard plugin's done check runs `save_signer` of the pinned proofbundle 6.5.0 only when `os.path.exists` reports the path absent (plugins/proofbundle-guard/hooks/proofbundle_gate.py lines 23204 to 23214). `os.path.exists` follows a link, so for a dangling link at the key path the 6.5.0 function writes the seed into the link's target. This is read from the source and not run through the tool. The 6.5.0 function opens the path with the same call as the one at 41959070 (src/proofbundle/emit.py line 85 at v6.5.0, line 87 at 41959070), where the new test measures the link followed. It ends with the commit that moves the plugin pins to 6.6.0, as in the pin case below. P3.

### The core layer gate does not see the descriptor forms of file operations

The core layer gate names the file operations it forbids in the core (scripts/core_layer_gate.py lines 74 to 83), but not their descriptor forms such as `os.fchmod`, `os.fsync`, `os.fchown`, `os.ftruncate` and `os.close`. The write path of `save_signer` uses `os.fchmod`, `os.fsync` and `os.close` (src/proofbundle/emit.py lines 122, 129 and 136), so the exception list does not name them; its entry `os.chmod` covers only the fallback for a platform without `fchmod` (line 124). No other module under src/proofbundle uses one of these forms at this snapshot. The seven entries that the save_signer fix added to scripts/core_layer_exceptions.json carry their reason. The class is closed after the tag, with a counter-case for each form. P2.

### Findings of the deep gate at 41959070

The deep gate ran one round at 41959070, the head with the two fixes of its run at c71eeb12 (CHANGELOG.md lines 42 and 84), under the owner's end rule that only a confirmed P0 or P1 stops a release: six lenses read all eleven targets once, and one more lens re-read the save_signer fix at 0c67aa6b. No finding is P0 or P1. Every finding below was confirmed by running its lens's script at 41959070, or at 0c67aa6b for the re-read, and run again at c71eeb12 and v6.5.0; each line says where it shows. The save_signer finding is fixed in this release (CHANGELOG.md line 92), and its neighbour in the guard plugin is named above. Every lens named files it had read only in part, so by its own rule the run gave no verdict; the owner judged its coverage sufficient for 6.6.0. The lens of the foreign family released targets Z1, Z2, Z7, Z8 and Z9 in its first reading only, and several of the line ranges it cites for them end past the end of their file at 41959070; for that lens these five targets count as partly read. The owner chose to record this rather than to have the five targets read again before the tag. Each finding below is an item for 6.7.0.

Producers that give out what their own verifier or reader refuses:

- `hf_evals.receipt_token` compresses the bundle without a size check (src/proofbundle/hf_evals.py lines 56 to 92), so it packs a token that `verify_receipt_token` refuses at its decompression cap of 262,144 bytes (lines 43 and 167 to 170). P2; the same at c71eeb12 and v6.5.0.
- `build_initial_sequence`, `renew_timestamp` and `renew_hashtree` apply no count budget (src/proofbundle/renewal.py lines 751, 836 and 874): a sequence over 2,000 data digests is built, and `verify_sequence` refuses it for budget (lines 1017 to 1023 and 1088 to 1094). P2 by a third reading; the same at c71eeb12 and v6.5.0.
- `cosign_checkpoint` (src/proofbundle/checkpoint.py line 783) appends a 513th signature line, which `verify_checkpoint` refuses; the cap of 512 lines (line 551) is applied to the note it reads, not to the note it writes. P3 by a third reading; the same at c71eeb12 and v6.5.0.
- `present_with_key_binding` signs an `aud` or a `nonce` that is a list or a number (src/proofbundle/sdjwt_issue.py line 401), which `verify_key_binding` refuses because it is not a non-empty string (src/proofbundle/kbjwt.py lines 253 to 258). It is the neighbour of the empty-string finding above. P3 by a third reading; the same at c71eeb12 and v6.5.0.
- The producer preflight judges an integer by its number of digits (src/proofbundle/_strict_json.py lines 298 to 303), while `loads_strict` refuses a long integer for its form (lines 93 to 104). `sign_envelope` therefore refuses a body with a 2,500-digit integer as `BudgetExceeded("int_bits")` (src/proofbundle/dsse.py lines 201 to 206), where the verifier's reason would be its form. P3; the same at c71eeb12, and not at v6.5.0.
- `issue_status_list_token` and the enclave issuer now apply only that budget preflight (src/proofbundle/statuslist.py lines 379 to 385, src/proofbundle/experimental/enclave.py lines 250 to 256, src/proofbundle/_strict_json.py line 315), so they sign an `iat` of 2**53 that their verifiers refuse for its form, where c71eeb12 refused it. CHANGELOG.md line 84 makes this change on purpose; the lenses recorded it against the wording of the targets, not as a defect. P3.
- `sign_envelope` (src/proofbundle/dsse.py line 95) signs an envelope whose keyid has 999,000 characters outside the Basic Multilingual Plane: `verify_envelope` accepts it as a dict, and its file form is over the reader's `input_bytes`. Reached only through the library. P3; the same at c71eeb12 and v6.5.0.
- `save_signer` writes 57 bytes for an Ed448 key, which `load_signer` refuses, although its docstring says it writes a 32-byte Ed25519 seed (src/proofbundle/emit.py lines 76, 98 and 155). Reached only through the library. P3; the same at 41959070, c71eeb12 and v6.5.0.

`proofbundle emit` and its key file:

- `proofbundle emit` writes the `--new-key` file (src/proofbundle/cli.py line 1281, through line 505) before it reads `--payload-file` (line 1286). When `--payload-file` names that file, as the same path, another spelling of it or a dangling link to it, the bundle carries the fresh private seed as its signed payload; `emit` exits 0 and `verify` passes. `--key K --payload-file K` signs the key's own seed in the same way. This release closes only the form in which the file already exists. P2; measured at 0c67aa6b, 41959070, c71eeb12 and v6.5.0.
- `--new-key K --out K` exits 0, and K then holds the bundle, so the seed that signed it is gone (src/proofbundle/cli.py lines 1281 and 1295). SECURITY.md lines 31 to 32 say that every `--new-key` option refuses an existing path "so a key is not replaced by accident"; here the command replaces the key it has just written. P3; the same at 41959070, c71eeb12 and v6.5.0.
- The refusal of an existing `--new-key` path prints the path without the control-character filter of `_err` (src/proofbundle/cli.py lines 510 to 512, against lines 141 to 145), so a path with line breaks writes lines of its own to stderr, one of which can read as the success line of a key that was not written. The exit code is 2. It came with the save_signer fix of this release. P3.

The Rust cross-verifier:

- `pb_verify_rs verify-relation` does not apply the predicate checks of a primary decision receipt: they run only under `if statement_mode` (tools/pb_verify_rs/src/main.rs line 2534), the comment at lines 2516 to 2521 names them Python-only, and the function returns exit 0 at line 2679. For the same bytes `decision verify` exits 2 and `verify-relation` exits 0 when the predicate lacks a required member such as `decision` or `decisionId` (src/proofbundle/decision.py lines 58 to 61 and 258 to 261), when its `predicateType` is foreign, and when the receipt has expired: `validity.expiresAt` (src/proofbundle/decision.py lines 1167 to 1180) does not occur in main.rs. CROSS_IMPLEMENTATION_REPORT.md lists full decision predicate validation as pending (lines 135 to 140); none of these forms is one of R1 to R4. Four lenses and the release author staged it P3 and the lens of the foreign family P2, so a third reader, who knew neither reading, staged the class: P2. The key as a word after the path, which one lens named beside it, is not part of the class; it is the residual CROSS_IMPLEMENTATION_REPORT.md lines 112 to 113 already name, P3. The same at c71eeb12 and v6.5.0. Not measured: the primary predicate of an outcome receipt under the same command.

Closed sets and the pre-tag readers:

- `measure_vector_set` neither refuses nor measures an unnamed case directory reached through a directory link: its walk leaves out every linked directory (src/proofbundle/verifier_block.py lines 245 to 246), and the scan for unnamed cases uses that walk (lines 338 to 345), so the digest equals that of the corpus without it. P2; the same at c71eeb12, and at v6.5.0 the script ended before its check.
- `measure_build` leaves `__pycache__` out of its closed-set check (src/proofbundle/verifier_block.py lines 85, 157 and 192 to 199), so a forged `.pyc` that carries the source's time and size is executed in place of the source while the measurement stays the same. P2; the same at c71eeb12 and v6.5.0.
- docs/VERIFIER_BLOCK.md lines 139 to 140 say that a case directory the manifest does not list is not part of the corpus and not part of the digest; since this release `measure_vector_set` refuses such a directory when it carries `case.json` (src/proofbundle/verifier_block.py lines 334 to 345). P3; the same at c71eeb12, and not at v6.5.0.
- `receipt_json` (scripts/pre_tag_receipt_lib.py lines 612 to 630) raises `RecursionError` for a deeply nested receipt on CPython 3.10 and 3.11, and neither of its callers catches it (scripts/verify_pre_tag_receipt.py lines 1352 to 1353, scripts/pre_tag_audit_gate.py lines 335 to 336): both end with a traceback and exit 1, not with an accept. P3; measured with CPython 3.10, the same at c71eeb12 and v6.5.0.

### Pre-tag receipts of earlier releases

The receipt library now refuses a member outside the nine signed fields, `signature` and `signer_pubkey`. The receipt of 5.0.0 carries such a member, and the gate of this release, run against the v5.0.0 tree, rejects it; the gate of the v5.0.0 tag still verifies it. Because the gate source changes, a receipt of 5.1.0 or later bound to an earlier gate reads as `other_tree` (CHANGELOG.md line 76).

### main may fail the plugin pin case from the tag until the pin commit

Expected from the rule the test states, not measured. `tests/test_plugin_pin_is_the_newest_release.py` accepts pins to the preceding release only while the clone holds no tag of the version of the tree (lines 9 to 22). The plugins pin 6.5.0 in the tree of this release (`plugins/proofbundle/server/proofbundle_mcp.py`, landed with pull request 494). Once the tag v6.6.0 stands, the same window as in RESTRISIKO_650.md line 23 would open until the commit that moves the pins. By the owner choice of 2026-11-12, plugin 0.4.1 follows the main tag, so the plugins keep pinning 6.5.0 until 6.6.0 is on PyPI and this window is open by design. Register entry `PIN-CASE-RED-FROM-TAG-UNTIL-PIN-COMMIT-02`.

### Repository tools

- The release workflows pin the build frontend and the build backend through `PIP_CONSTRAINT` and `.github/build-constraints.txt`, unchanged since 6.5.0 (`git diff --stat v6.5.0 82411560 -- .github/build-constraints.txt .github/workflows/release.yml` printed nothing, exit 0). The limits RESTRISIKO_650.md line 27 names stay: only the setuptools version is read back from the built wheel, the pins name versions, not hashes, and the Python interpreter of the build is not pinned.

### Not measured at this snapshot

The findings register in this tree is signed for version `6.6.0` (audit_artifacts/findings_register_361.json, field `version`). The deep gate ran at d8881edc, and its four findings are fixed in pull request 519 (CHANGELOG.md lines 40, 42, 54 and 68). It ran again at c3472f6f and ended in its first iteration with seven findings: six are fixed as classes with their neighbours (CHANGELOG.md lines 80 to 90), and the seventh names the new `executorIds` member of a Trust Pack key, the format extension of this release (CHANGELOG.md line 44). It ran a third time at c71eeb12, the head with those fixes, and ended in its first iteration with five findings: two are fixed (CHANGELOG.md lines 42 and 84), and three stay open as named above. It ran a fourth time at 41959070, the head that carries these two fixes, as one round under the owner's end rule; its findings are named above. The canonical mutation run and the pre-tag audit have not run when this record was written. Their findings are recorded here before the tag.

## What 6.6.0 does not claim

The negative list of docs/NON_CLAIMS.md stands for this release; 6.6.0 changes its point on `executor.id` and the section on the steps of the decision receipt draft, as above. A receipt does not prove the semantic truth of a result, fairness, safety, generalization, the right threshold or metric, or that a model or dataset is what its name suggests (lines 20 to 34). It does not replace an audit, in-toto, SLSA or a transparency log (lines 36 to 42). A verified decision receipt is not an authorization token and does not prove that a decision was correct or that an action happened (lines 51 to 64). A verified enclave Attestation Result does not prove that the enclave is genuine (lines 126 to 129).

## What this file does not say

It does not say that the findings above are the only open ones. A finding that is not listed here is not shown to be absent.
