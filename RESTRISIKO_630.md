# Residual risk, release 6.3.0

This file records findings reported for the 6.3.0 release and their stated status. It does not claim that the release is free of defects. Earlier findings and their recorded status remain documented in [the earlier residual-risk record](RESTRISIKO_620.md).

## The defect search on the candidate

The candidate review examined commit `98b168b9` on 2026-10-12 for false positive verdicts within its stated scope. It reported ten finding classes rated P1, four additional P2 groups and no P0 findings. The maintainer assessed their release impact on 2026-10-12.

- The fixes for K1 and K2 are included in this release candidate through pull requests 346 and 347.
- K3 to K10 remain open outside the installed Python package, in repository tools, examples, checks and interoperability code. The review rated them P1; the maintainer assigned P2 during the release assessment. They are targeted for 6.3.1.
- Four additional P2 groups listed below are also targeted for 6.3.1 and are not included in the signed register. Some concern the installed package. These targets are planned follow-up work, not completed fixes.

## Fixed in this candidate

- **K1, descriptor digests were not always recomputed.** The unreleased eval-result v0.2 implementation could accept ResourceDescriptors whose `md5`, `sha3_224`, `sha512_224` or `sha512_256` digests did not match the supplied content, including descriptors in subject, model, dataset and evidence fields. The exporter could also emit these inconsistent descriptors. The fix uses one algorithm table for digest validation and content comparison. For these recognised algorithms, supplied content is checked against the digest, and a mismatch or an unavailable hash function causes rejection. Register entry `CODEX-630-K1`.
- **K2, a rounded pass rate decided the threshold.** The pytest plugin rounded the pass rate to six decimal places before comparing it with the threshold. With the `>=` comparator, two passes out of three therefore passed a threshold of `0.666667`. This candidate bases the verdict on exact test counts instead. Register entry `CODEX-630-K2`.

## Open, targeted for 6.3.1

- **K3, two readings of one object.** `tools/pilot/github_write_profile.py` reads the payload again after
  verification, so a mapping subtype can make a refused outcome read as accepted; the outer envelope of
  `tools/merkle_accumulator/accumulator.py` has the same class. Register entry `CODEX-630-K3`.
- **K4, the example checker trusts the key it checks.** `examples/verdict_contract/check_example.py` takes its
  pin from the directory it checks. Register entry `CODEX-630-K4`.
- **K5, a duplicate member is dropped before the strict check.** The same example checker parses the envelope with
  `json.loads`. Register entry `CODEX-630-K5`.
- **K6, an import alias read at the wrong point.** `scripts/core_layer_gate.py` resolves earlier calls against the
  last alias of a name. Register entry `CODEX-630-K6`.
- **K7, an empty coverage report passes.** `scripts/rust_parity_gate.py` takes `{}` as no evidence needed.
  Register entry `CODEX-630-K7`.
- **K8, one rendering, two verdicts.** The advisory pull-request form gate reads Markdown paragraphs as separate
  runs. Register entry `CODEX-630-K8`.
- **K9, an unknown scope member drops out.** `interop/acde_01/acde01/reconcile.py` filters a requested scope down to
  the population it knows. Register entry `CODEX-630-K9`.
- **K10, an equation taken from the report it checks.** `interop/acde_01/acde01/report_check.py` trusts
  `draft_equation_holds`. Register entry `CODEX-630-K10`.

## Additional P2 findings, targeted for 6.3.1

- `proofbundle intoto --verify` ignores the options that only apply when writing, and two benchmark renderers accept
  unknown options.
- The v0.2 shape check accepts non-ASCII digits in `evaluatedAt`, and the accumulator restores a signed empty state
  whose frontier is not a list.
- The prompt rule of the verdict-contract example asks for bare output while its parser accepts decoration.
- One memory test of the test-load guard fails on CPython 3.12.14 because both measurements give the same size.

## What this file does not say

It does not say that the search covered every path of the candidate; its report names what it did not measure, among
them the full suite, the mutation layer and the SCITT package, which needs `cbor2`.

## Found after the candidate review

- **Two trees that name a path twice can share one release digest.** `subject_tree_digest` in `scripts/pre_tag_receipt_lib.py` and `tree_digest` in `scripts/sign_readiness_artifact.py` accept a Git tree that names the same path twice and give the same digest for either order of the two entries, although `git show` and a checkout then read different content. The check on candidate `c2d189b6d32b0ae94874151edc1976f2890d295b` found no repeated paths among 2,217 tree entries. Before the pre-tag receipt is produced, the check for repeated paths must be recorded for the final release tree. Completion of the final pre-tag audit and receipt is not established by this page. This check addresses the reported duplicate-path case in the inspected tree; it does not establish a general guarantee that the receipt binds a unique interpretation of every possible tree. Refusing such trees in both functions is targeted for 6.3.1. This finding is not in the signed register.
- **Nine further findings from a class search for 6.3.1.** A search on `main` at `f6ea5cc3` on 2026-10-13 reported nine further instances of the error classes described above. The affected files are unchanged between 6.2.1 and the 6.3.0 preparation commit `718af92548eaa872d0ea893e328b7dfd23dc5d5d`. Two findings concern the installed package: the search reports that `verify_sdjwt_vc` and `verify_bundle` accept a presentation in which two committed disclosures give the same claim different values, and that a test-result statement with all three case lists missing passes validation and is accepted by `join_test_result` as `PASSED`; validation rejects the corresponding statement with empty lists. Three concern release tooling: `scripts/pre_tag_attestation.py` and `scripts/findings_register.py` parse JSON without rejecting duplicate member names before verification, keeping the last value, and the differential check in `scripts/audit_candidate_matrix.py` uses the signed report's agreement flags without recomputing them from its rows. The remaining four concern rereading artifact metadata after signature verification, parsing a readiness receipt without rejecting duplicate member names, accepting duplicate minimum-count members in a test manifest lock, and treating a missing lock file or an empty JSON object as zero minimum counts. The search proposed P1 for five findings and P2 for four; the maintainer has not yet assigned severity ratings to these nine findings. The findings register at preparation commit `718af92548eaa872d0ea893e328b7dfd23dc5d5d` was read with the strict parser and contained no duplicate JSON member names. This check concerns that register input only and does not resolve the parser findings. Fixes for all nine are targeted for 6.3.1. These findings are not in the signed register.
