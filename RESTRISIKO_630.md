# Residual risk, release 6.3.0

This file names what the defect search on the 6.3.0 candidate found and where each finding stands. It does not
claim that the release is defect free. The items that were open before this release stay in `RESTRISIKO_620.md`.

## The defect search on the candidate

Codex searched the candidate `98b168b9` on 2026-10-12 for false positive verdicts under a written contract and
reported ten classes it rated P1, four P2 findings and no P0. The owner's triage of 2026-10-12 decided:

- K1 and K2 lie in the installed package and are fixed before the tag.
- K3 to K10 lie outside the installed package, in tools, examples, gates of this repository and the interop
  reading. They move to 6.3.1 with severity P2 by that triage; the search rated them P1 under its contract.
- The four P2 findings move to 6.3.1 and are not register entries.

## Closed before the tag

- **K1, a digest the verifier did not recompute.** The eval-result v0.2 verifier accepted evidence whose
  `sha3_224`, `sha512_224` or `sha512_256` digest did not match the supplied content, because the shape table
  knew those algorithms and the content check did not. Register entry `CODEX-630-K1`.
- **K2, a rounded pass rate decided the threshold.** The pytest plugin rounded the pass rate to six decimals
  before comparing it with the threshold, so two of three tests passed a threshold of 0.666667. Register entry
  `CODEX-630-K2`.

## Open, moved to 6.3.1

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

## P2 findings, moved to 6.3.1

- `proofbundle intoto --verify` ignores the options that only apply when writing, and two benchmark renderers accept
  unknown options.
- The v0.2 shape check accepts non-ASCII digits in `evaluatedAt`, and the accumulator restores a signed empty state
  whose frontier is not a list.
- The prompt rule of the verdict-contract example asks for bare output while its parser accepts decoration.
- One memory test of the test-load guard fails on CPython 3.12.14 because both measurements give the same size.

## What this file does not say

It does not say that the search covered every path of the candidate; its report names what it did not measure, among
them the full suite, the mutation layer and the SCITT package, which needs `cbor2`.
