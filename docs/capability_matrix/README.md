# Capability and release matrix

Which capability a user gets from the published package, and which exists only on main. The v6.1.0
wheel and sdist as PyPI serves them and the main branch are inventoried separately, and every cell
names the version and the commit it was measured at. The matrix states what is present and how the
project labels it; it does not rate the quality of any capability, and a "published" cell is not a
promise beyond what [COMPATIBILITY.md](../../COMPATIBILITY.md) makes.

The data is [`matrix.json`](matrix.json), written by
[`tools/capability_matrix/measure.py`](../../tools/capability_matrix/measure.py). The two tables below
are rendered from that file by the same script; a test holds them to it.

## How a cell is measured

- **The artifacts.** The wheel and the sdist of 6.1.0 are downloaded from PyPI, and their SHA-256 is
  compared with the digest PyPI states for them. Every package file in the wheel is compared byte for
  byte with the same file at the tag `v6.1.0`.
- **Presence.** A capability is present when its package modules, its console subcommands and its entry
  points are all found: in the wheel for the release column, at the main commit for the main column. A
  capability that lives only in the repository (the Rust verifier, the GitHub Action) is looked up at the
  tag and at main.
- **Label.** The project's own words for the capability are read at the tag and at main, from the file the
  row names (the predicate inventory, COMPATIBILITY.md, README.md, INTEGRATIONS.md or CHANGELOG.md). A
  present capability whose label is not found stops the measurement; its status is then not measured.
- **Status.** Derived, never set by hand: `experimental` when the label says experimental, `published`
  otherwise; `main only` when present on main and absent from the release; `planned` when present on a
  named branch only; `from elsewhere` when another project provides it and the docs point there;
  `absent` in the release column of a main-only or planned row. A capability the wheel lacks while the
  sdist (its files) or the tag carries it has no status in this vocabulary, and the measurement stops.
- **Channel.** How a user gets it: the PyPI wheel, a git tag of this repository, the repository only
  (built from source), or another project.
- **Changed since v6.1.0.** `git diff --shortstat` between the tag and main over the capability's files.

## Why not an existing list

[`docs/version_truth_list.md`](../version_truth_list.md) answers a different question: where the version
number is written and which of those places a gate compares. It has no notion of a capability and of its
presence in an artifact, so it cannot say what 6.1.0 contains. A `site-data.json` does not exist in this
repository (`git ls-files` finds none, measured at `0ace3039`).

## The matrix

<!-- matrix: written by tools/capability_matrix/measure.py -->

| capability | channel | v6.1.0 (tag `v6.1.0`, PyPI) | main `0ace3039` | changed since v6.1.0 |
|---|---|---|---|---|
| Decision receipt (decision-receipt/v0.1) | PyPI wheel | published — shipped (2.1.0) | published | 1 file changed, 8 insertions(+), 4 deletions(-) |
| Action outcome (action-outcome/v0.1) | PyPI wheel | experimental — EXPERIMENTAL (3.2.0) | experimental | 1 file changed, 7 insertions(+), 3 deletions(-) |
| Hugging Face Community Evals export (verifyToken, .eval_results entry) | PyPI wheel | published — Hugging Face Community Evals (`.eval_results/*.yaml`, v1.4) | published | 1 file changed, 69 insertions(+), 18 deletions(-) |
| EAT bridge (TEE Attestation Result, verify-enclave) | PyPI wheel | experimental — the `[experimental]` extra — the TEE-attestation bridge, see | experimental | 1 file changed, 2 insertions(+), 2 deletions(-) |
| Rust second verifier (pb_verify_rs) | repository only (built from source) | experimental — Experimental in 6.0.0 and advisory only: agreement on recorded vectors, no conformance promise; own milestone 6.1; parity registry: 5 COVERED, 2 PARTIAL, 61 PENDING of 68 surfaces | experimental — The Rust cross verifier is experimental and advisory.; parity registry: 5 COVERED, 3 PARTIAL, 63 PENDING of 71 surfaces | 1 file changed, 1463 insertions(+), 173 deletions(-) |
| Inspect lifecycle hook (inspect_ai entry point) | PyPI wheel | published — inspect_ai (end-of-task hook) | published | no change |
| pytest plugin (pytest11 entry point) | PyPI wheel | published — pytest (pytest11 plugin) | published | no change |
| GitHub Action (action/action.yml) | git tag v1.0.0 (the docs pin it; the release's file differs from it: 1 file changed, 42 insertions(+), 2 deletions(-)) | published — A composite action is prepared under `action/action.yml` (SHA-pinned). Usage: | published | no change |
| SLSA build provenance over a receipt | another project | from elsewhere — Optional, complementary — a GitHub-anchored SLSA provenance *over* the receipt (the receipt attests the | from elsewhere | — |
| promptfoo adapter (results.json) | PyPI wheel | published — promptfoo (results.json adapter, v1.4) | published | no change |
| lm-evaluation-harness adapter (results_*.json) | PyPI wheel | published — lm-evaluation-harness (results_*.json adapter, v0.6; sample-count provenance since v3.7.0) | published | no change |
| Inspect log adapter (read_eval_log) | PyPI wheel | published — inspect_ai (end-of-task hook) | published | no change |
| Every Eval Ever converter (from_eee_dataset) | PyPI wheel | published — Every Eval Ever converter (`proofbundle.adapters.from_eee_dataset`): reads an EEE v0.2.2 aggregate | published | no change |
| AGT MCP tool-call receipt verifier (adapters.agt_receipt) | main tree only, in no release | absent | main only — (`src/proofbundle/adapters/agt_receipt.py`). Verifies an AGT MCP tool-call receipt without AGT | — |
| SCITT receipts (scitt-ccf/v1 reader) | branch feat/640-scitt-anker only | absent | planned (branch `feat/640-scitt-anker` at `531e2564`) | — |

<!-- end of matrix -->

## A new user, in a fresh environment

A new virtual environment, the wheel installed with its `[eval]` extra (the extra's dependencies from
PyPI), then: sign a payload, verify it, verify a copy whose signed payload has one character changed, and
run the built-in demo. Once with the wheel from PyPI, once with a wheel built from the main commit.

<!-- fresh environment: written by tools/capability_matrix/measure.py -->

| wheel | step | exit | first line of output |
|---|---|---|---|
| proofbundle-6.1.0-py3-none-any.whl (PyPI) | `proofbundle --version` | 0 | proofbundle 6.1.0 |
| proofbundle-6.1.0-py3-none-any.whl (PyPI) | `proofbundle emit --payload-file payload.txt --out receipt.json --new-key signer.key` | 0 | wrote receipt.json |
| proofbundle-6.1.0-py3-none-any.whl (PyPI) | `proofbundle verify receipt.json` | 0 | [PASS] ed25519-signature: payload signed by stated key |
| proofbundle-6.1.0-py3-none-any.whl (PyPI) | `proofbundle verify tampered.json` | 1 | [FAIL] ed25519-signature: invalid signature (tampered: `payload_b64`, first character 'Y' -> 'B') |
| proofbundle-6.1.0-py3-none-any.whl (PyPI) | `proofbundle demo` | 0 | proofbundle offline demo — in memory, no files, no network |
| proofbundle-6.1.0-py3-none-any.whl (built from 0ace3039) | `proofbundle --version` | 0 | proofbundle 6.1.0 |
| proofbundle-6.1.0-py3-none-any.whl (built from 0ace3039) | `proofbundle emit --payload-file payload.txt --out receipt.json --new-key signer.key` | 0 | wrote receipt.json |
| proofbundle-6.1.0-py3-none-any.whl (built from 0ace3039) | `proofbundle verify receipt.json` | 0 | [PASS] ed25519-signature: payload signed by stated key |
| proofbundle-6.1.0-py3-none-any.whl (built from 0ace3039) | `proofbundle verify tampered.json` | 1 | [FAIL] ed25519-signature: invalid signature (tampered: `payload_b64`, first character 'Y' -> 'B') |
| proofbundle-6.1.0-py3-none-any.whl (built from 0ace3039) | `proofbundle demo` | 0 | proofbundle offline demo — in memory, no files, no network |

<!-- end of fresh environment -->

## Two findings the measurement made

1. **A wheel built from main is also called 6.1.0.** `pyproject.toml` on main still says `6.1.0`, so the
   wheel built from `0ace3039` is `proofbundle-6.1.0-py3-none-any.whl` like the published one, with other
   bytes (its SHA-256 is in `matrix.json`) and with `proofbundle/adapters/agt_receipt.py` inside, a module
   that is in no release. The version string alone does not tell the two apart. Whoever reports a result
   from a source build names the commit, not only the version.
2. **The docs pin the GitHub Action at `v1.0.0`.** INTEGRATIONS.md shows
   `uses: b7n0de/proofbundle/action@v1.0.0`. The action file at that tag differs from the one at `v6.1.0`
   and on main (one file, 42 lines added, 2 removed): the later file passes both inputs through the
   environment and checks their shape before pip sees them; at `v1.0.0` they are spliced into the shell
   script. A reader following the docs runs the older file. Which tag the docs should pin is the
   maintainer's decision; this matrix only records the difference.

## What this does not measure

- The quality, security or correctness of any capability; only presence, label and change.
- Behaviour on other Python versions than the one named in `matrix.json`, or on other operating systems.
- Whether a capability's documentation is complete. The label is read, not reviewed.
- The GitHub Action as it runs on GitHub; its file is compared, not executed.
- Releases before 6.1.0.
