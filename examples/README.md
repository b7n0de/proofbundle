# Examples

Each example is offline and self-contained. Run from a checkout with `PYTHONPATH=src python
examples/<file>` (or `make examples` to run all that need no optional extras). Expected tail is
`=> OK` / exit 0 unless noted.

| Example | What it shows | Extra needed |
|---|---|---|
| `make_example.py` | Emit a signed, Merkle-anchored bundle with throwaway keys; verify it | none |
| `lm_eval_receipt.py` | lm-evaluation-harness `results.json` → signed eval receipt (real fixture) | none |
| `eee_receipt.py` | Every Eval Ever aggregate JSON → signed receipt | none |
| `intoto_dsse_export.py` | Export a receipt as a DSSE-signed in-toto `test-result` statement | none |
| `checkpoint_example.py` | Sign a C2SP tlog-checkpoint over the Merkle root; verify it | none |
| `tlog_proof_example.py` | Build + verify a C2SP `.tlog-proof` with Ed25519 (and ML-DSA-44 if available) witnesses | none (`[pq]` enables the PQ witness) |
| `rekor_interop.py` | Verify a REAL Sigstore Rekor inclusion proof offline (committed fixture) | none |
| `persample_audit.py` | Per-sample Merkle receipt + forced-random-sample audit; a swapped sample is rejected | none |
| `inspect_receipt.py` | inspect_ai `.eval` log → signed receipt via the stable API | `[inspect]` + the binary fixture |
| `inspect_hook_example.py` | The opt-in end-of-task hook auto-emitting a receipt | `[inspect]` |
| `pytest_plugin_example.py` | The opt-in pytest plugin emitting a run receipt | `pytest` |

For the whole trust story with no checkout at all: `pip install proofbundle && proofbundle demo`
(honest receipt verifies, six tampers fail, a swapped sample is caught — see `docs/DEMO.md`).
