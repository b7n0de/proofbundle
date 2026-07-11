# Integrations — a signed receipt of your eval or test run, automatically

proofbundle can auto-emit a signed, offline-verifiable receipt of an **inspect_ai eval** or a **pytest run**
via each framework's native plugin API. Both are **opt-in**: they emit only when you explicitly turn them on
(the `PROOFBUNDLE_EMIT=1` environment variable, or a flag) — never silently, and never failing your run.

## inspect_ai (end-of-task hook)

```bash
pip install "proofbundle[inspect,eval]"
PROOFBUNDLE_EMIT=1 inspect eval task.py --model mockllm/model
```

Installed via the `inspect_ai` entry-point group; the hook fires at end of task and writes a receipt. Needs
`inspect_ai>=0.3.112` (the generic lifecycle hooks). Config via env: `PROOFBUNDLE_KEY` (a 32-byte Ed25519
seed; else an ephemeral key, with a warning), `PROOFBUNDLE_OUT` (file or directory), `PROOFBUNDLE_METRIC` /
`PROOFBUNDLE_COMPARATOR` / `PROOFBUNDLE_THRESHOLD` (the pass/fail assertion; default `>= 0`). The model and
dataset stay salted commitments.

## pytest (pytest11 plugin)

```bash
pip install "proofbundle[pytest,eval]"
PROOFBUNDLE_EMIT=1 pytest            # or: pytest --proofbundle
```

Installed via the `pytest11` entry-point; `pytest_terminal_summary` emits a receipt of the run (metric
`pass_rate`, with the per-outcome counts and exit status in provenance) from `terminalreporter.stats`.

## GitHub Action

A composite action is prepared under [`action/action.yml`](action/action.yml) (SHA-pinned). Usage:

```yaml
- uses: b7n0de/proofbundle/action@v1.0.0
  with:
    command: "verify receipt.json"
```

**Optional, complementary** — a GitHub-anchored SLSA provenance *over* the receipt (the receipt attests the
*run*, `attest-build-provenance` attests the *build*). Add to the caller job:

```yaml
permissions: { id-token: write, attestations: write, contents: read }
steps:
  - uses: b7n0de/proofbundle/action@v1.0.0
    with: { command: "emit-eval --claim claim.json --out receipt.json --new-key signer.key" }
  - uses: actions/attest-build-provenance@<full-sha>  # v3
    with: { subject-path: receipt.json }
  - uses: actions/upload-artifact@<full-sha>          # v7
    with: { name: proofbundle-receipt, path: receipt.json }
```

## promptfoo (results.json adapter, v1.4)

promptfoo already exports one JSON per run (`promptfoo eval -o results.json`, summary version 3).
The adapter is file-based — no promptfoo dependency:

```python
from proofbundle.adapters import from_promptfoo_results
from proofbundle.evalclaim import emit_eval_receipt
from proofbundle import generate_signer

claim, salts = from_promptfoo_results("results.json", comparator=">=",
                                      threshold="0.900000", timestamp="2026-07-02T14:00:00Z")
receipt = emit_eval_receipt(claim, generate_signer())
```

Metric: `pass_rate` = successes / (successes + failures + errors) from `results.stats`, as a
fixed-point decimal. The model commitment pins the sorted provider-id set; the dataset commitment
derives from the canonical `config.tests` JSON (the test suite IS the dataset). Legacy summary
v1/v2 files are rejected with a clear message — re-export with a current promptfoo. In CI this
composes with the GitHub Action: run promptfoo, emit the receipt, attach both to the run.

## Hugging Face Community Evals (`.eval_results/*.yaml`, v1.4)

HF's Community Evals accept per-benchmark result entries with an optional string `verifyToken`
("a signature that can be used to prove that evaluation is provably auditable and reproducible").
**Honest boundary:** the Hub's *verified badge* is granted server-side by HF (currently HF Jobs +
inspect-ai); that token format is not public, and proofbundle does not imitate it. What
proofbundle provides is a *self-contained, offline-verifiable* token — `pb1.` +
base64url(zlib(receipt JSON)) — that anyone can check without trusting the submitter:

```python
from proofbundle.hf_evals import to_eval_results_entry, eval_results_yaml, verify_receipt_token

entry = to_eval_results_entry(receipt, dataset_id="Idavidrein/gpqa", task_id="gpqa_diamond",
                              value=0.412, date="2026-07-02",
                              source_url="https://example.com/my-eval-traces")
open(".eval_results/proofbundle.yaml", "w").write(eval_results_yaml([entry]))

result, bundle = verify_receipt_token(entry["verifyToken"])   # offline, exit-code style .ok
```

CLI: `proofbundle hf-token receipt.json` emits the token; `proofbundle hf-token --verify <token>`
checks one. The entry builder is fail-closed (a non-verifying receipt is refused) and the YAML
emitter is a strict, purpose-built serializer (JSON-escaped scalars — a valid-YAML subset — so
dates and tokens can never be misparsed). Publishing a `value` is a disclosure decision the
caller makes; a receipt may withhold the exact score via SD-JWT.

## Where proofbundle sits (fairly)

proofbundle is the **standards-native, offline receipt** of an eval or test *run*, auto-emitted via the
framework's own plugin API. It is complementary to its neighbours: [ai-audit-trail](https://pypi.org/project/ai-audit-trail/)
records **runtime** agent Decision Receipts (FastAPI / LangChain / MCP, ISO 42001) — a different layer;
[ValiChord](https://github.com/ValiChord/ValiChord) builds attestation bundles from inspect_ai logs
**post-hoc** (its v1 library is unsigned — JCS + SHA-256 Merkle + HMAC; signatures are v2 scope). proofbundle's angle is the **opt-in auto-emit via the native
plugin** (an inspect_ai hook + a pytest11 plugin) plus the standards stack (Ed25519 + RFC 6962 + SD-JWT +
in-toto). Honest scope: it attests authenticity + integrity of the run, not the correctness of the
computation.
