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

## Where proofbundle sits (fairly)

proofbundle is the **standards-native, offline receipt** of an eval or test *run*, auto-emitted via the
framework's own plugin API. It is complementary to its neighbours: [ai-audit-trail](https://pypi.org/project/ai-audit-trail/)
records **runtime** agent Decision Receipts (FastAPI / LangChain / MCP, ISO 42001) — a different layer;
[ValiChord](https://github.com/topeuph-ai/ValiChord) builds attestation bundles from inspect_ai logs
**post-hoc** (its v1 library is unsigned — JCS + SHA-256 Merkle + HMAC; signatures are v2 scope). proofbundle's angle is the **opt-in auto-emit via the native
plugin** (an inspect_ai hook + a pytest11 plugin) plus the standards stack (Ed25519 + RFC 6962 + SD-JWT +
in-toto). Honest scope: it attests authenticity + integrity of the run, not the correctness of the
computation.
