# Integrations — a signed receipt of your eval or test run, automatically

proofbundle can auto-emit a signed, offline-verifiable receipt of an **inspect_ai eval** or a **pytest run**
via each framework's native plugin API. Both are **opt-in**: they emit only when you explicitly turn them on
(the `PROOFBUNDLE_EMIT=1` environment variable, or a flag) — never silently, and never failing your run.

## inspect_ai (end-of-task hook)

```bash
pip install "proofbundle[inspect,eval]"
PROOFBUNDLE_EMIT=1 PROOFBUNDLE_THRESHOLD=0.9 inspect eval task.py --model mockllm/model
```

Installed via the `inspect_ai` entry-point group; when enabled, the hook can write a receipt at the end of a task.
The `inspect` extra installs `inspect_ai>=0.3.112,<=0.3.266`. Configure it through environment variables.
`PROOFBUNDLE_KEY` is a path to a file containing a 32-byte raw Ed25519 seed; when unset, signing uses an ephemeral
key with a warning. `PROOFBUNDLE_OUT` selects a file or directory. `PROOFBUNDLE_METRIC` selects the metric,
`PROOFBUNDLE_COMPARATOR` defaults to `>=`, and `PROOFBUNDLE_THRESHOLD` is required for receipt emission since
5.0.0, with no default. The model and dataset stay salted commitments.

## pytest (pytest11 plugin)

```bash
pip install "proofbundle[pytest,eval]"
PROOFBUNDLE_EMIT=1 PROOFBUNDLE_THRESHOLD=0.9 pytest     # or: PROOFBUNDLE_THRESHOLD=0.9 pytest --proofbundle
```

Installed via the `pytest11` entry-point; when enabled, `pytest_terminal_summary` can emit a receipt of the run
(metric `pass_rate`, with the per-outcome counts and exit status in provenance) from `terminalreporter.stats`.
`PROOFBUNDLE_THRESHOLD` is required for receipt emission, with no default. If `PROOFBUNDLE_KEY` is unset,
signing uses an ephemeral key with a warning.
The metric is always `pass_rate`: `PROOFBUNDLE_METRIC` set to any other value skips the receipt and prints
why, so no receipt names a metric the plugin did not compute.

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

## lm-evaluation-harness (results_*.json adapter, v0.6; sample-count provenance since v3.7.0)

EleutherAI's lm-evaluation-harness writes a results JSON per run. The adapter is file-based — no
lm_eval import:

```python
from proofbundle.adapters import from_lm_eval_results
from proofbundle.evalclaim import emit_eval_receipt
from proofbundle import generate_signer

claim, salts = from_lm_eval_results("results.json", "arc_easy", "acc", comparator=">=",
                                    threshold="0.30", timestamp="2026-07-01T12:00:00Z")
receipt = emit_eval_receipt(claim, generate_signer())
```

Metric keys resolve with the harness suffix convention (`acc` matches `acc,none`). The signed
provenance carries `git_hash`, task version, n-shot, sibling stderr — and, since 3.7.0, the
sample counts from the harness `n-samples` block: `effective_samples`, `original_samples` and
`skipped_samples`, validated fail-closed (negative counts raise; `effective > original` clamps
`skipped_samples` to 0 with both raw counts visible; `effective = 0` keeps the honest `n`
fallback). A silently subsetted run can no longer present itself as a full run under the same
signed claim. See `examples/lm_eval_receipt.py` for a complete offline round-trip.

## JUnit XML and CTRF JSON test reports (after 6.3.0)

A CI that writes a JUnit XML report (pytest `--junitxml`, Maven Surefire, jest-junit) or a CTRF
JSON report gets an eval receipt from it. The adapter reads the file only and imports no test tool.

```bash
proofbundle emit-test-receipt --junit report.xml --commit "$GITHUB_SHA" --key pb.key --out test-receipt.json
proofbundle show-eval test-receipt.json --expect-issuer ed25519:<your key>
proofbundle check-test-receipt test-receipt.json --report report.xml
```

```python
from proofbundle.adapters import from_junit_xml, verify_test_receipt
from proofbundle.evalclaim import emit_eval_receipt
from proofbundle import generate_signer

claim, salts = from_junit_xml("report.xml", commit="<40 or 64 hex>")
receipt = emit_eval_receipt(claim, generate_signer())
assert verify_test_receipt(receipt, "report.xml")["ok"]
```

`from_ctrf_json` and `--ctrf` read CTRF. `read_junit_xml` and `read_ctrf_json` return the counts of
report bytes without building a claim.

**What is read.** Five counts: tests, passed, failed, errors and skipped. A JUnit testcase with an
`<error>` is an error, otherwise with a `<failure>` a failure, otherwise with a `<skipped>` a skip,
otherwise passed; pytest's xfail is a skip. A Surefire testcase that passed on a rerun
(`flakyFailure`, `flakyError`) is passed. In CTRF, `pending` is counted as skipped and `other` as an
error: CTRF has no error status, and `other` is an outcome that is neither a pass, a failure nor a
skip (jest writes a `test.todo` as `other`), so it never reads as passed. Both counts stand in the
provenance as read.

**The claim.** `metric` is `pass_rate`, `comparator` `>=` and `threshold` `1`, over `n` = passed +
failed + errors. Passed means no failure, no error and at least one passed test, so an empty report
and a report of skipped tests only do not pass. The provenance carries `report_sha256` (the SHA-256
of the report's bytes), the optional `commit`, the counts as `tests_total`, `tests_passed`,
`tests_failed`, `tests_errors` and `tests_skipped`, the pass rate rounded down to six places,
`verdict_rule` and `non_claims`. The dataset commitment is over `sha256:<report digest>` and the
model commitment over `git:<commit>`.

**What is refused.** Every refusal is a `ReportRefused` with a stable `code` and a sentence naming
the reason; the CLI exits 2 and writes no receipt.

| Code | When |
|---|---|
| `doctype`, `entity`, `processing_instruction` | an XML document type declaration (DTD, entity declarations, external references, parameter entities), an undefined entity, a processing instruction |
| `duplicate_attribute`, `duplicate_key` | a duplicated XML attribute, a duplicated JSON key at any depth |
| `encoding` | anything but UTF-8; an XML declaration naming another encoding; a byte order mark in CTRF |
| `trailing_content`, `malformed` | bytes after the one root element or JSON value; not well-formed; `NaN`, `Infinity` or a lone surrogate in JSON |
| `structure` | a JUnit element where the formats above have none, such as a `<testcase>` inside `<system-out>` or an unknown outcome inside a `<testcase>` |
| `count_mismatch`, `bad_count`, `contradiction` | a `tests`, `failures`, `errors` or `skipped` attribute or a CTRF summary count that disagrees with what it counts; a count that is not a non-negative integer; a rerun record without a final failure, or a flaky mark beside one |
| `not_ctrf`, `unsupported_version`, `unknown_field`, `missing_field`, `bad_value` | not a CTRF document; a `specVersion` other than 0.2.x; a field CTRF does not define outside `extra` in the root, `results`, `tool`, `summary` or a test; a required field missing or of the wrong type |
| `too_large`, `too_deep`, `not_a_file`, `unreadable` | past 64 MiB (`--max-report-bytes`) or 64 levels of nesting; a path that is not a regular file |

Two real reports are refused for contradicting themselves: jest-junit 17.0.0 writes a `test.todo` as
a testcase without a child and leaves it out of `tests`, and an older Surefire writer counted one test
for two testcases. The objects CTRF defines but this adapter does not read (`environment`,
`insights`, `baseline`, and a test's retry attempts, attachments and steps) are not validated; use a
JSON Schema validator against the CTRF schema for full conformance. The CTRF reader follows
`spec/ctrf.md` of `ctrf-io/ctrf`, version 0.2.0 of 2026-10-10. The vectors, real and synthetic, are in
`tests/fixtures/test_reports`.

**What the receipt does not prove** stands in it as `non_claims`: which report was signed by which
key, and how its counts read under the rule. Not that the tests are meaningful, that the report came
from the real run, or that it lists every test. Measured on 2026-10-16: a jest test file that failed
to load was missing from both the jest-junit and the CTRF report of the same run, and nothing in
either file showed it.

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
