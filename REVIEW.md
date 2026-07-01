# v0.5 review protocol (six lenses + orthogonal iteration)

Per the standing work rule: each part reviewed across six lenses with a concrete, checkable artifact
(test name / fixture / file:line), plus an orthogonal iteration that actively hunts defects. The review
was run as a multi-agent lane (three independent sonnet reviewers, one per lens cluster), each executing
against the real work-tree, not inspecting prose.

## Teil 1 — inspect_ai adapter (stable `read_eval_log` API, extra `proofbundle[inspect]`)

| Lens | Finding | Artifact / test |
|---|---|---|
| 1 Correctness | maps `log.eval.task`→suite, `score.metrics[m].value`→value against a REAL `.eval` | `tests/test_adapters.py::test_inspect_ai_stable_api` (fixture `tests/fixtures/inspect_logs/safety_refusal_demo.eval`, a real Zip/Zstd inspect artifact) |
| 2 Interop | uses the stable `read_eval_log(header_only=True)`, not `.eval` parsing | `getsource` confirms `read_eval_log`, no `json.loads`; extra pinned `inspect_ai>=0.3.100,<0.4` |
| 3 No-Fake | missing metric → clear `InspectAdapterError`, not a bare AttributeError | `tests/test_adapters.py::test_inspect_ai_missing_metric_clear_error` |
| 4 Executability | red-test on the clear-error path (proven non-tautological by mutation) | L4: replaced the raise → test went red, only that test |
| 5 Convention | lazy import inside the function; core stays dependency-free | `import proofbundle` works without inspect_ai installed |
| 6 Anti-scope | lm-eval adapter still stdlib file-read, no framework import | grep: no top-level `inspect_ai`/`lm_eval` import |

## Teil 2 — in-toto Statement v1 (self-hosted predicate type)

| Lens | Finding | Artifact / test |
|---|---|---|
| 1 Correctness | subject.digest = hex of `model_id_commit`; structurally valid statement | `tests/test_intoto.py::test_structure`, `test_digest_is_commit_hex` |
| 2 Interop | validates against the in-toto Statement-v1 JSON schema via jsonschema | `test_validates_against_official_intoto_v1_schema` (schema `schemas/in_toto_statement_v1.schema.json`) |
| 3 No-Fake | digest under custom key `proofbundleModelCommitV1`, NEVER `sha256`; honesty note mirrored | `test_structure` asserts `assertNotIn("sha256", …)`; `PREDICATE.md` + `predicate.subject_digest_note` |
| 4 Executability | schema rejects an empty subject (non-tautological, proven by mutation) | `test_schema_rejects_missing_subject`; L4: removed `minItems` → test went red |
| 5 Convention | consumes the eval claim + `root_b64`, no Merkle/sig rebuild | `intoto.py` builds from `claim` + external `root_b64` |
| 6 Anti-scope | no official in-toto PR, no DSSE, no in-toto client | grep: none present |

## Teil 3 — SD-JWT issuance (RFC 9901 §4.2.4.1)

| Lens | Finding | Artifact / test |
|---|---|---|
| 1 Correctness | digest over the base64url-ENCODED disclosure string (not JSON bytes); matches the reference lib formula | `tests/test_sdjwt_issue.py::test_digest_byte_chain_vector` (fixture `tests/fixtures/sdjwt_disclosure_vector.json`); L1 hand-recomputed + read `sd_jwt/disclosure.py` |
| 2 Interop | accepted by the openwallet-foundation-labs/sd-jwt-python reference verifier (0/1/4 disclosures) | `test_reference_verifier_accepts` |
| 3 No-Fake | bundle payload is the source of truth; always-open passed/threshold plaintext, score selective | `test_always_open_vs_selective`; SD-JWT binds `receipt.root_b64` |
| 4 Executability | divergence + tamper red-tests (both proven non-tautological by mutation) | `test_divergence_red`, `test_tamper_disclosure_red`; L4 mutated `check_binds_bundle`/`_digest` → each test went red |
| 5 Convention | own verifier (`proofbundle.sdjwt`) accepts the issuance unchanged; Ed25519 only | `test_own_verifier_accepts`; same key as `issuer` |
| 6 Anti-scope | no SD-JWT VC, no Key-Binding JWT, no status lists | grep: no `vct`/KB-JWT/status-list code |

## Orthogonal iteration (adversarial, different angle)

The lane deliberately looked for staleness/overclaim beyond the changed files and for tautological
red-tests. It found:

1. **`README.md:25` stale test count** ("50 tests" → actually 62) — a regression of the exact class
   v0.4.1's changelog says it fixed once. **Fixed** → live count 62.
2. **`docs/profile_README.md:8`** still said SD-JWT "issuance is on the roadmap" while v0.5 ships it.
   **Fixed** → "the verifier plus (since v0.5) issuance".

No crypto, interop, scope-creep, or executability defect survived. The four v0.5 red-tests were each
proven non-tautological by real mutation (all reverted; work-tree verified pristine). Crypto correctness
(the load-bearing digest byte-chain) was independently recomputed and cross-checked against the reference
implementation — no off-by-one in the encoding.

**Verdicts:** L1 crypto-correct · L3 honest+narrow (2 doc-staleness items, fixed) · L4 executable+real+interop.
