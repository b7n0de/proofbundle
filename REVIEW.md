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

---

# v0.6 review protocol (six lenses + orthogonal check)

| Lens | Finding | Artifact / test |
|---|---|---|
| 1 Correctness | inspect_ai adapter already on the non-deprecated `results.scores[*].metrics[name].value` + None-guard | `adapters/inspect_ai.py:44-52`; `tests/test_adapters.py::test_inspect_ai_stable_api` |
| 2 Interop/adapter | lm-eval adapter reads the REAL `acc,none` suffix + `acc_stderr,none` sibling against a genuine harness 0.4.12 export | `tests/test_adapters.py::test_lm_eval_real_acc_none_format` (fixture `tests/fixtures/lm_eval_arc_easy_real.json`, model=dummy run); `examples/lm_eval_receipt.py` → OK |
| 3 Standards | INTEROP.md maps OMS / CycloneDX ML-BOM v1.6 / in-toto test-result/v0.1 / C2PA honestly; predicate aligned to test-result form | `INTEROP.md`; `PREDICATE.md` |
| 4 Distribution | PEP 740 attestations verified present on PyPI (Integrity API, publisher=GitHub) BEFORE documenting; badge cache-buster + pepy | `SECURITY.md` "Release integrity"; README badges (`?cacheSeconds=3600`, pepy) |
| 5 Format/DX | CITATION.cff added; optional additive `provenance` field, schema string unchanged (no byte-format break) | `CITATION.cff`; `schemas/eval_claim_v0_1.schema.json` (provenance optional); `tests/test_eval_claim_schema.py` |
| 6 Findability | README/SPEC positioned as the verification layer for trustworthy eval logs (arXiv:2507.06893); integration targets named | README "A verification layer…"; `docs/outreach_note.md` (human decides to send) |

**Orthogonal check (skeptical senior, anti-vanity, anti-over-engineering):** the lm-eval fixture is a
GENUINE harness run (`model=dummy`, arc_easy, `--limit 2`), not an invented structure — the `acc,none`
suffix + `acc_stderr,none` sibling are exactly as produced. No CycloneDX/C2PA/OMS re-implementation, no
`lm_eval` runtime dependency, no `.zenodo.json` (would shadow CITATION.cff). PEP 740 was verified real on
PyPI before being documented. Downloads badge (pepy), not stars — an honest metric.

**Human-only:** connect Zenodo for a citable DOI; decide whether to send `docs/outreach_note.md`; submit
an in-toto ML-eval predicate proposal upstream; confirm the Trusted Publisher is scoped to the `pypi`
environment.

---

# v0.7 review protocol (skip-already-done + additive citability)

The v0.7 update repeats the v0.6 lenses with an explicit mandate: **detect what v0.6 already delivered,
skip it, build only the open points.** State was checked (git log, CHANGELOG, code) before building.

| Lens | Status | Artifact / evidence |
|---|---|---|
| 1 inspect_ai | **SKIP** (done v0.6) | non-deprecated `results.scores[*].metrics[name].value` + None-guard, proven under `-W error::DeprecationWarning` |
| 2 lm-eval adapter | **SKIP** (done v0.6) | real `acc,none` + `acc_stderr,none`, provenance, genuine fixture `tests/fixtures/lm_eval_arc_easy_real.json` |
| 3 INTEROP.md | **SKIP** (done v0.6) | `INTEROP.md` (OMS/CycloneDX/in-toto test-result/C2PA), honesty verified |
| 4 PEP 740 + badges | **SKIP** (done v0.6) | attestations verified on PyPI (Integrity API), badge cache-buster + pepy |
| 5 Citability | **BUILT** | ORCID `0009-0006-8947-6065` in `CITATION.cff`; DOI placeholder (Zenodo assigns on release) marked in README + CITATION.cff — no fake DOI |
| 6 in-toto proposal | **BUILT** | `docs/in_toto_predicate_proposal.md` — draft ML-eval predicate proposal (human submits) |

**Orthogonal check:** no duplicate/overwrite of correct v0.6 work (each point re-confirmed, not rebuilt);
no fake DOI (placeholder + human-note, since Zenodo has not archived proofbundle yet — verified via the
Zenodo API, no proofbundle record exists); no `.zenodo.json` (would shadow CITATION.cff). Version 0.7.0.

**Human-only:** after release, add the Zenodo-assigned DOI to README + CITATION.cff; decide whether to
send the outreach note; submit the in-toto predicate proposal.

---

# Holistic integration review (v0.1-v0.7) + 0.7.1 hardening

A full 6-lens review of the WHOLE package (5 independent sonnet reviewers + orthogonal synthesis) ran
against the live PyPI/GitHub state — not one version, the whole integration. It found real defects the
per-version reviews missed. All fixed in 0.7.1 (72 tests, mypy in CI, ruff clean):

| Lens | Finding | Fix + artifact |
|---|---|---|
| 1 Correctness | verifier crashed on malformed input (type-confusion) + accepted unknown fields vs SPEC MUST | `bundle.py` guards + `_reject_unknown`; red-tests `tests/test_bundle_robustness.py` |
| 1 Correctness | `build_eval_claim` accepted schema-violating values (n<0, `1e2`, `Infinity`) | `_DECIMAL_RE` + n-range check; red-tests `TestEvalClaimSchemaConformance` |
| 2 Standards | CycloneDX v1.6→**1.7**, C2PA ~v2.3→**~2.4** (out-of-scope mentions) | INTEROP.md |
| 2 Standards | arXiv:2507.06893 attributed to "UK AISI team" — actually Arcadia Impact (UK-AISI-funded) | README + essay |
| 3 No-Fake | Zenodo "is linked and archives each release" — present-tense, but 7 tags/0 archived | aspirational wording (README/CITATION/CHANGELOG) |
| 4 Distribution | **CI RED on Python 3.9 for 3 releases** — `inspect_ai` (needs ≥3.10) in `dev` broke the 3.9 install | `python_version >= "3.10"` marker in `inspect`/`dev` extras |
| 5 Completeness | inspect_ai adapter never filled `provenance` (data available) | provenance parity (git commit + harness/task version); test |
| 5 Completeness | mypy declared, never run + 2 real errors in intoto.py | mypy wired into CI + fixed |
| 3/5 drift | stale CONTRIBUTING good-first-issue, PR/issue templates, bundle.py docstring, rfc8785 lazy error | refreshed / clear error |

**Orthogonal synthesis:** the crypto core is provably correct (RFC 8032/6962/8785 vectors, real Rekor
proof, sd-jwt-python reference interop, independent MTH reimplementation) — no crypto defect. The gaps
were all in **robustness, schema-conformance, CI, and doc-accuracy**. Key lesson (recorded): a green
RELEASE workflow ≠ a green CI workflow — the 3.9 test job was red for 3 releases while the release
(build+publish, 3.12 only) was green, and the per-version self-reviews never checked the CI matrix.

---

# v0.9 review (standards moat: in-toto/DSSE, C2SP checkpoint, EEE converter)

Specs verified against primary sources BEFORE building (4 spec lenses): DSSE PAE over raw bytes + in-toto test-result/v0.1 (jsonschema-valid), C2SP signed-note byte format (EM DASH, standard base64, keyID formula), EEE schema v0.2.2 field paths. 3 update-doc corrections caught (C2SP '>=3 lines', EEE dataset_name always present, continuous->min/max). Two real bugs caught by my own smoke tests before review: the C2SP vkey over-split on '+' in standard-base64 key material (fixed to split maxsplit=2, tested with a '+'-bearing key), and an EEE privacy leak (the evaluation_id embeds the model id in cleartext, defeating the salted commitment — removed from provenance). 93 tests, ruff clean.
| Lens | Evidence |
|---|---|
| Correctness | PAE byte-rule + in-toto Statement jsonschema-valid; C2SP round-trip byte-exact; EEE round-trip verifies |
| Interop | generic test-result predicate (not self-hosted); C2SP witness-compatible; EEE bridge |
| Standards | in-toto/DSSE/C2SP/RFC 9901 verified against primary sources, 3 doc-drifts corrected |
| Distribution | vendored EEE schema in package-data; 3.9 floor held (no every_eval_ever import) |
| Format-contract | SPEC §7b/§7c normative; payloadType pinned; standard base64 not base64url |
| Supply-chain | no new core runtime dep; neighbours named fairly (ValiChord/EEE/OpenSSF/Attestable Audits) |
| Orthogonal | anti-vanity: value is in the standards, not novelty prose; honesty guardrail visible; 3.9 floor held |

---

# v1.0 review (distribution: inspect_ai hook + pytest plugin + GitHub Action)

APIs verified vs primary sources before building (inspect_ai Hooks floor 0.3.112, data.log=EvalLog, header-only eval_set fallback; pytest terminalreporter.stats; gh-action composite). A 6-lens review + adversarial verify found 7 real defects in the fresh work — all fixed: score=repr→fixed-point (tiny/large metric values no longer fail the claim); pytest ran double-counted teardown-error tests → count UNIQUE nodeids (the signed pass_rate/n is now honest); action.yml command interpolation → env indirection; the emit_enabled gate is wired; and — the important one — ValiChord was MIS-stated as 'signing' inspect logs (its v1 is unsigned), which undersold the real, honest novelty: proofbundle is (as far as documented) the first to auto-emit an Ed25519-SIGNED receipt via the native framework plugin. Both plugins tested end-to-end (opt-in safety holds; receipts verify; model stays a salted commitment). 102 tests.
| Lens | Evidence |
|---|---|
| Correctness | fixed score formatting + unique-test counting; both drive real receipts that verify |
| Interop | native entry-points (inspect_ai + pytest11) registered (importlib.metadata) |
| Standards | receipt format unchanged; APIs verified vs inspect/pytest/gh-action primary sources |
| Distribution | opt-in, light (no crypto at plugin load), pytest/inspect optional, 3.9 floor held |
| Format-contract | INTEGRATIONS.md quickstart per integration; action.yml SHA-pinned + env-indirect |
| Supply-chain | no new core dep; opt-in safety = never silent write, never fail host run |
| Orthogonal | novelty corrected + honestly stated (first SIGNED auto-emit; ValiChord post-hoc + unsigned-v1) |

---

# v1.1 review (trust hardening) — pending 6-lens + 3 orthogonal iterations
