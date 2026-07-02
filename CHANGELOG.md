# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-07-02

### Added — holder binding + witness quorum (verified against primary sources)
- **Key Binding JWT verification** (`proofbundle.kbjwt`, closes #1): RFC 9901 §4.3, fully offline —
  header `typ` MUST be `kb+jwt` (alg EdDSA), payload MUST carry `iat`/`aud`/`nonce`/`sd_hash`,
  `sd_hash` recomputed over the US-ASCII bytes of the presented `JWT~disclosures…~` with the SD-JWT's
  `_sd_alg` (binds the *presented disclosure set* — dropping or swapping a disclosure after signing is
  detected), signature verified under the issuer-bound `cnf.jwk` holder key (RFC 7800; a supplied holder
  key is the fallback, the issuer's binding wins). `expected_aud`/`expected_nonce` for relying-party
  policy; `iat` freshness stays caller policy (offline verifier, no trusted clock). SPEC §6/§7.
- **KB-JWT issuance/presentation** (`sdjwt_issue`): `issue_sd_jwt(..., holder_public_key=...)` embeds
  `cnf.jwk` (OKP/Ed25519); new `present_with_key_binding(compact, holder_signer, aud=, nonce=, iat=)`
  builds the holder presentation. Explicit `iat` — the library never samples wall clocks for signatures.
- **New bundle check `sd-jwt-key-binding`** — **fail-closed**: a KB-JWT that is present must verify;
  previously a trailing KB-JWT was **silently ignored**, a downgrade risk (a bundle carrying holder
  binding verified `OK` without the binding being checked). Bundles *without* a KB-JWT are untouched —
  no new check, behavior identical to v1.1. SPEC §7 order gains step 5.
- **C2SP tlog-cosignature, Ed25519 cosignature/v1** (`proofbundle.checkpoint`): `cosign_checkpoint` /
  `verify_cosignature` / `verify_witnessed_checkpoint(..., threshold=)` — witness key ID algorithm byte
  **0x04** (domain-separated from the log's 0x01 by construction), signature blob
  `keyID[4]‖u64-BE-timestamp‖sig[64]` (exactly 76 bytes), signed message
  `"cosignature/v1\n" + "time <ts>\n" + note body`. Verifying a witness quorum rules out a split view
  by the log operator, offline — the pattern Rekor v2 (GA 2025-10) institutionalizes. The log's own
  signature stays required (witnesses attest consistency, they don't replace the log). SPEC §7d.
- **CLI `proofbundle verify --verbose`** (closes #2): prints the recomputed Merkle root next to the
  stated root (also under `--json` as `merkle_root.{stated_b64,recomputed_b64}`), via the new public
  `recompute_merkle_root_b64`. Debugging inclusion-proof failures no longer needs a REPL.

### Release-review hardening (2026-07-02, 6-lens adversarial review before tag)
- **CRITICAL — holder-binding downgrade closed.** A credential *issued with* a `cnf` holder key REQUIRES
  proof-of-possession; before this fix a presentation with the KB-JWT **stripped** (the RFC-9901-legal
  no-key-binding compact form) still verified OK — anyone who saw the disclosed SD-JWT could replay it as
  a bearer token. `verify_bundle` now fails when the issuer payload carries a `cnf` key but no KB-JWT is
  present (bundles with no `cnf` are untouched → v0.9/v1.0/v1.1 stay backward-compatible).
- **HIGH — witness quorum counts distinct KEY MATERIAL, not names.** `verify_witnessed_checkpoint` used
  name-only dedup, so one physical Ed25519 key registered under N names satisfied a `threshold=N` quorum
  with zero independent witnesses. It now dedups by the witness public key (C2SP: operators MUST use
  distinct keys per cosigner); the witnesses report is keyed by name+keyID (no same-name overwrite).
- **sd_hash uses the SD-JWT's `_sd_alg`** in `present_with_key_binding` (was a hardcoded sha256), matching
  the kbjwt verifier for any future non-sha256 `_sd_alg`.

### Verification discipline
- Green roundtrips plus an adversarial red matrix per feature (disclosure drop/swap after KB signing,
  `typ`/`alg` confusion, missing required claims, fail-open probes, cosignature timestamp/body tamper,
  log-vkey-as-witness type confusion, quorum double-count, oversized signature blob), plus the two
  release-review regressions above (cnf-bound stripped-KB must fail; one-key-under-two-names must not
  satisfy `threshold=2`). 148 tests total.

### Notes
- Python floor stays **3.9** in this release (no floor change in a minor); 3.9 is EOL since 2025-10 —
  bumping to 3.10 is a deliberate follow-up decision.
- Still deferred, stated honestly: SD-JWT VC conformance / `vct` type metadata
  (draft-ietf-oauth-sd-jwt-vc-16, RFC expected ~Q4 2026), Token Status List verification (draft-21 in
  the RFC-Editor queue; frozen bit-array+zlib format — a good candidate as a bundled snapshot),
  ML-DSA-44 cosignatures (C2SP SHOULD for new deployments; needs an ML-DSA dependency).

## [1.1.0] - 2026-07-02

### Added — trust hardening: the honest foundation (authorship + integrity, stated precisely)
- **Signed `assurance_level`** (required field, enum `self_attested` | `third_party` | `reproduced` |
  `enclave_attested`, default `self_attested`) in the eval claim + schema + EVAL_CLAIM.md. The 1.0
  integrations emit self_attested. `show-eval` always displays it; the level is signed (tamper-evident,
  issuer-declared) — a third party cannot alter it, though a dishonest issuer can self-declare a higher level
  (the signature binds who claimed it, not that it is true). Schema keeps assurance_level OPTIONAL for v1.0
  backward-compat; the code always emits it (setdefault). Pre-1.1 claim JSONs default to self_attested.
- **THREAT_MODEL.md** — what `verify` catches (tampering, issuer swap, model swap, filtered disclosure,
  replay, weak-assurance-masking) and what it structurally cannot (dishonest self-attested issuer,
  publish-best-of-many without pre-registration, suite validity, per-sample sub-sampling = roadmap).
- **`claim_warnings`** — warns on the weakest combination (self_attested with no `prereg_sha256`); shown by
  `show-eval`.
- **`verify_commitment(identifier, salt, commitment)`** — checks a presented model/dataset identifier against
  the salted commitment, so a model swap is visible.
- **`check_freshness(claim, max_age_seconds)`** — reports receipt age (replay protection); the timestamp was
  carried but never judged before.
- **`sd_jwt_hidden_count`** — surfaces the number of withheld SD-JWT fields, so omission is visible.
- **`tests/test_adversarial.py`** — actively forges receipts: invented-numbers-with-valid-signature (PASS is
  EXPECTED + warned — binds authorship not truth), tampered payload (FAIL), withheld-field count, model swap
  (mismatch), replay (detectable), honest receipt still verifies.
- A consolidated **"What a receipt proves (and what it does not)"** section high in the README + assurance table.

### Note
- Terminology hygiene throughout: *tamper-evident signed evidence*, not *proof*; *authenticity and
  integrity*, not *correctness of the computation*.

## [1.0.0] - 2026-07-02

### Added — distribution: opt-in framework integrations (the 1.0 milestone: usable with zero third-party wiring)
- **inspect_ai end-of-task hook** (`proofbundle._inspect_registry` via the `inspect_ai` entry-point): auto-
  emits a signed receipt from the eval log at task end. Requires `inspect_ai>=0.3.112`. `data.log` is the
  EvalLog (no re-read for a normal `eval()`; header-only `eval_set()` falls back to reading the log).
- **pytest plugin** (`proofbundle.pytest_plugin` via the `pytest11` entry-point): auto-emits a signed
  receipt of the run (metric `pass_rate` over UNIQUE tests, per-outcome counts + exit status in provenance)
  from `terminalreporter.stats`. New optional `[pytest]` extra.
- **OPT-IN SAFETY** (the top rule): both integrations emit ONLY when explicitly enabled (`PROOFBUNDLE_EMIT=1`
  or `pytest --proofbundle`) — never silently write a file, never fail the host run, crypto imported lazily.
- Composite **GitHub Action** prepared under `action/action.yml` (SHA-pinned, env-indirect command) +
  `INTEGRATIONS.md` with a complementary `attest-build-provenance` recipe.
- The package `__init__` is now lazy (PEP 562): loading the plugin/hook no longer pulls the crypto core until
  a public name is actually used, keeping framework startup light.

### Changed
- README leads with the integration story; fair demarcation from ai-audit-trail (runtime agent Decision
  Receipts) and ValiChord (which builds attestation bundles from inspect_ai logs *post-hoc* — its v1 library
  is unsigned; signatures are v2 scope). Honest novelty: as far as documented, proofbundle is the first to
  auto-emit an **Ed25519-signed** receipt of an inspect_ai eval / pytest run via the framework's native plugin.
- The inspect_ai adapter renders metric scores as fixed-point decimals (not `repr`), so tiny/large values
  (e.g. `1e-05`) no longer fail the claim's decimal format.

## [0.9.0] - 2026-07-02

### Added — the standards moat (verified against primary sources)
- **DSSE-signed in-toto test-result export** (`proofbundle.intoto.export_intoto_dsse` + `verify_intoto_dsse`,
  new `proofbundle.dsse`): a receipt as a DSSE envelope over the GENERIC in-toto `test-result/v0.1`
  predicate (result PASSED/FAILED, `configuration` ResourceDescriptors with real digests, metrics in
  `annotations`). PAE is signed over the RAW Statement bytes (never base64), payloadType is pinned. SPEC §7b.
- **C2SP tlog-checkpoint** (`proofbundle.checkpoint`): a signed note over the RFC 6962 Merkle root
  (origin / tree size / standard-base64 root; EM DASH U+2014 signature line; keyID =
  SHA-256(name‖0x0A‖0x01‖pubkey)[:4]; vkey encoding). Raw note bytes signed, no PAE. SPEC §7c.
- **Every Eval Ever converter** (`proofbundle.adapters.from_eee_dataset`): reads an EEE v0.2.2 aggregate
  JSON into a signed receipt, validated against the vendored EEE schema, with NO runtime import of
  `every_eval_ever` (it needs Python 3.12; proofbundle stays 3.9+). The EEE `evaluation_id` (which embeds
  the model id) is deliberately NOT copied into provenance — the receipt keeps the model a salted commitment.
- Examples for all three (`examples/intoto_dsse_export.py`, `checkpoint_example.py`, `eee_receipt.py`).

### Changed — standards-native repositioning
- README tagline + "How it fits" name the neighbours fairly (Every Eval Ever, OpenSSF Model Signing,
  ValiChord, Attestable Audits) with the honesty guardrail visible; INTEROP.md gains a ValiChord section.
- SD-JWT digest mechanic re-verified against RFC 9901 §4.2.3 (Nov 2025) + the sd-jwt-python reference.

## [0.8.1] - 2026-07-01

### Fixed
- `make demo` / `scripts/demo.sh` / `Makefile` now invoke **`python3`** (overridable via `PYTHON=...`),
  not a bare `python`, so the documented demo works on systems where only `python3` is on PATH (PEP 394).

## [0.8.0] - 2026-07-01

### Added
- **Offline demonstrator**: `make demo` / `scripts/demo.sh` + `Makefile` turn genuine eval logs (an
  inspect_ai `mockllm` `.eval` and an lm-eval `--model dummy` `results.json`, committed fixtures generated
  offline) into signed, Merkle-anchored receipts and verify them — no network, API key, or GPU.
  `examples/inspect_receipt.py` added; a "Demo" README section makes it prominent.
- **Honesty guardrail** (README + SPEC): a receipt attests authenticity + integrity of a *claimed* result,
  **not** the correctness of the computation nor the absence of cherry-picking (TEE audits target that,
  different trust model). Demarcated from a bare hash (ref inspect_evals PR #1610) and from TEE approaches.
- INTEROP.md: Every Eval Ever (integration target, converter bridge) + Attestable Audits (TEE, different
  trust model) sections; SECURITY.md notes the SLSA v1.2 attestation model.
- Engagement drafts (`OUTREACH_issue_inspect_evals.md` + updated outreach note) — clearly marked
  draft-only; the human posts and replies personally per the inspect_evals AI-use policy.

### Note
- v0.6/v0.7 already delivered the lm-eval + inspect_ai adapters, INTEROP.md, PEP 740 docs and CITATION.cff;
  this release skipped those and added only the open points (demo, guardrail, outreach), per the update.

## [0.7.1] - 2026-07-01

### Fixed
A holistic 6-lens review of the whole integration (v0.1-v0.7) found robustness/conformance/CI gaps the
per-version reviews missed; all fixed here:
- **Verifier robustness**: `verify_bundle` now rejects malformed input with a `BundleFormatError` (the
  documented malformed path) instead of a raw traceback - type-confused `leaf_index`/`tree_size`
  (non-int/float), a non-object `signature`/`merkle`, a missing `inclusion_proof_b64` (required per SPEC),
  and unknown top-level/nested fields (SPEC additionalProperties:false, previously unenforced).
- **Eval-claim schema conformance**: `build_eval_claim` rejects values that fail its own published schema -
  negative `n`, and non-plain-decimal `threshold`/`score` (`1e2`, `Infinity`, `+5`, spaces).
- **CI on Python 3.9**: `inspect_ai` (requires Python >=3.10) is gated by a `python_version >= "3.10"`
  marker in the `inspect`/`dev` extras, so `pip install .[dev]`/`[inspect]` no longer fails on 3.9.
- **inspect_ai provenance parity**: the inspect adapter now captures run provenance (git commit, harness
  version, task version) into `provenance`, matching the lm-eval adapter.
- mypy is now run in CI (declared but never enforced); fixed two real mypy errors in `intoto.py`. A clear
  error names the missing `[eval]` extra if `rfc8785` is absent on the emit path.

### Changed (docs)
- Zenodo DOI wording made aspirational (no DOI assigned yet). INTEROP.md updated to CycloneDX v1.7 + C2PA
  ~v2.4. Corrected the arXiv:2507.06893 attribution (inspect_evals maintainers, Arcadia Impact, UK-AISI-
  funded). Refreshed stale CONTRIBUTING/PR/issue-template wording.

## [0.7.0] - 2026-07-01

### Added
- CITATION.cff now carries the author ORCID (0009-0006-8947-6065); a Zenodo DOI placeholder is marked in
  the README + CITATION.cff (a DOI is assigned once Zenodo archives a release; none exists yet — human checklist).
- `docs/in_toto_predicate_proposal.md` — a draft proposing an ML eval-result predicate upstream to
  in-toto/attestation (no registered ML-eval predicate exists yet); the human decides whether to submit.

### Unchanged (already delivered in v0.6, verified, not rebuilt)
- inspect_ai adapter (non-deprecated `results.scores[*].metrics[name].value` path), lm-evaluation-harness
  adapter (real `acc,none` format + provenance), INTEROP.md, PEP 740 attestations + badge fixes. This
  release re-confirmed each is present and correct rather than duplicating it.

## [0.6.0] - 2026-07-01

### Added
- **Second eval adapter, EleutherAI lm-evaluation-harness** — `proofbundle.adapters.from_lm_eval_results`
  reads a real `results_*.json` (no `lm_eval` import), handling the genuine 0.4.x format: metric keys with
  a filter suffix (`acc,none`) and the sibling `acc_stderr,none`. Captures run provenance (git_hash, task
  version, n-shot, stderr) into the receipt's optional `provenance` field. Validated against a committed
  real fixture (`tests/fixtures/lm_eval_arc_easy_real.json`, harness 0.4.12) + `examples/lm_eval_receipt.py`.
- **INTEROP.md** — honest mapping to OpenSSF Model Signing (complement, not eval), CycloneDX ML-BOM v1.6
  (can reference a receipt), in-toto test-result/v0.1 (the open ML-eval niche), C2PA (out of scope).
- **CITATION.cff** so the repo shows a "Cite this repository" button.
- Optional additive `provenance` field on the eval claim (backward-compatible, schema string unchanged).

### Changed
- inspect_ai adapter confirmed on the non-deprecated `results.scores[*].metrics[name].value` path with a
  None-guard (already correct since v0.5; documented).
- README/SPEC positioned as the verification layer for trustworthy eval logs; PEP 740 attestations
  documented (verified present on PyPI via the Integrity API, publisher = GitHub Trusted Publishing).
- Badges: python-version badge cache-buster (`?cacheSeconds=3600`) + a pepy downloads badge.

### Deferred (not built)
- No CycloneDX / C2PA / OMS re-implementation, no `lm_eval` runtime dependency, no `.zenodo.json`
  (would shadow CITATION.cff), no official in-toto predicate PR (drafted for the human to submit).

## [0.5.0] - 2026-07-01

### Added
- **SD-JWT issuance** (RFC 9901) — `proofbundle.sdjwt_issue.issue_sd_jwt`: issue an eval receipt so a
  holder can disclose `passed`+`threshold` while withholding the exact score and the identifier openings.
  The signed bundle payload is the **source of truth**; the SD-JWT is a derived view, binds the bundle
  merkle root (`receipt.root_b64`), and is signed with the same Ed25519 key as `issuer`. Digest byte-chain
  exactly per RFC 9901 §4.2.4.1 (over the base64url-encoded disclosure string). Verified by proofbundle's
  own verifier **and** the openwallet-foundation-labs/sd-jwt-python reference; divergence + tamper red-tests.
- **in-toto Statement v1** view — `proofbundle.intoto.to_intoto_statement`: self-hosted predicate type
  `https://b7n0de.com/proofbundle/eval-receipt/v0.1`. The subject digest is a salted commitment under a
  custom key `proofbundleModelCommitV1` (NOT `sha256`, which would imply an artifact hash). Validated
  against the in-toto Statement-v1 JSON schema via jsonschema. See PREDICATE.md.
- **inspect_ai adapter** via the stable `read_eval_log(header_only=True)` API (lazy import, optional
  extra `proofbundle[inspect]` pinned `>=0.3.100,<0.4`), with a real committed `.eval` fixture.

### Changed
- The inspect_ai adapter now uses the stable API instead of parsing the `.eval` file (robust across
  versions). The lm-eval adapter still reads `results.json` without importing the framework.

### Deferred (explicitly not in v0.5)
- SD-JWT VC conformance + `vct` type metadata, Key-Binding JWT, status lists / revocation, an official
  in-toto/attestation PR, a DSSE envelope or full in-toto verification client.

## [0.4.1] - 2026-07-01

### Fixed
- Removed a dead v0.3 `emit_eval_receipt` roadmap stub from `emit.py` that contradicted
  the real emitter now in `evalclaim.py`.
- Corrected the RFC 9901 publication date to November 2025 (was "December 2025") in the
  README, `sdjwt.py`, and this changelog.
- Doc staleness: test count and version wording in the README.
- Release workflow: the PyPI publish step is now idempotent (`skip-existing`) so a
  re-tagged release does not fail on an already-uploaded file.

## [0.4.0] - 2026-07-01

### Added
- **Eval-receipt emitter** (`src/proofbundle/evalclaim.py`): turn a reproducible eval
  run into a signed, Merkle-anchored receipt that proves *suite S `comparator` threshold
  T, passed* while carrying only **salted commitments** to the model and dataset
  identifiers (never the weights, data, or plaintext names). Built on `emit_bundle`, so
  the existing `verify_bundle` verifies a receipt unchanged.
  - `build_eval_claim` computes `passed` itself; `emit_eval_receipt` binds the receipt to
    the signer (`issuer` field in the signed payload); `decode_eval_claim` verifies the
    bundle **and** the issuer binding.
  - RFC 8785 JCS canonicalization on the **emit path only** (UTF-16 key sort, NFC, duplicate-
    key + Python-float rejection, safe-int range); the verify path checks stored bytes, so the
    verifier stays dependency-free.
- File-based framework adapters (`proofbundle.adapters.from_lm_eval_results`,
  `from_inspect_ai_log`) that read exported result JSON without importing the framework.
- CLI: `proofbundle emit-eval` and `proofbundle show-eval`.
- `EVAL_CLAIM.md` (normative claim spec + data-minimization) and
  `schemas/eval_claim_v0_1.schema.json` with a validation test.
- Optional extras: `proofbundle[eval]` (RFC 8785 canonicalizer, emit side), `proofbundle[adapters]`.

## [0.3.0] - 2026-07-01

### Added
- **External RFC 6962 conformance**: verifies canonical inclusion vectors vendored
  from transparency-dev/merkle (tests/fixtures/rfc6962_vectors.json) — proven
  RFC-conformant, not merely self-consistent. Plus Hypothesis property tests
  (inclusion + consistency) for trees up to several hundred leaves.
- **Sigstore Rekor interop**: `examples/rekor_interop.py` verifies a real Sigstore
  Rekor inclusion proof (logIndex 25579, tree size 4.16M) fully offline, with a
  committed fixture and a field-mapping doc (Rekor bundle / C2SP checkpoint).
- SD-JWT is an optional extra: `pip install "proofbundle[sdjwt]"` (core stays
  cryptography-only).
- Normative format specification `SPEC.md` (fields, encodings, RFC 6962 hashing,
  verification order), consistent with the JSON Schema.
- `.github/dependabot.yml` (github-actions + pip).
- PyPI Trusted Publishing (OIDC) publish job in the release workflow.

### Changed
- All GitHub Actions pinned to full commit SHAs (post tj-actions incident).
- SD-JWT docstrings/README cite RFC 9901 (SD-JWT core, November 2025); clarify SD-JWT VC
  is still an IETF draft.

## [0.2.0] - 2026-07-01

### Added
- Bundle emitter: `emit_bundle` signs a payload with Ed25519 and anchors it as
  the last leaf of an RFC 6962 Merkle tree, producing a bundle that
  `verify_bundle` accepts — the offline counterpart to the verifier.
- Signing-key helpers `generate_signer`, `save_signer`, `load_signer` (raw 32
  byte Ed25519 seeds).
- `proofbundle emit` command line interface (`--payload-file`, `--new-key` /
  `--key`, `--out`).
- Emit-then-verify round-trip tests, including prior-leaf anchoring, tamper
  detection and key save/load.

### Notes
- No new runtime dependency; the emitter reuses the existing Merkle logic and
  `cryptography`. The v0.3 eval-receipt emitter remains a roadmap stub.

## [0.1.0] - 2026-07-01

### Added
- Offline evidence bundle verifier (`proofbundle/v0.1` schema).
- Published JSON Schema (`schemas/proofbundle_v0_1.schema.json`) with a
  validation test, `py.typed` marker and community files (Code of Conduct,
  issue and pull-request templates).
- RFC 6962 / RFC 9162 Merkle inclusion and consistency proof verification.
- Ed25519 signature verification via `cryptography`.
- Minimal SD-JWT selective-disclosure verification (EdDSA issuer signatures,
  disclosure-digest commitment check).
- `proofbundle verify` command line interface with human and JSON output.
- Example bundle generator (`examples/make_example.py`) and a real example bundle.
- Full unit test suite (Merkle round-trip across sizes, signature, bundle, CLI).
- Emitter roadmap stub for v0.2 (bundle emission) and v0.3 (eval receipts).
