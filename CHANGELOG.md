# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.7.0] - 2026-07-02

### Changed — release supply-chain hardening (review P1: attested artifact must equal published artifact)
- **`release.yml` now builds ONCE and publishes the attested bytes.** Previously the `publish-pypi`
  job ran `python -m build` a second time, so the SLSA/PEP-740 provenance covered a *different*
  build than what landed on PyPI. Now `build-and-attest` uploads the exact `dist/` via
  `actions/upload-artifact`; `publish-pypi` downloads it and a **sha256 gate** fails the upload
  unless the bytes equal the attested subject digests. A `SHA256SUMS` file is attached to the
  GitHub Release. This closes the single most important supply-chain gap for a tool whose whole
  premise is provenance.
- **`pypi` GitHub Environment** now carries a `url:` and is documented to require reviewer approval
  (RELEASE.md) so a `v*` tag cannot publish unreviewed; top-level workflow `permissions` reduced to
  `contents: read` with per-job escalation (least privilege).
- All new actions SHA-pinned (`upload-artifact` v4.6.2, `download-artifact` v4.3.0).

### Added
- **RELEASE.md** — one-time setup (Trusted Publishing, `pypi` environment reviewers, branch
  protection, assets, badge gating) + per-release checklist + a "verify a published release" recipe
  (`gh attestation verify`).
- **docs/REVIEWERS.md** — a 30-minute adversarial audit path: the trusted-core map, the two external
  correctness anchors (RFC 6962 vectors + real Rekor proof), the mutation gate, and an explicit
  "where the bodies are buried" list of invitations to attack.
- **CI `crypto-floor` job** — installs `cryptography==42.*` (the declared floor) and runs the suite
  + `proofbundle demo`, proving the lower bound actually works, not just the latest.
- **External-review issue template** (`.github/ISSUE_TEMPLATE/external_review.md`).

### Fixed — scope-honesty (review Lens 1)
- Badges that render broken/false before the first PyPI release (PyPI version/pyversions/downloads,
  SLSA, PEP 740) are commented out with a note to enable them on first publish (RELEASE.md).
- SECURITY.md attestation language moved to conditional ("once the first release is published, each
  release WILL carry…") — no release exists yet, so present-tense claims were premature.

### Notes
- No library API or wire-format change; verification behavior is byte-identical to v1.6.1. This is a
  release-engineering + docs release. The `pypi` environment reviewers and branch protection are
  GitHub settings the maintainer must apply (documented, not code).
## [1.6.1] - 2026-07-02

### Added — developer experience (review backlog P0-DX; no security or format change)
- **`proofbundle demo`** — a pip-only, offline, in-memory demo: an honest receipt verifies, six
  independent tampers (payload rewrite, signature graft, public-key swap, Merkle-root swap,
  leaf-index shift, dropped `hash_alg`) each verify FAILED, and the per-sample audit catches a
  swapped sample. Exits non-zero if any guarantee breaks, so it doubles as a fail-closed smoke
  test. `--json` for machine output. No files, no network, no optional extras. Closes the
  "quickstart requires a git checkout" gap — the README quickstart now works after a bare
  `pip install`.
- **`examples/persample_audit.py`** — the v1.5 per-sample feature finally has a runnable example:
  build a 1000-sample tree, sign the root into a receipt, auditor challenges 20 random indices
  with a fresh nonce, all openings verify, a swapped-sample opening is rejected.
- **`scripts/demo_tamper.sh`** + Makefile targets `demo`, `tamper-demo`, `persample-demo`,
  `full-demo` (the old real-log demo), `mutation`, `examples`.
- **docs/DEMO.md** — three tiers (pip-only / checkout / extras), each with expected output and
  the reviewer forced-random-sample-check CLI recipe.

### Verification discipline
- 254 tests (was 251): `tests/test_demo.py` pins that all six tampers are caught and none missed,
  in both text and JSON modes and via the CLI entry point.
## [1.6.0] - 2026-07-02

### Fixed — external Principal-Security review (6 lenses + orthogonal iterations); every fix
has a regression test and a mutation operator
- **CRITICAL (P0) — bearer-downgrade via issuer-key omission** (`bundle.py`): the holder-binding
  check was gated on issuer-signature verification, so an attacker could strip the KB-JWT AND
  drop `sd_jwt_vc.issuer_public_key_b64` to silently downgrade a `cnf`-bound credential to a
  passing bearer token. Now a `cnf`-carrying SD-JWT whose issuer cannot be verified is REFUSED
  (`sd-jwt-key-binding` = False), fail-closed. Plain SD-JWTs without `cnf`/KB keep the documented
  no-key path. Proven closed by an executed attack (`test_bundle_cnf_bound_no_issuer_key_fails_closed`)
  + backward-compat pin.
- **P1 — verify-side invariants** (`evalclaim.decode_eval_claim`): the `samples.n == n`,
  `leaf_alg` and 32-byte-root checks (previously only in the emitter) now run on the VERIFY path
  — a hand-signed claim that lies about the committed tree size is rejected. New
  `decode_eval_claim(bundle, *, expected_context=...)` enforces the signed `context_binding`
  (cross-context replay guard); it was signed but never checked.
- **P1 — status-list freshness** (`statuslist.py`): a token with neither `exp` nor `ttl` is no
  longer reported "fresh forever" — `fresh` is `None` (cannot judge) so a stale pre-revocation
  snapshot cannot masquerade as current; `exp`/`ttl` must be integers when present (a string that
  looks like an expiry but never enforces is rejected, not silently ignored).
- **P1 — `merkle.hash_alg` is now REQUIRED** (`bundle.py`): a silently-defaulted algorithm
  contradicted the "reject anything non-canonical" posture and would mask alg-confusion in a
  future multi-alg version.
- **Docs/honesty**: softened the Rekor v2 witnessing claim to "is integrating" (matches the
  Sigstore GA post, which says witnessing is coming, not shipped); quickstart notes that
  `examples/` ships in the repo, not the wheel; SECURITY.md `0.x`→`1.x`; persample module
  docstrings de-drifted from "(v2.0)" to "(v1.5)" (wire constants unchanged).

### Changed
- **Development Status classifier → 4 - Beta** (was Alpha): SemVer-committed, 251 tests, stable
  lazy public API. COMPLIANCE.md still says do not rely on it as a sole compliance control.

### Verification discipline
- 251 tests (was 242): +9 for the fixes above (P0 attack + backward-compat, verify-side samples
  matrix, context_binding enforcement, status freshness/typing). Mutation gate: 26 operators
  (+4 for the v1.6 fixes), all killed; the one documented-equivalent mutant still survives.
- A full REVIEW_v1.6.md accompanies this release: executive verdict, top-10 weaknesses, P0/P1/P2
  plans, README-rewrite proposal, ≥20-row test matrix, 20-issue backlog, outreach pack, pitches.

### Not yet done (tracked in REVIEW_v1.6.md issue backlog, honest)
- `make tamper-demo` + `proofbundle demo` (pip-only) + a per-sample example are DESIGNED and
  specified in the review but not yet shipped in this patch (they are P0 DX, not security).
- Release supply-chain: attested artifact must equal published artifact (`release.yml` rebuilds);
  `pypi` environment reviewers; badges gated behind first publish. Specified, not yet wired.

## [1.5.0] - 2026-07-02

### Added — per-sample receipts (the THREAT_MODEL's named gap, closed; design verified against
TRUCE arXiv:2403.00393, RFC 9901, RFC 6962/9162, RFC 3797, PoR literature)
- **`proofbundle.persample`**: `build_sample_tree` commits every individual sample of a run into
  an RFC 6962 SHA-256 Merkle tree (leaf = 0x00-domain-separated hash over a base64url disclosure
  `[salt, record]` — the RFC 9901 digest mechanic, so verification never canonicalizes JSON).
  Canonical leaf order with the position `idx` embedded INSIDE each committed record; per-leaf
  ≥128-bit salts derived HMAC-SHA-256-as-PRF from ONE holder-kept `tree_secret` (never in the
  receipt; one shared salt would be burned by the first opening — eval answer spaces are tiny).
- **Signed `samples` claim field** `{root_b64, n, leaf_alg}` (schema: additive optional;
  `samples.n` MUST equal the claim's `n`). **Measured, documented finding:** an RFC 6962
  inclusion proof binds n only up to path-shape equivalence (index 4 of a 10-leaf tree verifies
  under any claimed n′ ∈ [9..16]) — the SIGNATURE is the size-truth anchor, and the test suite
  pins the coincidence window so it stays measured fact, not folklore. SPEC §7g.
- **Openings + audit protocol**: `sample_opening` / `verify_sample_opening` (inclusion under the
  signed root, disclosure decode, `record.idx == index` replay guard — the case where the lie
  sits inside a validly-committed leaf, i.e. a lying PRODUCER, is red-tested);
  `audit_challenge` derives k distinct indices via SHA-256 domain-separated seed + HMAC counter
  expansion + rejection sampling (`_map_draw` isolated as a pure function because the rejection
  branch fires with p≈1e-19 and can only be tested in isolation). Modes: auditor nonce
  (grinding-impossible), public beacon (RFC 3797-style), self-challenge (sanity only —
  re-salting grinding bound ≈ g·(1−m/n)^k stated, never hidden; the CLI warns actively).
  PoR soundness table in docs (k=300 → 95% @ m=1%, k=459 → 99%). CLI: `audit-challenge`,
  `verify-opening`. The protocol domain strings are pinned at `proofbundle/v2/*` (protocol
  identifiers, independent of the package version).
- **Sample extractors** (`adapters.samples`): lm-evaluation-harness `--log_samples` JSONL
  (consumes its native `doc_hash`/`prompt_hash`/`target_hash` — wrapped INSIDE the salted leaf,
  since upstream hashes are unsalted and dictionary-attackable alone) and promptfoo v3 rows.
  Two-layer hiding: leaves carry content hashes/compact results, never benchmark plaintext.

### Verification discipline
- 33 new tests (209 → 242): byte-exact pins (salt derivation, RFC 6962 leaf prefix, independent
  challenge re-derivation, rejection sampling in isolation), roundtrips, and an adversarial
  matrix incl. the lying-producer embedded-idx forgery, disclosure/proof tamper, root/n
  confusion, and the pinned n′ shape-equivalence window; 6 new mutation operators (22 total,
  all as expected).
- **Mutation-gate hardening after a real incident**: a same-size mutation on a coarse-mtime
  filesystem left a stale `.pyc` that silently survived restoration and skewed three
  measurements; the runner now purges `__pycache__`, runs with `-B`/PYTHONDONTWRITEBYTECODE,
  and force-touches source mtimes (existing caches are READ even under `-B`).

### Notes
- Versioning: per-sample receipts are strictly additive (no API or format break; v1.4 receipts
  verify unchanged) — hence a MINOR release per SemVer, deliberately NOT a marketing-major.
- Honest residuals (THREAT_MODEL updated): best-of-many full runs remain undetectable without
  pre-registration; opened samples are burned (auditor-directed openings only).

## [1.4.0] - 2026-07-02

### Added — distribution (formats verified against primary sources, 2026-07-02)
- **promptfoo adapter** (`proofbundle.adapters.from_promptfoo_results`): reads a promptfoo
  `eval -o results.json` (summary **version 3**, verified against promptfoo main
  `src/types/index.ts` OutputFile/EvaluateSummaryV3/EvaluateStats) into a `pass_rate` receipt —
  successes/(successes+failures+errors) as a fixed-point decimal, model commitment over the
  sorted provider-id set, dataset commitment over canonical `config.tests` JSON (the test suite
  IS the dataset; promptfoo's internal datasetId is not exported). File-based, no promptfoo
  import. Legacy v1/v2 summaries (a different `table` shape) are REJECTED with a clear message —
  never half-parsed; "v4" is promptfoo's storage version and never appears in output files.
  Committed realistic fixture.
- **Hugging Face Community Evals bridge** (`proofbundle.hf_evals`, CLI `proofbundle hf-token`):
  `receipt_token(bundle)` packs a receipt as `pb1.` + base64url(zlib(bundle JSON)) — the token
  IS the receipt, verified offline by `verify_receipt_token` (zip-bomb-capped, fail-closed);
  `to_eval_results_entry` + `eval_results_yaml` emit schema-faithful `.eval_results/*.yaml`
  entries (spec: hub-docs eval_results.yaml), refusing non-verifying receipts, with a strict
  purpose-built YAML serializer (JSON-escaped scalars — dates and tokens cannot be misparsed).
  **Honesty boundary, stated in code and docs:** HF's *verified badge* is decided server-side by
  HF (HF Jobs + inspect-ai); its token format is not public. The `pb1.` token is
  proofbundle-verifiable and schema-valid in the `verifyToken` field — it is NOT presented as
  HF-endorsed, and the receipt link belongs in `source.url`/`notes` either way.
- **INTEGRATIONS.md**: promptfoo + HF sections; `OUTREACH_pr_every_eval_ever.md` — a draft
  upstream PR description offering the EEE→receipt converter (shipped since v0.9) to
  evaleval/every_eval_ever (the human submits, per that project's contribution norms).

### Changed — BREAKING (deliberate, roadmap item)
- **Python floor is now 3.10** (`requires-python >= 3.10`): Python 3.9 reached end-of-life
  2025-10-31; the ecosystem (NumPy, inspect_ai, current cryptography features) has moved. The
  redundant `python_version >= "3.10"` markers on the inspect extras are gone; CI drops the 3.9
  lane (matrix is now 3.10–3.14). Code changes: none required — the codebase was already
  3.9-clean, the floor change is packaging metadata + CI.

### Verification discipline
- 21 new tests (188 → 209): promptfoo green fixture → verified receipt, data-minimization pin
  (no exact score in the claim), dataset-commitment sensitivity, version-gate red tests,
  zero/negative/bool count guards; `pb1.` token roundtrip, tamper-inside-token, garbage/zip-bomb/
  non-dict red matrix, YAML structure + JSON-scalar parseability pins, broken-receipt refusal.
- 4 new mutation operators (16 total, all as expected): HF broken-receipt guard off, token-verify
  fake OK, promptfoo version gate off, failures dropped from pass_rate.

## [1.3.0] - 2026-07-02

### Security & correctness hardening (full 6-lens re-audit of the whole tool before tag, 2026-07-02)
- **CRITICAL — holder-binding downgrade closed.** A credential issued with a `cnf` holder key now FAILS
  verification if the KB-JWT is stripped (RFC-9901-legal no-key-binding form) — previously a bearer replay of
  a proof-of-possession credential verified OK. Bundles without `cnf` stay backward-compatible.
- **HIGH — RFC 9901 §7.3 audience/replay binding reachable through the public API.** `verify_bundle` (and CLI
  `verify --aud/--nonce`) now accept and enforce `expected_aud`/`expected_nonce`; before, the aud/nonce
  enforcement existed only on the internal `verify_key_binding` helper no public caller could reach.
- **HIGH — holder-binding check requires a verified issuer signature.** The `sd-jwt-key-binding` check now runs
  only when `sd_jwt_vc.issuer_public_key_b64` was supplied and the issuer signature verified — otherwise the
  `cnf` holder key (declared inside the issuer-signed JWT) is unauthenticated and a forged SD-JWT could report
  a valid-looking holder binding.
- **HIGH — witness quorum counts distinct KEY MATERIAL, not names** in BOTH verifiers. `verify_witnessed_checkpoint`
  AND `verify_tlog_proof` now share `checkpoint.witness_quorum`, deduping on the DECODED key bytes (Ed25519 +
  ML-DSA); one physical key under N names no longer satisfies `threshold=N` in either path.
- **HIGH — no raw tracebacks on malformed input:** a non-string `sd_jwt_vc.compact` now raises `BundleFormatError`
  (was `AttributeError`); CLI `verify`/`show-eval` catch file/JSON errors cleanly.
- **MEDIUM:** KB-JWT `aud` restricted to a single string (RFC 9901 §4.3); C2SP tree-size rejects non-ASCII
  digits; `present_with_key_binding` hashes `sd_hash` with the SD-JWT's OWN declared `_sd_alg` (read from the
  presented compact, not a module constant); the lm-eval adapter formats scores as fixed-point (no
  scientific-notation drop); `sign_checkpoint` validates keyname; origin/witness names reject all Unicode
  whitespace; `recompute_merkle_root_b64` validates `hash_alg` and shows the stated root canonically; the
  ML-DSA verify path builds its signed message inside the fail-closed guard; the status-list zlib decompression
  is size-bounded (CWE-409); `verify_tlog_proof` accepts an optional `expected_origin`.
- 188 tests (adds regressions for every item above, incl. one-key-under-many-names in tlog-proof, and a
  holder-binding check skipped when the issuer signature is unverified).

### Added — the portable proof (spec-verified against primary sources, 2026-07-02)
- **C2SP tlog-proof** (`proofbundle.tlogproof`, new CLI `proofbundle verify-proof`): emit and
  verify `.tlog-proof` files — index + RFC 6962 inclusion proof + verbatim (co)signed checkpoint,
  the C2SP "transparent signature" envelope (`c2sp.org/tlog-proof@v1`). `tlog_proof_for_bundle`
  refuses a checkpoint that disagrees with the bundle's root/size (No-Fake at build time); the
  verifier recomputes the leaf hash from the exact payload bytes, never trusts the file, treats
  `extra` as unauthenticated, and reports log/witness/inclusion sub-verdicts with a conjunction
  verdict. Rekor v2 institutionalizes exactly this persist-your-proof model. SPEC §7e.
- **ML-DSA-44 witness cosignatures** (C2SP type 0x06, FIPS 204 — the spec's SHOULD for new
  witness deployments): `cosign_checkpoint_mldsa` / `cosign_vkey_mldsa`; `verify_cosignature` now
  dispatches on the vkey algorithm byte (0x04 Ed25519 / 0x06 ML-DSA-44 — a 0x01 LOG key is still
  never a witness). Signed message = the C2SP `cosigned_message` struct (label `"subtree/v1\n\0"`,
  name-committing, RFC 8446 serialization) — pinned byte-exact by a KAT test, not just a
  roundtrip. Optional extra `proofbundle[pq]` (= `cryptography>=48`, PQ in default wheels since
  2026-05); on builds without ML-DSA a configured 0x06 witness raises UnsupportedError —
  fail-closed, never a silent False. Ed25519 stays the default; primary signatures unchanged.
  SPEC §7d.
- **Token Status List snapshot** (`proofbundle.statuslist`): offline revocation per
  draft-ietf-oauth-status-list (RFC-Editor queue, format frozen at -21). `status_claim(uri, idx)`
  goes into the receipt SD-JWT; `verify_status_snapshot` checks a supplied signed
  `statuslist+jwt` (EdDSA, `sub`↔`uri` binding, bits ∈ {1,2,4,8}, zlib bit-array) and reads the
  status. Freshness (`iat`/`exp`/`ttl`) is reported, and judged ONLY when the caller supplies
  `now` — no wall-clock assumptions in an offline verifier. Bundle format v0.1 unchanged: the
  snapshot is a separate verifier input. SPEC §7f.
- **SD-JWT VC markers** (`sdjwt_issue`): issuer header `typ: dc+sd-jwt`, a `vct` type URI
  (default `https://b7n0de.com/proofbundle/vct/eval-receipt/v1`), optional `status` claim — the
  four stable interop markers of draft-ietf-oauth-sd-jwt-vc (pre-IESG; full VC conformance stays
  deferred, type-metadata resolution deliberately not implemented).
- **COMPLIANCE.md** — an honest, non-legal mapping of receipts onto EU AI Act Article 12
  record-keeping (applies to high-risk systems from 2026-08-02), the GPAI Code of Practice Model
  Report evidence, NIST AI RMF MEASURE, and prEN 18229-1 / ISO/IEC DIS 24970 — including the
  anti-patterns section (what NOT to claim).

### Verification discipline
- **`scripts/mutation_check.py` + a CI `mutation` job** — the orthogonal mutation suite is now a
  repeatable repo gate (12 operators across kbjwt/bundle/checkpoint/tlogproof/statuslist/CLI),
  differential against the baseline; documented-equivalent mutants are asserted to SURVIVE so a
  stale equivalence argument also fails the gate. The suite immediately earned its keep: the
  ML-DSA domain-separation-label mutant survived the first run (emit+verify shared the constant —
  a self-consistency tautology) and is now killed by a byte-exact `cosigned_message` KAT.
- 44 new tests (133 → 177 in-tree): green roundtrips + red matrices (wrong leaf/log key/index,
  proof-hash tamper, unauthenticated-extra probes, quorum shortfall, ML-DSA name-commitment
  forgery, timestamp/body tamper, status-list signature/uri/typ/index attacks, bit-flip
  needs-resign) + the ML-DSA KAT pins.
- CI matrix extended to Python 3.13 / 3.14.

### Notes
- Still deferred, stated honestly: full SD-JWT VC conformance + `vct` type metadata (pre-IESG),
  per-sample Merkle receipts (v2.0 direction, THREAT_MODEL's named gap), an official in-toto
  eval predicate (proposal path via OpenSSF/CoSAI), Python-3.10 floor.

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

### Verification discipline
- 37 new tests: green roundtrips plus an adversarial red matrix per feature (disclosure drop/swap after
  KB signing, `typ`/`alg` confusion, missing required claims, fail-open probes, cosignature
  timestamp/body tamper, log-vkey-as-witness type confusion, quorum double-count, oversized signature
  blob). An orthogonal mutation suite (9 operators across kbjwt/bundle/checkpoint/CLI) kills 8/9
  mutants; the survivor is provably equivalent (oversized blobs already die at `verify_ed25519`'s hard
  64-byte signature length check).

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
