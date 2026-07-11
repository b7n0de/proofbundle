# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed — duplicate JSON keys rejected on the verify paths (WP-C1)
- **`json.loads` last-wins duplicate keys are rejected fail-closed** (new stdlib-only
  `proofbundle._strict_json.loads_strict`, `object_pairs_hook`, any nesting depth, clear
  `duplicate JSON key '<k>'` message). A duplicated key is a classic parser differential: two JSON
  implementations can disagree about which `root_b64`/`sig_b64`/`predicateType` they verified —
  for a signed **status-list token** that was a PROVEN VALID-vs-INVALID revocation split-brain.
  Converted: the native bundle (`load_bundle`; the `pb1.` HF receipt token), the DSSE statement
  verifiers (eval-result / test-result / SVR / decision), the **trust-policy loader**, the
  **per-sample opening's committed disclosure record**, the **chia-datalayer and markovian anchor
  envelopes**, the **status-list token**, the **enclave EAT**, and every `json.load` in the CLI
  (`verify-opening`, `intoto --verify`, `svr --verify`, `decision emit/verify/inspect`,
  `--anchors`). Emit side too: a predicate file carrying a duplicate key is refused before
  anything is signed. **SPEC §2 now makes duplicate-key rejection normative** (an interoperating
  implementation that keeps either occurrence is non-conforming); THREAT_MODEL carries the
  parser-differential row.
- Deliberate behavior deltas (each stricter, never looser): `to_eval_results_entry` now REFUSES a
  crypto-valid bundle whose payload carries a duplicate key (previously the entry was built
  last-wins — refusing to publish an unjudgeable value is the honest outcome);
  `decision inspect` exits 2 instead of risking a raw traceback on malformed/duplicated payloads.
- Known residual (documented in `_strict_json`): the SD-JWT/KB-JWT payload parses (`sdjwt.py`,
  `kbjwt.py`, the `bundle._issuer_requires_holder_binding` helper) — a naive conversion would
  INVERT a fail-closed direction (a rejected `cnf` read must not read as "no holder binding
  required"); that group needs its own careful pass. Keys differing only by Unicode normalization
  or a BOM are distinct JSON keys by spec and stay distinct (a downstream-validator concern).
- Negative tests `tests/test_dup_key_reject.py` (native bundle signature/merkle/top-level, HF
  token, all four DSSE verify functions in BOTH content-root modes, decision library+CLI,
  emit-side refusal, policy/statuslist/persample/enclave/anchor-envelope rejects) + a mutation
  operator proving the tests kill a disabled guard.

### Fixed — claims-hygiene gate honesty (WP-N1)
- **`scripts/claims_hygiene_check.py` no longer skips missing docs silently.** Six of sixteen
  `_DEFAULT_DOCS` entries did not exist (four lacked the `docs/` prefix; `docs/MATURITY.md` and
  `docs/MIGRATION_2.0.md` never existed), so the gate scanned only 10 docs while reporting PASS. A
  listed-but-missing path is now a FAIL (exit 1, `missing[]` in the JSON), the scan list matches the
  repository exactly, and six more user-facing docs are scanned (`docs/NON_CLAIMS.md`, `docs/DEMO.md`,
  `docs/ANCHORS.md`, `docs/ANCHORS_MARKOVIAN.md`, `docs/REVIEWERS.md`, `docs/EXPERIMENTAL_ENCLAVE.md`).
- **Soft-wrapped Markdown sentences are unwrapped before the negation check.** A negation on the
  previous physical line of the same sentence ("… not a statement that a\n  model is safe to deploy")
  was lost because every newline counted as a sentence boundary; block starts (blank line, heading,
  list item, quote, table row) remain boundaries.
- **New forbidden phrasings** (Gate 3, standard-track): `safe to deploy`, `safe model`,
  `verified result`, `correct decision`, `authorized action`, and positive `trustless` (the allowed
  wording is "trust-minimized (Bitcoin PoW time)", or an explicit negation).

### Changed — wording and reference hygiene (WP-N2)
- `verify` labels the assurance source: `ASSURANCE: <level> (issuer-declared)` plus a machine-readable
  `assurance_declared_by: "issuer"` JSON field (null when the bundle is not an eval receipt, and null
  when crypto failed — no level to attribute) — the level is the issuer's own declaration, never an
  appraisal. **Migration note:** a consumer that matched the FULL line (e.g.
  `^ASSURANCE: reproduced$`) must accept the ` (issuer-declared)` suffix; `assertIn`-style prefix
  matching keeps working.
- `trustless` → `trust-minimized (Bitcoin PoW time)` in `anchors_markovian.py` and
  `docs/ANCHORS_MARKOVIAN.md` (the Bitcoin time component is trust-minimized; nothing here is
  trust-free).
- `docs/NON_CLAIMS.md` gains a **Decision Receipts** section (a verified ALLOW is a *record*, not an
  authorization/bearer token; against cross-context replay issue receipts with `validity.audience`/
  `validity.nonce` and verify with `--aud`/`--nonce` — a v0.2 policy's `require_audience`/
  `require_nonce` enforce their *presence*) and a **TEE bridge** section; `decision verify --help`
  carries the same boundary, including that `--aud`/`--nonce` only bind a receipt that carries a
  `validity` object.
- Reference fixes, pinned by `tests/test_docs_truth.py`: ValiChord URL →
  `github.com/ValiChord/ValiChord` (INTEROP.md, INTEGRATIONS.md); SD-JWT VC citation →
  draft-ietf-oauth-sd-jwt-vc-17 (IESG "Publication Requested"; `dc+sd-jwt` not yet IANA-registered);
  `docs/EXPERIMENTAL_ENCLAVE.md` install no longer pins the stale `2.0.0b1` beta.

### Hardened after the six-lens adversarial review of this change set (2026-07-11)
- **Gate:** a listed-but-unreadable doc is now a FAIL like a missing one (it silently counted as
  scanned + PASS); heading/table-row/fence/setext lines no longer merge forward into the next
  paragraph (a negation inside a heading could exonerate the following prose); clause separators
  (`;`, `:`, `—`) now bound the negation window (a negation in an earlier, grammatically independent
  clause no longer exonerates a later positive claim); the scan set additionally covers
  INTEGRATIONS.md, EVAL_CLAIM.md, RELEASE.md, GOVERNANCE.md, CONTRIBUTING.md (25 docs).
- **Docs truth:** `docs/ANCHORS.md` no longer asserts a positive `trustless` ("run your own and no
  third-party trust remains"); `docs/REVIEWERS.md` drops its stale hard-coded test/operator counts
  (683→ the suite had grown; 26→ the operator list lives in `scripts/mutation_check.py`);
  RELEASE.md's beta section is reframed as convention-for-future-pre-releases (the "v1.x stays the
  default" sentence was stale since 2.0.0 final); THREAT_MODEL.md quotes the new `ASSURANCE:` line
  format; NON_CLAIMS.md says "digest-bound `outcomeRef`" (the verifier checks the digest's presence
  and binding, not a signature on the outcome record).
- **Tests:** content-violation ⇒ exit 1 pinned at the `main()` level; unreadable-doc ⇒ FAIL pinned;
  the exit-2 error path is pinned to carry the FULL `verify --json` field contract (incl.
  `assurance_declared_by`); the CLI-help assertion is terminal-width-independent; a line-number pin
  proves soft-unwrap keeps positions 1:1.

## [2.1.0] - 2026-07-10

First release on the 2.x line after **2.0.0 final**: a new vendored **decision-receipt/v0.1** predicate for
agent decisions; a shared **universal content root** (`jcs-sha256-v1`) that the eval-result / test-result / SVR
export paths now adopt with an explicit declared legacy mode (every already-signed 2.0.0 receipt keeps
verifying byte-for-byte); and **anchors v0.1** — a `verify --require-anchor` relying-party gate plus RFC 3161
policy-OID / certificate-expiry hardening over the experimental external-time-anchor layer. All three are
additive over 2.0.0; no released receipt is invalidated.

### Added — Decision Receipt predicate `decision-receipt/v0.1` (Phase D)
- A new **vendored** in-toto predicate for agent decisions:
  `https://b7n0de.com/proofbundle/predicates/decision-receipt/v0.1` (ADR 0001). A Decision Receipt records
  *who decided, what action was proposed, against which policy boundary, on which digest-bound evidence, what
  the verdict was, and what was explicitly not checked*. It is a DSSE-signed in-toto Statement, verified over
  the exact signed bytes.
- **CLI:** `proofbundle decision {init,emit,verify,inspect}`. `verify` follows the Phase B exit contract
  (0 crypto+structure OK · 1 crypto failure · 2 malformed/predicateType-confusion · 3 crypto OK but a supplied
  `--policy` was not satisfied). Without `--policy` the output shows `POLICY: NOT_EVALUATED`. `--version` now
  lists `predicates: eval-result/v0.1 decision-receipt/v0.1`.
- **Emission is RFC-8785 canonical** (JCS); verify never re-serializes and fails closed if the received payload
  is not its own canonical form (hash-binding rule).
- **Trust Policy v0.2** (additive): the v0.1 trust policy gains a `decision_receipt` section
  (`trusted_decision_makers`, `accepted_predicate_types`, `allowed_decision_types`/`verdicts`,
  `required_evidence_relations`, `require_policy_digest`, `require_external_anchor`/`allow_pending`). A v0.1
  policy stays valid unchanged under the v0.2 parser. The signer is matched to `trusted_decision_makers` by
  public key — `decisionMaker.id` is never believed on the JSON claim alone.
- **Non-claims (unchanged boundary):** a Decision Receipt does not prove the decision was correct, legal, safe,
  or fully informed; `actionOutcome=executed` without a separately signed outcome is self-assertion, reported
  as `action_outcome_proven=false`.
- **Decision `anchors[]` composition landed.** A `statement`-target anchor binds the SHA-256 content root
  over the exact signed payload bytes and is kept **detached** (outside the signed predicate — an anchor
  cannot live inside the bytes whose hash it commits; proofbundle#7 consensus, 2026-07-10). `verify` gains
  `--anchors`; with a policy's `require_external_anchor`/`allow_pending`, a pending (calendar-only) anchor
  is the absence of a time anchor → exit 3. See `docs/ANCHORS.md` and `tests/test_decision_anchors.py`.
- **The tamper / replay / fuzz matrix landed.** A systematic, deterministic sweep
  (`tests/test_decision_fuzz.py` — every signature byte, spread payload bytes, every required-field deletion,
  top-level type confusion, ten malformed-envelope classes, a wrong-key batch), plus audience/nonce replay
  gating (`tests/test_decision_hardening.py`, `tests/test_decision_verify.py`).
- Still deferred (not in this core): independent cross-implementation worked vectors over a decision object
  (MarkovianProtocol's reference anchor), iterated on proofbundle#7.

### Added — universal Statement content root `jcs-sha256-v1`, with a declared legacy mode (WP2, ADR 0002)
- A single shared content-root primitive now underlies both the decision-receipt path and the in-toto
  eval-result / test-result / SVR export paths: `statement_content_root` = SHA-256 over the **RFC-8785 (JCS)**
  canonical bytes of the **full** pre-signature Statement (`_type`, `subject`, `predicateType`, `predicate`).
  Signature/envelope bytes are never in the preimage, so a content root survives counter-signing and key
  rotation and a decision receipt composes byte-for-byte with an eval-result statement it cites. Exposed as the
  public `proofbundle.canonicalize_statement` / `proofbundle.statement_content_root` (shared `canonical.py`).
- The algorithm is a first-class **versioned** id (`contentRootAlg`, default `jcs-sha256-v1`), declared inside
  the signed payload so it cannot be flipped after signing. A verifier re-serializes with **exactly** the
  declared algorithm to confirm the payload is its own canonical form (fail-closed), never re-canonicalizes to
  compute a root, and never falls back between algorithms. An unknown algorithm fails closed — the
  anti-algorithm-confusion rule already applied to `merkle.hash_alg`.
- **Migration is a compatible evolution, not a cutover.** The historic `json.dumps(sort_keys=True)` wire is
  retained as an explicitly declared named mode `legacy-sortkeys-json-v0`. **Absent `contentRootAlg` ⇒ legacy**
  (never silently JCS), so every already-signed **2.0.0** eval-result / test-result / SVR receipt keeps
  verifying byte-for-byte; legacy verification is stdlib-only, so those receipts still verify on a base
  install. New receipts default to `jcs-sha256-v1`; verifying JCS canonicality needs the emit-side `[eval]`
  extra and is fail-closed without it.
- **Honest scope (No-Overclaim):** this is **not** a "universal migration complete." The eval-result /
  test-result / SVR producers now default to the new algorithm and a P0 activation test pins the boundary
  (`tests/test_intoto_content_root_migration.py`: a `sort_keys` root offered *as* `jcs-sha256-v1` is rejected;
  genuine JCS bytes declared legacy are rejected; an unknown algorithm fails closed). Still deferred: a CLI
  flag to select the content-root algorithm from the command line, and independent cross-implementation
  (MarkovianProtocol) worked interop vectors.

### Added — anchors v0.1: a `verify --require-anchor` relying-party gate + RFC 3161 hardening (WP4)
- The experimental external-time-anchor layer (`anchors[]`, shipped experimental-gated in 2.0.0) gains a
  relying-party gate: **`verify --require-anchor`** (optionally narrowed by `--anchor-type <type>`) turns "no
  verifying anchor (of that type)" into a failure — a gate layered OVER the crypto result, **exit 3 when
  unmet** (distinct from a crypto failure, exit 1), exactly like `--policy`. A **pending** anchor (an
  un-upgraded OpenTimestamps proof, a Merkle-only chia-datalayer level-i anchor) does NOT satisfy the gate
  unless `--allow-pending` is given; the gate follows the matched anchor's own status, not the global aggregate.
- **`anchors` is now a KNOWN top-level bundle field** (SPEC §7i, JSON Schema): formalized as EXPERIMENTAL and
  **detached** from the content root (an anchor attests *about* a receipt, never part of what it attests; the
  `receipt` target stamps the canonical root computed with `anchors` excluded). One-way compatibility is
  documented: a verifier built against an earlier revision lists no `anchors` field and, under
  `additionalProperties: false`, rejects an anchored bundle as malformed (exit 2) rather than ignoring it.
- **RFC 3161 TSA hardening:** the frozen TSA certificate chain is validated at the token's own `gen_time` (not
  the current wall clock), so a frozen token stays verifiable after the TSA certificate expires or rotates, and
  a certificate not valid at `gen_time` fails closed; a relying party MAY pin the TSA **policy OID** via
  `frozen.policyOid`, in which case a token whose `TSTInfo.policy` differs fails closed. New tests:
  `tests/test_cli_require_anchor.py`, `tests/test_anchors_rfc3161.py`, `tests/test_anchors_generic.py`.

### Verification discipline
- 683 tests (was 550 at 2.0.0): the decision-receipt suite (emit/verify/inspect, the tamper/replay/fuzz
  matrix in `tests/test_decision_fuzz.py` / `tests/test_decision_hardening.py`, `anchors[]` composition),
  the universal content-root migration pins (`tests/test_intoto_content_root_migration.py`: `jcs-sha256-v1`
  vs `legacy-sortkeys-json-v0`, the algorithm-confusion red matrix), and the anchors v0.1 relying-party gate
  (`tests/test_cli_require_anchor.py`, RFC 3161 policy-OID / certificate-expiry). Mutation gate: 39
  operators, all killed; the one documented-equivalent mutant still survives.

## [2.0.0] - 2026-07-09

First **2.0.0 final**. Consolidates the 2.0.0b1–b3 pre-release line (below) with the Phase B P0-core
hardening. **Breaking changes**, each with migration notes in its entry below: `merkle.hash_alg` is now
REQUIRED; `verify`'s human output replaces the bare `=> OK` with a labelled `CRYPTO:` / `POLICY:` /
`ASSURANCE:` / `LIMITATIONS:` block; exit code **3** is new (crypto OK but a supplied `--policy` was not
satisfied, distinct from a crypto failure). New: a machine-readable, fail-closed, offline **trust
policy** (`verify --policy`); an extended `--version`; a stable `verify --json` single-field contract.
The experimental TEE-attestation bridge and `anchors[]` stay experimental-gated as in the betas.

### Added — trust policy v0.1 + `verify --policy` (WP-B3)
- A relying party's trust decision is now first-class and machine-readable. `verify receipt.json
  --policy trust_policy.json` applies a fail-closed, offline trust decision OVER the crypto result:
  the signer (matched by **public key**, kid is a hint only), signature alg, bundle schema, Merkle
  hash alg, SD-JWT audience/nonce/key-binding, eval-claim freshness, and assurance level /
  pre-registration. Without a policy `verify` makes NO trust decision (`POLICY: NOT_EVALUATED`); a
  policy failure is the new exit **3** (crypto OK but policy unmet), distinct from a crypto failure
  (exit 1). A policy is never evaluated on bytes whose crypto failed.
- Policy format `proofbundle/trust-policy/v0.1` (`schemas/trust_policy_v0_1.schema.json`): snake_case,
  versioned, **fail-closed** (an unknown field is a parse error — a typo cannot silently weaken a
  policy), **offline** (no key is ever fetched). Worked example: `examples/trust_policy_strict.json`.
  `verify --json` gains `policy_ok`, `policy_id`, `policy_checks[]`.
- Honest v0.1 boundary: the `status` section is accepted so a policy can declare revocation intent,
  but `verify --policy` has no status-snapshot input in v0.1 — an ENABLED status requirement fails
  closed with a clear reason (evaluate revocation separately with `verify_status_snapshot`). A `--aud`
  flag that conflicts with the policy's `sd_jwt.expected_aud` is exit 2 (ambiguity, never a silent
  override).
- Docs: `docs/TRUST_ANCHORS.md` gains the machine-readable policy profile; the README quickstart shows
  a policy example with the explicit note that verify makes no trust decision without one.

### BREAKING — `verify` output separates CRYPTO / POLICY / ASSURANCE, and a new exit code 3 (WP-B2)
- **The human `verify` output no longer prints a bare `=> OK` / `=> FAILED`.** It now prints a
  context-labelled block so a crypto success can never be read as a policy pass or a truth verdict:
  `CRYPTO: OK|FAILED` (the only thing the offline core proves), `POLICY: NOT_EVALUATED (no trust
  policy supplied)`, `ASSURANCE: <issuer's verbatim self-declared level> | n/a`, and `LIMITATIONS:`
  (the honest "what a signature does NOT mean" line). **A script that greps `verify`'s stdout for
  `=> OK` must switch to `CRYPTO: OK`** (other subcommands — `verify-proof`, `show-eval`, etc. — keep
  their existing `=> OK` for now).
- **New exit code 3.** The `verify` exit-code contract is now `0` = crypto OK (and policy satisfied
  or none supplied), `1` = crypto/verification failure, `2` = malformed input, `3` = crypto OK but a
  supplied `--policy` was NOT satisfied. `--policy` itself lands with WP-B3; until then exit 3 cannot
  occur and `POLICY:` always reads `NOT_EVALUATED`. Documented in `proofbundle verify --help`.
- **`verify --json` gains a stable single-field contract** (additive; the existing `ok`/`checks`/
  `matrix`/`meaning` keys are unchanged): `schema_ok`, `signature_ok`, `merkle_ok`, `sd_jwt_ok`,
  `sd_jwt_issuer_verified`, `key_binding_ok`, `audience_ok`, `nonce_ok`, `freshness_ok`, `anchor_ok`,
  `witness_ok`, `status_ok`, `assurance_policy_ok`, `crypto_ok`, `policy_ok`, `assurance`,
  `warnings[]`, `limitations[]`. A check that did not run in the offline core path is `null` (not
  applicable), **never silently `true`** — in particular `sd_jwt_ok` is `null`, not `true`, when an
  SD-JWT's issuer signature was not checked (no issuer key supplied), with a warning saying so.
- **Hardening (verify-lens review):** `decode_eval_claim` now rejects an out-of-enum `assurance_level`
  on the verify path (closing an ASSURANCE-line injection where a hand-signed claim could embed
  newlines to forge fake `CRYPTO:`/`POLICY:` lines); deeply-nested JSON maps to the documented
  malformed exit (2) instead of a raw `RecursionError`; the error-path JSON carries the full field
  contract so integrators can always read `crypto_ok`.
- **Migration**: replace any `verify`-stdout `=> OK` grep with `CRYPTO: OK`; treat exit 3 as a new
  (policy) outcome distinct from 1 (crypto failure). No bundle format change.

### BREAKING — `merkle.hash_alg` is now a REQUIRED field in SPEC.md and the JSON Schema (WP-B1)
- **The verifier already rejected a missing `hash_alg`** since v1.6 (`bundle.py` `_require`d it) — this
  closes the documentation/schema half of that gap. `SPEC.md` §5 now states `hash_alg` as `required: yes`
  (was `no`, contradicting the code) with an explicit anti-algorithm-confusion MUST: a verifier MUST NOT
  silently default a missing value, and a future hashing algorithm MUST register its own distinct value.
  `schemas/proofbundle_v0_1.schema.json` adds `hash_alg` to `merkle.required` to match.
- **Who this actually breaks:** any consumer that validated bundles against the **JSON Schema only**
  (not `proofbundle verify`) previously accepted a pre-v1.6 bundle missing `hash_alg` that the real
  verifier already rejected — that schema-only path is now correctly stricter, matching the code.
  Every bundle any proofbundle emitter has ever produced since v1.6 already carries `hash_alg`, so this
  affects only hand-authored or archived pre-v1.6 bundles.
- **Migration**: add `"hash_alg": "sha256-rfc6962"` to the bundle's `merkle` object. The verifier's error
  message for a missing field now states this explicitly (`bundle.py::_require_hash_alg`, shared by
  `verify_bundle` and `recompute_merkle_root_b64` so the two call sites cannot drift apart again).
- **Attribution correction**: this entry is a SEPARATE breaking fix and does not close any tracked
  issue. Issue #28 is scoped exclusively to `--version` printing the pinned spec revision — see the
  entry directly below, which is the one that actually closes it.

### BREAKING — `proofbundle --version` output is now multi-line (closes #28)
- Was a single line (`proofbundle <version>`). Now four lines: package version, the pinned `SPEC.md`
  revision (new `SPEC_REVISION` constant next to `__version__`, kept in sync with SPEC.md's own
  `Revision:` header by a doc-truth test), the JSON Schema id, and a best-effort, fail-safe list of
  optional extras actually usable in this install (`eval`/`sdjwt`/`anchors[beta]`/`pq`/`inspect`/
  `experimental` — a missing/broken extra is silently omitted, never a traceback). **A script that
  parsed `--version`'s stdout expecting exactly one line must be updated**; the exit code (0) and the
  first line's `proofbundle <version>` prefix are unchanged.

## [2.0.0b3] - 2026-07-06  (BETA / pre-release)

### Added — external time / provenance anchors (the `anchors[]` layer, EXPERIMENTAL)
- **`chia-datalayer/v1`** (first-party): a fail-closed offline verifier for a canonical root proven included
  under a published Chia DataLayer store root via a level-i Merkle inclusion path. Ships as a built-in anchor
  type; a level-i-only proof reports `warn` (does not satisfy `--require-anchor`). See `docs/ANCHORS.md`.
- **`markovian-provenance/v1`** (third-party worked example, external contributor MarkovianProtocol, #18):
  a wallet-attributable, Bitcoin-anchored stamp registered through `register_anchor_type`. It binds the
  committed data to a wallet (`merkle_root = sha256(data_hash:salt:wallet)`) and delegates the Bitcoin time
  proof verbatim to the built-in OpenTimestamps verifier (compose, not reinvent). Opt-in via `register()`;
  not wired into the built-in set by design.
- README now documents the `anchors[]` extension layer and the `register_anchor_type` bring-your-own-type
  interface (the `[anchors]` extra), with an honest "v2.0 beta" label.

### Changed
- **Repo hygiene**: removed a committed `.venv-anchors/` tree from tracking (cleared 59 OSSF-Scorecard HIGH
  alerts); enabled auto-delete-head-branches, Dependabot alerts/updates, and secret-scanning push protection.
- Type checker (`mypy src`) is clean again after the third-party anchor addition (narrowed envelope fields).

## [2.0.0b2] - 2026-07-05  (BETA / pre-release)

### Added — in-toto eval-result attestation export (PROPOSED; under discussion in-toto/attestation#565)
- **`proofbundle intoto <receipt>`** exports an eval receipt as a DSSE-signed in-toto Statement v1 with
  the dedicated **`eval-result/v0.1`** predicate (vendor namespace `https://b7n0de.com/attestation/eval-result/v0.1`
  for now — the migration path to an `in-toto.io` namespace is documented and needs a redirect PR only
  there). The predicate extends the community `test-result` shape with a threshold-based `claims[]`,
  privacy-preserving **salted-commitment** subjects, and an optional binding to the external signed
  receipt. DSSE `payloadType` is the canonical `application/vnd.in-toto+json`; verification accepts
  standard and url-safe base64.
- **Subject profiles** (`--subject-profile`): `receipt` (default — binds without revealing the model),
  `public-model` and `release-gate` (a disclosed artifact via `--subject-name`/`--subject-sha256`, the
  SLSA "deploy only if the eval passed" hook). Each profile documents what the subject IS.
- **Commitment-only guarantee**: the export refuses a claim that still carries a plaintext identifier or a
  raw salt (fail-closed), is deterministic (byte-identical statement for identical input), and refuses an
  incomplete receipt. New adversarial tests + a salt-leak mutation operator.
- Status is **PROPOSED, not standardized** — see docs and the homepage label. No new runtime dependency;
  the export stays in the pure-Python DSSE path.

### Added — in-toto SVR export (Summary Verification Result, svr/v0.1)
- **`proofbundle svr <receipt>`** emits an in-toto **SVR** (`https://in-toto.io/attestation/svr/v0.1`) for a
  receipt — but ONLY after a real, passing verification. It carries only PASSING property strings
  (`PROOFBUNDLE_SIGNATURE_VALID`, `PROOFBUNDLE_RECEIPT_UNCHANGED`, `PROOFBUNDLE_THRESHOLD_MET`, and, when
  genuinely verified, `PROOFBUNDLE_SAMPLE_ROOT_VALID` / `PROOFBUNDLE_PREREG_BOUND` / `PROOFBUNDLE_ANCHOR_VALID`)
  — type-generic, never a vendor/service name. A missing check produces NO property.
- **No SVR on FAIL**: the export refuses (fail-closed) if the receipt is not a valid eval receipt, does not
  cryptographically verify, or did not pass its threshold. SVR has no FAILED form — a PASSED|FAILED verdict
  would be a VSA, deliberately not implemented here (documented). `verifier.policy` ({uri, digest}) is the
  optional v0.1 extension field. WATCH: in-toto/attestation#551 (verifier.policies as required) is an open
  SVR-v0.2 risk. New adversarial tests + an SVR-passing-only mutation operator.

### Added — external time-anchor layer (EXPERIMENTAL; the `[anchors]` extra)
- **`proofbundle.anchors`** — a generic, fail-closed layer for external time anchors on a receipt. Two
  targets, never mixed: `preRegistration` (the commitment existed before the run — the in-toto#565
  backdating point) and `receipt` (existed from time T). Missing anchors → SKIP; present → a root
  mismatch, unknown type, or broken proof is a FAIL, never silent; `--require-anchor <type|any>`. The
  base install stays anchor-free (only `cryptography`); a receipt with no anchors verifies unchanged.
- **RFC 3161 TSA anchor** (`anchors_rfc3161`): offline verify (`rfc3161-client`) against the TSA chain
  **frozen into the anchor at emit time** (a TSA can rotate — FreeTSA rotated March 2026). Proven
  against a real captured FreeTSA token fixture incl. the frozen-chain rotation test.
- **OpenTimestamps anchor** (`anchors_ots`): honest lifecycle — a PENDING proof is a **WARN**, never a
  full anchor; an upgraded proof needs a Bitcoin block header (a local pruned node) to verify offline,
  and without one it is reported as upgraded-unverified, never a silent pass. Pending vs upgraded are
  distinguished.
- **Extension mechanism** (`register_anchor_type`) for third-party anchor types with a fail-closed
  verify callable. `docs/ANCHORS.md`. A dedicated CI `anchors` job exercises the TSA + OTS tests.

### Added — verify check matrix + honest meaning block
- **`proofbundle verify --matrix`** prints the per-check status matrix plus an explicit "what `=> OK`
  proves / does NOT prove" block (authenticity + integrity of the bytes, never the truth of the result —
  see `NON_CLAIMS.md`). The same `meaning` / `nonMeaning` fields and a `matrix` array are ALWAYS present
  in `verify --json`. Additive and non-breaking: the existing `ok` / `checks` keys are unchanged and the
  default human output is identical unless `--matrix` is passed.
## [1.9.2] - 2026-07-05

Verify-path hardening from an independent six-lens review, plus a public-trust documentation pass.
No wire-format change; no new features.

### Fixed — verify-path completeness (both are stricter, never looser)
- **Eval-claim field set enforced on the VERIFY path** (`decode_eval_claim`, review F3). The exact
  key set (`_REQUIRED` present, no unknown fields) was enforced only when emitting; a hand-signed
  claim missing a required field or carrying an unknown one decoded fine. It is now rejected
  fail-closed. **SemVer note:** claims that were previously *accepted* on decode despite a missing
  or unknown field are now *rejected* — this matches the documented `_REQUIRED` contract, and every
  claim `emit_eval_receipt` produces still decodes unchanged. New regression test + mutation operator.
- **Downgrade trap closed** (`verify_bundle`, review F4): when a relying party passes
  `expected_aud`/`expected_nonce` (CLI `--aud`/`--nonce`) but the bundle carries no verifiable Key
  Binding JWT, verification now FAILs closed with an `sd-jwt-key-binding` check instead of returning
  `=> OK` — the requested RFC 9901 §7.3 replay/audience binding could not be enforced. Backward
  compatible: verifiers that pass no `expected_*` are unaffected. Test + mutation operator.
- **`show-eval`** no longer risks a raw traceback on a malformed claim (the F3 fix makes decode
  reject it first); regression test pins the "never a raw traceback" contract.

### Added — CI gates
- **Claims-hygiene gate** (`scripts/claims_hygiene_check.py`): fails when a forbidden marketing
  overclaim appears in the docs outside a negation (the exact phrase list lives in the script).
- **Doc-link gate** (`scripts/doc_link_check.py`): fails on a broken internal Markdown link.

### Changed — public-trust documentation (truth pass)
- README leads with the receipt kernsatz + a plain-language section; the stale hardcoded test count
  is gone (guarded). New `docs/INSPECT_HAPPY_PATH.md` — the one Inspect-to-receipt walkthrough,
  every command verified against the real API. CITATION version synced + abstract bounded (with a
  version==pyproject test). SECURITY gains a coordinated-disclosure window. COMPLIANCE EU AI Act
  high-risk timeline updated for the Digital Omnibus (2027-12-02 / 2028-08-02). The 95% detection
  claim now states its externally-sourced-challenge condition. Internal review/outreach drafts
  archived out of the repo root.

## [2.0.0b1] - 2026-07-02  (BETA / pre-release)

### Added — TEE-attestation bridge (EXPERIMENTAL v2.0 preview; opt-in, unstable)
- **`proofbundle.experimental.enclave`** (install extra `[experimental]`): make
  `assurance_level = enclave_attested` verifiable. Following the IETF RATS Passport model
  (RFC 9334), a Verifier appraises raw TEE evidence (Intel TDX / NVIDIA GPU) out of band and signs
  an **EAT** (RFC 9711, JSON/JWS, EdDSA); `verify_enclave_attestation` checks it OFFLINE — signature
  under the Verifier key (a supplied trust anchor), `typ`/`alg`, and `eat_nonce ==
  enclave_binding_for(receipt)` (the binding = base64url SHA-256 over the receipt's exact signed
  payload, which the enclave places in its quote user-data / TDX `REPORTDATA` / GPU report nonce).
  The trustworthiness `tier` is REPORTED verbatim (stand-in for the still-draft AR4SI/EAR), never
  interpreted. **Honest scope:** proofbundle does not parse or appraise raw hardware evidence — that
  is the Verifier's role; it verifies the Verifier's signed result + the receipt binding. Standards-
  native (RFC 9334 + 9711), offline, vendor-neutral — vs proprietary certificate + ledger approaches.
  CLI `proofbundle verify-enclave`; `docs/EXPERIMENTAL_ENCLAVE.md`; `examples/experimental_enclave.py`.

### Experimental gating (so nothing depends on a preview by accident)
- Everything lives under `proofbundle.experimental`, is NOT re-exported from the top-level package
  (must be imported explicitly), and emits an `ExperimentalWarning` once on import. The stable v1.x
  trusted core imports none of it.

### Beta-release discipline
- Version `2.0.0b1` (PEP 440 pre-release — `pip install proofbundle` will NOT pull it; use `--pre`
  or an exact pin). The stable **v1.x line remains the default**; the experimental bridge is doubly
  gated (pre-release channel + `[experimental]` extra). No wire-format or behavior change to any v1
  path. Promote toward `2.0.0` only after the preview stabilizes and, ideally, an external audit.

### Verification discipline
- 320 tests (303 on the v1.9.1 base; +16 enclave and +1 EAT-verifier fuzz case: binding, verify roundtrip, freshness,
  and an adversarial red matrix — wrong verifier key, cross-receipt binding, typ/alg confusion,
  profile mismatch, claim tamper, garbage, string-exp — plus the experimental-gating pins). Mutation
  gate: 31 operators (+1 receipt-binding), all killed. Parser fuzz extended to the EAT verifier.

### Notes
- Built on the byte-exact upstream **v1.9.1** tag (which carried extra release-review hardening:
  symmetric `self_issued` type-guard, beacon flag mutual-exclusion + u64 round bound).
- Preview roadmap: migrate `tier` to AR4SI/EAR when they become RFCs; optional CWT/COSE encoding;
  reference Verifier profiles for TDX + GPU (kept out of the core — they pull vendor tooling).
## [1.9.1] - 2026-07-02

### Added — closing the last small review-backlog items
- **Status-list trust-anchor separation** (external review #8/#12): `verify_status_snapshot` gains
  an optional `receipt_issuer_pubkey` and reports `self_issued=True` when the status list is signed
  by the SAME key as the receipt — an issuer attesting its own "still valid" state carries no
  independent revocation assurance. Reported, not fatal (the relying party decides); a distinct,
  independently-operated status authority is the stronger anchor. New THREAT_MODEL row + statuslist
  docstring + tests + mutation operator.
- **`make coverage`** target (line coverage of the core over the suite; needs `coverage`).
- **docs/GLOSSARY.md** — proofbundle in plain terms for a developer without a crypto background
  (the review's Iteration-2 request): the 30-second picture, five steps in order, and a term list,
  plus "what `=> OK` means and doesn't". Linked from the README docs table.

### Verification discipline
- 303 tests (was 299): +3 self-issued separation (not-asked → None, same-key → True, distinct-key →
  False). Mutation gate: 30 operators (+1 self_issued compare), all killed.

### Notes
- No wire-format or verify-behavior change for existing callers — `self_issued` is a new optional
  report; omitting `receipt_issuer_pubkey` behaves exactly as before.
- Remaining backlog is now owner-only (a binary inspect_ai `.eval` fixture for `make full-demo`,
  README design assets, GitHub branch-protection / `pypi` reviewer settings) or human actions
  (outreach, external audit, JOSS paper) — all tracked in REVIEW_v1.6.md and RELEASE.md.

## [1.9.0] - 2026-07-02

### Added — public-beacon audit mode + a rewritten README
- **Public-randomness beacon audits** (`proofbundle.beacon`, CLI `audit-challenge
  --beacon-randomness/--beacon/--round`): the third per-sample challenge mode (after auditor-nonce
  and self-challenge) is now formalized. Derive the challenge from a drand / NIST beacon pulse —
  `nonce = SHA-256("proofbundle/v1.9/beacon-nonce" ‖ beacon_id ‖ round ‖ pulse)` — so the audit is
  **non-interactive** (no live auditor) and **publicly re-derivable** (anyone re-fetches the same
  pulse and gets the same indices). A pulse from a round emitting after the receipt's signed
  timestamp cannot have been ground against (RFC 3797 pattern). `AuditRequest.as_dict()` publishes
  the beacon id + round + indices alongside the receipt. Offline-first: the relying party supplies
  the pulse bytes and validates the beacon's own signature + round timing out of band (stated
  honestly — this module does not verify the BLS/RSA beacon signature). `examples/persample_audit.py`
  gains a beacon variant. SPEC §7g.
- **README rewritten for humans** (556 → ~130 lines): problem-first, a 60-second offline try, the
  "what it proves / does not prove" table up top, one architecture diagram, a features-at-a-glance
  list, and a docs table — the exhaustive standards enumeration and deep-dives moved to the linked
  SPEC/EVAL_CLAIM/INTEROP/FAQ docs. Closes the review's "a fresh reviewer gets lost / quickstart
  needs a checkout" finding.

### Verification discipline
- 299 tests (was 289 test-methods upstream; +10 beacon, roundtrip/binding/red-matrix + CLI mode +
  a pinned nonce-construction KAT). Mutation gate: 29 operators (+1 beacon round-binding), all
  killed; the documented-equivalent survivor still survives.

### Notes
- Built on the byte-exact upstream **v1.8.0** tag (which carried release-review hardening — verify-
  path TOCTOU single-read, `merkle.hash_alg` required, comparator/threshold enforcement in
  `decode_eval_claim`, HF value-check fail-closed, per-sample canonical-order with native-int
  compare, `prereg --check` authenticated, tlog-proof ASCII-digit guard). No wire-format change;
  the beacon mode is a new way to *derive* an existing challenge, not a format change.
## [1.8.0] - 2026-07-02

### Added — provenance, pre-registration, and credibility (external-review backlog P1/P2)
- **Adapter provenance hardening** (`adapters/_provenance.py`): inspect_ai, lm-eval and promptfoo
  claims now record, where the framework exposes it, a stable **run-id**, a **config-hash**
  (`<alg>:<hex>` over canonical config JSON — RFC 8785 JCS when available, deterministic
  sort-keys fallback, labeled either way), and the **log-native timestamp** (inspect
  `eval.created`, lm-eval's Unix-float `date`, promptfoo `evaluationCreatedAt`) instead of only
  the caller's timestamp — this ties the receipt's descriptive run_timestamp to the value the harness's
  own log recorded, narrowing (not eliminating) the "a self-attesting issuer can backdate" gap: a dishonest issuer
  who controls the log can still forge the log-native field. lm-eval
  also carries its native `task_hash`.
- **`proofbundle prereg <protocol>`** (`prereg.py`, CLI): commit to an eval protocol BEFORE the
  run — sha256 over the RAW file bytes (the accepted document-commitment convention: git blob,
  RFC 6962 leaf, in-toto DigestSet all hash raw bytes) → goes in the claim's `prereg_sha256`.
  `--check <receipt>` verifies a disclosed protocol matches. This is the anti-cherry-picking
  mitigation for best-of-many runs (per-sample audit covers within-run doctoring).
- **HF value-consistency guard** (`hf_evals.to_eval_results_entry`): a published `value` that
  contradicts the receipt's signed pass/fail verdict (value `<comparator>` threshold ≠ `passed`)
  is refused unless `allow_value_mismatch=True` — a Hub reader sees the value, not the token.

### Added — security tooling & credibility docs
- **CodeQL** workflow (advanced setup, SHA-pinned to codeql-action v4.35.1 — default setup can't
  be pinned) and **OpenSSF Scorecard** workflow (scorecard-action v2.4.3, publishes results).
- **Property-based parser fuzzing** (`tests/test_fuzz_parsers.py`, Hypothesis): every
  attacker-controlled parser (tlog-proof, checkpoint, cosignature, SD-JWT, KB-JWT, status-list)
  must return-or-raise-a-proofbundle-error on ANY input, never an uncaught crash. (Manually
  smoke-tested over ~16k hostile inputs where Hypothesis was unavailable.)
- **docs/FAQ.md** (skeptics), **docs/TRUST_ANCHORS.md** (where every anchor comes from),
  **docs/PROJECT_BRIEF.md** (funding one-pager + 3 grant-abstract seeds), **examples/README.md**.
- **COMPLIANCE.md**: regulatory-safe wording, an 8-item "claims that must NEVER be made" list, an
  honest capability→concept→gap mapping, and a legal/governance FAQ — standards status verified
  2026-07 (EU AI Act Art. 12 in force 2026-08-02; NIST AI RMF 1.0 + GenAI Profile; no eval-attestation
  standard exists).
- **INTEROP.md**: at-a-glance comparison tables vs Sigstore Rekor, Inspect logs, in-toto
  test-result, ValiChord, plus the ≤25-word niche + its explicit bound.
- **EVAL_CLAIM.md**: field table gains `provenance` and `samples` rows; stale "3.9-safe" comment removed.

### Verification discipline
- 289 tests (was 263): +provenance (config-hash determinism, log-native timestamp, run-id per
  adapter), +prereg (raw-bytes hash, match/mismatch, CLI roundtrip, trailing-byte tamper),
  +HF value-consistency (consistent ok / inconsistent refused / override / non-eval skip),
  +parser fuzz module. Mutation gate: 28 operators (+2 for prereg + HF checks), all killed.

### Notes
- No wire-format or verify-behavior change; `provenance`/`samples` are additive optional claim
  fields (already schema-additive since v1.4/v1.5). CodeQL/Scorecard SHAs are current as of
  2026-07-02 — re-verify before relying on them (RELEASE.md).
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
- No wire-format change. NOTE: the released v1.7.0 additionally carried pre-release-review security fixes
  (decode_eval_claim TOCTOU single-read, verify-side comparator/threshold validation, persample native-id ordering)
  that DO change verify-path behavior vs v1.6.1 — see the v1.8.0 section and commits. This is a
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
