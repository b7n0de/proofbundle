# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.6.1] - 2026-07-18 (security patch, BETA, relation EXPERIMENTAL)

Status boundary (No-Overclaim): 3.6.1 remains audit-candidate BETA, relation/v0.1 EXPERIMENTAL —
NOT stable/audited/production-ready. This is a targeted security patch closing the eight findings of
the 3.6.0 Teil-1/Teil-2 adversarial audit; the overall maturity verdict is unchanged (Research Beta).

### Fixed (security)
- **PB-2026-0717-01 (P0) targetSubjectDigest pin fail-open:** a declared `targetSubjectDigest` against a
  cryptographically valid target whose actual subject is absent / null / malformed / ambiguous fell
  through to `VERIFIED` (False Accept, reaching `safeForAutomation=true`). Now fail-closed with a stable
  wire code (`RELATION_TARGET_SUBJECT_MISSING` / `_AMBIGUOUS` / `_MALFORMED`; present-but-wrong stays
  `_MISMATCH`); the CLI loader no longer silently binds `subject[0]` from a multi-subject statement.
  Fixed in Python (decision + outcome closed by construction) AND the Rust second-verifier.
- **PB-2026-0717-06 (P0) canonicality optional without JCS:** without `rfc8785` the `strict=False` path
  accepted a non-canonical, validly-signed payload with `ok=true`. `rfc8785` is now a **core dependency**
  and the security-verify path fails closed regardless of `strict` (an absent canonicalizer is a broken
  install, never a lenient mode).
- **PB-2026-0717-04 (P1) same-key missing verified_under:** a VERIFIED same-key edge with a missing
  `verified_under` produced no violation; now `RELATION_SIGNER_UNAUTHORIZED` (Python + Rust).
- **PB-2026-0717-07 (P1) verify-API raised on malformed input:** `verify_decision_receipt` /
  `verify_outcome_receipt` now return a stable fail-closed verdict for untrusted unparseable input; the
  explicit `verify_*_or_raise` variants raise. The RE-GATE closed a residual hole in the same class: a
  wide (`json_nodes` over cap) or oversized (`input_bytes` over the 8 MiB cap) but validly-signed payload
  raised a raw `BudgetExceeded` (a `ProofBundleError` sibling of `BundleFormatError`) because the crypto
  verify + body load + budget check ran outside the never-raise guard; they now sit inside it and surface
  as a fail-closed verdict. The low-level primitives (`dsse.verify_envelope`, `_strict_json.loads_strict`)
  keep their raising contract.
- **PB-2026-0718-11 (P1) never-raise broken on the CLI (RecursionError):** a pathologically deep JSON
  pack raised a RAW `RecursionError` out of `anchor verify-pack` (and other raw `json.load` verify
  surfaces). All verify surfaces (CLI `anchor verify-pack` / `anchor inspect` / key-extract, the bundle
  claim-payload path) now route through the strict parser, which maps deep nesting to a clean
  `BundleFormatError` (bounded depth) with the same malformed class on API and CLI, never a raw traceback.
- **PB-2026-0718-11b (P1) bounded-depth was interpreter-version-dependent:** the deep-nesting guard relied
  solely on CPython raising `RecursionError` during parse — true on <=3.11 but NOT on 3.12+, where the C
  scanner accepts far deeper input without raising, so the documented bounded-depth guarantee silently did
  not hold on 3.12/3.13/3.14. The strict parser now enforces an EXPLICIT `budget.json_depth` cap (default
  64, comfortably above the repo's deepest legitimate document at depth 9 and far below CPython's
  ~1000-frame recursion limit so downstream JCS canonicalization stays safe), giving one stable
  `"JSON nesting is too deep"` outcome on every interpreter.
- **PB-2026-0718-F3 (P1) verify raised on malformed detached anchors:** `verify_decision_receipt`, given a
  caller-supplied malformed `anchors` (a non-dict entry, an unknown field, invalid base64, a non-list),
  raised a raw `BundleFormatError` out of the detached-anchor block, which ran outside the never-raise
  guard. It now fails closed to `anchors_ok=False` + an error, consistent with the fail-closed verdicts
  `verify_anchor` already returns for a bad target/type/root.
- **PB-2026-0718-F2 (P1) verify crashed on a type-confused non-dict `policy`:** a caller-supplied non-dict
  `policy` (a JSON scalar or list) made `verify_decision_receipt` / `verify_outcome_receipt` raise a raw
  `AttributeError` from `policy.get(...)` — not even a `ProofBundleError`, so an `except ProofBundleError`
  consumer got a raw traceback (and on the outcome path the crash fired even on an unauthenticated
  envelope). Guarded in two layers: `evaluate_decision_policy` returns a fail-closed verdict for a non-dict
  policy, and the decision/outcome call sites treat a non-dict policy as a fail-closed `policy_ok=False`
  (a requested-but-malformed policy is never a silent pass).
- **PB-2026-0718-MJSON-01 (P2) `decode_eval_claim` broke its "None on any failure" contract:**
  `load_bundle` (a bad path → `OSError`) and `verify_bundle` (a non-bundle dict → `UnsupportedError` /
  `BundleFormatError`) ran outside its try, so a non-bundle / non-path argument raised a raw exception. Both
  now sit inside the guard and the except covers the malformed-input family, so the documented `None` holds.
- **PB-2026-0718-PKG-01 (P1) sdist was not genuinely self-testable:** the sdist collected cleanly but 26
  shipped tests FAILED from an extracted sdist because they assert repo/CI/Rust/docs layout facts (the
  contents of `.github/workflows`, the Rust verifier source under `tools/`, `SPEC.md`/`CITATION.cff`, audit
  records) — material the allowlist deliberately prunes. Those repo-context tests now SKIP outside a git
  checkout (`tests/conftest.py`), so `pip install <sdist> && pytest` runs clean (1873 passed, 0 failed);
  the MANIFEST.in "self-testable" claim is corrected to this honest form.
- **PB-2026-0718-PKG-02 (P2) shipped-example policy missing from the sdist:**
  `docs/adr/renewal_policy.example.json`, which `tests/test_renewal_policy.py` loads as a "shipped
  example", was absent from the tarball (the allowlist grafted only `docs/readiness_pack`). It is now
  shipped by exact path (not `graft docs/adr`, which would also ship ADR markdowns whose links reference
  pruned repo files).
- **PB-2026-0718-CB-01 (P1) bytearray public key crashed every DSSE verify entrypoint:** the shared
  `signature.verify_ed25519` primitive admitted a `bytearray` in its type guard but passed it straight to
  `Ed25519PublicKey.from_public_bytes` / `.verify`, which require exact `bytes` and raise a raw `TypeError`
  — escaping decision / outcome / relation-statement / run-ledger / verification-summary verify as an
  uncaught crash (defeating the never-raise fix above). It now coerces `bytes(public_key)` / `bytes(signature)`
  so a VALID bytearray key VERIFIES (mirrors `verify_ecdsa_p256`, which already coerced), never a crash or a
  wrong False.
- **PB-2026-0718-BUDGET (P1) sibling DSSE verifiers leaked raw BudgetExceeded:** `verify_run_ledger`,
  `verify_relation_statement`, `verify_verification_summary` and `verify_trust_pack` are dict-returning
  never-raise surfaces, but a wide (json_nodes over cap) / oversized (input_bytes over 8 MiB) / over-signatures
  untrusted envelope raised a raw `BudgetExceeded` (a `ProofBundleError` sibling of `BundleFormatError`) —
  the crypto/load/budget/parse ran outside the guard and the except only caught `BundleFormatError`. All four
  now move that prefix inside the never-raise try and catch `ProofBundleError`, returning a fail-closed
  verdict (mirrors decision/outcome). `verify_trust_pack`'s non-list-signatures case is now a fail-closed
  verdict too, not a raise.
- **PB-2026-0718-CANON (P2) sibling verifiers failed OPEN without the canonicalizer:** `verify_run_ledger`,
  `verify_relation_statement`, `verify_verification_summary` and `verify_trust_pack` used
  `canonical_ok is True or (canonical_ok is None and not strict)`, so with `rfc8785` absent a non-canonical
  payload passed with `ok=true` in default mode — the same False Accept PB-2026-0717-06 already closed for
  decision. Since `rfc8785` is now a core dependency, an absent canonicalizer is a broken install: all four
  fail closed regardless of `strict`.
- **PB-2026-0718-RE-TCE-06 (P2) `verify_status_snapshot` crashed on a non-str token:** a non-str
  `status_list_token` (int / None / list) raised a raw `AttributeError` from `.count(".")`. A wrong-type
  token is now a fail-closed verdict, like a garbage string already was.
- **PB-2026-0718-SWEEP (P2) four verifiers crashed on a type-confused primary argument:** a full breadth
  sweep (annotation-typed) of every public `verify_*` entrypoint found `verify_tlog_proof` raising a raw
  `TypeError` on a non-str `text` (and `BundleFormatError` on a bad `threshold`), `verify_key_binding` a raw
  `AttributeError` on a non-str `compact`, `verify_sd_jwt` a raw `AttributeError` on a non-str `compact`, and
  `verify_commitment` a raw `AttributeError` on a non-str presented `identifier`. All four now return a
  fail-closed verdict / `False` for those inputs. The remaining verifiers swept clean (`verify_inclusion` /
  `verify_consistency` return `bool` on hostile well-typed input, type-confusion there is a caller error not
  an untrusted-wire path; `verify_witnessed_checkpoint` / `verify_sample_opening` already typed-reject).
- **PB-2026-0717-08 (P1) legacy assurance booleans overstate:** `action_outcome_proven` / `evidence_bound`
  (decision) and `execution_proven` / `receiver_bound` (outcome) are digest-presence booleans, now
  **deprecated** in favour of the `evidence_levels` ladder (a deprecation warning fires on an
  over-claim); fields retained for backward compat.

### Changed / Added
- **PB-2026-0718-11 (P1) cross-format comparator passed vacuously on singleton groups:** the conformance
  corpus-integrity check grouped cases by `crossFormatId` and SKIPPED any group with fewer than two members
  — but all six `xfmt-*` groups had exactly one member, so the "the same scenario agrees across formats"
  check was vacuously true and reported ok=true while verifying nothing. A singleton `crossFormatId` is now
  a fail-closed problem (a cross-format id must link >= 2 format representations), and the six ids now link
  their decision AND outcome encodings (which agree on every shared axis), so the comparator is non-vacuous.
  RT-07: a sweep confirmed `cross_format.py` was the only group-by-id comparator with the skip-on-<2 pattern.
- **PB-2026-0718-16 (P2) merkle-path step budget was not enforced on the direct dict path:** the
  `merkle_path` budget (256) existed but was checked nowhere — `verify_inclusion` / `verify_consistency` ran
  a per-step hash loop over an unbounded `proof` list, and the 8 MiB `input_bytes` byte-proxy never applies
  when a bundle is passed as a dict (no bytes to measure). A proof over the budget (257 / 4096 / 65536 steps)
  now fails closed in the verification core, effective on the direct dict path (RT-09); a non-list proof or
  non-int tree size is fail-closed too (no raw comparison crash). A legitimate `<= log2(tree_size)` proof is
  unaffected.
- **PB-2026-0717-05 (P1):** conformance corpus gains normative subject-pin negative-state vectors
  `relation/target-subject-missing` + `relation/target-subject-ambiguous` (independent SPEC oracle).
- **PB-2026-0717-02 (P1):** `MANIFEST.in` ships the tests' runtime assets in the sdist (fixtures,
  schemas, examples, conformance, formal, scripts) → a fresh-from-sdist pytest collects with 0 errors
  (was 13); the Rust tree is excluded (not a Python-sdist artifact).
- **PB-2026-0717-03 (P2):** byte-reproducible sdist regression test over the existing F2 normaliser
  (`scripts/build_reproducible.py --check` proves two clean builds are byte-identical). The published
  3.6.0 predates F2 and is honestly NOT byte-reproducible.

## [3.6.0] - 2026-07-17 (audit-candidate, BETA, relation EXPERIMENTAL)

Status boundary (No-Overclaim): 3.6.0 is **NOT** stable, audited, or production-ready. The only
progress claim is **audit-candidate: all internal assurance gates are green; the sole remaining gate to
stable is an independent external security audit**. 4.0.0-stable = 3.6.0 + that external audit closed +
findings accepted + relation wire-freeze. This section was produced under the six-lens / adversarial
master-prompt-v2 pre-tag audit discipline (Front-Load §7); that INTERNAL audit is explicitly not a
substitute for the external one.

### Added (audit-candidate assurance, EXT §10 minus the external audit)
- **33-check audit-candidate matrix (`scripts/audit_candidate_matrix.py`):** one machine-checkable
  check per §9 acceptance obligation, orchestrating the foundation gates (formal model, type-confusion,
  rust-parity, readiness pack, claims-hygiene, test-manifest, fuzz-soak). Honest verdict vocabulary
  (PASS / PENDING_JUSTIFIED / DATA_BLOCKED / EXTERNAL_PENDING / FAIL) — a DATA_BLOCKED (needs
  cargo/24h-soak/build-backend) is never a fake PASS, and the single external audit is EXTERNAL_PENDING.
- **Trust-Pack payloadType-binding defense-in-depth (O7):** `verify_trust_pack` now pins the DSSE
  envelope `payloadType` field fail-closed against the in-toto statement type (the PAE already bound the
  signed bytes to the type; this closes the unexamined field for a downstream consumer). Negative
  vectors in `tests/test_trust_pack_payloadtype_negatives.py`. Formal obligation O7 stays **RESERVED**
  in `formal/model.py` — code-enforced and vector-tested, not a fabricated proof.
- **WP-B locked test manifest (`scripts/test_manifest_gate.py` + `tests/test_manifest_lock.json`):**
  pytest is the normative runner; a drop below the collected-test floor or any collection error is a CI
  FAIL (no silent test schwund), and the pytest-only (unittest-invisible) module class is floor-locked.
- **WP-D fuzz-soak (`scripts/fuzz_soak.py`):** a bounded, wall-clock soak over every AST-discovered
  verifier class asserting never-raise + never-false-accept (0 crash / 0 false-accept on the recorded
  run, hundreds of thousands of iterations); the four EXT robustness classes fixed as regression
  vectors; the continuous coverage-guided leg is `.clusterfuzzlite/` + `fuzz/fuzz_verifiers.py`
  (Atheris). The full 24h soak is an operational artifact (DATA_BLOCKED until an artifact records it).
- **WP-C differential evidence:** `crosscheck.py --matrix` writes the reproducible Python<->Rust matrix
  (40 relation vectors + the 54-case corpus reproduced independently); `docs/readiness_pack/`
  `rust_parity_scope.md` declares the deliberately-PENDING Rust surface (No-Fake, no fake 100%).
- **WP-G external-audit readiness pack (3.6.0 slot filled):** reproduction runbook, auditor open-points
  list, threat-model delta, differential-matrix doc, SHA-256 pack manifest + advisory proofbundle
  self-receipt (`scripts/readiness_pack_manifest.py`).
- **Claims-hygiene extended (§9 criterion 11):** the forbidden list now catches the
  `production-ready` / `externally audited` / `has-been-audited` claim class outside a negation; the
  release-stability claim is guarded mechanically by the pyproject Development-Status classifier
  (stays 4 - Beta).

### Added (OTS hardening + calendar-risk — anchor-longevity moat, EXPERIMENTAL, the `[anchors]` extra)
- **`proofbundle anchor` CLI group (WP-A/B/C):** the honest OpenTimestamps lifecycle as an offline
  toolset. `anchor upgrade` bundles an UPGRADED proof into a self-contained, calendar-independent
  evidence pack (a still-PENDING proof is refused with exit 3 and writes nothing, never a fake pass);
  `anchor verify-pack` verifies a pack OFFLINE (no socket) against a relying-party Bitcoin header
  (exit 0 confirmed / 3 pending-or-needs-header / 1 hard fail / 2 malformed); `anchor inspect` prints
  the lifecycle state and the calendars/operators carrying a proof (transparency, no crypto trust).
  New CLI commands in `src/proofbundle/cli.py`; the pack mechanism (`src/proofbundle/evidence_pack.py`)
  gains `describe_proof`. WP-A1 boundary kept: the pack's own bundled/frozen header is never trusted, so
  a colluding or backdating producer cannot self-certify.
- **Calendar transparency (WP-B):** `anchors_ots.calendar_uris` / `calendar_operator` /
  `calendar_operators` surface WHICH calendars carry a proof and how many INDEPENDENT operators back it
  (`operatorRedundancy`), because two URLs on one operator are one point of failure, not two. The
  `operatorRedundancy` figure is read from the proof bytes (`provenCalendars`) but is an
  embedded-but-UNVERIFIED transparency hint, NOT cryptographic redundancy evidence; producer-declared
  calendars are kept separate (`declaredCalendars`, `declaredCalendarsVerified: false`) and are likewise
  never redundancy evidence (see Fixed below). Docs (`docs/ANCHORS.md`) add how to run or pin your own calendar and how to
  obtain a trusted Bitcoin header for verification.
- **ripemd160-free confirmed-path fixture (WP-D1):** `tests/fixtures/ots/synthetic-upgraded-sha256.*`
  (generator `scripts/gen_synthetic_ots_fixture.py`), a SHA-256-only upgraded proof that deserializes
  and confirms WITHOUT ripemd160, so the confirmed/self-contained OTS path has an UNCONDITIONAL
  regression in the cleanroom pytest where the ripemd160-gated external vector (`hello-world.txt.ots`)
  is honestly skipped. Pinned in `PROVENANCE.json`, labelled synthetic (No-Fake, not an external vector).
- **RFC 3161 framed as a first-class legal second anchor (WP-D3):** `docs/ANCHORS.md` documents the
  eIDAS/QTSP hedge (Regulation 910/2014 Article 41, ETSI EN 319 422 / RFC 5816) as the complementary,
  immediate, legally recognized anchor alongside the trust-minimized OpenTimestamps one. The anchor
  registry stays open and fail-closed (an unknown type is a FAIL).
- **Readiness-pack calendar-independence paragraph (WP-E):**
  `docs/readiness_pack/calendar_independence.md`, wired into `index.json` conclusion C1, states the four
  facts (calendar-independent verification, calendar fragility affects only stamping, verification needs
  a Bitcoin header source, RFC 3161 legal second anchor) before an external audit asks.

### Fixed (OTS hardening — Berkeley live-reproduced audit, 2026-07-16)
- **`verify-pack` refuses a self-fabricated Null-Op pack and a Litecoin-height confusion (CRITICAL,
  No-Fake, `anchors_ots.verify_opentimestamps` + `cli.py` + `evidence_pack`, 2026-07-17):** the 6-lens
  re-review reproduced a CRITICAL live on the standalone `anchor verify-pack` / `verify_evidence_pack`
  surface (the canonical `verify --require-anchor` path, which cross-checks `canonicalRoot` against an
  independently recomputed root at `anchors.py`, is a DIFFERENT surface and is UNCHANGED). A pack whose
  `file_digest == canonicalRoot` with a `BitcoinBlockHeaderAttestation` planted directly on the root
  (leaf == root, no op chain) returned `ok: true` / `status: confirmed` / exit 0, because the attested
  value equalled the producer-supplied header with no hashing at all. `verify_opentimestamps` now requires
  at least one cryptographic hash op (`CryptOp` / `OpSHA256`) on the path from the file digest to each
  attestation (`_bitcoin_confirmations`); a hash-free branch is refused with `status: null_op`
  (fail-closed) even when its value matches the header, while a genuine branch still confirms alongside it
  (the 2026-07-16 multi-branch scan is preserved). The confirm loop no longer uses `getattr(att, "height")`:
  it filters to `isinstance BitcoinBlockHeaderAttestation`, so a `LitecoinBlockHeaderAttestation` with a
  colliding integer height no longer confirms against a Bitcoin header. `anchor inspect --json` no longer
  echoes a hand-edited `declaredCalendarsVerified: true` (forced `false`, declared is unverified by
  definition) nor the raw pack `selfContained` (only the authoritative recomputed value is reported).
  `docs/ANCHORS.md` gains the honest reservation (a bare `verify-pack` is a lifecycle/header check;
  `canonicalRoot` is self-declared; a trust decision must bind the anchor independently via
  `verify --require-anchor`). The provenance-pinned synthetic confirmed-path fixture was itself a
  leaf == root Null-Op and was regenerated to a real op chain (append a nonce, then double SHA-256);
  `PROVENANCE.json` and `block.json` pins were refreshed. `claims_hygiene_check.scan_cli_surface` now also
  scans argparse `epilog=`. Live: the exact attack pack now returns `ok: false` / `status: null_op` /
  exit 1. Regression: `test_ots_calendar_hardening.py` (Null-Op refused, Litecoin-height not a Bitcoin
  confirmation, `inspect` forces `declaredCalendarsVerified` false, `packSelfContained` dropped,
  `epilog=` scanned) plus a canonical-path-unaffected assertion.
- **Attestation-scan no longer short-circuits (MAJOR, `anchors_ots.verify_opentimestamps`):** the
  confirm loop returned on the FIRST relying-party-covered Bitcoin height, so a single wrong or tampered
  branch masked a genuinely confirmable one (a False-REJECT / DoS: height 111 wrong + height 222 correct
  reported `block_mismatch`). It now scans ALL covered branches and confirms as soon as ANY matches,
  falling through to `block_mismatch` / `bad_header` / `upgraded_unverified` only when NONE match;
  per-branch diagnostics (`mismatchHeights` / `badHeaderHeights`) are retained so real tamper stays
  visible. Sound because the structural binding pins every branch to the same canonical root. Regression:
  `tests/test_anchors_ots.py::TestMultiBranchAttestationScan` (both iteration orderings).
- **Operator redundancy is proof-derived, never producer testimony (MAJOR, `evidence_pack` + CLI):**
  `operatorRedundancy` and `calendarOperators` were fed from the producer-claimed `--calendar` list, which
  for an upgraded pack (`calendar_uris(proof) == []`) was ALWAYS unverifiable, so a fabricated calendar
  list could inflate the "surfaced honestly" redundancy. The pack now splits `provenCalendars`
  (read from the proof bytes) from `declaredCalendars` (producer testimony via a CLI flag,
  `declaredCalendarsVerified: false`, never counted). The CLI flag `--calendar` is renamed
  `--calendar-declared` and its output labels it unverified. Docs (`docs/ANCHORS.md`,
  `docs/readiness_pack/calendar_independence.md`) no longer present declared redundancy as audit evidence.
  Regression: `test_evidence_pack.py::test_declared_calendars_never_count_as_proven_redundancy`.
- **Calendar redundancy is embedded-but-unverified, NOT cryptographic evidence (MAJOR, No-Fake follow-up,
  2026-07-17):** the 2026-07-16 split still over-claimed the proof-embedded set as "proven" / "the only
  redundancy figure a reviewer may treat as evidence". That is false: a `PendingAttestation` URI is
  unauthenticated and offline-constructible (the test helper `_upgraded_proof_retaining_pending` fabricates
  them), so `provenCalendars` / `operatorRedundancy` are an embedded-but-UNVERIFIED transparency hint, not
  audit evidence. The ONLY cryptographic guarantees are (a) the structural binding of the proof to the
  canonical root and (b) the Bitcoin confirmation against a relying-party header. Docstrings, code comments,
  `docs/ANCHORS.md`, `docs/readiness_pack/calendar_independence.md` and ADR 0006 are re-worded accordingly;
  no field is presented as cryptographic redundancy evidence.
- **`anchor verify-pack` recomputes calendar/self-contained fields from the proof bytes (MAJOR, `cli.py`):**
  `verify-pack` passed the pack's own `operatorRedundancy` / `provenCalendars` / `provenCalendarOperators` /
  `selfContained` JSON fields straight into its authoritative `--json` report, so a hand-edited pack could
  report `operatorRedundancy: 3` with fabricated operators under `status: confirmed` / exit 0 while
  `anchor inspect` on the SAME file computed `0`. It now RECOMPUTES all four from the proof bytes via
  `describe_proof`, exactly as `inspect` does; the report never echoes untrusted pack fields. Regression:
  `test_ots_calendar_hardening.py::test_verify_pack_recomputes_calendar_fields_from_proof_not_json`.
- **Operator-label heuristic blind spot documented (MINOR):** `calendar_operator` is a bare-hostname
  heuristic, not a verified-independent-entity claim; the last-two-labels fallback does not resolve the
  public-suffix boundary, so a `co.uk` / `com.au` host can undercount two independent operators as one.
  Documented next to `operatorRedundancy` in the code and both docs (optional `tldextract` noted, not
  added — it stays a heuristic).

### Changed (OTS hardening)
- **`opentimestamps` pin upper-bounded (WP-D2):** the `[anchors]` extra now requires
  `opentimestamps>=0.4.5,<0.5` (the consensus-critical `python-opentimestamps` LIBRARY on the 0.4.x
  line), so a future 0.5 wire/API change is a deliberate opt-in, not a silent break. Documented that the
  `opentimestamps-client` CLI tool (0.7.x) is a SEPARATE package and not a proofbundle dependency.

### Added (relation-statement/v0.1 3.5.0 — standalone profile + Rust parity, still EXPERIMENTAL)
- **`relation-statement/v0.1` standalone profile (WP-A):** a DSSE-signed statement OVER a
  target receipt, carrying EXACTLY ONE typed edge and no decision/outcome payload of its own —
  the retroactive case the in-receipt edges cannot express (declaring a foreign or older receipt
  retracted / superseded / amended without emitting a successor and without touching the
  original). predicateType `.../relation-statement/v0.1`; new module
  `src/proofbundle/relation_statement.py` and CLI `proofbundle relation-statement
  init|emit|verify|inspect` (exit contract 0/1/2/3 identical to the decision/outcome paths). The
  edge validation, lineage resolution and the `relations` trust-policy gate REUSE the in-receipt
  functions (`relation.validate_relationships` / `verify_relationship_edges` /
  `evaluate_relations_policy`) — no second implementation. Status-as-a-separate-object precedent: W3C
  Bitstring Status List v1.0, CT/OCSP revocation, SCITT protected-object-binding.
- **`relations.reject_retracted` trust-policy pin (WP-A):** a relying party who knows BOTH the
  target and a verified retracts statement of a pinned/authorized signer can treat continued
  automated use of the target as an exit-3 block (`LINEAGE_REQUIREMENT_FAILED`);
  `reject_superseded` extends to the successor relations. Without the policy the verified statement
  is pure visibility. Honesty boundary (verbatim): a relation statement proves the issuer DECLARED
  the relation over exact bytes; it does not retract the target's cryptographic validity, and
  whether the issuer may declare it is a relying-party policy decision. `lineage` never feeds
  `cryptoValid` (lattice monotonicity).
- **Rust parity of the relation profile (WP-B):** the independent Rust verifier
  (`tools/pb_verify_rs`) now carries the profile — new subcommands `verify-relation` (in-receipt
  decision/outcome edges) and `verify-relation-statement` (standalone), with its OWN parser
  (serde_json + serde_jcs, sharing NO canonicalizer/parser with Python). `crosscheck.py` drives
  ALL 40 relation vectors — decision, outcome and standalone, positive AND negative (incl. the
  3.4.0 decoy-parent / subject-mismatch / signer / t1 vectors and the wrong-payloadType vector) —
  through BOTH implementations and
  asserts they land on the same common-vocabulary label (exit class + lineage) on every vector.
  Differential AGREEMENT on these vectors, not a correctness proof of either implementation. The
  parity registry (`scripts/rust_parity_registry.json`) is raised from PENDING to COVERED for
  `relation.verify_relationship_edges` and the new
  `relation_statement.verify_relation_statement`, AST-verified by `scripts/rust_parity_gate.py`.
  The Vector × {Python, Rust} matrix is exported with an environment freeze
  (`audit_artifacts/rust_relation_differential_matrix.json`).
- **Conformance + tests:** six new standalone vectors under `conformance/relation/` (retracts
  verified+blocked, retracts visible, retracts unauthorized, retracts declared-unresolved,
  supersedes verified, malformed), a new `relation_statement` runner kind, property + never-raise +
  exit-contract tests (`tests/test_relation_statement.py`) and the Rust differential gate
  (`tests/test_relation_statement_rust_parity.py`). Existing 3.3.0/3.4.0 vectors and behaviour are
  unchanged (pure additivity, no wire break); the profile stays EXPERIMENTAL through 4.0.

### Fixed (relation-statement/v0.1 3.5.0 — pre-release audit)
- **Rust payloadType fail-open (BLOCKER, security):** the independent Rust verifier's `verify_dsse`
  derived the PAE from the envelope's OWN `payloadType` without pinning an expected type, so the
  relation paths (`run_verify_relation` crypto check and `load_related`) would AUTHENTICATE a
  same-key envelope presented under the WRONG payloadType — where Python pins
  `application/vnd.in-toto+json` and rejects it. `verify_dsse` now takes an `expected_payload_type`
  and the relation paths pin the in-toto type, mirroring Python fail-closed; the generic
  `verify-dsse` subcommand stays deliberately type-agnostic. A new same-key wrong-payloadType
  differential vector proves BOTH implementations now reject it (exit 2, lineage FAIL).
- **`policy lint` missed `reject_retracted` (MAJOR):** `explain_policy` had no `reject_retracted`
  branch, so `lint_policy` wrongly called a `reject_retracted`-only policy a vacuous pass while the
  verify path enforces it at exit 3. `explain_policy` now lists it (explain⟺enforce parity).
- **Docs:** the roadmap `O6_RETRACTS_NEVER_RAISES` note corrected to reserved (code-enforced +
  tested + mutation-killed, not yet a formal proof); the dead `RELATION_STATEMENT_SCHEMA_VERSION`
  constant removed; the `reject_superseded` double meaning cross-referenced in
  `evaluate_relations_policy`.

### Added (relation/v0.1 3.4.0 — three lineage pins, still EXPERIMENTAL)
- **`relation_signer` trust-policy pin (WP-A, WHO may replace):** a new fail-closed
  `relations.relation_signer` map — per relation `{"mode":"same-key"}` or
  `{"mode":"pinned","keys":[<b64>,…]}`. The SUCCESSOR's issuer key must satisfy the rule
  (byte membership of the raw Ed25519 key, never a keyId alias). Unmet →
  `RELATION_SIGNER_UNAUTHORIZED`, exit 3. CLI `decision/outcome verify --with-related PATH
  --related-pub B64` (position-paired) enables cross-issuer chains; the check runs against
  the key the target ACTUALLY verified under (`verified_under`), never a claim. In-toto
  layout/functionaries precedent (authorized keys per step); flat set, no thresholds (YAGNI).
- **`require_relation_target` + `targetSubjectDigest` enforcement (WP-A2, WHICH parent —
  KERNFUND F1/O1/O2, from Loek Verdonk / No Silent Landing's byte-verified adversarial
  review):** `relations.require_relation_target` pins the expected parent content root(s)
  per relation; a supersedes-like edge that resolves to any OTHER (even valid) parent →
  `RELATION_TARGET_MISMATCH`, exit 3, on EVERY such edge, the accept path (T2) included —
  closing the decoy-parent gap where `require_relation_resolution` alone only proved SOME
  edge resolves. The previously dormant `targetSubjectDigest` edge field is now binding when
  PRESENT (gegengeprueft against the resolved target's subject; mismatch →
  `RELATION_TARGET_SUBJECT_MISMATCH`, lineage FAIL, exit 2).
- **Outcome-path relations gate (WP-B):** `verify_outcome_receipt(..., policy=…)` /
  `outcome verify --policy` enforce the `relations` section identically to the decision path
  (require_relation_resolution / reject_superseded / relation_signer / require_relation_target),
  same exit-code contract and blocker names. trust_pack role auth is separate and unchanged.
- **Automation-surface consistency (WP-A3 / F5):** `referencesResolved` is no longer `true`
  while a REQUESTED lineage relation is unresolved/failed; `policy explain` lists the two new
  pins (explain⟺enforce parity).
- **Conformance corpus:** the shared `relations`-policy evaluator (`relation.evaluate_relations_policy`,
  cut as its own function for the future relation-statement verifier) and new vectors for
  relation_signer, the decoy-parent fix (target-mismatch + must-pass gegenprobe + accept-path
  + documented no-pin old behavior, `crossFormatId xfmt-t3-decoy`), the `targetSubjectDigest`
  O2 gegenpruefung, a JCS-canonical invalid-signature vector (F2), and an `outcome_relation`
  harness mirror. Lattice monotonicity preserved throughout: relation_signer / target-mismatch
  change ONLY the policy verdict, never `cryptoValid`. relation/v0.1 stays EXPERIMENTAL.
- Honest follow-ups (3.5.0): Rust differential parity for the new surface (NOT_RUN until the
  Rust core carries the profile); threshold signer sets and DID/VC identity indirection remain
  DELIBERATELY out of scope.

## [3.3.0] - 2026-07-16

### Added (relation/v0.1 lineage profile — EXPERIMENTAL)
- **`relation/v0.1` lineage/relationship profile** (EXPERIMENTAL): an optional, SIGNED
  `relationships: [edge, …]` field on the decision-receipt and action-outcome predicates —
  typed edges (`supersedes`/`revises`/`corrects`/`retracts`/`renews`/`derivedFrom`/`amends`,
  closed vocabulary) onto a predecessor's `jcs-sha256-v1` content root, with an EXPLICIT,
  never-defaulted `digestAlgorithm`. Change is expressed by a declared, signed back-edge —
  never by mutation; the old receipt stays valid for its bytes forever. Docs:
  `docs/predicates/relation.md`; interop mapping to W3C PROV and the SCITT relationship
  draft checked against the draft-nobuo-00 FULL TEXT (no `amends` exists there — stated
  honestly, not bent). New module `src/proofbundle/relation.py` (fail-closed, never-raise
  validators; pure offline chain walk with per-path cycle detection and depth cap 32).
- **Lineage verdict in `verify_decision_receipt` / `verify_outcome_receipt`** (additive
  `related=` kwarg + `lineage` result field with the four honest states VERIFIED /
  DECLARED_UNRESOLVED / FAIL / NOT_EVALUATED): computed only over authenticated bytes;
  lattice monotonicity proven by test — lineage never flips the crypto verdict in either
  direction, and DECLARED_UNRESOLVED never reads as a pass.
- **CLI `decision verify --with-related PATH`** (repeatable, offline, same-key contract):
  attached targets are verified standalone and keyed by their computed content root; an
  attached-but-unverified target FAILS lineage (present-and-wrong beats absent); a REQUESTED
  lineage check that FAILs exits 2, never a silent 0. `lineage` emitted in the `--json`
  report projections.
- **Trust-policy v0.2 `relations` section** (`require_relation_resolution`,
  `reject_superseded`) enforced on the decision verify path with the LIVE automation blocker
  `LINEAGE_REQUIREMENT_FAILED`; `policy explain` lists both pins (explain⟺enforce parity);
  retracts-then-use blocked under `reject_superseded`.
- **Conformance corpus `conformance/relation/`**: 15 vectors end-to-end through the real CLI
  (new harness kind `decision_relation`), the five skeleton vectors carrying `crossFormatId`
  `xfmt-c0`/`t1`–`t4` per the No Silent Landing shared-vector convention, plus the internal
  superset incl. the F6 malformed-digest never-raise vector (DSSE-crafted — the honest
  emitter refuses to emit it) and depth-exceeded (real hash cycles are impossible under
  content-root addressing; documented).
- 3 new relation-specific mutation operators (`scripts/mutation_check.py`: cycle-detection
  disabled, malformed-digest guard disabled, verified-flag laxened — each kill hand-verified),
  and a No-Fake aggregate fix (6-lens audit): a requested lineage FAIL is now visible in the
  library `ok` / `automation.safeForAutomation` verdict via a derived `lineage_ok`, not only
  at the CLI exit code (crypto verdict untouched — lattice monotonicity preserved).
- New verify surface honestly registered PENDING in the Rust parity registry (differential
  = NOT_RUN until the core carries the profile). Documented follow-ups: `relation_signer`
  (pinned-set), outcome-path policy gate, `relation-statement/v0.1` standalone profile,
  and the still-unwritten SPEC.md profile chapter + GLOSSARY entry (the canonical prose lives
  in `docs/predicates/relation.md` for now).

## [3.2.3] - 2026-07-15

Second remediation wave of the six-lens post-3.2.2 audit (Findings 01, 03, 11, 12, 15b, 16, 14a, 17, 18, 19, 20). Additive/non-breaking: no
existing `result["ok"]` field changes for any correct caller; every new field/param is opt-in with a
backward-compatible default — with ONE deliberate exception (honest, not opt-in): the Finding 15b
`VerificationBudget` DoS ceilings are enforced unconditionally, so an input that was previously accepted
but is over a generous limit (a DSSE envelope with >512 signature entries, a Trust Pack `keys`/role
`keyIds` map with >256 entries, a renewal sequence with >10,000 ArchiveTimeStamp entries, or a >8 MiB
DSSE payload) now fails closed. The ceilings sit far above any legitimate receipt/pack/sequence; they are
a DoS backstop, not a behavioural knob.

### Security (combined-integration review hardening)

A four-lens combined-integration review of this wave, plus an orthogonal-refuter iteration that refused to
rubber-stamp the first round of fixes, surfaced real fail-open/DoS gaps that each passed the per-finding
tests but not adversarial cross-checking; all are fixed and covered by bidirectional, mutation-verified
tests:

- **DSSE / parse DoS (Finding 15b, extends the cap)**: `dsse.verify_envelope` — the single chokepoint
  `decision`/`outcome`/`verification_summary`/`run_ledger` verify funnel through — now caps the
  attacker-controlled `signatures` list BEFORE its verify loop; and `loads_strict` (the ONE parse
  chokepoint every verify path funnels through) now refuses raw input over `budget.input_bytes` BEFORE
  `json.loads` (an unbounded parse of a 50 MB envelope was a real pre-loop DoS the signature cap could not
  reach) and enforces the previously-dead `budget.json_nodes` as a parsed-structure node-count cap.
  `budget.signatures` was raised 64 → 512 so a legitimate two-stage rotation envelope (new-root threshold +
  old-root vouch reuse one `signatures` list) still verifies. `trust_pack.verify_trust_pack` now also fails
  closed with a clean `BundleFormatError` on a non-list `signatures` (JSON `true` / a huge dict), which
  previously skipped its cap or raised an uncaught `TypeError`. A second refuter round further capped the
  raw base64 `payload` in `dsse._payload_bytes` BEFORE it is decoded (the decode, run twice per verify, was
  a layer earlier than `loads_strict`), and added the same pre-decode cap to `anchors_markovian` (mirroring
  `anchors_chia`).
- **`require_external_token` fail-closed on absent token (Finding 14a)**: `renewal.verify_sequence(...,
  require_external_token=True)` now appends a FAILING `renewal:external_token` check when the newest ATS
  carries no `external_token_type`. The external-token fields are deliberately outside the signed ATS
  bytes, so an attacker/MITM could strip them; previously the whole block was skipped and `.ok` was
  unaffected — a silent no-op "require".
- **Receiver independence is enforced, not just labeled (Finding 16)**: `assurance.
  classify_receiver_corroboration` now takes `executor_key_id`/`receiver_key_id` and reaches
  `INDEPENDENTLY_ATTESTED` ONLY when BOTH key ids are present AND differ. `executor.keyId` is schema-optional
  and executor-controlled, so a one-sided check would be evaded by simply omitting one's own keyId; an
  absent executor key id now blocks promotion too, and both key ids must be STRINGS (a second refuter round
  found that a non-str `receiverKeyId` wrapping the executor's own id, e.g. `["kid-exec"]`, is `!=` the str
  `"kid-exec"` and would read as "distinct"). Wired through `outcome.verify_outcome_receipt`. Honest
  inherent limit: two distinct keys can still belong to the same principal — principal-level independence
  needs the `outcomeReceivers` Trust Pack role (an out-of-band trust binding), documented in the code.

Plus: `decision`/`outcome` `verify --json` now emit `automation`/`evidence_levels`/receiver fields (a
`jq` filter no longer gets `null`, indistinguishable from a real "not evaluated"), and `assurance`/
`budget`/`automation_verdict` are now top-level `from proofbundle import …` exports.

### Added
- **Finding 01 — uniform automation-safety verdict**: new `automation_verdict.automation_summary` mirrors
  `bundle.py::root_authenticity_summary`'s `safeForAutomation`/`automationBlockers` pattern for the other
  five receipt-chain predicates. Each of `decision.verify_decision_receipt`,
  `outcome.verify_outcome_receipt`, `trust_pack.verify_trust_pack`,
  `verification_summary.verify_verification_summary` and `run_ledger.verify_run_ledger` now stashes a
  `result["automation"]` dict; `safeForAutomation` requires the policy/authorization dimension to be
  `True` EXACTLY (never merely `is not False`, unlike the permissive `ok` aggregate). `outcome.py` also
  gains an optional `trust_pack` parameter (`outcome.executor_trusted_by_role`) that checks the executor's
  `keyId` against the Trust Pack's `outcomeExecutors` role — closing the gap
  docs/predicates/action-outcome.md §7 listed as open/future work.
- **Finding 03 — EvidenceLevel ladder**: new `assurance.py` (`EvidenceLevel`,
  `classify_digest_evidence`, `evidence_ladder_summary`/`evidence_ladder_best`) makes the STRENGTH of a
  digest-presence "proven"/"bound" claim explicit and orderable
  (`CLAIMED < REFERENCE_WELL_FORMED < CONTENT_RESOLVED < RECEIPT_CRYPTO_VERIFIED < POLICY_AUTHORIZED <
  INDEPENDENTLY_ATTESTED < EFFECT_OBSERVED`). `decision.verify_decision_receipt` and
  `outcome.verify_outcome_receipt` gain an additive `result["evidence_levels"]` plus an optional
  `evidence_resolver` callable that, when supplied, wires the previously-unused
  `decision.resolve_evidence_ref` primitive into the actual verify path (a digest can now reach
  `CONTENT_RESOLVED`, not only `REFERENCE_WELL_FORMED`). The pre-existing boolean
  `action_outcome_proven`/`outcome_execution_proven`/`evidence_bound` fields are UNCHANGED.
  `EvidenceLevel.EFFECT_OBSERVED` is a real, orderable enum member that stays structurally unreachable (a
  real-world effect-observation channel is a separate, inherent limit outside this repo — see the Finding 16
  entry below for what its self-fixable part DOES now reach: `INDEPENDENTLY_ATTESTED`) — an explicit
  `EFFECT_OBSERVED_NOT_IMPLEMENTED` marker documents this rather than silently omitting it.
- **Finding 15b — VerificationBudget**: new `budget.py` (`VerificationBudget`, `DEFAULT_BUDGET`,
  `BudgetExceeded`) centralizes the DoS-guard pattern already used ad hoc by `sdjwt._MAX_DISCLOSURES`,
  `statuslist._MAX_STATUS_LIST_BYTES`, `hf_evals._MAX_TOKEN_BYTES` and `anchors_chia._MAX_LAYERS`/
  `_MAX_PROOF_BYTES` (which are unchanged and stay the authoritative caps for their own surfaces). Wired
  concretely into the two identified unguarded paths — `trust_pack.validate_trust_pack_predicate`'s
  `keys` map / per-role `keyIds` counts, and `renewal.verify_sequence`'s total ArchiveTimeStamp count
  across a whole sequence — plus a generous `input_bytes` cap on the raw DSSE payload bytes (checked
  BEFORE JSON parsing) on every one of the five receipt-chain `verify_*` entry points named above.
  `BudgetExceeded` is a `ProofBundleError` subclass, so every existing `except (ProofBundleError, ...)`
  call site already handles it identically to any other malformed/over-limit input.

- **Finding 16 — outcome receiver/observer corroboration (self-fixable part, additive)**: an optional
  `receiverRefs[]` on `action-outcome/v0.1` (digest-bound exactly like `evidenceRefs[]`) plus
  `assurance.classify_receiver_corroboration` let a genuinely independent, cryptographically verified
  receiver/observer statement reach `EvidenceLevel.INDEPENDENTLY_ATTESTED` (given a new
  `receiver_attestation_resolver` parameter on `outcome.verify_outcome_receipt`); an additive
  `outcomeReceivers` Trust Pack role (`outcome.receiver_trusted_by_role`, mirrors `outcomeExecutors`) lets a
  verifier check that party against a known list, deliberately advisory (never wired into the aggregate
  `ok`, since `receiverRefs` is optional supplementary evidence). Also additive: `sequence.{runId,seq}` +
  `outcome.detect_outcome_sequence_gaps` for spotting a suppressed outcome later in the same run, when the
  executor opts in. Fully backward compatible — a receipt with no `receiverRefs`/`sequence` is unaffected.
  **Honest, INHERENT limit this increment does NOT close:** proofbundle cannot itself make a downstream
  system SIGN a receiver acknowledgement (ecosystem adoption, outside this repo); `EvidenceLevel.
  EFFECT_OBSERVED` stays structurally unreachable even with a verified receiver corroboration (still a
  receipt about the effect, never a live observation of it) — see `assurance.EFFECT_OBSERVED_NOT_IMPLEMENTED`.
- **Finding 14a — RFC-3161/OTS↔ArchiveTimeStamp integration glue + truncation detection (additive, ADR
  0006 B3 OPEN items)**: an `ArchiveTimeStamp` may now carry a DETACHED `external_token_type` /
  `external_token` / `external_token_frozen`, verified by the new `renewal._verify_ats_external_token` via
  the ALREADY-HARDENED standalone `anchors_rfc3161.verify_rfc3161` / `anchors_ots.verify_opentimestamps` —
  pure glue between two already-hardened modules, no new cryptography. `renewal.verify_sequence` gains
  `rp_trust` (relying-party TSA-root/Bitcoin-header trust material, WP-A1 discipline) and
  `require_external_token` (demand the full verified state, not merely OTS-pending). Separately,
  `verify_sequence(..., known_newest_token_digest=…)` closes the "a stale prefix of a legitimately-renewed
  sequence still verifies" gap: when the relying party supplies the digest of the newest ATS it last
  observed (its own persisted state — no `RelyingPartyStateStore` exists in this repo, so this is the
  additive-parameter fallback), a truncated/rolled-back sequence fails the new `renewal:no_rollback` check.
  None of the three additions are surfaced unless the caller opts in — fully backward compatible with every
  existing `ArchiveTimeStamp`/sequence. **Still OPEN (honest, unchanged):** the full ASN.1/XMLERS export and
  a signature-algorithm staleness trigger in `RenewalPolicy` — see `docs/adr/0006-anchor-longevity.md`.

- **Finding 11 — Rust-parity honesty gate**: `scripts/rust_parity_gate.py` AST-scans every
  `src/proofbundle/*.py` for a module-level `verify_*` function (ground truth, rediscovered each run)
  and cross-checks it against the declarative `scripts/rust_parity_registry.json`. Every COVERED/PARTIAL
  claim is verified against REAL evidence — the claimed `rust_subcommand` must be an actual match arm in
  `main.rs`, appear in the built binary's self-declared `coverage-report`, and the claimed crosscheck
  call site must literally exist; a stale claim is caught (`STALE_COVERED_CLAIM`), a new untracked
  `verify_*` is `UNTRACKED`, a dangling `python_ref` is `ORPHANED`. Advisory by default, `--strict`
  exits 1 on a registry-integrity problem, never on an honestly-declared PENDING. First real portation:
  `main.rs`'s `verify-trust-pack-threshold` (root-of-trust threshold check, Ed25519 leg only, reported
  PARTIAL not COVERED; mldsa65/hybrid skipped-and-reported, never silently accepted). New advisory CI
  `rust-parity` job (`continue-on-error`, non-blocking).
- **Finding 12 — external-audit readiness package (NOT_SELF_FIXABLE, readiness only)**: no audit is
  performed or simulated. `docs/AUDIT_SCOPE.md` (STABLE vs. EXPERIMENTAL module table cross-checked
  against docstrings/SPEC/CODEOWNERS/CHANGELOG, coupled to a format-freeze mechanism), `docs/
  AUDIT_READINESS.md` (OSTIF-facing briefing of existing hardening evidence, honest current-state, no
  audit-completion claim), `docs/adr/0007-crypto-agility-alg-dispatch.md` (the alg-dispatch pattern
  trust_pack.py and renewal.py share), a `Revision:` header on `THREAT_MODEL.md`, a dedicated
  "Security Audit" `funding.json` purpose. Surfaces a CODEOWNERS gap (checkpoint.py/renewal.py/
  anchors_chia_add.py missing from the review-required path list) without silently fixing it.
- **Finding 18 — Evaluation Cards (P2, additive)**: optional `evaluation_card_sha256` claim field +
  `src/proofbundle/evalcard.py` (`evaluation_card_hash`/`verify_evaluation_card`), mechanically
  identical to `prereg_sha256`; references the Hugging Face EvalEval Coalition's Evaluation Cards
  (arXiv:2606.09809) rather than inventing a proofbundle-specific format. CLI `proofbundle evalcard
  <card> [--check RECEIPT]` mirrors `prereg`.
- **Finding 19 — computation-correctness / enclave assurance wiring**: the enclave RATS/EAT bridge was
  already implemented but README's roadmap misclassified it as not-yet-built (a No-Fake UNDERclaim) —
  README framing corrected. Real gap closed: `assurance_level=enclave_attested` was an unverified
  string; new `evalclaim.enclave_assurance_proven(claim, bundle, eat_jws=…, verifier_pubkey=…)`
  (analogous to `decision.action_outcome_proven`) optionally corroborates the declared level against a
  real, receipt-bound Attestation Result (True/False/None), wired into `show-eval --eat/--verifier-key/
  --profile`. Lazy function-local import keeps the ExperimentalWarning from firing on plain
  `evalclaim` import; never force-promotes the signed `assurance_level`.
- **Finding 17 — benchmark-hacking VISIBILITY (OPEN_BY_DESIGN)**: visibility only, no anti-hacking
  guarantee built or implied (BenchJack, arXiv:2605.12673, cited in THREAT_MODEL.md). Optional
  provenance sub-keys `run_attempts`/`aborted_runs` (non-negative ints) and `methodology_sha256`/
  `benchjack_audit_report_sha256` (plain sha256 references), wired via `adapters/_provenance.py`; zero
  schema change (provenance is free-form) and zero `intoto.py` change (`to_test_result_statement`
  already copies the whole provenance dict verbatim — proven by a new regression test).

### Deferred (tracked, not built this increment — the one deliberately BREAKING piece)
- `bundle.py`'s CLI `verify` exit-code default is NOT changed by this increment. `root_authenticity_summary`
  already computes `safeForAutomation`/`automationBlockers` correctly (unaffected); a FUTURE v4 could add an
  opt-in `--strict-automation` CLI flag that gates the process exit code on `safeForAutomation` instead of
  the current crypto-only exit contract (a `POLICY_NOT_EVALUATED` receipt would then exit non-zero even
  though `CRYPTO: OK`). That flip would be a REAL default-behavior change for any script parsing exit
  codes today, so it is explicitly NOT flipped as a default here — only the opt-in flag is a plausible v4
  addition, and even that is not implemented in this increment (No-Fake: the capability described above
  IS built and IS additive; only the CLI default-exit-code change is the deferred, tracked item).

### Added — SD-JWT VC interop, Finding 20 (issue #27)

- **ES256 issuer-signature verification.** `sdjwt.verify_sd_jwt` now verifies ECDSA P-256
  (ES256, RFC 7518 §3.4) issuer signatures alongside EdDSA, dispatched strictly on the issuer
  JWT header's literal `alg` claim — the algorithm the EUDI Digital Identity Wallet and the
  OAuth WG's own SD-JWT VC worked examples use, closing proofbundle's biggest SD-JWT VC interop
  gap (previously every real-world ES256 credential could only be checked structurally, never
  cryptographically). New primitive `signature.verify_ecdsa_p256` (65-byte SEC1 uncompressed
  public key, RFC 7518 §3.4's fixed-width 64-byte `R‖S` JWS signature, converted to DER before
  calling into `cryptography` — never hand-rolled ECDSA math). `bundle.py`'s `sd-jwt-issuer-identity`
  fingerprint prefix is now alg-aware (`"ed25519:"` / `"es256:"`) rather than hardcoded to EdDSA — a
  latent false-reject the new algorithm would otherwise have exposed for an ES256-signed `sd_jwt_vc`
  that discloses proofbundle's own `issuer` claim format.
- **Trust-policy `sd_jwt.expected_vct`.** A relying party can now pin an exact required `vct` in the
  bundle trust policy (`policy.py`'s `_SDJWT_KEYS`); `evaluate_policy` adds a `policy:expected_vct`
  check, read ONLY from an issuer payload whose signature actually verified (mirrors the
  "verified vs. merely present" discipline `policy:nonce_present` already established — an
  unverified `vct` claim proves nothing). Complements, and is distinct from, `sdjwt_vc.py`'s
  standalone `vctAllowlist`.
- **Real cryptographic external conformance.** `tests/fixtures/sdjwtvc/` now also vendors the ES256
  issuer public key the OAuth WG's 5 worked SD-JWT VC examples are signed under (from the same
  pinned commit's `examples/settings.yml`, independently re-verified before vendoring);
  `test_sdjwtvc_external_vectors.py` cryptographically verifies the issuer signature end-to-end, not
  just the structural disclosure-commitment path (previously honestly out of scope — see the removed
  `test_all_examples_have_es256_issuer_alg_by_design_not_checked_here` boundary marker). No official
  NEGATIVE SD-JWT VC vectors were found upstream (checked oauth-wg/oauth-sd-jwt-vc,
  oauth-wg/oauth-selective-disclosure-jwt, and openwallet-foundation-labs/sd-jwt-python's
  `tests/testcases/` — every published example in all three is a positive structural variant), so the
  new negative tests adversarially mutate the vendored positive vectors in code instead (the
  established pattern this suite already used for `test_tampered_disclosure_is_rejected`).
- Docs: `docs/SD_JWT_VC_PROFILE.md` updated to reflect the above against issue #27's roadmap;
  `SPEC.md` §6 documents the alg-keyed `issuer_public_key_b64` encoding and the alg-aware
  `sd-jwt-issuer-identity` fingerprint.

Backward compatible: EdDSA-signed SD-JWTs verify exactly as before (same primitive, same call
sites); the `sd_jwt.expected_vct` policy field is opt-in (absent = unchanged behavior).

## [3.2.2] - 2026-07-15

Security and robustness hardening from a six-lens plus red-team audit of 3.2.1. Additive; no
wire-format change and no change to a correct 3.2.1 caller's result unless the input was actually
malformed or over-limit.

### Security
- **SD-JWT recursive-disclosure O(n^2) CPU-DoS fixed (CWE-400/407)**: `verify_sd_jwt`'s fixpoint
  resolution was quadratic under adversarially-ordered disclosures (n=4000 drove ~11s of CPU from a
  520KB bundle, reachable via `verify_bundle`). Rewritten as an O(n) BFS/worklist over disclosures
  grouped by digest, plus a fail-closed `_MAX_DISCLOSURES = 256` cap before any per-disclosure work.

### Hardening
- **Decision/outcome schema is a strict SSOT now**: `decisionId` type/non-empty enforced;
  `actionOutcome`/`validity` must be JSON objects when present; empty `parametersRef` rejected;
  `additionalProperties:false` enforced on every sub-object of both `*.schema.json`; the existing
  `nested_closure_violations` is wired into the validators; new `test_schema_parity.py` proves the
  hand validator and the docs schema agree on every golden example and 11 negative vectors.
- **Decision subject-rehang gate**: `verify_decision_receipt` classifies the subject (opt-in
  `require_derived_subject`, CLI `--require-derived-subject`); a caller-overridden subject that does
  not derive from the predicate can be made fail-closed. Corrected an earlier CHANGELOG claim that
  overstated the outcome default as "fail-closed" (it is warned-by-default, fail-closed only opt-in).
- **Trust-pack crypto-agility**: root and rotation keys carry an explicit `alg`
  (`ed25519` default, `mldsa65`, or `hybrid-ed25519-mldsa65`), verified alg-aware via the existing
  `pqsig` ML-DSA (FIPS 204) paths; a policy-declared hybrid key is not satisfied by an Ed25519-only
  signature (downgrade defense). Backward compatible for `alg`-less packs.
- **Renewal seed is verifiable, not a bare label**: `renew_*` accept an immutable
  `VerifiedAnchorResult` bound to the prior ATS digest (`require_verified_prior`); the self-asserted
  `anchor_status` path is tagged `renewal_seed_evidence_class` rather than silently trusted.
- **Public-transparency consistency is typed and bound**: a `ConsistencyVerificationResult`
  (old/new origin, tree size and root, plus proof/verifier/policy digests) replaces the ungrounded
  boolean; the confirmed claim is re-bound to the checkpoint actually being evaluated
  (`strict_consistency`), catching wrong-pair and split-view inputs.

## [3.2.1] - 2026-07-14

Anchor-longevity hardening release. A six-lens plus red-team audit of the 3.2.0 anchor modules
(EXPERIMENTAL) found the core cryptographic verify paths solid: every direct forgery attempt was
repelled. This release closes a cluster of defense-in-depth gaps in non-default, incomplete-caller
and weak-input cases. Additive only; no wire-format change and no change to a correct 3.2.0 caller's
result.

### Security and correctness (fail-closed hardening)

- **`require_pq` is a verified-PQ floor, not a label.** `renewal.verify_sequence(..., require_pq=True)`
  now passes only when the newest ArchiveTimeStamp's post-quantum signature was actually verified
  (authority-key mode). A post-quantum label on `sig_alg` under an `anchor_verifier` or unauthenticated
  anchor no longer satisfies the floor, because a label is not verification.
- **Future-dated ArchiveTimeStamp flagged.** `evaluate_renewal_policy` reports a newest ATS whose time
  is in the future as anomalous rather than perpetually fresh (its age went negative, which could
  otherwise evade the renewal-due signal).
- **Hash-strength surfaced.** `verify_sequence` emits a `renewal:current_hash` check when the newest ATS
  uses a deprecated hash, so `.ok` never hides it, and fails closed under the new `require_current_hash=True`.
- **Trust-pack version chain enforced.** A `version > 1` pack with a null `prevVersionDigest` (a
  "version-2 genesis") is rejected at validate time; it previously skipped two-stage rotation authorization.
- **Trust-pack expiry parses fractional seconds.** A validator-legal RFC-3339 `expires` with fractional
  seconds is now parsed correctly; a valid future expiry with a fraction was read as expired (a
  false-closed availability bug from a regex/parser divergence).

### Conformance

- **SD-JWT recursive disclosures (RFC 9901).** `verify_sd_jwt` resolves nested `_sd` digests committed
  inside a parent disclosure's value via a fixpoint, so valid official recursive-disclosure vectors no
  longer fail `structure_ok`. Security is unchanged: every disclosure must still be transitively rooted
  in the issuer-signed payload.

### Tests

- New `tests/test_anchor_hardening_321.py` pins each finding red to green; trust-pack version-chain and
  fractional-seconds tests; five new mutation operators in `scripts/mutation_check.py` (55 operators, 0 gaps).
- Vendored external-vector test suites, each fixture provenance-pinned (source URL + commit + sha256) and
  cryptographically self-verified rather than merely copied: NIST ACVP ML-DSA (FIPS 204) sigVer vectors
  cross-checked against the official answer key (the `verify_mldsa` external/pure/empty-context surface is 3
  vectors per parameter set, an honest property of the source data); real OpenTimestamps fixtures from the
  opentimestamps examples (pending path unconditional; the confirmed Bitcoin-anchored path skips where the
  OpenSSL legacy `ripemd160` provider is unavailable); C2SP signed-note checkpoint KATs (sum.golang.org vkey
  read from the pinned Go toolchain source, Rekor v2 key decoded from Sigstore's trusted root); SD-JWT-VC
  structure vectors from the OAuth-WG editor's copy (signature verification stays EdDSA-only by design).

## [3.2.0] - 2026-07-14

The eval → decision → **outcome** chain, plus a trust root and transparency/credential layers. Everything in
this release is **EXPERIMENTAL** (a v3 preview: API and wire format may change without deprecation; do not
depend on it in production). Additive wire format; no change to the shipped `eval-result` / `decision-receipt`
verify paths. Each predicate carries a hand-rolled fail-closed validator (the JSON Schemas remain docs-only)
and states its non-claims as explicitly as its guarantees. Predicate docs under
[`docs/predicates/`](docs/predicates/README.md).

### Added — anchor longevity (EXPERIMENTAL, ADR 0006)
- Long-term evidence mechanics so an anchor keeps its force as algorithms age. All EXPERIMENTAL, additive,
  fail-closed.
- `hashalg` — an explicit hash-algorithm registry (RFC 6920 model, RFC 4998 `digestAlgorithm` OIDs) with
  fail-closed resolution (no implicit SHA-256; deprecated/unknown rejected) and a dual-hash for new receipts.
- `renewal` — an RFC 4998 `ArchiveTimeStampSequence` (timestamp + hash-tree renewal) with an offline
  end-to-end verify, plus a `RenewalPolicy` (watch-only-newest, no network). An ArchiveTimeStamp MAY carry
  a real time-authority signature (the RFC-4998 TimeStampToken role; unsigned/legacy stays valid) with the
  algorithm bound into the signed bytes (downgrade defense); renewal MIGRATES it ed25519 → hybrid → mldsa65
  (B3↔B5); `verify_sequence(authority_keys=…)` checks the newest signature against the relying party's
  trusted keys, fail-closed by default with an optional `require_pq` floor. ASN.1/XMLERS export, a real
  external RFC-3161/OTS-token binding, and truncation/rollback detection stay OPEN.
- `pqsig` — ML-DSA (FIPS 204) verify/sign + a hybrid Ed25519+ML-DSA verify, wired into `renewal`'s
  signature migration. SLH-DSA (FIPS 205) is OPEN (`PQUnavailable`).
- `evidence_pack` — an offline OTS evidence pack (no network at verify); the WP-A1 boundary holds (a bundled
  header is producer evidence, never trust). A real confirmed-receipt pack is OPEN (needs a calendar submit).

### Added — `action-outcome/v0.1` predicate (EXPERIMENTAL, O1)
- A signed record that a specific executor carried out (or refused/failed) the action a Decision Receipt
  permitted, bound by content root to that decision (`decisionRef`), with the requested action and observed
  effect digest-bound. `proofbundle outcome init|emit|verify|inspect`.
- Verify is fail-closed: crypto → predicate type → `hash_binding` → `decision_bound` (embedded `decisionRef`
  equals the expected content root) → `role_separation` (executor ≠ decision maker) → `execution_proven`
  (`status = executed` only proven when an `effectDigest`/`actualActionDigest` backs it, else self-asserted +
  warning) → audience/nonce. No-Overclaim: never proves the action was correct or safe. Doc:
  [`docs/predicates/action-outcome.md`](docs/predicates/action-outcome.md).

### Added — `trust-pack/v0.1` predicate (EXPERIMENTAL, O2)
- A TUF-inspired root of trust: roles → `{keyIds, threshold}`, a `keyId -> publicKey` map, an offline `revoked`
  list, a monotone `version` with a `prevVersionDigest` chain (rollback/freeze protection), and `expires`.
  `verify_trust_pack` counts DISTINCT valid non-revoked root signatures against the root threshold; validation
  is dead-on-arrival aware (a root that can never meet threshold is rejected). Doc:
  [`docs/predicates/trust-pack.md`](docs/predicates/trust-pack.md).

### Added — `verification-summary/v0.1` predicate (EXPERIMENTAL, O4)
- A signed roll-up of a receipt chain: per level (eval/decision/outcome) the verified receipt content root,
  status (`VERIFIED`/`FAILED`/`NOT_EVALUATED`), and evidence class, with a mandatory `nonClaims` block. The
  `levels_consistent` rule is real (non-tautological): a `VERIFIED` level MUST carry a `receiptRef`; a
  `NOT_EVALUATED` level without one stays consistent. Doc:
  [`docs/predicates/verification-summary.md`](docs/predicates/verification-summary.md).

### Added — `run-ledger/v0.1` predicate (EXPERIMENTAL, O5)
- A signed, gap-free run history against best-of-many cherry-picking: a strictly monotone `seq` (no gaps), a
  `prevDigest` chain (each run links the previous run's `resultDigest`), aborted/failed runs kept VISIBLE, and
  a `runBudget` declared up front. A selection that drops the bad runs cannot produce an intact chain. Doc:
  [`docs/predicates/run-ledger.md`](docs/predicates/run-ledger.md).

### Added — public-transparency policy layer (EXPERIMENTAL, O3)
- `public_transparency.py::evaluate_public_transparency` composes the existing C2SP checkpoint primitives into
  one relying-party verdict with named statuses (`LOG_ORIGIN`, `CHECKPOINT_SIGNATURE`,
  `ROOT_BYTES_AUTHENTICITY`, `TREE_CONTEXT_AUTHENTICITY`, `CONSISTENCY`, `WITNESS_QUORUM`,
  `PUBLIC_TRANSPARENCY`), fail-closed (a required-but-unevaluable check is FAIL; an optional un-requested check
  is `NOT_EVALUATED` and stays visible). It is a library layer; wiring it into the `--policy` FILE of the
  reference CLI remains proposed (see [`docs/PUBLIC_TRANSPARENCY_PROFILE.md`](docs/PUBLIC_TRANSPARENCY_PROFILE.md)).

### Added — subject-binding + SD-JWT VC layers (EXPERIMENTAL, O6, O7)
- `subject_binding.py`: classifies a Statement subject as `DERIVED` (SHA-256 over the RFC-8785 canonical
  predicate, re-derived and matched) vs `EXTERNAL_ATTESTED` (override/tamper). An `EXTERNAL_ATTESTED` subject
  is warned by default on both the decision and outcome verify paths; it is only fail-closed when the caller
  opts in via `require_derived_subject` / `decision verify --require-derived-subject` /
  `outcome verify --require-derived-subject`. Plus nested schema closure. Doc:
  [`docs/SUBJECT_BINDING.md`](docs/SUBJECT_BINDING.md).
- `sdjwt_vc.py`: an SD-JWT VC relying-party profile (`typ = dc+sd-jwt`, `vct` allowlist, offline
  type-metadata integrity, holder-binding required). SSRF-safe by construction — no network I/O, a URL `vct`
  is an opaque identifier and never dereferenced. Doc: [`docs/SDJWT_VC_PROFILE.md`](docs/SDJWT_VC_PROFILE.md).

### Governance
- CODEOWNERS covers the seven new EXPERIMENTAL security modules (outcome, trust-pack, public-transparency,
  subject-binding, run-ledger, verification-summary, sdjwt-vc) — no self-merge for a security path.

## [3.1.3] - 2026-07-13

Security hardening release: the remaining P0 findings of the 3.1.1 audit round (verified live
against 3.1.2). Additive wire format; one deliberate, security-motivated tightening of
`safeForAutomation` (see below). SPEC revision `2026-07-13`.

### Changed — `safeForAutomation` requires the ATOMIC (root, tree size) authentication (A-P0-1, security)
- The sharp audit vector: an RFC 6962 inclusion proof constrains `(leaf_index, tree_size)` only up
  to path-shape equivalence — a real 2-leaf receipt (index 1) relabelled as `(index 2, tree_size 3)`
  verifies with the SAME payload, signature, root and proof. A root-BYTES pin cannot tell the two
  apart (both share the root), so `rootAuthenticity: PASS` + `safeForAutomation: true` was reachable
  for a forged tree context. Now `safeForAutomation` additionally requires
  `TREE_CONTEXT_AUTHENTICITY: PASS`: root AND tree size authenticated atomically from ONE source —
  a signed C2SP checkpoint (`--trusted-checkpoint`/`--checkpoint-vkey`, or a policy
  `merkle.trusted_checkpoints` entry) or an `--expected-root` + `--expected-tree-size` PAIR. A naked
  root pin is reported as `rootTrustLevel: ROOT_BYTES_ONLY` and never automation-safe
  (new blocker `TREE_CONTEXT_NOT_AUTHENTICATED`).
- New additive verdict keys: `rootBytesAuthenticity` (the legacy `rootAuthenticity` key stays as its
  wire-compat alias), `treeContextAuthenticity`, `checkpointAuthenticity`, `rootTrustLevel`
  (`CHECKPOINT` / `ROOT_AND_TREE_SIZE_PINNED` / `ROOT_BYTES_ONLY` / `NONE`).
- New policy section `merkle.trusted_checkpoints[]`: pins a SIGNED `(origin, treeSize, root)` triple
  (C2SP vkey + signature blob, optional `validUntil`); signature-verified, expiry-checked,
  `hashAlg`-checked at evaluation — origin/size/root tamper invalidates the signature. A non-empty
  list enforces on its own, exactly like `trusted_roots`.

### Fixed — expired eval policy now FAILS the policy evaluation (A-P0-2, security)
- The decision path already rejected an expired policy (exit 3); the EVAL path did not — an expired
  eval policy still produced `POLICY: OK` / exit 0 (only `safeForAutomation` went false). Lifecycle
  is now part of `evaluate_policy` itself: `policy:not_template`, `policy:not_expired`,
  `policy:not_before` (new additive `valid_from` field) → `POLICY: FAIL`, exit 3, path parity.
- Historical verification is explicit-only: `verify --verification-time <ISO-8601> --policy …`
  evaluates the policy lifecycle AS OF that instant with labelled output
  (`VERIFICATION_TIME: HISTORICAL`, `CURRENT_POLICY_STATUS`, `HISTORICAL_POLICY_STATUS`); an
  expired-today policy keeps `safeForAutomation: false` even in historical mode. No silent
  backdating, no silent acceptance.

### Fixed — decision `validity.audience` type confusion (found by the new regression corpus, security)
- A wrong-TYPE `validity.audience` (a STRING instead of the required array) satisfied a requested
  audience binding via Python substring matching (`"rp.example" in "rp.example"`). The check now
  requires a real JSON array (fail-closed).

### Added — `policyPurpose` binds a policy to ONE verifier path (A-P0-4)
- New additive field `policyPurpose` ∈ `eval` / `decision` / `outcome` / `trust-pack` /
  `public-transparency` (the latter three reserved for the 3.2.0 verifiers). The eval verify path
  accepts only `eval`, the decision path only `decision`; the wrong purpose is exit 3. Policies
  without the field keep working (documented transitional default); `policy lint --strict` requires
  it. All five shipped profiles now declare their purpose.

### Added — hardened policy metadata (A-P0-5)
- `merkle.trusted_roots` entries are hard-validated at load (standard base64, exactly 32 bytes) with
  their OWN error — never a silent never-matches.
- Reserved metadata (`deploymentReady`, `requiresIdentityOverlay`, `policyPurpose`, `schema`,
  `generatedFromTemplate`) can no longer be set by an instantiate overlay (loud `PolicyError`);
  `deploymentReady` is DERIVED from the final instance (identity pinned AND trust material valid AND
  purpose defined AND lifecycle valid AND not a template), and instances record their
  `generatedFromTemplate` provenance. Contradictory metadata (`deploymentReady: true` +
  `requiresIdentityOverlay: true`) is refused at load.

### Hardened after the 6-lens adversarial review (folded back before release)
- **Historical mode is present-tense-safe (was the one release-blocker).** `safeForAutomation` is a
  "safe to act on now" verdict, so its lifecycle and tree-context inputs are always evaluated at the
  REAL current time — even under `--verification-time`. Previously only `valid_until` had a current-time
  backstop, so a not-yet-valid policy or an expired-today `trusted_checkpoints` entry read
  automation-safe when a past (or future) instant was supplied. Now: `--verification-time` MUST be a
  past instant (a future one is exit 2); a new `POLICY_NOT_YET_VALID` blocker mirrors `POLICY_EXPIRED`;
  and the policy is evaluated twice in historical mode (the historical instant for the exit code + label,
  the current time for `safeForAutomation`). `CURRENT_POLICY_STATUS` now surfaces `NOT_YET_VALID`.
- **No `rootTrustLevel: CHECKPOINT` / `checkpointAuthenticity: PASS` overclaim.** `checkpointAuthenticity`
  now reports whether a checkpoint authenticated AND matched this bundle, not merely that some pinned
  checkpoint's signature verified; a verified-but-non-matching checkpoint reads FAIL and never labels a
  pair-derived context `CHECKPOINT`.
- **A matching `trusted_checkpoints` pin satisfies `require_authenticated_root`** (a checkpoint
  cryptographically authenticates the root, strictly stronger than a `trusted_roots` byte-pin) — the
  checkpoint match is now evaluated before the authenticated-root check.
- `treeSizeExpectation` reports `FAIL` (not `NOT_REQUESTED`) when a checkpoint was supplied but its
  signature did not verify. `policyPurpose: null` now loads and is treated exactly like absent
  (schema⟺parser parity). `evaluate_policy` fails closed (no traceback) on a non-string
  `checkpointSigner` in a raw dict that bypassed `load_policy`. `policy explain` lists the raw-template
  pin so `policy lint` no longer calls a minimal template vacuous.

### Migration notes
- A `merkle.trusted_roots` list mixing a valid 32-byte root with a malformed entry now fails to LOAD
  (exit 2) instead of silently skipping the bad entry (A-P0-5 hard validation); fix the malformed pin.
- `policy lint --strict` now FAILs any policy without `policyPurpose` (declare the verifier path); plain
  `verify` and non-strict `lint` are unaffected.
- Policy artifacts produced by 3.1.3 `policy instantiate` carry `policyPurpose` / `generatedFromTemplate`
  and are refused (fail-closed unknown-field) by 3.1.2 verifiers. In a mixed-version fleet, upgrade
  verifiers to 3.1.3 before re-instantiating policies. Bundles and verify output stay additive.
- `instantiate_template(..., overlay={...})` now rejects the reserved keys `deploymentReady`,
  `requiresIdentityOverlay`, `policyPurpose`, `schema`, `generatedFromTemplate` (they are derived or
  lifecycle-fixed); a `valid_until` overlay still works.

### Regression corpus (A-P0-1 … A-P0-5, plus the A-P0-3 vectors closed in 3.1.2)
- `tests/test_tree_context_authenticity.py` (relabel reproduction, checkpoint pin closes it, origin/
  signer/expiry/hashAlg mismatch vectors, legacy-root-pin-never-tree-context, CLI checkpoint path),
  `tests/test_policy_lifecycle_purpose.py` (lifecycle, historical mode, purpose matrix, metadata
  hardening, and the named decision aud/nonce fail-closed vectors), and
  `tests/test_lens_review_fixes_3_1_3.py` (the historical fail-open, future-instant rejection,
  expired-today checkpoint, require-auth-root-by-checkpoint, lib robustness, explain parity,
  policyPurpose null). Note: decision-receipt/v0.1 `validity` carries only `audience`+`nonce` — there
  is no predicate-level time window to expire; time-windowing lives on the policy
  (`valid_from`/`valid_until`), a predicate-level window would be a format change for the next breaking
  version.

## [3.1.2] - 2026-07-13

Patch release: one fail-closed security fix on the decision-verify path. No new API, no wire-format
change, fully backward-compatible.

### Fixed — `decision verify` audience/nonce binding is fail-closed on an absent validity object (security)
- A relying party that supplies `--aud` / `--nonce` (or `expected_audience` / `expected_nonce`) is
  asking for RFC-9901-§7.3-style replay/audience binding. Previously, if the decision receipt carried
  **no `validity` object** (or a non-dict one), the checks were skipped entirely — `audience_ok` /
  `nonce_ok` stayed `None`, the CLI exit gate (`None is not False`) let it pass **exit 0**, and the
  requested binding was silently unenforced (a fail-OPEN downgrade). Now an absent
  `validity` / `audience` / `nonce` is a FAIL (`audience_ok` / `nonce_ok` = `False`, exit 2) — the
  requested binding is never silently dropped. This mirrors the eval-path F4 hardening and the 3.1.1
  decision-path template/expiry gates. Regression:
  `tests/test_decision_hardening.py::test_missing_validity_with_expected_aud_nonce_fails_closed`.

## [3.1.1] - 2026-07-13

Patch release: automation-safety hardening. Three additive gates plus one fail-closed security fix,
all backward-compatible at the wire-format level. The one behaviour change is deliberate and
security-motivated: `safeForAutomation` is now stricter (see the note below).

### Changed — `safeForAutomation` is a stricter, global trust verdict (AP-1, behaviour change)
- `safeForAutomation` is now `true` **only** when the crypto verdict passed, the Merkle root was
  affirmatively authenticated, a supplied trust policy PASSED (`policy_ok is True` — no policy, i.e.
  `None`, never qualifies), that policy actually **pins a trusted signer**, it carries no blocking
  warning, it is **not expired**, and no required anchor / public-transparency / replay gate FAILED.
  A verify that previously reported `safeForAutomation: true` on a crypto-valid, root-pinned receipt
  **without** an evaluated, signer-pinning policy now reports `false`. This is intended: the flag is a
  global "safe to act on automatically" verdict, not a crypto-only verdict.
- New machine-readable `automationBlockers` array names every reason the flag is false
  (`POLICY_NOT_EVALUATED`, `POLICY_FAILED`, `SIGNER_NOT_PINNED`, `TEMPLATE_NOT_INSTANTIATED`,
  `ROOT_NOT_AUTHENTICATED`, `POLICY_EXPIRED`, `POLICY_WARNINGS_PRESENT`, `ANCHOR_REQUIRED_FAILED`,
  `PUBLIC_TRANSPARENCY_REQUIRED_FAILED`, `REPLAY_BINDING_REQUIRED_FAILED`, `CRYPTO_FAILED`).
  `PUBLIC_TRANSPARENCY_REQUIRED_FAILED` and `REPLAY_BINDING_REQUIRED_FAILED` are forward-compatible and
  **dormant** in this release (no reference call site supplies a `False` value yet); every other blocker
  is live. See SPEC.md "Enforcement status of the gate conditions".
- New human `SAFE_FOR_AUTOMATION: YES/NO` line with per-blocker reasons, derived from the same summary
  so the human and JSON forms can never disagree.
- Migration: `MIGRATION_3.1.0_TO_3.1.1.md`.

### Added — trust-policy templates and instantiation (AP-2)
- The four `strict-*` profiles are renamed `*-template-v1` and carry `deploymentReady: false` +
  `requiresIdentityOverlay: true`. The old names remain resolvable as **deprecated aliases** (a
  deprecation line on stderr, no break); `policy list-profiles` marks them.
- New `proofbundle policy instantiate <template> --issuer-key <pub> [--expected-root-file <f>]
  --policy-id <id> [--valid-until <iso8601>] [--output <f>]` turns a template into a deployment-ready
  org policy that pins your signer identity, offline. It is `deploymentReady: true` only when every
  required field is filled; unknown overlay fields fail closed.
- `policy lint --strict` now fails on a raw template (`deploymentReady: false`) and a still-set
  `requiresIdentityOverlay: true` with no signer pin. An expired `valid_until` fails `policy lint` in
  BOTH modes (strict and non-strict) — it is a lifecycle failure, not a strictness preference.
- New optional policy field `valid_until` (ISO-8601 UTC lifecycle expiry). A raw template used
  productively can never yield `safeForAutomation: true` (AP-1 + AP-2 §6.2).
- `schemas/trust_policy_v0_1.schema.json` gains `deploymentReady`, `requiresIdentityOverlay`,
  `valid_until` (kept in sync with the parser's allow-list).

### Added — `expected-tree-size` machine-readable status (AP-3)
- Verify JSON now carries a `treeSizeExpectation` object (`status: PASS|FAIL|NOT_REQUESTED`,
  `expected`, `actual`), so an integrator never has to infer from a missing line whether the check ran.
  The check itself still runs INDEPENDENTLY of the root (a mismatch already fails the crypto verdict).
- Added regressions for negative / zero / absurdly large expected values, the non-integer CLI usage
  error, and the `NOT_REQUESTED` status when the flag is absent.

### Fixed — unbindable eval SD-JWT graft refused fail-closed (N1, security)
- An eval SD-JWT that carries an eval-binding **root commitment** (a `receipt.root_b64` string, the real
  cross-receipt substitution vector) grafted onto a **non-eval-claim** payload has nothing to bind to and
  is now refused fail-closed (`sd-jwt-bundle-binding` FAIL → the whole bundle FAILs). The discriminator is
  the presence of `receipt.root_b64`, NOT a word-match on `passed`/`threshold`/`comparator`/`suite`, so
  the guard catches a graft even when those facts are moved into selective disclosures and never
  false-refuses a **generic** SD-JWT-VC (`iss` / `vct`, no `receipt.root_b64`) — which stays in scope
  (backward-compatible). Regression: `tests/test_sdjwt_verify_binding.py::TestN1UnbindableEvalSdJwt`.

### Fixed — pre-land 6-lens audit hardening (2026-07-13, security + honesty)
- **Decision path sibling gates (HIGH):** `decision verify` now enforces the same AP-1/AP-2 guards as the
  eval path — a raw, un-instantiated `decision-receipt-template-v1` (or any `requiresIdentityOverlay:true`
  policy) and an expired (`valid_until` past) decision policy no longer authorise a decision (both
  fail-closed → exit 3). `decision verify --policy` also accepts a packaged profile name (parity with
  eval `verify`). Regressions: `tests/test_decision_policy.py::TestDecisionPathTemplateAndExpiryGate`.
- **Honest automation blocker (AP-1):** a policy that DOES pin the signer but still carries an un-cleared
  `requiresIdentityOverlay:true` now reports the distinct `TEMPLATE_NOT_INSTANTIATED` blocker instead of a
  factually-wrong `SIGNER_NOT_PINNED`.
- **N1 empty-root hardening:** an always-open `receipt.root_b64: ""` no longer evades the graft check.

## [3.1.0] - 2026-07-13

Minor release: native Merkle **root authenticity** (relying-party root pinning + a trust-policy
requirement + separate verdicts, ADR 0004), score-vs-**threshold-verdict** evidence classes (P0-B),
**named trust-policy profiles** (WP3), claims-hygiene overclaim vocabulary, and the pre-release
six-lens audit hardening below. All additive and backward-compatible.

### Changed — six-lens audit hardening (2026-07-13, pre-release)
- **`THREAT_MODEL.md`** corrected: the "Merkle-root / inclusion tampering → FAIL" row no longer
  overclaims. A *coherent root rewrap* (the same signed payload re-anchored under a different valid
  root) is now stated honestly as `NOT_EVALUATED` by default, FAIL only under an authenticated-root
  policy / `--expected-root`.
- **`SPEC.md` §7** verification order now documents the additive `root-authenticity` / `tree-size`
  checks and the separate verdicts, so a second implementation knows they exist.
- **Shipped profile `strict-eval-authenticated-root-v1`** — the coherent-rewrap protection is now
  reachable from a NAMED profile (sets `merkle.require_authenticated_root`), not only a bespoke policy;
  the relying party supplies the authenticated root (`--expected-root` / `trusted_roots`).
- **`schemas/trust_policy_v0_1.schema.json`** gains `merkle.require_authenticated_root` +
  `trusted_roots` (they were enforced by the parser but rejected by the schema — a second implementation
  would have rejected the policy the code accepts). Nested schema↔parser parity test added.
- **Claims-hygiene** exception tightened: a genuine OUTER "signed Merkle/bundle root" or a first-party
  "our own tree is append-only" overclaim co-located in a per-sample / Rekor section is no longer
  over-exempted; `signed samples root` and external-log `append-only` stay exempt.
- **Cross-implementation corpus** now carries the coherent-rewrap vectors (verifies without policy;
  FAILs under `--expected-root`), so the finding is cross-checked, not only asserted in unit tests.
- Fixes: `verify --json` error path carries the `root_authenticity` key (was omitted → KeyError);
  `verify_bundle(expected_tree_size=)` rejects a float; a CLI-level root-authenticity + exit-code test;
  a decimal-precision evidence-class test. ADR `docs/adr/0005-eval-semantics-score-vs-threshold.md`.

### Added — score-vs-threshold evidence classes (P0-B, Hardening 3.0.1 §7)
- **`proofbundle.evalclaim.eval_evidence_class`** — a receipt today signs a THRESHOLD VERDICT (`passed`
  against the signed `comparator`/`threshold`); the exact score is used at emit to compute `passed` and
  then discarded, so no output may imply an exact score was verified. The classifier returns one of
  `THRESHOLD_VERDICT_VERIFIED` (the only class the frozen v0.1 schema produces), `EXACT_SCORE_VERIFIED`,
  `SCORE_COMMITMENT_PRESENT` (a binding, NOT a range proof), `SCORE_WITHHELD`, plus the always-present
  `METHODOLOGY_NOT_EVALUATED`. The last four are forward-compatible with the optional, additive
  exact-score profile (§7.2, EXPERIMENTAL, not in the frozen 3.x core).
- **`show-eval`** now prints an `evidence` line declaring the class and a `note` line for methodology,
  so the CLI never implies an exact score. Docs: `EVAL_CLAIM.md` §1a. Tests:
  `tests/test_eval_evidence_class.py`. No schema / wire / API break (additive read-side classifier).

### Added — native Merkle root authenticity (P0-A, Hardening 3.0.1 §6)
- The native Merkle root is NOT in the signature input, so the SAME signed payload verifies under
  DIFFERENT roots (a **coherent one-leaf rewrap**, reproduced in `tests/test_root_authenticity.py`).
  Merkle inclusion proves CONSISTENCY under the stated root, never its authenticity.
- **`verify_bundle(..., expected_root_b64=, expected_tree_size=)`** and CLI **`--expected-root` /
  `--expected-tree-size`** — relying-party root authentication, enforced bit-exactly; a mismatch FAILS.
- **Trust-policy `merkle.require_authenticated_root` + `trusted_roots`** — a policy can DEMAND an
  authenticated root; a stated root matching neither `--expected-root` nor a `trusted_roots` entry is a
  POLICY FAIL (exit 3, compared by bytes, malformed entries never match — fail-closed).
- **`root_authenticity_summary`** + a `ROOT-AUTHENTICITY` CLI line and JSON `root_authenticity` field —
  separate `payloadSignature` / `merkleConsistency` / `rootAuthenticity` / `publicTransparency` verdicts
  plus `safeForAutomation` (true only when the root was affirmatively authenticated). `merkle-inclusion`
  now reads "Merkle-consistent under the STATED root". ADR: `docs/adr/0004-native-root-authenticity.md`.
- Non-breaking: absent an expected root / policy, root authenticity is NOT_EVALUATED and every existing
  verdict is unchanged. `expected_checkpoint` / public-log toggles are the separate §10 profile (a later minor).

### Added — named trust-policy profiles (WP3, v2-audit)
- **`src/proofbundle/policies/*.json`** — four packaged, loadable trust-policy profiles:
  `research-preview-v1` (baseline structural pins only), `strict-eval-v1` (`assurance.minimum_level:
  reproduced`, `reject_self_attested_without_prereg`, KB-JWT required when `cnf` present),
  `strict-prereg-v1` (v0.2, requires a confirmed — not merely pending — external time anchor stamping
  the `preRegistration` target), and `decision-receipt-v1` (v0.2, pins `decision_receipt` structural
  requirements). Every profile is a REAL policy: it loads, `policy explain` lists real pins, and
  `policy lint` passes (non-strict) — see `docs/POLICY_PROFILES.md` for the honest scope (no profile
  pins a signer identity, since that is inherently deployment-specific; each carries the expected
  "attributes to nobody" warning as shipped).
- **`proofbundle.policy_profiles`** (`list_profiles`, `profile_path`, `resolve_policy_source`) — the
  loader. `resolve_policy_source` lets `policy explain` / `policy lint` / `verify --policy` accept a
  bare or `proofbundle-policy/`-prefixed profile name anywhere a policy path is accepted; a real file
  on disk always wins over a same-named packaged profile (never silently shadowed).
- **`proofbundle policy list-profiles`** — a new CLI subcommand listing the shipped profiles.
- **`explain_policy` now reports the `anchors` section as a real pin** (`policy.py`). Previously a
  policy whose ONLY pin was `anchors.require_anchor` / `require_anchor_target` looked "wirkungslos" to
  `policy lint` even though `verify --policy`'s anchor-requirement reconciliation genuinely gates exit
  code 3 on it (`_cmd_verify` reads `policy["anchors"]` directly) — a false vacuous-policy verdict for
  a pin that was, in fact, enforced. `evaluate_policy` itself (and the CLI's own anchor-requirement
  logic) is unchanged; only what `explain`/`lint` REPORT about an already-enforced pin was corrected.
  Tests: `tests/test_policy_profiles.py`.

### Added — v2-audit documentation deliverables (WP5/WP6/WP7/WP9)
- **`docs/PUBLIC_TRANSPARENCY_PROFILE.md`** — the distinction between a bundle's own local Merkle root
  and public transparency-log inclusion (already-implemented C2SP checkpoint/cosignature/tlog-proof
  support, SPEC.md §7c/§7d/§7e); documents the proposed (not implemented) `public-log-required-v1`
  trust-policy section honestly as a gap, not a shipped capability.
- **`docs/SD_JWT_VC_PROFILE.md`** (progresses issue #27) — the implemented SD-JWT core (RFC 9901) plus
  the 3.0.0 secure-by-default hardening (unsigned-fails, issuer-identity, bundle-binding), the emitted-
  but-unenforced SD-JWT VC syntactic markers (`typ: dc+sd-jwt`, `vct`, status-list pointer), and the
  three still-open items from issue #27 (type-metadata resolution, OAuth WG conformance vectors, a
  `vct`-requiring verifier flag) — none of which are implemented in this change; scoped as a follow-up.
- **`docs/MIGRATION_EVAL_PREDICATE.md`** (progresses issue #26) — the content-root canonicalization
  migration (`jcs-sha256-v1` vs. `legacy-sortkeys-json-v0`, already released in 2.1.0/ADR 0002) as a
  practitioner migration guide, plus an honest status check on issue #26's literal ask (an official
  upstream in-toto eval predicate): `in-toto/attestation#565` remains open/unmerged, so there is no
  official type to migrate to yet; the vendored `predicateType` is unchanged.
- **`docs/adr/0003-hybrid-payload-signatures.md`** (WP9) — a forward-looking ADR: a decision to DEFER
  payload-level post-quantum signatures (not implemented), comparing four options (A: status quo
  Ed25519 + hash anchors, B: Ed25519+ML-DSA-44 hybrid, C: DSSE multi-signature, D: COSE/JWS profile)
  and sketching four future trust-policy modes (`require_classical` / `require_pq` /
  `require_hybrid_both` / `allow_legacy_with_confirmed_hash_anchor`) as a design record, not a schema
  change — `policy.py`'s `signature` section is unchanged by this ADR.
- `scripts/claims_hygiene_check.py` scan set gains the four new user-facing docs (33 docs scanned, was
  29) — ADRs stay out of the scan set, matching 0001/0002 precedent.

### Added — claims-hygiene overclaim vocabulary (P0-C, Hardening 3.0.1 §5.4)
- `scripts/claims_hygiene_check.py` now also bans, unless negated: `signed (Merkle) root` (the outer
  root is a commitment, not the signed object), `publicly anchored`, `append-only`, `verified score` /
  `exact score verified`, `benchmark is secure`, `evaluation is correct`, `action was executed`,
  `<EU AI Act|AI Act|GDPR>-compliant`, and `<verifies|guarantees|certifies|…> truth`.
- Two precision exceptions keep the gate honest (a gate that cries wolf gets ignored):
  the **per-sample** exception exempts `signed root` inside a section carrying `per-sample` /
  `samples root` / `audit-challenge` / `prereg` (the samples root IS a field of the signed eval-claim
  payload, docs/DEMO.md); the **external-public-log** exception exempts `append-only` inside a section
  discussing Rekor / a transparency log (it is a correct property there, an overclaim only for a lone
  issuer-local tree). `truth` bans the claim VERBS, never the idioms `source of truth` / `ground truth`;
  `compliant` bans the regulatory sense, never `spec-`/`RFC 9162-`/`C2SP-compliant`. Tests:
  `tests/test_claims_hygiene.py` (`TestP0CAdditions`, both directions).

## [3.0.1] - 2026-07-12

### Security — close the residual model-id oracle in the EEE digest (M2)
- The `every_eval_ever` (EEE) digest stripped `model_info.id` and the top-level `evaluation_id`, but left the
  per-result `evaluation_result_id` (nested in `evaluation_results[*]`) inside the digest, while the `run_id`
  provenance path already guards that same id. An `evaluation_result_id` can embed or correlate the cleartext
  model id, so a digest over it was a model-id confirmation/enumeration oracle, asymmetric to the guarded
  provenance path. `_model_id_stripped` now also strips `evaluation_result_id` from each result. Tamper-evidence
  over scores/timestamps/dataset is unchanged (a tampered score still changes the digest); the id stays available
  for `run_id` provenance with its own leak guard. This closes the gap that shipped in 3.0.0.

### Documentation
- README: add PEP 740 (attestations) and SLSA build-provenance badges now that the first attested release is live.
- README: restructure for scannability (table of contents, deduplication, roadmap section).
- Erratum for the frozen 3.0.0 artifact: its `CHANGELOG.md` stated "811 tests" for the 3.0.0 line; the correct
  count is **817** (corrected on `main` post-tag). Tags are immutable, so the shipped 3.0.0 changelog keeps the
  typo; this 3.0.1 changelog carries the correction.

### CI / release hygiene
- Add a version-and-changelog integrity gate (`.github/workflows` + `scripts/check_version_and_changelog.py`):
  fails CI when `pyproject.toml`, `src/proofbundle/__init__.py` and `CITATION.cff` disagree on the version, or
  when the top changelog heading does not match that version. Closes the "merged but never released / version
  drift" class that let the M2 fix and the 811-vs-817 typo sit unreleased.

## [3.0.0] - 2026-07-12

### Security (BREAKING) — SD-JWT disclosures must be signed AND bind their bundle (WP-C1/C2, 6-lens review)
- An `sd_jwt_vc` block lives OUTSIDE `payload_b64`, so the bundle's Ed25519 signature does not cover it —
  only the issuer signature authenticates its disclosures. Two verify-path holes are now closed
  (secure-by-default; SPEC.md §6/§7 revision 2026-07-11):
  - **Unsigned SD-JWT now FAILS (was null-and-warn).** A bundle carrying an `sd_jwt_vc` with **no**
    `issuer_public_key_b64` previously verified with a warning and a null `sd_jwt_ok`; its disclosures were
    unauthenticated yet the bundle passed. It now fails verification (exit 1) with a failing
    **sd-jwt-issuer-signature** check, `sd_jwt_ok: false`, `sd_jwt_issuer_verified: false`, reason
    `unsigned`. There is no opt-out flag that lets an unsigned SD-JWT verify.
  - **Cross-receipt substitution now FAILS (new sd-jwt-bundle-binding check).** For a
    `proofbundle/eval-claim/v0.1` payload, a *validly issuer-signed* SD-JWT whose always-open disclosures
    (passed/threshold/comparator/suite/issuer + committed merkle root) describe a **different** bundle —
    a receipt lifted and grafted on — now fails (exit 1, `sd-jwt-bundle-binding: false`,
    `sd_jwt_ok: false`, reason `unbound`/`mismatch`).
  - **Forged issuer identity now FAILS (new sd-jwt-issuer-identity check).** A self-signed SD-JWT whose
    issuer signature verifies under an attacker-chosen key while its always-open `issuer` claim names a
    *trusted* party now fails (exit 1, `sd-jwt-issuer-signature: true` but `sd-jwt-issuer-identity: false`,
    `sd_jwt_ok: false`, reason `issuer-key-mismatch`): the verifying key is bound to the disclosed issuer
    (`fingerprint(issuer_public_key_b64) == issuer`).
  - **Migration.** If you emit bundles with an `sd_jwt_vc`, add `sd_jwt_vc.issuer_public_key_b64`
    (Base64 of the 32-byte raw Ed25519 issuer key) so verifiers can authenticate the disclosures, and
    ensure the SD-JWT's disclosed claims + `receipt.root_b64` match the bundle they ship in. Bundles that
    carry no `sd_jwt_vc` are unaffected. The three prior backward-compat tests are re-pinned as negative
    tests of the new secure behaviour; conformance corpus gains `bundle/sd-jwt-unsigned-unauthenticated`,
    `bundle/sd-jwt-signed-but-unbound` and `bundle/sd-jwt-forged-issuer-identity` (all expect exit 1).
### Docs — No-Overclaim scope corrections from the 6-lens review (MED)
- **`intoto.svr_properties` / `export_svr_dsse`** (WP-E1) — PROOFBUNDLE_PREREG_BOUND / PROOFBUNDLE_ANCHOR_VALID
  are emitted from the caller's flags (the function does not call verify_anchors) — caller-attested.
- **`decision.build_decision_statement`** (WP-E2) — a caller-supplied subject_sha256 is verbatim, not
  cross-checked against the predicate (nor re-derived at verify).
- **`merkle.verify_inclusion`** (WP-D2) — documented the RFC 6962 precondition: tree_size + root must come
  atomically from one authenticated source.
- **`policy` sd_jwt.max_iat_age_seconds** (WP-C3) — bounds the eval claim timestamp, NOT the KB-JWT iat.
### Security (BREAKING) — external time-anchor trust comes from the relying party, not the bundle (WP-A1)
- An external time anchor (`anchors[]`) previously took its trust root from the bundle's own `frozen`
  block: `anchors_rfc3161` from `frozen.rootCertsDerB64`, `anchors_ots` from
  `frozen.bitcoinBlockHeaderMerkleRootsByHeight`. That block is producer-controlled, so a malicious
  producer could freeze its OWN self-signed TSA root (or a self-committed backdated Bitcoin header) and
  self-certify a **backdated** timestamp — `--require-anchor` passed on nothing but self-consistency.
  Trust now comes ONLY from the relying party (SPEC.md §7i Trust model, rev 2026-07-11):
  - **rfc3161-tsa** is verified against `--trusted-tsa-root` (repeatable, DER/PEM) or policy
    `anchors.trusted_tsa_roots`; the frozen root is evidence (`frozenEvidence`), never trust.
  - **opentimestamps** is confirmed only against `--bitcoin-header HEIGHT:MERKLEROOT_HEX` (internal byte
    order) or policy `anchors.bitcoin_block_headers`; the frozen header is never trusted.
  - Without relying-party trust material a time anchor is `needs_rp_trust` (ok=False) and
    `--require-anchor` is **unmet → exit 3**, never a silent pass. Per-entry results carry `rp_trusted`,
    `needs_rp_trust`, `frozenEvidence`.
  - The same flags + policy `anchors` trust apply to `decision verify` (a statement time anchor on a
    decision receipt): `verify_decision_receipt(..., rp_trust=...)`, `decision verify --trusted-tsa-root /
    --bitcoin-header`.
  - **Migration.** A relying party that used `--require-anchor` (or `decision verify --anchors`) on a
    TSA/OTS anchor MUST now supply the trust material (`--trusted-tsa-root` / `--bitcoin-header`, or the
    policy `anchors` section). The
    bundle's frozen material stays in the format as evidence (TSA rotation) and is reported, so nothing
    is dropped; only its role as a trust source is removed. Third-party extension anchor verifiers keep
    working (backward-compatible dispatch); anchor tests are re-pinned; conformance gains
    `forged-anchor-own-frozen` (exit 3). THREAT_MODEL.md names the backdating attack.

### Security — pre-auth DoS: bound oversized integer parsing (WP-D1, 6-lens review)
- Python caps `int(str)` at `sys.get_int_max_str_digits()` (default 4300) and raises a raw `ValueError`
  above it (CWE-674 / CVE-2020-10735). A pre-auth parser that fed an unbounded decimal string to
  `int()` surfaced this as an uncaught traceback. Fixed at three sites: `_strict_json.loads_strict`
  maps the int-conversion `ValueError` from an oversized JSON integer literal to `BundleFormatError`
  (covers every JSON verify path — bundle / decision / in-toto / status-list / anchors); `tlogproof`
  and `checkpoint` bound the tree-size / index digit count (<= 20, i.e. 2**64) BEFORE `int()`; and the
  CLI `verify-proof` handler catches `ValueError` as a stopgap. Regression-tested; never a raw traceback.
### Security — verify-path hardening from a 6-lens adversarial review (2026-07-11)
- **Trust policy rejects a low-order / non-canonical pinned key** (`policy.py`) — the core verifier
  deliberately accepts low-order and non-canonical Ed25519 encodings (SPEC §4a). A policy that PINS such
  a key as a trusted issuer / decision-maker would accept a fixed `(pub, sig)` pair for many messages
  (for the identity encodings, ALL messages) with no private key — forgery of a trusted identity without
  a secret. `load_policy` now fail-closed rejects the whole class by the point's **y-value**
  (sign-independent, so no encoding variant slips past — an earlier hand-kept byte-string blocklist
  missed three) plus the non-canonical (`y >= p`) class, in `allowed_issuers` and
  `trusted_decision_makers`; a low-order key is also refused at the evaluation layer
  (`evaluate_policy` / `evaluate_decision_policy`) as defense-in-depth, so a policy dict that skipped
  `load_policy` gets no trust from it either. (Scope: a genuine full-order key from an honest keygen is
  accepted; MIXED-order keys are accepted and are not forgeable via this attack — a full prime-subgroup
  membership check is a follow-up.)
- **`verify_decision_receipt` no longer reports trust fields over unauthenticated bytes** (`decision.py`)
  — a forged/unsigned envelope previously left `audience_ok`/`nonce_ok`/`evidence_bound` computed
  (potentially True) with an empty `errors[]`. Now an aggregate **`ok`** field is the single verdict, the
  trust-derived fields stay `None` when `crypto_ok` is False (mirroring the anchors/policy gates), an
  error is recorded on a crypto failure, and `evidence_bound` is `None` (not a vacuous `all([])` True)
  when there are no evidence refs.
- **Decision trust policy surfaces the "attributes to nobody" warning** (`decision.py`) — a decision
  policy that constrains the verdict/type but pins no `trusted_decision_makers` means `POLICY: OK` proves
  integrity by an unknown signer. `policy_warnings()` (already decision-aware) is now wired into the
  decision verify path, matching the eval path.
- **`evalclaim.load_claim_text` uses the shared strict parser** (`evalclaim.py`) — it reimplemented
  duplicate-key rejection and did not map `RecursionError`, so a pathologically deep-nested claim payload
  crashed `decode_eval_claim` uncaught (CWE-674) — reachable from the batch verifier
  `hf_evals.verify_eval_results_entry`, `policy.evaluate_policy`, and CLI `emit-eval`. It now delegates to
  `loads_strict` (deep nesting and duplicate keys become a clean `EvalClaimError`, never a raw traceback).

### Docs — No-Overclaim corrections from the 6-lens review (2026-07-11)
- **`hf_evals.to_eval_results_entry` docstring + THREAT_MODEL** — the value↔verdict check was described
  as making the published `value` "match" a disclosed score and "stops 0.60 next to 0.99". The signed
  claim carries `threshold`/`comparator`/`passed`, not the exact score, so the check binds the value to
  the correct SIDE of the threshold, not to a true magnitude: an inflated value on the passing side (a
  true `0.81` published as `99.9`, both `>= 0.80`) still verifies. Docstring corrected and a
  value-magnitude boundary row added to THREAT_MODEL.
- **`docs/OPERATIONS_SECURITY.md`** — the `[Owner]` checklist items read as accomplished present-tense
  fact ("account on 2FA", "tags are protected", "Scorecard is enabled"), contradicting the document's
  own "does not assert they are done" preamble. The marker is now **`[Owner · to verify]`** on every
  line so the unverified status survives a reader skimming the list.

### Added — native-bundle conformance vectors (WP-S1)
- **`conformance/bundle/`** — four native proofbundle bundle cases (kind `native_bundle`) checked
  against the CLI verify exit-code contract: `valid-minimal` (a valid bundle verifies, exit 0),
  `duplicate-json-key` (a bundle whose raw JSON carries a duplicate top-level key is rejected as
  malformed, exit 2 — locking the C1 Bishop-Fox parser-differential defense onto the conformance
  gate), `tampered-payload` (a valid bundle with one payload byte flipped fails the signature, exit 1),
  and `corrupted-signature` (payload intact but the signature bytes corrupted, exit 1). The harness `native_bundle` handler runs `proofbundle verify` and asserts the exact exit
  code, with the same fail-closed floor (a case must declare `exitCode`). Anti-tautology regression
  tests: a wrong expected exit code fails, a missing exitCode fails, and the duplicate-key bundle is
  proven rejected.
### Added — MAINTAINERS.md + TRADEMARK.md + OPERATIONS_SECURITY.md governance docs (WP-W5 phase 1-2)
- **`MAINTAINERS.md`** — the conventional human-readable maintainer file: names the single maintainer,
  points to `GOVERNANCE.md`, the DEFAULT-DENY `oss_maintainer_roles.json`, `.github/CODEOWNERS`, and
  `SECURITY.md`. No delegated maintainers today.
- **`TRADEMARK.md`** — an honest use-of-name policy: the MIT-licensed code is free to use and fork; the
  "proofbundle" / "b7n0de" names are **not registered trademarks** (no ® claim) but should not be used
  to name a competing fork/package or imply official status. Protects the one thing the project cannot
  fork away: that a receipt under this name comes from the reviewed, gated releases.
- **`docs/OPERATIONS_SECURITY.md`** — the supply-chain posture checklist (accounts/2FA, PyPI trusted
  publishing, signing-key custody, SHA-pinned CI actions, fork-PR secret isolation, domain lock). It is
  a checklist, not a claim: `[Owner]` items are the maintainer's to verify and are not asserted done;
  `[repo]` items are enforced by files in the repo. Distinct from `SECURITY.md` (which is about
  receiving vulnerability reports).
- **`docs/GRANT_MILESTONES.md`** — the public deliverable/status tracker for the funded independent
  security-review track (M1–M…), factual and linked to repo evidence, never aspirational.
- All four docs are now in the `claims_hygiene_check` scanned set (29 docs), so they are held to the
  same No-Overclaim discipline as the rest of the documentation.

### Added — offline conformance corpus with cross-implementation decision vectors (WP-W2)
- **`conformance/`** — a versioned, digest-pinned corpus verified fully offline by
  `conformance/run_conformance.py` (`make conformance`). Each case declares what it proves AND what
  it does not, so a green run never overclaims. Two cross-implementation decision-receipt vectors
  from MarkovianProtocol/audit-anchor (credited, pure data):
  - `decision/crossimpl/confirmed-anchor-lifecycle` — proves RFC 8785 canonicalization + content-root
    binding cross-implementation **and** a confirmed Bitcoin anchor at block 957504: the OTS proof's
    committed root matches the real block merkle root (independently fetched, frozen in the case,
    verified offline; a wrong frozen root is rejected — `block_mismatch`, covered by `test_anchors_ots.py`).
    Does not prove `decision-receipt/v0.1` schema conformance (predicate reports 12 findings, expected-fail).
  - `decision/crossimpl/canonicalization-root-binding` — proves canonicalization + root binding; anchor
    still pending and predicate not yet schema-conformant (both recorded as expected, not hidden).
  Anchor sub-checks run in the `anchors` CI job (`[anchors]` extra, `--require-anchors`); the corpus's
  non-anchor checks run in every matrix leg. README §Interop precised: canonicalization interop proven,
  full decision-receipt conformance of the external fixture still pending. The harness is fail-closed by a
  required-expectations floor: a `decision_crossimpl` case that under-declares its bindings FAILS rather
  than passing green asserting nothing, and its defining checks (JCS byte-identity, content-root match,
  evidenceRef binding, anchor when a `.ots` ships) run unconditionally; a missing fixture is a per-case
  FAIL, not a run-aborting crash. Hardened further after a 6-lens review: a missing case dir,
  a malformed case.json, or a case.json with no `kind` is now a per-case FAIL (the outer parse was
  outside the try before), and a native_bundle `input` cannot escape its case directory.

### Added — decision-receipt validator API hardening + cross-impl gap record (WP-W6 / WP-W1)
- **`decision.require_valid_decision_predicate(pred)`** — a raising counterpart to
  `validate_decision_predicate`. The list-returning validator (empty list == valid, never raises)
  is easy to misuse as `try: validate(...) ; except: ...`, which silently passes every predicate:
  that idiom produced a public "passes the enforced v0.1 validator as-is" claim for an external
  cross-implementation fixture that in fact reported 12 findings. The wrapper raises
  `DecisionReceiptError` (with the finding count) on an invalid predicate, `None` on a valid one.
  `docs/predicates/decision-receipt.md` §6.1 documents the list-vs-raise contract; a regression
  test (`tests/test_decision_validator_api.py`) pins that the naive try/except idiom wrongly passes.
- **`audit_artifacts/crossimpl_fixture_gap_20260711.md`** — No-Overclaim record for the
  MarkovianProtocol/audit-anchor decision-receipt fixture: the RFC 8785 canonicalization and
  content-root binding are proven byte-identical cross-implementation (evidence `323adb18…`,
  decision `ff05e3e0…`), but the external predicate does not yet satisfy the enforced
  `decision-receipt/v0.1` schema (field mapping thread-prose → v0.1 included). Both statements are
  recorded so neither is overclaimed nor hidden.

### Added — CODEOWNERS + roles registry, dead governance link fixed (WP-G2)
- **`.github/CODEOWNERS`** for the trusted core, `SPEC.md`, `schemas/`, `docs/predicates`,
  `docs/adr`, and the CI/release wiring — a change to those paths requires the maintainer's review
  ("more eyes, not weaker gates", GOVERNANCE.md). Single-maintainer today; co-maintainers are added
  per-person, never implicitly.
- **`oss_maintainer_roles.json`** at the repo root — the delegated-rights registry GOVERNANCE.md
  referenced but which pointed at a non-existent `office/governance/` path (a monorepo path that
  never shipped here). DEFAULT DENY: nobody holds merge/release/secret rights without an explicit
  entry. GOVERNANCE.md now links the real file and CODEOWNERS.
- The project's **first external contributor** (@onxxdatas, issue #28 — `--version` prints the
  pinned spec revision) is recorded in the governance story and the roles registry (no delegated
  rights, like every contributor).

### Added — HF entry verifier-side binding + EEE source digest (WP-I2 / WP-I3)
- **`hf_evals.verify_eval_results_entry(entry)`** — the value↔verdict consistency was emit-side
  only: an `.eval_results` entry whose displayed `value` was edited AFTER the `pb1.` token was
  minted verified fine (the token check covers only the embedded bundle, and a Hub reader sees the
  value, not the token). Now the verifier side checks token crypto AND
  `value <comparator> threshold == passed` against the decoded, issuer-bound claim (fail-closed:
  a non-eval bundle or a non-finite value never judges as consistent). **Documented replay
  boundary** (module + THREAT_MODEL row): the entry's `dataset.id`/`task_id` are NOT bound to the
  receipt's salted dataset commitment — that binding needs the salt opening; this function is a
  value check, never a repo-binding check.
- **`adapters.from_eee_dataset` now binds the receipt to its exact source record** (it was the
  only adapter without a provenance binding): `provenance.eee_record_sha256` =
  `sha256-jcs:<hex>` over the RFC-8785-canonical record (labeled `sha256-sortkeys` fallback,
  mirroring `adapters/_provenance.config_hash`), plus the RESULT-level `evaluation_result_id` as
  `run_id` — guarded: dropped if a producer embedded the cleartext model id in it (the TOP-level
  `evaluation_id` stays excluded for exactly that reason; digest-privacy consideration documented
  in the adapter).
- Hardened after a Tier-1 review (2 P1 privacy findings): the `eee_record_sha256` digest is now computed over a **model-id-stripped** record — an unsalted digest over a record embedding `model_info.id` in cleartext was a model-id confirmation/enumeration oracle (the old "not enumerable" comment was an overclaim); it still binds scores/timestamps/dataset for tamper-evidence. The `run_id` privacy guard now drops the id on ANY model-name component (bare name, slug variants, case-insensitive), not only the full `org/name` id. `verify_eval_results_entry` returns fail-closed (not a raise) for a token-less entry (verifyToken is optional in the HF schema) and rejects a boolean `value` (the builder rejects bool too).

### Added — anchor TARGET gate + structured trustedTime (WP-A1 / WP-A2 / WP-A7)
- **`verify --anchor-target receipt|preRegistration|statement`** (implies `--require-anchor`) and
  the trust-policy **v0.2 `anchors` section** (`require_anchor`, `require_anchor_target`,
  `allow_pending`): the anchor requirement matched the TYPE only, so a `receipt` anchor stamped
  today satisfied a relying party who demanded backdating protection — existence-now proves
  nothing about existence-before-the-run. Matched is now ok ∧ ¬warn ∧ type ∧ **target**; a
  CLI/policy conflict is exit 2 (mirrors `expected_aud`), never a silent override.
- **Structured `trustedTime` in per-anchor results** (SPEC §7i): `{source: rfc3161_gen_time,
  time, tz}` from a verified token's own gen_time; `{source: bitcoin_block, height}` from a
  confirmed OTS attestation (native unit, no wall-clock guess); the markovian type carries the
  delegated OTS time through. Present ONLY when the proof carries it — never derived from the
  informative `anchoredAt` (a tampered `anchoredAt` changes neither verdict nor trustedTime,
  pinned by regression test). Time-window policies over `verify --json` become buildable.
- **A7 regressions closed:** a v0.1 bundle carrying `anchors[].target: "statement"` is now
  rejected as malformed (exit 2) by the verifier itself — the docs promised it, the code never
  enforced it (`statement` is exclusively for DETACHED decision evidence); a non-string
  `anchoredAt` on a detached anchor fails closed; anchoredAt-tamper invariance is pinned.
### Added — `policy explain` / `policy lint` + the vacuous-pass warning (WP-TP1)
- **A policy that pins nothing no longer passes silently.** `evaluate_policy` returns
  `policy_ok = all(checks)`; with an empty/id-only policy `checks` is empty and `all([])` is True —
  a green `POLICY: OK` that evaluated nothing. Now: `proofbundle policy lint <policy>` exits 1 on
  such a wirkungslose policy (`--strict` also fails an attributes-to-nobody policy);
  `proofbundle policy explain <policy>` lists the effective pins (human + `--json`).
- `verify --policy` marks a PASSING policy that pins no signer inline —
  `POLICY: OK (WARNING: attributes to nobody)` — plus a machine-readable `policy_warnings[]` JSON
  field. Exit codes unchanged (a warning, never a new failure mode; fail-closed behavior of real
  policy violations untouched).
- docs/TRUST_ANCHORS.md documents the new subcommands; +9 tests
  (`tests/test_policy_explain_lint.py`).

### Fixed — predicateType enforcement on the in-toto verify paths (WP-I1)
- **`verify_eval_result_dsse` / `verify_svr_dsse` / `verify_intoto_dsse` now ENFORCE the
  `predicateType`, not just return it.** Previously a validly-signed envelope of one predicate type
  verified `ok=True` through the verify function of another (a swapped SVR accepted as an
  eval-result, a test-result as an SVR, …) — the decision-receipt layer already rejected such
  confusion, the eval/SVR/test-result layer did not. Each function now pins its own type by default
  (`expected_predicate_type`, opt out with `None`), returns `ok=False` + a `predicate_type_ok`
  field + a "confusion attack?" detail on a foreign type. Additive return field; the diagonal
  (matching type) verifies exactly as before.
- Cross-predicate matrix test (`tests/test_predicate_type_enforcement.py`): every emitted in-toto
  type signed and run through every verify function — only the diagonal verifies, every
  off-diagonal cell is `ok=False`; plus explicit-expected-type pin, opt-out, and
  wrong-signature-still-fails. A mutation operator (disable the check ⇒ red).
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

### Added — Ed25519 verify semantics decided, documented, pinned (WP-C2)
- SPEC.md gains **§4a Verification semantics — the edge-case envelope**: proofbundle's Ed25519
  verification (via `cryptography`/OpenSSL) matches the **BoringSSL / Dalek (non-strict)** row of
  the "Taming the Many EdDSAs" corpus exactly (ACCEPT {0,1,2,3,11}, REJECT {4,5,6,7,8,9,10};
  eprint 2020/1244) — cofactorless, RFC 8032 S-bound enforced, non-canonical R rejected,
  non-canonical A partially accepted, small-order accepted; NEITHER Dalek-strict (rejects
  {0,1,2,11}) NOR ZIP-215 (additionally accepts {4,5,9,10}). Honest RFC 8032 signatures are
  unaffected; the cross-verifier-consensus consequence for crafted signatures is documented here
  and in THREAT_MODEL.md.
- The 12-vector corpus is vendored **byte-identical** (`tests/fixtures/ed25519_speccheck_cases.json`,
  from novifinancial/ed25519-speccheck commit `5e4bfc4…`, blob `8686dcb…`, Apache-2.0 — LICENSE +
  provenance README beside it) and pinned by `tests/test_ed25519_semantics.py` (content SHA-256 +
  per-vector verdict) — a fixture tamper OR a backing-library behavior change turns the
  repository's CI red, demanding a deliberate documented decision, never a silent drift.
  No behavior change; switching profiles would be a versioned, breaking change.
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
### Verification discipline
- **817 tests** (was 683 at 2.1.0) across the 3.10–3.14 CI matrix, all green. A pre-release audit
  hardened the two anti-regression instruments so they actually cover the code this release adds:
  the mutation gate (`scripts/mutation_check.py`, Anti-Goodhart) now carries an operator for **each of
  the four new breaking defenses** — WP-C2 unsigned-fail, WP-C1 issuer-identity and bundle-binding,
  WP-A1 needs-rp-trust — so a future accidental revert of any of them goes red (the mutation CI job now
  installs `[anchors]` so the WP-A1 operators are exercised, not short-circuited at `no_lib`). The
  offline conformance corpus's `sd-jwt-unsigned-unauthenticated` vector is now **cnf-free so it isolates
  WP-C2** (disabling that defense flips the vector to exit 0), instead of riding on the older v1.6
  cnf-downgrade check.
- **SD-JWT / KB-JWT payloads now parse with `loads_strict`** like every other verify path: a DUPLICATE
  JSON key (e.g. a second `cnf` naming an attacker holder key) is rejected fail-closed at the structure
  gate. The release-audit follow-up extended this to the last parse site of the same class, the
  `evalclaim.sd_jwt_hidden_count` disclosure-transparency helper (a duplicate key now returns `None`,
  not a last-wins count), closing the documented parser-differential residual in full (regression:
  `tests/test_sdjwt_duplicate_cnf.py`).
### Packaging
- The `Development Status` classifier stays **`4 - Beta`** for 3.0.0 (Owner decision E1, 2026-07-12):
  stable is evidenced, not asserted. The move to `5 - Production/Stable` is a separate, audit-gated
  milestone that lands only after the funded external security review passes
  (tracked in `docs/GRANT_MILESTONES.md`), never claimed pre-audit — even for a breaking security release.

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
  is unsigned; signatures are v2 scope). Honest novelty: proofbundle auto-emits an **Ed25519-signed**
  receipt of an inspect_ai eval / pytest run via the framework's native plugin, a capability not found in
  a comparable released tool at the time of writing.
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
