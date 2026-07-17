# Auditor open points — what the machine CANNOT decide (No-Fake)

This is the honest boundary of the readiness pack: the points below are exactly the ones no test in
this repository can settle, so they need a human cryptographer's / protocol reviewer's judgement. The
pack states its own limit here rather than letting a green matrix imply completeness. Passing every
internal gate (see `REPRODUCTION_RUNBOOK.md`) is a precondition for this review, not a substitute for it.

## A. Cryptographic construction soundness (Q2_PRIMITIVE_HARDNESS)

- Ed25519 / ECDSA-P256 / ML-DSA-65 / hybrid signature usage: correct domain separation, no nonce or
  malleability pitfalls, correct public-key handling. Our tests prove agreement and tamper-evidence,
  not primitive hardness (IACR 2025/980: formal covers logic, not primitives).
- DSSE PAE binding, RFC 8785 (JCS) canonicalization edge cases, RFC 6962 Merkle construction: we test
  differential agreement Python<->Rust and against the C2SP/Wycheproof style negative vectors, but a
  reviewer should confirm the constructions themselves, not only that two implementations agree.
- SD-JWT / KB-JWT / status-list constructions and the BBS selective-disclosure profile.

## B. Protocol semantics

- The relation-lineage aggregation ladder (relation/v0.1, EXPERIMENTAL): the LOGIC is modelled and
  proven (formal O1-O4) and code-enforced, but the SEMANTIC claim (what a supersedes/revises/retracts
  edge should mean for a downstream consumer) is a design question for review.
- Trust-Pack root-of-trust: threshold semantics, two-stage rotation authorization, revocation, and the
  payloadType/predicateType binding (O7, reserved) are code-enforced and vector-tested but not formally
  modelled.
- Anchor trust-root distribution (Q1_ANCHOR_TRUST_ROOT_DISTRIBUTION): how a verifier obtains and pins
  the OpenTimestamps / RFC 3161 trust roots is an operational trust question outside the code.

## C. Side channels (Q3_SIDE_CHANNELS)

- Timing / cache behaviour of the verify paths. Deliberately out of scope for the formal model and the
  fuzz soak; a permanent external/research remainder (see PROGRESS.md's ~2% irreducible ceiling).

## D. Supply chain / build provenance beyond L3 shape

- The reusable attest workflow provides the SLSA-L3 SHAPE (signing separated from build). A reviewer
  should confirm the actual PyPI Trusted Publishing + PEP 740 attestation chain on a real published
  artifact, and the org-shared reusable workflow question (Q4_REUSABLE_WORKFLOW_ORG_SHARED).

## E. Consciously deferred (documented, not gaps to close for audit-candidate)

- Full TEE-attestation path, whole-program verification, distributed OSS-Fuzz on Google infra
  (ClusterFuzzLite local is sufficient for audit-candidate, SOTA §7).
- The Rust second verifier covers a deliberate slice; the 36 PENDING surfaces are honestly declared,
  not fake-100% (see `rust_parity_scope.md`). Whether that slice is the right one is a review question.

## F. The one remaining gate to stable

The single deliberately-open acceptance criterion is "external audit completed". 4.0.0-stable = this
pack + the external audit ABSCHLUSS + findings closed/accepted + relation wire-freeze. Nothing in this
repository can flip that bit; only the external reviewer can.

## G. Known limitations of the audit-candidate matrix instrument itself (No-Fake, self-declared)

`scripts/audit_candidate_matrix.py` is a self-check tool, so its own boundaries are declared here
rather than left implicit. None of these hide a green where the obligation is broken; they are honest
edges a reviewer should know about.

- **C1.1 test-runner recognition is head-scoped.** `_is_real_test_invocation` recognises a real run
  only when the executed command head is `pytest` / `py.test` / `python -m pytest` /
  `python -m unittest` / `unittest discover` and is not a `--collect-only` / `--co` dry run.
  Consequence: `make test` and `tox` (which run tests indirectly through a Makefile / tox config) are
  deliberately NOT recognised, so a CI that ran its suite only via `make test` would read as "no
  executing test step". This is a conscious trade (recognising them would need parsing the
  Makefile/tox config); the repository's own `ci.yml` runs `python -m unittest discover` directly, so
  it is covered.
- **C1.1 falls to DATA_BLOCKED without PyYAML.** The workflow is YAML-parsed (never a file-wide
  substring scan), so if PyYAML is absent the check reports DATA_BLOCKED (honestly "not verified
  here"), never a fake PASS and never a FAIL.
- **C12.2 negation guard is lexical and line-scoped.** A `0 open P0/P1` line that is negated/conceded
  on the SAME line (`NOT` / `nicht` / `still open` / `remaining` / `offen`) does not satisfy the
  obligation. Because it is a light lexical guard, a positive phrasing that happens to place one of
  those words on the claim line (e.g. `0 P0/P1 remaining`) would be conservatively treated as
  not-satisfied; the canonical record states the claim plainly and avoids such phrasing.
- **The sibling presence checks C1.2 / C1.3 / C9.2 / C11.3 are raw substring-presence checks** (a
  keyword such as `SOURCE_DATE_EPOCH`, `sha256`, `attest`, or `EXPERIMENTAL` present in the file). A
  keyword sitting in a comment satisfies them; they assert that the artifact EXISTS and names the
  concept, not that the underlying behaviour is correct — the deeper behaviours are enforced by their
  own dedicated blocking gates/tests elsewhere in CI.
- **`pre_tag_audit_gate.audit_records_for` follows symlinks.** Its `rglob` is rooted at the exact
  `audit_artifacts/<token>/` subfolder (it never walks the wider tree), but a symlink placed inside
  that subfolder pointing outside the repo would be traversed. The committed tree carries no such
  symlink.
