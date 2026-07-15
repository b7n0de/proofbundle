# For reviewers — a 30-minute adversarial audit path

proofbundle asks to be trusted with a security-sensitive claim ("this verifies offline"), so it
should be easy to try to break. This page is written for a skeptical external reviewer, not a user.

## What to trust, and how small it is

The **trusted core** — the code whose correctness the whole tool rests on — is deliberately tiny
and depends only on `cryptography` + the standard library:

- `src/proofbundle/signature.py` — Ed25519 verify (delegated to `cryptography`; strict length checks).
- `src/proofbundle/merkle.py` — RFC 6962 leaf/node hashing (0x00/0x01 domain separation),
  inclusion + consistency proofs, constant-time root compare.
- `src/proofbundle/bundle.py` — the verifier: signature, Merkle inclusion, optional SD-JWT/KB,
  strict unknown-field rejection, fail-closed.

Everything else is emit-side, adapters, or optional layers (SD-JWT/KB-JWT, C2SP checkpoints /
cosignatures / tlog-proof, Token Status List, per-sample trees). A reviewer can audit the core in
an afternoon and treat the rest as "does not weaken the core if ignored."

## Scope beyond the v0.1 bundle core (2.1.0+)

The three files above are the complete trusted core for the original `proofbundle/v0.1` bundle
verifier, and the "audit in an afternoon, everything else does not weaken the core if ignored"
line is still exactly right **for that scope**. It stopped being the whole picture once the
`decision-receipt/v0.1` predicate shipped in 2.1.0 and the 3.2.x attestation-chain modules
followed: each module below runs its OWN fail-closed structural, threshold, or replay-binding
logic before it ever calls into `signature.py` / `pqsig.py` / `dsse.py` for the underlying
Ed25519 / ML-DSA primitive, so "the rest is decoration around the three files" is no longer a
safe assumption when scoping review time. The versioned, maintained statement of what is
STABLE vs. EXPERIMENTAL (and therefore what a paid external audit should target first) is
[`docs/AUDIT_SCOPE.md`](AUDIT_SCOPE.md); the short orientation for a reviewer here:

- `decision.py` (shipped, 2.1.0) — DSSE-signed decision receipts. The attack surface worth
  probing is the caller-attested `subject_sha256` override in `build_decision_statement`
  (`subject_binding.classify_subject` is what turns a subject-rehang into a signal, not a
  silent pass) and the `validity.audience` / `validity.nonce` replay-binding gate.
- `trust_pack.py` (EXPERIMENTAL, 3.2.0) — a TUF-inspired, threshold-of-root trust document.
  Probe the crypto-agility `alg` dispatch (`ed25519` default / `mldsa65` /
  `hybrid-ed25519-mldsa65`; PB-2026-0715-08, [ADR 0007](adr/0007-crypto-agility-alg-dispatch.md))
  for a downgrade path, and the two-stage rotation vouching (`prev_root_keys` /
  `prev_root_threshold`) for a self-owned-keys rollover.
- `outcome.py` (EXPERIMENTAL, 3.2.0) — role separation (`executor.id` must differ from the bound
  decision's `decisionMaker.id`) and `decisionRef` content-root binding; probe for a replay of one
  outcome across a different decision.
- `renewal.py` (EXPERIMENTAL, 3.2.0, ADR 0006) — the RFC 4998 ArchiveTimeStampSequence. Probe the
  algorithm-confusion binding (`sig_alg` is folded into the exact bytes an authority signs, so a
  signature cannot be relabeled to a weaker algorithm and re-verified) and the multiple anchor
  modes in `verify_sequence` (an unauthenticated structural-only mode exists but needs an explicit
  opt-in).
- `checkpoint.py` (shipped, SPEC §7c/§7d) — C2SP checkpoints plus Ed25519 and ML-DSA-44 witness
  cosignatures. Probe `witness_quorum`'s dedup by decoded key MATERIAL rather than key name (one
  physical key registered under many names must count once, not N times).
- `public_transparency.py` (EXPERIMENTAL, 3.2.0) — a policy layer composed over `checkpoint.py`.
  Probe that the aggregate status cannot pass without a cryptographic anchor (a checkpoint
  signature or a witness quorum) — plaintext origin/root/tree-size fields parsed from an unsigned
  note must not be enough on their own.
- `sdjwt.py` / `sdjwt_issue.py` / `sdjwt_vc.py` — RFC 9901 selective-disclosure verify/issue and
  the SD-JWT VC relying-party profile. Probe the recursive-disclosure resolution (PB-2026-0715-15a
  closed a quadratic CPU cost there) and the VC `vct` / type-metadata path, which is offline-only
  by construction (no code path opens a socket, so a hostile `vct` cannot drive a request).

None of this widens the ORIGINAL three-file core — `signature.py` / `merkle.py` / `bundle.py` are
unchanged in shape and stay the single afternoon-sized read. It widens what "the rest" means: a
reviewer auditing the full eval → decision → outcome chain, or the trust-pack root of trust, needs
the scoped time budget in `docs/AUDIT_SCOPE.md`, not the 30-minute path below.

## The 30-minute path

1. **Run it, then break it (5 min).** `pip install -e ".[eval]" && proofbundle demo` — an honest receipt
   verifies, six tampers each verify FAILED, a swapped sample is caught. The command exits
   non-zero if any tamper verifies; if you can make it exit 0 with a real tamper, that is a break.
2. **Full suite (5 min).** `make test` — the whole test suite (the current count is what CI prints;
   it is deliberately not hard-coded here, a stale number reads as neglect). Without optional dev
   extras you will see a few skips/env errors (`jsonschema`, `pytest`); those are environmental,
   not code defects.
3. **Correctness is not self-referential (5 min).** Two external anchors are vendored and tested:
   RFC 6962 conformance vectors from `transparency-dev/merkle`
   (`tests/fixtures/rfc6962_vectors.json`) and a real Sigstore Rekor inclusion proof
   (`tests/fixtures/rekor_inclusion_25579.json`, logIndex 25579 in a 4.16M-entry tree,
   recomputed offline by `examples/rekor_interop.py`). The SD-JWT digest is cross-checked against
   the `sd-jwt-python` reference (dev extra).
4. **The mutation gate (5 min).** `make mutation` — the tests must KILL deliberately broken
   implementations, not merely be green (anti-Goodhart). The operator list lives in
   `scripts/mutation_check.py`; one documented-equivalent survivor is expected and asserted.
5. **The per-sample audit (5 min).** `make persample-demo` — a producer signs a samples root into
   a receipt, an auditor challenges random indices with a fresh nonce, openings verify, a swap
   fails. This is the anti-cherry-picking mechanism; try to forge an opening.
6. **Read the honest limits (5 min).** `THREAT_MODEL.md` and the README "what a receipt proves /
   does not prove". A receipt attests authorship + integrity, never that the number is true, the
   issuer honest, or the eval well-designed.

## Where the bodies are buried (invitations to attack)

- **Issuer-declared assurance.** `assurance_level` is what the issuer *says*, signed but not
  independently verified. A dishonest issuer can self-declare `reproduced` — the signature binds
  who claimed it, not that it is true. Is that boundary stated clearly enough everywhere?
- **Adapter timestamps.** Some adapters take the timestamp from the caller, not the eval log — a
  self-attesting issuer could backdate. (Tracked; see the provenance table.)
- **Self-challenge grinding.** `audit-challenge` without a fresh nonce is grindable by re-salting;
  the CLI warns, and the bound is documented — confirm the warning and the math.
- **Emit-side "tree" is issuer-local.** A single-bundle Merkle inclusion adds little beyond the
  signature; its value is real for witnessed checkpoints and the per-sample tree. Overstated anywhere?
- **Status-list issuer key.** A status snapshot signed by the same key as the receipt carries no
  independent revocation assurance — the docs say the status issuer SHOULD be a distinct anchor.
- **Trust anchors are supplied out of band.** The bundle issuer key is in-band and self-asserting;
  a relying party MUST pin it. SD-JWT/status/log/witness keys come from the verifier's policy.

## Reporting

Security issues: see `SECURITY.md` (private advisory). A "break" is any tamper-matrix row that
verifies, any fail-open, or any guarantee that holds only on the emit path and not on verify.
Please include your environment and a reproducing transcript.
