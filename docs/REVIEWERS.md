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
