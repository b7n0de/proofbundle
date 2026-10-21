# ADR 0010: A structured trust anchor per key, and a signing principal on the build machine

- **Status:** draft, 2026-10-21. Written for the scope of 6.4.0, where B2 and B3 are named as open. It
  changes no code and no anchor file; every step below that touches an anchor is an owner commit.
- **Deciders:** proofbundle maintainer (b7n0de)
- **Builds on:** ADR 0008 (the pre-tag audit record as a signed attestation), the line format of
  `audit_artifacts/readiness_trusted_pubkeys.txt` (2026-09-06), and the register rows B2 and B3 of
  `docs/release_scope/6.3.0.md`.

## Context, measured on main 56eb5a6f

- Two anchor files, one key. `audit_artifacts/pre_tag_trusted_pubkeys.txt` and
  `audit_artifacts/readiness_trusted_pubkeys.txt` both carry `iJipntJA8N//h+ln9CgLzeC9n/M5OdCZNeBhbfagom8=`.
  The readiness file says so itself: the scopes are separated by files and by a comment, not by
  principals.
- Two formats. The readiness anchor has the line `<key> role=<role> not_after=<YYYY-MM-DD>`, both
  fields mandatory, and `scripts/audit_candidate_matrix.py` checks the role against the artifact's
  `signer_role` and the date against `produced_at` and against the day the gate runs. The pre-tag
  anchor is a list of bare keys. A search on main finds `role=` and `not_after` in none of
  `scripts/pre_tag_receipt_lib.py`, `scripts/pre_tag_audit_gate.py` and
  `scripts/verify_pre_tag_receipt.py`, so the pre-tag path checks neither.
- One holder. The private half is held on the maintainer's machine, never on the build host; the
  build host verifies. Every signature a release needs, routine evidence included, waits for the
  maintainer.
- The limit `scripts/verify_pre_tag_receipt.py` prints with every verdict: the anchor is a key in
  the same repository, with no authority from outside.

## Decision (proposed)

### B3: one anchor format, read by one reader, on every path

1. Every anchor file uses one line per key:
   `<base64 raw 32-byte Ed25519 key> kid=<id> role=<role> not_before=<date> not_after=<date> policy=<kinds>`.
   `policy` lists the artifact kinds the key may sign, from a closed list (`pre_tag_receipt`,
   `findings_register`, `readiness_artifact`, `measurement_record`).
2. One reader in the package parses every anchor file. A line with a field missing, an unknown field,
   a field twice, or a date that does not parse is discarded, never read as a key without
   restrictions; a file left with no key fails closed, as both files do today.
3. Every gate that admits a signature checks four things against the anchor line of the signing key:
   the key, the role the artifact names, the validity window at the artifact's time and at the day the
   gate runs, and that the artifact's kind is in `policy`. The pre-tag path gains the checks the
   readiness path already has.
4. Rotation adds the new key in its own commit before the candidate, as the readiness anchor already
   requires (`_anchor_last_touched_at_head`), and closes the old one with `not_after`. Two keys may
   overlap in time; they never share a role and a kind.

### B2: a second principal for routine evidence, on the build machine

1. Routine release evidence (the readiness artifacts, measurement records) is signed by a key of its
   own, role `build-evidence`, policy `readiness_artifact measurement_record`.
2. That key is held by a principal on the build machine that the agent sessions cannot act as: a
   separate operating-system user without a login shell, or a PKCS#11 token. The sessions hand it the
   bytes to sign; they never read the key.
3. The maintainer's key keeps role `release` with policy `pre_tag_receipt findings_register`. A
   `build-evidence` key cannot sign a pre-tag receipt, because its policy does not name the kind.

### Pull request 391 as a building block

Pull request 391 adds `proofbundle.signer`: a `Signer` interface with a key file, a key held
elsewhere (`ExternalSigner`) and an optional PKCS#11 signer (`Pkcs11Signer`, RFC 7512 URI, the PIN
from a prompt or a named environment variable, Ed25519 only, every returned signature checked
against the public key before use). It fits B2 as the interface between the sessions and the
principal. What it does not carry: the release scripts (`scripts/sign_readiness_artifact.py`, the
pre-tag receipt) do not take a `Signer` yet, and it knows nothing of roles or policy. At the
measurement of 2026-10-21 10:5xZ its required check `all-checks-passed` was FAILURE with `test (3.10)`
red, cause not measured, and it conflicts with main in four files.

## Alternatives

- **Keep one key, as today.** Simplest; every routine signature waits for the maintainer, and the
  separation of scopes stays a comment.
- **Keyless signing for routine evidence** (Sigstore, as ADR 0008 proposes for the pre-tag record).
  It adds an online dependency and a second trust model to evidence that is read offline.
- **A key file the sessions can read.** Rejected: the sessions are the party whose evidence is
  checked, so a key they hold attests themselves.

## Consequences

- The pre-tag anchor is rewritten into the new format in an owner commit; until then the pre-tag
  path keeps its present reading.
- Receipts and artifacts signed under the old reading stay verifiable by the old reader; the new
  reader applies from the release that ships it.
- Tests: the reader holds each malformed line form as discarded (property tests over the fields), and
  each gate refuses a signature whose role, window or kind does not match, with an unchanged control.

## What this ADR does not decide

Which operating-system mechanism or token holds the B2 key, who may rotate it, whether a trusted
timestamp (RFC 3161) replaces the second date check, and whether 6.4.0 waits for any of this. Those
are the maintainer's.
