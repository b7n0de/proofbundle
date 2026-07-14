# Cross-Implementation Report (3.2.0 O8)

An independent, read-only **second verifier** written in Rust (`tools/pb_verify_rs`) that agrees
with the Python implementation on the core verifier properties. It shares **no** canonicalization
or parser code with Python: it uses the Rust `serde_jcs` crate for RFC 8785 (a different
implementation than Python's `rfc8785` package), `ed25519-dalek` for Ed25519 (RFC 8032), `sha2`
for SHA-256, and a hand-rolled strict-JSON deserializer for duplicate-key rejection. No network I/O.

## How to reproduce

```bash
cd tools/pb_verify_rs && cargo build          # builds the independent Rust verifier
cd ../.. && python tools/pb_verify_rs/crosscheck.py   # drives it against Python-produced fixtures
# exit 0 iff every property below AGREES between the two implementations
```

## Covered — cross-implementation AGREEMENT proven

Each is checked by `crosscheck.py` against fixtures the Python implementation produces at run time;
a green run means the Rust verifier computed the SAME value / reached the SAME verdict independently.

| Property | Standard | Rust checks | Agreement |
|---|---|---|---|
| `jcs-sha256-v1` content root of a signed statement | RFC 8785 (JCS) + SHA-256 | `content-root` | byte-identical hex vs Python |
| DSSE / Ed25519 signature over the exact PAE bytes | DSSE + RFC 8032 | `verify-dsse` | Rust verifies a Python-signed envelope → OK |
| flipped payload byte (negative vector) | — | `verify-dsse` | Rust → FAIL (exit 1) |
| duplicate JSON key (parser-differential defense, C1) | — | `strict-parse` | Rust → REJECT (exit 1), independent of Python's `_strict_json` |
| RFC 6962 Merkle tree head | RFC 6962 | `merkle-root` | byte-identical hex vs Python |
| native bundle verify exit-code contract (sig + inclusion + root/tree-size) | RFC 6962 / 9162 | `verify-bundle` | same exit code (0/1/2) as the Python CLI, incl. relying-party `--expected-root` / `--expected-tree-size` |

The PAE byte rule (`DSSEv1 SP LEN(type) SP type SP LEN(body) SP body`) and the RFC 6962 node rule
(`SHA256(0x01 ‖ left ‖ right)`) are implemented from the specs in Rust, not ported from the Python
source.

### Reproduces the actual conformance corpus

`crosscheck.py` also runs the Rust verifier against the pinned `conformance/` corpus and reproduces
these cases independently (§7 "Zweitverifier reproduziert den Conformance-Corpus"):

- `decision/crossimpl/canonicalization-root-binding` and `.../confirmed-anchor-lifecycle`: the Rust
  content root of `decision_receipt.json` equals the corpus-pinned `decision_content_root`, and the
  committed `.jcs` bytes hash to that same root (byte-identical RFC 8785 canonicalization).
- `bundle/{valid-minimal, tampered-payload, corrupted-signature, coherent-rewrap-fails-expected-root,
  tree-size-expectation-mismatch, coherent-rewrap-verifies-no-policy, duplicate-json-key}`: the Rust
  `verify-bundle` produces the same exit code (0/1/2) as the Python CLI for each, using the case's own
  `verifyArgs` (`--expected-root` / `--expected-tree-size`).

- `bundle/{sd-jwt-unsigned-unauthenticated, sd-jwt-signed-but-unbound, sd-jwt-forged-issuer-identity}`:
  the SD-JWT issuer-authenticity slice reproduces exit 1 — no issuer key → unauthenticated, a forged
  issuer Ed25519 signature → reject, and a holder-bound (`cnf`) credential fail-closes (its KB-JWT is
  not yet verified, so it is refused rather than passed). `valid-minimal` (a `cnf`-free, issuer-signed
  SD-JWT) stays exit 0.

- `bundle/n1-eval-sdjwt-graft-non-eval`: the eval-root-graft check — an SD-JWT carrying the always-open
  `receipt.root_b64` eval commitment must bind to a proofbundle eval-claim payload (its
  passed/threshold/comparator/suite/issuer match the signed payload AND its `receipt.root_b64` equals
  the bundle merkle root). Grafted onto a non-eval payload it does not bind → reject (exit 1), matching
  `bundle.py`'s `check_binds_bundle` + `_sd_jwt_carries_eval_root_commitment`.

- `bundle/forged-anchor-own-frozen`: the WP-A1 anchor-trust decision — a bundle's own `frozen` Bitcoin
  block header is producer-controlled and is NEVER trusted, so under `--require-anchor` (with no
  relying-party block header, which the offline corpus never supplies) the anchor requirement is unmet →
  exit 3 (policy). This faithfully reproduces the SECURITY decision (reject own-frozen); the Rust verifier
  does not yet parse the OTS binary proof or verify a real Bitcoin block header — that depth is only needed
  to CONFIRM a genuine relying-party-supplied anchor, which no corpus case exercises (`--bitcoin-header` is
  not an allowed conformance verifyArg).

**All 14 of the 14 corpus cases are reproduced independently** (`crosscheck.py`, exit 0). Research note:
a SOTA review (2026) confirms OpenTimestamps-over-Bitcoin as the strongest trust-minimized long-term
*archival* anchor (permissionless, offline-verifiable, no trusted third party) — correctly used here as
an OPTIONAL layer, not the primary trust — with Sigsum / RFC 3161 / transparency logs as lower-latency
*connected* alternatives.

## Pending — NOT yet covered by the Rust verifier (honest scope)

The full O8 `Mindestumfang` from the 3.2.0 implementation prompt grows from this core. The following
are declared as **not yet reproduced** by the second implementation and remain Python-only for now:

- `decision-receipt/v0.1` full predicate validation (schema + hand-validator parity)
- `action-outcome/v0.1`, `run-ledger/v0.1`, `verification-summary/v0.1` predicate validation
- Trust Pack threshold-of-root signature verify (distinct key-material counting, rotation)
- SD-JWT / SD-JWT VC holder key binding and issuer-signature verify
- Checkpoint signature + witness-quorum trust, atomic root/tree-size trust
- External anchors (OpenTimestamps / RFC 3161) offline resolution

These are the next slices; each will graduate the same way — an independent Rust check plus a
`crosscheck.py` assertion of agreement — and this table will move rows from Pending to Covered.

## No-Overclaim

Cross-implementation agreement attests that two independent implementations compute the same
canonical bytes, content roots, Merkle heads and signature verdicts. It does not attest that the
underlying claims are true, nor does it substitute for the independent security review (O9). The
Rust verifier is read-only and EXPERIMENTAL.
