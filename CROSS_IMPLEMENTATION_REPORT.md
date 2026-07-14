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

The PAE byte rule (`DSSEv1 SP LEN(type) SP type SP LEN(body) SP body`) and the RFC 6962 node rule
(`SHA256(0x01 ‖ left ‖ right)`) are implemented from the specs in Rust, not ported from the Python
source.

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
