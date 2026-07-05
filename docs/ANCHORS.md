# External time anchors (`proofbundle.anchors`)

Status: **EXPERIMENTAL**, the `[anchors]` extra. API and wire format may change. This layer is optional:
the base install pulls only `cryptography`, and a receipt with no anchors verifies exactly as before.

A receipt's own Ed25519 signature and RFC 6962 Merkle structure prove *who signed these exact bytes* and
*that nothing changed*. What they cannot prove on their own is *when* — a self-emitted timestamp is
producer-clock testimony. An **anchor** adds external evidence of time, from a party the producer does
not control.

## Two targets, never mixed

| target | claim | why |
|---|---|---|
| `preRegistration` | the commitment existed **before** the run | backdating protection (the point raised in in-toto/attestation#565) |
| `receipt` | the receipt existed **from** time T | publication proof |

An anchor's `canonicalRoot` is the canonical root of its **own** target — for `receipt` the RFC 8785
(JCS) sha256 of the receipt bundle, for `preRegistration` the sha256 of the raw protocol bytes (the
receipt's `prereg_sha256`). A `preRegistration` anchor can therefore never validate a `receipt` target,
and vice versa: the roots differ, and a mismatch is a FAIL.

## Schema

Each `anchors[]` entry:

```jsonc
{
  "type": "rfc3161-tsa" | "opentimestamps" | "<extension>/vN",
  "target": "receipt" | "preRegistration",
  "canonicalRoot": "<base64 of the target's canonical root>",
  "proof": "<base64 of the type-specific proof>",
  "anchoredAt": "<RFC 3339 Z, INFORMATIVE only>",
  "frozen": { /* OPTIONAL type-specific material bundled at emit time, e.g. the TSA cert chain */ }
}
```

`anchoredAt` is informative — the trusted time comes from the proof, never from this field.

## Verify contract (fail-closed)

- **Missing / empty `anchors` → SKIP**, not FAIL. This matches in-toto's Monotonic Principle: deny only
  when an attestation is present and wrong, not when it is absent.
- **Present → fail-closed.** A root mismatch, an unknown `type`, or a broken proof is a **FAIL**, never
  a silent pass. A verifier that raises is treated as FAIL.
- `--require-anchor <type|any>` turns "no verifying anchor (of that type)" into a FAIL.
- Anchoring **writes a new file**. A network error while stamping never corrupts the local receipt.

## Built-in types

### `rfc3161-tsa`

An RFC 3161 timestamp token from a Time-Stamping Authority. Verification is **offline** (Trail of Bits
`rfc3161-client`, `VerifierBuilder`) against the TSA's root certificate. **Freeze the chain:** the TSA
certificate + chain are bundled in the anchor's `frozen` field, because a TSA can rotate its certificate
(FreeTSA rotated its TSA certificate in March 2026) — after a rotation an old token is only offline
re-verifiable against the chain that was frozen at emit time, not the TSA's current chain. Suggested
TSAs: the Sigstore TSA (`https://timestamp.sigstore.dev/api/v1/timestamp`) and FreeTSA as a second,
independent anchor.

### `opentimestamps`

An OpenTimestamps proof anchored in the Bitcoin blockchain. Honest lifecycle: a fresh stamp goes to
public calendars and is initially **PENDING** (a pending proof is a WARN / its own status, never a
full-strength anchor). `ots upgrade` embeds the Bitcoin block-header path; only then is the proof
self-contained. Verifying an upgraded proof needs no calendar, but — per the documented client path — a
**local (pruned) Bitcoin node** for the block header. There is no documented "header-file instead of a
node" mode, and we do not claim one. Doc wording to reuse verbatim: *"offline verifiable given a local
(pruned) Bitcoin node; no calendar or account needed for verification."*

## Extension mechanism — bring your own anchor type

A third party can ship an anchor `type` without changing proofbundle:

```python
from proofbundle.anchors import register_anchor_type

def verify_my_anchor(proof: bytes, canonical_root: bytes, *, frozen: dict, now):
    # Return {"ok": bool, "detail": str}. MUST be fail-closed: return ok=False on any doubt,
    # never raise for an ordinary bad proof. `canonical_root` is already matched to the target;
    # your job is to prove `proof` anchors exactly those bytes at/for a time.
    ...
    return {"ok": True, "detail": "verified against <authority>"}

register_anchor_type("my-org/timebeacon/v1", verify_my_anchor)
```

The contract: a namespaced `type` (`<org>/<name>/vN`), a fail-closed verify callable, and the
canonicalRoot ↔ target binding enforced by the layer for you. Third-party types are welcome as
extensions with credit — see in-toto/attestation#565 and the reference-implementation tracking issue.
