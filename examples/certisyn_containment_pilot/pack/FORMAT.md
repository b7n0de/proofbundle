# Certisyn containment public record: format v1

Scope of this document: the record and seal format, and the verification procedure. Method internals are outside it.

## 1. Files

A sealed result is two JSON files.

- record: the public record, schema `certisyn/containment-public/v1`
- seal: the signature over the record digest

An optional third file, the input series, lets a verifier recompute `input_digest`.

## 2. Record fields

| Field | Type | Meaning |
|---|---|---|
| schema | string | `certisyn/containment-public/v1` |
| kind | string | `channel` |
| subject_ref | string | Free text naming the pair of domains under test |
| verdict | string | `CHANNEL_DETECTED` or `NO_DEPENDENCE_DETECTED` |
| input_digest | hex | SHA-256 of the canonical form of the input file |
| result | object | n, interval_ms, statement, detection_floor_bits_per_second, leakage_lower_bound_bits_per_second, undetected_budget |
| withheld | object | A SHA-256 commitment to the internal result, and a disclosure line |
| result_digest | hex | SHA-256 of the canonical form of every other member of the record |

A negative verdict covers its pair, its window and its telemetry. It states what was tested and the floor below which nothing could be seen.

## 3. Canonical form

Canonical form is JSON with no whitespace, object members sorted by UTF-16 code unit of the member name, arrays in order, strings and numbers serialised as ECMAScript `JSON.stringify` serialises them. For this data it matches RFC 8785 (JCS). Numbers are IEEE 754 doubles. A verifier in another language needs the ECMAScript shortest round-trip number form, which JCS also specifies.

## 4. Digests

- `input_digest` = SHA-256(canonical(input file)), lowercase hex
- `result_digest` = SHA-256(canonical(record without `result_digest`)), lowercase hex

## 5. The seal

| Field | Value |
|---|---|
| algorithm | `ed25519` |
| domain | `certisyn/containment-seal/v1` |
| signed_message | `certisyn/containment-seal/v1` LF `certisyn/containment-public/v1` LF result_digest |
| signed_message_sha256 | SHA-256 of signed_message |
| signature_b64 | Ed25519 signature over the UTF-8 bytes of signed_message |
| key_id, ed25519_pub_b64 | informational only |

LF is the single byte 0x0A. The domain prefix keeps a containment seal from verifying as any other Certisyn seal.

## 6. Verification procedure

1. Parse the record and the seal with a parser that refuses a repeated member name. Names are compared after unescaping, so `verdict` and `verdict` are the same name.
2. Check `schema`.
3. Recompute `result_digest` from the record body. They must be equal.
4. If the input file is supplied, recompute `input_digest`.
5. Check the seal domain and algorithm.
6. Rebuild signed_message from the record digest. It must equal the seal's signed_message, and its SHA-256 must equal signed_message_sha256.
7. Verify the signature under the pinned public key from `KEY.json`. The key printed inside a seal is never used.

Any failed step is a refusal. The verifier reports every failed step it reaches.

## 7. Limits

- Integrity only. A verified pair proves the record is the record that was sealed, by the holder of the pinned key. Whether the result is right is a separate question that a reproducible example, and later an audit, address.
- The pilot data is synthetic.
- The pilot key is pilot-only and signs no Certisyn production seal.
