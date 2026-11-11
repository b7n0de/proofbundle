# `proofbundle scitt match` (EXPERIMENTAL)

Status: EXPERIMENTAL since 6.6.0. The command line and the result may change without deprecation. No verify path of
this package reaches it, and its result is a statement about bytes, not a trust decision.

`scitt match` reads a reference and a candidate Signed Statement and reports, for one identification scheme you name,
the axes of Section 6 of draft-gruszka-scitt-statement-identification-03. With it you can recompute the 14 cases of
that draft yourself, from the files in `interop/scitt-statement-identification-03/cases`.

```
proofbundle scitt match CANDIDATE --reference REFERENCE --scheme ToBeSigned --alg -16 \
    --external-aad AAD [--detached-payload PAYLOAD] [--pub B64] [--json]
```

`CANDIDATE` is a COSE_Sign1, bare or with tag 18, and `REFERENCE` the CBOR array `[alg, scheme, digest]`, both as
binary CBOR files. `AAD` and `PAYLOAD` are files of raw bytes; a file of 0 bytes is a supplied empty value.

## Schemes

You name the scheme and its hash function. The reference never chooses them, and there is no fallback to another
scheme: under `ToBeSigned` a reference that names `WholeBytes` is not usable (case C14).

- **ToBeSigned**, Section 5.1 of the draft: the digest of the deterministic encoding of
  `["Signature1", body_protected, external_aad, payload]`. `body_protected` is the protected header byte string as
  received. A nil payload is replaced by `--detached-payload`; an embedded payload is used even when a detached one is
  given (case C1). Without `--external-aad`, or with a nil payload and no `--detached-payload`, there is no ToBeSigned
  and the match is INDETERMINATE, never a success.
- **WholeBytes**, named by case C14 of the draft and defined by this command as a local experimental scheme: the digest
  of the candidate bytes exactly as given, tag and signature included, nothing removed or re-encoded. It needs neither
  `--external-aad` nor a detached payload. A candidate that fails the read check below is no statement under this
  scheme either.

`--alg` takes a COSE algorithm number of a hash function with a fixed output length (RFC 9054): -16 SHA-256, -43
SHA-384, -44 SHA-512, -17 SHA-512/256, -15 SHA-256/64, -18 SHAKE128, -45 SHAKE256 and -14 SHA-1.

## Result

| field | meaning |
|---|---|
| `ref_usable` | the reference is one array `[alg, scheme, digest]`, alg an integer naming one of the hash functions above, scheme a text string, digest a byte string of that function's output length, and its alg and scheme equal the ones you named |
| `match` | MATCH or NO_MATCH when the comparison is made, INDETERMINATE when the reference is not usable or a needed input is not supplied |
| `is_scitt` | the candidate passes the read check below and carries tag 18; a structural check, not conformance to the SCITT envelope profile |
| `sig_valid` | always `null`, with `sig_valid_reason`: see Signature below |
| `signature` | Ed25519 over the ToBeSigned under `--pub`, as proofbundle checks it, decided in this order once the candidate passes the read check: `null` without `--pub`; `false` for a signature that is not 64 bytes, with or without a ToBeSigned; `null` for a 64-byte signature when there is no ToBeSigned; otherwise the library's result |
| `digest` | the digest of the scheme's bytes, hex, or `null` |
| `reasons` | why an axis is what it is |

**The read check** of Section 6: an array of exactly four elements, a protected header byte string that is empty or
encodes one map, an unprotected header map, a payload byte string or nil, and a signature byte string; the candidate
and its protected header each one valid CBOR data item under RFC 8949 Section 5.3.1. Heads that are not the shortest,
indefinite lengths and tags are accepted, as the section says; duplicate map keys and text that is not valid UTF-8 are
not. A candidate that fails it gives `is_scitt` false and NO_MATCH under a usable reference, INDETERMINATE under one
that is not.

## Exit codes

- `0` MATCH, and nothing else: a MATCH may come with a signature that does not verify or without tag 18 (cases C6,
  C9 and C11).
- `1` NO_MATCH.
- `2` an input or option that cannot be read, or no verdict (below).
- `3` INDETERMINATE.

## No verdict

The candidate and the reference are read by proofbundle's strict CBOR reader (`_strict_cbor`). It does not represent
some valid input: a map key that is an array, a map, a tag or a NaN, and two keys that are distinct data items but one
Python dict key, such as 1 and true, 0 and false, or 0 and 0.0 (RFC 8949 Section 5.6.1 keeps them apart). It also stops
at its budget: 8 MiB of input, 64 levels of nesting (a chunk of an indefinite string counts one level below its
string), and 200,000 array elements, map pairs and string chunks. For such input the command gives no verdict and
exits 2. It does not report a candidate it could not read as "not a statement". The checker of the interop folder reads
deeper (200 levels) and up to 1 MiB, and it represents those keys.

## Signature

Section 6 defines `sig_valid` by four rules, and rule 2 asks that A and R have order L. proofbundle checks Ed25519
through `cryptography` under the profile of SPEC.md section 4a, which accepts small-order and mixed-order components
and performs no order check, and refuses a malformed, non-canonical or small-order key under section 4b. This command
therefore does not report `sig_valid`; `signature` carries the result under that profile. On the 14 cases of the draft
and their variants, `signature` equals the draft's `sig_valid`. Two kinds of input are known where they differ, and
`tests/test_scitt_match_reader.py` keeps both: a signature whose R is the neutral point, and a key of mixed order, each
with a signature its key holder made. Under Section 6 both are `false`; `signature` is `true`.

## What a match is not

A MATCH says that the digest of the scheme's bytes equals the reference. It is not a signature check, not a judgement
on the issuer, and not evidence of registration with a Transparency Service (Section 7 of the draft).
