# Independent reading of draft-watts-agent-evidence-boundary-00

This directory holds an implementation of the verification side of
draft-watts-agent-evidence-boundary-00 ("Evidence-Bounded Authorization for Agentic Systems:
Evidence Qualification Receipts"), derived from the text of that draft alone, together with the
requirement table it was built from, derived test vectors and a run record. It is an
interoperability exercise. It is not part of the proofbundle library, it defines no proofbundle
format, and proofbundle does not adopt the draft's representation as its own. The directory is
named after the object of the draft (EQR), not after a person or a product.

## Input, and what was not used

The only normative input is the plain-text rendering of revision -00:

- source: https://www.ietf.org/archive/id/draft-watts-agent-evidence-boundary-00.txt
- form: txt, 1064 lines, 37609 bytes, dated 12 September 2026
- SHA-256: `e9d47a647af3d1474f3c4fdcc286d6dae3d60a2a378e1f86741e4e95cb81bd5d`

Every line number in this directory refers to that copy. The copy itself is not stored here;
`tools/extract_requirements.py` refuses any other bytes. Revision -01 was not published when this
was written.

Not read and not used: the author's local reference package named in Section 13, and any other
implementation, vector set or correspondence. Where the text allows more than one reading, the
readings considered and the one implemented are written down below and in `requirements_map.json`.

## What the reader does

`eqr00.verify.verify(receipt, context)` runs the eight checks of Section 8 on one receipt,
fail-closed, and keeps four things apart, as Table 1 of Section 11 asks:

1. **receipt validity**: `VALID`, `INVALID` (malformed, refused by strict decoding, signature or
   issuer binding failed, a binding mismatch, outside its validity interval), or `UNVERIFIABLE`
   when the verifier lacks a local input it needs (no proposition, no verification time);
2. **the evaluation** the receipt carries, exposed unchanged and only for a valid receipt
   (`pass`, `fail`, `indeterminate`);
3. **qualification** for a policy that requires PASS (Section 8.1): true only for a valid PASS
   receipt with every requirement satisfied, no blocking contradiction, and local acceptance of the
   issuer for the profile and of every evidence class;
4. **no authorization decision**: the result says so in every case (Sections 3 and 9).

`eqr00.verify.verify_set(receipts, context)` adds Section 10: one receipt id with two contents is a
mutation, a supersession never deletes its predecessor, a cycle of supersession is refused.

Decoding follows the strict decoding standard of 14 October 2026: proofbundle's
`_strict_json.loads_strict` (duplicate keys refused at any depth, bytes after the value refused),
behind a front that also refuses a byte order mark, any encoding other than UTF-8, NaN, the
infinities and integers outside the I-JSON range. Measured on 22 October 2026 at `07b6122c`:
`loads_strict` alone accepts each of those five; see the report of this delivery.

Integrity (Section 6) is JWS compact serialization with EdDSA over Ed25519, keys only from the
verifier's trust configuration. Header keys and key URLs (`jwk`, `jku`, `x5u`, `x5c`) are never used
or fetched, `crit` and `b64` are refused. COSE Sign1, the other example the draft names, is not
implemented. Local JSON values (proposition, profile, action, context) are hashed over their RFC
8785 bytes; non-JSON values over the exact bytes the profile defines.

## What was derived

1. `requirements.json`, `REQUIREMENTS.md`: every sentence that carries a BCP 14 key word in upper
   case, outside the key-word convention of Section 2. 30 sentences; key-word occurrences MUST 13,
   MUST NOT 11, SHOULD 4, MAY 2.
2. `eqr00/`: `wire.py` (strict JSON, base64url, RFC 3339 times, URIs, RFC 8785), `jws.py` (the
   integrity mechanism), `verify.py` (Sections 8, 8.1 and 10).
3. `vectors/eqr00_vectors.json`: 69 vectors (13 positive, 56 negative) over 74 receipts, 68 of them
   signed (JWS with EdDSA under test keys derived from fixed labels; only public keys appear in the
   file) and 6 unprotected ones for the intra-domain case and the decoding refusals.
   `vectors/build.py` writes them; `vectors/generate_vectors.py --check` confirms the committed file
   equals a fresh generation.
4. `tests/`: the vectors and their bookkeeping, the strict decoding tests (a duplicated member in
   the signed payload, the header and an unprotected receipt, each with a control on valid bytes,
   and a meta test showing that a lax decoder would pass the duplicate), the re-extraction of the
   requirement table, and a check that the package imports no network module (Section 15).
5. `run_record.json`, `RUN_RECORD.md`.

## What was found

Per requirement sentence: agreement 20, contradiction 0, ambiguity 5, not implemented 5.

| id | finding |
|---|---|
| S5.1-4 | A receipt whose evaluation members contradict each other: invalid, or valid and non-qualifying? |
| S5.1-5 | How a verifier learns that a profile's required-condition set is empty. |
| S8-1 | Which members an EQR must carry and in which form; only the example names them. |
| S10-3 | Whether a receipt superseded by a valid successor can still satisfy a PASS requirement. |
| S15-2 | Whether an evidence descriptor past its fresh_until keeps a receipt from qualifying. |

Further open points without a requirement sentence of their own (Table 1 has no row for an expired
receipt; the type of blocking_contradictions; a nonce without an expected value; null for optional
members; the lower-case status against upper-case prose) are in the delivery's
`OFFENE_PUNKTE_draft-watts-agent-evidence-boundary-00.md`.

Not implemented, because nothing in a verifier corresponds to them: S4-1 (whether an authorization
system requires an EQR), S5-2, S7-2 and S7-3 (what a profile defines), S16-1 (privacy practice).

## Not done

- No COSE Sign1, no other JWS algorithm.
- No authorization decision, no profile format, no evaluation of evidence: the reader checks a
  receipt, it does not re-evaluate the profile.
- No claim about the correctness of the draft or of any other implementation.

## Running

```
PYTHONPATH=src python -m pytest interop/eqr_00/tests
PYTHONPATH=src python interop/eqr_00/vectors/generate_vectors.py --check
EQR00_DRAFT_TXT=<path to the pinned copy> PYTHONPATH=src python -m pytest interop/eqr_00/tests
```

`PYTHONPATH=src` makes proofbundle's strict JSON helper importable. The test files are named
`check_*.py` and `interop/eqr_00/pytest.ini` collects them, so they run when this directory is named
and stay out of the repository's own test collection.

## Run record

See `RUN_RECORD.md`; its machine-readable form is `run_record.json`.
