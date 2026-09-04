# SCITT CCF data-hash — an independent recomputation, and a third framing axis

This directory holds the reader and the scripts used to recompute the two SCITT CCF
`data-hash` vectors published on the `scitt@ietf.org` list, and to derive one further
encoding of the same Signed Statement.

## What this is

An independent check, on a third platform, in a second language. The two vectors were
published by Nicholas Vokes (mail of 2026-09-03, pinned at commit
`db33ff3ff8ed439b3ebd97e5ef96facd7f49b65a`); Emek Küçükkaya recomputed them on node,
Henri Birecki on aarch64. This is Linux x86_64 with CPython 3.11.15.

The reader (`cbor_min.py`) is written here from RFC 8949 and handles **definite and
indefinite** lengths. It is deliberately not a COSE library: recomputing a vector with the
same library that produced it checks nothing about the library, and the third axis below is
not measurable at all with a reader that only accepts definite-length CBOR.

## What it is not

Not a Transparency Service. Not a real Receipt. Not independently derived vectors — the
seed, the bytes and the signature are Nicholas'; **no keys were generated here**, the
signature is taken over, and that it verifies across both encodings *is* the finding. Not a
statement about what COSE implementations in the wild produce; only the two named below were
measured.

## What was measured

All four published states reproduce, `Sig_structure` is 109 bytes throughout, and the
signature regenerates from the published seed byte for byte.

| case | | size | outcome |
|---|---|---|---|
| V1 / A | as registered | 165 B | digest matches, signature reproduced |
| V1 / B | carrying receipt | 203 B | digest matches, signature reproduced |
| V2 / A | tagged | 165 B | digest matches, signature reproduced |
| V2 / C | untagged | 164 B | digest matches, signature reproduced |

The tag vector ships no bytes, only sizes, digests and the minter. `A_tagged` and
`C_untagged` are therefore **derived** from the vector 1 bytes and held against its digests,
which checks the "byte-identical to A" claim instead of restating it.

### The third axis: outer array framing

Same four elements, same tag 18, outer array indefinite instead of definite:

| | encoding | size | sha256 |
|---|---|---|---|
| A | `0x84` definite | 165 B | `8595e4a4c8b93e7b1b7b798dc302a2b7d2890021f7eff372d79b32f78867e4ac` |
| D | `0x9f` … `0xff` | 166 B | `79c6215d691cd72ce47feb4e5b26eb047e1880a64c7ef6fbd51f6a0cba092a11` |

The same signature verifies over both: `Sig_structure` per RFC 9052 §4.4 does not cover the
outer array. Two byte positions change (head `0x84` → `0x9f`, tail `0xff` appended) for a net
size difference of one.

It is named `D_indefinite_array`, not "C" — the published tag vector already carries a
`C_untagged`, and two different things under one letter on a mailing list is a confusion
nobody untangles later.

### Why the axis is quieter than the tag axis

Nothing rejects it. Measured with `cbor2` 5.9.0 and `pycose` 1.1.0 in a throwaway venv:

    reader             A definite     D indefinite
    cbor2 5.9.0        accepted       accepted
    pycose 1.1.0       accepted       accepted

    A -> cbor2.dumps()             165 B  8595e4a4…  == A
    A -> cbor2.dumps(canonical)    165 B  8595e4a4…  == A
    D -> cbor2.dumps()             165 B  8595e4a4…  == A   <-- D disappears
    D -> cbor2.dumps(canonical)    165 B  8595e4a4…  == A   <-- D disappears
    D -> pycose encode()           165 B  8595e4a4…  == A   <-- D disappears

So a party that registers D and a party that re-serialises get **different data-hashes**, and
nothing signals it: the signature verifies over both, both readers accept both, and every
re-serialisation silently returns the A bytes (RFC 8949 §4.2 requires definite-length
encoding). A rejection would have been a signal; silent acceptance followed by silent
normalisation is the worse case.

## The upstream vectors are referenced, not vendored

`data-hash-vector.json`, `data-hash-tag-vector.json` and `mint_tag_vector.py` are Nicholas'
artefacts and are **not** copied into this repository. They were fetched from the pinned
commit and checked byte for byte against the sizes and digests stated on the list:

    data-hash-vector.json       3243 B  e137d34fb25246c5f9e09fe8a293ac19…  matches
    data-hash-tag-vector.json   2415 B  d8a03d6aa7398c24bf8f902cd2253525…  matches

## Reproducing

    python3 fetch_upstream_vectors.py   # fetches both vectors at the pinned commit and
                                        # verifies size and sha256; fail-closed on mismatch
    python3 nachrechnen.py              # recomputes all four published states
    python3 mint_indefinite.py          # derives D, verifies the signature over both encodings

The first step is not optional: the other two read the upstream vectors from this directory,
and those are fetched rather than vendored (see below). Only the standard library plus
`cryptography` for Ed25519. `nachrechnung.json` and `vektor_d.json` carry the recorded
results of a run on 2026-09-04.

## A control that failed first, and why the versions are named

The first run had `pycose` 1.1.0 against `cbor2` 6.1.4 and rejected **both** A and D. As a
finding that would have read "pycose does not accept the indefinite form" — wrong in two
directions. The control caught it: pycose could not read back **its own** encoded message
(79 B, correct `0xd2` tag head, then `TypeError`). A red control proves nothing. Installing
`cwt` pulled `cbor2` back to 5.9.0, the control went green, and only then do the numbers
above hold. That is why every version is named.

## Limitations

Whether COSE implementations beyond these two accept the indefinite form is **not measured**.
`cwt` 3.3.0 was installed but not run against the two encodings.

---

Prepared with AI agent involvement, reviewed and submitted under human oversight.
