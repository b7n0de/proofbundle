# SCITT CCF receipts — two literal readings, two Merkle roots

A measurement of `draft-ietf-scitt-receipts-ccf-profile-04`: two readings that both follow the
document word for word, and the roots each computes from one and the same input.

## The two readings

**Section 2.1** defines the tree:

    MTH({})      = HASH()
    MTH({d[0]})  = HASH(d[0])
    MTH(D_n)     = HASH(MTH(D[0:k]) || MTH(D[k:n])),  k the largest power of two < n

There, `d[i]` is a *"serialized transaction (as byte string)"*. Section 2.1 does not say **how**
a transaction is serialized. **Section 2.2** supplies the CDDL:

    ccf-leaf = [ internal-transaction-hash: bstr .size 32
               , internal-evidence:         tstr .size (1..1024)
               , data-hash:                 bstr .size 32 ]

So the reading that follows from 2.1 together with 2.2 is `leaf = HASH(CBOR(ccf-leaf))`.

**Section 3.2** defines verification:

    h := HASH( internal-transaction-hash || HASH(internal-evidence) || data-hash )

That is not a serialization of the three fields. It is a concatenation of raw bytes in which the
middle field is hashed separately first.

## What was measured

    COUNTERCHECK: PASSED -- both the equal case and the unequal case are correct

     n  verdict
     0  equal (3.2 has no empty tree -- NOT APPLICABLE)
     1  DIVERGES
     2  DIVERGES
     3  DIVERGES
     4  DIVERGES
     5  DIVERGES

    RESULT: 5 of 6 cases diverge (n=0 through n=5).

Both roots per `n` are in `RUNS.txt`.

**`n=0` is not applicable.** `MTH({})` is `HASH()` for *any* leaf rule, so neither leaf function
is called and the case cannot distinguish the readings. Section 3.2 describes no empty tree at
all. Counted over the applicable cases it is 5 of 5; the summary line says 5 of 6 because the
tool counts every `n` it ran.

**`e3b0c442…` at `n=0`** is the sha256 of the empty string. That is usually a sign of a failed
measurement; here it is what 2.1 prescribes literally.

The difference sits in the leaf preimage and nowhere else in the tree: the node rule
`HASH(left || right)` is identical in both readings. Within the leaf there are two independently
sufficient differences — CBOR framing, and the inner hash of the evidence field. Measured
preimage sizes for transaction 0: reading 2.1 = 74 B, reading 3.2 = 96 B, and a hybrid with raw
concatenation but without the inner hash = 68 B, which still differs from reading 2.1.

## What is not measured

- What a real CCF implementation computes. The subject is the document, not an implementation.
- Whether these roots are the *correct* ones. The draft states no test vectors, and no foreign
  implementation was available here. `fangnachweis.py` shows that the checker reacts to changes;
  it does not show that the document is read correctly.
- Whether the quoted passages match the published draft byte for byte. The source is pinned by
  size and digest below, but no diff against the archive was run here.

## Running it

    python3 zwei_lesarten.py
    python3 fangnachweis.py

Standard library only. Input data is generated deterministically from visible preimages
(`itx-<i>`, `ce-<i>`, `dh-<i>`), so every value can be recomputed by hand. The countercheck runs
before the result and aborts if it fails; it exercises each reading separately and prints a trace
derived from the roots it actually computed, so that switching it off cannot go unnoticed.

`zwei_lesarten.py` does not reimplement CBOR: it loads `schreibe()` from
`tools/scitt_ccf_datahash_vector/cbor_min.py`, or reads that file from a pinned commit if it is
not in the working tree.

## Source

| | |
|---|---|
| document | `draft-ietf-scitt-receipts-ccf-profile-04`, 2026-06-24 |
| retrieved | 2026-09-13 from `https://www.ietf.org/archive/id/draft-ietf-scitt-receipts-ccf-profile-04.txt` |
| size | 21295 B, sha256 `80ba0dd88f5109598952bff4ef0d8f0d83936345abd951f0e330924b149b847a` |
