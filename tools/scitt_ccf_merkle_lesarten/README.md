# SCITT CCF receipts — two literal readings of the same document, two Merkle roots

This directory holds a small measurement of
`draft-ietf-scitt-receipts-ccf-profile-04`: two readings of the draft that both
follow its text word for word, and the roots each of them computes from the same
input.

The question was raised by Henri Sirkkavaara as finding 4 during Last Call review
of the draft. What is measured here is not an opinion about the document — it is
what two literal readings **compute from one and the same input**.

## The two readings

**Section 2.1** defines the tree:

    MTH({})      = HASH()
    MTH({d[0]})  = HASH(d[0])
    MTH(D_n)     = HASH(MTH(D[0:k]) || MTH(D[k:n])),  k the largest power of two < n

There, `d[i]` is a *"serialized transaction (as byte string)"*. Section 2.1 does not
say **how** a transaction is serialized; **section 2.2** supplies the CDDL:

    ccf-leaf = [ internal-transaction-hash: bstr .size 32
               , internal-evidence:         tstr .size (1..1024)
               , data-hash:                 bstr .size 32 ]

So the natural reading is `leaf = HASH(CBOR(ccf-leaf))`.

**Section 3.2** defines verification:

    h := HASH( internal-transaction-hash || HASH(internal-evidence) || data-hash )

That is **not** a serialization of the three fields. It is a concatenation of raw
bytes in which the **middle** field is hashed separately first.

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

**On `e3b0c442…` at `n=0`:** that is the sha256 of the empty string, which is
usually a sign of a *failed* measurement. Here it is correct — 2.1 prescribes
`MTH({}) = HASH()` literally. The case is still marked **NOT APPLICABLE**, because
3.2 does not describe an empty tree at all; counting it as "equal" would flatter the
result.

## What the finding is — and what it is not

The difference sits at **exactly one place**: the preimage of the leaf. The node rule
`HASH(left || right)` is identical in both readings, and so is the empty tree. The
divergence propagates from the leaves; it does not arise in several places. Claiming
more than that would overstate it.

**Not measured, with reason:** what a real CCF instance computes. The subject here is
the document, not an implementation. A statement about CCF itself would not be covered
by this measurement.

## No second producer

This repository's own Merkle code (`src/proofbundle/merkle.py`) implements **RFC 6962**
with the prefixes `0x00` at the leaf and `0x01` at the node. The CCF tree has **no**
prefixes. That is a different structure, not the same question — this repository's code
cannot compute a CCF root, and using it here would be wrong rather than economical.

The CBOR serialization, by contrast, is **not** rewritten: `zwei_lesarten.py` loads
`schreibe()` from `tools/scitt_ccf_datahash_vector/cbor_min.py`. If that file is not in
the working tree, the script reads it from a pinned commit via `git show` — deliberately
not as a copy, because a copy drifts and a ref does not.

## The catch-proof, and how it refuted its own announcement

`fangnachweis.py` plants six defects in `zwei_lesarten.py` and measures whether they
show up. Each mutation carries a planting assertion (`assert new != original`): without
it, `str.replace()` reports success silently when the pattern does not match.

**First run: 4 announced as counting, 3 measured.** One defect — removing the inner
`HASH(internal-evidence)` of reading 3.2 — slipped through. The reason is sharper than
the defect itself: the measured surface was only the **number** of divergences, and
three of the six defects leave that number at 5.

**The class:** a checker that holds two readings **against each other** is blind to any
error that hits **both equally**. That follows from its construction, not from a lack of
care, and looking harder does not fix it.

**The hardening is therefore not a stricter rule but a second, independent quantity:**
the root values themselves belong to the measured surface. They bind the result to fixed
bytes instead of to a comparison. Announcement before the second run: **6 of 6** —
measured **6 of 6**. `RUNS.txt` carries the full protocol.

**What remains NOT MEASURABLE, with reason:** whether these roots are the *correct*
ones. The draft states no test vectors, and no foreign implementation is available here.
The proof shows that the checker reacts to changes — not that it reads the document
correctly.

## Running it

    python3 zwei_lesarten.py
    python3 fangnachweis.py

Standard library only. The input data is generated deterministically from visible
preimages (`itx-<i>`, `ce-<i>`, `dh-<i>`) so that every value can be recomputed by hand.
The countercheck runs **before** the result and aborts if it fails: without it, a uniform
"diverges" proves nothing, since it could equally mean the comparison always reports
unequal.

## Provenance of the document

| | |
|---|---|
| document | `draft-ietf-scitt-receipts-ccf-profile-04`, 2026-06-24 |
| retrieved | 2026-09-13 from `https://www.ietf.org/archive/id/draft-ietf-scitt-receipts-ccf-profile-04.txt` |
| size | 21295 B, sha256 `80ba0dd88f5109598952bff4ef0d8f0d83936345abd951f0e330924b149b847a` |
| state | *Waiting for AD Go-Ahead* as of 2026-09-12; Last Call closed, no -05 |

## Files

| file | |
|---|---|
| `zwei_lesarten.py` | the two readings and the shared tree rule; prints both roots per `n` |
| `fangnachweis.py` | plants six defects and measures which of them the checker reports |
| `RUNS.txt` | the output of both, as run |
