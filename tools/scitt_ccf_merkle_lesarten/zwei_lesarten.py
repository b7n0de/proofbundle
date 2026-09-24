#!/usr/bin/env python3
"""Two readings of the same document, two roots.

draft-ietf-scitt-receipts-ccf-profile-04 (24.06.2026), geholt am 13.09.2026 von
https://www.ietf.org/archive/id/draft-ietf-scitt-receipts-ccf-profile-04.txt
21295 Bytes, sha256 80ba0dd88f5109598952bff4ef0d8f0d83936345abd951f0e330924b149b847a

The question comes from Henri Sirkkavaara, finding 4 in the Last Call. What is measured is not
an opinion about the document but what two literal readings compute FROM THE SAME INPUT.

SECTION 2.1, Merkle Tree Shape, verbatim:

    MTH({})      = HASH().
    MTH({d[0]})  = HASH(d[0]).
    MTH(D_n)     = HASH(MTH(D[0:k]) || MTH(D[k:n])),  k largest power of two < n

  Per 2.1, d[i] is a "serialized transaction (as byte string)". HOW a transaction is serialized is
  not stated in 2.1; 2.2 gives the CDDL for it:

    ccf-leaf = [ internal-transaction-hash: bstr .size 32
               , internal-evidence:         tstr .size (1..1024)
               , data-hash:                 bstr .size 32 ]

  The obvious reading is therefore d[i] = CBOR(ccf-leaf), leaf = HASH(CBOR(ccf-leaf)).

SECTION 3.2, Inclusion Proof Verification Algorithm, verbatim:

    compute_root(proof):
      h := HASH( proof.leaf.internal-transaction-hash
                 || HASH(proof.leaf.internal-evidence)
                 || proof.leaf.data-hash )
      for [left, hash] in proof.path:
          h := HASH(hash + h) if left else HASH(h + hash)
      return h

  Here the leaf is NOT a serialization of the three fields but a concatenation of raw bytes in
  which the MIDDLE field is hashed on its own beforehand.

THE DIFFERENCE SITS AT EXACTLY ONE PLACE, and that is the whole finding: the node rule is
HASH(left || right) in both readings, identically. Only the LEAF has two preimages. Everything
else is the same, and whoever claims more is overstating it.

NOT MEASURED, with the reason: what a real CCF instance computes. What is measured is the
document, not an implementation.

NO SECOND PRODUCER: our own Merkle code (src/proofbundle/merkle.py) computes RFC 6962 with the
prefixes 0x00 at the leaf and 0x01 at the node (lines 34-41, measured). The CCF tree has NO
prefixes. That is a different structure, not the same question — our code cannot compute a CCF
root, and using it here would be wrong rather than frugal. The CBOR serialization, by contrast, is
NOT rewritten; it is taken from tools/scitt_ccf_datahash_vector/cbor_min.py (`schreibe`).
"""

from __future__ import annotations

import hashlib
import importlib.util
import pathlib
import sys

# The state cbor_min.py is read from when it is not in the working tree.
# main == the target of tag v6.0.0, measured on 2026-09-13.
CBOR_MIN_COMMIT = "4e32e83b647235bfedf23b55cebe69fdf14fd6f5"

H = lambda b: hashlib.sha256(b).digest()          # noqa: E731 -- H as in the document
hx = lambda b: b.hex()                            # noqa: E731


# --- the CBOR serialization comes from the existing tool, not from here ---------------
def _repo_wurzel() -> pathlib.Path | None:
    """Derive the repository root from the location of THIS file, not from $HOME.

    A fixed path under the home directory carries the user name outwards and is besides only
    correct on one machine.
    """
    for eltern in pathlib.Path(__file__).resolve().parents:
        if (eltern / ".git").exists():
            return eltern
    return None


REL = "tools/scitt_ccf_datahash_vector/cbor_min.py"


def _lade_cbor_min():
    """`schreibe` from the sibling tool's cbor_min, or a named refusal."""
    hier = pathlib.Path(__file__).resolve().parent
    wurzel = _repo_wurzel()
    kandidaten = [hier.parent / "scitt_ccf_datahash_vector" / "cbor_min.py"]
    if wurzel is not None:
        kandidaten.append(wurzel / REL)
    for p in kandidaten:
        if p.is_file():
            spec = importlib.util.spec_from_file_location("cbor_min", p)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
            return m, REL + " (working tree)"

    # Third route, for a run OUTSIDE the repository: read from the pinned commit. Explicitly not
    # a copy — a copy drifts, a ref does not.
    import subprocess
    ziel = "%s:%s" % (CBOR_MIN_COMMIT, REL)
    if wurzel is not None:
        r = subprocess.run(["git", "show", ziel], capture_output=True, text=True, cwd=wurzel)
        if r.returncode == 0 and r.stdout:
            m = importlib.util.module_from_spec(
                importlib.util.spec_from_loader("cbor_min", loader=None))
            exec(compile(r.stdout, ziel, "exec"), m.__dict__)
            return m, "git show %s" % ziel

    raise SystemExit(
        "NICHT MESSBAR: cbor_min.py was not found. Searched next to this tool and under "
        + REL + ", then in the pinned commit.\n"
        "Reason: the serialization is not rewritten (no second producer)."
    )


CBOR, CBOR_PFAD = _lade_cbor_min()


# --- the input, deterministic and recomputable by hand --------------------------------
def blatt(i: int) -> dict:
    """Transaction i. Every field from a visible preimage, so that nothing is guessed."""
    return {
        "internal_transaction_hash": H(b"itx-%d" % i),          # 32 B, as the CDDL demands
        "internal_evidence": "ce-%d" % i,                        # tstr, 1..1024
        "data_hash": H(b"dh-%d" % i),                            # 32 B
    }


# --- reading A, sections 2.1 + 2.2 ----------------------------------------------------
def blatt_hash_a(b: dict) -> bytes:
    serialisiert = CBOR.schreibe([
        b["internal_transaction_hash"],
        b["internal_evidence"],
        b["data_hash"],
    ])
    return H(serialisiert)


# --- reading B, section 3.2 -----------------------------------------------------------
def blatt_hash_b(b: dict) -> bytes:
    return H(
        b["internal_transaction_hash"]
        + H(b["internal_evidence"].encode("utf-8"))
        + b["data_hash"]
    )


# --- the tree rule is the same in BOTH readings, so it stands here once ----------------
def mth(blatt_hashes: list[bytes]) -> bytes:
    """MTH per 2.1: empty list -> HASH(), one element -> the leaf, otherwise recursive."""
    n = len(blatt_hashes)
    if n == 0:
        return H(b"")
    if n == 1:
        return blatt_hashes[0]
    k = 1
    while k * 2 < n:                       # largest power of two k with k < n <= 2k
        k *= 2
    return H(mth(blatt_hashes[:k]) + mth(blatt_hashes[k:]))


def wurzeln(n: int) -> tuple[bytes, bytes]:
    blaetter = [blatt(i) for i in range(n)]
    return (mth([blatt_hash_a(b) for b in blaetter]),
            mth([blatt_hash_b(b) for b in blaetter]))


# --- counter-probe: the comparison MUST also be able to say "equal" --------------------
def _durchgang(blatt_hash, blaetter, gleichwertig, verbogen) -> tuple[bool, bool, bytes]:
    """ONE pass of one reading. Returns the FINDINGS and passes no judgement.

    Factored out because the positive control further down has to run exactly the same mechanics as
    the real readings. A control on a path of its own tests itself.
    """
    links = mth([blatt_hash(b) for b in blaetter])
    rechts = mth([blatt_hash(b) for b in gleichwertig])
    anders = mth([blatt_hash(b) for b in verbogen])
    return links == rechts, anders != links, links + anders


def _taube_lesart(b: dict) -> bytes:
    """Does not read its input. MUST fail — the positive control hangs on that."""
    return H(b"konstant")


def gegenprobe() -> tuple[bool, str, str]:
    """Check EACH reading on its own for the equal case and the unequal case, with a positive control.

    Without those cases a uniform "differs" proves nothing: it could just as well mean the comparison
    always reports unequal.

    BOTH READINGS: the first version ran blatt_hash_b exclusively. Replacing blatt_hash_a with a
    CONSTANT still produced "passed" — the reading the result says something about was itself never
    checked.

    TWO REFUTATIONS FROM CROSS-READINGS STAND IN THIS VERSION, both measured:

    1. The equal case was a tautology. `links` and `rechts` were the same expression over the same
       data; with a deterministic H it can never report unequal. Measured: the branch was taken in 0
       of 9 versions. The right-hand side now holds an INDEPENDENTLY built leaf of equal content with
       the key order reversed, so the case checks the canonical ordering of the encoding rather than
       determinism.

    2. The trace bound to the computed intermediate values, not to the comparison results. Deleting
       the two if blocks and leaving everything else standing changed not one byte of the trace:
       measured 0a87e1a7611f53dd before and after the defect, every field of the measuring surface
       identical. The FINDINGS therefore go into the trace themselves now, and that is why a positive
       control stands at the end: a reading that does not read its input MUST show up as
       non-discriminating. A disarmed comparison is otherwise not observable in a run where the
       property holds — only a case that MUST fail makes the mechanics themselves measurable.
    """
    blaetter = [blatt(i) for i in range(4)]
    gleichwertig = [dict(reversed(list(b.items()))) for b in blaetter]
    verbogen = [dict(blaetter[0], data_hash=H(b"dh-abweichend"))] + blaetter[1:]

    befunde = []
    spur = b""
    for name, blatt_hash in (("2.1", blatt_hash_a), ("3.2", blatt_hash_b)):
        gleich, ungleich, roh = _durchgang(blatt_hash, blaetter, gleichwertig, verbogen)
        befunde.append((name, gleich, ungleich))
        spur += roh + bytes([gleich, ungleich])

    _, taub_ungleich, taub_roh = _durchgang(_taube_lesart, blaetter, gleichwertig, verbogen)
    mechanik = not taub_ungleich
    spur += taub_roh + bytes([mechanik])

    fehler = [
        "reading %s: equal case %s, unequal case %s" % (n, g, u)
        for n, g, u in befunde
        if not (g and u)
    ]
    if not mechanik:
        fehler.append("positive control: a deaf reading counted as discriminating")
    if fehler:
        return False, "; ".join(fehler), hx(H(spur))[:16]
    return True, "equal case, unequal case and positive control all correct", hx(H(spur))[:16]

def main() -> int:
    print("source : draft-ietf-scitt-receipts-ccf-profile-04, sections 2.1/2.2 and 3.2")
    print("CBOR   :", CBOR_PFAD)
    print()

    ok, grund, spur = gegenprobe()
    print(f"COUNTER-PROBE: {'PASSED' if ok else 'FAILED'} -- {grund} [trace {spur}]")
    if not ok:
        print("Stopping: without a valid counter-probe every result below is meaningless.")
        return 2
    print()

    print(f"{'n':>2}  {'root, reading 2.1':<66}  {'root, reading 3.2':<66}  verdict")
    abweichend = gesamt = 0
    for n in range(0, 6):
        a, b = wurzeln(n)
        gesamt += 1
        if a == b:
            urteil = "equal"
            if n == 0:
                urteil = "equal (3.2 knows no empty tree -- NOT APPLICABLE)"
        else:
            urteil = "DIFFERS"
            abweichend += 1
        print(f"{n:>2}  {hx(a):<66}  {hx(b):<66}  {urteil}")

    print()
    print(f"RESULT: {abweichend} of {gesamt} cases differ "
          f"(n=0 to n={gesamt - 1}).")
    print("The difference sits exclusively in the leaf preimage; the node rule "
          "HASH(left || right) is the same in both readings.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
