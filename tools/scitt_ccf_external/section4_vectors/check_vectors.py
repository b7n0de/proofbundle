#!/usr/bin/env python3
"""Recompute readings A and B of section 4 of draft-ietf-scitt-receipts-ccf-profile-05 for every vector.

    python check_vectors.py [--dir DIR] [--json]

Standard library, cbor2 and cryptography only. Nothing is imported from proofbundle, so this file is
an implementation of its own, not a copy of the reader under test, and it does not recompute the
reader statuses a vector records.

Reading A is Figure 9 of section 4.2, statement by statement. Reading B applies the listed wire,
root-binding and signature checks (B1 to B13); B10 and B11 are derived necessary shape conditions,
not complete checks of strict growth or the canonical anchor. The size-free result runs B1 to B13
without tree sizes and reports passes_size_free_checks when they pass. The separate size-aware
result adds B14 using the vector's older_size and newer_size.

Exit 0 when manifest.json matches the files of the directory and every vector's recorded readings A
and B (size-free and size-aware) are reproduced; exit 1 otherwise.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Mapping
from pathlib import Path

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import load_der_public_key

HERE = Path(__file__).resolve().parent
VDP, VDS, ALG, INCLUSION, CONSISTENCY = 396, 395, 1, -1, -2
CCF_LEDGER_SHA256 = 2          # TBD_1, the value -05 requests
ALGS = {-7: (ec.SECP256R1, hashes.SHA256, 32), -35: (ec.SECP384R1, hashes.SHA384, 48)}


def H(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ------------------------------------------------------------------------------------------------
# The pieces both readings share
# ------------------------------------------------------------------------------------------------
def cose_sign1(receipt: bytes) -> tuple:
    """(protected bytes, protected map, unprotected map, payload, signature) of a COSE_Sign1."""
    obj = cbor2.loads(receipt)
    body = obj.value if isinstance(obj, cbor2.CBORTag) and obj.tag == 18 else obj
    prot_raw, unprot, payload, sig = body
    return prot_raw, (cbor2.loads(prot_raw) if prot_raw else {}), unprot, payload, sig


def compute_roots(proof: bytes) -> tuple:
    """compute_roots of Figure 9: fold the anchor with the left siblings alone (older) and with all
    siblings (newer)."""
    d = cbor2.loads(proof)
    older = newer = d[1]
    for left, sibling in d[2]:
        if left:
            older = H(sibling + older)
            newer = H(sibling + newer)
        else:
            newer = H(newer + sibling)
    return older, newer


def compute_root(proof: bytes) -> bytes:
    """compute_root of Figure 7 (3.2), for an inclusion proof beside the consistency proofs."""
    d = cbor2.loads(proof)
    itx, evidence, data_hash = d[1]
    h = H(itx + H(evidence.encode("utf-8")) + data_hash)
    for left, sibling in d[2]:
        h = H(sibling + h) if left else H(h + sibling)
    return h


def verify_cose(prot_raw: bytes, alg: object, payload: bytes, sig: bytes, spki: bytes) -> bool:
    """verify_cose over the detached payload: Sig_structure ["Signature1", protected, h'', payload]."""
    if isinstance(alg, bool) or not isinstance(alg, int) or alg not in ALGS or not isinstance(sig, bytes):
        return False                            # an int, not a float that hashes like one (-35.0)
    curve, hash_cls, n = ALGS[alg]
    key = load_der_public_key(spki)
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, curve) or len(sig) != 2 * n:
        return False
    tbs = cbor2.dumps(["Signature1", prot_raw, b"", payload])
    der = utils.encode_dss_signature(int.from_bytes(sig[:n], "big"), int.from_bytes(sig[n:], "big"))
    try:
        key.verify(der, tbs, ec.ECDSA(hash_cls()))
        return True
    except InvalidSignature:
        return False


# ------------------------------------------------------------------------------------------------
# Reading A: Figure 9, as written
# ------------------------------------------------------------------------------------------------
def reading_a(receipt: bytes, older_root: bytes, spki: bytes) -> tuple:
    """Each assert of verify_consistency_receipt in Figure 9, in its order; the first that fails is
    the result."""
    try:
        prot_raw, prot, unprot, payload, sig = cose_sign1(receipt)
        if VDP not in unprot:
            return "reject", "assert(VDP_LABEL in consistency_receipt.unprotected_header)"
        vdp = unprot[VDP]
        if CONSISTENCY not in vdp:
            return "reject", "assert(CONSISTENCY_PROOF_LABEL in vdp)"
        proofs = vdp[CONSISTENCY]
        if not len(proofs) > 0:
            return "reject", "assert(len(proofs) > 0)"
        if payload is not None:
            return "reject", "assert(consistency_receipt.payload == nil)"
        payloads = []
        for proof in proofs:
            older, newer = compute_roots(proof)
            if older == older_root:
                payloads.append(newer)
        if not len(payloads) > 0:
            return "reject", "assert(len(payloads) > 0)"
        for p in payloads:
            if not verify_cose(prot_raw, prot.get(ALG), p, sig, spki):
                return "reject", "assert(verify_cose(consistency_receipt, payload))"
        return "accept", "return true"
    except Exception as exc:  # noqa: BLE001 - Figure 9 does not say what an undecodable input is
        return "reject", f"the receipt does not decode as Figure 9 reads it ({type(exc).__name__})"


# ------------------------------------------------------------------------------------------------
# Reading B: the listed wire, root-binding and signature checks, size-free (B1 to B13) and size-aware (B14)
# ------------------------------------------------------------------------------------------------
B_RULES = {
    "B1": "5: protected-header-map carries alg (1) => int and vds (395) => TBD_1; 4.1: \"the same protected "
          "header requirements as an inclusion proof signature\"",
    "B2": "4.1: \"Its unprotected header MUST include: vdp (label 396): map.\"",
    "B3": "5: verifiable-proofs has the keys -1 and -2 and no other (the CDDL map has no wildcard)",
    "B4": "4.1: \"It MUST contain the consistency-proof (-2) key, whose value is an array of one or more "
          "ccf-consistency-proof values\"",
    "B5": "4: ccf-consistency-proof = bstr .cbor {1: bstr .size 32, 2: [+ ccf-proof-element]}, "
          "ccf-proof-element = [bool, bstr .size 32]",
    "B6": "5: inclusion-proofs = [+ ccf-inclusion-proof]; 3: ccf-inclusion-proof and ccf-leaf CDDL",
    "B7": "4.1: \"The payload is the newer root R_n, and MUST be detached.\"",
    "B8": "4.1: \"When the array contains more than one consistency proof, every proof MUST compute to the "
          "same newer root.\"",
    "B9": "5: \"All proofs in a receipt recompute the same root (the newer root, for consistency proofs), "
          "which is the detached payload.\"",
    "B10": "4: \"where 0 < m < n\" (a path of left siblings only folds both roots to one: m = n)",
    "B11": "4: \"The anchor MUST be the root of the subtree covering transactions T[m - 2^t], ..., T[m - 1]\" "
           "(without m: the first path element is a right sibling)",
    "B12": "4.2: \"At least one proof must start from older_root\"",
    "B13": "4.2: \"assert(verify_cose(consistency_receipt, payload))\" over the newer root",
    "B14": "4: the anchor MUST and 0 < m < n with the tree sizes older_size m and newer_size n: 0 < m < n, "
           "and the tags equal those of RFC 9162 2.1.4.1 for m and n (for a proof that does not start from "
           "older_root, for some m' below n); with m alone, the proof from older_root has popcount(m) - 1 "
           "left siblings",
}


def _array(x: object) -> bool:
    """A CBOR array; cbor2 returns a tuple for an array inside a map it decodes as immutable."""
    return isinstance(x, (list, tuple))


def _bstr32(x: object) -> bool:
    return isinstance(x, bytes) and len(x) == 32


def _element(e: object) -> bool:
    return _array(e) and len(e) == 2 and isinstance(e[0], bool) and _bstr32(e[1])


def _consistency_shape(p: object) -> bool:
    if not isinstance(p, bytes):
        return False
    d = cbor2.loads(p)
    return (isinstance(d, Mapping) and set(d) == {1, 2} and _bstr32(d[1]) and _array(d[2])
            and len(d[2]) >= 1 and all(_element(e) for e in d[2]))


def _inclusion_shape(p: object) -> bool:
    if not isinstance(p, bytes):
        return False
    d = cbor2.loads(p)
    if not (isinstance(d, Mapping) and set(d) == {1, 2}):
        return False
    leaf, path = d[1], d[2]
    return (_array(leaf) and len(leaf) == 3 and _bstr32(leaf[0]) and isinstance(leaf[1], str)
            and 1 <= len(leaf[1].encode("utf-8")) <= 1024 and _bstr32(leaf[2])
            and _array(path) and len(path) >= 1 and all(_element(e) for e in path))


def _lp2(n: int) -> int:
    return 1 << ((n - 1).bit_length() - 1)


def canonical_tags(m: int, n: int) -> list:
    """The left-sibling tags of the section 4 proof for sizes m and n, from RFC 9162 section 2.1.4.1
    SUBPROOF with the side of each sibling kept (True: a left sibling). No leaf is needed."""
    def sub(m_: int, lo: int, hi: int, b: bool) -> list:
        size = hi - lo
        if m_ == size:
            return [] if b else ["anchor"]
        k = _lp2(size)
        if m_ <= k:
            return sub(m_, lo, lo + k, b) + [False]
        return sub(m_ - k, lo + k, hi, False) + [True]
    return [t for t in sub(m, 0, n, True) if t != "anchor"]


def _b14(paths: list, roots: list, older_root: bytes, m: int | None, n: int | None) -> bool:
    """True if the anchor rule holds with the sizes given; True where no size is given."""
    if m is None:
        return True
    if n is None:
        return all(sum(left for left, _h in path) == bin(m).count("1") - 1
                   for path, (o, _n) in zip(paths, roots) if o == older_root)
    if not 0 < m < n:
        return False
    for path, (o, _n) in zip(paths, roots):
        tags = [left for left, _h in path]
        if o == older_root:
            if tags != canonical_tags(m, n):
                return False
        elif not any(tags == canonical_tags(k, n) for k in range(1, n)):
            return False
    return True


SIZE_FREE_PASS = ("passes_size_free_checks", "B1 to B13 hold")
SIZE_AWARE_PASS = ("accept", "B1 to B14 hold")


def reading_b_size_free(receipt: bytes, older_root: bytes, spki: bytes) -> tuple:
    """(result, rule): B1 to B13, no tree size anywhere; passing establishes neither 0 < m < n nor
    the canonical anchor position."""
    verdict = _b1_to_b13(receipt, older_root, spki)
    return verdict[:2] if verdict[0] else SIZE_FREE_PASS


def reading_b_size_aware(receipt: bytes, older_root: bytes, spki: bytes, older_size: int | None,
                         newer_size: int | None) -> tuple:
    """(result, rule): B1 to B13, then B14 with the sizes supplied. Without an older size B14 has
    nothing to use, and the result says so instead of passing."""
    verdict = _b1_to_b13(receipt, older_root, spki)
    if verdict[0]:
        return verdict[:2]
    if older_size is None:
        return "no_sizes_supplied", "B14"
    _none, _rule, paths, roots = verdict
    if not _b14(paths, roots, older_root, older_size, newer_size):
        return "reject", "B14"
    return SIZE_AWARE_PASS


def _b1_to_b13(receipt: bytes, older_root: bytes, spki: bytes) -> tuple:
    """("reject", rule, None, None) at the first of B1 to B13 that fails, else (None, None, paths, roots)."""
    try:
        prot_raw, prot, unprot, payload, sig = cose_sign1(receipt)
    except Exception as exc:  # noqa: BLE001
        return "reject", f"B1 the receipt is not a COSE_Sign1 ({type(exc).__name__})", None, None
    alg, vds = prot.get(ALG), prot.get(VDS)
    if not (isinstance(alg, int) and not isinstance(alg, bool)) \
            or not (isinstance(vds, int) and not isinstance(vds, bool) and vds == CCF_LEDGER_SHA256):
        return "reject", "B1", None, None                   # int and not bool: 2.0 == 2 in Python
    vdp = unprot.get(VDP) if isinstance(unprot, Mapping) else None
    if not isinstance(vdp, Mapping):
        return "reject", "B2", None, None
    if any(k not in (INCLUSION, CONSISTENCY) for k in vdp):
        return "reject", "B3", None, None
    proofs = vdp.get(CONSISTENCY)
    if not (_array(proofs) and len(proofs) >= 1):
        return "reject", "B4", None, None
    try:
        if not all(_consistency_shape(p) for p in proofs):
            return "reject", "B5", None, None
        inclusion = vdp.get(INCLUSION)
        if INCLUSION in vdp and not (_array(inclusion) and len(inclusion) >= 1
                                     and all(_inclusion_shape(p) for p in inclusion)):
            return "reject", "B6", None, None               # a present -1 is checked, null included
    except Exception:  # noqa: BLE001 - a proof that does not decode fails its CDDL
        return "reject", "B5", None, None
    if payload is not None:
        return "reject", "B7", None, None
    roots = [compute_roots(p) for p in proofs]
    newer = roots[0][1]
    if any(n_ != newer for _o, n_ in roots):
        return "reject", "B8", None, None
    if any(compute_root(p) != newer for p in inclusion or []):
        return "reject", "B9", None, None
    paths = [cbor2.loads(p)[2] for p in proofs]
    if any(all(left for left, _h in path) for path in paths):
        return "reject", "B10", None, None
    if any(path[0][0] for path in paths):
        return "reject", "B11", None, None
    if not any(o == older_root for o, _n in roots):
        return "reject", "B12", None, None
    if not verify_cose(prot_raw, alg, newer, sig, spki):
        return "reject", "B13", None, None
    return None, None, paths, roots


# ------------------------------------------------------------------------------------------------
# The directory
# ------------------------------------------------------------------------------------------------
def check_manifest(directory: Path) -> list:
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    problems = []
    listed = {f["path"] for f in manifest["files"]}
    present = {p.name for p in directory.iterdir() if p.is_file() and p.name != "manifest.json"}
    for name in sorted(present - listed):
        problems.append(f"{name}: not in manifest.json")
    for f in manifest["files"]:
        p = directory / f["path"]
        if not p.is_file():
            problems.append(f"{f['path']}: missing")
            continue
        data = p.read_bytes()
        if len(data) != f["length"] or hashlib.sha256(data).hexdigest() != f["sha256"]:
            problems.append(f"{f['path']}: length or sha256 differs from manifest.json")
    return problems


def check_vector(v: dict) -> dict:
    receipt = bytes.fromhex(v["receipt_hex"])
    older_root = bytes.fromhex(v["older_root_hex"])
    spki = bytes.fromhex(v["public_key"]["spki_der_hex"])
    a = reading_a(receipt, older_root, spki)
    b = reading_b_size_free(receipt, older_root, spki)
    bs = reading_b_size_aware(receipt, older_root, spki, v.get("older_size"), v.get("newer_size"))
    prot = cbor2.loads(cose_sign1(receipt)[0])
    decoded = [{"anchor_hex": d[1].hex(), "path": [[left, h.hex()] for left, h in d[2]]}
               for d in (cbor2.loads(p) for p in cose_sign1(receipt)[2].get(VDP, {}).get(CONSISTENCY, []) or [])]
    return {
        "id": v["id"],
        "reading_a": {"result": a[0], "step": a[1]},
        "reading_b_size_free": {"result": b[0], "rule": b[1]},
        "reading_b_size_aware": {"result": bs[0], "rule": bs[1]},
        "a_matches": [a[0], a[1]] == [v["reading_a"]["result"], v["reading_a"]["step"]],
        "b_matches": [b[0], b[1]] == [v["reading_b_size_free"]["result"], v["reading_b_size_free"]["rule"]]
                     and [bs[0], bs[1]] == [v["reading_b_size_aware"]["result"], v["reading_b_size_aware"]["rule"]],
        "kid_matches": prot.get(4) == v["public_key"]["kid"].encode("ascii"),
        "decoded_matches": decoded == v.get("consistency_proofs_decoded", decoded),
    }


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", type=Path, default=HERE)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    problems = check_manifest(args.dir)
    rows = []
    for path in sorted(args.dir.glob("S4-*.json")):
        v = json.loads(path.read_text(encoding="utf-8"))
        rows.append(check_vector(v))
    bad = [r for r in rows if not (r["a_matches"] and r["b_matches"] and r["kid_matches"] and r["decoded_matches"])]
    if args.json:
        print(json.dumps({"manifest_problems": problems, "vectors": rows}, indent=2))
    else:
        for r in rows:
            ok = "OK  " if r not in bad else "DIFF"
            b, bs = r["reading_b_size_free"], r["reading_b_size_aware"]
            print(f"{ok} {r['id']}  A: {r['reading_a']['result']:<7} B size-free: "
                  f"{b['result'] + (' ' + b['rule'] if b['result'] == 'reject' else ''):<24} B size-aware: "
                  f"{bs['result'] + (' ' + bs['rule'] if bs['result'] == 'reject' else '')}")
        for p in problems:
            print(f"MANIFEST {p}")
        print(f"readings A and B of {len(rows) - len(bad)} of {len(rows)} vectors reproduced (reader statuses "
              f"are not recomputed here); manifest problems: {len(problems)}")
    return 0 if rows and not bad and not problems else 1


if __name__ == "__main__":
    sys.exit(main())
