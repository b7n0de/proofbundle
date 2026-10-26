#!/usr/bin/env python3
"""Run the Go reader on the fifteen section 4 vectors and print one Markdown table row per vector.

Usage: python3 run_section4.py <path to ccfverify binary> <path to section4_vectors directory>

Standard library only. For each S4-*.json it writes the receipt bytes (receipt_hex) and a COSE_KeySet with the
vector's public key (kty EC2, kid as the ASCII bytes of the kid string, alg, crv P-384, x and y taken from
spki_der_hex), then calls

    ccfverify -consistency <receipt> -older-root <older_root_hex> -keys <keyset>

and prints the reader's line next to the two readings recorded in the vector."""
import glob
import json
import os
import subprocess
import sys
import tempfile

def head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | ai]) + n.to_bytes(size, "big")
    raise ValueError(n)

def enc(v):
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(enc(x) for x in v)
    if isinstance(v, dict):
        return head(5, len(v)) + b"".join(enc(k) + enc(x) for k, x in v.items())
    raise TypeError(type(v))

CRV = {"P-256": (1, 32), "P-384": (2, 48), "P-521": (3, 66)}

def keyset(pk):
    crv, size = CRV[pk["crv"]]
    spki = bytes.fromhex(pk["spki_der_hex"])
    point = spki[-(1 + 2 * size):]
    assert point[0] == 4, "uncompressed point expected"
    key = {1: 2, 2: pk["kid"].encode("ascii"), 3: pk["alg"], -1: crv, -2: point[1:1 + size], -3: point[1 + size:]}
    return enc([key])

def main():
    binary, vectors = sys.argv[1], sys.argv[2]
    print("| vector | title | Go reader | reading A | reading B size-free | reading B size-aware |")
    print("|---|---|---|---|---|---|")
    with tempfile.TemporaryDirectory() as tmp:
        for path in sorted(glob.glob(os.path.join(vectors, "S4-*.json"))):
            v = json.load(open(path, encoding="utf-8"))
            rec, keys = os.path.join(tmp, "receipt.cose"), os.path.join(tmp, "keys.cbor")
            open(rec, "wb").write(bytes.fromhex(v["receipt_hex"]))
            open(keys, "wb").write(keyset(v["public_key"]))
            out = subprocess.run([binary, "-consistency", rec, "-older-root", v["older_root_hex"], "-keys", keys],
                                 capture_output=True, text=True, timeout=60).stdout.strip()
            def r(x): return x["result"] + (" " + x["rule"] if x.get("rule") else "")
            print("| %s | %s | %s | %s | %s | %s |" % (v["id"], v["title"].replace("|", r"\|"), out.split(" newer_root=")[0],
                  r(v["reading_a"]), r(v["reading_b_size_free"]), r(v["reading_b_size_aware"])))

if __name__ == "__main__":
    main()
