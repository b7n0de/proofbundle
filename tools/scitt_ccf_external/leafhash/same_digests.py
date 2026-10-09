"""-05 section 4: "Apart from the tags, `path` holds the same digests in the same order as the
consistency proof of {{Section 2.1.4.1 of RFC9162}} for the same sizes".

Computes the RFC 9162 section 2.1.4.1 proof for the run-2 pairs 19 to 24, 22 to 24 and 19 to 22 twice,
once with this document's hashing (no prefix) and once with RFC 9162's own (0x00 leaf, 0x01 node), and
compares each digest with the -05 anchor and path recorded in ../consistency_result.json.

Measurement only. Writes same_digests_result.json next to this file.

Usage: python3 same_digests.py --ledger LEDGER_DIR   (needs the ccf package 7.0.17)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import ccf.ledger as L  # noqa: E402
import measure as M  # noqa: E402 - Tree, lp2, H of the same directory


def subproof(t, m, lo, hi, b):
    """RFC 9162 section 2.1.4.1 SUBPROOF over the tree t."""
    n = hi - lo
    if m == n:
        return [] if b else [t.node(lo, hi)]
    k = M.lp2(n)
    if m <= k:
        return subproof(t, m, lo, lo + k, b) + [t.node(lo + k, hi)]
    return subproof(t, m - k, lo + k, hi, False) + [t.node(lo, lo + k)]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--ledger", type=Path, required=True)
    args = ap.parse_args()
    leaves, pres = [bytes(32)], [bytes(32)]
    for ch in L.Ledger([str(args.ledger)], committed_only=False):
        for tx in ch:
            pd = tx.get_public_domain()
            pre = tx.get_write_set_digest() + pd.get_commit_evidence_digest() + pd.get_claims_digest()
            assert M.H(pre) == tx.get_tx_digest()
            leaves.append(tx.get_tx_digest())
            pres.append(pre)
    ccf_t = M.Tree(leaves, M.plain)
    rfc_t = M.Tree([M.H(b"\x00" + p) for p in pres], M.prefixed)
    cp = json.loads((HERE.parent / "consistency_result.json").read_text(encoding="utf-8"))["proofs"]
    out = {}
    for key, (m, n) in {"19->24": (19, 24), "22->24": (22, 24), "19->22": (19, 22)}.items():
        p05 = [bytes.fromhex(cp[key]["anchor"])] + [bytes.fromhex(h) for _side, h in cp[key]["path"]]
        if m & (m - 1) == 0:
            p05 = p05[1:]           # m a power of two: the anchor is R_m, not part of the RFC 9162 proof
        a, b = subproof(ccf_t, m, 0, n, True), subproof(rfc_t, m, 0, n, True)
        out[key] = {"digests": len(p05),
                    "equal_under_05_hashing": sum(x == y for x, y in zip(a, p05)) if len(a) == len(p05)
                    else "length differs",
                    "equal_under_rfc9162_hashing": sum(x == y for x, y in zip(b, p05)) if len(b) == len(p05)
                    else "length differs"}
    (HERE / "same_digests_result.json").write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
