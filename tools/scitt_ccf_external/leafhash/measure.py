"""Leaf and node hashing of one real CCF 7.0.17 ledger state, recomputed with and without prefixes.

Reads a ledger directory of the local scitt-ccf-ledger (run 2 of consistency_probe.py) with the ccf
package 7.0.17 (PyPI, Apache-2.0), takes every leaf preimage the way ccf.ledger computes
get_tx_digest, and lets the service's own COSE signature decide which of four hashing rules gives the
signed roots: CCF as written (no prefix), RFC 9162 prefixes on leaf and node, leaf prefix only, node
prefix only. It also records leaf and node preimage lengths, checks the three -05 inclusion receipts of
the same run against the ledger leaves, and runs the leaf/node confusion forgeries against a
transcription of the -05 section 3.2 pseudo-code that checks neither sizes nor types. The same
forgeries against proofbundle's reader run in reader_forgery.py, under the pinned cbor2 of the [scitt]
extra, from forgery_inputs.json written here.

Measurement only. Writes result.json and forgery_inputs.json next to this file.

Usage: python3 measure.py --ledger LEDGER_DIR --run RUN_DIR
  LEDGER_DIR  the ledger directory the service wrote (ledger_*.committed and ledger_* files)
  RUN_DIR     the run directory with older/middle/newer.receipt.cbor
Needs the ccf package 7.0.17 and cbor2 (any version; it only reads the three receipts).
"""
from __future__ import annotations

import argparse
import hashlib
import json
from importlib.metadata import version
from pathlib import Path

import cbor2
import ccf.ledger as L
from ccf import signatures as SIG

HERE = Path(__file__).resolve().parent


def H(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def lp2(n: int) -> int:
    """The largest power of two smaller than n (n > 1)."""
    return 1 << ((n - 1).bit_length() - 1)


class Tree:
    """MTH of -05 section 2.1 over given leaf hashes, with node rule ``node(left, right)``."""

    def __init__(self, leaves, node):
        self.leaves, self.nodefn, self.memo = leaves, node, {}
        self.node_preimage_lengths = []

    def node(self, lo, hi):
        if (lo, hi) not in self.memo:
            if hi - lo == 1:
                self.memo[(lo, hi)] = self.leaves[lo]
            else:
                k = lp2(hi - lo)
                left, right = self.node(lo, lo + k), self.node(lo + k, hi)
                self.node_preimage_lengths.append(len(left) + len(right))
                self.memo[(lo, hi)] = self.nodefn(left, right)
        return self.memo[(lo, hi)]

    def root(self, n):
        return self.node(0, n)


def plain(left: bytes, right: bytes) -> bytes:
    return H(left + right)


def prefixed(left: bytes, right: bytes) -> bytes:
    return H(b"\x01" + left + right)


def read_ledger(ledger_dir: Path):
    """Every leaf with its preimage, and every signature transaction, as the ccf package reads them."""
    validator = L.LedgerValidator(verification_level=L.VerificationLevel.FULL)
    ledger = L.Ledger([str(ledger_dir)], committed_only=False, verification_level=L.VerificationLevel.FULL)
    # leaf 0: 32 zero bytes, not hashed (ccf.ledger LedgerValidator.__init__; C++ MerkleTreeHistory(first_hash = {}))
    rows = [{"index": 0, "seqno": None, "form": "genesis constant, 32 zero bytes, no preimage",
             "preimage": None, "leaf": bytes(32)}]
    signed = []
    for chunk in ledger:
        for tx in chunk:
            pd = tx.get_public_domain()
            tables = pd.get_tables()
            seqno = tx.gcm_header.seqno
            if SIG.is_signature_transaction(tables):
                signed.append({"seqno": seqno, "tree_size": len(rows),
                               "cose": SIG.parse_cose_signature_from_tx(tables),
                               "service_cert": validator.service_cert})
            validator.add_transaction(tx)            # FULL: raises if a signed root does not match
            ws, ce, cl = tx.get_write_set_digest(), pd.get_commit_evidence_digest(), pd.get_claims_digest()
            raw_tx = tx.get_raw_tx()
            if cl is None and ce is None:
                form, pre = "write set only: leaf = SHA256(write set)", raw_tx
            elif cl is None:
                form, pre = "ws || ce", ws + ce
            else:
                form, pre = "ws || ce || claims", ws + ce + cl
            leaf = tx.get_tx_digest()
            assert H(pre) == leaf, seqno
            rows.append({"index": len(rows), "seqno": seqno, "form": form, "preimage": pre, "leaf": leaf,
                         "ws": ws, "ce": ce, "claims": cl, "raw_tx_len": len(raw_tx)})
    assert [r["leaf"] for r in rows] == list(validator.merkle.leaves), "leaves differ from the validator's"
    return validator, rows, signed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--ledger", type=Path, required=True)
    ap.add_argument("--run", type=Path, required=True)
    args = ap.parse_args()
    validator, rows, signed = read_ledger(args.ledger)

    def sig_ok(s, root):
        try:
            SIG.verify_cose_root_signature(s["service_cert"], root, s["cose"])
            return True
        except SIG.InvalidRootCoseSignatureException:
            return False

    def pre_of(r):
        return r["preimage"] if r["preimage"] is not None else r["leaf"]   # leaf 0: its 32 bytes as preimage

    rules = {
        "ccf_as_found": ([r["leaf"] for r in rows], plain),
        "rfc9162_both_prefixes": ([H(b"\x00" + pre_of(r)) for r in rows], prefixed),
        "leaf_prefix_only": ([H(b"\x00" + pre_of(r)) for r in rows], plain),
        "node_prefix_only": ([r["leaf"] for r in rows], prefixed),
    }
    trees = {k: Tree(lv, nf) for k, (lv, nf) in rules.items()}
    for s in signed:                                  # the root each COSE signature verifies over
        s["signed_root"] = Tree([r["leaf"] for r in rows], plain).root(s["tree_size"])
        assert sig_ok(s, s["signed_root"]), s["seqno"]
    roots = {k: sum(sig_ok(s, t.root(s["tree_size"])) for s in signed) for k, t in trees.items()}
    # leaf 0 kept as the constant under the prefixed rules too (the other way to read it)
    alt = Tree([rows[0]["leaf"]] + [H(b"\x00" + r["preimage"]) for r in rows[1:]], prefixed)
    roots["rfc9162_both_prefixes_leaf0_kept"] = sum(sig_ok(s, alt.root(s["tree_size"])) for s in signed)

    t = trees["ccf_as_found"]
    n_last = signed[-1]["tree_size"]
    t.node_preimage_lengths.clear()
    t.memo.clear()
    t.root(n_last)
    node_lens = t.node_preimage_lengths[:]

    # one leaf and one interior node, shown in full, the node from the ccf package's own tree
    lv = validator.merkle
    lv.get_merkle_root()
    level1 = lv._levels[1] if len(lv._levels) > 1 else []
    example_node = {"children": [rows[0]["leaf"].hex(), rows[1]["leaf"].hex()],
                    "sha256(left||right)": H(rows[0]["leaf"] + rows[1]["leaf"]).hex(),
                    "ccf_package_level1_node0": level1[0].hex() if level1 else None}
    ex = [r for r in rows[1:] if r["claims"] is not None][0]
    example_leaf = {"seqno": ex["seqno"], "ws": ex["ws"].hex(), "ce": ex["ce"].hex(), "claims": ex["claims"].hex(),
                    "preimage_length": len(ex["preimage"]), "sha256(ws||ce||claims)": H(ex["preimage"]).hex(),
                    "ccf_get_tx_digest": ex["leaf"].hex(),
                    "rfc9162_leaf_sha256(00||preimage)": H(b"\x00" + ex["preimage"]).hex()}

    # the -05 receipts of the same run: leaf components map to ws, ce, claims
    rc_check, receipt_files = [], {}
    for name in ("older", "middle", "newer"):
        raw = (args.run / f"{name}.receipt.cbor").read_bytes()
        receipt_files[f"{name}.receipt.cbor"] = {"length": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        rc = cbor2.loads(raw)
        rc = rc.value if hasattr(rc, "value") else rc
        itx, ev, dh = cbor2.loads(rc[1][396][-1][0])[1]
        leaf05 = H(itx + H(ev.encode()) + dh)
        match = next((r for r in rows[1:] if r["leaf"] == leaf05), None)
        rc_check.append({"receipt": name, "evidence_utf8_length": len(ev.encode()),
                         "leaf_equals_ledger_leaf_at_seqno": match["seqno"] if match else None,
                         "itx_is_ws": bool(match) and itx == match["ws"],
                         "hash_evidence_is_ce": bool(match) and H(ev.encode()) == match["ce"],
                         "data_hash_is_claims": bool(match) and dh == match["claims"]})

    # forgeries at the last signed state, every interior node presented as a leaf
    last_root = signed[-1]["signed_root"]
    interior = [(lo, hi) for (lo, hi) in t.memo if hi - lo > 1 and hi <= n_last]

    def pos_path(lo, hi):
        """Path from the node [lo, hi) to the root of n_last, as [(left, hash)], node upward."""
        a, b, segs = 0, n_last, []
        while (a, b) != (lo, hi):
            k = lp2(b - a)
            if lo < a + k:
                segs.append((False, t.node(a + k, b)))
                b = a + k
            else:
                segs.append((True, t.node(a, a + k)))
                a = a + k
        return list(reversed(segs))

    known_pre = {r["leaf"]: r["preimage"] for r in rows if r["preimage"] is not None}

    def preimage_of(lo, hi):
        if hi - lo == 1:
            return known_pre.get(t.leaves[lo])
        k = lp2(hi - lo)
        return t.node(lo, lo + k) + t.node(lo + k, hi)

    def lax_root(itx, ev_bytes, dh, path):
        """-05 section 3.2 compute_root, transcribed without the ccf-leaf sizes and types."""
        h = H(itx + H(ev_bytes) + dh)
        for left, sib in path:
            h = H(sib + h) if left else H(h + sib)
        return h

    f = {"interior_nodes": len(interior), "A_node_as_05_leaf_itx_L_dh_R": 0,
         "B_lax_itx_L_ev_rightpreimage_dh_empty": 0, "B_right_child_preimage_known": 0,
         "B_right_child_preimage_valid_utf8": 0}
    export = []
    for (lo, hi) in interior:
        k = lp2(hi - lo)
        left_h, right_h = t.node(lo, lo + k), t.node(lo + k, hi)
        p = pos_path(lo, hi)
        rp = preimage_of(lo + k, hi)
        export.append({"lo": lo, "hi": hi, "L": left_h.hex(), "R": right_h.hex(),
                       "path": [[side, s.hex()] for side, s in p], "right_child_preimage": (rp or b"").hex()})
        # A: the classic RFC 6962 confusion, the node's children as leaf components
        f["A_node_as_05_leaf_itx_L_dh_R"] += lax_root(left_h, b"x", right_h, p) == last_root
        # B: sizes and types unchecked: itx = L, evidence = the right child's own preimage, dh empty
        if rp is None:
            continue
        f["B_right_child_preimage_known"] += 1
        f["B_lax_itx_L_ev_rightpreimage_dh_empty"] += lax_root(left_h, rp, b"", p) == last_root
        try:
            rp.decode("utf-8")
            f["B_right_child_preimage_valid_utf8"] += 1
        except UnicodeDecodeError:
            pass

    (HERE / "forgery_inputs.json").write_text(json.dumps(
        {"last_signed_root": last_root.hex(), "tree_size": n_last, "nodes": export}, indent=1) + "\n",
        encoding="utf-8")
    # 64-byte leaves: could one be read as an interior node over a -05 leaf?
    leaf64 = [r for r in rows[1:] if r["preimage"] is not None and len(r["preimage"]) == 64]
    c64 = {"leaves_with_64_byte_preimage": len(leaf64),
           "their_write_set_lengths": sorted({r["raw_tx_len"] for r in leaf64}),
           "write_set_of_96_bytes": sum(r["raw_tx_len"] == 96 for r in leaf64)}

    by_form: dict = {}
    for r in rows:
        key = r["form"] + ("" if r["preimage"] is None else f", preimage {len(r['preimage'])} B")
        by_form[key] = by_form.get(key, 0) + 1
    ledger_files = {p.name: {"length": p.stat().st_size, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                    for p in sorted(args.ledger.iterdir()) if p.is_file()}

    doc = {
        "ccf_package": version("ccf"),
        "ledger_files": ledger_files, "receipt_files": receipt_files,
        "transactions": len(rows) - 1, "leaves": len(rows),
        "signatures_verified_by_the_ccf_validator": validator.signature_count,
        "signed_states": [{"seqno": s["seqno"], "tree_size": s["tree_size"], "signed_root": s["signed_root"].hex()}
                          for s in signed],
        "signed_roots_reproduced": {k: f"{v} of {len(signed)}" for k, v in roots.items()},
        "leaf_forms": by_form,
        "leaf_preimage_lengths": sorted({len(r["preimage"]) for r in rows if r["preimage"] is not None}),
        "node_preimage_lengths_at_last_signed_state": {"count": len(node_lens), "lengths": sorted(set(node_lens))},
        "example_leaf": example_leaf, "example_interior_node": example_node,
        "receipts_05_against_ledger": rc_check,
        "forgeries_at_last_signed_state": f, "leaves_64": c64,
    }
    (HERE / "result.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(doc, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
