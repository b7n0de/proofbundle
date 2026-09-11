#!/usr/bin/env python3
"""Prepare a transparency-log registration, recompute its inclusion path, and say where it goes.

Register entry N23. Measured on 2026-09-12: of the nine receipts 6.0.0 ships, ZERO carry a
log registration — while this repository has verified a foreign log's proof since 5.1.0 and
submitted an entry of its own once (the frozen fixtures `proof_7271` and `submit_7727`).
The capability is not the gap. Its use for our own receipts is.

Three commands:

  dryrun     what a submission WOULD send, byte for byte, without sending it. A real
             submission is outward-facing and is the owner's act, never this script's.

  recompute  walk the inclusion path by hand, per RFC 6962 section 2.1.1, and compare the
             root we derive against the witnessed checkpoint. Deliberately NOT calling this
             project's own anchor code: a proof checked only by the implementation that
             produced it is checked by nobody. This is the independent oracle, and it is
             forty lines long precisely so it can be read.

  layout     the storage form next to the release assets, as a manifest — so a later reader
             finds the proof without knowing this script exists.

The word `submit` appears in no code path that opens a socket. That is on purpose.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "tests" / "fixtures" / "anchors" / "markovian_log" / "submit_7727"

LEAF_PREFIX = b"\x00"   # RFC 6962 section 2.1: leaf hashes are prefixed 0x00
NODE_PREFIX = b"\x01"   #                       interior nodes 0x01


def leaf_hash(leaf_bytes: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + leaf_bytes).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def root_from_inclusion_path(leaf: bytes, index: int, tree_size: int,
                             path: list[bytes]) -> bytes:
    """RFC 6962 section 2.1.1, written out rather than imported.

    `fn`/`sn` are the node index and the last-node index at the current level; the loop
    walks up, and which side the sibling goes on is decided by the shape of the tree, not
    by a flag in the proof. A path of the wrong length is a failure, not a truncation —
    an inclusion proof that ends early has not proven inclusion, it has proven nothing.
    """
    if not 0 <= index < tree_size:
        raise ValueError(f"index {index} outside a tree of {tree_size}")
    fn, sn = index, tree_size - 1
    r = leaf_hash(leaf)
    for p in path:
        if sn == 0:
            raise ValueError("path is longer than the tree is deep")
        if (fn & 1) or (fn == sn):
            r = node_hash(p, r)
            while fn != 0 and (fn & 1) == 0:
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError("path is shorter than the tree is deep")
    return r


def _checkpoint(path: Path) -> tuple[str, int, bytes]:
    """A C2SP signed note: origin, size, root, then signature lines."""
    lines = path.read_text(encoding="utf-8").split("\n")
    return lines[0].strip(), int(lines[1].strip()), base64.b64decode(lines[2].strip())


def _path_hashes(path: Path) -> list[bytes]:
    return [base64.b64decode(z.strip())
            for z in path.read_text(encoding="utf-8").splitlines() if z.strip()]


def _json_prefix(path: Path) -> dict:
    """Read the first complete JSON value and ignore what follows.

    The frozen response is the RAW answer, `HTTP 200` status line included — kept that
    way on purpose, because a fixture that was tidied up is no longer what came back.
    `raw_decode` reads the document and stops; a plain `loads` chokes on the extra line.
    """
    return json.JSONDecoder().raw_decode(path.read_text(encoding="utf-8").lstrip())[0]


def recompute(fixture: Path, as_json: bool = False) -> int:
    resp = _json_prefix(fixture / "submit_response.json")
    leaf = (fixture / "leaf.txt").read_bytes().rstrip(b"\n")
    pfad = _path_hashes(fixture / "inclusion_path.txt")
    origin, size, root_witnessed = _checkpoint(fixture / "checkpoint_witnessed.txt")

    index, tree_size = resp["leaf_index"], resp["tree_size"]
    erg = {
        "fixture": fixture.name,
        "origin": origin,
        "leaf_index": index,
        "tree_size_response": tree_size,
        "tree_size_checkpoint": size,
        "path_length": len(pfad),
        "leaf_sha256": hashlib.sha256(leaf).hexdigest(),
        "leaf_hash_rfc6962": leaf_hash(leaf).hex(),
    }
    try:
        root = root_from_inclusion_path(leaf, index, size, pfad)
    except ValueError as exc:
        erg.update(ok=False, reason=f"path does not walk: {exc}")
        root = None
    else:
        erg["root_recomputed"] = base64.b64encode(root).decode()
        erg["root_witnessed"] = base64.b64encode(root_witnessed).decode()
        erg["ok"] = root == root_witnessed
        erg["reason"] = ("recomputed root equals the witnessed checkpoint"
                         if erg["ok"] else "recomputed root DIFFERS from the checkpoint")
    # NO second length check here, and that absence is deliberate.
    #
    # The first version of this function carried one: `max(1, size-1).bit_length()`, the
    # depth of a COMPLETE tree. It reported FAIL on a path that is correct — 9 nodes for
    # index 7727 in a tree of 7728, exactly what the frozen fixture recorded as
    # `inclusion_path_nodes_required_by_rfc6962`. A Merkle tree of 7728 leaves is not
    # complete, and the last leaf sits on a shorter path than the formula assumes.
    #
    # The deeper fault was not the arithmetic. The length is ALREADY bound by the walk
    # itself: a path that is too short leaves `sn != 0`, a path that is too long runs out
    # of tree, and both raise. Adding a formula next to it created a SECOND SOURCE for one
    # truth — the shape this whole register keeps finding. The walk decides; nothing here
    # restates it. `tests/test_markovian_submit.py` binds both directions.

    # Second, independent comparison: the fixture states what it measured in 2026-08.
    # Agreeing with a number written by someone else is worth more than agreeing with
    # ourselves — and a silent divergence here would mean one of the two is wrong.
    man = fixture / "MANIFEST.json"
    if man.is_file():
        soll = json.loads(man.read_text(encoding="utf-8")).get("measured_2026_08_31", {})
        erg["fixture_says"] = {
            "leaf_hash_b64": soll.get("leaf_hash_b64"),
            "recomputed_root_b64": soll.get("recomputed_root_b64"),
            "inclusion_path_nodes": soll.get("inclusion_path_nodes"),
        }
        eigen_leaf = base64.b64encode(leaf_hash(leaf)).decode()
        erg["agrees_with_fixture"] = (
            eigen_leaf == soll.get("leaf_hash_b64")
            and erg.get("root_recomputed") == soll.get("recomputed_root_b64")
            and len(pfad) == soll.get("inclusion_path_nodes")
        )
        if not erg["agrees_with_fixture"]:
            erg["ok"] = False
            erg["reason"] = (erg.get("reason", "") +
                             " | DISAGREES with the figures the fixture recorded in 2026-08")
    if as_json:
        print(json.dumps(erg, indent=2))
    else:
        print(f"origin                {erg['origin']}")
        print(f"leaf index / size     {index} / {size}")
        print(f"path length           {erg['path_length']} (bound by the walk, not by a formula)")
        print(f"leaf hash (RFC 6962)  {erg['leaf_hash_rfc6962']}")
        print(f"root recomputed       {erg.get('root_recomputed', '-')}")
        print(f"root witnessed        {erg.get('root_witnessed', '-')}")
        if "agrees_with_fixture" in erg:
            print(f"agrees with fixture   {erg['agrees_with_fixture']}  "
                  f"(figures recorded 2026-08-31, independent of this run)")
        print(f"VERDICT               {'OK' if erg.get('ok') else 'FAIL'}  —  {erg['reason']}")
    return 0 if erg.get("ok") else 1


def dryrun(receipt: Path, origin: str) -> int:
    roh = receipt.read_bytes()
    d = hashlib.sha256(roh).hexdigest()
    leaf = f"public-note:v1 sha256:{d} <RFC3339 timestamp at submission>"
    print("DRY RUN — nothing was sent, no socket was opened.")
    print()
    print(f"receipt        {receipt}")
    print(f"bytes          {len(roh)}")
    print(f"sha256         {d}")
    print(f"origin         {origin}")
    print()
    print("the leaf this would submit, in the form the frozen fixture uses:")
    print(f"  {leaf}")
    print()
    print("what leaves the house: the line above. NOT the receipt, NOT its content —")
    print("a digest and a timestamp. What comes back: leaf index, tree size, an inclusion")
    print("path, and a witnessed checkpoint.")
    print()
    print("A REAL SUBMISSION IS AN OWNER GATE. It is outward-facing and permanent: a")
    print("transparency log cannot forget. This script has no code path that sends.")
    return 0


def layout(as_json: bool = False) -> int:
    form = {
        "schema": "proofbundle.log_registration_layout.v1",
        "where": "next to the release assets, not inside the tree",
        "reason": ("a proof written into the tree it is about is a fixed point: writing it "
                   "changes the digest it commits to"),
        "files": [
            {"name": "<asset>.logproof", "content": "c2sp.org/tlog-proof@v1 bundle: index, inclusion path, checkpoint"},
            {"name": "<asset>.checkpoint", "content": "the witnessed checkpoint the path was verified against"},
            {"name": "SHA256SUMS", "content": "already published; the leaf commits to these digests"},
        ],
        "verify_command": "python scripts/markovian_submit.py recompute --fixture <dir>",
        "acceptance": ("a reader recomputes the root from the path with any RFC 6962 "
                       "implementation and compares it against the checkpoint the witnesses signed"),
    }
    print(json.dumps(form, indent=2) if as_json else
          "\n".join(f"{k:18s} {v}" for k, v in form.items() if not isinstance(v, list)))
    if not as_json:
        print("files:")
        for f in form["files"]:
            print(f"  {f['name']:24s} {f['content']}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("dryrun", help="what a submission would send, without sending")
    d.add_argument("receipt", type=Path)
    d.add_argument("--origin", default="markovianprotocol.com/log")
    r = sub.add_parser("recompute", help="walk the inclusion path per RFC 6962")
    r.add_argument("--fixture", type=Path, default=FIXTURE)
    r.add_argument("--json", action="store_true")
    lay = sub.add_parser("layout", help="the storage form next to the release assets")
    lay.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    if a.cmd == "dryrun":
        if not a.receipt.is_file():
            print(f"no such receipt: {a.receipt}", file=sys.stderr)
            return 2
        return dryrun(a.receipt, a.origin)
    if a.cmd == "recompute":
        return recompute(a.fixture, a.json)
    return layout(a.json)


if __name__ == "__main__":
    raise SystemExit(main())
