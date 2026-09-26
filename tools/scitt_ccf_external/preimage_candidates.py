#!/usr/bin/env python3
"""Which bytes is the receipt's data-hash the SHA-256 of? Ten candidates per accepted corpus vector.

WHY. Owner order of 2026-09-26, the seventh addendum to the corpus work. A reviewer
of the differential corpus asked for the exact preimage of the data-hash before the mutations are
broadened. No new ledger run: every candidate is computed from the bytes stored in differential_corpus/.

WHAT. For each accepted vector, vectors/<id>/candidate_hashes.json holds the SHA-256 of every candidate
below and whether it equals the data-hash in that vector's receipt. preimage_summary.json counts the
matches over the corpus and names the service source lines that build the hashed bytes. Both files are
derived from the stored raw bytes alone. ``--check`` exits 1 unless the stored files equal their
derivation.

THE CANDIDATES, numbered as in the order:
   1  the exact request bytes
   2  the returned statement bytes
   3  the returned statement with the receipt material removed, every other byte as served
   4  a deterministic encoding of [protected, {}, payload, signature]
   5  a deterministic encoding of [protected, U, payload, signature], where U is the submitted
      unprotected map without the receipt material
   6  the Sig_structure of RFC 9052 section 4.4: ["Signature1", protected, h'', payload]
   7  the protected-header bytes
   8  the payload bytes
   9  the signature bytes
  10  protected || payload || signature

RULES APPLIED. They are written into every output file, in RULES below.

ORACLES.
  * Every candidate is an own computation: this file's CBOR reader and encoder, and hashlib.
  * The data-hash is read twice. Once by this file's own reader, once by cbor2, a foreign library
    pinned by the [scitt] extra. The two readings must agree.
  * Candidates 4, 5 and 6 are encoded a second time by cbor2. For the sorted variant of 5, cbor2's
    canonical mode orders keys length-first (RFC 8949 section 4.2.3), not bytewise (4.2.1). So
    agreement there is measured per vector, not assumed.

usage: preimage_candidates.py [--corpus DIR] [--write] [--check]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "differential_corpus"
SHA = lambda b: hashlib.sha256(b).hexdigest()  # noqa: E731
RECEIPTS = 394

RULES = {
    "deterministic_encoding": (
        "RFC 8949 section 4.2.1, core deterministic encoding: the preferred (shortest) argument in "
        "every head, definite lengths only, map keys sorted by the bytewise lexicographic order of "
        "their deterministic encodings. Byte and text string contents are never changed. The "
        "protected header therefore stays the content of its bstr as submitted, because those are "
        "the signed bytes."),
    "receipt_material": (
        "the unprotected label 394 'receipts', and no other label. Sources: COSE Receipts, WG source "
        "https://github.com/cose-wg/draft-ietf-cose-merkle-tree-proofs at "
        "df5113e94e6b6788de0bfb112db63726516b88ab, section 'Receipts' (requested assignment 394); "
        "SCITT architecture, WG source https://github.com/ietf-wg-scitt/draft-ietf-scitt-architecture "
        "at ba7d23d40557f0206735592036532414139d9a57 ('label 394 receipts in the unprotected "
        "header'); both retrieved 2026-09-25"),
    "tag_18": (
        "open for candidates 3, 4 and 5, so each is computed tagged and untagged. 1 and 2 are the "
        "stored bytes. 6 to 10 are not COSE_Sign1 messages and carry no tag."),
    "key_order_of_U": (
        "open for candidate 5, so both: sorted per 4.2.1, and in the submitted entry order with "
        "preferred heads"),
    "element_form": (
        "open for candidates 7 to 10, so both: the content bytes, and the element as a byte string "
        "with a preferred head. Candidate 7 is also computed as the element exactly as submitted."),
    "source_of_the_element_contents": (
        "the request. The returned statement's protected, payload and signature contents are checked "
        "equal to the request's, per vector"),
}

#: the header of every candidate_hashes.json; the full text is RULES, in preimage_summary.json
RULES_SHORT = {
    "deterministic_encoding": "RFC 8949 section 4.2.1 core deterministic; string contents never changed",
    "receipt_material": "unprotected label 394 only (COSE Receipts WG source df5113e9, SCITT architecture "
                        "WG source ba7d23d4)",
    "tag_18": "3, 4 and 5 tagged and untagged; 1 and 2 as stored; 6 to 10 untagged",
    "key_order_of_U": "5 sorted per 4.2.1 and in the submitted order",
    "element_form": "7 to 10 as content and as a preferred-head bstr; 7 also as submitted",
    "full_text": "preimage_summary.json, key rules",
}

NAMES = {
    "1": "exact request bytes",
    "2": "returned statement bytes",
    "3-tagged": "returned statement, label 394 removed, every other byte as served, tag 18 kept",
    "3-untagged": "returned statement, label 394 removed, every other byte as served, tag 18 dropped",
    "4-tagged": "deterministic [protected, {}, payload, signature], tag 18",
    "4-untagged": "deterministic [protected, {}, payload, signature], no tag",
    "5-sorted-tagged": "deterministic [protected, U, payload, signature], U sorted per 4.2.1, tag 18",
    "5-sorted-untagged": "deterministic [protected, U, payload, signature], U sorted per 4.2.1, no tag",
    "5-submitted-order-tagged": "[protected, U, payload, signature], U in submitted order, preferred heads, tag 18",
    "5-submitted-order-untagged": "[protected, U, payload, signature], U in submitted order, preferred heads, no tag",
    "6": "Sig_structure, RFC 9052 section 4.4",
    "7-content": "protected header, content of the bstr",
    "7-element": "protected header, bstr with a preferred head",
    "7-element-as-submitted": "protected header, bstr exactly as submitted",
    "8-content": "payload, content of the bstr",
    "8-element": "payload, bstr with a preferred head",
    "9-content": "signature, content of the bstr",
    "9-element": "signature, bstr with a preferred head",
    "10-content": "protected || payload || signature, contents",
    "10-element": "protected || payload || signature, bstrs with preferred heads",
}

SOURCE = [
    {"what": "registration: the unprotected header is replaced by an empty map, and the SHA-256 of the "
             "result is bound as the claims digest, the receipt's data-hash",
     "repository": "https://github.com/microsoft/scitt-ccf-ledger",
     "commit": "00101f769d872711356e080fbb089ac48589c60a", "file": "app/src/main.cpp", "lines": "417-425",
     "file_sha256": "4868e3696c361913e011e48deb36c694b521da9878c0056197e453ccda812ecf",
     "quote": "const auto signed_statement = ccf::cose::edit::set_unprotected_header(body, "
              "ccf::cose::edit::desc::Empty{}); ctx.rpc_ctx->set_claims_digest("
              "ccf::ClaimsDigest::Digest(signed_statement));"},
    {"what": "set_unprotected_header: parses the COSE_Sign1, requires tag 18, copies protected, payload "
             "and signature, puts an empty map in position 1, wraps it in tag 18 and serializes",
     "repository": "https://github.com/microsoft/CCF", "commit": "ccf-7.0.17 (cdcb74c7365dbe4b3fad739868bfa9802d77ed75)",
     "file": "src/crypto/cose.cpp", "lines": "18-89",
     "file_sha256": "97982db318771ac293d0162fd2003520ee0964752355bcf041502c5b6c18358e",
     "quote": "edited.push_back(shallow_copy(phdr)); ... edited.push_back(make_map({})); ... "
              "make_tagged(ccf::cbor::tag::COSE_SIGN_1, make_array(std::move(edited))); return "
              "edited_envelope.nondet_serialize();"},
    {"what": "the serializer: preferred head widths in both modes, map entries kept in order in the "
             "non-deterministic mode",
     "repository": "https://github.com/microsoft/CCF", "commit": "ccf-7.0.17 (cdcb74c7365dbe4b3fad739868bfa9802d77ed75)",
     "file": "3rdparty/internal/tee-attestation-verification/cbor/src/lib.rs", "lines": "14-16",
     "file_sha256": "260961dd67e2a35053cdbd5a9e69d812966746b1237f2c88c2a8ab560d5ec031",
     "quote": "Serialization: the modes differ only in map entry order. [`Det`] sorts keys into "
              "canonical order, [`Nondet`] emits them as given. Both write preferred head widths"},
    {"what": "the claims digest is SHA-256 over the byte vector",
     "repository": "https://github.com/microsoft/CCF", "commit": "ccf-7.0.17 (cdcb74c7365dbe4b3fad739868bfa9802d77ed75)",
     "file": "include/ccf/claims_digest.h, src/crypto/sha256_hash.cpp", "lines": "12; 17-20",
     "quote": "using Digest = ccf::crypto::Sha256Hash; Sha256Hash::Sha256Hash(const std::vector<uint8_t>& vec) "
              "{ default_sha256(vec, h.data()); }"},
]


# ------------------------------------------------------------------------------------------------
# An own CBOR reader that keeps order, duplicates and the byte span of every item
# ------------------------------------------------------------------------------------------------
class Node:
    __slots__ = ("kind", "value", "start", "end")

    def __init__(self, kind, value, start, end):
        self.kind, self.value, self.start, self.end = kind, value, start, end


def _head(b: bytes, i: int):
    ib = b[i]
    mt, ai = ib >> 5, ib & 0x1F
    i += 1
    if ai < 24:
        return mt, ai, i
    if ai in (24, 25, 26, 27):
        n = 1 << (ai - 24)
        return mt, int.from_bytes(b[i:i + n], "big"), i + n
    if ai == 31:
        return mt, None, i
    raise ValueError(f"additional information {ai} at {i - 1}")


def parse(b: bytes, i: int = 0, depth: int = 0):
    """(node, end) of one data item. Indefinite strings are joined; floats are refused."""
    if depth > 32:
        raise ValueError("nesting deeper than 32")
    start = i
    mt, arg, i = _head(b, i)
    if mt in (0, 1):
        return Node("int", arg if mt == 0 else -1 - arg, start, i), i
    if mt in (2, 3):
        if arg is None:
            parts = []
            while b[i] != 0xFF:
                _mt, n, i = _head(b, i)
                parts.append(b[i:i + n])
                i += n
            i += 1
            content = b"".join(parts)
        else:
            content = b[i:i + arg]
            i += arg
        return Node("bytes" if mt == 2 else "text", content, start, i), i
    if mt in (4, 5):
        items = []
        want = None if arg is None else (arg if mt == 4 else 2 * arg)
        while (want is None and b[i] != 0xFF) or (want is not None and len(items) < want):
            node, i = parse(b, i, depth + 1)
            items.append(node)
        if want is None:
            i += 1
        if mt == 4:
            return Node("array", items, start, i), i
        return Node("map", [(items[k], items[k + 1]) for k in range(0, len(items), 2)], start, i), i
    if mt == 6:
        inner, i = parse(b, i, depth + 1)
        return Node("tag", (arg, inner), start, i), i
    if arg is not None and arg < 24:
        return Node("simple", arg, start, i), i
    raise ValueError(f"float or reserved simple value at {start}")


def _h(mt: int, n: int) -> bytes:
    if n < 24:
        return bytes([(mt << 5) | n])
    for ai, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * width):
            return bytes([(mt << 5) | ai]) + n.to_bytes(width, "big")
    raise ValueError("argument too large")


def encode(node: Node, *, sort: bool) -> bytes:
    """Preferred heads and definite lengths throughout; map keys sorted bytewise when ``sort``."""
    k, v = node.kind, node.value
    if k == "int":
        return _h(0, v) if v >= 0 else _h(1, -1 - v)
    if k in ("bytes", "text"):
        return _h(2 if k == "bytes" else 3, len(v)) + v
    if k == "array":
        return _h(4, len(v)) + b"".join(encode(x, sort=sort) for x in v)
    if k == "map":
        pairs = [(encode(a, sort=sort), encode(b, sort=sort)) for a, b in v]
        if sort:
            pairs.sort(key=lambda p: p[0])
        return _h(5, len(pairs)) + b"".join(a + b for a, b in pairs)
    if k == "tag":
        return _h(6, v[0]) + encode(v[1], sort=sort)
    return bytes([0xE0 | v])


def bstr(content: bytes) -> bytes:
    return _h(2, len(content)) + content


def sign1(raw: bytes):
    """(tag node or None, the four element nodes) of a COSE_Sign1, tagged or not."""
    top, end = parse(raw)
    if end != len(raw):
        raise ValueError("trailing bytes")
    tag = top if top.kind == "tag" else None
    arr = top.value[1] if tag else top
    if arr.kind != "array" or len(arr.value) != 4:
        raise ValueError("not a four-element array")
    return tag, arr.value


def data_hash_own(receipt: bytes) -> list:
    """Every inclusion proof's leaf data-hash in a CCF receipt, read by this file's reader:
    unprotected 396 (vdp), key -1 (inclusion proofs), each a bstr holding {1: leaf, 2: path}, and the
    leaf's third element."""
    _tag, (_p, unprot, _pl, _s) = sign1(receipt)
    vdp = next(v for k, v in unprot.value if k.kind == "int" and k.value == 396)
    proofs = next(v for k, v in vdp.value if k.kind == "int" and k.value == -1)
    out = []
    for proof in proofs.value:
        m, _e = parse(proof.value)
        leaf = next(v for k, v in m.value if k.kind == "int" and k.value == 1)
        out.append(leaf.value[2].value.hex())
    return out


def data_hash_cbor2(receipt: bytes):
    """The same reading by cbor2, or None when cbor2 is not installed."""
    try:
        import cbor2
    except ImportError:
        return None
    body = cbor2.loads(receipt)
    body = body.value if isinstance(body, cbor2.CBORTag) else body
    return [bytes(cbor2.loads(p)[1][2]).hex() for p in body[1][396][-1]]


def foreign_encodings(request: bytes):
    """Candidates 4, 5 and 6 encoded by cbor2 from cbor2's own decoding of the request, or None."""
    try:
        import cbor2
    except ImportError:
        return None
    msg = cbor2.loads(request)
    prot, unprot, payload, sig = (msg.value if isinstance(msg, cbor2.CBORTag) else msg)
    kept = {k: v for k, v in unprot.items() if k != RECEIPTS}
    t = lambda x: cbor2.dumps(cbor2.CBORTag(18, x))  # noqa: E731
    return {
        "4-tagged": SHA(t([prot, {}, payload, sig])),
        "4-untagged": SHA(cbor2.dumps([prot, {}, payload, sig])),
        "5-sorted-tagged": SHA(cbor2.dumps(cbor2.CBORTag(18, [prot, kept, payload, sig]), canonical=True)),
        "5-sorted-untagged": SHA(cbor2.dumps([prot, kept, payload, sig], canonical=True)),
        "5-submitted-order-tagged": SHA(t([prot, kept, payload, sig])),
        "5-submitted-order-untagged": SHA(cbor2.dumps([prot, kept, payload, sig])),
        "6": SHA(cbor2.dumps(["Signature1", prot, b"", payload])),
    }


# ------------------------------------------------------------------------------------------------
# The candidates of one vector
# ------------------------------------------------------------------------------------------------
def candidates(request: bytes, statement: bytes) -> tuple:
    """({candidate id: bytes}, facts about the inputs)."""
    _rt, (rp, ru, rpl, rs) = sign1(request)
    st, (sp, su, spl, ss) = sign1(statement)
    prot, payload, sig = rp.value, rpl.value, rs.value
    if payload is None or rpl.kind != "bytes":
        raise ValueError("payload is not an embedded byte string")
    facts = {
        "returned_contents_equal_request_contents": (sp.value, spl.value, ss.value) == (prot, payload, sig),
        "request_unprotected_labels": [_label(k) for k, _v in ru.value],
        "returned_unprotected_labels": [_label(k) for k, _v in su.value],
    }
    pnode, _e = parse(prot)
    facts["protected_content_is_core_deterministic"] = encode(pnode, sort=True) == prot

    def cose(unprot: bytes, tagged: bool) -> bytes:
        body = b"\x84" + bstr(prot) + unprot + bstr(payload) + bstr(sig)
        return (b"\xd2" + body) if tagged else body

    kept = [(k, v) for k, v in ru.value if not (k.kind == "int" and k.value == RECEIPTS)]
    u_sorted = encode(Node("map", kept, 0, 0), sort=True)
    u_order = encode(Node("map", kept, 0, 0), sort=False)
    # 3: surgery on the returned bytes; only the unprotected map is rebuilt, from its kept entries
    su_kept = [(k, v) for k, v in su.value if not (k.kind == "int" and k.value == RECEIPTS)]
    su_new = _h(5, len(su_kept)) + b"".join(statement[k.start:v.end] for k, v in su_kept)
    arr_start = st.value[1].start if st else 0
    arr_head = statement[arr_start:sp.start]
    rest = arr_head + statement[sp.start:sp.end] + su_new + statement[spl.start:ss.end]
    tag_head = statement[:arr_start]
    c = {
        "1": request,
        "2": statement,
        "3-tagged": tag_head + rest,
        "3-untagged": rest,
        "4-tagged": cose(b"\xa0", True),
        "4-untagged": cose(b"\xa0", False),
        "5-sorted-tagged": cose(u_sorted, True),
        "5-sorted-untagged": cose(u_sorted, False),
        "5-submitted-order-tagged": cose(u_order, True),
        "5-submitted-order-untagged": cose(u_order, False),
        "6": b"\x84\x6aSignature1" + bstr(prot) + b"\x40" + bstr(payload),
        "7-content": prot,
        "7-element": bstr(prot),
        "7-element-as-submitted": request[rp.start:rp.end],
        "8-content": payload,
        "8-element": bstr(payload),
        "9-content": sig,
        "9-element": bstr(sig),
        "10-content": prot + payload + sig,
        "10-element": bstr(prot) + bstr(payload) + bstr(sig),
    }
    facts["returned_statement_tagged"] = st is not None
    return c, facts


def _label(node: Node):
    """A map label for the record: an integer, or text."""
    return node.value.decode("utf-8") if node.kind == "text" else node.value


def _hex(path: Path) -> bytes:
    return bytes.fromhex("".join(path.read_text(encoding="ascii").split()))


def derive(corpus: Path) -> tuple:
    """({vector id: candidate_hashes.json object}, preimage_summary.json object)."""
    man = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))
    per, byte_sets = {}, {}
    for vid in man["vectors"]:
        d = corpus / "vectors" / vid
        rec = json.loads((d / "record.json").read_text(encoding="utf-8"))
        if not rec["service"]["accepted"]:
            continue
        raw = {name: _hex(d / name) for name in ("request.hex", "statement.hex", "receipt.hex")}
        for name, blob in raw.items():
            if SHA(blob) != rec["files"][name]["sha256"]:
                raise SystemExit(f"REFUSED: {vid}/{name} is not the recorded bytes")
        own = data_hash_own(raw["receipt.hex"])
        foreign = data_hash_cbor2(raw["receipt.hex"])
        if len(set(own)) != 1:
            raise SystemExit(f"REFUSED: {vid} has {len(own)} inclusion proofs with differing data-hashes")
        dh = own[0]
        cands, facts = candidates(raw["request.hex"], raw["statement.hex"])
        fenc = foreign_encodings(raw["request.hex"])
        byte_sets[vid] = cands
        per[vid] = {
            "tool": "tools/scitt_ccf_external/preimage_candidates.py",
            "vector": vid, "class": rec["class"], "base": rec["base"], "mutation": rec["mutation"],
            "rules": RULES_SHORT,
            "encodings_in_this_directory": {
                "request.hex": "the exact submitted encoding", "statement.hex": "the exact returned encoding "
                "(GET /entries/{txid}/statement)", "receipt.hex": "the receipt as served"},
            "oracles": {
                "candidates": "own computation: this tool's CBOR reader and encoder, hashlib SHA-256",
                "data_hash": "own reader of receipt.hex, checked against cbor2 (foreign, pinned by the "
                             "[scitt] extra) where installed",
                "foreign_re_encoding": "cbor2 encodes 4, 5 and 6 again from its own decoding of request.hex; "
                                       "its canonical mode is length-first (RFC 8949 4.2.3)",
            },
            "receipt_data_hash": dh,
            "receipt_inclusion_proofs": len(own),
            "data_hash_cbor2_agrees": None if foreign is None else foreign == own,
            "facts": facts,
            "candidates": {cid: {"sha256": SHA(b), "equals_data_hash": SHA(b) == dh,
                                 **({"cbor2_equal": fenc[cid] == SHA(b)} if fenc and cid in fenc else {})}
                           for cid, b in cands.items()},
        }
    ids = list(NAMES)
    n = len(per)
    table = []
    for cid in ids:
        hits = sum(1 for v in per.values() if v["candidates"][cid]["equals_data_hash"])
        cb = [v["candidates"][cid].get("cbor2_equal") for v in per.values()]
        table.append({"candidate": cid, "what": NAMES[cid], "matches": hits, "of": n,
                      "oracle": "own computation",
                      **({"cbor2_encoding_equal": sum(1 for x in cb if x)} if any(x is not None for x in cb) else {})})
    full = [cid for cid in ids if all(v["candidates"][cid]["equals_data_hash"] for v in per.values())]
    same = {}
    for cid in full:
        same[cid] = [o for o in full if all(byte_sets[vid][o] == byte_sets[vid][cid] for vid in per)]
    partial = {cid: sorted(vid for vid, v in per.items() if v["candidates"][cid]["equals_data_hash"])
               for cid in ids if 0 < sum(v["candidates"][cid]["equals_data_hash"] for v in per.values()) < n}
    agree = [v["data_hash_cbor2_agrees"] for v in per.values()]
    summary = {
        "tool": "tools/scitt_ccf_external/preimage_candidates.py",
        "corpus": "tools/scitt_ccf_external/" + corpus.name,
        "pins": man.get("pins", "per vector, in vectors/<id>/record.json"),
        "rules": RULES,
        "candidate_names": NAMES,
        "accepted_vectors": n,
        "table": table,
        "match_every_accepted_vector": full,
        "same_bytes_in_every_accepted_vector": same,
        "match_some_vectors_only": partial,
        "data_hash_readers": {
            "own_reader": n,
            "cbor2_agrees": (sum(1 for x in agree if x) if any(x is not None for x in agree)
                             else "NOT MEASURED: cbor2 is not installed"),
        },
        "facts_over_the_corpus": {
            key: sum(1 for v in per.values() if v["facts"][key])
            for key in ("returned_contents_equal_request_contents", "protected_content_is_core_deterministic",
                        "returned_statement_tagged")},
        "service_source": SOURCE,
    }
    return per, summary


def _dump(v) -> str:
    return json.dumps(v, indent=1) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--corpus", type=Path, default=CORPUS)
    ap.add_argument("--write", action="store_true", help="write candidate_hashes.json and preimage_summary.json")
    ap.add_argument("--check", action="store_true", help="exit 1 unless the stored files equal their derivation")
    a = ap.parse_args(argv)
    per, summary = derive(a.corpus)
    files = {a.corpus / "vectors" / vid / "candidate_hashes.json": obj for vid, obj in per.items()}
    files[a.corpus / "preimage_summary.json"] = summary
    if a.write:
        for path, obj in files.items():
            path.write_text(_dump(obj), encoding="utf-8")
    if a.check:
        bad = [str(p.relative_to(a.corpus)) for p, obj in files.items()
               if not p.is_file() or p.read_text(encoding="utf-8") != _dump(obj)]
        print("derived equals stored" if not bad else "DIFFERS: " + ", ".join(bad))
        return 0 if not bad else 1
    for row in summary["table"]:
        print(f"{row['candidate']:28s} {row['matches']:3d} of {row['of']}")
    print("match every accepted vector:", ", ".join(summary["match_every_accepted_vector"]) or "none")
    return 0


if __name__ == "__main__":
    sys.exit(main())
