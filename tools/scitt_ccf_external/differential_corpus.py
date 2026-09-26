#!/usr/bin/env python3
"""A differential corpus: one-variable mutations of a control statement, registered on a LOCAL
scitt-ccf-ledger, with the full chain per accepted vector and an admissibility matrix of refusals.

WHY. Requested on the SCITT list for adversarial tests, after the acceptance difference measured by
local_ledger_probe.py (a CCF service accepts forms the proofbundle v1 reader refuses, and re-encodes
some of them). Owner order of 2026-09-25.

WHAT. One control: an RFC 9995 hash envelope over the RFC 8785 root of examples/example_bundle.json,
signed ES256 by a signer made for the run (private key discarded). Every other vector changes exactly
one thing against its named base, in six classes:

  a  unprotected-map value changes and additional labels
  b  protected-header bstr framing only (content bytes unchanged)
  c  payload bstr framing only
  d  signature bstr framing only
  e  unprotected-map ordering (base: an a-vector with the same labels in the other order)
  f  separately generated valid signatures over the same signed content

FOR EVERY ACCEPTED VECTOR the record holds: submitted bytes and their SHA-256, the decoded COSE
structure with the framing of every element, the Sig_structure bytes and their SHA-256, the returned
statement bytes, the receipt, the receipt's leaf data-hash, the transaction id, the receipt signature
checked with the service key set, the data-hash candidates it does or does not equal, and the verdict
of the proofbundle v1 reader on the same bytes.

REFUSALS are kept apart, in admissibility.json, with the service's error as returned. A refusal is what
this service did; it is not judged SCITT-invalid here.

PINS, in every record: the service commit, image id, CCF version, the configuration the service
reports, the attestation format of the node (virtual), and the verifier: this repository's commit,
package version and the library versions the run used.

USAGE, against a ledger already running and opened with ``scitt governance local_development``:

    python3 differential_corpus.py --service-cert CERT --ledger-commit SHA --image-id ID \\
        --build-inputs FILE [--url https://127.0.0.1:8000] [--out DIR]

Talks to the given URL only, never through a proxy. Output: differential_corpus/ next to this file.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
OUT = HERE / "differential_corpus"
sys.path.insert(0, str(HERE))
import local_ledger_probe as P  # noqa: E402 - the signer and service client of this directory
import recompute as R  # noqa: E402 - the measuring aid of this directory

B64 = lambda b: base64.b64encode(b).decode("ascii")  # noqa: E731
SHA = lambda b: hashlib.sha256(b).hexdigest()  # noqa: E731
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


# ------------------------------------------------------------------------------------------------
# Encoding pieces
# ------------------------------------------------------------------------------------------------
def head(mt: int, n: int, width: int | None = None) -> bytes:
    """A CBOR head; ``width`` forces the argument width in bytes (1, 2, 4, 8), else shortest."""
    if width is None:
        return R._h(mt, n)
    ai = {1: 24, 2: 25, 4: 26, 8: 27}[width]
    return bytes([(mt << 5) | ai]) + n.to_bytes(width, "big")


def bstr(content: bytes, form: str = "shortest") -> bytes:
    """A byte string with the given framing: shortest, width1/2/4/8, indefinite1, indefinite2."""
    if form == "shortest":
        return head(2, len(content)) + content
    if form.startswith("width"):
        return head(2, len(content), int(form[5:])) + content
    if form == "indefinite1":
        return b"\x5f" + head(2, len(content)) + content + b"\xff"
    if form == "indefinite2":
        k = len(content) // 2
        return (b"\x5f" + head(2, k) + content[:k] + head(2, len(content) - k) + content[k:] + b"\xff")
    raise ValueError(form)


def umap(entries: list) -> bytes:
    """An unprotected map with its entries in exactly the given order."""
    return head(5, len(entries)) + b"".join(R.encode(k) + R.encode(v) for k, v in entries)


def sign1(prot: bytes, unprot: bytes, payload: bytes, sig: bytes) -> bytes:
    return b"\xd2\x84" + prot + unprot + payload + sig


def high_s(sig: bytes) -> bytes:
    """The other valid ECDSA signature over the same message: (r, n - s)."""
    r, s = sig[:32], int.from_bytes(sig[32:], "big")
    return r + (P256_N - s).to_bytes(32, "big")


# ------------------------------------------------------------------------------------------------
# A lenient reader that keeps the framing of every item
# ------------------------------------------------------------------------------------------------
def _hd(b: bytes, i: int):
    ib = b[i]
    mt, ai = ib >> 5, ib & 0x1F
    i += 1
    if ai < 24:
        return mt, ai, i, "argument in the initial byte"
    if ai in (24, 25, 26, 27):
        n = 1 << (ai - 24)
        arg = int.from_bytes(b[i:i + n], "big")
        minimal = (ai == 24 and arg >= 24) or (ai > 24 and arg >= 1 << (8 * (n // 2)))
        return mt, arg, i + n, f"{n}-byte argument, {'shortest' if minimal else 'NOT shortest'}"
    if ai == 31:
        return mt, None, i, "indefinite length"
    raise ValueError(f"additional information {ai} at {i - 1}")


def item(b: bytes, i: int, depth: int = 0):
    """(end, rendering) of one data item, indefinite lengths allowed."""
    if depth > 32:
        raise ValueError("too deep")
    start = i
    mt, arg, i, form = _hd(b, i)
    if mt in (2, 3):
        chunks = []
        if arg is None:
            while b[i] != 0xFF:
                _mt, n, i, _f = _hd(b, i)
                chunks.append(b[i:i + n])
                i += n
            i += 1
        else:
            chunks.append(b[i:i + arg])
            i += arg
        content = b"".join(chunks)
        r = {"type": "bstr" if mt == 2 else "tstr", "framing": form, "chunks": len(chunks),
             "length": len(content)}
        if mt == 2:
            # the bytes themselves are in the record's base64 fields; long ones are named by digest
            r.update(content_sha256=SHA(content))
            if len(content) <= 64:
                r["content_hex"] = content.hex()
        else:
            r["text"] = content.decode("utf-8", "replace")
        r["_content"] = content
        return i, r
    if mt in (0, 1):
        return i, {"type": "int", "framing": form, "value": arg if mt == 0 else -1 - arg}
    if mt in (4, 5):
        out = []
        n = arg
        while (n is None and b[i] != 0xFF) or (n is not None and len(out) < (n if mt == 4 else 2 * n)):
            i, v = item(b, i, depth + 1)
            out.append(v)
        if n is None:
            i += 1
        if mt == 4:
            return i, {"type": "array", "framing": form, "items": out}
        return i, {"type": "map", "framing": form, "entries": [[out[k], out[k + 1]] for k in range(0, len(out), 2)]}
    if mt == 6:
        i, v = item(b, i, depth + 1)
        return i, {"type": "tag", "number": arg, "framing": form, "value": v}
    return i, {"type": "simple", "value": {20: False, 21: True, 22: None}.get(arg, arg), "framing": form,
               "_raw": b[start:i].hex()}


def cose_structure(raw: bytes) -> dict:
    """The decoded COSE_Sign1 with the framing and the span of each of its four elements."""
    i = 0
    tag = None
    mt, arg, j, _f = _hd(raw, 0)
    if mt == 6:
        tag, i = arg, j
    mt, n, j, array_form = _hd(raw, i)
    i = j
    elems, spans = [], []
    for _ in range(4):
        e, v = item(raw, i)
        spans.append([i, e])
        elems.append(v)
        i = e
    if n is None:
        i += 1
    names = ("protected", "unprotected", "payload", "signature")
    out = {"tag": tag, "array_framing": array_form, "trailing_bytes": len(raw) - i}
    for name, v, sp in zip(names, elems, spans):
        v = dict(v)
        v["span"] = sp
        v["element_hex_head"] = raw[sp[0]:sp[0] + 9].hex()
        out[name] = v
    prot = elems[0].get("_content")
    if prot:
        _e, pv = item(prot, 0)
        out["protected"]["decoded"] = _strip(pv)
    return _strip(out)


def _strip(v):
    if isinstance(v, dict):
        return {k: _strip(x) for k, x in v.items() if not k.startswith("_")}
    if isinstance(v, list):
        return [_strip(x) for x in v]
    return v


def contents(raw: bytes) -> tuple:
    """(protected content, payload content, signature content, element byte spans)."""
    i = 0
    mt, arg, j, _f = _hd(raw, 0)
    if mt == 6:
        i = j
    _mt, _n, i, _f = _hd(raw, i)
    vals, spans = [], []
    for _ in range(4):
        e, v = item(raw, i)
        vals.append(v)
        spans.append((i, e))
        i = e
    return vals[0].get("_content"), vals[2].get("_content"), vals[3].get("_content"), spans


# ------------------------------------------------------------------------------------------------
# The vectors
# ------------------------------------------------------------------------------------------------
def vectors(key, chain, did, payload: bytes) -> list:
    prot_map = {1: -7, 15: {1: did, 2: "proofbundle differential corpus"}, 33: chain,
                258: -16, 259: "application/json"}
    prot = R.encode(prot_map)
    tbs = R.sig_structure(prot, payload)
    sig = P.sign(key, tbs)
    ctl = sign1(bstr(prot), b"\xa0", bstr(payload), bstr(sig))
    v = [("control", "control", None, "the v1 shape: tagged, definite, shortest, embedded payload, empty unprotected", ctl),
         ("control-resubmitted", "control", "control", "the control's bytes submitted a second time (zero changes; a reference)", ctl)]

    def a(vid, entries, what):
        v.append((vid, "a", "control", what, sign1(bstr(prot), umap(entries), bstr(payload), bstr(sig))))
    a("a01-label-99-text", [(99, "probe")], "unprotected label 99 added, a text value")
    a("a02-label-99-other-text", [(99, "other")], "unprotected label 99 added, another text value")
    a("a03-label-99-bstr", [(99, b"\x00")], "unprotected label 99 added, a byte string value")
    a("a04-label-99-int", [(99, 0)], "unprotected label 99 added, an integer value")
    a("a05-text-label", [("x", 1)], "unprotected text label 'x' added")
    a("a06-negative-label", [(-70000, 1)], "unprotected label -70000 added")
    a("a07-kid", [(4, b"kid")], "unprotected kid (4) added")
    a("a08-receipts-label", [(394, [b"\x00"])], "unprotected receipts label (394) added with one junk entry")
    a("a09-x5chain-both-buckets", [(33, chain)], "x5chain (33) also in the unprotected bucket")
    a("a10-cwt-claims-unprotected", [(15, {1: "did:example:spoofed"})], "CWT claims (15) with another issuer in the unprotected bucket")
    a("a11-two-labels", [(99, "a"), (100, "b")], "unprotected labels 99 and 100 added, in ascending order")
    a("a12-int-and-text-labels", [(99, "a"), ("x", 1)], "unprotected labels 99 and 'x' added, integer first")
    a("a13-negative-after-positive", [(10, 0), (-10, 0)], "unprotected labels 10 and -10 added, in canonical order")

    def e(vid, base, entries, what):
        v.append((vid, "e", base, what, sign1(bstr(prot), umap(entries), bstr(payload), bstr(sig))))
    e("e01-two-labels-reversed", "a11-two-labels", [(100, "b"), (99, "a")], "the labels of a11 in descending order")
    e("e02-text-label-first", "a12-int-and-text-labels", [("x", 1), (99, "a")], "the labels of a12, text label first")
    e("e03-negative-first", "a13-negative-after-positive", [(-10, 0), (10, 0)], "the labels of a13, -10 first")

    for cls, idx, what in (("b", 0, "protected"), ("c", 2, "payload"), ("d", 3, "signature")):
        parts = [prot, None, payload, sig]
        n = len(parts[idx])
        shortest = 0 if n < 24 else 1 if n < 256 else 2 if n < 65536 else 4
        forms = [f"width{w}" for w in (1, 2, 4, 8) if w > shortest] + ["indefinite1", "indefinite2"]
        for k, form in enumerate(forms, start=1):
            elems = [bstr(parts[0]), b"\xa0", bstr(parts[2]), bstr(parts[3])]
            elems[idx] = bstr(parts[idx], form)
            label = (f"a {form[5:]}-byte length argument, {n} bytes of content" if form.startswith("width")
                     else {"indefinite1": "indefinite length, one chunk",
                           "indefinite2": "indefinite length, two chunks"}[form])
            v.append((f"{cls}{k:02d}-{form}", cls, "control", f"the {what} byte string with {label}", sign1(*elems)))

    sig2, sig3 = P.sign(key, tbs), P.sign(key, tbs)
    for vid, s, what in (("f01-second-signature", sig2, "a second ES256 signature by the same key over the same Sig_structure"),
                         ("f02-third-signature", sig3, "a third ES256 signature by the same key over the same Sig_structure"),
                         ("f03-high-s-twin", high_s(sig), "the control's signature with s replaced by n - s, made without the key")):
        v.append((vid, "f", "control", what, sign1(bstr(prot), b"\xa0", bstr(payload), bstr(s))))
    return v


# ------------------------------------------------------------------------------------------------
# The run
# ------------------------------------------------------------------------------------------------
def _git(*args) -> str:
    return subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True).stdout.strip()


def pins(args, svc) -> dict:
    import cryptography
    from importlib.metadata import version
    code, _h, cfg = svc.call("GET", "/configuration")
    code_v, _h, ver = svc.call("GET", "/node/version")
    code_q, _h, quote = svc.call("GET", "/node/quotes/self")
    q = json.loads(quote) if code_q == 200 else {}
    return {
        "service": {"repository": "https://github.com/microsoft/scitt-ccf-ledger", "commit": args.ledger_commit,
                    "image_id": args.image_id, "url": args.url,
                    "node_version": json.loads(ver) if code_v == 200 else f"HTTP {code_v}",
                    "configuration": json.loads(cfg) if code == 200 else f"HTTP {code}",
                    "attestation_format": q.get("format"),
                    "mode": "virtual (no TEE), single node, opened with `scitt governance local_development`",
                    "image_build_inputs_sha256": SHA(Path(args.build_inputs).read_bytes())
                    if args.build_inputs else None},
        "verifier": {"repository": "https://github.com/b7n0de/proofbundle", "commit": _git("rev-parse", "HEAD"),
                     "tree_clean": _git("status", "--porcelain") == "", "package_version": version("proofbundle"),
                     "reader": "proofbundle.scitt_ccf (scitt-ccf/v1)", "tool": "tools/scitt_ccf_external/differential_corpus.py",
                     "python": platform.python_version(), "cbor2": version("cbor2"),
                     "cryptography": cryptography.__version__},
    }


def v1_reader(raw: bytes, *, transparent: bool, root: bytes, rp: dict) -> dict:
    from proofbundle import scitt_ccf as S
    if transparent:
        r = S.verify_transparent_statement(raw, canonical_root=root, rp_trust=rp)
        return {"status": r.status, "detail": r.detail[:200]}
    try:
        S.decode_cose_sign1(raw, role="statement")
        return {"status": "read", "detail": "decode_cose_sign1 reads the submitted statement"}
    except S.ScittFormatError as exc:
        return {"status": exc.status, "detail": str(exc)[:200]}


def record(vec, rec, keyset, pinned, root, rp, control_dh) -> dict:
    vid, cls, base, what, sub = vec
    out = {"id": vid, "class": cls, "base": base, "mutation": what, "pins": pinned,
           "request": {"bytes_b64": B64(sub), "sha256": SHA(sub), "length": len(sub),
                       "decoded": cose_structure(sub)},
           "v1_reader_on_submitted_bytes": v1_reader(sub, transparent=False, root=root, rp=rp),
           "service": {"post_status": rec.get("post_status"), "accepted": bool(rec.get("accepted"))}}
    pc, plc, sgc, sub_spans = contents(sub)
    tbs = R.sig_structure(pc, plc if plc is not None else b"")
    out["sig_structure"] = {"bytes_b64": B64(tbs), "sha256": SHA(tbs)}
    if not rec.get("accepted"):
        out["service"]["error"] = rec.get("error")
        return out
    out["service"]["txid"] = rec.get("txid")
    receipt, served = rec.get("receipt"), rec.get("transparent_statement")
    if receipt is None or served is None:
        out["service"]["incomplete"] = rec.get("error", "no receipt or no statement")
        return out
    rr = R.receipt(receipt, keyset, None)
    leaf_dh = rr["inclusion_proofs"][0]["data_hash"] if rr.get("inclusion_proofs") else None
    ps, pls, sgs, sspans = contents(served)
    stored_elems = [served[a:b] for a, b in sspans]
    sub_elems = [sub[a:b] for a, b in sub_spans]
    cands = {
        "sha256(submitted bytes)": SHA(sub),
        "sha256(returned statement bytes)": SHA(served),
        "sha256(returned elements as served, unprotected emptied, tag 18)":
            SHA(b"\xd2\x84" + stored_elems[0] + b"\xa0" + stored_elems[2] + stored_elems[3]),
        "sha256(submitted elements as submitted, unprotected emptied, tag 18)":
            SHA(b"\xd2\x84" + sub_elems[0] + b"\xa0" + sub_elems[2] + sub_elems[3]),
        "sha256(contents re-encoded shortest and definite, unprotected emptied, tag 18)":
            SHA(b"\xd2\x84" + bstr(pc) + b"\xa0" + (bstr(plc) if plc is not None else b"\xf6") + bstr(sgc)),
        "sha256(Sig_structure)": SHA(tbs),
    }
    out["response"] = {
        "txid": rec["txid"], "receipt_b64": B64(receipt), "receipt_sha256": SHA(receipt),
        "receipt_signature_valid_with_service_keyset": rr["signature_valid"],
        "receipt_leaf_data_hash": leaf_dh,
        "returned_statement_b64": B64(served), "returned_statement_sha256": SHA(served),
        "returned_statement_decoded": cose_structure(served),
        "returned_elements_equal_submitted_elements": {
            name: stored_elems[k] == sub_elems[k] for k, name in ((0, "protected"), (2, "payload"), (3, "signature"))},
        "returned_unprotected_labels": [str(e[0].get("value", e[0].get("text"))) for e in
                                        cose_structure(served)["unprotected"].get("entries", [])],
        "returned_embedded_receipt_equals_served_receipt": _embedded_receipt(served) == receipt,
        "returned_contents_equal_submitted_contents": (ps, pls, sgs) == (pc, plc, sgc),
        "data_hash_candidates": {k: {"sha256": h, "equals_receipt_data_hash": h == leaf_dh} for k, h in cands.items()},
        "receipt_data_hash_equals_control": leaf_dh == control_dh if control_dh else None,
        "v1_reader_on_returned_transparent_statement": v1_reader(served, transparent=True, root=root, rp=rp),
    }
    return out


def _embedded_receipt(served: bytes):
    """The first receipt under label 394 of a returned statement, as bytes, or None."""
    import cbor2
    body = cbor2.loads(served)
    body = body.value if hasattr(body, "value") else body
    receipts = body[1].get(394) if hasattr(body[1], "get") else None
    return bytes(receipts[0]) if receipts else None


def conclusions(records: list) -> dict:
    """What the receipt data-hash commits to, as far as these mutations decide it."""
    by = {r["id"]: r for r in records}

    def acc(r):
        return r["service"]["accepted"] and "response" in r

    def dh(r):
        return r["response"]["receipt_leaf_data_hash"]
    ctl = by["control"]
    out = {}
    for cls, name in (("a", "the unprotected map's labels and values"), ("b", "the framing of the protected bstr"),
                      ("c", "the framing of the payload bstr"), ("d", "the framing of the signature bstr"),
                      ("e", "the order of the unprotected map"), ("f", "the signature bytes, the signed content unchanged")):
        rs = [r for r in records if r["class"] == cls]
        accepted = [r for r in rs if acc(r)]
        pairs = [(r["id"], dh(r) == dh(by[r["base"]]) if acc(by[r["base"]]) else None) for r in accepted]
        same = [p for p, eq in pairs if eq is True]
        differ = [p for p, eq in pairs if eq is False]
        if not accepted:
            verdict = (f"NOT MEASURABLE: the service refused every {cls}-vector, so no receipt shows whether "
                       f"the data-hash commits to {name}")
        elif differ and not same:
            verdict = f"commits to {name}: every accepted {cls}-vector has a data-hash other than its base"
        elif same and not differ:
            verdict = (f"does not commit to {name}, as far as the {len(same)} accepted vectors go: each has its "
                       f"base's data-hash")
        else:
            verdict = f"mixed: equal to the base for {same}, different for {differ}"
        out[cls] = {"about": name, "vectors": len(rs), "accepted": len(accepted), "refused": len(rs) - len(accepted),
                    "same_data_hash_as_base": same, "other_data_hash_than_base": differ, "verdict": verdict}
    if acc(by["control-resubmitted"]) and acc(ctl):
        out["control"] = {"identical bytes twice": "same data-hash" if dh(by["control-resubmitted"]) == dh(ctl)
                          else "different data-hash",
                          "txids": [ctl["response"]["txid"], by["control-resubmitted"]["response"]["txid"]]}
    rule = "sha256(returned elements as served, unprotected emptied, tag 18)"
    out["measured_rule_holds_for_every_accepted_vector"] = all(
        r["response"]["data_hash_candidates"][rule]["equals_receipt_data_hash"] for r in records if acc(r))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="A differential corpus on a local scitt-ccf-ledger.")
    ap.add_argument("--url", default="https://127.0.0.1:8000")
    ap.add_argument("--service-cert", required=True, type=Path)
    ap.add_argument("--ledger-commit", required=True)
    ap.add_argument("--image-id", required=True)
    ap.add_argument("--build-inputs", type=Path)
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args(argv)

    from proofbundle.anchors import receipt_canonical_root
    bundle = json.loads(P.BUNDLE.read_text(encoding="utf-8"))
    root = receipt_canonical_root({k: v for k, v in bundle.items() if k != "anchors"})
    svc = P.Service(args.url, args.service_cert)
    code, _h, keys_raw = svc.call("GET", "/.well-known/scitt-keys")
    if code != 200:
        print(f"NOT MEASURABLE: the service did not serve its keys ({code}).", file=sys.stderr)
        return 2
    keyset = R.cose_keyset(keys_raw)
    from proofbundle import scitt_ccf as S
    pinned = pins(args, svc)
    key, chain, did, spki = P.make_signer()
    rp = {"scitt_ccf_services": {"127.0.0.1:8000": S.load_cose_keyset(keys_raw)}, "scitt_statement_keys": [spki]}
    vecs = vectors(key, chain, did, root)

    records, control_dh = [], None
    for vec in vecs:
        rec = svc.register(vec[4])
        r = record(vec, rec, keyset, pinned, root, rp, control_dh)
        if vec[0] == "control" and "response" in r:
            control_dh = r["response"]["receipt_leaf_data_hash"]
        records.append(r)
        print(f"  {vec[0]:32s} {r['service']['post_status']} accepted={r['service']['accepted']!s:5} "
              f"{(r.get('response') or {}).get('txid', '')}")

    out = args.out
    if out.exists():
        shutil.rmtree(out / "vectors", ignore_errors=True)
    (out / "vectors").mkdir(parents=True, exist_ok=True)
    for r in records:
        (out / "vectors" / f"{r['id']}.json").write_text(json.dumps(r, indent=1) + "\n", encoding="utf-8")
    matrix = [{"id": r["id"], "class": r["class"], "base": r["base"], "mutation": r["mutation"],
               "submitted_sha256": r["request"]["sha256"], "post_status": r["service"]["post_status"],
               "service_error": r["service"].get("error"), "v1_reader_on_submitted_bytes": r["v1_reader_on_submitted_bytes"],
               "file": f"vectors/{r['id']}.json"} for r in records if not r["service"]["accepted"]]
    (out / "admissibility.json").write_text(json.dumps({
        "note": "Refusals of this service, as returned. A refusal is what this service did with the bytes; it is "
                "not judged SCITT-invalid here.", "pins": pinned, "refused": matrix}, indent=1) + "\n", encoding="utf-8")
    summary = {
        "tool": "tools/scitt_ccf_external/differential_corpus.py", "measured_on": datetime.date.today().isoformat(),
        "pins": pinned, "service_keyset_b64": B64(keys_raw), "service_keyset_sha256": SHA(keys_raw),
        "image_build_inputs": (json.loads(Path(args.build_inputs).read_text(encoding="utf-8"))
                               if args.build_inputs else None),
        "signer": {"did": did, "spki_b64": B64(spki), "alg": "ES256", "note": "made for this run, private key discarded"},
        "target": {"bundle": str(P.BUNDLE.relative_to(REPO)), "receipt_canonical_root": root.hex()},
        "vectors": [{"id": r["id"], "class": r["class"], "base": r["base"], "accepted": r["service"]["accepted"],
                     "txid": (r.get("response") or {}).get("txid"),
                     "data_hash": (r.get("response") or {}).get("receipt_leaf_data_hash"),
                     "returned_elements_equal_submitted": (r.get("response") or {}).get(
                         "returned_elements_equal_submitted_elements"),
                     "v1_reader_on_submitted_bytes": r["v1_reader_on_submitted_bytes"]["status"],
                     "v1_reader_on_returned": ((r.get("response") or {}).get(
                         "v1_reader_on_returned_transparent_statement") or {}).get("status")} for r in records],
        "what_the_data_hash_commits_to": conclusions(records),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(summary["what_the_data_hash_commits_to"], indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
