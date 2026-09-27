#!/usr/bin/env python3
"""The shared vectors of `verify_consistency_receipt`, run by the Python and the Rust verifier.

WHAT IT WRITES. tests/fixtures/scitt_consistency_receipt/vectors.json: CCF consistency receipts
(draft-ietf-scitt-receipts-ccf-profile-05, section 4), the older root and older issuer each is checked
against, the relying-party trust, and the verdict each vector is built to produce.
tests/test_scitt_consistency_receipt_parity.py runs both verifiers over every vector and
tools/pb_verify_rs/crosscheck.py runs them in CI. Both hold the two verifiers to each other on every
field of the result but the prose (`detail`), and to the built verdict.

WHERE THE BYTES COME FROM.
- Real, from a foreign tool: tests/fixtures/scitt_ccf/local_ledger_consistency.json, three signed
  states of one local scitt-ccf-ledger (00101f76, CCF 7.0.17), written by consistency_probe.py on
  2026-09-25. No service measured emits a consistency receipt, so the receipts here are the service's
  own COSE_Sign1 over the newer root, taken from its newer inclusion receipt, with proofs the probe
  computed from the ledger's leaves (own implementation) in the unprotected header, which no signature
  covers. The roots of the three states are the ones the fixture recorded from the ledger; each is
  also the root the Python verifier confirms for that state's Transparent Statement, checked here
  before a vector is written. They are named by field, not copied.
- Synthetic: throwaway service keys made here and never stored (P-256 and P-384), a tree of 40 leaf
  hashes, the -05 proofs of section 4 built by consistency_probe.Tree from RFC 9162 section 2.1.4.1,
  and receipts built byte by byte for every rule of the receipt pass and of the status logic.

THE ORACLE. Every vector carries the verdict it is designed to produce. The generator refuses to write
the file unless the Python verifier returns exactly that for every vector; the Rust verifier is held
to the same, and to Python on every other field.

FORM. As in transparent_statement_vectors.py, whose reading of parts, refs and trust this file uses:
a byte string is a list of parts, a trust document is in the form `pb_verify_rs` reads, and named
trust documents are under `trusts`. `older_issuer` is text, as the Rust command line takes it.

Usage:  PYTHONPATH=src python tools/scitt_ccf_external/consistency_receipt_vectors.py [--check]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(HERE))
from proofbundle import scitt_ccf as C  # noqa: E402
from proofbundle._cbor_prescan import scan  # noqa: E402
from proofbundle._wire_b64 import decode_b64  # noqa: E402  (the one strict base64 decoder tools may use)
from consistency_probe import Tree  # noqa: E402
from statement_signature_vectors import bstr, uint  # noqa: E402
from transparent_statement_vectors import (  # noqa: E402
    FALSE, NIL, TRUE, Builder as TransparentBuilder, arr, assemble, cmap, dump, python_trust, resolve, text)

OUT = ROOT / "tests" / "fixtures" / "scitt_consistency_receipt" / "vectors.json"
LEDGER = "tests/fixtures/scitt_ccf/local_ledger_consistency.json"
ISSUER = "svc.example"
H = lambda b: hashlib.sha256(b).digest()  # noqa: E731
FIELDS = ("status", "readable", "signature_valid", "older_root_matches", "newer_root", "proofs", "issuer",
          "kid", "kid_bound_to_key", "receipt_iat", "ccf_txid", "inclusion_proofs_present")


# -- the shared reading of the file (the parity test and crosscheck.py carry the same few lines) --------
def trust_of(doc: dict, v: dict):
    """The vector's trust document with refs resolved, or None when the vector passes no trust."""
    if "trust" not in v:
        return None
    t = v["trust"]
    return resolve(doc["trusts"][t] if isinstance(t, str) else t["inline"], doc["refs"])


def python_result(doc: dict, v: dict) -> dict:
    """Python's result as `to_dict()`, with the prose left out."""
    trust = trust_of(doc, v)
    r = C.verify_consistency_receipt(assemble(v["receipt"], doc["refs"]),
                                     older_root=assemble(v["older_root"], doc["refs"]),
                                     older_issuer=v["older_issuer"],
                                     rp_trust=None if trust is None else python_trust(trust)).to_dict()
    r.pop("detail")
    return r


def observed(r: dict) -> dict:
    """The fields a vector's `want` may name, read from a result in `to_dict()` form."""
    return {k: r[k] for k in FIELDS}


def mismatch(want: dict, got: dict) -> dict:
    seen = observed(got)
    return {k: (w, seen[k]) for k, w in want.items() if seen[k] != w}


# -- the builder --------------------------------------------------------------------------------------
class Builder(TransparentBuilder):
    """Consistency receipts byte by byte, over the transparent builder's service keys and CBOR."""

    def __init__(self):
        super().__init__()
        self.refs = {k: v for k, v in self.refs.items() if k.startswith("spki_svc_")}
        self.tree = Tree([H(b"proofbundle consistency vectors" + i.to_bytes(4, "big")) for i in range(40)])
        self.signatures: dict = {}

    def svc_sign(self, name: str, tbs: bytes) -> bytes:
        """One signature per key and ToBeSigned: an ECDSA signature differs on every call, and the
        receipts that share their header and newer root then share their bytes."""
        if (name, tbs) not in self.signatures:
            self.signatures[(name, tbs)] = super().svc_sign(name, tbs)
        return self.signatures[(name, tbs)]

    @staticmethod
    def proof(anchor: bytes, path: list) -> bytes:
        return cmap([(uint(1), bstr(anchor)),
                     (uint(2), arr([arr([TRUE if left else FALSE, bstr(sib)]) for left, sib in path]))])

    def pair(self, m: int, n: int) -> bytes:
        return self.proof(*self.tree.proof05(m, n))

    def crec(self, proofs: list | None = None, *, n: int = 24, m: int = 13, vdp: bytes | None = None,
             inclusion: list | None = None, sign_root: bytes | None = None, **kw) -> bytes:
        """A consistency receipt; by default one proof from size m to size n, signed over the root of n.
        Every other element can be replaced as in the transparent builder's `receipt`."""
        if vdp is None:
            fam = [(uint(-2), arr([bstr(p) if isinstance(p, bytes) else p.raw
                                   for p in (proofs if proofs is not None else [self.pair(m, n)])]))]
            if inclusion is not None:
                fam.insert(0, (uint(-1), arr([bstr(p) for p in inclusion])))
            vdp = cmap(fam)
        kw.setdefault("txid", text("2.24"))
        return self.receipt(b"", vdp=vdp, inclusion=[], sign_root=self.tree.root(n) if sign_root is None
                            else sign_root, **kw)

    def add(self, vid: str, what: str, receipt, older, want: dict, *, issuer: str = ISSUER, trust="syn",
            origin: str = "synthetic") -> None:
        v = {"id": vid, "what": what, "origin": origin,
             "receipt": receipt if isinstance(receipt, list) else self.compress(receipt),
             "older_root": older if isinstance(older, list) else [older.hex()],
             "older_issuer": issuer, "want": want}
        if trust is not None:
            v["trust"] = trust
        self.vectors.append(v)


class _Raw:
    """An element inserted into an array as it is, not wrapped in a byte string."""

    def __init__(self, raw: bytes):
        self.raw = raw


def want(status: str, **kw) -> dict:
    out = {"status": status}
    out.update(kw)
    return out


def confirmed(**kw) -> dict:
    return want("confirmed", readable=True, signature_valid=True, older_root_matches=True, **kw)


def malformed(**kw) -> dict:
    return want("malformed", readable=False, signature_valid=None, older_root_matches=None, newer_root=None,
                proofs=0, issuer=None, **kw)


# ---------------------------------------------------------------------------------------------------
# Real vectors
# ---------------------------------------------------------------------------------------------------
def _cose(data: bytes) -> list:
    """The four elements of a tagged COSE_Sign1, decoded."""
    import cbor2  # noqa: PLC0415
    return cbor2.loads(data).value


def _parts_of(receipt: bytes) -> tuple:
    """(protected element, signature element) of a tagged COSE_Sign1, as served."""
    sc = scan(receipt, max_bytes=len(receipt), max_depth=16, tag_allowed=lambda path, n: n == 18)
    (pa, pe), _u, _p, (sa, se) = sc.element_spans
    return receipt[pa:pe], receipt[sa:se]


def real_vectors(b: Builder) -> None:
    doc = json.loads((ROOT / LEDGER).read_text(encoding="utf-8"))
    issuer = doc["issuer"]
    keys = C.load_cose_keyset(decode_b64(doc["service_keyset_b64"]))
    entries = []
    for i, k in enumerate(keys):
        b.refs[f"spki_ledger_{i}"] = k["spki"].hex()
        entries.append({"spki": {"ref": f"spki_ledger_{i}"}, "kid": k["kid"].hex()} if k["kid"] is not None
                       else {"ref": f"spki_ledger_{i}"})
    b.trusts["ledger"] = {"scitt_ccf_services": {issuer: entries}}
    b.trusts["ledger-statement-keys-only"] = {
        "scitt_statement_keys": [decode_b64(doc["statement_signer_spki_b64"]).hex()]}

    # The roots the fixture recorded from the ledger are the roots Python confirms for each state.
    rp = {"scitt_ccf_services": {issuer: keys}, "scitt_statement_keys": [decode_b64(doc["statement_signer_spki_b64"])]}
    roots, receipts = {}, {}
    for name, s in doc["states"].items():
        statement = decode_b64(s["transparent_statement_b64"])
        r = C.verify_transparent_statement(statement, canonical_root=bytes.fromhex(doc["canonical_root_hex"]),
                                           rp_trust=rp)
        assert r.status == "confirmed" and r.receipts[0].merkle_root.hex() == s["root_hex"], name
        roots[name] = bytes.fromhex(s["root_hex"])
        receipts[name] = _cose(statement)[1][394][0]
    newer = decode_b64(doc["newer_receipt_b64"])
    assert newer == receipts["newer"]
    prot, sig = _parts_of(newer)
    b.blob("blob_ledger_newer_protected", prot)
    b.blob("blob_ledger_newer_signature", sig)
    proofs = {k.replace("->", "_to_"): decode_b64(p) for k, p in doc["proofs_b64"].items()}
    proofs["deeper"] = decode_b64(doc["deeper_anchor_proof_b64"])
    for k, p in proofs.items():
        b.blob(f"blob_ledger_proof_{k}", bstr(p))
    inclusion = {name: _cose(r)[1][396][-1] for name, r in receipts.items()}
    for name, family in inclusion.items():
        b.blob(f"blob_ledger_inclusion_{name}", arr([bstr(p) for p in family]))

    def rewrap(names: list, *, payload: bytes = NIL, beside: str | None = None) -> bytes:
        """The service's own COSE_Sign1 over the newer root, its unprotected header replaced (the
        consistency_probe.py construction): vdp -2 holds the named proofs, and -1 the inclusion proofs
        of the state `beside`, if given."""
        fam = [(uint(-1), arr([bstr(p) for p in inclusion[beside]]))] if beside else []
        fam.append((uint(-2), arr([bstr(proofs[n]) for n in names])))
        return b"\xd2\x84" + prot + cmap([(uint(396), cmap(fam))]) + payload + sig

    ledger = f"scitt-ccf-ledger {doc['ledger_commit'][:8]}, {LEDGER}"
    real = {"origin": ledger, "trust": "ledger"}
    newer_hex = roots["newer"].hex()
    ok = dict(newer_root=newer_hex, issuer=issuer, ccf_txid=doc["states"]["newer"]["txid"])
    b.add("r01-served-control", "the fixture's consistency receipt, 19 -> 24, against the older state's root",
          [{"fixture": LEDGER, "field": "consistency_receipt_b64"}], roots["older"],
          confirmed(proofs=1, kid_bound_to_key=True, inclusion_proofs_present=False, **ok), issuer=issuer, **real)
    b.add("r02-19-to-24", "the 19 -> 24 proof under the service's signature over the newer root",
          rewrap(["19_to_24"]), roots["older"], confirmed(proofs=1, **ok), issuer=issuer, **real)
    b.add("r03-22-to-24", "the 22 -> 24 proof against the middle state's root",
          rewrap(["22_to_24"]), roots["middle"], confirmed(proofs=1, **ok), issuer=issuer, **real)
    b.add("r04-19-to-24-held-middle", "the 19 -> 24 proof against the middle state's root",
          rewrap(["19_to_24"]), roots["middle"],
          want("consistency_older_root_mismatch", older_root_matches=False, signature_valid=True, **ok),
          issuer=issuer, **real)
    b.add("r05-19-to-22", "the 19 -> 22 proof: the middle root is not what the service signed here",
          rewrap(["19_to_22"]), roots["older"],
          want("signature_invalid", older_root_matches=True, signature_valid=False, kid_bound_to_key=None,
               newer_root=roots["middle"].hex()), issuer=issuer, **real)
    for held in ("older", "middle"):
        b.add(f"r06-both-proofs-held-{held}", f"19 -> 24 and 22 -> 24 against the {held} state's root",
              rewrap(["19_to_24", "22_to_24"]), roots[held], confirmed(proofs=2, **ok), issuer=issuer, **real)
    b.add("r07-newer-roots-differ", "19 -> 24 and 19 -> 22 in one receipt",
          rewrap(["19_to_24", "19_to_22"]), roots["older"],
          want("consistency_newer_roots_differ", older_root_matches=None, signature_valid=None, proofs=2, **ok),
          issuer=issuer, **real)
    b.add("r08-deeper-anchor", "a proof whose anchor is below the one section 4 requires",
          rewrap(["deeper"]), roots["middle"], want("consistency_anchor_not_canonical", signature_valid=True,
                                                    **ok), issuer=issuer, **real)
    b.add("r09-other-issuer", "the served receipt, the older root taken from another service's receipt",
          [{"fixture": LEDGER, "field": "consistency_receipt_b64"}], roots["older"],
          want("consistency_issuer_mismatch", older_root_matches=True, signature_valid=True, **ok),
          issuer="127.0.0.1:8001", **real)
    b.add("r10-no-trust", "the served receipt without relying-party trust",
          [{"fixture": LEDGER, "field": "consistency_receipt_b64"}], roots["older"],
          want("needs_rp_trust", older_root_matches=True, signature_valid=None, **ok),
          issuer=issuer, origin=ledger, trust=None)
    b.add("r11-statement-keys-only", "the served receipt under trust with statement keys and no service",
          [{"fixture": LEDGER, "field": "consistency_receipt_b64"}], roots["older"],
          want("needs_rp_trust", signature_valid=None, **ok), issuer=issuer, origin=ledger,
          trust="ledger-statement-keys-only")
    b.add("r12-held-the-newer-root", "the served receipt against the newer root itself",
          [{"fixture": LEDGER, "field": "consistency_receipt_b64"}], roots["newer"],
          want("consistency_older_root_mismatch", older_root_matches=False, **ok), issuer=issuer, **real)
    b.add("r13-inclusion-receipt", "the newer inclusion receipt the ledger served, read as a consistency receipt",
          [{"fixture": LEDGER, "field": "newer_receipt_b64"}], roots["older"],
          want("consistency_proof_missing", readable=False, proofs=0, inclusion_proofs_present=True,
               newer_root=None, issuer=issuer), issuer=issuer, **real)
    b.add("r14-inclusion-beside", "19 -> 24 beside the newer receipt's own inclusion proof",
          rewrap(["19_to_24"], beside="newer"), roots["older"],
          confirmed(proofs=1, inclusion_proofs_present=True, **ok), issuer=issuer, **real)
    b.add("r15-older-inclusion-beside", "19 -> 24 beside the older receipt's inclusion proof, another root",
          rewrap(["19_to_24"], beside="older"), roots["older"],
          want("consistency_newer_roots_differ", inclusion_proofs_present=True, **ok), issuer=issuer, **real)
    b.add("r16-payload-attached", "19 -> 24 with the newer root attached as payload",
          rewrap(["19_to_24"], payload=bstr(roots["newer"])), roots["older"],
          want("consistency_payload_attached", readable=True, newer_root=None), issuer=issuer, **real)


# ---------------------------------------------------------------------------------------------------
# Synthetic vectors
# ---------------------------------------------------------------------------------------------------
def synthetic_vectors(b: Builder) -> None:
    t = b.tree
    b.trusts["syn"] = {"scitt_ccf_services": {ISSUER: [{"ref": "spki_svc_p256"}, {"ref": "spki_svc_p384"}]}}
    r13, r24 = t.root(13), t.root(24)
    ok = dict(newer_root=r24.hex(), issuer=ISSUER, ccf_txid="2.24", receipt_iat=1790000000)
    kid = b.kid("svc_p256").hex()
    good = b.pair(13, 24)
    base = b.crec()
    # Stored once: the control's protected header, its signature and its proof, which most vectors carry.
    for name, blob in zip(("blob_control_protected", "blob_control_signature"), _parts_of(base)):
        b.blob(name, blob)
    b.blob("blob_control_proof", bstr(good))
    b.blob("blob_kid_p256", bstr(b.kid("svc_p256")))

    # -- the control, and pairs: every pair up to 6 and a few beyond -----------------------------------
    b.add("s01-control", "13 -> 24, P-256 service key, every field", b.crec(), r13,
          confirmed(proofs=1, kid=kid, kid_bound_to_key=True, inclusion_proofs_present=False, **ok))
    b.add("s02-p384", "13 -> 24 under the P-384 service key, alg -35",
          b.crec(key="svc_p384", alg=-35), r13, confirmed(kid=b.kid("svc_p384").hex(), kid_bound_to_key=True))
    pairs = [(m, n) for n in range(2, 7) for m in range(1, n)] + [
        (8, 9), (16, 17), (1, 24), (19, 24), (22, 24), (23, 24), (31, 40), (32, 40), (39, 40)]
    for m, n in pairs:
        b.add(f"p-{m}-{n}", f"the section 4 proof from size {m} to size {n}", b.crec(m=m, n=n), t.root(m),
              confirmed(newer_root=t.root(n).hex()))
    for m, n in ((3, 8), (6, 8), (12, 24), (13, 24), (20, 24), (28, 40)):
        for j, (anchor, path) in enumerate(t.deeper(m, n)):
            b.add(f"d-{m}-{n}-{j}", f"a deeper anchor on the right edge of size {m}, {n}: both folds reach "
                  "the right roots, the first sibling is on the left", b.crec([b.proof(anchor, path)], m=m, n=n),
                  t.root(m), want("consistency_anchor_not_canonical", older_root_matches=True,
                                  signature_valid=True, newer_root=t.root(n).hex()))

    # -- the CDDL pass of the receipt: malformed, never readable ---------------------------------------
    b.add("m01-empty", "no bytes", b"", r13, malformed())
    b.add("m02-junk", "not CBOR", b"not cbor \xff", r13, malformed())
    b.add("m03-trailing", "a byte after the receipt", base + b"\x00", r13, malformed())
    b.add("m04-tag-19", "tag 19 around the receipt", b"\xd3" + base[1:], r13, malformed())
    b.add("m05-three-elements", "a COSE_Sign1 of three elements", b"\xd2\x83" + base[2:-66], r13, malformed())
    b.add("m06-a-text-receipt", "a text string", text("a receipt"), r13, malformed())
    prot_pairs = [(uint(1), uint(-7)), (uint(4), bstr(b.kid("svc_p256"))),
                  (uint(15), cmap([(uint(1), text(ISSUER)), (uint(6), uint(1790000000))])), (uint(395), b"\x02"),
                  (text("ccf.v1"), cmap([(text("txid"), text("2.24"))]))]

    def pp(**swap) -> list:
        """The protected pairs with the label named by its number swapped (None drops it)."""
        out = []
        for k, v in prot_pairs:
            name = {uint(1): "alg", uint(4): "kid", uint(15): "cwt", uint(395): "vds"}.get(k, "ccf")
            if name in swap:
                if swap[name] is not None:
                    out.append((k, swap[name]))
            else:
                out.append((k, v))
        return out

    # A receipt the pass refuses, or holds outside the profile, never reaches its signature: zeros.
    b.zero_signatures = True
    for vid, what, rc in (
        ("m07-alg-bool", "alg is true", b.crec(prot_pairs=pp(alg=TRUE))),
        ("m08-crit-empty", "crit is an empty array", b.crec(extra_prot=[(uint(2), arr([]))])),
        ("m09-crit-bytes-label", "crit holds a byte string", b.crec(extra_prot=[(uint(2), arr([bstr(b"x")]))])),
        ("m10-cty-negative", "content type is a negative integer", b.crec(extra_prot=[(uint(3), uint(-1))])),
        ("m11-kid-text", "kid is text", b.crec(prot_pairs=pp(kid=text(kid)))),
        ("m12-cwt-not-map", "the CWT claims are an array", b.crec(prot_pairs=pp(cwt=arr([])))),
        ("m13-issuer-int", "the CWT issuer is an integer",
         b.crec(prot_pairs=pp(cwt=cmap([(uint(1), uint(7))])))),
        ("m14-iat-text", "the CWT iat is text",
         b.crec(prot_pairs=pp(cwt=cmap([(uint(1), text(ISSUER)), (uint(6), text("1790000000"))])))),
        ("m15-vds-text", "vds is text", b.crec(prot_pairs=pp(vds=text("2")))),
        ("m16-vds-bool", "vds is true", b.crec(prot_pairs=pp(vds=TRUE))),
        ("m17-vdp-not-map", "vdp is an array", b.crec(vdp=arr([uint(1)]))),
        ("m18-vdp-protected-not-map", "a protected vdp that is an array",
         b.crec(extra_prot=[(uint(396), arr([]))], unprot=cmap([]))),
        ("m19-both-buckets", "kid in both buckets",
         b.crec(unprot=cmap([(uint(4), bstr(b"x")), (uint(396), cmap([(uint(-2), arr([bstr(good)]))]))]))),
        ("m20-alg-text-ccf", "a text alg in a CCF receipt (-05 CDDL: int)", b.crec(prot_pairs=pp(alg=text("ES256")))),
        ("m21-vdp-unknown-family", "vdp carries -3 beside -2",
         b.crec(vdp=cmap([(uint(-2), arr([bstr(good)])), (uint(-3), arr([]))]))),
        ("m22-vdp-empty", "vdp is an empty map", b.crec(vdp=cmap([]))),
        ("m23-vdp-text-key", "vdp carries a text key beside -2",
         b.crec(vdp=cmap([(uint(-2), arr([bstr(good)])), (text("x"), arr([]))]))),
        ("m24-consistency-not-array", "-2 is a byte string", b.crec(vdp=cmap([(uint(-2), bstr(good))]))),
        ("m25-consistency-empty", "-2 is an empty array", b.crec(vdp=cmap([(uint(-2), arr([]))]))),
        ("m26-consistency-nine", "nine consistency proofs", b.crec([good] * 9)),
        ("m27-inclusion-empty", "an empty -1 beside -2", b.crec(inclusion=[])),
        ("m28-inclusion-not-array", "-1 is a map beside -2",
         b.crec(vdp=cmap([(uint(-1), cmap([])), (uint(-2), arr([bstr(good)]))]))),
        ("m29-inclusion-junk", "an inclusion proof that does not decode beside -2", b.crec(inclusion=[b"junk"])),
        ("m30-proof-text", "a proof that is text", b.crec([_Raw(text("proof"))])),
        ("m31-proof-junk", "a proof that does not decode", b.crec([b"not cbor \xff"])),
        ("m32-proof-tagged", "a tag inside a proof", b.crec([b"\xd8\x18" + good])),
        ("m33-proof-extra-key", "a proof with a third key",
         b.crec([cmap([(uint(1), bstr(r13)), (uint(2), arr([arr([FALSE, bstr(r13)])])), (uint(3), uint(0))])])),
        ("m34-proof-no-path", "a proof without its path", b.crec([cmap([(uint(1), bstr(r13))])])),
        ("m35-path-empty", "an empty path", b.crec([cmap([(uint(1), bstr(r13)), (uint(2), arr([]))])])),
        ("m36-path-65", "a path of 65 elements", b.crec([b.proof(r13, [(False, r13)] * 65)])),
        ("m37-path-int-tag", "a path element whose side is 0",
         b.crec([cmap([(uint(1), bstr(r13)), (uint(2), arr([arr([uint(0), bstr(r13)])]))])])),
        ("m38-path-hash-31", "a sibling of 31 bytes", b.crec([b.proof(r13, [(False, r13[:31])])])),
        ("m39-path-three", "a path element of three items",
         b.crec([cmap([(uint(1), bstr(r13)), (uint(2), arr([arr([FALSE, bstr(r13), NIL])]))])])),
        ("m40-anchor-31", "an anchor of 31 bytes", b.crec([b.proof(r13[:31], [(False, r13)])])),
        ("m41-anchor-text", "an anchor that is text",
         b.crec([cmap([(uint(1), text("anchor")), (uint(2), arr([arr([FALSE, bstr(r13)])]))])])),
        ("m42-proof-trailing", "a byte after a proof", b.crec([good + b"\x00"])),
        ("m43-proof-indefinite", "a proof as an indefinite map", b.crec([b"\xbf" + good[1:] + b"\xff"])),
        ("m44-proof-duplicate-key", "a proof with key 1 twice",
         b.crec([b"\xa2" + uint(1) + bstr(r13) + uint(1) + bstr(r13)])),
        ("m45-leaf-two", "an inclusion leaf of two components beside -2",
         b.crec(inclusion=[cmap([(uint(1), arr([bstr(r13), text("ev")])), (uint(2), arr([arr([FALSE, bstr(r13)])]))])])),
        ("m46-evidence-bytes", "internal-evidence of 342 characters and 1026 bytes beside -2",
         b.crec(inclusion=[b.inclusion(r13, ev="€" * 342)[0]])),
        ("m47-data-hash-31", "a data-hash of 31 bytes beside -2",
         b.crec(inclusion=[cmap([(uint(1), arr([bstr(r13), text("ev"), bstr(r13[:31])])),
                                 (uint(2), arr([arr([FALSE, bstr(r13)])]))])])),
        ("m48-inclusion-nine", "nine inclusion proofs beside -2", b.crec(inclusion=[b.inclusion(r13)[0]] * 9)),
        ("m49-payload-int", "the payload is an integer", b.crec(payload=uint(0))),
        ("m50-signature-text", "the signature is text", base[:-66] + text("s" * 64)),
        ("m53-alg-bool-not-ccf", "alg is true in a receipt that is not CCF: typed in every receipt",
         b.crec(prot_pairs=pp(alg=TRUE, vds=uint(1)))),
        ("m54-alg-unprotected-bytes", "alg in the unprotected bucket as a byte string",
         b.crec(prot_pairs=pp(alg=None), unprot=cmap([(uint(1), bstr(b"\x26")),
                                                      (uint(396), cmap([(uint(-2), arr([bstr(good)]))]))]))),
        ("m55-sibling-33", "a sibling of 33 bytes", b.crec([b.proof(r13, [(False, r13 + b"\x00")])])),
        ("m56-anchor-33", "an anchor of 33 bytes", b.crec([b.proof(r13 + b"\x00", [(False, r13)])])),
        ("m57-leaf-four", "an inclusion leaf of four components beside -2",
         b.crec(inclusion=[cmap([(uint(1), arr([bstr(r13), text("ev"), bstr(r13), NIL])),
                                 (uint(2), arr([arr([FALSE, bstr(r13)])]))])])),
    ):
        b.add(vid, what, rc, r13, malformed())
    b.zero_signatures = False

    def padded(size: int) -> bytes:
        """The control receipt with an unprotected label 1000 of zeros, `size` bytes in all."""
        vdp = (uint(396), cmap([(uint(-2), arr([bstr(good)]))]))
        rc = b.crec(unprot=cmap([vdp, (uint(1000), bstr(b""))]))
        grow = size - len(rc)
        while len(rc) != size:
            rc = b.crec(unprot=cmap([vdp, (uint(1000), bstr(bytes(grow)))]))
            grow += size - len(rc)
        return rc

    b.add("m51-65537-bytes", "a receipt of 65537 bytes, one past MAX_STATEMENT_BYTES, otherwise the control",
          padded(65537), r13, malformed())
    b.add("m52-65536-bytes", "a receipt of 65536 bytes, MAX_STATEMENT_BYTES, otherwise the control",
          padded(65536), r13, confirmed())

    # -- outside the profile ------------------------------------------------------------------------------
    b.zero_signatures = True
    for vid, what, rc, readable in (
        ("o01-untagged", "the receipt is not tagged 18", b.crec(tag=b""), True),
        ("o02-alg-es512", "alg -36, not in v1", b.crec(prot_pairs=pp(alg=uint(-36))), True),
        ("o03-alg-ps256", "alg -37, a statement algorithm, not a receipt one", b.crec(prot_pairs=pp(alg=uint(-37))),
         True),
        ("o04-alg-absent", "no alg", b.crec(prot_pairs=pp(alg=None)), True),
        ("o05-no-kid", "no kid", b.crec(prot_pairs=pp(kid=None)), True),
        ("o06-no-issuer", "no CWT issuer", b.crec(prot_pairs=pp(cwt=cmap([(uint(6), uint(1790000000))]))), True),
        ("o07-no-cwt", "no CWT claims", b.crec(prot_pairs=pp(cwt=None)), True),
        ("o08-crit-unprotected", "crit in the unprotected header",
         b.crec(unprot=cmap([(uint(2), arr([uint(1)])), (uint(396), cmap([(uint(-2), arr([bstr(good)]))]))])), True),
        ("o09-crit-unprocessed", "crit lists label 99, which v1 does not process",
         b.crec(extra_prot=[(uint(2), arr([uint(99)])), (uint(99), uint(1))]), True),
        ("o10-crit-text", "crit lists a text label", b.crec(extra_prot=[(uint(2), arr([text("ccf.v1")]))]), True),
        ("o11-vds-1", "vds 1, not CCF_LEDGER_SHA256: the proofs are not read", b.crec(prot_pairs=pp(vds=uint(1))),
         False),
        ("o12-vds-absent", "no vds", b.crec(prot_pairs=pp(vds=None)), False),
        ("o13-vds-1-junk-proof", "vds 1 with a proof that does not decode: no CDDL for it",
         b.crec([b"junk"], prot_pairs=pp(vds=uint(1))), False),
        ("o14-alg-text-vds-1", "a text alg outside CCF is typed, then outside",
         b.crec(prot_pairs=pp(alg=text("ES256"), vds=uint(1))), False),
    ):
        b.add(vid, what, rc, r13, want("outside_profile", readable=readable, older_root_matches=None,
                                       signature_valid=None, newer_root=None))
    b.zero_signatures = False
    b.add("o15-crit-processed", "crit lists vds, a label v1 processes", b.crec(extra_prot=[(uint(2), arr([uint(395)]))]),
          r13, confirmed())
    b.add("o16-crit-absent-label", "crit lists label 3, absent from the protected header",
          b.crec(extra_prot=[(uint(2), arr([uint(3)]))]), r13, want("outside_profile"))
    vdp_good = (uint(396), cmap([(uint(-2), arr([bstr(good)]))]))
    b.add("o17-kid-unprotected", "kid in the unprotected bucket only",
          b.crec(prot_pairs=pp(kid=None), unprot=cmap([(uint(4), bstr(b.kid("svc_p256"))), vdp_good])), r13,
          want("outside_profile", readable=True))
    b.add("o18-issuer-unprotected", "the CWT issuer in the unprotected bucket only",
          b.crec(prot_pairs=pp(cwt=None), unprot=cmap([(uint(15), cmap([(uint(1), text(ISSUER))])), vdp_good])), r13,
          want("outside_profile", readable=True, issuer=None))

    # -- section 4.1 --------------------------------------------------------------------------------------
    b.add("f01-no-vdp", "no vdp", b.crec(unprot=cmap([])), r13,
          want("consistency_proof_missing", readable=False, proofs=0, newer_root=None, inclusion_proofs_present=False))
    b.add("f02-inclusion-only", "vdp carries a valid -1 and no -2",
          b.crec(vdp=cmap([(uint(-1), arr([bstr(b.inclusion(r13)[0])]))])), r13,
          want("consistency_proof_missing", readable=False, proofs=0, inclusion_proofs_present=True))
    b.add("f03-vdp-protected-only", "vdp in the protected header only: read from the unprotected one",
          b.crec(extra_prot=[(uint(396), cmap([(uint(-2), arr([bstr(good)]))]))], unprot=cmap([])), r13,
          want("consistency_proof_missing", readable=False, proofs=0))
    b.add("f04-no-vdp-payload", "no vdp and an attached payload: the missing proof comes first",
          b.crec(unprot=cmap([]), payload=bstr(r24)), r13, want("consistency_proof_missing", readable=False))
    for vid, what, payload in (("a01-payload-newer", "the newer root attached", bstr(r24)),
                               ("a02-payload-zeros", "32 zero bytes attached", bstr(bytes(32))),
                               ("a03-payload-empty", "an empty byte string attached", bstr(b""))):
        b.add(vid, what, b.crec(payload=payload), r13,
              want("consistency_payload_attached", readable=True, proofs=1, newer_root=None, older_root_matches=None))
    other = b.pair(13, 20)
    a, path = t.proof05(17, 24)
    corrupted = b.proof(bytes([a[0] ^ 1]) + a[1:], path)
    b.add("a04-payload-before-newer", "two proofs to different newer roots and an attached payload",
          b.crec([good, b.pair(13, 20)], payload=bstr(r24)), r13, want("consistency_payload_attached", newer_root=None))
    b.add("n01-two-agree", "13 -> 24 and 17 -> 24", b.crec([good, b.pair(17, 24)]), r13, confirmed(proofs=2))
    b.add("n02-same-twice", "the same proof twice", b.crec([good, good]), r13, confirmed(proofs=2))
    b.add("n03-eight", "eight proofs, the limit", b.crec([b.pair(m, 24) for m in range(13, 21)]), r13,
          confirmed(proofs=8))
    b.add("n04-another-newer", "13 -> 24 and 13 -> 20", b.crec([good, other]), r13,
          want("consistency_newer_roots_differ", newer_root=r24.hex(), older_root_matches=None, signature_valid=None))
    b.add("n05-first-decides-newer", "13 -> 20 first, then 13 -> 24: the first proof names the newer root",
          b.crec([other, good]), r13, want("consistency_newer_roots_differ", newer_root=t.root(20).hex()))
    b.add("n06-corrupted-anchor", "a second proof whose anchor has one bit flipped", b.crec([good, corrupted]), r13,
          want("consistency_newer_roots_differ"))
    leaf_tree = Tree(list(t.leaves[:24]))
    itx, ev, dh = H(b"itx"), "ce:2.5:" + "00" * 32, H(b"a data-hash")
    leaf_tree.leaves[5] = H(itx + H(ev.encode()) + dh)
    leaf_tree.memo = {}

    def incl(tree, index, lo, hi):
        if hi - lo == 1:
            return []
        k = 1 << ((hi - lo - 1).bit_length() - 1)
        if index < lo + k:
            return incl(tree, index, lo, lo + k) + [(False, tree.node(lo + k, hi))]
        return incl(tree, index, lo + k, hi) + [(True, tree.node(lo, lo + k))]

    ipath = incl(leaf_tree, 5, 0, 24)
    iproof = b.inclusion(dh, itx=itx, ev=ev, path=ipath)[0]
    wrong = b.inclusion(dh, itx=itx, ev=ev, path=ipath[:-1])[0]
    lr24 = leaf_tree.root(24)
    lgood = b.proof(*leaf_tree.proof05(13, 24))
    b.add("n07-inclusion-beside", "an inclusion proof beside -2 computes the newer root too",
          b.crec([lgood], inclusion=[iproof], sign_root=lr24), leaf_tree.root(13),
          confirmed(newer_root=lr24.hex(), inclusion_proofs_present=True))
    b.add("n08-inclusion-beside-differs", "an inclusion proof beside -2 computes another root",
          b.crec([lgood], inclusion=[wrong], sign_root=lr24), leaf_tree.root(13),
          want("consistency_newer_roots_differ", newer_root=lr24.hex(), inclusion_proofs_present=True))

    # -- section 4: the anchor; 4.2: the older root, the issuer, the signature ----------------------------
    a13, p13 = t.proof05(13, 24)
    flipped = b.proof(a13, [(not p13[0][0], p13[0][1])] + p13[1:])
    b.add("n09-newer-before-anchor", "a canonical proof and the same proof with its first side flipped",
          b.crec([good, flipped]), r13, want("consistency_newer_roots_differ", older_root_matches=None))
    b.add("c01-first-left", "the first sibling's side flipped to left", b.crec([flipped]), r13,
          want("consistency_anchor_not_canonical", older_root_matches=False))
    b.add("c02-m-equals-n", "one left sibling: the newer root equals the older, m = n",
          b.crec([b.proof(t.node(8, 13), [(True, t.node(0, 8))])], n=13), r13,
          want("consistency_anchor_not_canonical", older_root_matches=True, signature_valid=True,
               newer_root=r13.hex()))
    b.add("c03-anchor-before-older", "a left first sibling and an older root that does not match",
          b.crec([flipped]), t.root(12), want("consistency_anchor_not_canonical", older_root_matches=False))
    b.add("c04-one-canonical-one-deeper", "a canonical proof and a deeper one of the same pair",
          b.crec([b.pair(12, 24), b.proof(*t.deeper(12, 24)[0])]), t.root(12),
          want("consistency_anchor_not_canonical", proofs=2))
    for vid, what, older in (
        ("h01-root-12", "the root of size 12", t.root(12)),
        ("h02-bit-flipped", "the older root with one bit flipped", bytes([r13[0] ^ 1]) + r13[1:]),
        ("h03-states-swapped", "the newer root held as the older", r24),
        ("h04-31-bytes", "31 bytes of the older root", r13[:31]),
        ("h05-33-bytes", "the older root and one byte", r13 + b"\x00"),
        ("h06-empty", "no bytes", b""),
    ):
        b.add(vid, what, b.crec(), older, want("consistency_older_root_mismatch", older_root_matches=False,
                                                signature_valid=True, kid_bound_to_key=True, **ok))
    b.add("h08-before-issuer", "an older root that does not match and another issuer: the root comes first",
          b.crec(), t.root(12), want("consistency_older_root_mismatch", older_root_matches=False),
          issuer="other.example")
    b.add("h07-second-proof-matches", "13 -> 24 and 17 -> 24 against the root of 17", b.crec([good, b.pair(17, 24)]),
          t.root(17), confirmed(proofs=2))
    for vid, what, issuer in (("i01-other", "another service", "other.example"),
                              ("i02-empty", "the empty string", ""),
                              ("i03-case", "the issuer in capitals", ISSUER.upper()),
                              ("i04-trailing-space", "the issuer and a space", ISSUER + " "),
                              ("i05-unicode", "a non-ASCII look-alike", "svc.exämple")):
        b.add(vid, what, b.crec(), r13, want("consistency_issuer_mismatch", older_root_matches=True,
                                              signature_valid=True, **ok), issuer=issuer)
    b.add("i06-over-needs-trust", "the issuer rule comes before trust", b.crec(), r13,
          want("consistency_issuer_mismatch", signature_valid=None), issuer="other.example", trust=None)
    b.add("i07-over-signature", "the issuer rule comes before the signature", b.crec(sig=bytes(64)), r13,
          want("consistency_issuer_mismatch", signature_valid=False), issuer="other.example")
    uni = "svc.exämple"
    b.trusts["unicode"] = {"scitt_ccf_services": {uni: [{"ref": "spki_svc_p256"}]}}
    b.add("i08-unicode-issuer", "a non-ASCII issuer in the receipt and on the command line",
          b.crec(prot_pairs=pp(cwt=cmap([(uint(1), text(uni)), (uint(6), uint(1790000000))]))), r13,
          confirmed(issuer=uni), issuer=uni, trust="unicode")
    uni_receipt = b.crec(prot_pairs=pp(cwt=cmap([(uint(1), text(uni)), (uint(6), uint(1790000000))])))
    b.add("i09-decomposed", "the same issuer with a decomposed a-umlaut on the command line: not the same text",
          uni_receipt, r13, want("consistency_issuer_mismatch", issuer=uni), issuer="svc.exa\u0308mple",
          trust="unicode")
    b.add("i10-zero-width", "the issuer and a zero-width space", b.crec(), r13,
          want("consistency_issuer_mismatch"), issuer=ISSUER + "\u200b")

    # -- trust -----------------------------------------------------------------------------------------------
    p256 = {"ref": "spki_svc_p256"}
    for n in (64, 65):
        b.trusts[f"{n}-keys"] = {"scitt_ccf_services": {ISSUER: [{"ref": "spki_svc_p384"}] * (n - 1) + [p256]}}
    for vid, what, trust in (
        ("k01-no-trust", "no trust document", None),
        ("k02-empty", "an empty trust document", {"inline": {}}),
        ("k03-other-issuer", "keys for another issuer", {"inline": {"scitt_ccf_services": {"other.example": [p256]}}}),
        ("k04-other-key", "the P-384 key only, whose kid is another", {"inline": {"scitt_ccf_services": {
            ISSUER: [{"ref": "spki_svc_p384"}]}}}),
        ("k05-services-list", "scitt_ccf_services is a list", {"inline": {"scitt_ccf_services": [p256]}}),
        ("k06-keys-text", "the issuer's keys are one text", {"inline": {"scitt_ccf_services": {ISSUER: p256}}}),
        ("k08-key-not-spki", "a key that is no SubjectPublicKeyInfo", {"inline": {"scitt_ccf_services": {
            ISSUER: ["3000"]}}}),
        ("k09-explicit-kid-other", "the right key under another explicit kid", {"inline": {"scitt_ccf_services": {
            ISSUER: [{"spki": p256, "kid": b"other".hex()}]}}}),
        ("k10-past-64", "the right key as the 65th entry", "65-keys"),
        ("k11-trust-not-object", "a trust document that is a list", {"inline": [p256]}),
    ):
        b.add(vid, what, b.crec(), r13, want("needs_rp_trust", older_root_matches=True, signature_valid=None,
                                              kid_bound_to_key=None, **ok), trust=trust)
    b.add("k12-explicit-kid", "the right key under its derived kid given explicitly", b.crec(), r13,
          confirmed(kid_bound_to_key=True), trust={"inline": {"scitt_ccf_services": {
              ISSUER: [{"spki": p256, "kid": kid}]}}})
    b.add("k13-kid-not-bound", "a receipt kid that is not the key's digest, given in trust", b.crec(kid=b"custom"), r13,
          confirmed(kid_bound_to_key=False, kid=b"custom".hex()), trust={"inline": {"scitt_ccf_services": {
              ISSUER: [{"spki": p256, "kid": b"custom".hex()}]}}})
    b.add("k14-bad-then-good", "a key that fails, then the right one, under one kid", b.crec(), r13,
          confirmed(kid_bound_to_key=True), trust={"inline": {"scitt_ccf_services": {
              ISSUER: [{"spki": {"ref": "spki_svc_p384"}, "kid": kid}, p256]}}})
    b.add("k15-bad-then-good-custom-kid", "a key that fails, then the right one, under a kid that is not the "
          "right key's digest", b.crec(kid=b"custom"), r13,
          confirmed(kid_bound_to_key=False), trust={"inline": {"scitt_ccf_services": {
              ISSUER: [{"spki": {"ref": "spki_svc_p384"}, "kid": b"custom".hex()},
                       {"spki": p256, "kid": b"custom".hex()}]}}})
    b.add("k16-64-then-good", "the right key as the 64th entry", b.crec(), r13, confirmed(), trust="64-keys")
    for vid, what, rc in (
        ("g01-over-older", "the signature over the older root", b.crec(sign_root=r13)),
        ("g02-zeros", "a signature of zeros", b.crec(sig=bytes(64))),
        ("g03-forged", "the P-384 key's signature under the P-256 kid",
         b.crec(key="svc_p384", kid=b.kid("svc_p256"))),
        ("g04-alg-p384-key-p256", "alg -35 over the P-256 key", b.crec(alg=-35)),
        ("g05-alg-p256-key-p384", "alg -7 over the P-384 key", b.crec(key="svc_p384", alg=-7)),
        ("g06-short-signature", "a signature of 63 bytes", b.crec(sig=bytes(63))),
        ("g07-over-empty", "the signature over no payload", b.crec(sign_root=b"")),
    ):
        b.add(vid, what, rc, r13, want("signature_invalid", signature_valid=False, kid_bound_to_key=None,
                                       older_root_matches=True))

    # -- the fields beside the status -----------------------------------------------------------------------
    for vid, what, cwt, iat in (
        ("x01-iat-max", "iat 2^64 - 1", [(uint(1), text(ISSUER)), (uint(6), uint(2 ** 64 - 1))], 2 ** 64 - 1),
        ("x02-iat-min", "iat -2^64", [(uint(1), text(ISSUER)), (uint(6), uint(-(2 ** 64)))], -(2 ** 64)),
        ("x03-iat-absent", "no iat", [(uint(1), text(ISSUER))], None),
    ):
        b.add(vid, what, b.crec(prot_pairs=pp(cwt=cmap(cwt))), r13, confirmed(receipt_iat=iat))
    b.add("x06-txid-unprotected", "the ccf.v1 header in the unprotected bucket: no txid",
          b.crec(prot_pairs=pp(ccf=None), unprot=cmap([(text("ccf.v1"), cmap([(text("txid"), text("2.24"))])),
                                                       vdp_good])), r13, confirmed(ccf_txid=None))
    b.add("x04-txid-absent", "no ccf.v1 header", b.crec(prot_pairs=pp(ccf=None)), r13, confirmed(ccf_txid=None))
    b.add("x05-txid-int", "a txid that is an integer",
          b.crec(prot_pairs=pp(ccf=cmap([(text("txid"), uint(24))]))), r13, confirmed(ccf_txid=None))


def build() -> dict:
    b = Builder()
    real_vectors(b)
    synthetic_vectors(b)
    return {
        "schema": "proofbundle.scitt_consistency_receipt_vectors.v1",
        "surface": "proofbundle.scitt_ccf.verify_consistency_receipt",
        "rust_subcommand": "verify-scitt-consistency-receipt",
        "generated_by": "tools/scitt_ccf_external/consistency_receipt_vectors.py",
        "oracle": ("each vector's want is the verdict it is built to produce; for the local ledger's states, the "
                   "roots the fixture recorded from the ledger, each confirmed by the Python verifier for that "
                   "state's Transparent Statement. The generator wrote the file only after the Python verifier "
                   "returned exactly that for every vector"),
        "refs": b.refs,
        "trusts": b.trusts,
        "vectors": b.vectors,
    }


def check(doc: dict) -> list:
    bad = []
    for v in doc["vectors"]:
        off = mismatch(v["want"], python_result(doc, v))
        if off:
            bad.append(f"{v['id']}: {off}")
    return bad


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="hold the stored vectors to the Python verifier")
    a = ap.parse_args(argv)
    doc = json.loads(OUT.read_text(encoding="utf-8")) if a.check else build()
    bad = check(doc)
    for line in bad:
        print("MISMATCH", line)
    if bad:
        return 1
    if not a.check:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(dump(doc), encoding="utf-8")
    print(f"{len(doc['vectors'])} vectors, Python gives every built verdict; "
          f"{OUT.relative_to(ROOT)}: {OUT.stat().st_size if OUT.exists() else 0} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
