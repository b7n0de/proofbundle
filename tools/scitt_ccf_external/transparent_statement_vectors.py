#!/usr/bin/env python3
"""The shared vectors of `verify_transparent_statement`, run by the Python and the Rust verifier.

WHAT IT WRITES. tests/fixtures/scitt_transparent_statement/vectors.json: Transparent Statements, the
canonical root each is checked against, the relying-party trust, and the verdict each vector is built
to produce. tests/test_scitt_transparent_statement_parity.py runs both verifiers over every vector and
tools/pb_verify_rs/crosscheck.py runs them in CI. Both hold the two verifiers to each other on every
field of the result but the prose (`detail`, the text of `ignored_trust`), and to the built verdict.

WHERE THE BYTES COME FROM.
- Real, from a foreign tool: every Transparent Statement a local scitt-ccf-ledger served in the two
  differential-corpus rounds (tools/scitt_ccf_external/differential_corpus and
  differential_corpus_round2, scitt-ccf-ledger 00101f76, CCF 7.0.17), with the service keyset of its
  round and phase and the statement signer of its round (two different ES256 signers). They are named by
  path, not copied. The built verdict of each is the status the corpus recorded for it
  (`v1_reader_on_returned` in the round's summary.json, the Python reader of that run); the leaf
  data-hash the ledger put in its receipt, as the corpus recorded it, is held to the receipt field. A few
  cross cases (one round's statement
  under the other round's trust, a keyset from before the service identity changed, another root) are
  built from the same bytes.
- Synthetic: throwaway keys made here and never stored (the statement signer on P-256, two service keys
  on P-256 and P-384), a self-signed certificate, and statements, receipts and CCF proofs built byte by
  byte for every rule of the receipt pass and of the status logic.

THE ORACLE. Every vector carries the verdict it is designed to produce. The generator refuses to write
the file unless the Python verifier returns exactly that for every vector; the Rust verifier is held
to the same, and to Python on every other field.

FORM. A byte string is a list of parts: a hex string, `{"ref": name}`, `{"zeros": n}`,
`{"repeat": hex, "times": n}`, `{"hexfile": path}` (a hex text file of the corpus) or `{"fixture": path, "field": name}` (a base64
field of a JSON fixture). Trust documents are in the form `pb_verify_rs` reads, a key entry being
SubjectPublicKeyInfo DER as hex or `{"spki": hex, "kid": hex}`; in the file, `{"ref": name}` anywhere
in a trust document stands for that ref's hex text. Named trust documents are under `trusts`.

Usage:  PYTHONPATH=src python tools/scitt_ccf_external/transparent_statement_vectors.py [--check]
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
from proofbundle._cbor_prescan import encode_head  # noqa: E402
from proofbundle._wire_b64 import decode_b64  # noqa: E402  (the one strict base64 decoder tools may use)
from statement_signature_vectors import Builder as StatementBuilder, bstr, spki, uint  # noqa: E402

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, utils  # noqa: E402

OUT = ROOT / "tests" / "fixtures" / "scitt_transparent_statement" / "vectors.json"
ROUND1 = HERE / "differential_corpus"
ROUND2 = HERE / "differential_corpus_round2"
ISSUER = "svc.example"
SYN_ROOT = hashlib.sha256(b"proofbundle scitt-ccf/v1 transparent statement vectors").digest()


# -- the shared reading of the file (the parity test and crosscheck.py carry the same few lines) --------
def assemble(parts: list, refs: dict) -> bytes:
    out = b""
    for p in parts:
        if isinstance(p, str):
            out += bytes.fromhex(p)
        elif "ref" in p:
            out += bytes.fromhex(refs[p["ref"]])
        elif "zeros" in p:
            out += bytes(p["zeros"])
        elif "repeat" in p:
            out += bytes.fromhex(p["repeat"]) * p["times"]
        elif "hexfile" in p:
            out += bytes.fromhex("".join((ROOT / p["hexfile"]).read_text(encoding="ascii").split()))
        else:
            doc = json.loads((ROOT / p["fixture"]).read_text(encoding="utf-8"))
            out += decode_b64(doc[p["field"]])
    return out


def resolve(x, refs: dict):
    """A trust document with every `{"ref": name}` replaced by that ref's hex text."""
    if isinstance(x, dict):
        if set(x) == {"ref"}:
            return refs[x["ref"]]
        return {k: resolve(v, refs) for k, v in x.items()}
    if isinstance(x, list):
        return [resolve(v, refs) for v in x]
    return x


def python_trust(t):
    """The trust document as the Python verifier takes it: key entries as bytes."""
    def entry(e):
        if isinstance(e, str):
            return bytes.fromhex(e)
        if isinstance(e, dict):
            return {k: bytes.fromhex(v) if k in ("spki", "kid") and isinstance(v, str) else v for k, v in e.items()}
        return e

    def keys(v):
        return [entry(e) for e in v] if isinstance(v, list) else v

    if not isinstance(t, dict):
        return t
    out = dict(t)
    if "scitt_statement_keys" in out:
        out["scitt_statement_keys"] = keys(out["scitt_statement_keys"])
    if isinstance(out.get("scitt_ccf_services"), dict):
        out["scitt_ccf_services"] = {k: keys(v) for k, v in out["scitt_ccf_services"].items()}
    return out


def trust_of(doc: dict, v: dict):
    """The vector's trust document with refs resolved, or None when the vector passes no trust."""
    if "trust" not in v:
        return None
    t = v["trust"]
    return resolve(doc["trusts"][t] if isinstance(t, str) else t["inline"], doc["refs"])


def python_result(doc: dict, v: dict) -> dict:
    """Python's result as `to_dict()`, with the prose left out and the ignored trust counted."""
    trust = trust_of(doc, v)
    r = C.verify_transparent_statement(assemble(v["statement"], doc["refs"]),
                                       canonical_root=assemble(v["root"], doc["refs"]),
                                       rp_trust=None if trust is None else python_trust(trust)).to_dict()
    r.pop("detail")
    r["ignored_trust_count"] = len(r.pop("ignored_trust"))
    for c in r["receipts"]:
        c.pop("detail")
    return r


def observed(r: dict) -> dict:
    """The fields a vector's `want` may name, read from a result in `to_dict()` form."""
    return {**{k: r[k] for k in ("status", "statement_status", "readable", "signature_valid",
                                 "statement_signature_valid", "profile_satisfied", "payload_digest",
                                 "data_hash", "ignored_trust_count")},
            "receipt_statuses": [c["status"] for c in r["receipts"]],
            "receipt_txids": [c["ccf_txid"] for c in r["receipts"]],
            "receipt_data_hashes": [c["data_hashes"] for c in r["receipts"]],
            "receipt_bound": [c["bound"] for c in r["receipts"]],
            "receipt_kid_bound": [c["kid_bound_to_key"] for c in r["receipts"]],
            "receipt_iats": [c["receipt_iat"] for c in r["receipts"]],
            "receipt_consistency": [c["consistency_proofs_present"] for c in r["receipts"]],
            "receipt_readable": [c["readable"] for c in r["receipts"]]}


def mismatch(want: dict, got: dict) -> dict:
    seen = observed(got)
    return {k: (w, seen[k]) for k, w in want.items() if seen[k] != w}


# -- CBOR by hand ---------------------------------------------------------------------------------------
def text(s: str) -> bytes:
    raw = s.encode("utf-8")
    return encode_head(3, len(raw)) + raw


def arr(items: list) -> bytes:
    return encode_head(4, len(items)) + b"".join(items)


def cmap(pairs: list) -> bytes:
    return encode_head(5, len(pairs)) + b"".join(k + v for k, v in pairs)


TRUE, FALSE, NIL = b"\xf5", b"\xf4", b"\xf6"


def h(*parts: bytes) -> bytes:
    return hashlib.sha256(b"".join(parts)).digest()


class Builder(StatementBuilder):
    """Transparent Statements and CCF receipts byte by byte."""

    def __init__(self):
        super().__init__()
        self.refs = {k: v for k, v in self.refs.items() if k in ("cert_p256", "spki_p256")}
        self.trusts: dict = {}
        self.svc = {"svc_p256": ec.generate_private_key(ec.SECP256R1()),
                    "svc_p384": ec.generate_private_key(ec.SECP384R1())}
        for name, key in self.svc.items():
            self.refs[f"spki_{name}"] = spki(key).hex()
        self.st_prot = self.protected(b"\x26", self.leaf("p256"))
        self.refs["st_prot"] = bstr(self.st_prot).hex()
        #: A receipt the receipt pass refuses never reaches its signature, which is then zeros.
        self.zero_signatures = False
        self.plain_receipts: dict = {}

    def svc_sign(self, name: str, tbs: bytes) -> bytes:
        key = self.svc[name]
        hh, n = (hashes.SHA256(), 32) if name == "svc_p256" else (hashes.SHA384(), 48)
        r, s = utils.decode_dss_signature(key.sign(tbs, ec.ECDSA(hh)))
        return r.to_bytes(n, "big") + s.to_bytes(n, "big")

    def kid(self, name: str) -> bytes:
        return hashlib.sha256(bytes.fromhex(self.refs[f"spki_{name}"])).hexdigest().encode("ascii")

    # -- the statement ------------------------------------------------------------------------------
    def statement_parts(self, prot: bytes | None = None, payload: bytes | None = SYN_ROOT,
                        sig: bytes | None = None) -> tuple:
        """(protected bstr, payload element, signature element) of a hash envelope over `payload`."""
        prot = self.st_prot if prot is None else prot
        if sig is None:
            sig = self.sign("p256", C._sig_structure(prot, payload if payload is not None else b""))
        return bstr(prot), (bstr(payload) if payload is not None else NIL), bstr(sig)

    def data_hash(self, prot: bytes | None = None, payload: bytes | None = SYN_ROOT, sig: bytes | None = None,
                  parts: tuple | None = None) -> tuple:
        p, pay, s = parts if parts is not None else self.statement_parts(prot, payload, sig)
        return h(b"\xd2\x84", p, b"\xa0", pay, s), (p, pay, s)

    @staticmethod
    def transparent(parts: tuple, receipts, *, tag: bytes = b"\xd2", unprot: bytes | None = None) -> bytes:
        p, pay, s = parts
        if unprot is None:
            unprot = cmap([(uint(394), arr([bstr(r) if isinstance(r, bytes) else r.raw for r in receipts]))])
        return tag + b"\x84" + p + unprot + pay + s

    # -- a CCF inclusion proof and a receipt ---------------------------------------------------------
    @staticmethod
    def leaf_root(itx: bytes, ev: str, dh: bytes, path: list) -> bytes:
        r = h(itx, h(ev.encode("utf-8")), dh)
        for left, sib in path:
            r = h(sib, r) if left else h(r, sib)
        return r

    def inclusion(self, dh: bytes, *, itx: bytes = b"\x01" * 32, ev: str = "ccf evidence",
                  path: list | None = None, leaf: bytes | None = None, raw_path: bytes | None = None) -> tuple:
        """(proof bytes, the root it computes) of one ccf-inclusion-proof."""
        path = [(True, b"\x02" * 32), (False, b"\x03" * 32)] if path is None else path
        if leaf is None:
            leaf = arr([bstr(itx), text(ev), bstr(dh)])
        if raw_path is None:
            raw_path = arr([arr([TRUE if left else FALSE, bstr(sib)]) for left, sib in path])
        proof = cmap([(uint(1), leaf), (uint(2), raw_path)])
        return proof, self.leaf_root(itx, ev, dh, path)

    def consistency(self, anchor: bytes, path: list) -> tuple:
        """(proof bytes, the newer root) of one ccf-consistency-proof."""
        newer = anchor
        for left, sib in path:
            newer = h(sib, newer) if left else h(newer, sib)
        proof = cmap([(uint(1), bstr(anchor)),
                      (uint(2), arr([arr([TRUE if left else FALSE, bstr(sib)]) for left, sib in path]))])
        return proof, newer

    def receipt(self, dh: bytes, *, key: str = "svc_p256", alg: int = -7, kid: bytes | None = None,
                iss: str | None = ISSUER, iat: int = 1790000000, vds: bytes | None = b"\x02",
                txid: bytes | None = None, prot_pairs: list | None = None, extra_prot: list = (),
                vdp: bytes | None = None, inclusion: list | None = None, consistency: list | None = None,
                unprot: bytes | None = None, payload: bytes = NIL, tag: bytes = b"\xd2", sig: bytes | None = None,
                sign_root: bytes | None = None) -> bytes:
        """A CCF receipt over `dh`. Every element can be replaced to break one rule at a time. The plain
        receipt over one data hash is made once: an ECDSA signature differs on every call."""
        plain = (key, alg, kid, iss, iat, vds, txid, prot_pairs, tuple(extra_prot), vdp, inclusion, consistency,
                 unprot, payload, tag, sig, sign_root, self.zero_signatures) == (
            "svc_p256", -7, None, ISSUER, 1790000000, b"\x02", None, None, (), None, None, None, None, NIL,
            b"\xd2", None, None, False)
        if plain and dh in self.plain_receipts:
            return self.plain_receipts[dh]
        made = self._receipt(dh, key=key, alg=alg, kid=kid, iss=iss, iat=iat, vds=vds, txid=txid,
                             prot_pairs=prot_pairs, extra_prot=extra_prot, vdp=vdp, inclusion=inclusion,
                             consistency=consistency, unprot=unprot, payload=payload, tag=tag, sig=sig,
                             sign_root=sign_root)
        if plain:
            self.plain_receipts[dh] = made
        return made

    def _receipt(self, dh: bytes, *, key, alg, kid, iss, iat, vds, txid, prot_pairs, extra_prot, vdp, inclusion,
                 consistency, unprot, payload, tag, sig, sign_root) -> bytes:
        roots = []
        if inclusion is None:
            proof, root = self.inclusion(dh)
            inclusion = [proof]
            roots.append(root)
        if prot_pairs is None:
            cwt = []
            if iss is not None:
                cwt.append((uint(1), text(iss)))
            cwt.append((uint(6), uint(iat)))
            prot_pairs = [(uint(1), uint(alg)), (uint(4), bstr(self.kid(key) if kid is None else kid)),
                          (uint(15), cmap(cwt))]
            if vds is not None:
                prot_pairs.append((uint(395), vds))
            prot_pairs.append((text("ccf.v1"), cmap([(text("txid"), text("2.70") if txid is None else txid)])))
        rprot = cmap(list(prot_pairs) + list(extra_prot))
        if unprot is None:
            if vdp is None:
                fam = [(uint(-1), arr([bstr(p) for p in inclusion]))]
                if consistency is not None:
                    fam.append((uint(-2), arr([bstr(p) for p in consistency])))
                vdp = cmap(fam)
            unprot = cmap([(uint(396), vdp)])
        root = sign_root if sign_root is not None else (roots[0] if roots else b"")
        if sig is None:
            sig = bytes(64) if self.zero_signatures else self.svc_sign(key, C._sig_structure(rprot, root))
        return tag + b"\x84" + bstr(rprot) + unprot + payload + bstr(sig)

    # -- vectors --------------------------------------------------------------------------------------
    def blob(self, name: str, data: bytes) -> bytes:
        """Store a byte string that many vectors carry once, under `refs`, for `compress` to name."""
        self.refs[name] = data.hex()
        return data

    def compress(self, data: bytes) -> list:
        """The bytes as parts: every stored blob and the certificate become references, and a run of one
        short unit repeated becomes `{"repeat": unit, "times": n}`."""
        names = sorted((n for n in self.refs if n.startswith("blob_") or n in ("st_prot", "cert_p256")),
                       key=lambda n: -len(self.refs[n]))
        parts: list = []
        rest = data
        while rest:
            hit = None
            for n in names:
                i = rest.find(bytes.fromhex(self.refs[n]))
                if i >= 0 and (hit is None or i < hit[0]):
                    hit = (i, n)
            if hit is None:
                parts += self.runs(rest)
                break
            i, n = hit
            parts += self.runs(rest[:i]) + [{"ref": n}]
            rest = rest[i + len(bytes.fromhex(self.refs[n])):]
        return parts

    @staticmethod
    def runs(data: bytes) -> list:
        """Literal hex, with every run of at least 64 bytes of one unit (1 to 48 bytes) as a repeat."""
        parts: list = []
        lit = 0
        i = 0
        while i < len(data):
            best = None
            for p in range(1, 49):
                unit = data[i:i + p]
                if len(unit) < p:
                    break
                n = 1
                while data[i + n * p:i + (n + 1) * p] == unit:
                    n += 1
                if n >= 4 and n * p >= 64 and (best is None or n * p > best[0] * best[1]):
                    best = (n, p)
            if best is None:
                i += 1
                continue
            n, p = best
            if lit < i:
                parts.append(data[lit:i].hex())
            parts.append({"repeat": data[i:i + p].hex(), "times": n})
            i += n * p
            lit = i
        if lit < len(data):
            parts.append(data[lit:].hex())
        return parts

    def add_ts(self, vid: str, what: str, statement, want: dict, *, trust="syn", root: bytes = SYN_ROOT,
               origin: str = "synthetic") -> None:
        v = {"id": vid, "what": what, "origin": origin,
             "statement": statement if isinstance(statement, list) else self.compress(statement),
             "root": [root.hex()], "want": want}
        if trust is not None:
            v["trust"] = trust
        self.vectors.append(v)


def confirmed(n: int = 1, **kw) -> dict:
    want = {"status": "confirmed", "statement_status": "confirmed", "readable": True, "signature_valid": True,
            "receipt_statuses": ["confirmed"] * n}
    want.update(kw)
    return want


def status(top: str, stmt: str, receipts: list, **kw) -> dict:
    want = {"status": top, "statement_status": stmt, "receipt_statuses": receipts}
    want.update(kw)
    return want


# ---------------------------------------------------------------------------------------------------
# Real vectors
# ---------------------------------------------------------------------------------------------------
def keyset_trust(b: Builder, name: str, keyset_hex: Path) -> list:
    """A service keyset as trust entries, converted to SubjectPublicKeyInfo by `load_cose_keyset`
    (the Python reader, own implementation) and stored as refs."""
    raw = bytes.fromhex("".join(keyset_hex.read_text(encoding="ascii").split()))
    out = []
    for i, k in enumerate(C.load_cose_keyset(raw)):
        b.refs[f"spki_{name}_{i}"] = k["spki"].hex()
        out.append({"spki": {"ref": f"spki_{name}_{i}"}, "kid": k["kid"].hex()} if k["kid"] is not None
                   else {"ref": f"spki_{name}_{i}"})
    return out


def real_vectors(b: Builder) -> None:
    s1 = json.loads((ROUND1 / "summary.json").read_text(encoding="utf-8"))
    s2 = json.loads((ROUND2 / "summary.json").read_text(encoding="utf-8"))
    b.refs["spki_round1_signer"] = s1["signer"]["spki_hex"]
    b.refs["spki_round2_signer"] = s2["signer"]["spki_hex"]
    root = bytes.fromhex(json.loads((ROUND1 / "manifest.json").read_text(encoding="utf-8"))
                         ["target"]["receipt_canonical_root"])
    assert root.hex() == json.loads((ROUND2 / "manifest.json").read_text(encoding="utf-8"))[
        "target"]["receipt_canonical_root"]
    issuer = "127.0.0.1:8000"
    b.trusts["round1"] = {"scitt_statement_keys": [{"ref": "spki_round1_signer"}],
                          "scitt_ccf_services": {issuer: keyset_trust(b, "round1", ROUND1 / "scitt-keys.hex")}}
    for ph in json.loads((ROUND2 / "manifest.json").read_text(encoding="utf-8"))["phases"]:
        b.trusts[f"round2-{ph['name']}"] = {
            "scitt_statement_keys": [{"ref": "spki_round2_signer"}],
            "scitt_ccf_services": {issuer: keyset_trust(b, f"round2_{ph['name'].replace('-', '_')}",
                                                        ROUND2 / ph["keyset"])}}
    for corpus, summary, label in ((ROUND1, s1, "round1"), (ROUND2, s2, "round2")):
        for row in summary["vectors"]:
            if not row["accepted"]:
                continue
            vid = row["id"]
            rec = json.loads((corpus / "vectors" / vid / "record.json").read_text(encoding="utf-8"))
            trust = label if label == "round1" else f"round2-{rec['phase']['name']}"
            want = {"status": row["v1_reader_on_returned"]}
            if row["v1_reader_on_returned"] == "confirmed":
                # The corpus txid is not held here: it is the transaction of the registration, one before
                # the receipt's own (measured: 2.88 against 2.89 for a08 of round 1).
                want.update(receipt_data_hashes=[[row["data_hash"]]])
            b.add_ts(f"r-{label}-{vid}", f"{label} {vid}: the Transparent Statement the ledger served "
                     f"({rec['mutation']})", [{"hexfile": str((corpus / "vectors" / vid / "statement.hex")
                                                              .relative_to(ROOT))}],
                     want, trust=trust, root=root, origin=f"scitt-ccf-ledger, {label}")
    ctl1 = [{"hexfile": str((ROUND1 / "vectors" / "control" / "statement.hex").relative_to(ROOT))}]
    ctl2 = [{"hexfile": str((ROUND2 / "vectors" / "control" / "statement.hex").relative_to(ROOT))}]
    j02 = [{"hexfile": str((ROUND2 / "vectors" / "j02-after-restart" / "statement.hex").relative_to(ROOT))}]
    cross = (
        ("x01-round1-control-under-round2-trust", "the round 1 statement under the round 2 signer and keyset",
         ctl1, "round2-initial", root, status("needs_rp_trust", "needs_rp_trust", ["needs_rp_trust"])),
        ("x02-round2-control-under-round1-trust", "the round 2 statement under the round 1 signer and keyset",
         ctl2, "round1", root, status("needs_rp_trust", "needs_rp_trust", ["needs_rp_trust"])),
        ("x03-after-restart-under-the-initial-keyset", "a receipt of the recovered service under the keyset of "
         "its first identity", j02, "round2-initial", root,
         status("needs_rp_trust", "confirmed", ["needs_rp_trust"], receipt_bound=[True])),
        ("x04-round1-control-another-root", "the round 1 statement against a root it does not carry", ctl1,
         "round1", SYN_ROOT, status("unbound", "unbound", ["confirmed"])),
        ("x05-round1-control-without-trust", "the round 1 statement with no trust at all", ctl1, None, root,
         status("needs_rp_trust", "needs_rp_trust", ["needs_rp_trust"], readable=True, signature_valid=False)),
        ("x06-round1-control-service-keys-only", "the round 1 statement with the service keyset and no signer",
         ctl1, {"inline": {"scitt_ccf_services": b.trusts["round1"]["scitt_ccf_services"]}}, root,
         status("needs_rp_trust", "needs_rp_trust", ["confirmed"], signature_valid=True)),
    )
    for vid, what, parts, trust, r, want in cross:
        b.add_ts(vid, what, parts, want, trust=trust, root=r, origin="differential corpus, rebuilt trust")
    fixture = "tests/fixtures/scitt_ccf/local_ledger_control.json"
    doc = json.loads((ROOT / fixture).read_text(encoding="utf-8"))
    b.refs["spki_local_ledger_signer"] = decode_b64(doc["statement_signer_spki_b64"]).hex()
    services = []
    for i, k in enumerate(C.load_cose_keyset(decode_b64(doc["service_keyset_b64"]))):
        b.refs[f"spki_local_ledger_{i}"] = k["spki"].hex()
        services.append({"spki": {"ref": f"spki_local_ledger_{i}"}, "kid": k["kid"].hex()})
    b.trusts["local-ledger"] = {"scitt_statement_keys": [{"ref": "spki_local_ledger_signer"}],
                                "scitt_ccf_services": {doc["issuer"]: services}}
    b.add_ts("l01-local-ledger-control", "the local-ledger control fixture of the profile tests",
             [{"fixture": fixture, "field": "transparent_statement_b64"}], confirmed(),
             trust="local-ledger", root=bytes.fromhex(doc["canonical_root_hex"]), origin=fixture)


# ---------------------------------------------------------------------------------------------------
# Synthetic vectors
# ---------------------------------------------------------------------------------------------------
def trusts(b: Builder) -> None:
    svc = [{"ref": "spki_svc_p256"}, {"ref": "spki_svc_p384"}]
    stmt = [{"ref": "spki_p256"}]
    b.trusts.update({
        "syn": {"scitt_statement_keys": stmt, "scitt_ccf_services": {ISSUER: svc}},
        "syn-explicit-kid": {"scitt_statement_keys": stmt, "scitt_ccf_services": {
            ISSUER: [{"spki": {"ref": "spki_svc_p256"}, "kid": b"explicit-kid".hex()}]}},
        "syn-kid-mismatch": {"scitt_statement_keys": stmt, "scitt_ccf_services": {
            ISSUER: [{"spki": {"ref": "spki_svc_p256"}, "kid": b"another-kid".hex()}]}},
        "syn-kid-not-bytes": {"scitt_statement_keys": stmt, "scitt_ccf_services": {
            ISSUER: [{"spki": {"ref": "spki_svc_p256"}, "kid": 7}]}},
        "syn-kid-null": {"scitt_statement_keys": stmt, "scitt_ccf_services": {
            ISSUER: [{"spki": {"ref": "spki_svc_p256"}, "kid": None}]}},
        "syn-other-issuer": {"scitt_statement_keys": stmt, "scitt_ccf_services": {"other.example": svc}},
        "syn-services-list": {"scitt_statement_keys": stmt, "scitt_ccf_services": svc},
        "syn-services-entry-object": {"scitt_statement_keys": stmt, "scitt_ccf_services": {
            ISSUER: {"spki": {"ref": "spki_svc_p256"}}}},
        "syn-no-services": {"scitt_statement_keys": stmt},
        "syn-no-statement-keys": {"scitt_ccf_services": {ISSUER: svc}},
        "syn-statement-keys-text": {"scitt_statement_keys": "00", "scitt_ccf_services": {ISSUER: svc}},
        "syn-statement-keys-junk": {"scitt_statement_keys": [5, {"spki": 1}, {"spki": {"ref": "spki_p256"},
                                                                               "kid": True}, "00",
                                                             {"spki": {"ref": "spki_svc_p384"}}, {"ref": "spki_p256"}],
                                    "scitt_ccf_services": {ISSUER: svc}},
        "syn-65-statement-keys": {"scitt_statement_keys": ["00"] * 64 + [{"ref": "spki_p256"}],
                                  "scitt_ccf_services": {ISSUER: svc}},
        "syn-64-statement-keys": {"scitt_statement_keys": ["00"] * 63 + [{"ref": "spki_p256"}],
                                  "scitt_ccf_services": {ISSUER: svc}},
        "syn-65-service-keys": {"scitt_statement_keys": stmt,
                                "scitt_ccf_services": {ISSUER: ["00"] * 64 + [{"ref": "spki_svc_p256"}]}},
    })
    b.trusts["syn-trust-a-list"] = [b.trusts["syn"]]


def synthetic_vectors(b: Builder) -> None:
    trusts(b)
    dh, parts = b.data_hash()
    ts = b.transparent
    rc = b.receipt
    good = rc(dh)
    b.blob("blob_good_receipt", bstr(good))
    b.blob("blob_statement_tail", parts[1] + parts[2])
    b.blob("blob_proof", bstr(b.inclusion(dh)[0]))
    b.blob("blob_receipt_protected", _protected_bstr(good))

    # -- the whole path confirmed, and each trust rule ----------------------------------------------
    b.add_ts("s01-confirmed", "a v1 hash envelope, one CCF receipt, both keys trusted", ts(parts, [rc(dh)]),
             confirmed(receipt_kid_bound=[True], receipt_bound=[True], ignored_trust_count=0,
                       statement_signature_valid=True, profile_satisfied=True, data_hash=dh.hex(),
                       payload_digest=SYN_ROOT.hex()))
    b.add_ts("s02-p384-service", "a receipt signed ES384 by the P-384 service key",
             ts(parts, [rc(dh, key="svc_p384", alg=-35)]), confirmed())
    b.add_ts("s03-explicit-kid", "the service key given with an explicit kid, the receipt naming it",
             ts(parts, [rc(dh, kid=b"explicit-kid")]), confirmed(receipt_kid_bound=[False]),
             trust="syn-explicit-kid")
    b.add_ts("s04-kid-mismatch", "the only service key names another kid",
             ts(parts, [rc(dh)]), status("needs_rp_trust", "confirmed", ["needs_rp_trust"], receipt_bound=[True]),
             trust="syn-kid-mismatch")
    b.add_ts("s05-kid-not-bytes", "a service key entry whose kid is a number is ignored",
             ts(parts, [rc(dh)]), status("needs_rp_trust", "confirmed", ["needs_rp_trust"]),
             trust="syn-kid-not-bytes")
    b.add_ts("s06-kid-null", "a service key entry with a null kid falls back to the derived kid",
             ts(parts, [rc(dh)]), confirmed(), trust="syn-kid-null")
    b.add_ts("s07-other-issuer", "service keys only for another issuer",
             ts(parts, [rc(dh)]), status("needs_rp_trust", "confirmed", ["needs_rp_trust"]),
             trust="syn-other-issuer")
    b.add_ts("s08-services-a-list", "scitt_ccf_services is a list, not a map",
             ts(parts, [rc(dh)]), status("needs_rp_trust", "confirmed", ["needs_rp_trust"]),
             trust="syn-services-list")
    b.add_ts("s09-services-entry-object", "the issuer's keys are one object, not a list",
             ts(parts, [rc(dh)]), status("needs_rp_trust", "confirmed", ["needs_rp_trust"]),
             trust="syn-services-entry-object")
    b.add_ts("s10-no-services", "no service keys", ts(parts, [rc(dh)]),
             status("needs_rp_trust", "confirmed", ["needs_rp_trust"], signature_valid=False),
             trust="syn-no-services")
    b.add_ts("s11-no-statement-keys", "no statement keys", ts(parts, [rc(dh)]),
             status("needs_rp_trust", "needs_rp_trust", ["confirmed"], signature_valid=True,
                    statement_signature_valid=None), trust="syn-no-statement-keys")
    b.add_ts("s12-statement-keys-text", "the statement keys are a text, one ignored entry",
             ts(parts, [rc(dh)]), status("needs_rp_trust", "needs_rp_trust", ["confirmed"],
                                         ignored_trust_count=1), trust="syn-statement-keys-text")
    b.add_ts("s13-statement-keys-junk", "four statement key entries v1 cannot use, then the P-384 service "
             "key, then the signer", ts(parts, [rc(dh)]), confirmed(ignored_trust_count=4),
             trust="syn-statement-keys-junk")
    b.add_ts("s14-65-statement-keys", "the signer as the 65th statement key is beyond the limit",
             ts(parts, [rc(dh)]), status("needs_rp_trust", "needs_rp_trust", ["confirmed"],
                                         ignored_trust_count=65), trust="syn-65-statement-keys")
    b.add_ts("s15-64-statement-keys", "the signer as the 64th statement key is inside the limit",
             ts(parts, [rc(dh)]), confirmed(ignored_trust_count=63), trust="syn-64-statement-keys")
    b.add_ts("s16-65-service-keys", "the service key as the 65th is beyond the limit",
             ts(parts, [rc(dh)]), status("needs_rp_trust", "confirmed", ["needs_rp_trust"]),
             trust="syn-65-service-keys")
    b.add_ts("s17-trust-a-list", "the trust document is a list: no trust", ts(parts, [rc(dh)]),
             status("needs_rp_trust", "needs_rp_trust", ["needs_rp_trust"]), trust="syn-trust-a-list")
    b.add_ts("s18-no-trust", "no trust document at all", ts(parts, [rc(dh)]),
             status("needs_rp_trust", "needs_rp_trust", ["needs_rp_trust"], readable=True), trust=None)

    # -- the statement: root, signature, profile ----------------------------------------------------
    b.add_ts("t01-another-root", "the statement carries another target's root", ts(parts, [rc(dh)]),
             status("unbound", "unbound", ["confirmed"], statement_signature_valid=None), root=b"\x07" * 32)
    b.add_ts("t02-root-31-bytes", "a canonical root of 31 bytes", ts(parts, [rc(dh)]),
             status("unbound", "unbound", ["confirmed"]), root=SYN_ROOT[:31])
    bad = b.statement_parts(sig=bytes(64))
    dh_bad, _ = b.data_hash(parts=bad)
    b.add_ts("t03-statement-signature-invalid", "a statement signature of zeros under a receipt that binds it",
             ts(bad, [rc(dh_bad)]), status("statement_signature_invalid", "statement_signature_invalid",
                                           ["confirmed"], statement_signature_valid=False))
    b.add_ts("t04-untagged-statement", "the statement without tag 18: outside, and no data hash",
             ts(parts, [rc(dh)], tag=b""), status("outside_profile", "outside_profile", ["receipt_not_bound"],
                                                   data_hash=None, receipt_bound=[False]))
    def envelope(vid, what, prot, stmt_status="outside_profile", payload=SYN_ROOT, **kw):
        p = b.statement_parts(prot=prot, payload=payload)
        d, _ = b.data_hash(parts=p)
        b.add_ts(vid, what, ts(p, [rc(d)]), status(stmt_status, stmt_status, ["confirmed"], **kw))
    cert = b.leaf("p256")
    envelope("t05-alg-eddsa", "statement alg -8", b.protected(uint(-8), cert))
    envelope("t06-no-258", "no payload hash algorithm", b.cbor_map([(b"\x01", b"\x26"), (uint(33), cert)]))
    envelope("t07-258-sha384", "label 258 is -43", b.cbor_map([(b"\x01", b"\x26"), (uint(258), uint(-43)),
                                                               (uint(33), cert)]))
    envelope("t08-cty-protected", "a content type in a hash envelope", b.protected(b"\x26", cert, [(b"\x03", uint(50))]))
    envelope("t09-crit-258", "crit lists 258, which v1 processes",
             b.protected(b"\x26", cert, [(b"\x02", arr([uint(258)]))]), stmt_status="confirmed")
    envelope("t10-crit-33", "crit lists 33, which v1 does not process",
             b.protected(b"\x26", cert, [(b"\x02", arr([uint(33)]))]))
    envelope("t11-crit-absent-label", "crit lists 1 and a label that is not there",
             b.protected(b"\x26", cert, [(b"\x02", arr([uint(1), uint(99)]))]))
    envelope("t12-crit-text", "crit lists a text label", b.protected(b"\x26", cert, [(b"\x02", arr([text("x")]))]))
    envelope("t13-no-x5chain", "no x5chain", b.protected(b"\x26", None))
    envelope("t14-payload-31", "a payload of 31 bytes", b.st_prot, payload=SYN_ROOT[:31], payload_digest=None)
    envelope("t15-alg-ps256", "statement alg PS256 with an EC key: in profile, the signature fails",
             b.protected(uint(-37), cert), stmt_status="statement_signature_invalid")
    for vid, what, unprot in (
            ("t16-259-unprotected", "label 259 in the unprotected header", [(uint(259), text("x"))]),
            ("t17-260-unprotected", "label 260 in the unprotected header", [(uint(260), text("x"))]),
            ("t18-cty-unprotected", "a content type in the unprotected header", [(b"\x03", uint(50))]),
            ("t19-crit-unprotected", "crit in the unprotected header", [(b"\x02", arr([uint(1)]))])):
        b.add_ts(vid, what, ts(parts, [], unprot=cmap([(uint(394), arr([bstr(rc(dh))]))] + unprot)),
                 status("outside_profile", "outside_profile", ["confirmed"]))
    detached = b.statement_parts(payload=None)
    b.add_ts("t20-detached-payload", "the statement payload is detached", ts(detached, [rc(dh)]),
             status("outside_profile", "outside_profile", ["receipt_not_bound"], payload_digest=None))

    # -- label 394 --------------------------------------------------------------------------------------
    for vid, what, unprot, stmt in (
            ("u01-no-394", "a Signed Statement without receipts", b"\xa0", "confirmed"),
            ("u02-394-empty", "label 394 holds an empty array", cmap([(uint(394), arr([]))]), "confirmed"),
            ("u03-394-nine", "nine receipts, one more than the limit",
             cmap([(uint(394), arr([bstr(rc(dh))] * 9))]), "confirmed"),
            ("u04-394-bytes", "label 394 holds a byte string", cmap([(uint(394), bstr(rc(dh)))]), "confirmed")):
        b.add_ts(vid, what, ts(parts, [], unprot=unprot),
                 status("malformed", stmt, [], readable=False, signature_valid=False, data_hash=None,
                        statement_signature_valid=True, payload_digest=SYN_ROOT.hex()))
    b.add_ts("u05-394-protected-only", "label 394 in the protected header only",
             ts(b.statement_parts(prot=b.protected(b"\x26", cert, [(uint(394), arr([bstr(rc(dh))]))])), [],
                unprot=b"\xa0"), status("malformed", "confirmed", []))
    b.add_ts("u06-eight-receipts", "eight receipts, the limit", ts(parts, [rc(dh)] * 8), confirmed(8))
    b.add_ts("u07-statement-trailing-byte", "a byte after the statement",
             ts(parts, [rc(dh)]) + b"\x00", status("malformed", "malformed", []))
    b.add_ts("u09-no-394-ignored-trust", "no receipts, with statement keys v1 cannot use: the refusal reports "
             "no ignored trust", ts(parts, [], unprot=b"\xa0"),
             status("malformed", "confirmed", [], ignored_trust_count=0), trust="syn-statement-keys-junk")
    b.add_ts("u08-unbound-and-malformed", "another root and an unreadable receipt: malformed decides",
             ts(parts, [b"\x01"]), status("malformed", "unbound", ["malformed"]), root=b"\x07" * 32)

    # -- the receipt pass: every rule refuses its receipt alone ------------------------------------------
    b.zero_signatures = True

    def refused(vid, what, receipt, **kw):
        b.add_ts(vid, what, ts(parts, [receipt, good]),
                 status("confirmed", "confirmed", ["malformed", "confirmed"], readable=True,
                        receipt_readable=[False, True], **kw))
    refused("v01-receipt-not-bytes", "a receipt that is an integer", _Raw(uint(5)))
    refused("v02-receipt-not-cbor", "a receipt that is not CBOR", b"\xff")
    refused("v03-receipt-kid-text", "receipt kid is text", rc(dh, prot_pairs=[
        (uint(1), uint(-7)), (uint(4), text("k")), (uint(15), cmap([(uint(1), text(ISSUER))])), (uint(395), b"\x02")]))
    refused("v04-cwt-iss-int", "the CWT issuer is an integer", rc(dh, prot_pairs=[
        (uint(1), uint(-7)), (uint(4), bstr(b.kid("svc_p256"))), (uint(15), cmap([(uint(1), uint(5))])),
        (uint(395), b"\x02")]))
    refused("v05-cwt-iat-text", "the CWT iat is text", rc(dh, prot_pairs=[
        (uint(1), uint(-7)), (uint(4), bstr(b.kid("svc_p256"))),
        (uint(15), cmap([(uint(1), text(ISSUER)), (uint(6), text("now"))])), (uint(395), b"\x02")]))
    refused("v06-unprotected-cwt-iat-text", "the CWT iat in the unprotected header is text",
            rc(dh, prot_pairs=[(uint(1), uint(-7)), (uint(4), bstr(b.kid("svc_p256"))), (uint(395), b"\x02")],
               unprot=cmap([(uint(15), cmap([(uint(1), text(ISSUER)), (uint(6), text("now"))])),
                            (uint(396), cmap([(uint(-1), arr([bstr(b.inclusion(dh)[0])]))]))])))
    refused("v07-vds-text", "vds is text", rc(dh, vds=text("2")))
    refused("v08-vdp-protected-bytes", "a protected vdp that is not a map, none unprotected",
            rc(dh, extra_prot=[(uint(396), bstr(b"x"))], unprot=cmap([])))
    refused("v09-vdp-key-3", "vdp carries -3", rc(dh, vdp=cmap([(uint(-1), arr([bstr(b.inclusion(dh)[0])])),
                                                            (uint(-3), arr([]))])))
    refused("v10-vdp-empty", "vdp is an empty map", rc(dh, vdp=cmap([])))
    refused("v11-inclusion-not-array", "vdp -1 is a byte string", rc(dh, vdp=cmap([(uint(-1), bstr(b"x"))])))
    refused("v12-inclusion-empty", "vdp -1 is empty", rc(dh, vdp=cmap([(uint(-1), arr([]))])))
    proof, _root = b.inclusion(dh)
    refused("v13-inclusion-nine", "nine inclusion proofs", rc(dh, vdp=cmap([(uint(-1), arr([bstr(proof)] * 9))])))
    refused("v14-consistency-nine", "nine consistency proofs",
            rc(dh, consistency=[b.consistency(b"\x04" * 32, [(True, b"\x05" * 32)])[0]] * 9))
    refused("v15-ccf-alg-text", "a CCF receipt whose alg is text", rc(dh, prot_pairs=[
        (uint(1), text("ES256")), (uint(4), bstr(b.kid("svc_p256"))), (uint(15), cmap([(uint(1), text(ISSUER))])),
        (uint(395), b"\x02")]))
    refused("v16-proof-not-bytes", "a proof that is an integer", rc(dh, vdp=cmap([(uint(-1), arr([uint(1)]))])))
    refused("v17-proof-not-cbor", "a proof that is not CBOR", rc(dh, vdp=cmap([(uint(-1), arr([bstr(b"\xff")]))])))
    refused("v18-proof-three-keys", "a proof map with a third key", rc(dh, inclusion=[
        cmap([(uint(1), arr([bstr(b"\x01" * 32), text("e"), bstr(dh)])), (uint(2), arr([arr([TRUE, bstr(b"\x02" * 32)])])),
              (uint(3), uint(0))])]))
    refused("v19-path-empty", "an empty path", rc(dh, inclusion=[b.inclusion(dh, raw_path=arr([]))[0]]))
    refused("v20-path-65", "a path of 65 elements", rc(dh, inclusion=[b.inclusion(dh, path=[(True, b"\x02" * 32)] * 65)[0]]))
    refused("v21-path-element-int", "a path element [int, bstr]",
            rc(dh, inclusion=[b.inclusion(dh, raw_path=arr([arr([uint(1), bstr(b"\x02" * 32)])]))[0]]))
    refused("v22-sibling-31", "a sibling of 31 bytes", rc(dh, inclusion=[b.inclusion(dh, path=[(True, b"\x02" * 31)])[0]]))
    refused("v23-leaf-two", "a leaf of two components",
            rc(dh, inclusion=[b.inclusion(dh, leaf=arr([bstr(b"\x01" * 32), bstr(dh)]))[0]]))
    refused("v24-itx-31", "internal-transaction-hash of 31 bytes",
            rc(dh, inclusion=[b.inclusion(dh, leaf=arr([bstr(b"\x01" * 31), text("e"), bstr(dh)]))[0]]))
    refused("v25-evidence-empty", "empty internal-evidence",
            rc(dh, inclusion=[b.inclusion(dh, leaf=arr([bstr(b"\x01" * 32), text(""), bstr(dh)]))[0]]))
    refused("v26-evidence-1025-bytes", "internal-evidence of 1025 bytes in 513 characters",
            rc(dh, inclusion=[b.inclusion(dh, ev="é" * 512 + "x")[0]]))
    refused("v27-data-hash-33", "a leaf data-hash of 33 bytes",
            rc(dh, inclusion=[b.inclusion(dh, leaf=arr([bstr(b"\x01" * 32), text("e"), bstr(dh + b"\x00")]))[0]]))
    refused("v28-anchor-31", "a consistency anchor of 31 bytes",
            rc(dh, consistency=[cmap([(uint(1), bstr(b"\x04" * 31)), (uint(2), arr([arr([TRUE, bstr(b"\x05" * 32)])]))])]))
    refused("v29-proof-with-tag", "a proof with a tag inside",
            rc(dh, inclusion=[cmap([(uint(1), b"\xc1" + arr([bstr(b"\x01" * 32), text("e"), bstr(dh)])),
                                    (uint(2), arr([arr([TRUE, bstr(b"\x02" * 32)])]))])]))
    refused("v30-receipt-protected-tag", "a tag in the receipt's protected header",
            rc(dh, extra_prot=[(uint(99), b"\xc1\x00")]))
    refused("v31-receipt-both-buckets", "the receipt carries kid in both buckets",
            rc(dh, unprot=cmap([(uint(4), bstr(b"k")), (uint(396), cmap([(uint(-1), arr([bstr(proof)]))]))])))
    refused("v32-receipt-crit-empty", "crit is an empty array", rc(dh, extra_prot=[(uint(2), arr([]))]))
    refused("v33-receipt-cwt-array", "the CWT claims are an array", rc(dh, prot_pairs=[
        (uint(1), uint(-7)), (uint(4), bstr(b.kid("svc_p256"))), (uint(15), arr([])), (uint(395), b"\x02")]))
    refused("v34-receipt-cty-negative", "a negative content type", rc(dh, extra_prot=[(uint(3), uint(-1))]))
    refused("v38-vds-text-unprotected", "vds as text in the unprotected header, none protected",
            rc(dh, vds=None, unprot=cmap([(uint(395), text("2")), (uint(396), cmap([(uint(-1), arr([bstr(proof)]))]))])))
    refused("v39-leaf-four", "a leaf of four components",
            rc(dh, inclusion=[b.inclusion(dh, leaf=arr([bstr(b"\x01" * 32), text("e"), bstr(dh), uint(0)]))[0]]))
    refused("v37-receipt-alg-bytes-not-ccf", "alg is a byte string in a receipt that is not CCF", rc(dh, prot_pairs=[
        (uint(1), bstr(b"\x26")), (uint(4), bstr(b.kid("svc_p256"))), (uint(15), cmap([(uint(1), text(ISSUER))])),
        (uint(395), uint(3))]))
    b.zero_signatures = False
    b.add_ts("v35-evidence-1024-bytes", "internal-evidence of 1024 bytes in 512 characters",
             ts(parts, [rc(dh, inclusion=[b.inclusion(dh, ev="é" * 512)[0]], sign_root=b.inclusion(dh, ev="é" * 512)[1])]),
             confirmed())
    b.add_ts("v36-path-64", "a path of 64 elements",
             ts(parts, [rc(dh, inclusion=[b.inclusion(dh, path=[(True, b"\x02" * 32)] * 64)[0]],
                           sign_root=b.inclusion(dh, path=[(True, b"\x02" * 32)] * 64)[1])]), confirmed())

    # -- the status logic of one receipt -------------------------------------------------------------
    def one(vid, what, receipt, receipt_status, top=None, **kw):
        b.add_ts(vid, what, ts(parts, [receipt]), status(top or receipt_status, "confirmed", [receipt_status], **kw))
    one("w01-receipt-untagged", "the receipt without tag 18", rc(dh, tag=b""), "outside_profile")
    one("w02-receipt-alg-ps256", "receipt alg -37", rc(dh, alg=-37), "outside_profile")
    one("w03-receipt-vds-absent", "no vds: not a CCF receipt, not readable", rc(dh, vds=None), "outside_profile",
        readable=False)
    one("w04-receipt-vds-3", "vds 3", rc(dh, vds=uint(3)), "outside_profile", readable=False)
    one("w05-receipt-kid-absent", "no kid", rc(dh, prot_pairs=[
        (uint(1), uint(-7)), (uint(15), cmap([(uint(1), text(ISSUER))])), (uint(395), b"\x02")]), "outside_profile")
    one("w06-receipt-iss-absent", "no CWT issuer", rc(dh, iss=None), "outside_profile")
    one("w07-receipt-payload-attached", "the receipt payload attached", rc(dh, payload=bstr(b.inclusion(dh)[1])),
        "outside_profile")
    one("w08-receipt-crit-unprotected", "crit in the receipt's unprotected header",
        rc(dh, unprot=cmap([(uint(2), arr([uint(1)])), (uint(396), cmap([(uint(-1), arr([bstr(proof)]))]))])),
        "outside_profile")
    one("w09-receipt-crit-99", "crit lists a label v1 does not process", rc(dh, extra_prot=[(uint(2), arr([uint(99)])),
                                                                                         (uint(99), uint(0))]),
        "outside_profile")
    one("w10-receipt-crit-kid", "crit lists kid, which v1 processes", rc(dh, extra_prot=[(uint(2), arr([uint(4)]))]),
        "confirmed")
    one("w11-receipt-crit-text", "crit lists a text label that is present",
        rc(dh, extra_prot=[(uint(2), arr([text("ccf.v1")]))]), "outside_profile")
    one("w12-no-inclusion", "only a consistency proof", rc(dh, vdp=cmap([(uint(-2), arr([bstr(
        b.consistency(b"\x04" * 32, [(True, b"\x05" * 32)])[0])]))])), "outside_profile", readable=False,
        receipt_consistency=[True])
    p2, _r2 = b.inclusion(dh, itx=b"\x09" * 32)
    one("w13-inclusion-roots-differ", "two inclusion proofs with different roots",
        rc(dh, inclusion=[proof, p2], sign_root=_root), "root_mismatch")
    cp, _newer = b.consistency(b"\x04" * 32, [(True, b"\x05" * 32)])
    one("w14-consistency-other-root", "a consistency proof computes another newer root",
        rc(dh, consistency=[cp]), "root_mismatch", receipt_consistency=[True])
    # a consistency proof whose newer root is the inclusion root: fold the anchor so it lands there
    leaf_path = [(True, b"\x02" * 32), (False, b"\x03" * 32)]
    a0 = b.leaf_root(b"\x01" * 32, "ccf evidence", dh, [])
    cp_same, newer_same = b.consistency(a0, leaf_path)
    assert newer_same == _root
    one("w15-consistency-same-root", "a consistency proof that computes the inclusion root",
        rc(dh, consistency=[cp_same]), "confirmed", receipt_consistency=[True])
    other_dh, _ = b.data_hash(payload=b"\x08" * 32)
    one("w16-receipt-not-bound", "a valid receipt over another statement's data hash", rc(other_dh),
        "receipt_not_bound", receipt_bound=[False], signature_valid=True)
    one("w17-receipt-signature-zeros", "a receipt signature of zeros", rc(dh, sig=bytes(64)), "signature_invalid",
        signature_valid=False, receipt_bound=[True])
    one("w18-receipt-alg-es256-p384-key", "alg -7 under the P-384 key's kid: the curve is not the algorithm's",
        rc(dh, key="svc_p384", alg=-7, sig=bytes(64)), "signature_invalid")
    one("w19-receipt-over-another-root", "a receipt signed over another root", rc(dh, sign_root=b"\x06" * 32),
        "signature_invalid")
    one("w20-receipt-signature-65", "a receipt signature of 65 bytes", rc(dh, sig=b.svc_sign(
        "svc_p256", C._sig_structure(b"", b"")) + b"\x00"), "signature_invalid")
    one("w21-iat-max", "the largest iat CBOR holds", rc(dh, iat=2 ** 64 - 1), "confirmed",
        receipt_iats=[2 ** 64 - 1])
    one("w22-iat-negative", "the most negative iat CBOR holds", rc(dh, iat=-(2 ** 64)), "confirmed",
        receipt_iats=[-(2 ** 64)])
    one("w23-txid-int", "a txid that is not text", rc(dh, txid=uint(7)), "confirmed", receipt_txids=[None])
    one("w24-ccf-header-not-map", "a ccf.v1 header that is text", rc(dh, prot_pairs=[
        (uint(1), uint(-7)), (uint(4), bstr(b.kid("svc_p256"))), (uint(15), cmap([(uint(1), text(ISSUER))])),
        (uint(395), b"\x02"), (text("ccf.v1"), text("2.70"))]), "confirmed", receipt_txids=[None], receipt_iats=[None])

    one("w25-consistency-not-ccf", "vds 3 with a consistency family: outside, the family reported",
        rc(dh, vds=uint(3), vdp=cmap([(uint(-2), arr([bstr(cp)]))])), "outside_profile", readable=False,
        receipt_consistency=[True])
    one("w26-vdp-protected-only", "a CCF receipt whose vdp is in the protected header: no inclusion proof read",
        rc(dh, extra_prot=[(uint(396), cmap([(uint(-1), arr([bstr(proof)]))]))], unprot=cmap([])),
        "outside_profile", readable=False)
    base = [(uint(1), uint(-7)), (uint(4), bstr(b.kid("svc_p256"))), (uint(15), cmap([(uint(1), text(ISSUER))])),
            (uint(395), b"\x02")]
    vdp_only = (uint(396), cmap([(uint(-1), arr([bstr(proof)]))]))
    one("w27-txid-unprotected", "the ccf.v1 header in the unprotected bucket: no txid",
        rc(dh, prot_pairs=base, unprot=cmap([(text("ccf.v1"), cmap([(text("txid"), text("2.70"))])), vdp_only])),
        "confirmed", receipt_txids=[None])
    one("w28-kid-unprotected", "kid in the unprotected bucket only", rc(dh, prot_pairs=[base[0], base[2], base[3]],
        unprot=cmap([(uint(4), bstr(b.kid("svc_p256"))), vdp_only])), "outside_profile")
    one("w29-issuer-unprotected", "the CWT issuer in the unprotected bucket only",
        rc(dh, prot_pairs=[base[0], base[1], base[3]],
           unprot=cmap([(uint(15), cmap([(uint(1), text(ISSUER))])), vdp_only])), "outside_profile")

    # -- two receipts: the best one, or the first status in the order --------------------------------
    b.add_ts("y01-invalid-and-untrusted", "a signature_invalid and a needs_rp_trust receipt",
             ts(parts, [rc(dh, sig=bytes(64)), rc(dh, key="svc_p256", kid=b"nobody")]),
             status("signature_invalid", "confirmed", ["signature_invalid", "needs_rp_trust"]))
    b.add_ts("y02-not-bound-and-mismatch", "receipt_not_bound and root_mismatch",
             ts(parts, [rc(other_dh), rc(dh, consistency=[cp])]),
             status("root_mismatch", "confirmed", ["receipt_not_bound", "root_mismatch"]))
    b.add_ts("y03-outside-then-confirmed", "an outside receipt and a confirmed one",
             ts(parts, [rc(dh, alg=-37), rc(dh)]), confirmed(2, receipt_statuses=["outside_profile", "confirmed"]))
    b.add_ts("y04-statement-invalid-over-confirmed", "a failed statement signature outranks a confirmed receipt",
             ts(bad, [rc(dh_bad), rc(dh_bad, key="svc_p384", alg=-35)]),
             status("statement_signature_invalid", "statement_signature_invalid", ["confirmed", "confirmed"]))
    b.add_ts("y05-outside-statement-root-mismatch", "outside_profile outranks root_mismatch",
             ts(detached, [rc(dh, consistency=[cp])]),
             status("outside_profile", "outside_profile", ["root_mismatch"]))


def _protected_bstr(receipt: bytes) -> bytes:
    """The protected-header element of a tagged COSE_Sign1, as served."""
    from proofbundle._cbor_prescan import scan  # noqa: PLC0415
    a, e = scan(receipt, max_bytes=len(receipt), max_depth=16, tag_allowed=lambda path, n: n == 18).element_spans[0]
    return receipt[a:e]


class _Raw:
    """A receipt element that is not a byte string, inserted into label 394 as it is."""

    def __init__(self, raw: bytes):
        self.raw = raw


def dump(doc: dict) -> str:
    """The file: everything but the vectors indented, then one vector per line."""
    head = json.dumps({k: v for k, v in doc.items() if k != "vectors"}, indent=1)
    rows = ",\n".join("  " + json.dumps(v) for v in doc["vectors"])
    return head[:-2] + ',\n "vectors": [\n' + rows + "\n ]\n}\n"


def build() -> dict:
    b = Builder()
    real_vectors(b)
    synthetic_vectors(b)
    return {
        "schema": "proofbundle.scitt_transparent_statement_vectors.v1",
        "surface": "proofbundle.scitt_ccf.verify_transparent_statement",
        "rust_subcommand": "verify-scitt-transparent-statement",
        "generated_by": "tools/scitt_ccf_external/transparent_statement_vectors.py",
        "oracle": ("each vector's want is the verdict it is built to produce; for a statement a scitt-ccf-ledger "
                   "served, the status its corpus round recorded and the leaf data-hash the ledger put in its receipt. "
                   "The generator wrote the file only after the Python verifier returned exactly that for every "
                   "vector"),
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
