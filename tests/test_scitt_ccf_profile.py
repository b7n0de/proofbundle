"""The scitt-ccf/v1 reader, class by class (ADR 0009, section "Test classes"). Needs the [scitt] extra.

Each class opens with its unchanged CONTROL, which must confirm, and then changes one thing per case
and names the status that change must produce. A class whose control failed would prove nothing, so
every negative case starts from the control's own builder with exactly one argument changed.

SYNTHETIC means: keys generated in this module, statements and receipts built here. REAL means the
committed vector tests/fixtures/scitt_ccf/local_ledger_control.json: a hash envelope over the root of
examples/example_bundle.json, registered on a local scitt-ccf-ledger in virtual mode
(tools/scitt_ccf_external/local_ledger_probe.py, 2026-09-25).
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import inspect
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

import pytest

# A module-wide skip mark, not a module-level importorskip: without the extra the cases must still be
# COLLECTED, so the mutation gate's collector sees this file (test_mutationstor_sammler_...py).
pytestmark = pytest.mark.skipif(importlib.util.find_spec("cbor2") is None,
                                reason="the scitt-ccf reader needs the [scitt] extra")

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils  # noqa: E402

from proofbundle import scitt_ccf as S  # noqa: E402

VECTOR = Path(__file__).resolve().parent / "fixtures" / "scitt_ccf" / "local_ledger_control.json"
ISSUER = "service.example"


# ------------------------------------------------------------------------------------------------
# A small shortest-form encoder, and bytes built by hand where a case needs other bytes
# ------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class T:
    n: int
    v: object


def _h(mt, n):
    if n < 24:
        return bytes([(mt << 5) | n])
    for ai, w in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * w):
            return bytes([(mt << 5) | ai]) + n.to_bytes(w, "big")
    raise ValueError(n)


def enc(o) -> bytes:
    if o is None:
        return b"\xf6"
    if o is True:
        return b"\xf5"
    if o is False:
        return b"\xf4"
    if isinstance(o, int):
        return _h(0, o) if o >= 0 else _h(1, -1 - o)
    if isinstance(o, bytes):
        return _h(2, len(o)) + o
    if isinstance(o, str):
        b = o.encode("utf-8")
        return _h(3, len(b)) + b
    if isinstance(o, list):
        return _h(4, len(o)) + b"".join(enc(x) for x in o)
    if isinstance(o, dict):
        return _h(5, len(o)) + b"".join(enc(k) + enc(v) for k, v in o.items())
    if isinstance(o, T):
        return _h(6, o.n) + enc(o.v)
    raise TypeError(type(o))


def tbs(prot: bytes, payload: bytes, aad: bytes = b"") -> bytes:
    return enc(["Signature1", prot, aad, payload])


def spki(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)


def ecdsa(key, data: bytes, n: int, h) -> bytes:
    r, s = utils.decode_dss_signature(key.sign(data, ec.ECDSA(h)))
    return r.to_bytes(n, "big") + s.to_bytes(n, "big")


STMT_KEY = ec.generate_private_key(ec.SECP256R1())
SERVICE_KEY = ec.generate_private_key(ec.SECP384R1())
OTHER_SERVICE_KEY = ec.generate_private_key(ec.SECP384R1())
ROOT = hashlib.sha256(b"a proofbundle target").digest()


def kid_of(key) -> bytes:
    return hashlib.sha256(spki(key)).hexdigest().encode("ascii")


# ------------------------------------------------------------------------------------------------
# The synthetic control, and the one-argument deviations from it
# ------------------------------------------------------------------------------------------------
AUTO = object()     # the protected x5chain names the signer, which v1 requires (owner answer N7 b)


@dataclass
class Stmt:
    prot_map: dict = field(default_factory=lambda: {1: -7, 258: -16, 259: "application/json",
                                                    15: {1: "did:example:signer"}})
    prot_raw: bytes | None = None
    payload: bytes | None = ROOT
    unprot: dict = field(default_factory=dict)
    key: object = None
    sig: bytes | None = None
    x5chain: object = AUTO      # AUTO: the signer's chain; None: no protected x5chain; else this value

    def header(self) -> dict:
        """The protected map as signed: prot_map, plus label 33 unless the map carries its own."""
        m = dict(self.prot_map)
        if 33 not in m and self.x5chain is not None:
            m[33] = chain_of(self.key or STMT_KEY) if self.x5chain is AUTO else self.x5chain
        return m

    def protected(self) -> bytes:
        return self.prot_raw if self.prot_raw is not None else enc(self.header())

    def signature(self) -> bytes:
        # made once per statement: ECDSA is randomised, and every call must see the same bytes
        if self.sig is None:
            self.sig = ecdsa(self.key or STMT_KEY, tbs(self.protected(), self.payload or ROOT), 32,
                             hashes.SHA256())
        return self.sig

    def signed_bytes(self) -> bytes:
        return b"\xd2\x84" + enc(self.protected()) + b"\xa0" + enc(self.payload) + enc(self.signature())


@dataclass
class Rcpt:
    data_hash: bytes = b""
    key: object = None
    alg: int = -35
    issuer: str = ISSUER
    kid: bytes | None = None
    vds: object = 2
    path_len: int = 4
    evidence: str = "ce:2.57:" + "8c" * 32
    extra_prot: dict = field(default_factory=dict)
    drop_prot: tuple = ()
    payload: object = None
    aad: bytes = b""
    leaf_rule: str = "-05"
    second_proof_root_differs: bool = False
    n_proofs: int = 1
    proofs_override: object = None     # the inclusion proofs as given, junk included
    tagged: bool = True

    def build(self) -> bytes:
        key = self.key or SERVICE_KEY
        itx = hashlib.sha256(b"itx").digest()
        if self.leaf_rule == "-05":
            leaf = hashlib.sha256(itx + hashlib.sha256(self.evidence.encode()).digest() + self.data_hash).digest()
        else:   # the -04 reading of section 2.1
            leaf = hashlib.sha256(enc([itx, self.evidence, self.data_hash])).digest()
        path = [[i % 2 == 0, hashlib.sha256(bytes([i])).digest()] for i in range(self.path_len)]
        h = leaf
        for left, sib in path:
            h = hashlib.sha256(sib + h if left else h + sib).digest()
        root = h
        proof = enc({1: [itx, self.evidence, self.data_hash], 2: path})
        proofs = [proof] * self.n_proofs if self.proofs_override is None else self.proofs_override
        if self.second_proof_root_differs:
            path2 = [[True, hashlib.sha256(b"other").digest()]]
            proofs = [proof, enc({1: [itx, self.evidence, self.data_hash], 2: path2})]
        prot = {1: self.alg, 4: self.kid if self.kid is not None else kid_of(key), 395: self.vds,
                15: {1: self.issuer, 2: "scitt.ccf.signature.v1", 6: 1790000000},
                "ccf.v1": {"txid": "2.58"}}
        for k in self.drop_prot:
            prot.pop(k, None)
        prot.update(self.extra_prot)
        prot_b = enc(prot)
        n, h_alg = (48, hashes.SHA384()) if isinstance(key.curve, ec.SECP384R1) else (32, hashes.SHA256())
        sig = ecdsa(key, tbs(prot_b, root, self.aad), n, h_alg)
        body = [prot_b, {396: {-1: proofs}}, self.payload, sig]
        return (b"\xd2" if self.tagged else b"") + enc(body)


def transparent(st: Stmt, receipts: list, extra_unprot: dict | None = None) -> bytes:
    unprot = {394: receipts}
    unprot.update(extra_unprot or {})
    return b"\xd2\x84" + enc(st.protected()) + enc(unprot) + enc(st.payload) + enc(st.signature())


def dh_of(st: Stmt) -> bytes:
    return hashlib.sha256(st.signed_bytes()).digest()


def trust(service_keys=None, statement_keys=None) -> dict:
    return {"scitt_ccf_services": {ISSUER: service_keys if service_keys is not None else [spki(SERVICE_KEY)]},
            "scitt_statement_keys": statement_keys if statement_keys is not None else [spki(STMT_KEY)]}


def control(**stmt_kw) -> tuple:
    st = Stmt(**stmt_kw)
    return st, transparent(st, [Rcpt(data_hash=dh_of(st)).build()])


def verify(ts: bytes, root: bytes = ROOT, rp=None):
    return S.verify_transparent_statement(ts, canonical_root=root, rp_trust=trust() if rp is None else rp)


def test_the_synthetic_control_confirms_with_three_separate_results():
    _st, ts = control()
    r = verify(ts)
    assert (r.status, r.readable, r.signature_valid, r.profile_satisfied) == ("confirmed", True, True, True)
    assert r.statement_signature_valid is True and r.receipts[0].kid_bound_to_key is True
    assert r.receipts[0].receipt_iat == 1790000000
    assert not hasattr(r, "warn") and "trustedTime" not in r.to_dict()


# ------------------------------------------------------------------------------------------------
# REAL: the local-ledger vector
# ------------------------------------------------------------------------------------------------
def _vector():
    v = json.loads(VECTOR.read_text(encoding="utf-8"))
    ks = S.load_cose_keyset(base64.b64decode(v["service_keyset_b64"]))
    rp = {"scitt_ccf_services": {v["issuer"]: ks},
          "scitt_statement_keys": [base64.b64decode(v["statement_signer_spki_b64"])]}
    return v, rp


def test_real_control_from_a_local_ccf_ledger_confirms_end_to_end():
    v, rp = _vector()
    r = S.verify_transparent_statement(base64.b64decode(v["transparent_statement_b64"]),
                                       canonical_root=bytes.fromhex(v["canonical_root_hex"]), rp_trust=rp)
    assert (r.status, r.readable, r.signature_valid, r.profile_satisfied) == ("confirmed", True, True, True)
    assert r.receipts[0].issuer == v["issuer"] and r.receipts[0].kid_bound_to_key is True


@pytest.mark.parametrize("variant, status", [
    ("nonshortest_sig_head", "confirmed"),   # the service stored it re-encoded in shortest form
    ("extra_unprotected", "confirmed"),      # the service stored it with the unprotected map emptied
    ("nonshortest_alg", "malformed"),        # the service kept the protected header as sent; v1 refuses it
])
def test_real_forms_the_service_accepted(variant, status):
    v, rp = _vector()
    ts = base64.b64decode(v["accepted_variants_b64"][variant])
    r = S.verify_transparent_statement(ts, canonical_root=bytes.fromhex(v["canonical_root_hex"]), rp_trust=rp)
    assert r.status == status


def test_real_control_one_input_missing_or_wrong_never_satisfies():
    v, rp = _vector()
    ts = base64.b64decode(v["transparent_statement_b64"])
    root = bytes.fromhex(v["canonical_root_hex"])
    assert S.verify_transparent_statement(ts, canonical_root=root, rp_trust=rp).profile_satisfied
    cases = {
        "unbound": dict(canonical_root=b"\x01" * 32, rp_trust=rp),
        "needs_rp_trust (statement)": dict(canonical_root=root,
                                           rp_trust={"scitt_ccf_services": rp["scitt_ccf_services"]}),
        "needs_rp_trust (service)": dict(canonical_root=root,
                                         rp_trust={"scitt_statement_keys": rp["scitt_statement_keys"]}),
        "needs_rp_trust (none)": dict(canonical_root=root, rp_trust=None),
        # owner answer N4 b: the protected x5chain names a key the RP no longer holds
        "needs_rp_trust (statement key rotated away)": dict(canonical_root=root, rp_trust={
            **rp, "scitt_statement_keys": [spki(ec.generate_private_key(ec.SECP256R1()))]}),
    }
    for label, kw in cases.items():
        r = S.verify_transparent_statement(ts, **kw)
        assert not r.profile_satisfied, label
        assert r.status == label.split(" ")[0], label


# ------------------------------------------------------------------------------------------------
# Class: structure
# ------------------------------------------------------------------------------------------------
def test_structure_control():
    assert verify(control()[1]).status == "confirmed"


@pytest.mark.parametrize("mutate, status", [
    (lambda ts: ts[:1] + b"\x83" + ts[2:], "malformed"),                     # three elements
    (lambda ts: ts[:1] + b"\x85" + ts[2:] + b"\x00", "malformed"),           # five elements
    (lambda ts: b"\x84" + ts[2:], "outside_profile"),                        # untagged statement
    (lambda ts: b"", "malformed"),
    (lambda ts: ts + b"\x00", "malformed"),                                  # trailing byte
])
def test_structure_statement(mutate, status):
    assert verify(mutate(control()[1])).status == status


def test_structure_no_receipt_is_not_a_transparent_statement():
    st = Stmt()
    ts = b"\xd2\x84" + enc(st.protected()) + b"\xa0" + enc(st.payload) + enc(st.signature())
    assert verify(ts).status == "malformed"
    ts = transparent(st, [])
    assert verify(ts).status == "malformed"


@pytest.mark.parametrize("rkw, status", [
    (dict(evidence=""), "malformed"),
    (dict(evidence="x" * 1025), "malformed"),
    (dict(path_len=0), "malformed"),
    (dict(tagged=False), "outside_profile"),
])
def test_structure_receipt(rkw, status):
    st = Stmt()
    r = verify(transparent(st, [Rcpt(data_hash=dh_of(st), **rkw).build()]))
    assert r.receipts[0].status == status and not r.profile_satisfied


def test_structure_leaf_and_path_element_types():
    st = Stmt()
    good = Rcpt(data_hash=dh_of(st)).build()
    assert verify(transparent(st, [good])).status == "confirmed"
    # a 31-byte data-hash and an integer where a bool belongs, spliced into an otherwise valid receipt
    short = Rcpt(data_hash=dh_of(st)[:31]).build()
    assert verify(transparent(st, [short])).receipts[0].status == "malformed"
    bad_flag = good.replace(b"\x82\xf5\x58\x20", b"\x82\x01\x58\x20", 1)
    assert bad_flag != good
    assert verify(transparent(st, [bad_flag])).receipts[0].status == "malformed"


def test_structure_a_legacy_two_element_receipt_is_malformed():
    st = Stmt()
    legacy = enc([enc({"tree_alg": "CCF"}), [b"\x00" * 96, b"cert", [], [b"\x00" * 32, "ce:1.1:" + "00" * 32]]])
    assert verify(transparent(st, [legacy])).receipts[0].status == "malformed"


# ------------------------------------------------------------------------------------------------
# Class: unique headers
# ------------------------------------------------------------------------------------------------
def test_unique_headers_control():
    assert verify(control()[1]).status == "confirmed"


def test_unique_headers_duplicate_label_in_protected_is_malformed():
    prot = enc({1: -7, 258: -16, 15: {1: "did:example:signer"}})
    dup = b"\xa4" + prot[1:] + b"\x01\x26"                   # a second label 1, same value
    st = Stmt(prot_raw=dup)
    assert verify(transparent(st, [Rcpt(data_hash=dh_of(st)).build()])).status == "malformed"


@pytest.mark.parametrize("stmt_kw, extra_unprot, status", [
    (dict(), {1: -7}, "malformed"),                                              # label in both buckets
    (dict(prot_map={1: -7, 15: {1: "i"}}), {258: -16}, "outside_profile"),       # 258 only unprotected
    (dict(prot_map={1: -7, 258: -16, 15: {1: "i"}}), {259: "text/plain"}, "outside_profile"),
    (dict(), {259: "text/plain"}, "malformed"),                                   # 259 in both buckets
    (dict(), {260: "https://example.invalid"}, "outside_profile"),
    (dict(prot_map={1: -7, 258: -16, 3: "application/json", 15: {1: "i"}}), {}, "outside_profile"),
    (dict(), {3: "application/json"}, "outside_profile"),
])
def test_unique_headers_placement(stmt_kw, extra_unprot, status):
    st = Stmt(**stmt_kw)
    ts = transparent(st, [Rcpt(data_hash=dh_of(st)).build()], extra_unprot)
    assert verify(ts).status == status


def test_unique_headers_duplicate_keys_deeper_down():
    # CWT claims with a duplicate key
    cwt_dup = b"\xa3\x01\x26\x19\x01\x02\x30\x0f\xa2\x01\x61\x69\x01\x61\x6a"
    st = Stmt(prot_raw=cwt_dup)
    assert verify(transparent(st, [Rcpt(data_hash=dh_of(st)).build()])).status == "malformed"
    # a key set with a duplicate key
    with pytest.raises(S.ScittFormatError):
        S.load_cose_keyset(b"\x81\xa2\x01\x02\x01\x02")
    # the inclusion proof map and vdp with a duplicate key
    st = Stmt()
    good = Rcpt(data_hash=dh_of(st)).build()
    dup_vdp = good.replace(b"\xa1\x19\x01\x8c\xa1\x20", b"\xa1\x19\x01\x8c\xa2\x20\x80\x20", 1)
    assert dup_vdp != good
    assert verify(transparent(st, [dup_vdp])).receipts[0].status == "malformed"


# ------------------------------------------------------------------------------------------------
# Class: crit
# ------------------------------------------------------------------------------------------------
def test_crit_control_listing_a_processed_label_still_confirms():
    st = Stmt(prot_map={1: -7, 2: [1], 258: -16, 15: {1: "i"}})
    assert verify(transparent(st, [Rcpt(data_hash=dh_of(st)).build()])).status == "confirmed"


@pytest.mark.parametrize("prot_map, extra_unprot", [
    ({1: -7, 258: -16, 15: {1: "i"}}, {2: [1]}),                  # crit in unprotected
    ({1: -7, 2: [], 258: -16, 15: {1: "i"}}, {}),                 # empty crit
    ({1: -7, 2: [260], 258: -16, 15: {1: "i"}}, {}),              # lists an absent label
    ({1: -7, 2: [259], 258: -16, 259: "a/b", 15: {1: "i"}}, {}),  # lists a label v1 does not process
])
def test_crit_statement(prot_map, extra_unprot):
    st = Stmt(prot_map=prot_map)
    assert verify(transparent(st, [Rcpt(data_hash=dh_of(st)).build()], extra_unprot)).status == "outside_profile"


def test_crit_receipt():
    st = Stmt()
    ok = Rcpt(data_hash=dh_of(st), extra_prot={2: [1, 395]}).build()
    assert verify(transparent(st, [ok])).status == "confirmed"
    bad = Rcpt(data_hash=dh_of(st), extra_prot={2: ["ccf.v1"]}).build()
    assert verify(transparent(st, [bad])).receipts[0].status == "outside_profile"


# ------------------------------------------------------------------------------------------------
# Class: resource and tag limits
# ------------------------------------------------------------------------------------------------
def test_limits_control_at_l():
    st = Stmt()
    dh = dh_of(st)
    rc = Rcpt(data_hash=dh, path_len=S.MAX_PATH, evidence="c" * S.MAX_EVIDENCE_BYTES).build()
    assert verify(transparent(st, [rc] * S.MAX_RECEIPTS)).status == "confirmed"
    rc = Rcpt(data_hash=dh, n_proofs=S.MAX_INCLUSION_PROOFS).build()
    assert verify(transparent(st, [rc])).status == "confirmed"


def test_limits_at_l_plus_one():
    st = Stmt()
    dh = dh_of(st)
    assert verify(transparent(st, [Rcpt(data_hash=dh, path_len=S.MAX_PATH + 1).build()])).receipts[0].status == "malformed"
    assert verify(transparent(st, [Rcpt(data_hash=dh, evidence="c" * (S.MAX_EVIDENCE_BYTES + 1)).build()])
                  ).receipts[0].status == "malformed"
    assert verify(transparent(st, [Rcpt(data_hash=dh, n_proofs=S.MAX_INCLUSION_PROOFS + 1).build()])
                  ).receipts[0].status == "malformed"
    rc = Rcpt(data_hash=dh).build()
    assert verify(transparent(st, [rc] * (S.MAX_RECEIPTS + 1))).status == "malformed"


def test_limits_evidence_counts_bytes_not_characters():
    st = Stmt()
    rc = Rcpt(data_hash=dh_of(st), evidence="é" * 600).build()      # 600 characters, 1200 bytes
    assert verify(transparent(st, [rc])).receipts[0].status == "malformed"


def test_limits_statement_size_at_l_and_l_plus_one():
    st = Stmt()
    base = transparent(st, [Rcpt(data_hash=dh_of(st)).build()])
    assert len(base) < S.MAX_STATEMENT_BYTES
    for size, status in ((S.MAX_STATEMENT_BYTES, "confirmed"), (S.MAX_STATEMENT_BYTES + 1, "malformed")):
        pad = size - len(transparent(st, [Rcpt(data_hash=dh_of(st)).build()], {99: b""}))
        ts = transparent(st, [Rcpt(data_hash=dh_of(st)).build()], {99: b"\x00" * pad})
        grow = len(ts) - size
        if grow:
            ts = transparent(st, [Rcpt(data_hash=dh_of(st)).build()], {99: b"\x00" * (pad - grow)})
        assert len(ts) == size
        assert verify(ts).status == status


def test_limits_depth():
    st = Stmt()
    deep = b"\x81" * 17 + b"\x00"
    ts = transparent(st, [Rcpt(data_hash=dh_of(st)).build()])
    ts_deep = ts[:1] + b"\x84" + enc(st.protected()) + b"\xa2\x19\x01\x8a" + enc(
        [Rcpt(data_hash=dh_of(st)).build()]) + b"\x18\x63" + deep + enc(st.payload) + enc(st.signature())
    assert verify(ts_deep).status == "malformed"


@pytest.mark.parametrize("tag_hex", ["c2", "d818", "d81c", "d9d9f7", "da0001869f"])
def test_limits_tags_refused_in_statement_and_receipt(tag_hex):
    st = Stmt()
    rc = Rcpt(data_hash=dh_of(st)).build()
    tag = bytes.fromhex(tag_hex)
    in_statement = (b"\xd2\x84" + enc(st.protected()) + b"\xa2\x19\x01\x8a" + enc([rc]) + b"\x18\x63"
                    + tag + b"\x41\x00" + enc(st.payload) + enc(st.signature()))
    assert verify(in_statement).status == "malformed"
    plain = Rcpt(data_hash=dh_of(st), extra_prot={"x": 0}).build()
    assert verify(transparent(st, [plain])).status == "confirmed"          # the control of this case
    in_receipt = plain.replace(b"\x61\x78\x00", b"\x61\x78" + tag + b"\x41\x00", 1)
    assert in_receipt != plain
    assert verify(transparent(st, [in_receipt])).receipts[0].status == "malformed"


def test_limits_tag_1_only_around_a_cwt_time_claim():
    ok = Stmt(prot_map={1: -7, 258: -16, 15: {1: "i", 6: T(1, 1790000000)}})
    assert verify(transparent(ok, [Rcpt(data_hash=dh_of(ok)).build()])).status == "confirmed"
    for bad in ({1: -7, 258: -16, 15: {1: "i", 2: T(1, 5)}},          # around a non-time claim
                {1: -7, 258: -16, 15: {1: "i"}, 99: T(1, 5)}):         # outside the CWT map
        st = Stmt(prot_map=bad)
        assert verify(transparent(st, [Rcpt(data_hash=dh_of(st)).build()])).status == "malformed"
    st = Stmt()
    rc = Rcpt(data_hash=dh_of(st), extra_prot={15: {1: ISSUER, 6: T(1, 5)}}).build()
    assert verify(transparent(st, [rc])).receipts[0].status == "malformed"      # never in a receipt


def test_limits_encoding_forms():
    st, ts = control()
    indefinite = b"\xd2\x9f" + ts[2:] + b"\xff"
    assert verify(indefinite).status == "malformed"
    nonshortest = ts.replace(b"\x58\x40", b"\x59\x00\x40", 1)
    assert nonshortest != ts and verify(nonshortest).status == "malformed"
    floaty = b"\xd2\x84" + enc(st.protected()) + b"\xa2\x19\x01\x8a" + enc(
        [Rcpt(data_hash=dh_of(st)).build()]) + b"\x18\x63\xf9\x3c\x00" + enc(st.payload) + enc(st.signature())
    assert verify(floaty).status == "malformed"


# ------------------------------------------------------------------------------------------------
# Class: signed bytes kept original
# ------------------------------------------------------------------------------------------------
def test_signed_bytes_kept_original():
    st, ts = control()
    assert verify(ts).status == "confirmed"
    assert S.recompute_data_hash(ts) == dh_of(st)
    reordered = dict(reversed(list(st.header().items())))          # the same map, other order
    st2 = Stmt(prot_raw=enc(reordered), sig=st.signature())     # same map, other order, old signature
    ts2 = transparent(st2, [Rcpt(data_hash=dh_of(st)).build()])
    r = verify(ts2)
    assert r.status == "statement_signature_invalid"
    assert S.recompute_data_hash(ts2) != dh_of(st)
    flipped = bytearray(ts)
    flipped[-1] ^= 1
    assert S.recompute_data_hash(bytes(flipped)) != dh_of(st)
    assert verify(bytes(flipped)).status == "statement_signature_invalid"


# ------------------------------------------------------------------------------------------------
# Class: external inputs (unknown is not empty)
# ------------------------------------------------------------------------------------------------
def test_external_inputs_control_and_no_aad_parameter_exists():
    assert verify(control()[1]).status == "confirmed"
    for fn in (S.verify_transparent_statement, S.verify_statement_signature, S.decode_cose_sign1):
        assert not any("aad" in p for p in inspect.signature(fn).parameters)


def test_external_inputs_receipt_signed_with_a_non_empty_aad_fails():
    st = Stmt()
    r = verify(transparent(st, [Rcpt(data_hash=dh_of(st), aad=b"\x00").build()]))
    assert r.receipts[0].status == "signature_invalid"


def test_external_inputs_missing_payload_is_not_an_empty_payload():
    st = Stmt()
    detached = b"\xd2\x84" + enc(st.protected()) + enc({394: [Rcpt(data_hash=dh_of(st)).build()]}) + b"\xf6" + enc(st.signature())
    r_missing = verify(detached)
    assert r_missing.status == "outside_profile" and "detached" in r_missing.detail
    empty = Stmt(payload=b"")
    r_empty = verify(transparent(empty, [Rcpt(data_hash=dh_of(empty)).build()]))
    assert r_empty.status == "outside_profile" and "32 bytes, not 0" in r_empty.detail
    assert r_missing.detail != r_empty.detail


def test_external_inputs_attached_receipt_payload_is_outside_even_when_it_is_the_root():
    st = Stmt()
    rc = Rcpt(data_hash=dh_of(st))
    built = rc.build()
    body = S.decode_cose_sign1(built, role="receipt")
    proof = body.unprotected[396][-1][0]
    import cbor2
    p = cbor2.loads(proof)
    h = hashlib.sha256(p[1][0] + hashlib.sha256(p[1][1].encode()).digest() + p[1][2]).digest()
    for left, sib in p[2]:
        h = hashlib.sha256(sib + h if left else h + sib).digest()
    attached = Rcpt(data_hash=dh_of(st), payload=h).build()
    assert verify(transparent(st, [attached])).receipts[0].status == "outside_profile"


def test_external_inputs_canonical_root_must_be_32_bytes():
    _st, ts = control()
    for root in (b"", ROOT[:31], ROOT + b"\x00", None, "00" * 32):
        assert verify(ts, root=root).status == "unbound"


# ------------------------------------------------------------------------------------------------
# Class: algorithm and key binding
# ------------------------------------------------------------------------------------------------
def test_algorithm_control():
    assert verify(control()[1]).status == "confirmed"


def test_algorithm_label_and_key_type_must_belong_together():
    st = Stmt()
    dh = dh_of(st)
    p256_service = ec.generate_private_key(ec.SECP256R1())
    # ES384 label, signed by a P-256 key the relying party trusts
    wrong = Rcpt(data_hash=dh, key=p256_service, alg=-35, kid=kid_of(p256_service)).build()
    r = verify(transparent(st, [wrong]), rp=trust(service_keys=[spki(p256_service)]))
    assert r.receipts[0].status == "signature_invalid"
    # the same key under its own label confirms: the check above failed for the binding, not the key
    right = Rcpt(data_hash=dh, key=p256_service, alg=-7, kid=kid_of(p256_service)).build()
    assert verify(transparent(st, [right]), rp=trust(service_keys=[spki(p256_service)])).status == "confirmed"
    # an EC label with an RSA statement key
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_label_rsa_chain = control(x5chain=chain_of(rsa_key))[1]              # ES256, the chain names the RSA key
    assert verify(ec_label_rsa_chain, rp=trust(statement_keys=[spki(rsa_key)])).status == "statement_signature_invalid"


def test_algorithm_outside_v1_is_not_invalid():
    st = Stmt(prot_map={1: -8, 258: -16, 15: {1: "i"}}, sig=b"\x00" * 64)
    assert verify(transparent(st, [Rcpt(data_hash=dh_of(st)).build()])).status == "outside_profile"
    st = Stmt()
    rc = Rcpt(data_hash=dh_of(st), extra_prot={1: -36}).build()
    assert verify(transparent(st, [rc])).receipts[0].status == "outside_profile"


def test_algorithm_ecdsa_signature_of_wrong_length():
    st = Stmt()
    st.sig = st.signature() + b"\x00"
    assert verify(transparent(st, [Rcpt(data_hash=dh_of(st)).build()])).status == "statement_signature_invalid"


def test_algorithm_pss_salt_length_and_key_size():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    prot = {1: -37, 258: -16, 15: {1: "i"}, 33: chain_of(key)}
    good_sig = key.sign(tbs(enc(prot), ROOT), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                        hashes.SHA256())
    st = Stmt(prot_map=prot, sig=good_sig)
    rp = trust(statement_keys=[spki(key)])
    assert verify(transparent(st, [Rcpt(data_hash=dh_of(st)).build()]), rp=rp).status == "confirmed"
    other_salt = key.sign(tbs(enc(prot), ROOT), padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                           salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    st = Stmt(prot_map=prot, sig=other_salt)
    assert verify(transparent(st, [Rcpt(data_hash=dh_of(st)).build()]), rp=rp).status == "statement_signature_invalid"
    small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    prot = {**prot, 33: chain_of(small)}
    small_sig = small.sign(tbs(enc(prot), ROOT), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                           hashes.SHA256())
    st = Stmt(prot_map=prot, sig=small_sig)
    assert verify(transparent(st, [Rcpt(data_hash=dh_of(st)).build()]),
                  rp=trust(statement_keys=[spki(small)])).status == "statement_signature_invalid"


def test_algorithm_label_of_a_key_set_is_never_read():
    # a COSE_Key carrying alg (label 3) = ES256 for a P-384 key: the receipt's own ES384 decides
    x = SERVICE_KEY.public_key().public_numbers()
    ks = enc([{1: 2, 2: kid_of(SERVICE_KEY), 3: -7, -1: 2, -2: x.x.to_bytes(48, "big"), -3: x.y.to_bytes(48, "big")}])
    keys = S.load_cose_keyset(ks)
    st, ts = control()
    assert verify(ts, rp=trust(service_keys=keys)).status == "confirmed"


# ------------------------------------------------------------------------------------------------
# Class: identity and cache
# ------------------------------------------------------------------------------------------------
def test_identity_value_2_is_no_api():
    assert not [n for n in dir(S) if not n.startswith("_") and ("tbs" in n.lower() or "tobesigned" in n.lower())]


def test_identity_one_tobesigned_signed_twice_is_two_registrations():
    a, b = Stmt(), Stmt()
    assert a.protected() == b.protected() and a.payload == b.payload
    assert a.signature() != b.signature()              # ECDSA is randomised
    ra = Rcpt(data_hash=dh_of(a)).build()
    assert verify(transparent(a, [ra])).status == "confirmed"
    r = verify(transparent(b, [ra]))
    assert r.receipts[0].status == "receipt_not_bound" and r.receipts[0].signature_valid is True


def test_identity_a_trusted_key_counts_only_for_its_own_issuer():
    st = Stmt()
    rc = Rcpt(data_hash=dh_of(st), issuer="other.example").build()
    r = verify(transparent(st, [rc]))                   # SERVICE_KEY is trusted, but for ISSUER only
    assert r.receipts[0].status == "needs_rp_trust" and not r.profile_satisfied


def test_identity_two_calls_do_not_share_a_verdict():
    a, ts_a = control()
    b = Stmt(payload=hashlib.sha256(b"another target").digest())
    ts_b = transparent(b, [Rcpt(data_hash=dh_of(a)).build()])
    assert verify(ts_a).status == "confirmed"
    assert verify(ts_b, root=b.payload).status == "receipt_not_bound"
    assert verify(ts_a).status == "confirmed"


# ------------------------------------------------------------------------------------------------
# Class: receipt verification
# ------------------------------------------------------------------------------------------------
def test_receipt_verification_control():
    r = verify(control()[1])
    assert r.receipts[0].status == "confirmed" and r.receipts[0].merkle_root is not None


@pytest.mark.parametrize("rkw, status", [
    (dict(leaf_rule="-04"), "signature_invalid"),
    (dict(vds=1), "outside_profile"),
    (dict(second_proof_root_differs=True), "root_mismatch"),
    (dict(key=OTHER_SERVICE_KEY), "needs_rp_trust"),
    (dict(drop_prot=(4,)), "outside_profile"),
    (dict(drop_prot=(15,)), "outside_profile"),
])
def test_receipt_verification(rkw, status):
    st = Stmt()
    r = verify(transparent(st, [Rcpt(data_hash=dh_of(st), **rkw).build()]))
    assert r.receipts[0].status == status and not r.profile_satisfied


def test_receipt_verification_path_changes():
    st = Stmt()
    good = Rcpt(data_hash=dh_of(st)).build()
    i = good.index(hashlib.sha256(bytes([1])).digest())
    bit = bytearray(good)
    bit[i] ^= 1
    assert verify(transparent(st, [bytes(bit)])).receipts[0].status == "signature_invalid"
    flag = good.replace(b"\x82\xf4\x58\x20", b"\x82\xf5\x58\x20", 1)
    assert flag != good
    assert verify(transparent(st, [flag])).receipts[0].status == "signature_invalid"


def test_readable_means_the_receipt_proofs_parsed_under_the_05_cddl():
    """Codex, PR 278: an early profile branch must not skip the shape of the proofs after it."""
    st = Stmt()
    control = verify(transparent(st, [Rcpt(data_hash=dh_of(st)).build()]))
    assert (control.status, control.readable, control.receipts[0].readable) == ("confirmed", True, True)
    other_alg = verify(transparent(st, [Rcpt(data_hash=dh_of(st), alg=-8).build()]))
    assert (other_alg.receipts[0].status, other_alg.receipts[0].readable) == ("outside_profile", True)
    junk = verify(transparent(st, [Rcpt(data_hash=dh_of(st), alg=-8, proofs_override=[b"junk"]).build()]))
    assert (junk.receipts[0].status, junk.receipts[0].readable, junk.readable) == ("malformed", False, False)
    not_ccf = verify(transparent(st, [Rcpt(data_hash=dh_of(st), vds=1).build()]))
    assert (not_ccf.receipts[0].status, not_ccf.receipts[0].readable) == ("outside_profile", False)
    none = verify(transparent(st, [Rcpt(data_hash=dh_of(st), proofs_override=[]).build()]))
    assert (none.receipts[0].status, none.receipts[0].readable) == ("outside_profile", False)


def test_missing_trust_is_never_reported_as_an_unbound_receipt():
    """Codex, PR 278: receipt_not_bound says the receipt signature is valid; without a key it is not known."""
    st = Stmt()
    other = Rcpt(data_hash=hashlib.sha256(b"another statement").digest()).build()
    with_key = verify(transparent(st, [other]))
    assert (with_key.receipts[0].status, with_key.receipts[0].signature_valid) == ("receipt_not_bound", True)
    no_key = verify(transparent(st, [other]), rp={"scitt_statement_keys": [spki(STMT_KEY)]})
    r = no_key.receipts[0]
    assert (r.status, r.signature_valid, r.bound, no_key.status) == ("needs_rp_trust", None, False, "needs_rp_trust")


def test_receipt_verification_trust_is_missing_not_failed():
    st, ts = control()
    for rp in ({}, {"scitt_ccf_services": {}}, {"scitt_ccf_services": {ISSUER: []}},
               {"scitt_ccf_services": {ISSUER: [spki(OTHER_SERVICE_KEY)]}},
               {"scitt_ccf_services": {ISSUER: ["not bytes", {"spki": 1}, b"not a key"]}}):
        rp = {**rp, "scitt_statement_keys": [spki(STMT_KEY)]}
        r = verify(ts, rp=rp)
        assert r.status == "needs_rp_trust" and r.receipts[0].signature_valid is None


def test_receipt_verification_one_confirmed_receipt_is_enough_and_the_other_is_reported():
    st = Stmt()
    good = Rcpt(data_hash=dh_of(st)).build()
    bad = bytearray(good)
    bad[-1] ^= 1
    r = verify(transparent(st, [bytes(bad), good]))
    assert r.status == "confirmed"
    assert [c.status for c in r.receipts] == ["signature_invalid", "confirmed"]
    r = verify(transparent(st, [bytes(bad), Rcpt(data_hash=dh_of(st), key=OTHER_SERVICE_KEY).build()]))
    assert r.status == "signature_invalid"        # a definite failure is named before missing trust


def test_statement_signer_is_always_required():
    _st, ts = control()
    assert verify(ts, rp=trust(statement_keys=[])).status == "needs_rp_trust"
    other = ec.generate_private_key(ec.SECP256R1())
    assert verify(ts, rp=trust(statement_keys=[spki(other)])).status == "needs_rp_trust"      # not the named key
    named_other = control(x5chain=chain_of(other))[1]                  # names other, STMT_KEY signed
    assert verify(named_other, rp=trust(statement_keys=[spki(other)])).status == "statement_signature_invalid"
    status, valid = S.verify_statement_signature(ts, statement_keys=None)
    assert (status, valid) == ("needs_rp_trust", None)
    assert S.verify_statement_signature(ts, statement_keys=[spki(STMT_KEY)]) == ("confirmed", True)


# ------------------------------------------------------------------------------------------------
# Class: statement key selection by the protected x5chain (owner answer N4 b)
# A selector among the RP statement keys, never trust: no RP key equal to the end-entity
# certificate's key is needs_rp_trust, a selected key must verify, and nothing else is tried.
# ------------------------------------------------------------------------------------------------
CA_KEY = ec.generate_private_key(ec.SECP256R1())
KEY_B = ec.generate_private_key(ec.SECP256R1())
_ID_EC_PUBLIC_KEY = bytes.fromhex("06072a8648ce3d0201")


def cert_der(key, cn: str = "statement signer", issuer_key=None) -> bytes:
    import datetime  # noqa: PLC0415
    from cryptography import x509  # noqa: PLC0415
    from cryptography.x509.oid import NameOID  # noqa: PLC0415
    name = lambda c: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, c)])  # noqa: E731
    t = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    return (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(name("test ca"))
            .public_key(key.public_key()).serial_number(7).not_valid_before(t)
            .not_valid_after(t + datetime.timedelta(days=365))
            .sign(issuer_key or CA_KEY, hashes.SHA256()).public_bytes(serialization.Encoding.DER))


_CHAINS: dict = {}


def chain_of(key) -> list:
    """A two-certificate chain for key, made once per key: certificates are not free to sign."""
    k = spki(key)
    if k not in _CHAINS:
        _CHAINS[k] = [cert_der(key), cert_der(CA_KEY, "test ca")]
    return _CHAINS[k]


def x5(x5chain, signer=None) -> Stmt:
    return Stmt(prot_map={1: -7, 258: -16, 259: "application/json", 15: {1: "did:example:signer"},
                          33: x5chain}, key=signer)


def ts_of(st: Stmt, extra_unprot: dict | None = None) -> bytes:
    return transparent(st, [Rcpt(data_hash=dh_of(st)).build()], extra_unprot)


def compressed_spki(key) -> bytes:
    point = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    alg_id = spki(key)[2:23]
    return bytes([0x30, len(alg_id) + 3 + len(point)]) + alg_id + bytes([0x03, 1 + len(point), 0]) + point


def test_x5chain_control_selects_the_signer_among_several_rp_keys():
    ts = ts_of(x5(chain_of(STMT_KEY)))
    r = verify(ts, rp=trust(statement_keys=[spki(KEY_B), spki(STMT_KEY)]))
    assert (r.status, r.statement_signature_valid, r.profile_satisfied) == ("confirmed", True, True)
    assert S.verify_statement_signature(ts, statement_keys=[spki(KEY_B), spki(STMT_KEY)]) == ("confirmed", True)


def test_x5chain_a_key_the_rp_rotated_away_is_missing_trust_not_a_failed_signature():
    new_key = ec.generate_private_key(ec.SECP256R1())
    with_chain = ts_of(x5(chain_of(STMT_KEY)))
    r = verify(with_chain, rp=trust(statement_keys=[spki(new_key)]))
    assert (r.status, r.statement_signature_valid, r.profile_satisfied) == ("needs_rp_trust", None, False)
    assert "x5chain end-entity key" in r.detail
    # owner answer N7 b: without a protected x5chain the statement is outside the profile, whatever the keys
    no_chain = control(x5chain=None)[1]
    assert verify(no_chain, rp=trust(statement_keys=[spki(new_key)])).status == "outside_profile"
    assert verify(no_chain).status == "outside_profile"
    assert S.verify_statement_signature(no_chain, statement_keys=[spki(STMT_KEY)]) == ("outside_profile", None)
    assert S.verify_statement_signature(no_chain, statement_keys=None) == ("outside_profile", None)


def test_x5chain_a_selected_key_must_verify_and_no_other_key_is_tried():
    signed_by_b = ts_of(x5(chain_of(STMT_KEY), signer=KEY_B))     # chain names STMT_KEY, KEY_B signed
    r = verify(signed_by_b, rp=trust(statement_keys=[spki(STMT_KEY), spki(KEY_B)]))
    assert (r.status, r.statement_signature_valid) == ("statement_signature_invalid", False)
    # control: the chain naming its own signer, KEY_B, confirms under the same RP keys
    assert verify(control(key=KEY_B)[1], rp=trust(statement_keys=[spki(STMT_KEY), spki(KEY_B)])).status == \
        "confirmed"


def test_x5chain_naming_an_untrusted_key_does_not_fall_back_to_the_trusted_one():
    stranger = ec.generate_private_key(ec.SECP256R1())
    r = verify(ts_of(x5(chain_of(stranger))), rp=trust(statement_keys=[spki(STMT_KEY)]))
    assert (r.status, r.profile_satisfied) == ("needs_rp_trust", False)


def test_x5chain_single_certificate_form_selects_too():
    ts = ts_of(x5(cert_der(STMT_KEY)))
    assert verify(ts, rp=trust(statement_keys=[spki(KEY_B), spki(STMT_KEY)])).status == "confirmed"
    assert verify(ts, rp=trust(statement_keys=[spki(KEY_B)])).status == "needs_rp_trust"


def test_x5chain_keys_are_compared_as_keys_not_as_encodings():
    ts = ts_of(x5(chain_of(STMT_KEY)))
    assert compressed_spki(STMT_KEY) != spki(STMT_KEY)
    assert verify(ts, rp=trust(statement_keys=[compressed_spki(STMT_KEY)])).status == "confirmed"


def test_x5chain_in_the_unprotected_header_selects_nothing():
    assert verify(ts_of(Stmt())).status == "confirmed"                  # control: the chain protected
    st = Stmt(x5chain=None)
    ts = ts_of(st, extra_unprot={33: chain_of(STMT_KEY)})               # the signer's own chain, unprotected
    r = verify(ts)
    assert r.status == "outside_profile" and "not integrity protected" in r.detail
    assert r.receipts[0].status == "confirmed"                          # the receipt is still reported


def test_x5chain_a_kid_in_the_statement_selects_nothing():
    st = x5(chain_of(STMT_KEY))
    st.prot_map[4] = kid_of(KEY_B)
    assert verify(ts_of(st), rp=trust(statement_keys=[spki(KEY_B), spki(STMT_KEY)])).status == "confirmed"


def test_x5chain_end_entity_key_that_cannot_be_loaded_matches_nothing():
    leaf = cert_der(STMT_KEY)
    assert leaf.count(_ID_EC_PUBLIC_KEY) == 1
    unknown = leaf.replace(_ID_EC_PUBLIC_KEY, bytes.fromhex("06072a8648ce3d0209"))   # an unassigned key OID
    r = verify(ts_of(x5([unknown, cert_der(CA_KEY, "test ca")])))
    assert r.status == "needs_rp_trust" and "cannot be loaded" in r.detail


@pytest.mark.parametrize("x5chain", [
    5, "text", {1: b"x"}, [], None,
    "ONE",                  # an array of one certificate: RFC 9360 wants a bstr or two or more
    "LEAF_AND_INT", b"not a certificate", "JUNK_LEAF",
], ids=["int", "text", "map", "empty", "null", "one-element", "non-bstr", "junk-bstr", "junk-leaf"])
def test_x5chain_of_another_shape_is_malformed(x5chain):
    good = chain_of(STMT_KEY)
    x5chain = {"ONE": [good[0]], "LEAF_AND_INT": [good[0], 7], "JUNK_LEAF": [b"\x30\x03\x02\x01\x00", good[1]]}.get(
        x5chain, x5chain) if isinstance(x5chain, str) else x5chain
    ts = ts_of(x5(x5chain))
    r = verify(ts)
    assert (r.status, r.profile_satisfied) == ("malformed", False)
    assert S.verify_statement_signature(ts, statement_keys=[spki(STMT_KEY)]) == ("malformed", None)


# ------------------------------------------------------------------------------------------------
# Class: crossed statement and receipt
# ------------------------------------------------------------------------------------------------
def test_crossed_control():
    assert verify(control()[1]).status == "confirmed"


def test_crossed_receipt_of_another_statement():
    a = Stmt()
    b = Stmt(payload=hashlib.sha256(b"a different target").digest())
    r = verify(transparent(b, [Rcpt(data_hash=dh_of(a)).build()]), root=b.payload)
    assert r.status == "receipt_not_bound" and r.signature_valid is True and not r.profile_satisfied


def test_crossed_real_receipt_moved_into_a_synthetic_statement():
    v, rp = _vector()
    real = S.decode_cose_sign1(base64.b64decode(v["transparent_statement_b64"]))
    st = Stmt()
    rp = {**rp, "scitt_statement_keys": [spki(STMT_KEY)]}
    r = S.verify_transparent_statement(transparent(st, list(real.unprotected[394])), canonical_root=ROOT,
                                       rp_trust=rp)
    assert r.receipts[0].status == "receipt_not_bound" and r.receipts[0].signature_valid is True


def test_crossed_statement_of_another_target_is_unbound():
    _st, ts = control()
    assert verify(ts, root=hashlib.sha256(b"not this target").digest()).status == "unbound"


# ------------------------------------------------------------------------------------------------
# The typed refusals of the three parsing surfaces
# ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("bad", [None, 1, "text", [b"x"], {"a": 1}, b"", b"\xd2\x84", os.urandom(64)])
def test_parsing_surfaces_refuse_typed(bad):
    for fn in (S.decode_cose_sign1, S.recompute_data_hash, S.load_cose_keyset):
        with pytest.raises(S.ScittFormatError):
            fn(bad)
    assert S.verify_transparent_statement(bad, canonical_root=ROOT).status in S.STATUS_ORDER
