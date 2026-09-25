"""CCF consistency receipts, draft-ietf-scitt-receipts-ccf-profile-05 section 4. Needs the [scitt] extra.

Each class starts from its unchanged CONTROL, which must confirm, and changes one thing per case.
SYNTHETIC: keys and trees made here, proofs built from RFC 9162 section 2.1.4.1 as written, with the
side of each sibling kept. REAL: tests/fixtures/scitt_ccf/local_ledger_consistency.json, three signed
states of one local scitt-ccf-ledger (tools/scitt_ccf_external/consistency_probe.py, 2026-09-25); no
service measured emits a consistency receipt, so the receipt there is the service's own signature over
the newer root with a proof computed from the ledger's leaves.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(importlib.util.find_spec("cbor2") is None,
                                reason="the scitt-ccf reader needs the [scitt] extra")

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, utils  # noqa: E402

from proofbundle import scitt_ccf as S  # noqa: E402
from proofbundle._wire_b64 import decode_b64  # noqa: E402

VECTOR = Path(__file__).resolve().parent / "fixtures" / "scitt_ccf" / "local_ledger_consistency.json"
ISSUER = "service.example"
SERVICE_KEY = ec.generate_private_key(ec.SECP384R1())
OTHER_KEY = ec.generate_private_key(ec.SECP384R1())
H = lambda b: hashlib.sha256(b).digest()  # noqa: E731


def _cbor2():
    import cbor2
    return cbor2


def spki(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)


def kid_of(key) -> bytes:
    return hashlib.sha256(spki(key)).hexdigest().encode("ascii")


# ------------------------------------------------------------------------------------------------
# A tree and the proofs of section 4, from RFC 9162 2.1.4.1 as written
# ------------------------------------------------------------------------------------------------
class Tree:
    def __init__(self, n: int, seed: bytes = b"leaves"):
        self.leaves = [H(seed + i.to_bytes(4, "big")) for i in range(n)]
        self.memo: dict = {}

    def node(self, lo, hi):
        if (lo, hi) not in self.memo:
            if hi - lo == 1:
                self.memo[(lo, hi)] = self.leaves[lo]
            else:
                k = 1 << ((hi - lo - 1).bit_length() - 1)
                self.memo[(lo, hi)] = H(self.node(lo, lo + k) + self.node(lo + k, hi))
        return self.memo[(lo, hi)]

    def root(self, size):
        return self.node(0, size)

    def _sub(self, m, lo, hi, b):
        n = hi - lo
        if m == n:
            return [] if b else [("anchor", self.node(lo, hi))]
        k = 1 << ((n - 1).bit_length() - 1)
        if m <= k:
            return self._sub(m, lo, lo + k, b) + [(False, self.node(lo + k, hi))]
        return self._sub(m - k, lo + k, hi, False) + [(True, self.node(lo, lo + k))]

    def proof(self, m, n):
        sp = self._sub(m, 0, n, True)
        if sp and sp[0][0] == "anchor":
            return sp[0][1], [[bool(s), h] for s, h in sp[1:]]
        return self.root(m), [[bool(s), h] for s, h in sp]

    def deeper(self, m, n):
        anchor, path = self.proof(m, n)
        t = (m & -m).bit_length() - 1
        return [(self.node(m - (1 << j), m),
                 [[True, self.node(m - (1 << (i + 1)), m - (1 << i))] for i in range(j, t)] + path)
                for j in range(t)]


TREE = Tree(40)


def enc_proof(anchor, path) -> bytes:
    return _cbor2().dumps({1: anchor, 2: path})


def sign_over(newer_root: bytes, *, key=SERVICE_KEY, prot=None) -> tuple:
    prot = prot if prot is not None else {1: -35, 4: kid_of(SERVICE_KEY), 395: 2,
                                          15: {1: ISSUER, 6: 1790000000}, "ccf.v1": {"txid": "2.24"}}
    prot_b = _cbor2().dumps(prot)
    tbs = _cbor2().dumps(["Signature1", prot_b, b"", newer_root])
    r, s = utils.decode_dss_signature(key.sign(tbs, ec.ECDSA(hashes.SHA384())))
    return prot_b, r.to_bytes(48, "big") + s.to_bytes(48, "big")


_SIGNED: dict = {}


def receipt(proofs=None, *, n=24, m=13, vdp=None, payload=None, signed=None, unprot_extra=None,
            tagged=True) -> bytes:
    """A consistency receipt; by default one proof from size m to size n, signed over R_n."""
    if signed is None:
        if n not in _SIGNED:
            _SIGNED[n] = sign_over(TREE.root(n))       # one signature per newer root, reused
        signed = _SIGNED[n]
    prot_b, sig = signed
    if vdp is None:
        vdp = {-2: proofs if proofs is not None else [enc_proof(*TREE.proof(m, n))]}
    unprot = {396: vdp, **(unprot_extra or {})}
    body = _cbor2().dumps([prot_b, unprot, payload, sig])
    return (b"\xd2" if tagged else b"") + body


def trust(keys=None, issuer=ISSUER):
    return {"scitt_ccf_services": {issuer: keys if keys is not None else [spki(SERVICE_KEY)]}}


def check(rcpt, older=None, issuer=ISSUER, rp=None, m=13):
    return S.verify_consistency_receipt(rcpt, older_root=TREE.root(m) if older is None else older,
                                        older_issuer=issuer, rp_trust=trust() if rp is None else rp)


# ------------------------------------------------------------------------------------------------
# Control
# ------------------------------------------------------------------------------------------------
def test_synthetic_control_confirms_with_every_result_reported():
    c = check(receipt())
    assert c.status == "confirmed"
    assert (c.readable, c.signature_valid, c.older_root_matches, c.kid_bound_to_key) == (True, True, True, True)
    assert (c.newer_root, c.proofs, c.issuer, c.ccf_txid) == (TREE.root(24), 1, ISSUER, "2.24")
    assert c.to_dict()["newer_root"] == TREE.root(24).hex()
    assert S.CONFIRMED not in S.CONSISTENCY_STATUS_ORDER


def test_every_pair_up_to_20_confirms_and_every_deeper_anchor_is_refused():
    confirmed = refused = 0
    for n in range(2, 21):
        for m in range(1, n):
            assert check(receipt(m=m, n=n), m=m).status == "confirmed", (m, n)
            confirmed += 1
            for anchor, path in TREE.deeper(m, n):
                # section 4.2 as written accepts these: both folds reach the right roots
                assert _fold(anchor, path) == (TREE.root(m), TREE.root(n))
                c = check(receipt([enc_proof(anchor, path)], m=m, n=n), m=m)
                assert c.status == "consistency_anchor_not_canonical", (m, n)
                refused += 1
    assert (confirmed, refused) == (190, 150)


def _fold(anchor, path):
    older = newer = anchor
    for left, h in path:
        older, newer = (H(h + older), H(h + newer)) if left else (older, H(newer + h))
    return older, newer


# ------------------------------------------------------------------------------------------------
# Section 4.1: what the receipt must carry
# ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("kw, status", [
    (dict(vdp={}), "consistency_proof_missing"),
    (dict(vdp={-2: []}), "consistency_proof_missing"),
    (dict(vdp={-1: []}), "consistency_proof_missing"),
    (dict(payload=TREE.root(24)), "consistency_payload_attached"),
    (dict(payload=b"\x00" * 32), "consistency_payload_attached"),
])
def test_41_rules(kw, status):
    assert check(receipt()).status == "confirmed"
    assert check(receipt(**kw)).status == status


def test_41_no_vdp_at_all_is_a_missing_proof():
    prot_b, sig = sign_over(TREE.root(24))
    raw = b"\xd2" + _cbor2().dumps([prot_b, {}, None, sig])
    assert check(raw).status == "consistency_proof_missing"


def test_41_every_proof_must_compute_the_same_newer_root():
    good = enc_proof(*TREE.proof(13, 24))
    other = enc_proof(*TREE.proof(13, 20))                        # a valid proof to another newer root
    a, path = TREE.proof(17, 24)
    corrupted = enc_proof(bytes([a[0] ^ 1]) + a[1:], path)        # 4.2 as written skips this one
    assert check(receipt([good, enc_proof(*TREE.proof(17, 24))])).status == "confirmed"
    assert check(receipt([good, good])).status == "confirmed"
    assert check(receipt([good, other])).status == "consistency_newer_roots_differ"
    assert check(receipt([good, corrupted])).status == "consistency_newer_roots_differ"


def _inclusion_path(tree, index, lo, hi):
    """RFC 9162 2.1.3.1 PATH, with the side of each sibling kept (left = True)."""
    if hi - lo == 1:
        return []
    k = 1 << ((hi - lo - 1).bit_length() - 1)
    if index < lo + k:
        return _inclusion_path(tree, index, lo, lo + k) + [[False, tree.node(lo + k, hi)]]
    return _inclusion_path(tree, index, lo + k, hi) + [[True, tree.node(lo, lo + k)]]


def test_section_5_an_inclusion_proof_beside_them_must_compute_the_newer_root_too():
    leaf = [H(b"itx"), "ce:2.5:" + "00" * 32, H(b"a data-hash")]
    tree = Tree(24, seed=b"with a ccf leaf")
    tree.leaves[5] = H(leaf[0] + H(leaf[1].encode()) + leaf[2])      # a leaf with its -05 components
    signed = sign_over(tree.root(24))
    inclusion = _cbor2().dumps({1: leaf, 2: _inclusion_path(tree, 5, 0, 24)})
    wrong = _cbor2().dumps({1: leaf, 2: _inclusion_path(tree, 5, 0, 24)[:-1]})    # computes another root
    consistency = enc_proof(*tree.proof(13, 24))

    def st(vdp):
        return S.verify_consistency_receipt(receipt(vdp=vdp, signed=signed), older_root=tree.root(13),
                                            older_issuer=ISSUER, rp_trust=trust()).status
    assert st({-2: [consistency], -1: [inclusion]}) == "confirmed"
    assert st({-2: [consistency], -1: [wrong]}) == "consistency_newer_roots_differ"


# ------------------------------------------------------------------------------------------------
# Section 4 and 4.2: the anchor, the older root, the signature
# ------------------------------------------------------------------------------------------------
def test_4_a_proof_that_starts_with_a_left_sibling_is_refused():
    a, path = TREE.proof(13, 24)
    flipped = [[not path[0][0], path[0][1]]] + path[1:]
    assert check(receipt([enc_proof(a, flipped)])).status == "consistency_anchor_not_canonical"
    only_left = [[True, TREE.node(0, 8)]]                          # m = n: newer equals older
    assert check(receipt([enc_proof(TREE.node(8, 13), only_left)])).status == \
        "consistency_anchor_not_canonical"


@pytest.mark.parametrize("older, status", [
    (TREE.root(12), "consistency_older_root_mismatch"),
    (bytes([TREE.root(13)[0] ^ 1]) + TREE.root(13)[1:], "consistency_older_root_mismatch"),
    (TREE.root(24), "consistency_older_root_mismatch"),         # the states swapped
    (TREE.root(13)[:31], "consistency_older_root_mismatch"),
    (None, "confirmed"),                                         # the control, via the default
    ("not bytes", "consistency_older_root_mismatch"),
])
def test_42_the_older_root_the_caller_holds(older, status):
    got = check(receipt(), older=older) if older is not None else check(receipt())
    assert got.status == status
    if status != "confirmed":
        assert got.older_root_matches is False


def test_42_the_older_root_must_come_from_this_service():
    assert check(receipt(), issuer="another.service").status == "consistency_issuer_mismatch"
    assert check(receipt(), issuer=None).status == "consistency_issuer_mismatch"


@pytest.mark.parametrize("rp, status", [
    ({}, "needs_rp_trust"),
    (None, "confirmed"),
    ("TRUST_OTHER_ISSUER", "needs_rp_trust"),
    ("TRUST_OTHER_KEY", "needs_rp_trust"),
])
def test_42_trust_is_the_relying_partys(rp, status):
    rp = {"TRUST_OTHER_ISSUER": trust(issuer="another.service"),
          "TRUST_OTHER_KEY": trust(keys=[spki(OTHER_KEY)])}.get(rp, rp) if isinstance(rp, str) else rp
    assert check(receipt(), rp=rp).status == status


def test_42_the_signature_is_over_the_newer_root():
    over_older = sign_over(TREE.root(13))                          # the newer root swapped for the older
    assert check(receipt(signed=over_older)).status == "signature_invalid"
    forged = sign_over(TREE.root(24), key=OTHER_KEY)              # SERVICE_KEY's kid, another key
    c = check(receipt(signed=forged))
    assert (c.status, c.signature_valid) == ("signature_invalid", False)


# ------------------------------------------------------------------------------------------------
# Profile and CDDL
# ------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("prot, status", [
    ({1: -35, 4: kid_of(SERVICE_KEY), 395: 1, 15: {1: ISSUER}}, "outside_profile"),
    ({1: -8, 4: kid_of(SERVICE_KEY), 395: 2, 15: {1: ISSUER}}, "outside_profile"),
    ({1: -35, 395: 2, 15: {1: ISSUER}}, "outside_profile"),
    ({1: -35, 4: kid_of(SERVICE_KEY), 395: 2}, "outside_profile"),
    ({1: -35, 4: kid_of(SERVICE_KEY), 395: 2, 15: {1: ISSUER}, 2: [99], 99: 1}, "outside_profile"),
    ({1: -35, 4: kid_of(SERVICE_KEY), 395: 2, 15: {1: ISSUER}}, "confirmed"),
])
def test_profile_of_the_protected_header(prot, status):
    assert check(receipt(signed=sign_over(TREE.root(24), prot=prot))).status == status


def test_profile_untagged_and_crit_unprotected():
    assert check(receipt(tagged=False)).status == "outside_profile"
    assert check(receipt(unprot_extra={2: [1]})).status == "outside_profile"


R4 = TREE.root(4)


@pytest.mark.parametrize("proof", [      # built inside the test: collection must not need cbor2
    lambda: b"not cbor at all \xff",
    lambda: "a text string",
    lambda: _cbor2().dumps({1: R4, 2: [[False, R4]], 3: 0}),
    lambda: _cbor2().dumps({1: R4[:31], 2: [[False, R4]]}),
    lambda: _cbor2().dumps({1: R4, 2: []}),
    lambda: _cbor2().dumps({1: R4, 2: [[0, R4]]}),
    lambda: _cbor2().dumps({1: R4, 2: [[False, R4[:31]]]}),
    lambda: _cbor2().dumps({1: R4, 2: [[False, R4]] * (S.MAX_PATH + 1)}),
    lambda: _cbor2().dumps({1: R4, 2: [[False, R4]]}) + b"\x00",
    lambda: bytes.fromhex("bf01") + _cbor2().dumps(R4) + b"\xff",
], ids=["junk", "text", "extra-key", "anchor-31", "empty-path", "int-tag", "hash-31", "path-too-long",
        "trailing", "indefinite"])
def test_cddl_of_a_consistency_proof_is_malformed_when_broken(proof):
    c = check(receipt([proof()]))
    assert (c.status, c.readable) == ("malformed", False)


@pytest.mark.parametrize("vdp", [
    lambda: {-2: [enc_proof(*TREE.proof(13, 24))], -3: []},
    lambda: {-2: enc_proof(*TREE.proof(13, 24))},
    lambda: {-2: [enc_proof(*TREE.proof(13, 24))] * (S.MAX_CONSISTENCY_PROOFS + 1)},
], ids=["unknown-proof-type", "not-an-array", "too-many"])
def test_cddl_of_vdp(vdp):
    assert check(receipt(vdp=vdp())).status == "malformed"


def test_vdp_not_a_map_is_malformed():
    prot_b, sig = _SIGNED.setdefault(24, sign_over(TREE.root(24)))
    raw = b"\xd2" + _cbor2().dumps([prot_b, {396: [1]}, None, sig])
    assert check(raw).status == "malformed"


@pytest.mark.parametrize("bad", [None, 1, "text", [b"x"], {"a": 1}, b"", b"\xd2\x84", os.urandom(64)])
def test_never_raises_and_every_status_is_in_the_closed_set(bad):
    c = S.verify_consistency_receipt(bad, older_root=bad, older_issuer=bad, rp_trust=bad)
    assert c.status in S.CONSISTENCY_STATUS_ORDER


# ------------------------------------------------------------------------------------------------
# REAL: three signed states of one local ledger
# ------------------------------------------------------------------------------------------------
def _vector():
    v = json.loads(VECTOR.read_text(encoding="utf-8"))
    rp = {"scitt_ccf_services": {v["issuer"]: S.load_cose_keyset(decode_b64(v["service_keyset_b64"]))},
          "scitt_statement_keys": [decode_b64(v["statement_signer_spki_b64"])]}
    return v, rp


def _verified_state(v, rp, name):
    """A root the verifier has already verified (-05 "Consistency Receipts"): from an inclusion receipt."""
    r = S.verify_transparent_statement(decode_b64(v["states"][name]["transparent_statement_b64"]),
                                       canonical_root=bytes.fromhex(v["canonical_root_hex"]), rp_trust=rp)
    assert r.status == "confirmed"
    return r.receipts[0]


def _rewrap(v, proofs):
    tag = _cbor2().loads(decode_b64(v["newer_receipt_b64"]))
    prot_b, _unprot, _payload, sig = tag.value
    return b"\xd2" + _cbor2().dumps([prot_b, {396: {-2: proofs}}, None, sig])


def test_real_control_older_state_to_newer_state():
    v, rp = _vector()
    older = _verified_state(v, rp, "older")
    newer = _verified_state(v, rp, "newer")
    c = S.verify_consistency_receipt(decode_b64(v["consistency_receipt_b64"]), older_root=older.merkle_root,
                                     older_issuer=older.issuer, rp_trust=rp)
    assert (c.status, c.signature_valid, c.older_root_matches) == ("confirmed", True, True)
    assert c.newer_root == newer.merkle_root and c.issuer == v["issuer"]


def test_real_states_the_signature_seqno_is_the_tree_size():
    v, _rp = _vector()
    for name, s in v["states"].items():
        assert s["tree_size"] == int(s["txid"].split(".")[1]), name   # measured, CCF's leaf 0 counted


def test_real_variants():
    v, rp = _vector()
    older, middle = _verified_state(v, rp, "older"), _verified_state(v, rp, "middle")
    p = {k: decode_b64(b) for k, b in v["proofs_b64"].items()}
    o_to_n, m_to_n, o_to_m = p["19->24"], p["22->24"], p["19->22"]

    def st(proofs, held):
        return S.verify_consistency_receipt(_rewrap(v, proofs), older_root=held.merkle_root,
                                            older_issuer=held.issuer, rp_trust=rp).status
    assert st([o_to_n], older) == "confirmed"
    assert st([m_to_n], middle) == "confirmed"
    assert st([o_to_n], middle) == "consistency_older_root_mismatch"
    assert st([o_to_m], older) == "signature_invalid"                 # the middle root is not signed here
    assert st([o_to_n, m_to_n], older) == st([o_to_n, m_to_n], middle) == "confirmed"
    assert st([o_to_n, o_to_m], older) == "consistency_newer_roots_differ"
    assert st([decode_b64(v["deeper_anchor_proof_b64"])], middle) == "consistency_anchor_not_canonical"
