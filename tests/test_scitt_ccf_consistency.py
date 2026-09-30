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
#: The success of a receipt checked without both tree sizes: the anchor rule of section 4 was checked
#: only as far as the first tag goes, and 0 < m < n not at all (addendum 1 to Z332).
UNSIZED = "confirmed_without_tree_sizes"


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


def sign_over(newer_root: bytes, *, key=SERVICE_KEY, prot=None, txid="2.24") -> tuple:
    prot = prot if prot is not None else {1: -35, 4: kid_of(SERVICE_KEY), 395: 2,
                                          15: {1: ISSUER, 6: 1790000000}, "ccf.v1": {"txid": txid}}
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
            # one signature per newer root, reused; its txid names the tree size as CCF 7.0.17 does (G5)
            _SIGNED[n] = sign_over(TREE.root(n), txid=f"2.{n}")
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
    assert c.status == UNSIZED
    assert (c.readable, c.signature_valid, c.older_root_matches, c.kid_bound_to_key) == (True, True, True, True)
    assert (c.newer_root, c.proofs, c.issuer, c.ccf_txid) == (TREE.root(24), 1, ISSUER, "2.24")
    assert c.to_dict()["newer_root"] == TREE.root(24).hex()
    assert S.CONFIRMED not in S.CONSISTENCY_STATUS_ORDER
    assert UNSIZED not in S.CONSISTENCY_STATUS_ORDER and UNSIZED != S.CONFIRMED


def test_every_pair_up_to_20_confirms_and_every_deeper_anchor_is_refused():
    confirmed = refused = 0
    for n in range(2, 21):
        for m in range(1, n):
            assert check(receipt(m=m, n=n), m=m).status == UNSIZED, (m, n)
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
    (dict(vdp={-1: []}), "malformed"),        # an empty -1 is outside the CDDL, and malformed comes first
    (dict(payload=TREE.root(24)), "consistency_payload_attached"),
    (dict(payload=b"\x00" * 32), "consistency_payload_attached"),
])
def test_41_rules(kw, status):
    assert check(receipt()).status == UNSIZED
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
    assert check(receipt([good, enc_proof(*TREE.proof(17, 24))])).status == UNSIZED
    assert check(receipt([good, good])).status == UNSIZED
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
    assert st({-2: [consistency], -1: [inclusion]}) == UNSIZED
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
    (None, UNSIZED),                                         # the control, via the default
    ("not bytes", "consistency_older_root_mismatch"),
])
def test_42_the_older_root_the_caller_holds(older, status):
    got = check(receipt(), older=older) if older is not None else check(receipt())
    assert got.status == status
    if status != UNSIZED:
        assert got.older_root_matches is False


def test_42_the_older_root_must_come_from_this_service():
    assert check(receipt(), issuer="another.service").status == "consistency_issuer_mismatch"
    assert check(receipt(), issuer=None).status == "consistency_issuer_mismatch"


@pytest.mark.parametrize("rp, status", [
    ({}, "needs_rp_trust"),
    (None, UNSIZED),
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
    ({1: -35, 4: kid_of(SERVICE_KEY), 395: 2, 15: {1: ISSUER}}, UNSIZED),
])
def test_profile_of_the_protected_header(prot, status):
    assert check(receipt(signed=sign_over(TREE.root(24), prot=prot))).status == status


def test_an_empty_array_of_the_other_proof_family_is_malformed():
    """Codex, PR 278 round four, the mirror of the inclusion case: the -05 CDDL makes -1 and -2 arrays
    of one or more proofs. An empty -1 beside the consistency proofs is outside that CDDL; an empty -2,
    the family this verifier checks, keeps its own status, because 4.2 asserts len(proofs) > 0."""
    good = enc_proof(*TREE.proof(13, 24))
    assert check(receipt(vdp={-2: [good]})).status == UNSIZED
    c = check(receipt(vdp={-2: [good], -1: []}))
    assert (c.status, c.readable) == ("malformed", False)
    assert check(receipt(vdp={-2: []})).status == "consistency_proof_missing"


def test_readable_means_the_consistency_proofs_parsed_under_the_05_cddl():
    """Codex, PR 278, the sibling of the inclusion case: proofs are parsed before the profile."""
    assert (c := check(receipt())).status == UNSIZED and c.readable
    alg8 = {1: -8, 4: kid_of(SERVICE_KEY), 395: 2, 15: {1: ISSUER}}
    good = check(receipt(signed=sign_over(TREE.root(24), prot=alg8)))
    assert (good.status, good.readable) == ("outside_profile", True)
    junk = check(receipt([b"junk"], signed=sign_over(TREE.root(24), prot=alg8)))
    assert (junk.status, junk.readable) == ("malformed", False)
    vds1 = {1: -35, 4: kid_of(SERVICE_KEY), 395: 1, 15: {1: ISSUER}}
    not_ccf = check(receipt([b"junk"], signed=sign_over(TREE.root(24), prot=vds1)))
    assert (not_ccf.status, not_ccf.readable) == ("outside_profile", False)
    assert check(receipt(vdp={})).readable is False                 # nothing parsed


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
    assert (c.status, c.signature_valid, c.older_root_matches) == (UNSIZED, True, True)
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
    assert st([o_to_n], older) == UNSIZED
    assert st([m_to_n], middle) == UNSIZED
    assert st([o_to_n], middle) == "consistency_older_root_mismatch"
    assert st([o_to_m], older) == "signature_invalid"                 # the middle root is not signed here
    assert st([o_to_n, m_to_n], older) == st([o_to_n, m_to_n], middle) == UNSIZED
    assert st([o_to_n, o_to_m], older) == "consistency_newer_roots_differ"
    assert st([decode_b64(v["deeper_anchor_proof_b64"])], middle) == "consistency_anchor_not_canonical"


# ------------------------------------------------------------------------------------------------
# Section 4 with the tree sizes (addendum 1 to Z332): the anchor rule in full
# ------------------------------------------------------------------------------------------------
HEADER = "protected header ccf.v1 txid"


def sized(rcpt, m, n=None, *, older=None, rp=None):
    """The reader with the older size the caller holds and, where given, the newer size."""
    return S.verify_consistency_receipt(rcpt, older_root=TREE.root(m) if older is None else older,
                                        older_issuer=ISSUER, rp_trust=trust() if rp is None else rp,
                                        older_size=m, newer_size=n)


def _n1():
    """S4-10 of the section 4 vectors, rebuilt here as Tiago Pinto wrote it: the older root R_6, the
    path [right HASH(d[6])] with leaf 6, and N1 = HASH(R_6 || HASH(d[6])) signed as if it were the
    root of a 7-leaf state (txid 2.7)."""
    n1 = H(TREE.root(6) + TREE.node(6, 7))
    return receipt([enc_proof(TREE.root(6), [[False, TREE.node(6, 7)]])], signed=sign_over(n1, txid="2.7"))


def test_n1_has_the_form_of_a_canonical_4_to_5_proof_and_only_the_sizes_tell_them_apart():
    a45, p45 = TREE.proof(4, 5)
    assert a45 == TREE.root(4) and [t for t, _h in p45] == [False]           # anchor = older root, one right
    four_to_five = receipt([enc_proof(a45, p45)], n=5)
    assert check(four_to_five, m=4).status == check(_n1(), older=TREE.root(6)).status == UNSIZED
    assert sized(four_to_five, 4).status == S.CONFIRMED
    c = sized(_n1(), 6)
    assert (c.status, c.anchor_rule_checked) == ("consistency_anchor_position_mismatch", True)
    assert (c.older_size, c.newer_size, c.newer_size_source) == (6, 7, HEADER)
    assert "node(0, 4)" in c.detail and "node(4, 6)" in c.detail


def test_the_older_size_is_the_callers_to_bind_like_the_older_root():
    """The reader cannot see which state older_root came from: told m = 4, it reads R_6 as the root of
    the first four leaves of N1's tree, and the path fits. The caller takes m from the receipt that
    verified older_root (its txid), as it takes older_root itself."""
    assert sized(_n1(), 4, older=TREE.root(6)).status == S.CONFIRMED


def test_with_both_sizes_every_pair_up_to_24_confirms_and_every_deeper_anchor_sits_elsewhere():
    confirmed = refused = 0
    for n in range(2, 25):
        for m in range(1, n):
            c = sized(receipt(m=m, n=n), m)                       # the newer size from the header
            assert (c.status, c.newer_size, c.newer_size_source) == (S.CONFIRMED, n, HEADER), (m, n)
            assert sized(receipt(m=m, n=n), m, n).status == S.CONFIRMED, (m, n)
            confirmed += 1
            for anchor, path in TREE.deeper(m, n):
                c = sized(receipt([enc_proof(anchor, path)], m=m, n=n), m)
                assert c.status == "consistency_anchor_position_mismatch", (m, n)
                refused += 1
    assert (confirmed, refused) == (276, 224)


def test_no_single_tag_flip_and_no_dropped_or_added_sibling_passes_with_both_sizes():
    """Never confirmed. A variant that still recomputes the older root is refused by the path rule; one
    that no longer does may be the canonical path of another pair (a flip in 1 to 4 is the path of 3
    to 4) and is then refused because no proof recomputes the older root."""
    counts = {"path rule": 0, "older root": 0}
    for n in range(2, 17):
        for m in range(1, n):
            anchor, path = TREE.proof(m, n)
            variants = [path[:i] + [[not path[i][0], path[i][1]]] + path[i + 1:] for i in range(len(path))]
            variants += [path[:-1], path + [[False, TREE.node(0, 1)]], path + [[True, TREE.node(0, 1)]]]
            for bad in (v for v in variants if v):
                c = sized(receipt([enc_proof(anchor, bad)], m=m, n=n), m)
                if _fold(anchor, bad)[0] == TREE.root(m):
                    assert c.status in ("consistency_anchor_position_mismatch",
                                        "consistency_path_not_canonical"), (m, n, bad)
                    counts["path rule"] += 1
                else:
                    assert c.status in ("consistency_anchor_position_mismatch", "consistency_path_not_canonical",
                                        "consistency_older_root_mismatch"), (m, n, bad)
                    counts["older root"] += 1
    assert counts == {"path rule": 190, "older root": 503}


def test_a_path_that_describes_no_node_of_the_newer_tree_is_not_canonical():
    anchor, path = TREE.proof(13, 24)
    too_deep = path + [[False, TREE.node(0, 1)]] * 3
    c = sized(receipt([enc_proof(anchor, too_deep)]), 13)
    assert c.status == "consistency_path_not_canonical" and "no node of a tree of 24 leaves" in c.detail


@pytest.mark.parametrize("m, n, status", [
    (24, 24, "consistency_tree_sizes_invalid"),        # 0 < m < n: m = n
    (25, 24, "consistency_tree_sizes_invalid"),
    (0, 24, "consistency_tree_sizes_invalid"),
    (-1, 24, "consistency_tree_sizes_invalid"),
    (13, 0, "consistency_tree_sizes_invalid"),
    ("13", 24, "consistency_tree_sizes_invalid"),
    (13.0, 24, "consistency_tree_sizes_invalid"),
    (True, 24, "consistency_tree_sizes_invalid"),
    (b"\x0d", 24, "consistency_tree_sizes_invalid"),
    (13, "24", "consistency_tree_sizes_invalid"),
    (13, 2 ** 64 + 1, "consistency_tree_sizes_invalid"),
    (13, 23, "consistency_newer_size_mismatch"),        # the header's txid says 24
    (13, 25, "consistency_newer_size_mismatch"),
    (13, 24, "confirmed"),
    (13, None, "confirmed"),
])
def test_the_sizes_the_caller_gives(m, n, status):
    c = S.verify_consistency_receipt(receipt(), older_root=TREE.root(13), older_issuer=ISSUER,
                                     rp_trust=trust(), older_size=m, newer_size=n)
    assert c.status == status, c.detail


def test_m_equal_to_n_is_refused_by_the_sizes_before_the_first_tag():
    only_left = [[True, TREE.node(0, 16)]]                   # anchor node(16, 24), both folds R_24
    rc = receipt([enc_proof(TREE.node(16, 24), only_left)])
    assert check(rc, older=TREE.root(24)).status == "consistency_anchor_not_canonical"
    assert sized(rc, 24).status == "consistency_tree_sizes_invalid"


@pytest.mark.parametrize("txid, size", [
    ("2.24", 24), ("0.24", 24), ("2.0", 0),
    ("2.024", None), ("2.+24", None), ("2.24 ", None), (" 2.24", None), ("2.２４", None),
    ("2.٢٤", None), ("24", None), ("2.24.1", None), ("", None), ("2.", None), (24, None),
    (b"2.24", None), ("2." + "9" * 21, None),
])
def test_the_newer_size_the_header_yields(txid, size):
    """PROOFBUNDLE'S OWN RULE, not a requirement of -05 (SECTION4_WGLC.md, G5): the seqno of the
    ccf.v1 txid is the tree size the signature covers, measured on CCF 7.0.17 with leaf 0 counted.
    Anything that is not "view.seqno" in ASCII digits yields no size, and the caller's counts."""
    rc = receipt(signed=sign_over(TREE.root(24), txid=txid))
    c = S.verify_consistency_receipt(rc, older_root=TREE.root(13), older_issuer=ISSUER, rp_trust=trust(),
                                     older_size=13)
    if size is None:
        assert (c.status, c.newer_size, c.anchor_rule_checked) == (UNSIZED, None, False)
        given = S.verify_consistency_receipt(rc, older_root=TREE.root(13), older_issuer=ISSUER,
                                             rp_trust=trust(), older_size=13, newer_size=24)
        assert (given.status, given.newer_size_source) == (S.CONFIRMED, "caller")
    elif size == 0:
        assert c.status == "consistency_tree_sizes_invalid"
    else:
        assert (c.status, c.newer_size, c.newer_size_source) == (S.CONFIRMED, size, HEADER)


def test_without_both_sizes_the_success_says_the_anchor_rule_was_not_checked():
    no_txid = sign_over(TREE.root(24), prot={1: -35, 4: kid_of(SERVICE_KEY), 395: 2, 15: {1: ISSUER}})
    for c in (check(receipt()),                                           # no size at all
              S.verify_consistency_receipt(receipt(), older_root=TREE.root(13), older_issuer=ISSUER,
                                           rp_trust=trust(), newer_size=24)):      # n, and no m
        assert (c.status, c.anchor_rule_checked, c.left_siblings_checked) == (UNSIZED, False, False)
        assert "anchor rule of section 4 was not checked beyond the first tag" in c.detail
    c = sized(receipt(signed=no_txid), 13)                                 # m, and no n anywhere
    assert (c.status, c.anchor_rule_checked, c.left_siblings_checked) == (UNSIZED, False, True)
    assert "checked only as far as m alone decides it" in c.detail
    c = sized(receipt(), 13)
    assert (c.status, c.anchor_rule_checked, c.detail) == (S.CONFIRMED, True, "")
    assert {"older_size", "newer_size", "newer_size_source", "anchor_rule_checked",
            "left_siblings_checked"} <= set(c.to_dict())


def test_every_other_proof_is_held_to_the_size_its_anchor_implies():
    good, beside = enc_proof(*TREE.proof(13, 24)), enc_proof(*TREE.proof(17, 24))
    deeper = enc_proof(*TREE.deeper(20, 24)[0])                           # below the anchor of m = 20
    assert sized(receipt([good, beside]), 13).status == S.CONFIRMED
    assert check(receipt([good, deeper])).status == "consistency_anchor_not_canonical"
    assert sized(receipt([good, deeper]), 13).status == "consistency_anchor_position_mismatch"


@pytest.mark.parametrize("bad", [None, -1, 2 ** 80, "24", 24.0, True, [24], {"n": 24}, object()])
def test_sizes_never_raise_and_every_status_is_in_the_closed_set(bad):
    for kw in (dict(older_size=bad), dict(newer_size=bad), dict(older_size=bad, newer_size=bad)):
        c = S.verify_consistency_receipt(receipt(), older_root=TREE.root(13), older_issuer=ISSUER,
                                         rp_trust=trust(), **kw)
        assert c.status in S.CONSISTENCY_STATUS_ORDER + (S.CONFIRMED, UNSIZED), (bad, kw)


def test_the_new_statuses_stand_in_the_order_that_decides():
    order = S.CONSISTENCY_STATUS_ORDER
    new = ("consistency_tree_sizes_invalid", "consistency_newer_size_mismatch",
           "consistency_path_not_canonical", "consistency_anchor_position_mismatch",
           "consistency_left_siblings_mismatch")
    assert [order.index(s) for s in new] == sorted(order.index(s) for s in new)
    assert order.index("consistency_newer_roots_differ") < order.index(new[0])
    assert order.index(new[-1]) < order.index("consistency_anchor_not_canonical")


def test_real_ledger_with_the_sizes_its_receipts_carry():
    """The caller takes m from the txid of the inclusion receipt that verified the older root; the
    reader takes n from the consistency receipt's own header. Measured: seqno = tree size, leaf 0
    counted (CCF 7.0.17)."""
    v, rp = _vector()
    older, middle = _verified_state(v, rp, "older"), _verified_state(v, rp, "middle")
    p = {k: decode_b64(b) for k, b in v["proofs_b64"].items()}

    def st(proofs, held, m=None):
        m = int(held.ccf_txid.split(".")[1]) if m is None else m
        return S.verify_consistency_receipt(_rewrap(v, proofs), older_root=held.merkle_root,
                                            older_issuer=held.issuer, rp_trust=rp, older_size=m)
    assert (older.ccf_txid, middle.ccf_txid) == ("2.19", "2.22")
    assert st([p["19->24"]], older).status == S.CONFIRMED
    assert st([p["22->24"]], middle).status == S.CONFIRMED
    assert st([p["19->24"], p["22->24"]], older).status == S.CONFIRMED
    assert st([p["19->24"]], older, m=22).status == "consistency_anchor_position_mismatch"
    deeper = decode_b64(v["deeper_anchor_proof_b64"])
    assert st([deeper], middle).status == "consistency_anchor_position_mismatch"
    assert st([p["19->24"]], older).newer_size == 24


def test_a_path_below_a_leaf_is_not_canonical_and_decides_before_an_anchor_elsewhere():
    """A leaf that is itself HASH(a || b) lets a path go one step below it and still compute R_24; it
    describes no node of the tree of 24 leaves. Beside a proof whose anchor sits elsewhere, the path
    status comes first, as CONSISTENCY_STATUS_ORDER says."""
    a, b = H(b"below the leaf, left"), H(b"below the leaf, right")
    tree = Tree(24, seed=b"a leaf with children")
    tree.leaves[12] = H(a + b)
    anchor, path = tree.proof(13, 24)                      # anchor: leaf 12
    below = enc_proof(a, [[False, b]] + path)
    deeper = enc_proof(*tree.deeper(20, 24)[0])
    signed = sign_over(tree.root(24), txid="2.24")

    def st(proofs):
        return S.verify_consistency_receipt(receipt(proofs, signed=signed), older_root=tree.root(13),
                                            older_issuer=ISSUER, rp_trust=trust(), older_size=13)
    good = enc_proof(anchor, path)
    assert st([good]).status == S.CONFIRMED
    assert st([good, below]).status == "consistency_path_not_canonical"
    assert st([good, deeper]).status == "consistency_anchor_position_mismatch"
    assert st([good, deeper, below]).status == st([good, below, deeper]).status == "consistency_path_not_canonical"


def test_another_proof_whose_anchor_ends_at_the_last_leaf_implies_no_smaller_older_tree():
    good = enc_proof(*TREE.proof(13, 24))
    right_edge = enc_proof(TREE.node(16, 24), [[True, TREE.node(0, 16)]])       # older = newer = R_24
    c = sized(receipt([good, right_edge]), 13)
    assert c.status == "consistency_anchor_position_mismatch"
    assert "ends at the last leaf of the newer tree" in c.detail


# ------------------------------------------------------------------------------------------------
# With the older size alone (Nachtrag 2 to Z332): popcount(m) - 1 left siblings
# ------------------------------------------------------------------------------------------------
NO_TXID = {1: -35, 4: kid_of(SERVICE_KEY), 395: 2, 15: {1: ISSUER}}


def _no_txid(proofs, newer_root):
    return receipt(proofs, signed=sign_over(newer_root, prot=NO_TXID))


def test_with_m_alone_a_trusted_m_of_6_refuses_tiagos_n1():
    """The list answer: a trusted m = 6 is enough to refuse N1 = HASH(R_6 || HASH(d[6])), whose one
    right sibling leaves no left sibling where 6 = 4 + 2 needs one."""
    n1 = H(TREE.root(6) + TREE.node(6, 7))
    rc = _no_txid([enc_proof(TREE.root(6), [[False, TREE.node(6, 7)]])], n1)
    c = S.verify_consistency_receipt(rc, older_root=TREE.root(6), older_issuer=ISSUER, rp_trust=trust(),
                                     older_size=6)
    assert (c.status, c.newer_size, c.left_siblings_checked, c.anchor_rule_checked) == \
        ("consistency_left_siblings_mismatch", None, True, False)
    assert "0 left siblings" in c.detail and "popcount(6) - 1 = 1" in c.detail
    bare = S.verify_consistency_receipt(rc, older_root=TREE.root(6), older_issuer=ISSUER, rp_trust=trust())
    assert (bare.status, bare.left_siblings_checked) == (UNSIZED, False)


def test_with_m_alone_every_canonical_pair_up_to_20_passes_and_every_deeper_anchor_is_refused():
    passed = refused = 0
    for n in range(2, 21):
        for m in range(1, n):
            c = S.verify_consistency_receipt(_no_txid([enc_proof(*TREE.proof(m, n))], TREE.root(n)),
                                             older_root=TREE.root(m), older_issuer=ISSUER, rp_trust=trust(),
                                             older_size=m)
            assert (c.status, c.left_siblings_checked) == (UNSIZED, True), (m, n)
            assert "as far as m alone decides it" in c.detail
            passed += 1
            for anchor, path in TREE.deeper(m, n):
                c = S.verify_consistency_receipt(_no_txid([enc_proof(anchor, path)], TREE.root(n)),
                                                 older_root=TREE.root(m), older_issuer=ISSUER,
                                                 rp_trust=trust(), older_size=m)
                assert c.status == "consistency_left_siblings_mismatch", (m, n)
                refused += 1
    assert (passed, refused) == (190, 150)


def test_with_m_alone_only_the_proof_that_recomputes_the_older_root_is_counted():
    good, beside = enc_proof(*TREE.proof(13, 24)), enc_proof(*TREE.proof(17, 24))
    c = S.verify_consistency_receipt(_no_txid([good, beside], TREE.root(24)), older_root=TREE.root(13),
                                     older_issuer=ISSUER, rp_trust=trust(), older_size=13)
    assert (c.status, c.left_siblings_checked) == (UNSIZED, True)
    wrong_m = S.verify_consistency_receipt(_no_txid([good], TREE.root(24)), older_root=TREE.root(13),
                                           older_issuer=ISSUER, rp_trust=trust(), older_size=12)
    assert wrong_m.status == "consistency_left_siblings_mismatch"      # 12 = 8 + 4 needs one, 13 has two


def test_with_both_sizes_the_full_rule_decides_and_the_count_is_not_reported_apart():
    c = sized(receipt([enc_proof(*TREE.deeper(20, 24)[0])], m=20, n=24), 20)
    assert (c.status, c.left_siblings_checked, c.anchor_rule_checked) == \
        ("consistency_anchor_position_mismatch", False, True)


def test_the_left_sibling_status_stands_between_the_path_rule_and_the_first_tag():
    order = S.CONSISTENCY_STATUS_ORDER
    assert order.index("consistency_anchor_position_mismatch") \
        < order.index("consistency_left_siblings_mismatch") < order.index("consistency_anchor_not_canonical")
