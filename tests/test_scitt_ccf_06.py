"""The -06 probes of finding B53-6 (CCF_7021 interop delivery): what draft -06 decides, case by case.

Draft text: draft-ietf-scitt-receipts-ccf-profile-06, retrieved 2026-10-24 from
https://www.ietf.org/archive/id/draft-ietf-scitt-receipts-ccf-profile-06.txt (sha256 a61b704bcd39283d1e3f3a451c05987c
9c845bae0009ee6bb50d1820ae398928, 1064 lines). Every "line" below is a line of that file.

1. An inclusion proof with an empty path is a tree of one leaf: "&(path: 2) => [* ccf-proof-element]" (line 351),
   "The path is empty for a tree of size 1, whose root is the leaf hash" (lines 362-363). The four inclusion samples
   of -06 (samples/inclusion-receipts at a62b5f9bb445ac580931a3649944fd4091267806) are rebuilt here from their
   README with an issuer and a key made here. Their bytes are not copied (IETF terms, as in the delivery), and they
   carry no CWT issuer, by which scitt-ccf/v1 selects a key (ADR 0009, Decision 5). M-INC-EMPTY-PATH, a receipt of
   ledger ef68d03d with its path emptied, stays refused, now by its signature (line 478).
2. S4-10 (tools/scitt_ccf_external/section4_vectors) passes Figure 9 (lines 633-658) and is accepted with the tree
   sizes 6 and 7 as without them: "verification does not establish m, n, or that the anchor is the node required
   above" (lines 548-549); the comparison with older_root confirms that the anchor is a node of that state, "but
   not that it is the anchor required in Section 4, which is not needed for the guarantee the receipt provides"
   (lines 681-683). S4-09 and S4-13 stay refused with the sizes, by the rule -06 does state: the first element of
   path MUST be a right sibling (lines 541-546, line 646).
3. A statement algorithm outside scitt-ccf/v1 is outside_profile in verify_statement_signature, as it already is in
   verify_transparent_statement. ADR 0009, Decision 6: "Any other algorithm is outside_profile, never invalid". -06
   sets no statement algorithm; its alg rule (lines 706-707) is the receipt's.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(importlib.util.find_spec("cbor2") is None,
                                reason="the -06 probes need cbor2 (the [scitt] extra)")

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, utils  # noqa: E402

from proofbundle import scitt_ccf as S  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "tests" / "fixtures" / "scitt_ccf" / "ccf_7021_b53_6.json"
S4 = REPO / "tools" / "scitt_ccf_external" / "section4_vectors"
ISSUER = "service.example"


def sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _h(mt: int, n: int) -> bytes:
    if n < 24:
        return bytes([(mt << 5) | n])
    for ai, w in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * w):
            return bytes([(mt << 5) | ai]) + n.to_bytes(w, "big")
    raise ValueError(n)


class Text(bytes):
    """A CBOR text string written from these bytes as they are, valid UTF-8 or not."""


def enc(o) -> bytes:
    if o is True:
        return b"\xf5"
    if o is False:
        return b"\xf4"
    if o is None:
        return b"\xf6"
    if isinstance(o, int):
        return _h(0, o) if o >= 0 else _h(1, -1 - o)
    if isinstance(o, Text):
        return _h(3, len(o)) + bytes(o)
    if isinstance(o, bytes):
        return _h(2, len(o)) + o
    if isinstance(o, str):
        return enc(Text(o.encode("utf-8")))
    if isinstance(o, list):
        return _h(4, len(o)) + b"".join(enc(x) for x in o)
    if isinstance(o, dict):
        return _h(5, len(o)) + b"".join(enc(k) + enc(v) for k, v in o.items())
    raise TypeError(type(o))


SERVICE_KEY = ec.generate_private_key(ec.SECP384R1())
SERVICE_SPKI = SERVICE_KEY.public_key().public_bytes(serialization.Encoding.DER,
                                                     serialization.PublicFormat.SubjectPublicKeyInfo)
KID = hashlib.sha256(SERVICE_SPKI).hexdigest().encode("ascii")


def receipt(leaf: list, signed_root: bytes) -> bytes:
    """A tagged COSE_Sign1 inclusion receipt with one proof, leaf as given and an empty path, signed over
    signed_root: ES384, the kid of the key and a CWT issuer, which the -06 samples do not carry."""
    prot = enc({1: -35, 4: KID, 395: 2, 15: {1: ISSUER, 2: "scitt.ccf.signature.v1"}})
    r, s = utils.decode_dss_signature(SERVICE_KEY.sign(enc(["Signature1", prot, b"", signed_root]),
                                                       ec.ECDSA(hashes.SHA384())))
    proof = enc({1: leaf, 2: []})
    return b"\xd2" + enc([prot, {396: {-1: [proof]}}, None, r.to_bytes(48, "big") + s.to_bytes(48, "big")])


def check(raw: bytes) -> S.ReceiptCheck:
    """Figure 7 of -06, verify_inclusion_receipt(inclusion_receipt, statement_digest), as the -06 samples run it:
    statement_digest is SHA-256("statement") (samples/inclusion-receipts/README.md). The CDDL pass runs first and
    a refusal there is the check (ADR 0009, Decision 16); the status logic reads only what it accepted."""
    v = S._receipt(0, raw)
    if not isinstance(v, S._ValidReceipt):
        return v
    return S._receipt_status(0, v, DIGEST, {ISSUER: [SERVICE_SPKI]})


# samples/inclusion-receipts/README.md of -06, "The leaves" and "The right leaf R"
DIGEST = sha(b"statement")
L = (sha(b"its"), b"ce:2.5:" + b"a" * 64, DIGEST)
R_CDDL = (b"internal-transaction-hash-000001", b"ce:2.5:51654972", b"data-hash-of-a-statement-0000001")
R_UTF8 = (sha(b"its"), b"ce:2.5:" + b"b" * 64, DIGEST)


def d(leaf: tuple) -> bytes:
    """The serialization of a leaf (-06 Figure 5): internal-transaction-hash || HASH(internal-evidence) || data-hash."""
    itx, ev, dh = leaf
    return itx + sha(ev) + dh


def root_as_leaf(right: tuple, data_hash: bytes) -> list:
    return [sha(d(L)), Text(d(right)), data_hash]


def test_the_rebuilt_samples_have_the_roots_their_readme_names():
    """The constructions below are the samples' own: the README of samples/inclusion-receipts names the root each
    one signs, and these leaves give exactly those roots."""
    assert sha(d(L)).hex() == "07a9c2f9dc15fedb52f83d2fc35d375e4b6720ffad9e389cc711de307802ce3a"
    assert sha(sha(d(L)) + sha(d(R_CDDL))).hex() == "28a11a835421faebbf4addb5623ad27dca5753798d52182c6f8d0d234577def8"
    assert sha(sha(d(L)) + sha(d(R_UTF8))).hex() == "7d78bec57d533d3192f1047b1b47cf6042a37be62cd5fcfa6dc88bb1e52e4cf4"
    d(R_CDDL).decode("utf-8")                                   # README: d(R) is valid UTF-8 for cddl-* and signature-*
    with pytest.raises(UnicodeDecodeError):
        d(R_UTF8).decode("utf-8")                               # and not for utf8-*


def test_valid_01_one_leaf_empty_path_confirms_over_the_leaf_hash():
    """-06 line 351, path [* ccf-proof-element]; lines 362-363, empty for a tree of size 1, whose root is the leaf
    hash. -05 wrote [+ ccf-proof-element] (its section 3), so a -05 reader refuses this receipt as malformed."""
    c = check(receipt([L[0], L[1].decode("ascii"), L[2]], sha(d(L))))
    assert (c.status, c.readable, c.signature_valid, c.bound) == (S.CONFIRMED, True, True, True)
    assert c.merkle_root == sha(d(L))


def test_invalid_cddl_root_as_leaf_empty_data_hash_is_malformed_at_the_leaf_sizes():
    """-06 lines 241 and 424: data-hash is a byte string of exactly 32 bytes. Refused for that, not for the path."""
    c = check(receipt(root_as_leaf(R_CDDL, b""), sha(sha(d(L)) + sha(d(R_CDDL)))))
    assert (c.status, c.readable) == ("malformed", False)
    assert "data-hash is not bstr .size 32" in c.detail and "path" not in c.detail, c.detail


def test_invalid_signature_root_as_leaf_data_hash_32_fails_on_the_signature():
    """-06 line 478, assert(verify_cose(inclusion_receipt, payload)) over compute_root: the leaf has the shapes of
    the CDDL, so the proof is read, and the signature is over another root."""
    c = check(receipt(root_as_leaf(R_CDDL, DIGEST), sha(sha(d(L)) + sha(d(R_CDDL)))))
    assert (c.status, c.readable, c.signature_valid) == ("signature_invalid", True, False)


def test_invalid_utf8_root_as_leaf_evidence_not_utf8_is_refused_at_decoding():
    """-06 lines 413-414 (valid CBOR, RFC 8949 section 5.3.1) and 421-422 (internal-evidence is valid UTF-8)."""
    c = check(receipt(root_as_leaf(R_UTF8, b""), sha(sha(d(L)) + sha(d(R_UTF8)))))
    assert (c.status, c.readable) == ("malformed", False)
    assert "UTF-8" in c.detail and "path" not in c.detail, c.detail


# ------------------------------------------------------------------------------------------------
# The ledger's own receipt with its path emptied (vectors K2.main_ef68d03d.*, CCF_7021 delivery)
# ------------------------------------------------------------------------------------------------
def _fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _end_to_end(v: dict) -> S.TransparentStatementCheck:
    services = {v["issuer"]: S.load_cose_keyset(bytes.fromhex(v["keyset_hex"]))}
    return S.verify_transparent_statement(bytes.fromhex(v["transparent_statement_hex"]),
                                          canonical_root=bytes.fromhex(v["canonical_root_hex"]),
                                          rp_trust={"scitt_ccf_services": services,
                                                    "scitt_statement_keys": [bytes.fromhex(v["statement_spki_hex"])]})


def test_the_ledger_control_confirms_and_its_path_emptied_fails_on_the_signature():
    """M-INC-EMPTY-PATH: the receipt of ledger ef68d03d (CCF 7.0.22) with its path removed. Under -06 the empty path
    is read (line 351), its root is the leaf hash (lines 362-363), and the signature over the ledger's root fails
    on it (line 478). The unchanged control confirms first."""
    control, emptied = _fixture()["inclusion"]
    assert control["vector_id"] == "K2.main_ef68d03d.ALG-ES256.ts"
    assert emptied["vector_id"] == "K2.main_ef68d03d.M-INC-EMPTY-PATH"
    assert _end_to_end(control).status == S.CONFIRMED
    r = _end_to_end(emptied)
    assert (r.status, r.statement_status, r.readable) == ("signature_invalid", S.CONFIRMED, True)
    assert (r.receipts[0].status, r.receipts[0].signature_valid, r.receipts[0].bound) == ("signature_invalid", False, True)


# ------------------------------------------------------------------------------------------------
# S4-10 and its neighbours with the tree sizes (tools/scitt_ccf_external/section4_vectors)
# ------------------------------------------------------------------------------------------------
def _s4(vid: str) -> dict:
    return json.loads((S4 / f"{vid}.json").read_text(encoding="utf-8"))


def _consistency(vid: str, older_size=None, newer_size=None) -> S.ConsistencyCheck:
    v = _s4(vid)
    key = v["public_key"]
    trust = {"scitt_ccf_services": {key["issuer"]: [{"spki": bytes.fromhex(key["spki_der_hex"]),
                                                      "kid": key["kid"].encode("ascii")}]}}
    return S.verify_consistency_receipt(bytes.fromhex(v["receipt_hex"]), older_root=bytes.fromhex(v["older_root_hex"]),
                                        older_issuer=key["issuer"], rp_trust=trust, older_size=older_size,
                                        newer_size=newer_size)


def test_s4_10_passes_figure_9_with_the_tree_sizes_as_without_them():
    """S4-10: anchor R_6, path [right HASH(d[6])], signed over N1 = HASH(R_6 || HASH(d[6])) with the txid 2.7. Every
    assert of Figure 9 (lines 633-658) holds. The sizes the caller gives do not make it fail: verification does not
    establish m, n or the anchor of section 4 (lines 548-549, 681-683, 850-851), and the signed value need not be a
    Merkle Tree Hash for the receipt to verify (lines 685-688, 853-857)."""
    v = _s4("S4-10")
    assert (v["older_size"], v["newer_size"]) == (6, 7)
    both = _consistency("S4-10", 6, 7)
    assert (both.status, both.signature_valid, both.older_root_matches) == (S.CONFIRMED, True, True)
    assert (both.older_size, both.newer_size, both.newer_size_source) == (6, 7, "caller")
    for m, n in ((6, None), (None, 7), (None, None)):
        assert _consistency("S4-10", m, n).status == S.CONFIRMED_WITHOUT_TREE_SIZES, (m, n)


@pytest.mark.parametrize("vid", ["S4-09", "S4-13"])
def test_a_first_left_sibling_is_refused_with_the_sizes_as_without_them(vid):
    """The rule -06 keeps for the anchor: "The first element of path MUST be a right sibling (left is false)" and
    "A proof whose first element is a left sibling MUST be rejected" (lines 541-546), assert(proof.path[0].left ==
    false) in Figure 9 (line 646). It decides with the sizes too; no rule of the sizes comes before it."""
    v = _s4(vid)
    assert _consistency(vid).status == "consistency_anchor_not_canonical"
    assert _consistency(vid, v["older_size"], v["newer_size"]).status == "consistency_anchor_not_canonical"


def test_s4_08_m_equal_to_n_stays_refused_by_the_sizes():
    """Not loosened: a consistency proof relates m to n "where 0 < m < n" (lines 511-513), and "there is no
    consistency proof for m == n" (lines 545-546). The caller's m = n = 24 is refused before the first tag."""
    assert _consistency("S4-08", 24, 24).status == "consistency_tree_sizes_invalid"
    assert _consistency("S4-08").status == "consistency_anchor_not_canonical"


# ------------------------------------------------------------------------------------------------
# The statements of the ALG forms as three ledger states served them (CCF_7021 delivery)
# ------------------------------------------------------------------------------------------------
_IN_PROFILE = ("ES256", "ES384", "PS256", "PS384")
_STATEMENTS = _fixture()["statements"] if FIXTURE.is_file() else []


def test_the_fixture_holds_every_served_alg_form_of_the_delivery():
    got = sorted((s["state"], s["alg"]) for s in _STATEMENTS)
    want = sorted((st, a) for st in ("basis_00101f76", "c7021_0288af35", "main_ef68d03d")
                  for a in _IN_PROFILE + ("ES512", "PS512", "EdDSA"))
    want.remove(("basis_00101f76", "EdDSA"))      # B53-2: that state answered HTTP 500 and served nothing
    assert got == want
    assert all(hashlib.sha256(bytes.fromhex(s["statement_hex"])).hexdigest() == s["statement_sha256"] for s in _STATEMENTS)
    assert {s["recorded"]["pycose_1.1.0"] for s in _STATEMENTS} == {"accept"}     # every signature itself is good


@pytest.mark.parametrize("s", _STATEMENTS, ids=[s["id"] for s in _STATEMENTS])
def test_a_statement_algorithm_outside_the_profile_is_outside_profile_not_invalid(s):
    """ES256, ES384, PS256 and PS384 confirm under the key of the statement's own x5chain. PS512 (-39), ES512 (-36)
    and EdDSA (-8) are outside scitt-ccf/v1: outside_profile with no verdict on the signature, the reason
    verify_transparent_statement gives for the same statement, not statement_signature_invalid or needs_rp_trust."""
    stmt, key = bytes.fromhex(s["statement_hex"]), bytes.fromhex(s["leaf_spki_hex"])
    got = S.verify_statement_signature(stmt, statement_keys=[key])
    if s["alg"] in _IN_PROFILE:
        assert got == (S.CONFIRMED, True)
        return
    assert got == ("outside_profile", None)
    st = S.decode_cose_sign1(stmt, role="statement")
    alg = st.protected[1]
    assert alg == {"ES512": -36, "PS512": -39, "EdDSA": -8}[s["alg"]]
    why = f"statement algorithm {alg!r} is not in scitt-ccf/v1"
    assert S._statement_profile(st) == why
    assert S._statement_signature(st, [key], S._statement_key_selector(st))[3] == why
