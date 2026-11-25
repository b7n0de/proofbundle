"""Issue 557: `evaluate_public_transparency` reports CONSISTENCY as PASS only for a verified proof.

Until 6.6.1 the status became PASS when the caller passed `consistency_confirmed=True`, or a
`ConsistencyVerificationResult` with `confirmed=True` bound to the checkpoint under evaluation. No proof
was checked on that path. These tests hold the rule that replaces it: CONSISTENCY is PASS only when a
consistency proof between the older state the relying party holds and the checkpoint under evaluation
was verified on this path, by `merkle.verify_consistency` (RFC 6962 / RFC 9162) or by
`scitt_ccf.verify_consistency_receipt` (a CCF consistency receipt). A caller's statement alone, as a
boolean or as a typed result, is a FAIL (the module's rule for a required check without its material).

THE EXPECTED VALUES COME FROM AN OWN REFERENCE, not from the code under test: `_mth` and `_subproof`
below are RFC 6962 section 2.1 and 2.1.2 written out, and `_ccf_receipt` builds a CCF consistency
receipt by the -06 profile from its own tree code. No helper of proofbundle computes an expected root or
proof here.

The cases. RFC 6962: 48 pairs (n, k) over n in GROESSEN, k in {1, 2, past the next power of two}. State 1
is n entries; state 2 is the same entries with entry 0 changed and k entries appended, honestly rebuilt.
The proof is the honest SUBPROOF of state 2, so it must not verify against the root of state 1. CCF: 25
pairs over the same k scheme, receipt signed with ES384 over the newer root. Each case has two tests:

- `..._with_the_proof_...` passes the proof through the new `consistency_proof` argument. At 6.6.1 the
  argument does not exist, so this test is red there only at the interface (TypeError).
- `..._typed_result_alone_...` passes the old typed result with `confirmed=True` for the same pair. At
  6.6.1 that was PASS, so this test is red there on the verdict. It is the counter-check that a verifier
  without the new rule deviates at every case.

The two errata to RFC 9942 (both "Reported", not "Verified", on 2026-11-21): eid9316, the tree size of a
receipt is authenticated only where it stands under the signature; eid9317, both sizes of a consistency
proof have to be bound to their roots through held or signed data. See the tests named `erratum_9316`
and `erratum_9317`.
"""
from __future__ import annotations

import base64
import hashlib

import pytest

from proofbundle.checkpoint import sign_checkpoint, vkey
from proofbundle.emit import generate_signer
from proofbundle.public_transparency import ConsistencyVerificationResult, evaluate_public_transparency

ORIGIN = "probe.example/log"
POLICY = {"requireSignedCheckpoint": True, "requireConsistencyProof": True}
GROESSEN = [1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 100]


# ---- own reference, RFC 6962 section 2.1 ----------------------------------------------------------
def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _k(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _mth(d: list) -> bytes:
    if not d:
        return _h(b"")
    if len(d) == 1:
        return _h(b"\x00" + d[0])
    k = _k(len(d))
    return _h(b"\x01" + _mth(d[:k]) + _mth(d[k:]))


def _subproof(m: int, d: list, b: bool) -> list:
    n = len(d)
    if m == n:
        return [] if b else [_mth(d)]
    k = _k(n)
    if m <= k:
        return _subproof(m, d[:k], b) + [_mth(d[k:])]
    return _subproof(m - k, d[k:], False) + [_mth(d[:k])]


def _entries(n: int, prefix: bytes = b"e") -> list:
    return [prefix + i.to_bytes(4, "big") for i in range(n)]


def _past_power_of_two(n: int) -> list:
    p = 1
    while p <= n:
        p *= 2
    return sorted({1, 2, p - n + 1})


FAELLE = [(n, k) for n in GROESSEN for k in _past_power_of_two(n)]
CCF_FAELLE = [(n, k) for n in (2, 3, 4, 5, 7, 8, 9, 16, 17) for k in _past_power_of_two(n)]


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _checkpoint(size: int, root: bytes):
    sk = generate_signer()
    return sign_checkpoint(ORIGIN, size, root, sk, "k"), vkey("k", sk.public_key().public_bytes_raw())


def _proof_input(**fields):
    """The new argument. Imported here, so the module collects at 6.6.1, where the class is absent and the
    test is red at the interface."""
    from proofbundle.public_transparency import ConsistencyProof  # noqa: PLC0415
    return ConsistencyProof(**fields)


def _typed(old_size, old_root, new_size, new_root) -> ConsistencyVerificationResult:
    return ConsistencyVerificationResult(
        old_origin=ORIGIN, old_tree_size=old_size, old_root_b64=_b64(old_root), new_origin=ORIGIN,
        new_tree_size=new_size, new_root_b64=_b64(new_root), proof_digest="none", verifier_version="none",
        policy_digest="none", confirmed=True)


def _states(n, k):
    d1 = _entries(n)
    d2 = [b"CHANGED"] + d1[1:] + _entries(k, b"new")
    return d1, d2


# ---- RFC 6962, 48 cases ---------------------------------------------------------------------------
def test_the_reference_matches_rfc_6962_on_honest_appends():
    """Control for the reference itself: an honest append verifies with merkle.verify_consistency in all 48."""
    from proofbundle import merkle
    for n, k in FAELLE:
        d1 = _entries(n)
        d = d1 + _entries(k, b"new")
        assert merkle.verify_consistency(n, n + k, _subproof(n, d, True), _mth(d1), _mth(d)) is True, (n, k)


@pytest.mark.parametrize("n,k", FAELLE)
def test_rfc6962_changed_early_entry_with_the_proof_fails(n, k):
    d1, d2 = _states(n, k)
    note, vk = _checkpoint(n + k, _mth(d2))
    beweis = _proof_input(old_origin=ORIGIN, old_tree_size=n, old_root_b64=_b64(_mth(d1)),
                          proof_b64=[_b64(p) for p in _subproof(n, d2, True)])
    r = evaluate_public_transparency(note, POLICY, log_vkey=vk, consistency_proof=beweis)
    assert r["statuses"]["CONSISTENCY"] == "FAIL", r
    assert r["PUBLIC_TRANSPARENCY"] == "FAIL", r


@pytest.mark.parametrize("n,k", FAELLE)
def test_rfc6962_changed_early_entry_typed_result_alone_is_no_pass(n, k):
    d1, d2 = _states(n, k)
    note, vk = _checkpoint(n + k, _mth(d2))
    r = evaluate_public_transparency(note, POLICY, log_vkey=vk,
                                     consistency_result=_typed(n, _mth(d1), n + k, _mth(d2)),
                                     strict_consistency=True)
    assert r["statuses"]["CONSISTENCY"] != "PASS", r
    assert r["PUBLIC_TRANSPARENCY"] != "PASS", r


# ---- CCF consistency receipts, 25 cases -----------------------------------------------------------
_KEY = []


def _ccf_receipt(leaves, m, n, txid, *, txid_unprotected=None):
    """A CCF consistency receipt by -06 section 4: anchor, path with sides, signed over the newer root.
    CCF nodes are H(l || r) without a prefix, and the leaves are already hashes. ``txid=None`` leaves the
    ccf.v1 map out of the protected header; ``txid_unprotected`` puts one in the unprotected header."""
    cbor2 = pytest.importorskip("cbor2")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    if not _KEY:
        _KEY.append(ec.generate_private_key(ec.SECP384R1()))
    key = _KEY[0]

    def node(lo, hi):
        if hi - lo == 1:
            return leaves[lo]
        kk = 1 << ((hi - lo - 1).bit_length() - 1)
        return _h(node(lo, lo + kk) + node(lo + kk, hi))

    def sub(mm, lo, hi, b):
        nn = hi - lo
        if mm == nn:
            return [] if b else [("anchor", node(lo, hi))]
        kk = 1 << ((nn - 1).bit_length() - 1)
        if mm <= kk:
            return sub(mm, lo, lo + kk, b) + [(False, node(lo + kk, hi))]
        return sub(mm - kk, lo + kk, hi, False) + [(True, node(lo, lo + kk))]

    sp = sub(m, 0, n, True)
    if sp and sp[0][0] == "anchor":
        anchor, path = sp[0][1], sp[1:]
    else:
        anchor, path = node(0, m), sp
    path = [[bool(s), hh] for s, hh in path]
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    kid = hashlib.sha256(spki).hexdigest().encode("ascii")
    protected = {1: -35, 4: kid, 395: 2, 15: {1: "probe.example", 2: "scitt.ccf.signature.v1", 6: 1790000000}}
    if txid is not None:
        protected["ccf.v1"] = {"txid": txid}
    prot = cbor2.dumps(protected)
    newer = node(0, n)
    tbs = cbor2.dumps(["Signature1", prot, b"", newer])
    r, s = utils.decode_dss_signature(key.sign(tbs, ec.ECDSA(hashes.SHA384())))
    unprotected = {396: {-2: [cbor2.dumps({1: anchor, 2: path})]}}
    if txid_unprotected is not None:
        unprotected["ccf.v1"] = {"txid": txid_unprotected}
    body = cbor2.dumps([prot, unprotected, None, r.to_bytes(48, "big") + s.to_bytes(48, "big")])
    return b"\xd2" + body, {"scitt_ccf_services": {"probe.example": [spki]}}


def _leaves(n, prefix=b"b"):
    return [_h(prefix + i.to_bytes(4, "big")) for i in range(n)]


def _ccf_root(bl):
    if len(bl) == 1:
        return bl[0]
    kk = 1 << ((len(bl) - 1).bit_length() - 1)
    return _h(_ccf_root(bl[:kk]) + _ccf_root(bl[kk:]))


def _ccf_input(receipt, trust, old_size, old_root, **over):
    fields = dict(old_origin=ORIGIN, old_tree_size=old_size, old_root_b64=_b64(old_root), ccf_receipt=receipt,
                  ccf_issuer="probe.example", ccf_rp_trust=trust)
    fields.update(over)
    return _proof_input(**fields)


@pytest.mark.parametrize("n,k", CCF_FAELLE)
def test_ccf_changed_early_entry_with_the_receipt_fails(n, k):
    b1 = _leaves(n)
    b2 = [_h(b"CHANGED")] + b1[1:] + _leaves(k, b"new")
    rc, tr = _ccf_receipt(b2, n, n + k, f"2.{n + k}")
    note, vk = _checkpoint(n + k, _ccf_root(b2))
    r = evaluate_public_transparency(note, POLICY, log_vkey=vk,
                                     consistency_proof=_ccf_input(rc, tr, n, _ccf_root(b1)))
    assert r["statuses"]["CONSISTENCY"] == "FAIL", r
    assert any("consistency_older_root_mismatch" in e for e in r["errors"]), r["errors"]


@pytest.mark.parametrize("n,k", CCF_FAELLE)
def test_ccf_changed_early_entry_typed_result_alone_is_no_pass(n, k):
    b1 = _leaves(n)
    b2 = [_h(b"CHANGED")] + b1[1:] + _leaves(k, b"new")
    note, vk = _checkpoint(n + k, _ccf_root(b2))
    r = evaluate_public_transparency(note, POLICY, log_vkey=vk,
                                     consistency_result=_typed(n, _ccf_root(b1), n + k, _ccf_root(b2)))
    assert r["statuses"]["CONSISTENCY"] != "PASS", r


# ---- positive cases: a verified proof is PASS -----------------------------------------------------
@pytest.mark.parametrize("n,k", FAELLE)
def test_rfc6962_honest_append_with_the_proof_passes(n, k):
    d1 = _entries(n)
    d = d1 + _entries(k, b"new")
    note, vk = _checkpoint(n + k, _mth(d))
    beweis = _proof_input(old_origin=ORIGIN, old_tree_size=n, old_root_b64=_b64(_mth(d1)),
                          proof_b64=[_b64(p) for p in _subproof(n, d, True)])
    r = evaluate_public_transparency(note, POLICY, log_vkey=vk, consistency_proof=beweis)
    assert r["statuses"]["CONSISTENCY"] == "PASS", r
    assert r["PUBLIC_TRANSPARENCY"] == "PASS", r


def test_rfc6962_same_size_same_root_with_an_empty_proof_passes():
    d = _entries(5)
    note, vk = _checkpoint(5, _mth(d))
    beweis = _proof_input(old_origin=ORIGIN, old_tree_size=5, old_root_b64=_b64(_mth(d)), proof_b64=[])
    r = evaluate_public_transparency(note, POLICY, log_vkey=vk, consistency_proof=beweis)
    assert r["statuses"]["CONSISTENCY"] == "PASS", r


@pytest.mark.parametrize("n,k", CCF_FAELLE)
def test_ccf_honest_append_with_the_receipt_passes(n, k):
    b1 = _leaves(n)
    b2 = b1 + _leaves(k, b"new")
    rc, tr = _ccf_receipt(b2, n, n + k, f"2.{n + k}")
    note, vk = _checkpoint(n + k, _ccf_root(b2))
    r = evaluate_public_transparency(note, POLICY, log_vkey=vk,
                                     consistency_proof=_ccf_input(rc, tr, n, _ccf_root(b1)))
    assert r["statuses"]["CONSISTENCY"] == "PASS", r
    assert r["PUBLIC_TRANSPARENCY"] == "PASS", r


@pytest.mark.parametrize("n,k", FAELLE)
def test_rfc6962_honest_pair_typed_result_alone_is_no_pass(n, k):
    """The old interface for an honest pair: PASS at 6.6.1 without any proof. A statement is no proof."""
    d1 = _entries(n)
    d = d1 + _entries(k, b"new")
    note, vk = _checkpoint(n + k, _mth(d))
    r = evaluate_public_transparency(note, POLICY, log_vkey=vk,
                                     consistency_result=_typed(n, _mth(d1), n + k, _mth(d)))
    assert r["statuses"]["CONSISTENCY"] == "FAIL", r
    assert r["PUBLIC_TRANSPARENCY"] == "FAIL", r


@pytest.mark.parametrize("n,k", CCF_FAELLE)
def test_ccf_honest_pair_typed_result_alone_is_no_pass(n, k):
    b1 = _leaves(n)
    b2 = b1 + _leaves(k, b"new")
    note, vk = _checkpoint(n + k, _ccf_root(b2))
    r = evaluate_public_transparency(note, POLICY, log_vkey=vk,
                                     consistency_result=_typed(n, _ccf_root(b1), n + k, _ccf_root(b2)))
    assert r["statuses"]["CONSISTENCY"] == "FAIL", r


def test_bare_boolean_alone_is_no_pass():
    d = _entries(9)
    note, vk = _checkpoint(9, _mth(d))
    r = evaluate_public_transparency(note, POLICY, log_vkey=vk, consistency_confirmed=True)
    assert r["statuses"]["CONSISTENCY"] == "FAIL", r
    assert r["PUBLIC_TRANSPARENCY"] == "FAIL", r


# ---- the proof is bound to this checkpoint and to the held state ----------------------------------
def _honest(n=5, k=4):
    d1 = _entries(n)
    d = d1 + _entries(k, b"new")
    return d1, d, [_b64(p) for p in _subproof(n, d, True)]


def test_a_proof_for_another_checkpoint_fails():
    d1, d, proof = _honest()
    note, vk = _checkpoint(9, _h(b"another root"))
    beweis = _proof_input(old_origin=ORIGIN, old_tree_size=5, old_root_b64=_b64(_mth(d1)), proof_b64=proof)
    r = evaluate_public_transparency(note, POLICY, log_vkey=vk, consistency_proof=beweis)
    assert r["statuses"]["CONSISTENCY"] == "FAIL", r


def test_an_older_state_of_another_origin_fails():
    d1, d, proof = _honest()
    note, vk = _checkpoint(9, _mth(d))
    beweis = _proof_input(old_origin="other.example/log", old_tree_size=5, old_root_b64=_b64(_mth(d1)),
                          proof_b64=proof)
    r = evaluate_public_transparency(note, POLICY, log_vkey=vk, consistency_proof=beweis)
    assert r["statuses"]["CONSISTENCY"] == "FAIL", r


def test_a_typed_result_beside_a_proof_must_agree_with_it():
    """The old typed result is still read beside a proof: its own negative or unbound answer is a FAIL."""
    d1, d, proof = _honest()
    note, vk = _checkpoint(9, _mth(d))
    beweis = _proof_input(old_origin=ORIGIN, old_tree_size=5, old_root_b64=_b64(_mth(d1)), proof_b64=proof)
    passt = _typed(5, _mth(d1), 9, _mth(d))
    r = evaluate_public_transparency(note, POLICY, log_vkey=vk, consistency_proof=beweis, consistency_result=passt)
    assert r["statuses"]["CONSISTENCY"] == "PASS", r
    andere_alte_seite = _typed(4, _mth(d1[:4]), 9, _mth(d))
    r = evaluate_public_transparency(note, POLICY, log_vkey=vk, consistency_proof=beweis,
                                     consistency_result=andere_alte_seite)
    assert r["statuses"]["CONSISTENCY"] == "FAIL", r
    nein = ConsistencyVerificationResult(**{**passt.__dict__, "confirmed": False})
    r = evaluate_public_transparency(note, POLICY, log_vkey=vk, consistency_proof=beweis, consistency_result=nein)
    assert r["statuses"]["CONSISTENCY"] == "FAIL", r
    r = evaluate_public_transparency(note, POLICY, log_vkey=vk, consistency_proof=beweis,
                                     consistency_confirmed=False)
    assert r["statuses"]["CONSISTENCY"] == "FAIL", r


def test_a_ccf_receipt_for_another_newer_root_fails():
    b1 = _leaves(5)
    b2 = b1 + _leaves(4, b"new")
    rc, tr = _ccf_receipt(b2, 5, 9, "2.9")
    note, vk = _checkpoint(9, _h(b"another root"))
    r = evaluate_public_transparency(note, POLICY, log_vkey=vk, consistency_proof=_ccf_input(rc, tr, 5, _ccf_root(b1)))
    assert r["statuses"]["CONSISTENCY"] == "FAIL", r


@pytest.mark.parametrize("bad", [
    {"old_tree_size": 0}, {"old_tree_size": True}, {"old_tree_size": "5"}, {"old_root_b64": "not base64!"},
    {"old_root_b64": _b64(b"short")}, {"proof_b64": "abc"}, {"proof_b64": [1, 2]}, {"proof_b64": None},
])
def test_malformed_proof_input_fails_and_never_raises(bad):
    d1, d, proof = _honest()
    note, vk = _checkpoint(9, _mth(d))
    fields = dict(old_origin=ORIGIN, old_tree_size=5, old_root_b64=_b64(_mth(d1)), proof_b64=proof)
    fields.update(bad)
    r = evaluate_public_transparency(note, POLICY, log_vkey=vk, consistency_proof=_proof_input(**fields))
    assert r["statuses"]["CONSISTENCY"] == "FAIL", r


def test_both_or_no_proof_form_fails():
    d1, d, proof = _honest()
    note, vk = _checkpoint(9, _mth(d))
    beide = _proof_input(old_origin=ORIGIN, old_tree_size=5, old_root_b64=_b64(_mth(d1)), proof_b64=proof,
                         ccf_receipt=b"\xd2")
    keine = _proof_input(old_origin=ORIGIN, old_tree_size=5, old_root_b64=_b64(_mth(d1)))
    for beweis in (beide, keine):
        r = evaluate_public_transparency(note, POLICY, log_vkey=vk, consistency_proof=beweis)
        assert r["statuses"]["CONSISTENCY"] == "FAIL", r


def _pad_bits_set(text: str) -> str:
    """The same 32 bytes in a second spelling: base64 of 32 bytes has two pad bits in its 43rd character."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    return text[:42] + alphabet[alphabet.index(text[42]) ^ 1] + text[43:]


def test_a_second_spelling_of_the_held_root_or_of_a_proof_hash_fails():
    """A value of the caller is read canonically (`_wire_b64.decode_b64`): the stdlib decoder takes a base64
    string with pad bits set as the same bytes, one root with two wire forms."""
    d1, d, proof = _honest()
    note, vk = _checkpoint(9, _mth(d))
    assert base64.b64decode(_pad_bits_set(_b64(_mth(d1)))) == _mth(d1)
    for fields in ({"old_root_b64": _pad_bits_set(_b64(_mth(d1))), "proof_b64": proof},
                   {"old_root_b64": _b64(_mth(d1)), "proof_b64": [_pad_bits_set(proof[0])] + proof[1:]}):
        beweis = _proof_input(old_origin=ORIGIN, old_tree_size=5, **fields)
        r = evaluate_public_transparency(note, POLICY, log_vkey=vk, consistency_proof=beweis)
        assert r["statuses"]["CONSISTENCY"] == "FAIL", r


@pytest.mark.parametrize("value", [object(), "proof", 5, {"old_tree_size": 5}])
def test_a_consistency_proof_of_another_type_fails(value):
    d = _entries(9)
    note, vk = _checkpoint(9, _mth(d))
    r = evaluate_public_transparency(note, POLICY, log_vkey=vk, consistency_proof=value)
    assert r["statuses"]["CONSISTENCY"] == "FAIL", r


@pytest.mark.parametrize("laenge", [0, 31, 33])
def test_a_proof_hash_that_is_not_32_bytes_fails(laenge):
    """Codex review round 1 on PR 559, finding 1: canonical base64 does not make a value a SHA-256 hash, and
    `merkle.verify_consistency` checks no length. Each case builds the signed size-2 root from the short or long
    element itself, SHA-256(0x01 || h || x), so the arithmetic of the proof holds; at 5c5d5672 all three gave
    CONSISTENCY and PUBLIC_TRANSPARENCY PASS (measured for the empty element)."""
    h = _h(b"\x00probe")
    x = b"\x07" * laenge
    note, vk = _checkpoint(2, _h(b"\x01" + h + x))
    beweis = _proof_input(old_origin=ORIGIN, old_tree_size=1, old_root_b64=_b64(h), proof_b64=[_b64(x)])
    r = evaluate_public_transparency(note, POLICY, log_vkey=vk, consistency_proof=beweis)
    assert r["statuses"]["CONSISTENCY"] == "FAIL", r
    assert r["PUBLIC_TRANSPARENCY"] == "FAIL", r
    assert any("not 32 bytes" in e for e in r["errors"]), r["errors"]


def test_the_same_shape_with_a_32_byte_element_still_passes():
    """The control for the case above: the same construction with a 32-byte element is an honest size-1 to size-2
    proof (the element is the leaf hash of the second entry's place) and passes."""
    h = _h(b"\x00probe")
    x = _h(b"\x00second")
    note, vk = _checkpoint(2, _h(b"\x01" + h + x))
    beweis = _proof_input(old_origin=ORIGIN, old_tree_size=1, old_root_b64=_b64(h), proof_b64=[_b64(x)])
    r = evaluate_public_transparency(note, POLICY, log_vkey=vk, consistency_proof=beweis)
    assert r["statuses"]["CONSISTENCY"] == "PASS", r


@pytest.mark.parametrize("groesse", [10 ** 5000, 2 ** 8193])
def test_a_held_size_past_the_integer_budget_fails_and_never_raises(groesse):
    """Codex review round 1 on PR 559, finding 2: at 5c5d5672 old_tree_size=10**5000 with a well-formed path raised
    ValueError when the failure message rendered it (Python's integer-string digit limit), and 2**8193 gave a
    message of 2613 characters. A size past `budget.int_magnitude_ok` is refused before any message renders it,
    on both proof forms."""
    d1, d, proof = _honest()
    note, vk = _checkpoint(9, _mth(d))
    for beweis in (
            _proof_input(old_origin=ORIGIN, old_tree_size=groesse, old_root_b64=_b64(_mth(d1)), proof_b64=proof),
            _proof_input(old_origin=ORIGIN, old_tree_size=groesse, old_root_b64=_b64(_mth(d1)),
                         ccf_receipt=b"\xd2\x84", ccf_issuer="probe.example",
                         ccf_rp_trust={"scitt_ccf_services": {}})):
        r = evaluate_public_transparency(note, POLICY, log_vkey=vk, consistency_proof=beweis)
        assert r["statuses"]["CONSISTENCY"] == "FAIL", r
        assert any("integer budget" in e for e in r["errors"]), r["errors"]
        assert all(len(e) < 400 for e in r["errors"]), [len(e) for e in r["errors"]]


def test_without_the_requirement_consistency_stays_not_evaluated():
    d1, d, proof = _honest()
    note, vk = _checkpoint(9, _mth(d))
    beweis = _proof_input(old_origin=ORIGIN, old_tree_size=5, old_root_b64=_b64(_mth(d1)), proof_b64=proof)
    r = evaluate_public_transparency(note, {"requireSignedCheckpoint": True}, log_vkey=vk, consistency_proof=beweis)
    assert r["statuses"]["CONSISTENCY"] == "NOT_EVALUATED", r


# ---- the two errata to RFC 9942 -------------------------------------------------------------------
def test_erratum_9316_a_signed_tree_size_that_differs_from_the_proof_fails():
    """eid9316: a tree size counts only where it stands under the signature. The CCF txid in the protected
    header names the tree size its signature covers (proofbundle's own rule, scitt_ccf._txid_tree_size); a
    receipt signed at 2.10 for a proof the checkpoint computes at size 9 is a failure."""
    b1 = _leaves(5)
    b2 = b1 + _leaves(4, b"new")
    rc, tr = _ccf_receipt(b2, 5, 9, "2.10")
    note, vk = _checkpoint(9, _ccf_root(b2))
    r = evaluate_public_transparency(note, POLICY, log_vkey=vk, consistency_proof=_ccf_input(rc, tr, 5, _ccf_root(b1)))
    assert r["statuses"]["CONSISTENCY"] == "FAIL", r
    assert any("consistency_newer_size_mismatch" in e for e in r["errors"]), r["errors"]


def test_erratum_9316_typed_result_alone_for_the_same_receipt_is_no_pass():
    """The old interface for the receipt above: a caller who verified it without sizes and reported
    confirmed=True was PASS at 6.6.1."""
    b1 = _leaves(5)
    b2 = b1 + _leaves(4, b"new")
    note, vk = _checkpoint(9, _ccf_root(b2))
    r = evaluate_public_transparency(note, POLICY, log_vkey=vk, consistency_result=_typed(5, _ccf_root(b1), 9, _ccf_root(b2)))
    assert r["statuses"]["CONSISTENCY"] != "PASS", r


def test_erratum_9316_a_size_outside_the_protected_header_is_stated_not_checked():
    """The other side of eid9316: a receipt without a protected txid carries no signed size, and one in the
    unprotected header is not covered by the signature, so neither is compared. The proof still decides."""
    b1 = _leaves(5)
    b2 = b1 + _leaves(4, b"new")
    note, vk = _checkpoint(9, _ccf_root(b2))
    for rc, tr in (_ccf_receipt(b2, 5, 9, None), _ccf_receipt(b2, 5, 9, None, txid_unprotected="2.10")):
        r = evaluate_public_transparency(note, POLICY, log_vkey=vk,
                                         consistency_proof=_ccf_input(rc, tr, 5, _ccf_root(b1)))
        assert r["statuses"]["CONSISTENCY"] == "PASS", r


def test_erratum_9317_the_older_size_is_the_held_one_and_is_checked():
    """eid9317: both sizes of a consistency proof have to be bound to their roots. The newer size is the
    signed checkpoint's; the older one is the size of the state the relying party holds. An honest (5, 9)
    proof against a held state named size 6 (or 4) with the root of 5 entries is a failure, because the
    proof is verified for exactly the pair (held size, signed size)."""
    d1, d, proof = _honest(5, 4)
    note, vk = _checkpoint(9, _mth(d))
    for falsch in (4, 6):
        beweis = _proof_input(old_origin=ORIGIN, old_tree_size=falsch, old_root_b64=_b64(_mth(d1)), proof_b64=proof)
        r = evaluate_public_transparency(note, POLICY, log_vkey=vk, consistency_proof=beweis)
        assert r["statuses"]["CONSISTENCY"] == "FAIL", (falsch, r)


def test_erratum_9317_typed_result_alone_with_the_wrong_older_size_is_no_pass():
    d1, d, _proof = _honest(5, 4)
    note, vk = _checkpoint(9, _mth(d))
    for falsch in (4, 6):
        r = evaluate_public_transparency(note, POLICY, log_vkey=vk, consistency_result=_typed(falsch, _mth(d1), 9, _mth(d)))
        assert r["statuses"]["CONSISTENCY"] != "PASS", (falsch, r)


def test_erratum_9317_ccf_both_sizes_reach_the_receipt_verifier():
    """The CCF receipt carries no sizes; both come from the held state and the signed checkpoint, and a
    held older size that is not below the newer one is refused (0 < m < n, -06 section 4)."""
    b1 = _leaves(5)
    b2 = b1 + _leaves(4, b"new")
    rc, tr = _ccf_receipt(b2, 5, 9, "2.9")
    note, vk = _checkpoint(9, _ccf_root(b2))
    r = evaluate_public_transparency(note, POLICY, log_vkey=vk, consistency_proof=_ccf_input(rc, tr, 9, _ccf_root(b1)))
    assert r["statuses"]["CONSISTENCY"] == "FAIL", r
    assert any("consistency_tree_sizes_invalid" in e for e in r["errors"]), r["errors"]
