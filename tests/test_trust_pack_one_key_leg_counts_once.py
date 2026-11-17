"""KR-01 (quality lens on the crypto foundation at 53d1eafe, 15.11.2026): one ML-DSA key counted twice in a root
threshold.

A Trust Pack is authenticated by a threshold of DISTINCT root keys. Distinct was decided by `publicKey` alone, in the
validator's aliasing check and in every count. That field holds the ML-DSA key of an `mldsa65` key but the Ed25519 leg
of a `hybrid-ed25519-mldsa65` key, whose ML-DSA leg sits in `publicKeyPq`. So one ML-DSA key P counted twice when it
appeared as an `mldsa65` key and as the PQ leg of a hybrid (case A), or as the PQ leg of two hybrids (case B). Once
Ed25519 is broken, the case hybrids exist for, one ML-DSA secret met a threshold of two. The same assumption sat in the
rotation vouch (the previous root comes from the caller and is never validated) and in the root-key pin (anchor 3).

The class: a key is the set of its legs, and two keys that share ANY leg are one signer. Every `rot_zuerst` case
failed at 53d1eafe, and so does the shared-leg case of the mixed old root; the `kontrolle` cases and the independent
mixed old root keep their verdict there and after the fix. The `regression` case guards a pin that held at 53d1eafe:
a key id listed twice in the root role is one key (Codex round 1 on this fix found the first fix refused it).
"""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone
from unittest import mock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import dsse
from proofbundle import trust_pack as tp
from proofbundle.pqsig import generate_mldsa

_NOW = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)
_P, _P2 = generate_mldsa(), generate_mldsa()
_E1, _E2, _E3 = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _ed(e) -> dict:
    return {"publicKey": _b64(e.public_key().public_bytes_raw())}


def _ml(p) -> dict:
    return {"alg": "mldsa65", "publicKey": _b64(p.public_key().public_bytes_raw())}


def _hy(e, p) -> dict:
    return {"alg": "hybrid-ed25519-mldsa65", "publicKey": _b64(e.public_key().public_bytes_raw()),
            "publicKeyPq": _b64(p.public_key().public_bytes_raw())}


def _pack(keys: dict, root: list, threshold: int, *, version: int = 1, prev=None) -> dict:
    return {"schemaVersion": "0.1.0", "trustPackId": "kr01", "version": version, "expires": "2030-01-01T00:00:00Z",
            "prevVersionDigest": prev, "roles": {"root": {"keyIds": root, "threshold": threshold}}, "keys": keys,
            "nonClaims": ["names which keys hold which role, not that the holders are honest"]}


def _envelope(predicate: dict, signers: list) -> dict:
    """Signed outside `sign_trust_pack`, which refuses a hybrid signer; each signer is (keyid, ed_sk or None, ml_sk or
    None): an Ed25519 key alone, an ML-DSA key alone, or both for a hybrid (`sig` and `sigPq`). The Statement is
    written by hand, as whoever builds such a pack writes it: `build_trust_pack_statement` validates, and since KR-01
    it refuses a pack whose keys share a leg."""
    sha = hashlib.sha256(tp._rfc8785_bytes(predicate)).hexdigest()
    statement = {"_type": tp.STATEMENT_TYPE, "subject": [{"name": "trust-pack:kr01:v1", "digest": {"sha256": sha}}],
                 "predicateType": tp.TRUST_PACK_PREDICATE_TYPE, "predicate": predicate}
    body = tp._rfc8785_bytes(statement)
    msg = dsse.pae(tp.INTOTO_STATEMENT_PAYLOAD_TYPE, body)
    sigs = []
    for kid, ed, ml in signers:
        e = {"keyid": kid}
        if ed is not None and ml is not None:
            e["sig"], e["sigPq"] = _b64(ed.sign(msg)), _b64(ml.sign(msg))
        else:
            e["sig"] = _b64((ed or ml).sign(msg))
        sigs.append(e)
    return {"payload": _b64(body), "payloadType": tp.INTOTO_STATEMENT_PAYLOAD_TYPE, "signatures": sigs}


# A: P as an `mldsa65` root key and as the PQ leg of a hybrid root key. B: P as the PQ leg of two hybrids.
_A_KEYS = {"k_pq": _ml(_P), "k_hy": _hy(_E1, _P), "k_x": _ed(_E3)}
_A_SIGN = [("k_pq", None, _P), ("k_hy", _E1, _P)]
_B_KEYS = {"h1": _hy(_E1, _P), "h2": _hy(_E2, _P), "k_x": _ed(_E3)}
_B_SIGN = [("h1", _E1, _P), ("h2", _E2, _P)]


def _aliasfehler(errors: list) -> bool:
    return any("duplicates the key material" in e for e in errors)


def test_rot_zuerst_a_validator_refuses_an_mldsa65_key_that_is_a_hybrids_pq_leg():
    assert _aliasfehler(tp.validate_trust_pack_predicate(_pack(_A_KEYS, list(_A_KEYS), 2)))


def test_rot_zuerst_b_validator_refuses_two_hybrids_with_one_pq_leg():
    assert _aliasfehler(tp.validate_trust_pack_predicate(_pack(_B_KEYS, list(_B_KEYS), 2)))


_FAELLE_AB = pytest.mark.parametrize("keys,sign", [(_A_KEYS, _A_SIGN), (_B_KEYS, _B_SIGN)], ids=["A", "B"])


@_FAELLE_AB
def test_rot_zuerst_a_and_b_do_not_verify_with_one_ml_dsa_secret(keys, sign):
    r = tp.verify_trust_pack(_envelope(_pack(keys, list(keys), 2), sign), now=_NOW)
    assert r["ok"] is False and _aliasfehler(r["errors"]), r["errors"]


@_FAELLE_AB
def test_rot_zuerst_the_count_alone_holds_without_the_validator(keys, sign):
    """Defense in depth: with the validator answering [] the threshold count itself counts one leg once."""
    with mock.patch.object(tp, "validate_trust_pack_predicate", return_value=[]):
        r = tp.verify_trust_pack(_envelope(_pack(keys, list(keys), 2), sign), now=_NOW)
        assert r["root_threshold_met"] is False and len(r["root_signers"]) == 1, r["root_signers"]


def test_rot_zuerst_the_root_key_pin_refuses_identities_with_one_pq_leg():
    pred = _pack({"h1": _hy(_E1, _P), "h2": _hy(_E2, _P)}, ["h1", "h2"], 2)
    assert tp.trust_pack_is_pinned(pred, expected_root_keys={"h1": _hy(_E1, _P), "h2": _hy(_E2, _P)}) is False


def _rotation(old_keys: dict, old_signers: list) -> dict:
    neu = _pack({"n1": _ed(_E3)}, ["n1"], 1, version=2, prev={"sha256": hashlib.sha256(b"v1").hexdigest()})
    return tp.verify_trust_pack(_envelope(neu, [("n1", _E3, None)] + old_signers), now=_NOW,
                                prev_root_keys=old_keys, prev_root_threshold=2)


def test_rot_zuerst_an_old_root_with_one_pq_leg_does_not_vouch_twice():
    r = _rotation({"h1": _hy(_E1, _P), "h2": _hy(_E2, _P)}, [("h1", _E1, _P), ("h2", _E2, _P)])
    assert r["rotation_authorized"] is False and len(r["old_root_signers"]) == 1 and r["ok"] is False, r


def test_kontrolle_c_the_same_mldsa65_key_twice_stays_refused():
    keys = {"a": _ml(_P), "b": _ml(_P), "k_x": _ed(_E3)}
    assert _aliasfehler(tp.validate_trust_pack_predicate(_pack(keys, list(keys), 2)))


def test_kontrolle_d_independent_keys_still_meet_the_threshold():
    keys = {"a": _ml(_P), "b": _hy(_E1, _P2), "k_x": _ed(_E3)}
    r = tp.verify_trust_pack(_envelope(_pack(keys, list(keys), 2), [("a", None, _P), ("b", _E1, _P2)]), now=_NOW)
    assert r["ok"] is True and r["root_signers"] == ["a", "b"], r["errors"]


def test_kontrolle_independent_hybrids_still_pin_and_vouch():
    pred = _pack({"h1": _hy(_E1, _P), "h2": _hy(_E2, _P2)}, ["h1", "h2"], 2)
    assert tp.trust_pack_is_pinned(pred, expected_root_keys={"h1": _hy(_E1, _P), "h2": _hy(_E2, _P2)}) is True
    r = _rotation({"h1": _hy(_E1, _P), "h2": _hy(_E2, _P2)}, [("h1", _E1, _P), ("h2", _E2, _P2)])
    assert r["rotation_authorized"] is True and r["old_root_signers"] == ["h1", "h2"], r


@pytest.mark.parametrize("keys", [_A_KEYS, _B_KEYS], ids=["A", "B"])
def test_rot_zuerst_the_producer_refuses_a_pack_whose_keys_share_a_leg(keys):
    """The producer side of the same class: `build_trust_pack_statement` and `sign_trust_pack` validate first."""
    with pytest.raises(tp.TrustPackError, match="duplicates the key material"):
        tp.build_trust_pack_statement(_pack(keys, list(keys), 2))


# Codex round 1 on the fix (15.11.2026), finding 1: a key id listed twice in the root role is ONE key. It must not read
# as two keys that share their legs, so a pin that held before the fix holds after it.
@pytest.mark.parametrize("root,threshold", [(["a", "a"], 1), (["a", "b", "a"], 2)], ids=["a-a", "a-b-a"])
def test_regression_a_key_id_listed_twice_keeps_a_valid_pin(root, threshold):
    keys = {"a": _ed(_E1), "b": _ed(_E2)}
    pred = _pack({k: keys[k] for k in dict.fromkeys(root)}, root, threshold)
    assert tp.validate_trust_pack_predicate(pred) == []
    assert tp.trust_pack_is_pinned(pred, expected_root_keys={k: keys[k] for k in dict.fromkeys(root)}) is True


def test_kontrolle_a_key_id_listed_twice_does_not_meet_a_threshold_of_two_alone():
    """The repeated id stays one signer in the count: a threshold of two is not met by the one key."""
    r = tp.verify_trust_pack(_envelope(_pack({"a": _ed(_E1)}, ["a", "a"], 2), [("a", _E1, None)]), now=_NOW)
    assert r["root_threshold_met"] is False and r["ok"] is False, r


# Finding 2: the rest of the class. A shared CLASSICAL leg was refused before the fix and stays refused; a revoked key
# that shares a leg is refused too (the invariant holds over every key of the pack); independent revoked keys and an
# old root of mixed algorithms keep their verdicts.
@pytest.mark.parametrize("keys", [
    {"e": _ed(_E1), "h": _hy(_E1, _P), "x": _ed(_E3)},
    {"h1": _hy(_E1, _P), "h2": _hy(_E1, _P2), "x": _ed(_E3)},
], ids=["ed25519-und-hybrid", "zwei-hybride"])
def test_kontrolle_a_shared_classical_leg_is_refused(keys):
    assert _aliasfehler(tp.validate_trust_pack_predicate(_pack(keys, list(keys), 2)))


def test_rot_zuerst_a_revoked_key_that_shares_a_pq_leg_is_refused():
    pred = _pack({"k_pq": _ml(_P), "k_hy": _hy(_E1, _P), "x": _ed(_E3), "y": _ed(_E2)}, ["k_hy", "x", "y"], 2)
    pred["revoked"] = ["k_pq"]
    assert _aliasfehler(tp.validate_trust_pack_predicate(pred))


def test_kontrolle_independent_keys_with_one_revoked_still_verify():
    pred = _pack({"a": _ml(_P), "b": _hy(_E1, _P2), "c": _ed(_E3)}, ["a", "b", "c"], 2)
    pred["revoked"] = ["c"]
    r = tp.verify_trust_pack(_envelope(pred, [("a", None, _P), ("b", _E1, _P2)]), now=_NOW)
    assert r["ok"] is True and r["root_signers"] == ["a", "b"], r["errors"]


@pytest.mark.parametrize("alt,erwartet", [
    ({"m": _ml(_P), "h": _hy(_E1, _P)}, False),
    ({"m": _ml(_P), "h": _hy(_E1, _P2)}, True),
], ids=["gemischt-geteilt", "gemischt-unabhaengig"])
def test_an_old_root_of_mixed_algorithms_vouches_once_per_key(alt, erwartet):
    zeichner = [("m", None, _P), ("h", _E1, _P if not erwartet else _P2)]
    r = _rotation(alt, zeichner)
    assert r["rotation_authorized"] is erwartet and len(r["old_root_signers"]) == (2 if erwartet else 1), r


# Codex round 2 on the fix (15.11.2026), P3: spellings and unreadable legs. `decode_b64` accepts exactly one spelling of
# a key (standard alphabet, padded, zero pad bits, no whitespace). Any other spelling of the same ML-DSA key is an
# unreadable leg: it gives no vote at the validator, the isolated root count, the old root and the pin, so it cannot
# become a second signer next to the canonical spelling. An `alg` label in other letter case is no algorithm.
def _schreibweisen(b64: str) -> dict:
    kanon = b64
    varianten = {
        "ohne-padding": kanon.rstrip("="),
        "url-alphabet": kanon.replace("+", "-").replace("/", "_"),
        "leerzeichen-ende": kanon + "\n",
        "leerzeichen-mitte": kanon[:40] + " " + kanon[40:],
        "zeichenmuell": "!!" + kanon[2:],
    }
    assert all(v != kanon for v in varianten.values())
    return varianten


_P_B64 = _b64(_P.public_key().public_bytes_raw())
_VARIANTEN = pytest.mark.parametrize("schreibweise", list(_schreibweisen(_P_B64)))


def _hy_mit(e, pq_b64: str) -> dict:
    return {"alg": "hybrid-ed25519-mldsa65", "publicKey": _b64(e.public_key().public_bytes_raw()), "publicKeyPq": pq_b64}


@_VARIANTEN
def test_kontrolle_another_spelling_of_a_pq_leg_is_refused_by_the_validator(schreibweise):
    keys = {"k_pq": _ml(_P), "k_hy": _hy_mit(_E1, _schreibweisen(_P_B64)[schreibweise]), "x": _ed(_E3)}
    assert tp.validate_trust_pack_predicate(_pack(keys, list(keys), 2)) != []


@_VARIANTEN
def test_kontrolle_another_spelling_gives_no_second_vote_in_the_isolated_count(schreibweise):
    keys = {"k_pq": _ml(_P), "k_hy": _hy_mit(_E1, _schreibweisen(_P_B64)[schreibweise]), "x": _ed(_E3)}
    with mock.patch.object(tp, "validate_trust_pack_predicate", return_value=[]):
        r = tp.verify_trust_pack(_envelope(_pack(keys, list(keys), 2), _A_SIGN), now=_NOW)
    assert r["root_threshold_met"] is False and len(r["root_signers"]) <= 1, r["root_signers"]


@_VARIANTEN
def test_kontrolle_another_spelling_does_not_vouch_twice_as_an_old_root(schreibweise):
    alt = {"m": _ml(_P), "h": _hy_mit(_E1, _schreibweisen(_P_B64)[schreibweise])}
    r = _rotation(alt, [("m", None, _P), ("h", _E1, _P)])
    assert r["rotation_authorized"] is False and len(r["old_root_signers"]) <= 1, r


@_VARIANTEN
def test_kontrolle_another_spelling_is_no_pinned_root(schreibweise):
    zweiter = _hy_mit(_E2, _schreibweisen(_P_B64)[schreibweise])
    pred = _pack({"h1": _hy(_E1, _P), "h2": zweiter}, ["h1", "h2"], 2)
    assert tp.trust_pack_is_pinned(pred, expected_root_keys={"h1": _hy(_E1, _P), "h2": zweiter}) is False


def test_kontrolle_an_alg_label_in_other_letter_case_is_no_algorithm():
    keys = {"a": {"alg": "MLDSA65", "publicKey": _P_B64}, "b": _ml(_P2), "x": _ed(_E3)}
    assert tp.validate_trust_pack_predicate(_pack(keys, list(keys), 2)) != []
    with mock.patch.object(tp, "validate_trust_pack_predicate", return_value=[]):
        r = tp.verify_trust_pack(_envelope(_pack(keys, list(keys), 2), [("a", None, _P), ("b", None, _P2)]), now=_NOW)
    assert r["root_threshold_met"] is False and r["root_signers"] == ["b"], r["root_signers"]
