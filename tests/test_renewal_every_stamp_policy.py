"""Every ArchiveTimeStamp signature counts: ``verify_sequence(..., stamp_policy=...)``.

Before this change ``verify_sequence`` authenticated only the NEWEST ArchiveTimeStamp. An older stamp whose
signature was invalid, a stamp key used after its validity window, and a hash algorithm relied on after its
horizon all verified, as long as the newest stamp was signed and every covering digest recomputed. The
shared RFC 4998 section 5.3 vector shows it: its cases 2, 4 and 5 must be WITHHELD and verified.

The stamp policy is an input of the VERIFIER, never part of the sequence. It names:

* the trusted stamp keys, each with a validity window ``not_before`` .. ``not_after``;
* one horizon per hash algorithm (an algorithm is relied on only strictly before its horizon);
* the verification time V.

Rules (the reference reading of the shared vector):

* the reference time of a stamp is the signed time of the NEXT stamp; the newest stamp is judged at V;
* every stamp verifies under a policy key whose window holds both its own signed time and its reference time;
* the hash algorithm of a stamp is before its horizon at the reference time;
* a hash-tree renewal happens before the horizon of every hash algorithm of the chain it renews.

The ten cases are built here, in the test, from published seeds and fixed times, never stored as files.
Cases 1 to 5 are exactly the reference tool's half (seeds, times, policy, expected verdicts); cases 6 to 10 are
five further cases of the same classes with parameters of their own.
"""
from __future__ import annotations

import base64
import dataclasses
import hashlib
from datetime import datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import renewal as rn
from proofbundle.hashalg import compute_digest


def _t(text: str) -> int:
    return int(datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp())


def _pub(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


# The six stamper seeds, written out. Each is the SHA-256 of its published sentence (the seed sentences of OURS and
# OTHER below, with T1, T2 or T3), so the keys are the reference tool's and never a secret. The shipped-sdist guard
# (tests/test_sdist_ohne_signierwerkzeug.py) admits a private key only from a seed written out in the source, so the
# seeds stand here as literals, and test_the_written_out_seeds_are_the_published_sentences holds each to its sentence.
_SEED_OURS_T1 = b"\x09\xc9\xaa\x48\xc5\x49\xaa\x01\x82\x16\x21\xbf\x83\xd2\x37\xff\x5b\xd8\xe3\xf4\xfe\x13\x29\xfd\x1a\x12\x01\xd5\xb7\x93\x24\xf7"
_SEED_OURS_T2 = b"\x2d\xfd\x73\x54\xc7\xf0\xeb\xcb\x59\x63\x28\xae\xba\x0b\x95\xc8\xac\xe5\xde\x14\x84\x0a\xbb\xa1\x1b\x77\xa5\xf6\xfd\xae\xa9\xdb"
_SEED_OURS_T3 = b"\xb8\x43\x7f\x1c\xa8\x8a\xf1\x2d\x1c\x63\x42\xf7\x16\x0e\x7a\xf4\x2e\xa4\x97\xa8\x41\xb6\x99\x0a\xc7\x46\xb4\x5e\xc7\x9f\x7f\xfc"
_SEED_OTHER_T1 = b"\x90\x48\xe2\x20\xff\x55\x0b\xe3\xcf\xb6\x36\xca\xa3\x91\xc0\xd8\x95\x33\xa4\x7f\x64\xb2\x8e\x49\xe7\x3b\xed\xe0\xfa\x32\x09\x97"
_SEED_OTHER_T2 = b"\x48\x03\xd9\xec\x21\xff\x47\x62\x7d\x02\x41\x41\xf5\xa8\x2e\x3f\x37\x65\x88\x83\x8f\x41\x84\xc1\xf0\xda\xc9\x72\x6d\xca\x54\xf4"
_SEED_OTHER_T3 = b"\x91\xa5\xcd\x54\x71\x87\xbd\x6d\x0e\x20\x93\x69\x49\x9c\x86\x75\xc2\x77\xe9\xe9\x63\xcb\x72\x78\x8c\x02\xd2\x86\x41\x50\x29\xe2"
_OURS_SENTENCE = "proofbundle shared RFC 4998 5.3 vector, stamper key %s"
_OTHER_SENTENCE = "proofbundle 6.7.0 second half of the 5.3 vector, stamper key %s"
_SEEDS = {_OURS_SENTENCE % "T1": _SEED_OURS_T1, _OURS_SENTENCE % "T2": _SEED_OURS_T2, _OURS_SENTENCE % "T3": _SEED_OURS_T3,
          _OTHER_SENTENCE % "T1": _SEED_OTHER_T1, _OTHER_SENTENCE % "T2": _SEED_OTHER_T2,
          _OTHER_SENTENCE % "T3": _SEED_OTHER_T3}
_KEYS = {_OURS_SENTENCE % "T1": Ed25519PrivateKey.from_private_bytes(_SEED_OURS_T1),
         _OURS_SENTENCE % "T2": Ed25519PrivateKey.from_private_bytes(_SEED_OURS_T2),
         _OURS_SENTENCE % "T3": Ed25519PrivateKey.from_private_bytes(_SEED_OURS_T3),
         _OTHER_SENTENCE % "T1": Ed25519PrivateKey.from_private_bytes(_SEED_OTHER_T1),
         _OTHER_SENTENCE % "T2": Ed25519PrivateKey.from_private_bytes(_SEED_OTHER_T2),
         _OTHER_SENTENCE % "T3": Ed25519PrivateKey.from_private_bytes(_SEED_OTHER_T3)}


def _key_from_seed(text: str) -> Ed25519PrivateKey:
    # the SHA-256 of the published sentence IS the private test key (published seed, never a secret); written out above
    return _KEYS[text]


def _tamper_first_signature(ats: rn.ArchiveTimeStamp) -> rn.ArchiveTimeStamp:
    alg, sig = ats.signatures[0]
    raw = bytearray(base64.b64decode(sig))
    raw[0] ^= 0x01
    return dataclasses.replace(ats, signatures=((alg, base64.b64encode(bytes(raw)).decode()),))


@dataclasses.dataclass(frozen=True)
class Vector:
    """One half of a vector: three stamp keys from published seeds, three stamp times and V."""

    seed_sentence: str
    times: tuple       # (T1, T2, T3)
    v: int
    content: bytes
    first_hash: str
    renewed_hash: str
    not_before: int

    @property
    def keys(self) -> dict:
        return {r: _key_from_seed(self.seed_sentence % r) for r in ("T1", "T2", "T3")}

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.content).hexdigest()

    def build(self, tamper_role: "str | None" = None) -> list:
        """T1 and T2 under first_hash, then a hash-tree renewal to renewed_hash with T3. Each stamp has its own key.
        A tampered stamp keeps its broken signature, and every later stamp is built over the token so produced."""
        k, (t1, t2, t3), d = self.keys, self.times, [self.digest]
        seq = rn.build_initial_sequence(d, hash_alg=self.first_hash, time=t1, sig_alg="ed25519",
                                        signers={"ed25519": k["T1"]})
        if tamper_role == "T1":
            seq = [[_tamper_first_signature(seq[0][0])]]
        seq = rn.renew_timestamp(seq, time=t2, sig_alg="ed25519", signers={"ed25519": k["T2"]})
        if tamper_role == "T2":
            seq = [[seq[0][0], _tamper_first_signature(seq[0][1])]]
        seq = rn.renew_hashtree(seq, d, new_hash_alg=self.renewed_hash, time=t3, sig_alg="ed25519",
                                signers={"ed25519": k["T3"]})
        return seq

    def policy(self, windows: dict, horizons: dict) -> "rn.StampPolicy":
        keys = tuple(rn.StampKey(key_id=r, public_keys={"ed25519": _pub(self.keys[r])},
                                 not_before=self.not_before, not_after=_t(windows[r]))
                     for r in ("T1", "T2", "T3"))
        return rn.StampPolicy(keys=keys, hash_horizons={a: _t(h) for a, h in horizons.items()},
                              verification_time=self.v)


# --- our half: exactly the reference tool's parameters -------------------------------------------------------
OURS = Vector(seed_sentence=_OURS_SENTENCE,
              times=(_t("2026-01-01T00:00:00Z"), _t("2027-01-01T00:00:00Z"), _t("2028-01-01T00:00:00Z")),
              v=_t("2029-01-01T00:00:00Z"), content=b"shared RFC 4998 5.3 vector, proofbundle side",
              first_hash="sha256", renewed_hash="sha3-512", not_before=_t("2025-01-01T00:00:00Z"))
_LONG = "2029-06-01T00:00:00Z"
_HORIZONS = {"sha256": "2035-01-01T00:00:00Z", "sha3-512": "2050-01-01T00:00:00Z"}
OUR_POLICY = {
    1: ({"T1": _LONG, "T2": _LONG, "T3": _LONG}, _HORIZONS),
    2: ({"T1": "2026-06-01T00:00:00Z", "T2": _LONG, "T3": _LONG}, _HORIZONS),
    3: ({"T1": "2027-06-01T00:00:00Z", "T2": _LONG, "T3": _LONG}, _HORIZONS),
    4: ({"T1": _LONG, "T2": _LONG, "T3": _LONG}, {"sha256": "2027-06-01T00:00:00Z", "sha3-512": "2050-01-01T00:00:00Z"}),
    5: ({"T1": _LONG, "T2": _LONG, "T3": _LONG}, _HORIZONS),
}
OUR_TAMPER = {5: "T1"}

# --- five further cases of the same classes, parameters of our own -------------------------------------------
OTHER = Vector(seed_sentence=_OTHER_SENTENCE,
               times=(_t("2030-03-01T00:00:00Z"), _t("2031-03-01T00:00:00Z"), _t("2032-03-01T00:00:00Z")),
               v=_t("2033-03-01T00:00:00Z"), content=b"second half of the 5.3 vector, built in the test",
               first_hash="sha512", renewed_hash="sha3-256", not_before=_t("2030-01-01T00:00:00Z"))
_OLONG = "2033-09-01T00:00:00Z"
_OHORIZONS = {"sha512": "2040-01-01T00:00:00Z", "sha3-256": "2060-01-01T00:00:00Z"}
OTHER_POLICY = {
    # a valid case
    6: ({"T1": _OLONG, "T2": _OLONG, "T3": _OLONG}, _OHORIZONS),
    # the key of T2 is outside its window at its reference time (T3, 2032-03-01)
    7: ({"T1": _OLONG, "T2": "2031-09-01T00:00:00Z", "T3": _OLONG}, _OHORIZONS),
    # valid: the window of T2 reaches exactly its reference time (inclusive bound)
    8: ({"T1": _OLONG, "T2": "2032-03-01T00:00:00Z", "T3": _OLONG}, _OHORIZONS),
    # the hash-tree renewal (T3, 2032-03-01) comes after the horizon of sha512 (2031-12-01)
    9: ({"T1": _OLONG, "T2": _OLONG, "T3": _OLONG}, {"sha512": "2031-12-01T00:00:00Z", "sha3-256": "2060-01-01T00:00:00Z"}),
    # an invalid older signature: T2 (the middle stamp), with T3 built over the broken token
    10: ({"T1": _OLONG, "T2": _OLONG, "T3": _OLONG}, _OHORIZONS),
}
OTHER_TAMPER = {10: "T2"}

EXPECTED = {1: "VERIFIED", 2: "WITHHELD", 3: "VERIFIED", 4: "WITHHELD", 5: "WITHHELD",
            6: "VERIFIED", 7: "WITHHELD", 8: "VERIFIED", 9: "WITHHELD", 10: "WITHHELD"}
# the check that must fail for each WITHHELD case (the reason, not merely ok False)
EXPECTED_FAILING = {2: {"renewal:stamp:c0a0:window"},
                    4: {"renewal:stamp:c0a1:horizon", "renewal:renewal_before_horizon:c1"},
                    5: {"renewal:stamp:c0a0:signature"},
                    7: {"renewal:stamp:c0a1:window"},
                    9: {"renewal:stamp:c0a1:horizon", "renewal:renewal_before_horizon:c1"},
                    10: {"renewal:stamp:c0a1:signature"}}


def _case_seq(n: int):
    """The vector and the sequence of case n, through the old interface only (builders and ArchiveTimeStamp)."""
    if n <= 5:
        return OURS, OURS.build(OUR_TAMPER.get(n))
    return OTHER, OTHER.build(OTHER_TAMPER.get(n))


def _case(n: int):
    vec, seq = _case_seq(n)
    windows, horizons = (OUR_POLICY if n <= 5 else OTHER_POLICY)[n]
    return vec, seq, vec.policy(windows, horizons)


def test_the_written_out_seeds_are_the_published_sentences() -> None:
    """Each written-out seed is the SHA-256 of its published sentence, and the six sentences are exactly the ones the
    two halves of the vector use, so the literals cannot drift from the reference tool's keys."""
    assert set(_SEEDS) == {v.seed_sentence % r for v in (OURS, OTHER) for r in ("T1", "T2", "T3")}
    for sentence, seed in _SEEDS.items():
        assert seed == hashlib.sha256(sentence.encode()).digest(), sentence
    assert set(_KEYS) == set(_SEEDS)


def _verdict(res) -> str:
    return "VERIFIED" if res.ok is True else "WITHHELD"


def _failing(res) -> set:
    return {c.name for c in res.checks if not c.ok}


@pytest.mark.parametrize("n", range(1, 11))
def test_every_stamp_verdict_matches_the_vector(n: int) -> None:
    vec, seq, policy = _case(n)
    res = rn.verify_sequence(seq, [vec.digest], stamp_policy=policy)
    assert _verdict(res) == EXPECTED[n], [str(c) for c in res.checks]
    if EXPECTED[n] == "WITHHELD":
        # the reason, exactly: the expected stamp check(s) and the aggregate, nothing structural
        assert _failing(res) == EXPECTED_FAILING[n] | {"renewal:every_stamp"}, [str(c) for c in res.checks]
    else:
        assert any(c.name == "renewal:every_stamp" and c.ok is True for c in res.checks)
        assert any(c.name == "renewal:last_anchor" and c.ok is True and "stamp policy" in c.detail
                   for c in res.checks)


@pytest.mark.parametrize("n", range(1, 11))
def test_old_interface_verdict_is_verified_for_every_case(n: int) -> None:
    """The old verdict over the SAME bytes, through the old interface only (the newest stamp's key as
    authority_keys). It is VERIFIED for all ten cases, also for the five that must be WITHHELD: this is the
    gap the stamp policy closes. Unchanged by this change (backward compatibility), so green at base and branch."""
    vec, seq = _case_seq(n)
    res = rn.verify_sequence(seq, [vec.digest], authority_keys={"ed25519": _pub(vec.keys["T3"])})
    assert res.ok is True, [str(c) for c in res.checks]


def test_without_policy_the_result_says_older_stamps_were_not_checked() -> None:
    """Backward compatible: same .ok as before, but a check of its own says what was NOT checked, so an .ok
    without a stamp policy never looks like an .ok with one."""
    vec, seq = _case_seq(5)
    old = rn.verify_sequence(seq, [vec.digest], authority_keys={"ed25519": _pub(vec.keys["T3"])})
    assert old.ok is True
    marker = [c for c in old.checks if c.name == "renewal:older_stamps_unchecked"]
    assert len(marker) == 1 and marker[0].ok is True
    assert "NOT CHECKED" in marker[0].detail
    assert not any(c.name == "renewal:every_stamp" for c in old.checks)
    _vec, _seq, policy = _case(5)
    new = rn.verify_sequence(seq, [vec.digest], stamp_policy=policy)
    assert not any(c.name == "renewal:older_stamps_unchecked" for c in new.checks)


def test_policy_beside_authority_keys_checks_both() -> None:
    vec, seq, policy = _case(5)
    res = rn.verify_sequence(seq, [vec.digest], authority_keys={"ed25519": _pub(vec.keys["T3"])},
                             stamp_policy=policy)
    assert res.ok is False
    assert "renewal:stamp:c0a0:signature" in _failing(res)
    assert any(c.name == "renewal:last_anchor" and c.ok is True for c in res.checks)


def test_a_key_not_in_the_policy_does_not_verify_an_older_stamp() -> None:
    vec, seq, _ = _case(1)
    windows, horizons = OUR_POLICY[1]
    policy = vec.policy(windows, horizons)
    without_t1 = dataclasses.replace(policy, keys=tuple(k for k in policy.keys if k.key_id != "T1"))
    res = rn.verify_sequence(seq, [vec.digest], stamp_policy=without_t1)
    assert res.ok is False
    assert _failing(res) == {"renewal:stamp:c0a0:signature", "renewal:every_stamp"}


def test_a_window_that_starts_after_the_stamp_was_signed_fails() -> None:
    vec, seq, policy = _case(1)
    keys = tuple(dataclasses.replace(k, not_before=vec.times[0] + 1) if k.key_id == "T1" else k for k in policy.keys)
    res = rn.verify_sequence(seq, [vec.digest], stamp_policy=dataclasses.replace(policy, keys=keys))
    assert res.ok is False
    assert _failing(res) == {"renewal:stamp:c0a0:window", "renewal:every_stamp"}


def test_the_newest_stamp_is_judged_at_v() -> None:
    vec, seq, policy = _case(1)
    # the window of T3 ends between T3 and V: at V the newest stamp's key is out of its window
    keys = tuple(dataclasses.replace(k, not_after=vec.v - 1) if k.key_id == "T3" else k for k in policy.keys)
    res = rn.verify_sequence(seq, [vec.digest], stamp_policy=dataclasses.replace(policy, keys=keys))
    assert res.ok is False
    assert _failing(res) == {"renewal:stamp:c1a0:window", "renewal:every_stamp"}
    # the same with the horizon of the newest hash at V
    horizons = dict(policy.hash_horizons, **{"sha3-512": vec.v})
    res = rn.verify_sequence(seq, [vec.digest], stamp_policy=dataclasses.replace(policy, hash_horizons=horizons))
    assert res.ok is False
    assert _failing(res) == {"renewal:stamp:c1a0:horizon", "renewal:every_stamp"}


def test_v_before_the_newest_stamp_fails_closed() -> None:
    vec, seq, policy = _case(1)
    res = rn.verify_sequence(seq, [vec.digest], stamp_policy=dataclasses.replace(policy, verification_time=vec.times[2] - 1))
    assert res.ok is False
    assert "renewal:every_stamp" in _failing(res)
    assert any("verification time" in c.detail for c in res.checks if c.name == "renewal:every_stamp")


def test_a_hash_without_a_horizon_is_never_read_as_no_limit() -> None:
    vec, seq, policy = _case(1)
    horizons = {"sha3-512": policy.hash_horizons["sha3-512"]}          # sha256 has no horizon
    res = rn.verify_sequence(seq, [vec.digest], stamp_policy=dataclasses.replace(policy, hash_horizons=horizons))
    assert res.ok is False
    assert {"renewal:stamp:c0a0:horizon", "renewal:stamp:c0a1:horizon",
            "renewal:renewal_before_horizon:c1"} <= _failing(res)


def test_renewal_before_horizon_of_every_algorithm_of_the_renewed_chain() -> None:
    """A chain that mixes algorithms (hand-built): its last stamp is sha3-256 and within horizon, its first is
    sha256. The hash-tree renewal must come before the horizon of sha256 too; only that rule fires here."""
    vec = OURS
    k, d = vec.keys, [vec.digest]
    t1, t2, t3 = vec.times
    a0 = rn.build_initial_sequence(d, hash_alg="sha256", time=t1, sig_alg="ed25519", signers={"ed25519": k["T1"]})[0][0]
    a1 = rn._make_ats("sha3-256", compute_digest(a0.token().encode(), "sha3-256"), t2, "confirmed", "ed25519",
                      {"ed25519": k["T2"]})
    seq = rn.renew_hashtree([[a0, a1]], d, new_hash_alg="sha3-512", time=t3, sig_alg="ed25519",
                            signers={"ed25519": k["T3"]})
    windows = {"T1": _LONG, "T2": _LONG, "T3": _LONG}
    # sha256 is relied on by a0 only up to t2; its horizon lies between t2 and t3
    horizons = {"sha256": "2027-06-01T00:00:00Z", "sha3-256": "2050-01-01T00:00:00Z", "sha3-512": "2050-01-01T00:00:00Z"}
    res = rn.verify_sequence(seq, d, stamp_policy=vec.policy(windows, horizons))
    assert res.ok is False
    assert _failing(res) == {"renewal:renewal_before_horizon:c1", "renewal:every_stamp"}
    # with a later sha256 horizon the same sequence verifies (the structure itself is sound)
    horizons["sha256"] = "2035-01-01T00:00:00Z"
    assert rn.verify_sequence(seq, d, stamp_policy=vec.policy(windows, horizons)).ok is True


@pytest.mark.parametrize("bad", ["policy-as-dict", "keys-not-tuple", "key-not-stampkey", "not_after-bool",
                                 "not_before-after-not_after", "horizon-str", "v-str", "public_keys-not-dict"])
def test_a_malformed_policy_object_fails_closed(bad: str) -> None:
    vec, seq, policy = _case(1)
    k0 = policy.keys[0]
    if bad == "policy-as-dict":
        p = {"keys": [], "hash_horizons": {}, "verification_time": vec.v}
    elif bad == "keys-not-tuple":
        p = dataclasses.replace(policy, keys=None)
    elif bad == "key-not-stampkey":
        p = dataclasses.replace(policy, keys=(dataclasses.asdict(k0),) + policy.keys[1:])
    elif bad == "not_after-bool":
        p = dataclasses.replace(policy, keys=(dataclasses.replace(k0, not_after=True),) + policy.keys[1:])
    elif bad == "not_before-after-not_after":
        p = dataclasses.replace(policy, keys=(dataclasses.replace(k0, not_before=k0.not_after + 1),) + policy.keys[1:])
    elif bad == "horizon-str":
        p = dataclasses.replace(policy, hash_horizons=dict(policy.hash_horizons, sha256="2035"))
    elif bad == "v-str":
        p = dataclasses.replace(policy, verification_time=str(vec.v))
    else:
        p = dataclasses.replace(policy, keys=(dataclasses.replace(k0, public_keys=None),) + policy.keys[1:])
    res = rn.verify_sequence(seq, [vec.digest], stamp_policy=p)
    assert res.ok is False
    assert "renewal:stamp_policy_malformed" in _failing(res), [str(c) for c in res.checks]


def _policy_dict(vec: Vector, windows: dict, horizons: dict) -> dict:
    return {"keys": [{"key_id": r, "public_keys": {"ed25519": _pub(vec.keys[r]).hex()},
                      "not_before": vec.not_before, "not_after": _t(windows[r])} for r in ("T1", "T2", "T3")],
            "hash_horizons": {a: _t(h) for a, h in horizons.items()},
            "verification_time": vec.v}


@pytest.mark.parametrize("n", [1, 2, 4, 5])
def test_from_dict_gives_the_same_verdict(n: int) -> None:
    vec, seq, _ = _case(n)
    windows, horizons = OUR_POLICY[n]
    policy = rn.StampPolicy.from_dict(_policy_dict(vec, windows, horizons))
    assert _verdict(rn.verify_sequence(seq, [vec.digest], stamp_policy=policy)) == EXPECTED[n]


@pytest.mark.parametrize("mutate", [
    lambda d: d.pop("hash_horizons"),
    lambda d: d.pop("verification_time"),
    lambda d: d.pop("keys"),
    lambda d: d["keys"][0].pop("not_after"),
    lambda d: d["keys"][0].pop("not_before"),
    lambda d: d["keys"][0].pop("public_keys"),
    lambda d: d["keys"][0].pop("key_id"),
    lambda d: d.__setitem__("hash_horizons", None),
    lambda d: d.__setitem__("hash_horizons", []),
    lambda d: d["hash_horizons"].__setitem__("sha256", None),
    lambda d: d["hash_horizons"].__setitem__("sha256", "2035-01-01T00:00:00Z"),
    lambda d: d.__setitem__("verification_time", None),
    lambda d: d.__setitem__("verification_time", True),
    lambda d: d.__setitem__("keys", {}),
    lambda d: d["keys"][0].__setitem__("not_after", None),
    lambda d: d["keys"][0].__setitem__("not_after", 1.5),
    lambda d: d["keys"][0].__setitem__("public_keys", {"ed25519": "zz"}),
    lambda d: d["keys"][0].__setitem__("public_keys", {"rsa": "00"}),
    lambda d: d["keys"][0].__setitem__("public_keys", {}),
    lambda d: d.__setitem__("unknown_field", 1),
    lambda d: d["keys"][0].__setitem__("not_before", d["keys"][0]["not_after"] + 1),
])
def test_from_dict_refuses_a_missing_or_mistyped_field(mutate) -> None:
    """Same rule as RenewalPolicy.from_dict: a field that is missing or of another type is refused, never read
    as no limit."""
    windows, horizons = OUR_POLICY[1]
    d = _policy_dict(OURS, windows, horizons)
    mutate(d)
    with pytest.raises(rn.RenewalError):
        rn.StampPolicy.from_dict(d)


# --- counter-probes: each rule decides its own case -----------------------------------------------------------
def _reference_reading(vec: Vector, seq: list, windows: dict, horizons: dict, *, signatures: bool = True,
                       windows_on: bool = True, horizons_on: bool = True) -> str:
    """An independent reading of the same rules (as the reference tool writes them), with each rule switchable.
    It is the oracle the counter-probes switch off; the product verdict is held to it above."""
    flat = [a for chain in seq for a in chain]
    roles = ["T1", "T2", "T3"]
    h = {a: _t(x) for a, x in horizons.items()}
    bad = False
    for i, a in enumerate(flat):
        ref = flat[i + 1].time if i + 1 < len(flat) else vec.v
        if signatures and not rn._verify_ats_signature(a, {"ed25519": _pub(vec.keys[roles[i]])}):
            bad = True
        if windows_on and ref > _t(windows[roles[i]]):
            bad = True
        if horizons_on and ref >= h.get(a.hash_alg, 0):
            bad = True
    if horizons_on and seq[1][0].time >= h[vec.first_hash]:
        bad = True
    return "WITHHELD" if bad else "VERIFIED"


@pytest.mark.parametrize("off, deviating", [("signatures", {5, 10}), ("windows_on", {2, 7}), ("horizons_on", {4, 9})])
def test_counter_probe_each_rule_decides_its_case(off: str, deviating: set) -> None:
    """A reader without the check of every signature deviates at case 5 (and 10), one without windows at case 2
    (and 7), one without horizons at case 4 (and 9); with all rules on, the reading is the expected verdict.
    The product verifier is held to the full reading (test_every_stamp_verdict_matches_the_vector), and the
    same switches as code mutants are measured on the product itself (mutants, see the delivery report)."""
    for n in range(1, 11):
        vec, seq = _case_seq(n)
        windows, horizons = (OUR_POLICY if n <= 5 else OTHER_POLICY)[n]
        full = _reference_reading(vec, seq, windows, horizons)
        assert full == EXPECTED[n]
        partial = _reference_reading(vec, seq, windows, horizons, **{off: False})
        assert (partial != EXPECTED[n]) == (n in deviating), (off, n, partial)


def test_require_pq_counts_a_pq_leg_verified_under_the_stamp_policy() -> None:
    """In the stamp policy mode the newest stamp's signature IS verified, so require_pq accepts a verified
    ML-DSA leg there; an Ed25519-only newest stamp still fails the PQ floor."""
    pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa")
    from proofbundle.pqsig import generate_mldsa  # noqa: PLC0415
    vec, d = OURS, [OURS.digest]
    m = generate_mldsa("mldsa65")
    m_pub = m.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    t1, t2, _t3 = vec.times
    seq = rn.build_initial_sequence(d, hash_alg="sha256", time=t1, sig_alg="ed25519", signers={"ed25519": vec.keys["T1"]})
    seq_pq = rn.renew_timestamp(seq, time=t2, sig_alg="mldsa65", signers={"mldsa65": m})
    keys = (rn.StampKey(key_id="T1", public_keys={"ed25519": _pub(vec.keys["T1"])}, not_before=vec.not_before, not_after=vec.v),
            rn.StampKey(key_id="PQ", public_keys={"mldsa65": m_pub}, not_before=vec.not_before, not_after=vec.v))
    policy = rn.StampPolicy(keys=keys, hash_horizons={"sha256": _t("2035-01-01T00:00:00Z")}, verification_time=vec.v)
    res = rn.verify_sequence(seq_pq, d, stamp_policy=policy, require_pq=True)
    assert res.ok is True, [str(c) for c in res.checks]
    res = rn.verify_sequence(seq, d, stamp_policy=policy, require_pq=True)
    assert res.ok is False
    assert _failing(res) == {"renewal:pq_floor"}


def test_require_pq_counts_the_policy_check_beside_a_caller_anchor() -> None:
    """Codex review round 1 on PR 560 (P2): beside an anchor_verifier the stamp policy still verifies the newest
    stamp's signature, so require_pq counts a PQ leg verified there, as it does without the callback. An
    Ed25519-only newest stamp still fails the PQ floor, and only that check."""
    pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa")
    from proofbundle.pqsig import generate_mldsa  # noqa: PLC0415
    vec, d = OURS, [OURS.digest]
    m = generate_mldsa("mldsa65")
    m_pub = m.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    t1, t2, _t3 = vec.times
    seq = rn.build_initial_sequence(d, hash_alg="sha256", time=t1, sig_alg="ed25519", signers={"ed25519": vec.keys["T1"]})
    seq_pq = rn.renew_timestamp(seq, time=t2, sig_alg="mldsa65", signers={"mldsa65": m})
    keys = (rn.StampKey(key_id="T1", public_keys={"ed25519": _pub(vec.keys["T1"])}, not_before=vec.not_before, not_after=vec.v),
            rn.StampKey(key_id="PQ", public_keys={"mldsa65": m_pub}, not_before=vec.not_before, not_after=vec.v))
    policy = rn.StampPolicy(keys=keys, hash_horizons={"sha256": _t("2035-01-01T00:00:00Z")}, verification_time=vec.v)
    res = rn.verify_sequence(seq_pq, d, stamp_policy=policy, anchor_verifier=lambda a: True, require_pq=True)
    assert res.ok is True, [str(c) for c in res.checks]
    assert any(c.name == "renewal:last_anchor" and "caller anchor_verifier" in c.detail for c in res.checks)
    res = rn.verify_sequence(seq, d, stamp_policy=policy, anchor_verifier=lambda a: True, require_pq=True)
    assert _failing(res) == {"renewal:pq_floor"}
    assert not any("needs authority_keys or a stamp_policy" in c.detail for c in res.checks)
