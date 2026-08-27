"""makellose-500 Spur-2 Linse C (fix-the-CLASS): the renewal never-raise surfaces must return a VERDICT,
never a raw crash, when a form-valid input carries ONE malformed FIELD — a giant int (CVE-2020-10735
int->str cap), a non-iterable container, or a non-str where a str is expected. An earlier round fixed only
the ONE expression a fuzzer happened to hit first; the deep gate then found neighbours on the SAME lines.

This is the GENERATOR, not a point fixture: it sweeps every ATS field and the `now` parameter across all
three shapes, so a regression that drops a guard anywhere in the class turns THIS red. The signed-bytes
surfaces (token()/_ats_content) are the mirror image — they must REFUSE the magnitude with a TYPED error
(a shortened render would change the signed bytes), which the never-raise surfaces then catch fail-closed.
"""
import itertools

import pytest

from proofbundle.errors import ProofBundleError
from proofbundle.renewal import (ArchiveTimeStamp, RenewalPolicy, build_initial_sequence,
                                 evaluate_renewal_policy, verify_sequence, _verify_ats_signature)

GIANT = 1 << 20000            # bit_length 20001, far over the 4300-digit int->str cap
NON_ITER = 12345              # a container that cannot be iterated
NON_STR = 999                 # an int where a str field is expected
MALFORMED = {"giant_int": GIANT, "non_iterable": NON_ITER, "non_str": NON_STR}
DATA = ["ab" * 32]


def _ats(**over):
    d = dict(hash_alg="sha256", covered_digest="ab" * 32, time=100, anchor_status="confirmed",
             sig_alg="", signatures=())
    d.update(over)
    return ArchiveTimeStamp(**d)


# fields folded into signed bytes / diagnostics — each must not crash a never-raise surface
_FIELDS = ["hash_alg", "covered_digest", "time", "sig_alg", "signatures",
           "external_token_type"]


@pytest.mark.parametrize("field,shape", list(itertools.product(_FIELDS, MALFORMED)))
def test_verify_sequence_returns_verdict_on_malformed_field(field, shape):
    bad = _ats(**{field: MALFORMED[shape], "sig_alg": "ed25519"} if field == "signatures"
               else {field: MALFORMED[shape]})
    if field == "external_token_type":
        bad = _ats(external_token_type=MALFORMED[shape], external_token=b"x")
    r = verify_sequence([[bad]], DATA)            # must NOT raise
    assert not r.ok                               # a malformed field can never verify
    # exercise the require_pq / require_current_hash branches too (they render fields)
    verify_sequence([[bad]], DATA, require_pq=True)
    verify_sequence([[bad]], DATA, require_current_hash=True)


@pytest.mark.parametrize("shape", list(MALFORMED))
def test_verify_ats_signature_returns_false_on_malformed_field(shape):
    for field in ("hash_alg", "covered_digest", "time"):
        assert _verify_ats_signature(_ats(sig_alg="ed25519", **{field: MALFORMED[shape]}),
                                     {"ed25519": b"x" * 32}) is False


@pytest.mark.parametrize("nowval", [
    pytest.param(None, id="none"), pytest.param("nan", id="str"), pytest.param([1], id="list"),
    pytest.param({}, id="dict"), pytest.param(GIANT, id="giant_int"),
])
def test_evaluate_policy_returns_verdict_on_malformed_now(nowval):
    r = evaluate_renewal_policy([[_ats()]], policy=RenewalPolicy(max_ats_age=10), now=nowval)
    assert isinstance(r.ok, bool)                 # verdict, never a raw TypeError


@pytest.mark.parametrize("shape", list(MALFORMED))
def test_evaluate_policy_returns_verdict_on_malformed_hash_alg(shape):
    r = evaluate_renewal_policy([[_ats(hash_alg=MALFORMED[shape])]], policy=RenewalPolicy(), now=200)
    assert isinstance(r.ok, bool)


@pytest.mark.parametrize("field,shape", list(itertools.product(["hash_alg", "covered_digest", "time", "sig_alg"], MALFORMED)))
def test_token_refuses_malformed_field_typed(field, shape):
    # token() builds the covered material — a shortened render would change signed bytes, so it REFUSES
    # with a TYPED ProofBundleError (never a raw ValueError/TypeError). Only giant-int / non-iterable
    # are refusable magnitudes; a non-str hash label renders fine, so restrict the assertion accordingly.
    val = MALFORMED[shape]
    over = {"sig_alg": "ed25519"}   # signed form so every field is rendered into the covered token
    over[field] = val               # the malformed field overrides (incl. sig_alg itself)
    ats = _ats(**over)
    if isinstance(val, int) and not isinstance(val, bool) and val == GIANT:
        with pytest.raises(ProofBundleError):
            ats.token()
    else:
        try:
            ats.token()                            # a non-giant malformed field may render; must not RAW-crash
        except ProofBundleError:
            pass                                   # typed refusal is also acceptable


def test_positive_control_valid_sequence_unchanged():
    seq = build_initial_sequence(DATA, hash_alg="sha256", time=100)
    assert verify_sequence(seq, DATA, allow_unauthenticated_anchor=True).ok is True
    assert evaluate_renewal_policy(seq, policy=RenewalPolicy(), now=200).ok is True
    assert isinstance(seq[0][0].token(), str)


# --- Deep-Gate Produkt-Linse Runde 2: the class was still instance-level. These sweep the members the
#     re-gate found — container-nested giant int, the sibling operand max_ats_age, data_digests, the
#     policy constructor — plus the STRUCTURAL net that enforces never-raise for anything unanticipated.

CONTAINER_GIANT = [1 << 100000]   # a giant int NESTED in a container (escapes a scalar-only guard)


@pytest.mark.parametrize("field", ["hash_alg", "covered_digest", "time", "sig_alg", "signatures", "external_token_type"])
def test_verify_sequence_container_nested_giant_int(field):
    bad = _ats(**({field: CONTAINER_GIANT, "sig_alg": "ed25519"} if field == "signatures"
                  else {field: CONTAINER_GIANT}))
    if field == "external_token_type":
        bad = _ats(external_token_type=CONTAINER_GIANT, external_token=b"x")
    assert not verify_sequence([[bad]], DATA).ok
    # the standalone never-raise bool surface must also survive it
    from proofbundle.renewal import _verify_ats_signature
    assert _verify_ats_signature(_ats(sig_alg=CONTAINER_GIANT), {"ed25519": b"\0" * 32}) is False


@pytest.mark.parametrize("bad", [
    pytest.param("99", id="str"), pytest.param([1], id="list"), pytest.param({}, id="dict"),
    pytest.param(b"x", id="bytes"), pytest.param(1 << 20000, id="giant_int_ok"),
])
def test_evaluate_policy_malformed_max_ats_age(bad):
    # DEFECT 1: max_ats_age is the sibling operand of the guarded `now`
    r = evaluate_renewal_policy([[_ats()]], policy=RenewalPolicy(max_ats_age=bad), now=5000)
    assert isinstance(r.ok, bool)


@pytest.mark.parametrize("dd", [pytest.param(123, id="int"), pytest.param(None, id="none"),
                                pytest.param("abc", id="str")])
def test_verify_sequence_malformed_data_digests(dd):
    r = verify_sequence([[_ats()]], dd)
    assert isinstance(r.ok, bool)


def test_evaluate_policy_malformed_deprecated_algs_direct():
    r = evaluate_renewal_policy([[_ats()]], policy=RenewalPolicy(deprecated_algs=123), now=2000)
    assert isinstance(r.ok, bool)


def test_from_dict_untrusted_policy_json_never_raw_crashes():
    from proofbundle.renewal import RenewalError
    # strictness giant int -> typed; max_ats_age non-int -> typed; unhashable deprecated_algs -> filtered
    with pytest.raises(RenewalError):
        RenewalPolicy.from_dict({"strictness": 1 << 20000})
    with pytest.raises(RenewalError):
        RenewalPolicy.from_dict({"max_ats_age": "99"})
    pol = RenewalPolicy.from_dict({"deprecated_algs": [[], "sha1", {}]})   # junk filtered, str kept
    assert pol.deprecated_algs == frozenset({"sha1"})


def test_structural_net_enforces_never_raise_for_unanticipated_fields(monkeypatch):
    # the decorator net is the fix-the-CLASS backstop: it must convert a FUTURE, unanticipated inner crash
    # (one no explicit guard names) into a fail-closed verdict. Simulate the gap by making an inner helper
    # raise, and confirm both surfaces return a VerificationResult (never propagate). A plant-and-catch on
    # the decorator itself (remove it) makes THIS test red -> the net is proven, not decorative.
    import proofbundle.renewal as R

    def _boom(*a, **k):
        raise RuntimeError("simulated future gap")

    monkeypatch.setattr(R, "_all_ats", _boom)
    r1 = R.verify_sequence([[_ats()]], DATA)
    assert r1.ok is False, "the net must yield a fail-closed verdict, not propagate"
    monkeypatch.setattr(R, "_newest", _boom)
    r2 = R.evaluate_renewal_policy([[_ats()]], policy=RenewalPolicy(), now=2000)
    assert r2.ok is False
