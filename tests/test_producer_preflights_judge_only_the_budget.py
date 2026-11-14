"""Deep gate 6.6.0 at c71eeb12, lens L6, finding Z7B: a producer that reads its own output before signing judges only
the budget its verifier reads that output under.

THE PROPERTY (target Z7 of the frozen run description): `dsse.sign_envelope`, `sign_trust_pack`,
`issue_status_list_token` and `issue_enclave_attestation` sign nothing their verifier refuses for its budget, and
refuse nothing their verifier refuses only for another reason. A question of form, such as an integer outside the
I-JSON range, is the verifier's to answer.

WHAT WAS WRONG at c71eeb12: the status list and enclave issuers read both token segments with `loads_strict`, the
whole reader of the verifier, so an `iat` of 2**53, 54 bits and far inside `int_bits`, was refused for the I-JSON
range. `_strict_json.enforce_budget_only` now holds the budget for every such producer, the DSSE primitive included.

THE ORACLE is `loads_strict` itself: for every input below it refuses, and the generator splits the inputs by the
reason it gives. A size reason must be refused by the producer check too, a form reason must not. Without the fix the
two issuer cases are red; the generator over `enforce_budget_only` cannot run there, the function does not exist.
"""
from __future__ import annotations

import base64
import json
import warnings

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle._strict_json import loads_strict
from proofbundle.budget import BudgetExceeded, VerificationBudget
from proofbundle.dsse import sign_envelope
from proofbundle.errors import BundleFormatError, ProofBundleError
from proofbundle.statuslist import issue_status_list_token, verify_status_snapshot

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from proofbundle.experimental.enclave import issue_enclave_attestation, verify_enclave_attestation

_KEY = Ed25519PrivateKey.from_private_bytes(b"\x11" * 32)
_PUB = _KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
_URI = "https://example.test/status"
_BINDING = "B" * 43
_PROFILE = "https://example.test/profile"

#: A budget small enough that each axis is passed by a few bytes; the reasons are the same as under DEFAULT_BUDGET.
_ENG = VerificationBudget(input_bytes=4096, json_nodes=20, json_depth=8, string_len=64, int_bits=64)


def _statusliste(iat: int, uri: str = _URI) -> str:
    return issue_status_list_token([0], uri=uri, signer=_KEY, iat=iat)


def _enklave(iat: int, binding: str = _BINDING) -> str:
    return issue_enclave_attestation(binding, _KEY, profile=_PROFILE, tier="hardware", iat=iat)


@pytest.mark.parametrize("iat", [2**53, 2**53 + 1, 2**60])
def test_the_status_list_issuer_signs_an_iat_outside_the_ijson_range_and_its_verifier_answers(iat):
    """[COUNTS] Red at c71eeb12: the issuer refused these for the I-JSON range. Now it signs, and the verifier gives
    the answer of form: ok False, naming the I-JSON range."""
    token = _statusliste(iat)
    urteil = verify_status_snapshot(token, expected_uri=_URI, index=0, issuer_pubkey=_PUB)
    assert urteil["ok"] is False and "I-JSON range" in urteil["detail"], urteil


@pytest.mark.parametrize("iat", [2**53, 2**53 + 1, 2**60])
def test_the_enclave_issuer_signs_an_iat_outside_the_ijson_range_and_its_verifier_answers(iat):
    """[COUNTS] Red at c71eeb12, as above, for `issue_enclave_attestation`."""
    token = _enklave(iat)
    urteil = verify_enclave_attestation(token, verifier_pubkey=_PUB, expected_binding=_BINDING)
    assert urteil["ok"] is False and "I-JSON range" in urteil["detail"], urteil


def test_CONTROL_both_issuers_sign_an_ordinary_iat_that_verifies():
    """[COUNTS] The control that lets the two cases above fail: an ordinary token verifies end to end."""
    assert verify_status_snapshot(_statusliste(1), expected_uri=_URI, index=0, issuer_pubkey=_PUB)["ok"] is True
    assert verify_enclave_attestation(_enklave(1), verifier_pubkey=_PUB, expected_binding=_BINDING)["ok"] is True


def test_ANTI_both_issuers_still_refuse_what_their_verifier_refuses_for_its_budget():
    """[COUNTS] The finding of c3472f6f stays closed: a `uri` and a `binding` of 1,100,000 characters pass
    `string_len` and are refused before anything is signed, now for the budget alone."""
    with pytest.raises(BundleFormatError, match="string_len"):
        _statusliste(1, uri="https://example.test/" + "u" * 1_100_000)
    with pytest.raises(BundleFormatError, match="string_len"):
        _enklave(1, binding="B" * 1_100_000)


def test_the_dsse_primitive_signs_a_json_body_outside_the_ijson_range_as_before():
    """[COUNTS] The DSSE primitive reads its `+json` payload through the same function now; what it signed before, an
    integer past the I-JSON range among them, it still signs."""
    env = sign_envelope(b'{"a": 9007199254740993}', _KEY, payload_type="application/vnd.in-toto+json")
    assert base64.b64decode(env["payload"]) == b'{"a": 9007199254740993}'


#: Inputs `loads_strict` refuses for a question of FORM: the producer check leaves each to the verifier.
_FORM = {
    "integer above the I-JSON range": b'{"iat": 9007199254740992}',
    "integer below the I-JSON range": b'{"iat": -9007199254740992}',
    "NaN": b'{"x": NaN}',
    "Infinity": b'{"x": Infinity}',
    "a number without a finite double": b'{"x": 1e400}',
    "a duplicate key": b'{"a": 1, "a": 2}',
    "a lone surrogate": b'{"a": "\\ud800"}',
    "a UTF-8 byte order mark": b'\xef\xbb\xbf{"a": 1}',
    "UTF-16": '{"a": 1}'.encode("utf-16"),
    "text that is not JSON": b'{"a": ',
}

#: Inputs `loads_strict` refuses for their SIZE under `_ENG`, one per axis: the producer check refuses each too.
#: `int_bits` is measured below the I-JSON range (2**45 under a bound of 40 bits): an integer past 53 bits is refused
#: by `loads_strict` for its form first, measured on the first run of this file, so it could not show the axis.
_ENG_INT = VerificationBudget(input_bytes=4096, json_nodes=20, json_depth=8, string_len=64, int_bits=40)
_GROESSE = {
    "input_bytes": (json.dumps({"a": "x" * 60, "b": ["y" * 60] * 15}).encode() + b" " * 4096, _ENG),
    "json_nodes": (json.dumps({"l": list(range(30))}).encode(), _ENG),
    "json_depth": (b"[" * 12 + b"]" * 12, _ENG),
    "string_len": (json.dumps({"a": "s" * 65}).encode(), _ENG),
    "int_bits": (json.dumps({"a": 2**45}).encode(), _ENG_INT),
}


@pytest.mark.parametrize("name", sorted(_FORM))
def test_GENERATOR_a_question_of_form_is_left_to_the_verifier(name):
    """[COUNTS] The oracle refuses each input; the producer check does not, under the default budget and the tight
    one alike."""
    from proofbundle._strict_json import enforce_budget_only
    data = _FORM[name]
    with pytest.raises((ProofBundleError, ValueError)):
        loads_strict(data)
    assert enforce_budget_only(data) is None
    assert enforce_budget_only(data, budget=_ENG) is None


@pytest.mark.parametrize("achse", sorted(_GROESSE))
def test_GENERATOR_every_axis_of_the_budget_is_refused_by_the_producer_check(achse):
    """[COUNTS] The oracle refuses each input for its axis; the producer check refuses it too, with a budget error."""
    from proofbundle._strict_json import enforce_budget_only
    data, eng = _GROESSE[achse]
    with pytest.raises(ProofBundleError) as orakel:
        loads_strict(data, budget=eng)
    with pytest.raises(ProofBundleError) as pruefung:
        enforce_budget_only(data, budget=eng)
    for exc in (orakel.value, pruefung.value):
        if achse == "json_depth":
            assert isinstance(exc, BundleFormatError) and "nesting is too deep" in str(exc), exc
        else:
            assert isinstance(exc, BudgetExceeded) and achse in str(exc), exc
    # ANTI: the same input under the default budget is within it, so the size and nothing else decided above.
    assert enforce_budget_only(data) is None


@pytest.mark.parametrize("achse", sorted(_GROESSE))
def test_GENERATOR_a_lone_surrogate_beside_an_axis_does_not_hide_the_size(achse):
    """[COUNTS] Codex, round one of this fix (P1): the first form returned on a lone surrogate before it measured
    anything, so a string past `string_len` with one surrogate passed. Each axis input of the generator above gets a
    member holding a lone surrogate; the producer check still refuses it for that axis."""
    from proofbundle._strict_json import enforce_budget_only
    data, eng = _GROESSE[achse]
    if achse == "json_depth":
        data = b'{"s": "\\ud800", "t": ' + data + b"}"
    elif achse == "input_bytes":
        data = b'{"s": "\\ud800", ' + data.lstrip()[1:]
    else:
        data = b'{"s": "\\ud800", ' + data[1:]
    with pytest.raises(ProofBundleError) as pruefung:
        enforce_budget_only(data, budget=eng)
    exc = pruefung.value
    if achse == "json_depth":
        assert isinstance(exc, BundleFormatError) and "nesting is too deep" in str(exc), exc
    else:
        assert isinstance(exc, BudgetExceeded) and achse in str(exc), exc


def test_both_issuers_refuse_an_over_budget_string_with_a_lone_surrogate_before_signing():
    """[COUNTS] The same at the issuers: a `uri` and a `binding` of 1,000,001 characters followed by a lone surrogate
    were signed by the first form of this fix; nothing may be signed, and the reason is the size."""
    gerufen = []

    class Zaehler:
        def sign(self, msg):
            gerufen.append(1)
            return _KEY.sign(msg)

    with pytest.raises(BundleFormatError, match="string_len"):
        issue_status_list_token([0], uri="u" * 1_000_001 + "\ud800", signer=Zaehler(), iat=1)
    with pytest.raises(BundleFormatError, match="string_len"):
        issue_enclave_attestation("B" * 1_000_001 + "\ud800", Zaehler(), profile=_PROFILE, tier="hardware", iat=1)
    assert gerufen == [], "nothing is signed before the refusal"


@pytest.mark.parametrize("ziffern", [4300, 4301, 5000, 20000])
def test_GENERATOR_an_integer_literal_longer_than_the_interpreter_converts_is_refused_for_int_bits(ziffern):
    """[COUNTS] Found in this fix before its pull request: `json.loads` raises a plain ValueError for a literal of more
    than `sys.get_int_max_str_digits()` digits (4300 by default), and the first form read every ValueError as a
    question of form. Measured with the default budget: 4300 nines were refused for `int_bits`, 4301 and 20000 nines
    passed. Each length here is far over `int_bits`; the producer check refuses it for that axis, at both signs, and
    the oracle refuses it as well."""
    from proofbundle._strict_json import enforce_budget_only
    for zahl in ("9" * ziffern, "-" + "9" * ziffern):
        data = ('{"iat": ' + zahl + "}").encode()
        with pytest.raises(ProofBundleError):
            loads_strict(data)
        with pytest.raises(BudgetExceeded, match="int_bits"):
            enforce_budget_only(data)


def test_the_dsse_primitive_refuses_an_integer_literal_longer_than_the_interpreter_converts():
    """[COUNTS] The same hole at the DSSE primitive, which takes the raw `+json` body from its caller: 4301 nines are
    over `int_bits`, and nothing is signed."""
    with pytest.raises(BundleFormatError, match="int_bits"):
        sign_envelope(b'{"a": ' + b"9" * 4301 + b"}", _KEY, payload_type="application/vnd.in-toto+json")


@pytest.mark.parametrize("vorzeichen", [1, -1])
def test_a_literal_longer_than_one_piece_is_measured_exactly(vorzeichen):
    """[COUNTS] A literal of more than 600 digits whose lower bound is within `int_bits` is converted in pieces, and the
    walk measures its exact bit length: 2**2400 has 723 digits and 2401 bits, so a bound of 2401 admits it and a bound
    of 2400 refuses it. A wrong piecewise conversion would move the edge."""
    from proofbundle._strict_json import enforce_budget_only
    data = ('{"a": %d}' % (vorzeichen * 2**2400)).encode()
    assert enforce_budget_only(data, budget=VerificationBudget(int_bits=2401)) is None
    with pytest.raises(BudgetExceeded, match="int_bits"):
        enforce_budget_only(data, budget=VerificationBudget(int_bits=2400))


def test_ANTI_a_lone_surrogate_within_the_budget_stays_with_the_verifier():
    """[COUNTS] The counter direction: a short `uri` with a lone surrogate is signed, and the verifier refuses it, as
    the DSSE primitive leaves such a body to its verifier."""
    token = _statusliste(1, uri=_URI + "\ud800")
    urteil = verify_status_snapshot(token, expected_uri=_URI + "\ud800", index=0, issuer_pubkey=_PUB)
    assert urteil["ok"] is False, urteil
