"""`emit_bundle` applies the structural budget of `verify_bundle` before it signs.

THE NATIVE-BUNDLE NEIGHBOUR of the SD-JWT finding of the 6.5.0 deep gate (review of the class fix, round 1): the
same class, a producer signs what its own verifier refuses under its resource policy. `verify_bundle` reads a
bundle dict with `enforce_structural_budget` (`string_len` 1,000,000 characters per string, and the node, depth
and integer bounds of `DEFAULT_BUDGET`), and `emit_bundle` signed without that reading: a payload over 750,000
bytes gives a `payload_b64` over 1,000,000 characters, which was emitted and then refused by `verify_bundle`
with BundleFormatError.

Before signing, `emit_bundle` applies the structural budget used by `verify_bundle` for dictionary input. An
over-budget bundle raises BundleFormatError before the signer is called. This includes payloads larger than
750,000 bytes and over-budget `sd_jwt_vc` values. The verifier's limits are unchanged. The byte limit of a
serialized file is not part of this guarantee.
"""
from __future__ import annotations

import pytest

from proofbundle.budget import DEFAULT_BUDGET
from _lastdeckel import KOSTEN_JE_ELEMENT, gedeckelt  # noqa: E402  (LAUF11-L3: a load built from a budget is capped)
from proofbundle.bundle import verify_bundle
from proofbundle.emit import emit_bundle, generate_signer
from proofbundle.errors import BundleFormatError

#: The largest payload whose standard base64 has at most `string_len` characters (4 per 3 bytes).
BOUND = gedeckelt(DEFAULT_BUDGET.string_len, bytes_je_element=KOSTEN_JE_ELEMENT["string_len"]) // 4 * 3


class _Counting:
    """A signer that counts its signatures, records the order it is asked in, and signs with the real key."""

    def __init__(self, inner):
        self.inner, self.signed, self.asked = inner, 0, []

    def sign(self, data):
        self.signed += 1
        self.asked.append("sign")
        return self.inner.sign(data)

    def public_key(self):
        self.asked.append("public_key")
        return self.inner.public_key()


@pytest.fixture(scope="module")
def signer():
    return generate_signer()


def test_a_payload_at_the_bound_is_emitted_and_verifies(signer):
    bundle = emit_bundle(b"x" * BOUND, signer)
    assert len(bundle["payload_b64"]) == DEFAULT_BUDGET.string_len
    assert verify_bundle(bundle).ok is True


def test_a_payload_one_byte_over_the_bound_is_refused_before_signing(signer):
    counting = _Counting(signer)
    with pytest.raises(BundleFormatError, match="verify_bundle cannot read"):
        emit_bundle(b"x" * (BOUND + 1), counting)
    assert counting.signed == 0


def test_an_sd_jwt_vc_string_over_string_len_is_refused_before_signing(signer):
    counting = _Counting(signer)
    with pytest.raises(BundleFormatError, match="verify_bundle cannot read"):
        emit_bundle(b"payload", counting, sd_jwt_vc={"compact": "c" * (gedeckelt(DEFAULT_BUDGET.string_len, bytes_je_element=KOSTEN_JE_ELEMENT["string_len"]) + 1)})
    assert counting.signed == 0


def test_control_verify_bundle_refuses_what_the_emitter_now_refuses(signer):
    """The emitter's refusal is the verifier's: a bundle built at the bound and then given one more payload
    byte by hand is refused by `verify_bundle` with the reason the emitter now gives before signing."""
    bundle = emit_bundle(b"x" * BOUND, signer)
    bundle["payload_b64"] += "eA=="
    with pytest.raises(BundleFormatError):
        verify_bundle(bundle)


def test_an_ordinary_bundle_is_emitted_and_verifies_as_before(signer):
    bundle = emit_bundle(b'{"claim": 1}', signer, prior_leaves=[b"a", b"b"])
    assert verify_bundle(bundle).ok is True
    assert bundle["merkle"]["tree_size"] == 3


def test_the_signer_is_asked_as_before_sign_then_public_key(signer):
    """The budget reading uses placeholders of the fixed key and signature lengths, so it asks the signer nothing.
    At f35a4b8d it read the public key BEFORE signing to build the bundle it measured: a signer whose public key
    depends on having signed then gave a signature and a key that do not belong together, and the control of
    tests/test_merkle_accumulator.py (Codex thread 4219203464 on pull request 307) fell."""
    counting = _Counting(signer)
    assert verify_bundle(emit_bundle(b"payload", counting)).ok is True
    assert counting.asked == ["sign", "public_key"]


def test_a_refused_bundle_asks_the_signer_nothing(signer):
    counting = _Counting(signer)
    with pytest.raises(BundleFormatError, match="verify_bundle cannot read"):
        emit_bundle(b"x" * (BOUND + 1), counting)
    assert counting.asked == []


class _Odd:
    """A signer of another kind: it signs and names its key with the real Ed25519 key unless told otherwise."""

    def __init__(self, inner, *, sig=None, pub=None):
        self.inner, self.sig, self.pub = inner, sig, pub

    def sign(self, data):
        return self.inner.sign(data) if self.sig is None else self.sig

    def public_key(self):
        echt, pub = self.inner.public_key(), self.pub

        class _Public:
            def public_bytes(self, *args):
                return echt.public_bytes(*args) if pub is None else pub
        return _Public()


@pytest.mark.parametrize("fall,sig,pub", [
    # Codex pre-review 5, reproduced: the key past the string budget after the reading had passed.
    ("public key of 750,001 bytes", None, b"k" * 750_001),
    ("signature of 750,001 bytes", b"s" * 750_001, None),
    ("public key of 31 bytes", None, b"k" * 31),
    ("signature of 65 bytes", b"s" * 65, None),
    ("signature that is no bytes", "s" * 64, None),
    ("public key that is no bytes", None, 32),
])
def test_a_signer_output_of_another_length_is_refused_and_no_bundle_returned(signer, fall, sig, pub):
    with pytest.raises(BundleFormatError, match="no bundle is returned"):
        emit_bundle(b"payload", _Odd(signer, sig=sig, pub=pub))


def test_control_a_signer_of_another_kind_with_ed25519_outputs_is_emitted_and_verifies(signer):
    """The check is on the outputs, not on the type of the signer: one that returns a 64-byte signature and a 32-byte
    key, as bytes or as a memoryview, gives the bundle the real key gives."""
    assert emit_bundle(b"payload", _Odd(signer)) == emit_bundle(b"payload", signer)
    gesehen = _Odd(signer, sig=memoryview(signer.sign(b"payload")))
    assert verify_bundle(emit_bundle(b"payload", gesehen)).ok is True


def test_ein_blatt_is_what_the_emitter_writes(signer):
    """Self-probe of the shared builder in tests/_ein_blatt_buendel.py: on an in-budget payload it writes the bundle
    the emitter writes, key for key and value for value, so a test that needs the same bundle past the budget gets
    exactly that and nothing else."""
    from _ein_blatt_buendel import ein_blatt
    for payload in (b'{"x": 1}', b"", b"x" * BOUND):
        assert ein_blatt(payload, signer) == emit_bundle(payload, signer)
    gross = ein_blatt(b"x" * (BOUND + 1), signer)
    assert len(gross["payload_b64"]) > DEFAULT_BUDGET.string_len
    with pytest.raises(BundleFormatError):
        verify_bundle(gross)
