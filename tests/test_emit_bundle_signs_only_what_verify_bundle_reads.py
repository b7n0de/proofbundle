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
from proofbundle.bundle import verify_bundle
from proofbundle.emit import emit_bundle, generate_signer
from proofbundle.errors import BundleFormatError

#: The largest payload whose standard base64 has at most `string_len` characters (4 per 3 bytes).
BOUND = DEFAULT_BUDGET.string_len // 4 * 3


class _Counting:
    """A signer that counts its signatures and signs with the real key."""

    def __init__(self, inner):
        self.inner, self.signed = inner, 0

    def sign(self, data):
        self.signed += 1
        return self.inner.sign(data)

    def public_key(self):
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
        emit_bundle(b"payload", counting, sd_jwt_vc={"compact": "c" * (DEFAULT_BUDGET.string_len + 1)})
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
