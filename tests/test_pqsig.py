"""B5 post-quantum signature path — the three regressions from the anchor-longevity enabler prompt.

  * pq_signature_verify_mldsa            (FIPS 204, real)
  * pq_signature_verify_slhdsa_optional  (FIPS 205, optional — OPEN if no library, never faked)
  * hybrid_classical_plus_pq_verify      (Ed25519 + ML-DSA, both must verify)
"""
from __future__ import annotations

import pytest

from proofbundle.pqsig import (
    PQUnavailable,
    generate_mldsa,
    sign_mldsa,
    verify_hybrid,
    verify_mldsa,
    verify_slhdsa,
)

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: F401
    _HAS_MLDSA = True
except ImportError:
    _HAS_MLDSA = False


def _mldsa_raw_pub(sk) -> bytes:
    from cryptography.hazmat.primitives import serialization as s
    return sk.public_key().public_bytes(encoding=s.Encoding.Raw, format=s.PublicFormat.Raw)


def _ed25519_keypair():
    from cryptography.hazmat.primitives import serialization as s
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(encoding=s.Encoding.Raw, format=s.PublicFormat.Raw)
    return sk, pub


MSG = b"a receipt migrated forward by the renewal layer"


@pytest.mark.skipif(not _HAS_MLDSA, reason="needs cryptography with FIPS 204 (ML-DSA)")
class TestMLDSA:
    def test_pq_signature_verify_mldsa(self) -> None:
        sk = generate_mldsa("mldsa65")
        sig = sign_mldsa(sk, MSG)
        assert verify_mldsa(_mldsa_raw_pub(sk), sig, MSG) is True

    def test_mldsa_rejects_wrong_message(self) -> None:
        sk = generate_mldsa("mldsa65")
        sig = sign_mldsa(sk, MSG)
        assert verify_mldsa(_mldsa_raw_pub(sk), sig, b"different message") is False

    def test_mldsa_rejects_tampered_signature(self) -> None:
        sk = generate_mldsa("mldsa65")
        sig = bytearray(sign_mldsa(sk, MSG))
        sig[0] ^= 0xFF
        assert verify_mldsa(_mldsa_raw_pub(sk), bytes(sig), MSG) is False

    def test_mldsa_malformed_pubkey_returns_false_not_raise(self) -> None:
        assert verify_mldsa(b"too short", b"x" * 3309, MSG) is False

    def test_mldsa_levels_are_independent(self) -> None:
        sk = generate_mldsa("mldsa65")
        sig = sign_mldsa(sk, MSG)
        # a 65-bit key verified under the 87 parameter set must fail closed, not crash
        assert verify_mldsa(_mldsa_raw_pub(sk), sig, MSG, level="mldsa87") is False


@pytest.mark.skipif(not _HAS_MLDSA, reason="needs cryptography with FIPS 204 (ML-DSA)")
class TestHybrid:
    def test_hybrid_classical_plus_pq_verify(self) -> None:
        ed_sk, ed_pub = _ed25519_keypair()
        pq_sk = generate_mldsa("mldsa65")
        ed_sig = ed_sk.sign(MSG)
        pq_sig = sign_mldsa(pq_sk, MSG)
        assert verify_hybrid(classical_pub=ed_pub, classical_sig=ed_sig,
                             pq_pub=_mldsa_raw_pub(pq_sk), pq_sig=pq_sig, message=MSG) is True

    def test_hybrid_fails_if_classical_leg_broken(self) -> None:
        ed_sk, ed_pub = _ed25519_keypair()
        pq_sk = generate_mldsa("mldsa65")
        pq_sig = sign_mldsa(pq_sk, MSG)
        assert verify_hybrid(classical_pub=ed_pub, classical_sig=b"\x00" * 64,
                             pq_pub=_mldsa_raw_pub(pq_sk), pq_sig=pq_sig, message=MSG) is False

    def test_hybrid_fails_if_pq_leg_broken(self) -> None:
        ed_sk, ed_pub = _ed25519_keypair()
        pq_sk = generate_mldsa("mldsa65")
        ed_sig = ed_sk.sign(MSG)
        bad_pq = bytearray(sign_mldsa(pq_sk, MSG))
        bad_pq[0] ^= 0xFF
        assert verify_hybrid(classical_pub=ed_pub, classical_sig=ed_sig,
                             pq_pub=_mldsa_raw_pub(pq_sk), pq_sig=bytes(bad_pq), message=MSG) is False


def test_pq_signature_verify_slhdsa_optional() -> None:
    # SLH-DSA (FIPS 205) is optional; with no library it must raise a clear PQUnavailable, NEVER fake a
    # verify (No-Fake). If a future build provides it, the call would instead verify.
    try:
        from cryptography.hazmat.primitives.asymmetric import slhdsa  # noqa: F401
        has_slhdsa = True
    except ImportError:
        has_slhdsa = False
    if not has_slhdsa:
        with pytest.raises(PQUnavailable):
            verify_slhdsa(b"pub", b"sig", MSG)
    else:  # pragma: no cover - environment-dependent
        # library present but wiring not implemented → still an honest PQUnavailable, not a fake pass
        with pytest.raises(PQUnavailable):
            verify_slhdsa(b"pub", b"sig", MSG)
