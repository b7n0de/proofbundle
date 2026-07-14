"""B5 post-quantum signature path for the renewal layer (EXPERIMENTAL; ADR 0006).

Hash-based time anchors survive a signature break; a receipt's *signatures* do not. The renewal layer
(B3) re-signs a migrated ArchiveTimeStamp with a NIST-standardized post-quantum scheme — this module
provides the primitives it uses, and `renewal.py` wires them (B3↔B5): an ATS carries a real
time-authority signature and `renew_timestamp`/`renew_hashtree` migrate the algorithm
ed25519 → hybrid → mldsa65 as the classical signature ages. The primitives:

* **ML-DSA (FIPS 204)** — the primary renewal target. Real here via ``cryptography``'s ``mldsa``
  (lattice-based). Verification only re-implements nothing: it wraps ``cryptography`` exactly like
  ``signature.verify_ed25519`` does for the classical path.
* **Hybrid classical + PQ** — the intermediate step. A hybrid signature is valid iff BOTH the Ed25519
  and the ML-DSA component verify, so an attacker must forge BOTH: the receipt stays secure as long as
  EITHER primitive is unbroken. This is the migration-safe default while confidence in a single PQ scheme
  matures.
* **SLH-DSA (FIPS 205)** — the hash-based conservative option, whose security rests only on the hash
  function. It is OPTIONAL and currently OPEN here: the installed ``cryptography`` exposes ML-DSA but not
  SLH-DSA, so ``verify_slhdsa`` raises a clear ``PQUnavailable`` rather than faking a result. LMS/XMSS
  (SP 800-208, RFC 8554/8391) are the stateful alternative, also out of scope until a vetted library is
  wired.

We never roll our own crypto. Malformed inputs to a verify function return ``False`` (a boolean per check),
never a raise — matching ``signature.verify_ed25519``.
"""
from __future__ import annotations

from typing import Any

from .errors import ProofBundleError
from .signature import verify_ed25519

__all__ = [
    "PQUnavailable",
    "verify_mldsa",
    "verify_slhdsa",
    "verify_hybrid",
    "generate_mldsa",
    "sign_mldsa",
]


class PQUnavailable(ProofBundleError):
    """A requested PQ scheme has no vetted library wired (honest OPEN, never a faked verify)."""


def _mldsa_classes(level: str) -> tuple[Any, Any]:
    """(PrivateKey, PublicKey) classes for an ML-DSA level, or raise PQUnavailable."""
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: PLC0415
    except ImportError as exc:
        raise PQUnavailable("ML-DSA needs a cryptography build with FIPS 204 support") from exc
    table = {
        "mldsa44": (mldsa.MLDSA44PrivateKey, mldsa.MLDSA44PublicKey),
        "mldsa65": (mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey),
        "mldsa87": (mldsa.MLDSA87PrivateKey, mldsa.MLDSA87PublicKey),
    }
    if level not in table:
        raise PQUnavailable(f"unknown ML-DSA level {level!r} (mldsa44 | mldsa65 | mldsa87)")
    return table[level]


def verify_mldsa(public_key: bytes, signature: bytes, message: bytes, *, level: str = "mldsa65") -> bool:
    """True iff ``signature`` is a valid ML-DSA (FIPS 204) signature over ``message`` at ``level``.

    ``public_key`` is the raw ML-DSA public key. Malformed input returns False (never raises), matching
    ``verify_ed25519``. A missing FIPS-204 build raises ``PQUnavailable`` (a wiring problem, not a check
    result)."""
    _priv_cls, pub_cls = _mldsa_classes(level)
    from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
    try:
        pub = pub_cls.from_public_bytes(public_key)
        pub.verify(signature, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def verify_slhdsa(public_key: bytes, signature: bytes, message: bytes, *,
                  level: str = "slhdsa-sha2-128s") -> bool:
    """SLH-DSA (FIPS 205) verify — OPTIONAL and currently OPEN.

    The installed ``cryptography`` does not expose SLH-DSA, so this raises ``PQUnavailable`` rather than
    fake a result (No-Fake). When a vetted FIPS-205 library is wired this becomes a real verify with the
    same boolean contract as ``verify_mldsa``."""
    try:
        from cryptography.hazmat.primitives.asymmetric import slhdsa  # type: ignore[attr-defined] # noqa: PLC0415,F401
    except ImportError as exc:
        raise PQUnavailable(
            "SLH-DSA (FIPS 205) is optional and not available in this cryptography build; the hash-based "
            "conservative PQ path is OPEN pending a vetted library (see ADR 0006)") from exc
    raise PQUnavailable("SLH-DSA wiring is not implemented yet")  # pragma: no cover - future path


def verify_hybrid(*, classical_pub: bytes, classical_sig: bytes, pq_pub: bytes, pq_sig: bytes,
                  message: bytes, pq_level: str = "mldsa65") -> bool:
    """True iff BOTH the Ed25519 and the ML-DSA signature over ``message`` verify.

    A hybrid signature's security is the OR of its parts (an attacker must forge both to forge the
    hybrid), so the verify is the AND of its parts: both components must be present and valid."""
    return (verify_ed25519(classical_pub, classical_sig, message)
            and verify_mldsa(pq_pub, pq_sig, message, level=pq_level))


# --- test / demo helpers (key generation + signing live here, not on the production issuance path) ----

def generate_mldsa(level: str = "mldsa65") -> Any:
    """Generate an ML-DSA private key (test/demo helper; production issuance is out of scope)."""
    priv_cls, _pub_cls = _mldsa_classes(level)
    return priv_cls.generate()


def sign_mldsa(private_key: Any, message: bytes) -> bytes:
    """Sign ``message`` with an ML-DSA private key (test/demo helper)."""
    return bytes(private_key.sign(message))
