"""Evidence bundle emitter (v0.2).

Sign a payload with Ed25519 and anchor it as the last leaf of an RFC 6962
Merkle tree, producing a bundle that ``verify_bundle`` accepts. This is the
counterpart to the verifier: create the evidence here, check it anywhere with
``proofbundle verify``, fully offline.

The eval-receipt emitter that builds on this (``emit_eval_receipt``) lives in
:mod:`proofbundle.evalclaim` since v0.4.
"""

from __future__ import annotations

import base64
import os
from typing import Optional, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from . import merkle
from .bundle import SCHEMA
from .canonical import _ein_stand

__all__ = [
    "generate_signer",
    "save_signer",
    "load_signer",
    "emit_bundle",
]


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _raw_pub(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


@_ein_stand
def generate_signer() -> Ed25519PrivateKey:
    """Generate a fresh Ed25519 signing key."""
    return Ed25519PrivateKey.generate()


def _pfad_boden(path) -> None:
    """EIN Typboden fuer beide Schluesseldatei-Flaechen, damit sie nicht wieder auseinanderlaufen.

    Er stand ab 2026-08-16 nur in `load_signer`. `save_signer` steht in derselben Datei, nimmt
    denselben aufrufer-gelieferten Pfad und hatte ihn nicht — gemessen 2026-08-18:
    `save_signer(echterSchluessel, 1)` warf einen rohen `TypeError` aus `os.open`, waehrend
    `load_signer(1)` eine typisierte Antwort gab. Zwei Nachbarn, ein Vertrag, zwei Antworten.

    WARUM ES NIEMAND SAH: die never-raise-Familieneigenschaft entdeckt Flaechen ueber
    Namensfamilien, und `load_` steht darin, `save_` nicht. In der begruendeten Ausschlussmenge
    liegt `save_signer` als ERZEUGER — "baut aus EIGENEN, bereits geprueften Werten". Das trifft
    auf sein `key`-Argument zu und auf seinen PFAD gerade nicht. Eine Begruendung, die fuer EIN
    Argument stimmt, deckt die Funktion nicht.
    """
    if not isinstance(path, (str, bytes, os.PathLike)):
        from .errors import BundleFormatError as _BFE  # noqa: PLC0415
        raise _BFE(f"signer key path must be a path string, got {type(path).__name__} (fail-closed)")


@_ein_stand
def save_signer(key: Ed25519PrivateKey, path: str) -> None:
    """Write the 32 byte raw Ed25519 private seed to ``path``, mode 0600.

    This is a secret. The file is created owner-read/write only (never
    world-readable, even briefly), so an accidental commit or a shared directory
    does not leak the key. Store it out of version control and treat it like a
    key, not like data.
    """
    # Vor der os-Grenze, wie bei `load_signer` — und aus demselben Grund: was hinter der Grenze
    # scheitert, scheitert bereits am Betriebssystem, und dessen Fehlerform ist nicht unsere.
    _pfad_boden(path)
    raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    # Open with 0600 from the start to avoid a world-readable window.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)


@_ein_stand
def load_signer(path: str) -> Ed25519PrivateKey:
    """Load an Ed25519 signing key from a 32 byte raw seed file."""
    # TYPE FLOOR, same invariant as evalcard/prereg (L1-01) — applied here only on 2026-08-16, because
    # until then this surface sat OUTSIDE the never-raise family property: `emit` was not in `_MODULES`,
    # so nothing ever asked the question. The moment the population was derived from the tree instead of
    # a hand-maintained list, the property caught this on its first run.
    #
    # Measured before the fix: `load_signer(9)` raised `OSError: [Errno 9] Bad file descriptor`. That is
    # the worse half of the int case — `open(9)` does not fail on a wrong type, it reads FILE
    # DESCRIPTOR 9. A wider except-tuple would hide the escape while leaving the fd read in place; the
    # floor is the fix, and it belongs before the os boundary, not after it.
    _pfad_boden(path)
    with open(path, "rb") as handle:
        return Ed25519PrivateKey.from_private_bytes(handle.read())


@_ein_stand
def emit_bundle(
    payload: bytes,
    signer: Ed25519PrivateKey,
    *,
    prior_leaves: Sequence[bytes] = (),
    sd_jwt_vc: Optional[dict] = None,
) -> dict:
    """Produce a ``proofbundle/v0.1`` bundle for ``payload``.

    The payload is signed with ``signer`` and appended as the last leaf of an
    RFC 6962 Merkle tree over ``prior_leaves + [payload]``. The returned dict is
    accepted by :func:`proofbundle.verify_bundle`.

    ``sd_jwt_vc`` is passed through verbatim if given (for example
    ``{"compact": "...", "issuer_public_key_b64": "..."}``). Its bytes belong to a foreign issuer and
    are never rewritten, an ES256 signature with a high s included: a Key Binding JWT's ``sd_hash``
    covers the issuer JWT exactly as presented (RFC 9901 §4.3), and rewriting it broke that binding
    for every verifier that hashes the bytes it gets (finding D1, measured on f536af50). An identity
    of the bundle is computed over the canonical low-s form instead
    (:func:`proofbundle.anchors.receipt_canonical_root`).

    Each input is read once, by what it holds (round 12): the payload and every prior leaf as the bytes
    they store (so the bytes signed, hashed into the tree and written are one reading, not three calls
    of a `bytes` subclass's own buffer; a ``memoryview`` as the bytes it views, as the leaf hash read it
    before), the prior leaves through the base iteration, and a dict ``sd_jwt_vc`` as the plain copy of
    what it stores, which is what the bundle carries.
    """
    from .canonical import _folge_von, _plain_for_jcs, _puffer_von  # noqa: PLC0415
    from .errors import BundleFormatError  # noqa: PLC0415
    if _puffer_von(payload) is not None:
        payload = _puffer_von(payload)
    prior_leaves = [_puffer_von(p) if _puffer_von(p) is not None else p for p in _folge_von(prior_leaves)]
    if sd_jwt_vc is not None and issubclass(type(sd_jwt_vc), dict):
        sd_jwt_vc = _plain_for_jcs(sd_jwt_vc, lambda text: BundleFormatError(f"sd_jwt_vc: {text}"))
    leaves = list(prior_leaves) + [payload]
    index = len(leaves) - 1
    root = merkle.merkle_tree_hash(leaves)
    proof = merkle.inclusion_proof(leaves, index)
    signature = signer.sign(payload)

    bundle = {
        "schema": SCHEMA,
        "payload_b64": _b64(payload),
        "signature": {
            "alg": "ed25519",
            "public_key_b64": _b64(_raw_pub(signer)),
            "sig_b64": _b64(signature),
        },
        "merkle": {
            "hash_alg": "sha256-rfc6962",
            "leaf_index": index,
            "tree_size": len(leaves),
            "inclusion_proof_b64": [_b64(p) for p in proof],
            "root_b64": _b64(root),
        },
    }
    if sd_jwt_vc is not None:
        bundle["sd_jwt_vc"] = sd_jwt_vc
    return bundle
