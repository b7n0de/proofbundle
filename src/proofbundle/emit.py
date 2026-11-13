"""Evidence bundle emitter (v0.2).

Sign a payload with Ed25519 and include it as the last leaf of an RFC 6962
Merkle tree. Before signing, apply the structural budget used by
``verify_bundle`` for dictionary input. This check does not validate an
embedded SD-JWT or impose the byte limit of a serialized file. This is the
counterpart to the verifier: create the evidence here, check it with
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


@_ein_stand(aussen={"key": "signierer", "path": "pfad"})
def save_signer(key: Ed25519PrivateKey, path: str, *, overwrite: bool = True) -> None:
    """Write the 32 byte raw Ed25519 private seed to ``path``, mode 0600.

    This is a secret. The seed is written into a new file in the directory of ``path``, created owner-read/write
    only (never world-readable, even briefly), which then takes the place of ``path``. So the file at ``path`` has
    mode 0600 after every write, whatever stood there before, and a symbolic link at ``path`` is replaced, never
    followed: the file it pointed to keeps its bytes.

    With ``overwrite=True`` (the default) an existing file at ``path`` is replaced. With ``overwrite=False`` an
    existing ``path``, a symbolic link included, raises ``FileExistsError`` and keeps its bytes; the check and the
    write are one step, so no file that appears in between is replaced either. Every ``--new-key`` option of the
    command line writes with ``overwrite=False``. Store the key out of version control and treat it like a key, not
    like data.
    """
    # Vor der os-Grenze, wie bei `load_signer` — und aus demselben Grund: was hinter der Grenze
    # scheitert, scheitert bereits am Betriebssystem, und dessen Fehlerform ist nicht unsere.
    _pfad_boden(path)
    if type(overwrite) is not bool:
        from .errors import BundleFormatError as _BFE  # noqa: PLC0415
        raise _BFE(f"overwrite must be True or False, got {type(overwrite).__name__} (fail-closed)")
    raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    _schreibe_geheimnis(os.fsdecode(os.fspath(path)), raw, overwrite)


def _schreibe_geheimnis(pfad: str, daten: bytes, ersetzen: bool) -> None:
    """Schreibt ``daten`` in eine NEUE Datei neben ``pfad`` (O_EXCL, 0600) und setzt sie dann an ``pfad``.

    Gefunden im Deep Gate 6.6.0 an 41959070 (L2 C4, L4 Nebenbefund, dritte Lesung P2): `os.open` mit
    O_CREAT|O_TRUNC setzte den Modus nur beim Anlegen, eine vorhandene 0644-Datei blieb 0644, ein Link wurde
    verfolgt, und `--new-key` ersetzte einen vorhandenen Schluessel still. Die neue Datei entsteht mit O_EXCL
    (folgt keinem Link, faengt keine vorhandene), ihr Modus wird nach dem Anlegen ausdruecklich 0600 gesetzt
    (die umask kann ihn sonst nur enger machen, nicht genau), und dann ersetzt ``os.replace`` den Eintrag an
    ``pfad`` (einen Link dort ersetzt es, statt ihm zu folgen). Ohne ``ersetzen`` setzt ``os.link`` sie
    stattdessen an ``pfad``: das scheitert mit ``FileExistsError``, wenn dort irgendein Eintrag steht, in
    einem Schritt mit dem Schreiben. Die Zwischendatei wird in jedem Fall entfernt, auch nach einem Fehler.
    """
    import tempfile  # noqa: PLC0415

    if not pfad:
        raise FileNotFoundError(2, "No such file or directory", pfad)
    verzeichnis = os.path.dirname(pfad) or "."
    fd, zwischen = tempfile.mkstemp(prefix=".proofbundle-key-", dir=verzeichnis)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        else:  # pragma: no cover - Plattform ohne fchmod
            os.chmod(zwischen, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(daten)
            handle.flush()
            os.fsync(handle.fileno())
        if ersetzen:
            os.replace(zwischen, pfad)
        else:
            os.link(zwischen, pfad)
    finally:
        if fd != -1:
            os.close(fd)
        if os.path.lexists(zwischen):
            os.unlink(zwischen)


@_ein_stand(aussen={"path": "pfad"})
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


@_ein_stand(aussen={"signer": "signierer"})
def emit_bundle(
    payload: bytes,
    signer: Ed25519PrivateKey,
    *,
    prior_leaves: Sequence[bytes] = (),
    sd_jwt_vc: Optional[dict] = None,
) -> dict:
    """Produce a ``proofbundle/v0.1`` bundle for ``payload``.

    The payload is signed with ``signer`` and appended as the last leaf of an
    RFC 6962 Merkle tree over ``prior_leaves + [payload]``. Before signing, the complete bundle is
    checked with the structural budget used by :func:`proofbundle.verify_bundle` for dictionary input.
    Exceeding that budget raises ``BundleFormatError`` without creating a signature. This check does not
    validate an embedded SD-JWT or impose the byte limit of a serialized file. It measures the signature and
    the public key at the lengths of Ed25519, 64 and 32 bytes, because a signer's outputs exist only once it
    is asked. A signer whose signature or public key has another length is refused with ``BundleFormatError``
    after it was asked, and no bundle is returned.

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

    # Placeholders of the fixed lengths of an Ed25519 public key and signature until the reading below has passed.
    # The signer is not asked before that reading, and then in the order this function always had: sign, then read
    # the public key (Codex thread 4219203464 on pull request 307, held by tests/test_merkle_accumulator.py). Equal
    # lengths give the budget the same verdict as the real values.
    signature: dict[str, str] = {
        "alg": "ed25519",
        "public_key_b64": _b64(bytes(32)),
        "sig_b64": _b64(bytes(64)),
    }
    bundle = {
        "schema": SCHEMA,
        "payload_b64": _b64(payload),
        "signature": signature,
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
    # THE STRUCTURAL BUDGET OF verify_bundle BEFORE THE SIGNATURE (the native-bundle neighbour of the 6.5.0 SD-JWT
    # finding, review of the class fix, rounds 1 and 2). verify_bundle reads a bundle dict with
    # `enforce_structural_budget` (string_len, json_nodes, json_depth, int_bits, all from DEFAULT_BUDGET) and
    # refused a bundle this function had signed: a payload over 750,000 bytes gives a payload_b64 over 1,000,000
    # characters. The same reading runs here before the signer is called, and a refusal is a BundleFormatError.
    # The byte limit of a serialized file (load_bundle, input_bytes) is not this check's.
    from ._strict_json import enforce_structural_budget  # noqa: PLC0415
    from .errors import ProofBundleError  # noqa: PLC0415
    try:
        enforce_structural_budget(bundle)
    except ProofBundleError as exc:
        raise BundleFormatError(f"emit_bundle: the bundle is one verify_bundle cannot read, so it is not "
                                f"signed: {exc}") from None
    # THE PLACEHOLDERS HOLD ONLY FOR AN Ed25519 SIGNER (Codex pre-review 5 of the class fix): the reading above
    # measured 64 signature bytes and 32 key bytes, and a signer of another kind could return any length after it,
    # so a key of 750,001 bytes gave a bundle verify_bundle refuses. The lengths the reading assumed are checked on
    # what the signer returns, read once as the bytes it holds; anything else is refused and no bundle is returned.
    from .signature import _ed25519_signatur_von  # noqa: PLC0415
    sig = _ed25519_signatur_von(signer.sign(payload))
    if sig is None:
        raise BundleFormatError("emit_bundle: the signer returned no 64-byte Ed25519 signature, so no bundle is "
                                "returned")
    signature["sig_b64"] = _b64(sig)
    pub = _puffer_von(_raw_pub(signer))
    if pub is None or len(pub) != 32:
        raise BundleFormatError("emit_bundle: the signer's public key is no 32-byte Ed25519 key, so no bundle is "
                                "returned")
    signature["public_key_b64"] = _b64(pub)
    return bundle
