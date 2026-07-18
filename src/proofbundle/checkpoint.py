"""C2SP tlog-checkpoint output — a signed note over the RFC 6962 Merkle root (v0.9).

proofbundle already has an RFC 6962 Merkle root and Ed25519, so it can emit a valid C2SP tlog-checkpoint:
a signed note that makes a receipt witness-network / transparency-log compatible. Pure serialization and
framing, no new crypto. Spec verified 2026-07 against C2SP/C2SP tlog-checkpoint.md + signed-note.md.

Byte-exact rules (the ones that bite):
  - Note text = at least three non-empty lines separated by U+000A: line 1 `origin` (a schemeless log
    identity, no unicode spaces, no '+'), line 2 the tree size as ASCII decimal with no leading zeros
    (empty tree = "0"), line 3 the Merkle root in STANDARD RFC 4648 §4 base64 (with padding) — NOT
    base64url. The note text ends with a final U+000A.
  - The signed note = note text (ending in U+000A) + one empty line + one-or-more signature lines.
  - A signature line is:  U+2014 (EM DASH, not a hyphen) SP keyname SP base64(keyID ‖ signature) U+000A
    where keyID is 4 bytes big-endian and, for Ed25519, signature is 64 raw bytes → 68 bytes total.
  - What is signed: the note text bytes INCLUDING the final U+000A, EXCLUDING the separating empty line.
    Raw bytes — NO DSSE/PAE wrapping.
  - keyID = SHA-256(keyname_bytes ‖ 0x0A ‖ 0x01 ‖ pubkey[32])[:4]   (0x01 = Ed25519 signature type).
  - vkey (to distribute the key) = keyname + "+" + hex8(keyID) + "+" + base64(0x01 ‖ pubkey[32]).
"""
from __future__ import annotations

import base64
import hashlib
from typing import Optional

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .errors import BundleFormatError, UnsupportedError
from .signature import verify_ed25519

__all__ = ["checkpoint_note", "key_id", "vkey", "sign_checkpoint", "verify_checkpoint",
           "root_bytes_from_b64", "cosign_key_id", "cosign_vkey", "cosign_checkpoint",
           "cosign_key_id_mldsa", "cosign_vkey_mldsa", "cosign_checkpoint_mldsa",
           "verify_cosignature", "verify_witnessed_checkpoint"]

EM_DASH = "—"
_ED25519_SIG_TYPE = 0x01
_COSIG_V1_SIG_TYPE = 0x04           # C2SP tlog-cosignature, Ed25519 cosignature/v1
_COSIG_MLDSA_SIG_TYPE = 0x06        # C2SP tlog-cosignature, ML-DSA-44 (FIPS 204) — v1.3
_COSIG_V1_PREFIX = "cosignature/v1\n"
_MAX_COSIG_TIMESTAMP = 2**63 - 1    # spec: MUST NOT exceed 2^63 - 1
_MLDSA44_PUB_LEN = 1312             # FIPS 204 ML-DSA-44 public key bytes
_MLDSA44_SIG_LEN = 2420             # FIPS 204 ML-DSA-44 signature bytes
_MLDSA_LABEL = b"subtree/v1\n\x00"  # cosigned_message.label[12] — fixed 12 bytes


def _root_std_b64(root: bytes) -> str:
    """Standard RFC 4648 §4 base64 (with padding) of the raw Merkle root — NOT base64url."""
    return base64.b64encode(root).decode("ascii")


def checkpoint_note(origin: str, tree_size: int, root: bytes) -> str:
    """Build the C2SP checkpoint note text (3 lines + trailing newline). ``root`` is the raw RFC 6962
    Merkle root bytes at ``tree_size``. ``origin`` must be non-empty with no spaces/'+' (a schemeless URL)."""
    if not origin or "+" in origin or any(c.isspace() for c in origin):
        raise BundleFormatError("checkpoint origin must be a non-empty schemeless id without whitespace or '+'")
    if isinstance(tree_size, bool) or not isinstance(tree_size, int) or tree_size < 0:
        raise BundleFormatError("checkpoint tree_size must be a non-negative integer")
    return f"{origin}\n{tree_size}\n{_root_std_b64(root)}\n"


def key_id(keyname: str, pubkey: bytes) -> bytes:
    """C2SP note key ID = first 4 bytes of SHA-256(keyname ‖ 0x0A ‖ 0x01 ‖ 32-byte-Ed25519-pubkey)."""
    if len(pubkey) != 32:
        raise BundleFormatError("Ed25519 public key must be 32 raw bytes")
    h = hashlib.sha256(keyname.encode("utf-8") + b"\n" + bytes([_ED25519_SIG_TYPE]) + pubkey).digest()
    return h[:4]


def vkey(keyname: str, pubkey: bytes) -> str:
    """C2SP verifier key encoding: name + '+' + hex8(keyID) + '+' + base64(0x01 ‖ pubkey)."""
    kid = key_id(keyname, pubkey)
    kid_hex = f"{int.from_bytes(kid, 'big'):08x}"
    keymat = base64.b64encode(bytes([_ED25519_SIG_TYPE]) + pubkey).decode("ascii")
    return f"{keyname}+{kid_hex}+{keymat}"


def sign_checkpoint(origin: str, tree_size: int, root: bytes, signer, keyname: str) -> str:
    """Produce a signed C2SP checkpoint note. ``signer`` is an Ed25519 private key whose public key must
    correspond to ``keyname``. The signature is over the RAW note-text bytes (including the trailing
    newline), never over base64 and never PAE-wrapped."""
    if not keyname or "+" in keyname or any(c.isspace() for c in keyname):
        raise BundleFormatError("checkpoint keyname must be non-empty without whitespace or '+'")
    note = checkpoint_note(origin, tree_size, root)
    pubkey = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    sig = signer.sign(note.encode("utf-8"))
    kid = key_id(keyname, pubkey)
    sig_b64 = base64.b64encode(kid + sig).decode("ascii")
    sig_line = f"{EM_DASH} {keyname} {sig_b64}\n"
    return note + "\n" + sig_line


def _parse_vkey(vkey_str: str, sig_type: int = _ED25519_SIG_TYPE) -> tuple[str, bytes, bytes]:
    # RE-GATE never-raise consistency: a non-str vkey (None/int/list from a caller/config) is a typed
    # BundleFormatError, never a raw AttributeError from `.split` — this parse helper raises BundleFormatError
    # for every other malformed vkey, so a wrong-type vkey joins that contract instead of an untyped crash.
    if not isinstance(vkey_str, str):
        raise BundleFormatError("vkey must be a string (name+hexKeyID+base64KeyMaterial)")
    # The key material is standard base64, which can itself contain '+'. Since the name has no '+' (a
    # schemeless origin) and the hex keyID has none, the FIRST TWO '+' are the separators and everything
    # after is the base64 — so split with maxsplit=2, never a plain split (that would over-split the b64).
    parts = vkey_str.split("+", 2)
    if len(parts) != 3:
        raise BundleFormatError("vkey must have 3 '+'-separated parts (name+hexKeyID+base64KeyMaterial)")
    name, kid_hex, keymat_b64 = parts
    try:
        keymat = base64.b64decode(keymat_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise BundleFormatError("vkey key material is not valid base64") from exc
    if len(keymat) != 33 or keymat[0] != sig_type:
        raise BundleFormatError(
            f"vkey key material must be 0x{sig_type:02x} followed by a 32-byte Ed25519 key")
    pubkey = keymat[1:]
    try:
        kid = bytes.fromhex(kid_hex)
    except ValueError as exc:
        raise BundleFormatError("vkey keyID is not valid hex") from exc
    return name, kid, pubkey


def verify_checkpoint(signed_note: str, vkey_str: str) -> dict:
    """Verify a signed C2SP checkpoint against a vkey. Returns {ok, origin, tree_size, root}. ``ok`` is
    True iff a signature line whose keyID matches the vkey verifies (Ed25519) over the exact note-text
    bytes. Reconstructs the note text from the parsed bytes — never re-derives it."""
    name, kid_v, pubkey = _parse_vkey(vkey_str)
    # 6-lens DEEP gate L1-02 (never-raise): a non-str signed_note made `"\n\n" not in signed_note` raise a
    # raw TypeError out of the public verify_witnessed_checkpoint/verify_checkpoint surface — mirror the
    # isinstance(str) guard already on witness_vkey (_parse_witness_vkey, RE-GATE never-raise consistency).
    if not isinstance(signed_note, str):
        raise BundleFormatError("signed note must be a string (non-str is malformed, fail-closed)")
    # note text = everything up to (and including the \n before) the separating empty line
    if "\n\n" not in signed_note:
        raise BundleFormatError("signed note has no empty-line separator between text and signatures")
    note_text, sig_block = signed_note.split("\n\n", 1)
    note_text += "\n"                       # restore the trailing newline that belongs to the note text
    note_bytes = note_text.encode("utf-8")
    lines = note_text.split("\n")
    if len(lines) < 4 or not lines[0] or not lines[1] or not lines[2]:
        raise BundleFormatError("checkpoint note must have at least 3 non-empty lines")
    origin, size_s, root_b64 = lines[0], lines[1], lines[2]
    if len(size_s) > 20 or (size_s != "0" and (size_s.startswith("0") or not (size_s.isascii() and size_s.isdigit()))):
        raise BundleFormatError("checkpoint tree size must be ASCII decimal with no leading zeros")
    try:
        root = base64.b64decode(root_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise BundleFormatError("checkpoint root is not valid standard base64") from exc

    ok = False
    kid_expected = key_id(name, pubkey)
    for line in sig_block.split("\n"):
        if not line.startswith(EM_DASH + " "):
            continue
        rest = line[len(EM_DASH) + 1:]
        try:
            lname, payload_b64 = rest.split(" ", 1)
        except ValueError:
            continue
        if lname != name:
            continue
        try:
            payload = base64.b64decode(payload_b64, validate=True)
        except (ValueError, TypeError):
            continue
        if len(payload) < 4:
            continue
        kid, sig = payload[:4], payload[4:]
        if kid != kid_v or kid != kid_expected:   # keyID must match both the vkey and the recomputed id
            continue
        if verify_ed25519(pubkey, sig, note_bytes):
            ok = True
            break
    return {"ok": ok, "origin": origin, "tree_size": int(size_s), "root": root}


def root_bytes_from_b64(root_b64: str) -> Optional[bytes]:
    """Decode a bundle's standard-base64 Merkle root to raw bytes (for feeding into checkpoint_note)."""
    try:
        return base64.b64decode(root_b64, validate=True)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# C2SP tlog-cosignature (Ed25519 cosignature/v1) — v1.2.
#
# A cosignature is a witness's statement that it verified the CONSISTENCY of a
# checkpoint: verifying a quorum of cosignatures rules out a split view by the
# log operator, entirely offline. Spec verified 2026-07 against
# C2SP/C2SP tlog-cosignature.md:
#   - witness key ID = SHA-256(name ‖ 0x0A ‖ 0x04 ‖ pubkey[32])[:4]  (0x04 = cosignature/v1;
#     NOTE: intentionally different from the log's 0x01 — a log key can never
#     masquerade as a witness key, the key IDs cannot collide by construction).
#   - signature blob on the note line = keyID[4] ‖ u64-BIG-ENDIAN-timestamp ‖ sig[64].
#   - signed message = "cosignature/v1\n" + "time <ts>\n" + the WHOLE note body
#     (all three-plus lines including the final U+000A, excluding signature lines).
#   - timestamp is a POSIX timestamp, MUST NOT exceed 2^63-1; verifiers MAY
#     reject future timestamps — as a pure-offline tool with no trusted clock,
#     proofbundle exposes the timestamp and leaves freshness policy to the caller.
# ---------------------------------------------------------------------------


def cosign_key_id(witness_name: str, pubkey: bytes) -> bytes:
    """Cosignature/v1 key ID = SHA-256(name ‖ 0x0A ‖ 0x04 ‖ 32-byte-Ed25519-pubkey)[:4]."""
    if len(pubkey) != 32:
        raise BundleFormatError("Ed25519 public key must be 32 raw bytes")
    h = hashlib.sha256(witness_name.encode("utf-8") + b"\n"
                       + bytes([_COSIG_V1_SIG_TYPE]) + pubkey).digest()
    return h[:4]


def cosign_vkey(witness_name: str, pubkey: bytes) -> str:
    """Witness verifier key: name + '+' + hex8(keyID) + '+' + base64(0x04 ‖ pubkey)."""
    kid = cosign_key_id(witness_name, pubkey)
    kid_hex = f"{int.from_bytes(kid, 'big'):08x}"
    keymat = base64.b64encode(bytes([_COSIG_V1_SIG_TYPE]) + pubkey).decode("ascii")
    return f"{witness_name}+{kid_hex}+{keymat}"


def _note_text_of(signed_note: str) -> str:
    """The note body of a signed note: everything before the empty-line separator, newline restored."""
    # 6-lens DEEP gate L1-01 (never-raise): a non-str signed_note leaked a raw TypeError out of the public
    # verify_cosignature surface — same isinstance(str) guard class as verify_checkpoint.
    if not isinstance(signed_note, str):
        raise BundleFormatError("signed note must be a string (non-str is malformed, fail-closed)")
    if "\n\n" not in signed_note:
        raise BundleFormatError("signed note has no empty-line separator between text and signatures")
    note_text = signed_note.split("\n\n", 1)[0] + "\n"
    lines = note_text.split("\n")
    if len(lines) < 4 or not lines[0] or not lines[1] or not lines[2]:
        raise BundleFormatError("checkpoint note must have at least 3 non-empty lines")
    return note_text


def _cosigned_message(note_text: str, timestamp: int) -> bytes:
    """The Ed25519 cosignature/v1 signed message: header line + time line + whole note body."""
    return (_COSIG_V1_PREFIX + f"time {timestamp}\n" + note_text).encode("utf-8")


def cosign_checkpoint(signed_note: str, witness_signer, witness_name: str, timestamp: int) -> str:
    """Append a witness cosignature line to a signed checkpoint note (Ed25519 cosignature/v1).

    ``witness_signer`` is the witness's Ed25519 private key; ``timestamp`` is the POSIX time of
    observation (explicit — an offline library does not sample wall clocks for signatures).
    Returns the note with the cosignature line appended. Emitting a cosignature here is for
    tests/demos and self-witnessing pipelines; real split-view resistance needs INDEPENDENT
    witnesses, which is a deployment property, not a code property.
    """
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) \
            or not 0 <= timestamp <= _MAX_COSIG_TIMESTAMP:
        raise BundleFormatError("cosignature timestamp must be an integer in [0, 2^63-1]")
    if not witness_name or "+" in witness_name or any(c.isspace() for c in witness_name):
        raise BundleFormatError("witness name must be non-empty without spaces or '+'")
    note_text = _note_text_of(signed_note)
    if not signed_note.endswith("\n"):
        raise BundleFormatError("signed note must end with a newline")
    pubkey = witness_signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    sig = witness_signer.sign(_cosigned_message(note_text, timestamp))
    kid = cosign_key_id(witness_name, pubkey)
    blob = kid + timestamp.to_bytes(8, "big") + sig
    return signed_note + f"{EM_DASH} {witness_name} {base64.b64encode(blob).decode('ascii')}\n"


def cosign_key_id_mldsa(witness_name: str, pubkey: bytes) -> bytes:
    """ML-DSA-44 cosignature key ID = SHA-256(name ‖ 0x0A ‖ 0x06 ‖ 1312-byte pubkey)[:4]."""
    if len(pubkey) != _MLDSA44_PUB_LEN:
        raise BundleFormatError("ML-DSA-44 public key must be 1312 raw bytes")
    h = hashlib.sha256(witness_name.encode("utf-8") + b"\n"
                       + bytes([_COSIG_MLDSA_SIG_TYPE]) + pubkey).digest()
    return h[:4]


def cosign_vkey_mldsa(witness_name: str, pubkey: bytes) -> str:
    """ML-DSA-44 witness verifier key: name + '+' + hex8(keyID) + '+' + base64(0x06 ‖ pubkey)."""
    kid = cosign_key_id_mldsa(witness_name, pubkey)
    kid_hex = f"{int.from_bytes(kid, 'big'):08x}"
    keymat = base64.b64encode(bytes([_COSIG_MLDSA_SIG_TYPE]) + pubkey).decode("ascii")
    return f"{witness_name}+{kid_hex}+{keymat}"


def _mldsa_module():
    """Lazy ML-DSA import — needs `cryptography>=48` on an OpenSSL 3.5+ build (`[pq]` extra).
    Raises UnsupportedError (never ImportError) so a caller who configured an ML-DSA witness on
    a system without the capability gets a clear, fail-closed answer — not a silent False."""
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: PLC0415
        mldsa.MLDSA44PublicKey  # noqa: B018 — probe the class, backends without PQ lack it
        return mldsa
    except (ImportError, AttributeError) as exc:
        raise UnsupportedError(
            "ML-DSA-44 cosignatures need cryptography>=48 with an OpenSSL 3.5+ backend — "
            "install with: pip install \"proofbundle[pq]\"") from exc


def _opaque8(data: bytes) -> bytes:
    """RFC 8446 §3 opaque<1..2^8-1>: 1-byte length prefix + bytes."""
    if not 1 <= len(data) <= 255:
        raise BundleFormatError("opaque<1..2^8-1> value must be 1..255 bytes")
    return bytes([len(data)]) + data


def _mldsa_cosigned_message(cosigner_name: str, timestamp: int, origin: str,
                            tree_size: int, root: bytes) -> bytes:
    """C2SP cosigned_message struct for an ML-DSA-44 checkpoint cosignature: fixed 12-byte label
    "subtree/v1\\n\\0", cosigner_name, u64 timestamp, log_origin, u64 start (0 for a checkpoint),
    u64 end (= tree size), 32-byte root. Commits to the cosigner NAME (unlike Ed25519) and NOT to
    checkpoint extension lines (per spec)."""
    if len(root) != 32:
        raise BundleFormatError("checkpoint root must be 32 bytes")
    return (_MLDSA_LABEL
            + _opaque8(cosigner_name.encode("utf-8"))
            + timestamp.to_bytes(8, "big")
            + _opaque8(origin.encode("utf-8"))
            + (0).to_bytes(8, "big")            # start = 0: this signs a checkpoint, not a subtree
            + tree_size.to_bytes(8, "big")      # end = tree size
            + root)


def cosign_checkpoint_mldsa(signed_note: str, witness_signer, witness_name: str,
                            timestamp: int) -> str:
    """Append an ML-DSA-44 witness cosignature line (C2SP type 0x06 — the spec's SHOULD for new
    deployments). ``witness_signer`` is a cryptography MLDSA44PrivateKey. Same input rules as
    :func:`cosign_checkpoint`; the signature blob is keyID[4] ‖ u64-BE-timestamp ‖ sig[2420]."""
    _mldsa_module()                              # capability probe, fail-closed
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) \
            or not 0 <= timestamp <= _MAX_COSIG_TIMESTAMP:
        raise BundleFormatError("cosignature timestamp must be an integer in [0, 2^63-1]")
    if not witness_name or "+" in witness_name or any(c.isspace() for c in witness_name):
        raise BundleFormatError("witness name must be non-empty without spaces or '+'")
    note_text = _note_text_of(signed_note)
    if not signed_note.endswith("\n"):
        raise BundleFormatError("signed note must end with a newline")
    lines = note_text.split("\n")
    origin, size_s, root_b64 = lines[0], lines[1], lines[2]
    root = base64.b64decode(root_b64, validate=True)
    pubkey = witness_signer.public_key().public_bytes_raw()
    msg = _mldsa_cosigned_message(witness_name, timestamp, origin, int(size_s), root)
    sig = witness_signer.sign(msg)
    kid = cosign_key_id_mldsa(witness_name, pubkey)
    blob = kid + timestamp.to_bytes(8, "big") + sig
    return signed_note + f"{EM_DASH} {witness_name} {base64.b64encode(blob).decode('ascii')}\n"


def _parse_witness_vkey(vkey_str: str) -> tuple[str, bytes, bytes, int]:
    """Parse a witness vkey, dispatching on the algorithm byte: 0x04 (Ed25519 cosignature/v1,
    32-byte key) or 0x06 (ML-DSA-44, 1312-byte key). Any other byte/length is rejected —
    including 0x01: a LOG key must never be accepted as a witness (domain separation)."""
    # RE-GATE never-raise consistency (mirror _parse_vkey): a non-str witness vkey is a typed
    # BundleFormatError, never a raw AttributeError from `.split` (verify_cosignature routes here).
    if not isinstance(vkey_str, str):
        raise BundleFormatError("vkey must be a string (name+hexKeyID+base64KeyMaterial)")
    parts = vkey_str.split("+", 2)
    if len(parts) != 3:
        raise BundleFormatError("vkey must have 3 '+'-separated parts (name+hexKeyID+base64KeyMaterial)")
    name, kid_hex, keymat_b64 = parts
    try:
        keymat = base64.b64decode(keymat_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise BundleFormatError("vkey key material is not valid base64") from exc
    try:
        kid = bytes.fromhex(kid_hex)
    except ValueError as exc:
        raise BundleFormatError("vkey keyID is not valid hex") from exc
    if len(keymat) == 33 and keymat[0] == _COSIG_V1_SIG_TYPE:
        return name, kid, keymat[1:], _COSIG_V1_SIG_TYPE
    if len(keymat) == _MLDSA44_PUB_LEN + 1 and keymat[0] == _COSIG_MLDSA_SIG_TYPE:
        return name, kid, keymat[1:], _COSIG_MLDSA_SIG_TYPE
    raise BundleFormatError(
        "witness vkey must be 0x04+32-byte Ed25519 or 0x06+1312-byte ML-DSA-44 key material")


def verify_cosignature(signed_note: str, witness_vkey: str) -> dict:
    """Verify one witness cosignature on a signed checkpoint note.

    ``witness_vkey`` carries the algorithm in its key material: 0x04 = Ed25519 cosignature/v1,
    0x06 = ML-DSA-44 (v1.3; needs the `[pq]` extra, else UnsupportedError — fail-closed, never a
    silent False). Returns ``{ok, alg, origin, tree_size, root, timestamp}``; ``ok`` is True iff
    a signature line whose name AND key ID match the vkey carries a valid cosignature over this
    checkpoint. Timestamp freshness is caller policy (offline verifier, no trusted clock).
    """
    name, kid_v, pubkey, sig_type = _parse_witness_vkey(witness_vkey)
    note_text = _note_text_of(signed_note)
    lines = note_text.split("\n")
    origin, size_s, root_b64 = lines[0], lines[1], lines[2]
    if len(size_s) > 20 or (size_s != "0" and (size_s.startswith("0") or not (size_s.isascii() and size_s.isdigit()))):
        raise BundleFormatError("checkpoint tree size must be ASCII decimal with no leading zeros")
    try:
        root = base64.b64decode(root_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise BundleFormatError("checkpoint root is not valid standard base64") from exc

    alg = "ed25519-cosignature/v1" if sig_type == _COSIG_V1_SIG_TYPE else "ml-dsa-44"
    result = {"ok": False, "alg": alg, "origin": origin, "tree_size": int(size_s), "root": root,
              "timestamp": None}
    if sig_type == _COSIG_V1_SIG_TYPE:
        kid_expected = cosign_key_id(name, pubkey)
        blob_len = 4 + 8 + 64
    else:
        kid_expected = cosign_key_id_mldsa(name, pubkey)
        blob_len = 4 + 8 + _MLDSA44_SIG_LEN
        mldsa = _mldsa_module()                  # raise BEFORE scanning lines — fail-closed
        mldsa_pub = mldsa.MLDSA44PublicKey.from_public_bytes(pubkey)

    sig_block = signed_note.split("\n\n", 1)[1]
    for line in sig_block.split("\n"):
        if not line.startswith(EM_DASH + " "):
            continue
        rest = line[len(EM_DASH) + 1:]
        try:
            lname, payload_b64 = rest.split(" ", 1)
        except ValueError:
            continue
        if lname != name:
            continue
        try:
            payload = base64.b64decode(payload_b64, validate=True)
        except (ValueError, TypeError):
            continue
        if len(payload) != blob_len:             # keyID[4] ‖ u64 ts ‖ signature — exact length
            continue
        kid, ts_bytes, sig = payload[:4], payload[4:12], payload[12:]
        if kid != kid_v or kid != kid_expected:
            continue
        timestamp = int.from_bytes(ts_bytes, "big")
        if timestamp > _MAX_COSIG_TIMESTAMP:
            continue
        if sig_type == _COSIG_V1_SIG_TYPE:
            sig_ok = verify_ed25519(pubkey, sig, _cosigned_message(note_text, timestamp))
        else:
            try:
                # build the signed message INSIDE the guard (release-review fix #6): attacker-controlled
                # name/origin/size must not escape as a raw exception from the message construction.
                msg = _mldsa_cosigned_message(name, timestamp, origin, int(size_s), root)
                mldsa_pub.verify(sig, msg)
                sig_ok = True
            except Exception:  # noqa: BLE001 — InvalidSignature and backend errors both mean no
                sig_ok = False
        if sig_ok:
            result["ok"] = True
            result["timestamp"] = timestamp
            break
    return result


def _witness_key_material(vkey: str) -> bytes:
    """The DECODED key material (sig-type byte ‖ pubkey) of a cosignature vkey — the identity to dedup a quorum
    by. NOT the name (a single key can wear many names) and NOT the raw base64 substring (padding can vary while
    the bytes are equal). name+keyID contain no '+'; the base64 keymat is everything after the second '+'."""
    return base64.b64decode(vkey.split("+", 2)[2])


def witness_quorum(signed_note: str, witness_vkeys, threshold: int):
    """Shared k-of-n witness quorum (release-review fix): counts DISTINCT witness KEY MATERIAL, not names —
    C2SP requires operators to use distinct keys per cosigner, so one physical key under N names is ONE witness.
    Alg-agnostic (Ed25519 0x04 + ML-DSA 0x06). Used by BOTH verify_witnessed_checkpoint AND tlogproof.
    verify_tlog_proof so the hardening can never drift between the two call sites again. Returns
    (witnesses_ok, witnesses_dict); the dict is keyed by name+keyID so a same-name-different-key entry does not
    overwrite. Fail-closed: an unparseable witness vkey raises (verify_cosignature); a non-verifying one is False."""
    keys_ok = set()
    witnesses = {}
    for wv in witness_vkeys:
        res = verify_cosignature(signed_note, wv)
        witnesses["+".join(wv.split("+")[:2])] = res
        if res["ok"]:
            keys_ok.add(_witness_key_material(wv))
    return len(keys_ok) >= threshold, witnesses


def verify_witnessed_checkpoint(signed_note: str, log_vkey: str, witness_vkeys, *,
                                threshold: int = 1) -> dict:
    """Verify a checkpoint is BOTH log-signed and witnessed by ``threshold`` distinct witnesses.

    The log signature (0x01) is always required — witnesses attest consistency, they do not
    replace the log's own signature. Returns ``{ok, log_ok, witnesses_ok, witnesses, origin,
    tree_size, root}`` where ``witnesses`` maps each vkey's name to its cosignature result.
    Fail-closed: an unparseable witness vkey raises; a non-verifying one counts as False.
    """
    if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 1:
        raise BundleFormatError("witness threshold must be a positive integer")
    log_res = verify_checkpoint(signed_note, log_vkey)
    witnesses_ok, witnesses = witness_quorum(signed_note, witness_vkeys, threshold)
    return {"ok": bool(log_res["ok"]) and witnesses_ok, "log_ok": log_res["ok"],
            "witnesses_ok": witnesses_ok, "witnesses": witnesses,
            "origin": log_res["origin"], "tree_size": log_res["tree_size"],
            "root": log_res["root"]}
