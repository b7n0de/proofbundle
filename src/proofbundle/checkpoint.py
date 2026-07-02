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

from .errors import BundleFormatError
from .signature import verify_ed25519

__all__ = ["checkpoint_note", "key_id", "vkey", "sign_checkpoint", "verify_checkpoint",
           "root_bytes_from_b64", "cosign_key_id", "cosign_vkey", "cosign_checkpoint",
           "verify_cosignature", "verify_witnessed_checkpoint"]

EM_DASH = "—"
_ED25519_SIG_TYPE = 0x01
_COSIG_V1_SIG_TYPE = 0x04           # C2SP tlog-cosignature, Ed25519 cosignature/v1
_COSIG_V1_PREFIX = "cosignature/v1\n"
_MAX_COSIG_TIMESTAMP = 2**63 - 1    # spec: MUST NOT exceed 2^63 - 1


def _root_std_b64(root: bytes) -> str:
    """Standard RFC 4648 §4 base64 (with padding) of the raw Merkle root — NOT base64url."""
    return base64.b64encode(root).decode("ascii")


def checkpoint_note(origin: str, tree_size: int, root: bytes) -> str:
    """Build the C2SP checkpoint note text (3 lines + trailing newline). ``root`` is the raw RFC 6962
    Merkle root bytes at ``tree_size``. ``origin`` must be non-empty with no spaces/'+' (a schemeless URL)."""
    if not origin or " " in origin or "+" in origin or "\n" in origin:
        raise BundleFormatError("checkpoint origin must be a non-empty schemeless id without spaces or '+'")
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
    note = checkpoint_note(origin, tree_size, root)
    pubkey = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    sig = signer.sign(note.encode("utf-8"))
    kid = key_id(keyname, pubkey)
    sig_b64 = base64.b64encode(kid + sig).decode("ascii")
    sig_line = f"{EM_DASH} {keyname} {sig_b64}\n"
    return note + "\n" + sig_line


def _parse_vkey(vkey_str: str, sig_type: int = _ED25519_SIG_TYPE) -> tuple[str, bytes, bytes]:
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
    if size_s != "0" and (size_s.startswith("0") or not size_s.isdigit()):
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
    if not witness_name or " " in witness_name or "+" in witness_name or "\n" in witness_name:
        raise BundleFormatError("witness name must be non-empty without spaces or '+'")
    note_text = _note_text_of(signed_note)
    if not signed_note.endswith("\n"):
        raise BundleFormatError("signed note must end with a newline")
    pubkey = witness_signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    sig = witness_signer.sign(_cosigned_message(note_text, timestamp))
    kid = cosign_key_id(witness_name, pubkey)
    blob = kid + timestamp.to_bytes(8, "big") + sig
    return signed_note + f"{EM_DASH} {witness_name} {base64.b64encode(blob).decode('ascii')}\n"


def verify_cosignature(signed_note: str, witness_vkey: str) -> dict:
    """Verify one witness cosignature on a signed checkpoint note.

    ``witness_vkey`` is a cosignature/v1 verifier key (algorithm byte 0x04). Returns
    ``{ok, origin, tree_size, root, timestamp}``; ``ok`` is True iff a signature line whose
    name AND key ID match the vkey carries a valid Ed25519 cosignature/v1 over this exact
    note body. Timestamp freshness is caller policy (offline verifier, no trusted clock).
    """
    name, kid_v, pubkey = _parse_vkey(witness_vkey, _COSIG_V1_SIG_TYPE)
    note_text = _note_text_of(signed_note)
    lines = note_text.split("\n")
    origin, size_s, root_b64 = lines[0], lines[1], lines[2]
    if size_s != "0" and (size_s.startswith("0") or not size_s.isdigit()):
        raise BundleFormatError("checkpoint tree size must be ASCII decimal with no leading zeros")
    try:
        root = base64.b64decode(root_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise BundleFormatError("checkpoint root is not valid standard base64") from exc

    result = {"ok": False, "origin": origin, "tree_size": int(size_s), "root": root,
              "timestamp": None}
    kid_expected = cosign_key_id(name, pubkey)
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
        # keyID[4] ‖ timestamp[8, big-endian] ‖ ed25519 signature[64] = 76 bytes exactly.
        if len(payload) != 76:
            continue
        kid, ts_bytes, sig = payload[:4], payload[4:12], payload[12:]
        if kid != kid_v or kid != kid_expected:
            continue
        timestamp = int.from_bytes(ts_bytes, "big")
        if timestamp > _MAX_COSIG_TIMESTAMP:
            continue
        if verify_ed25519(pubkey, sig, _cosigned_message(note_text, timestamp)):
            result["ok"] = True
            result["timestamp"] = timestamp
            break
    return result


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
    keys_ok = set()
    witnesses = {}
    for wv in witness_vkeys:
        res = verify_cosignature(signed_note, wv)
        # HIGH fix (release review 2026-07-02): the quorum counts DISTINCT KEY MATERIAL, not names. One physical
        # Ed25519 key registered under N different names is ONE witness — C2SP requires operators to use distinct
        # keys per cosigner, so name-only dedup let a single compromised key stuff any threshold=N quorum (defeating
        # the split-view resistance that is the whole point of witnessing). _parse_vkey already ran inside
        # verify_cosignature (fail-closed: unparseable → raised there), so it is safe to re-derive the pubkey.
        _wname, _wkid, _wpub = _parse_vkey(wv, _COSIG_V1_SIG_TYPE)
        # index by name+keyID so a same-name-different-key entry does not overwrite (LOW #11 report fidelity).
        witnesses["+".join(wv.split("+")[:2])] = res
        if res["ok"]:
            keys_ok.add(_wpub)
    witnesses_ok = len(keys_ok) >= threshold
    return {"ok": bool(log_res["ok"]) and witnesses_ok, "log_ok": log_res["ok"],
            "witnesses_ok": witnesses_ok, "witnesses": witnesses,
            "origin": log_res["origin"], "tree_size": log_res["tree_size"],
            "root": log_res["root"]}
