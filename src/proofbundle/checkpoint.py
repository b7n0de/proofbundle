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

__all__ = ["checkpoint_note", "key_id", "vkey", "sign_checkpoint", "verify_checkpoint", "root_bytes_from_b64"]

EM_DASH = "—"
_ED25519_SIG_TYPE = 0x01


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


def _parse_vkey(vkey_str: str) -> tuple[str, bytes, bytes]:
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
    if len(keymat) != 33 or keymat[0] != _ED25519_SIG_TYPE:
        raise BundleFormatError("vkey key material must be 0x01 followed by a 32-byte Ed25519 key")
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
