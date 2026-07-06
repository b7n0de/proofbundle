"""Chia DataLayer anchor (``chia-datalayer/v1``) — the first first-party extension anchor type.

This is the **offline Merkle verifier** (level i of the three-level honesty documented in ``docs/ANCHORS.md``):
it proves, with **pure SHA-256 and NO Chia software**, that a key/value pair is included under a published
DataLayer root. It does NOT prove the chain binding (that the ``published_root`` is actually an unspent
singleton on the heaviest chain) — that is level ii (light wallet) / level iii (own full node), which need
Chia software and are reported separately, never conflated here.

Wire facts (Chia 2.7.x / chia_rs datalayer, pinned in the adapter spec; re-check against the live version
before trusting — Chia moves modules): a DataLayer ``get_proof`` yields, per key:

    key_clvm_hash  = CLVM tree hash of the key atom   = sha256(0x01 ‖ key_atom)
    value_clvm_hash= CLVM tree hash of the value atom = sha256(0x01 ‖ value_atom)
    node_hash (leaf) = sha256(0x02 ‖ key_clvm_hash ‖ value_clvm_hash)
    internal node    = sha256(0x02 ‖ left ‖ right)
    ascent: each layer carries other_hash_side (0=LEFT sibling / 1=RIGHT sibling), other_hash, combined_hash
    root = layers[-1].combined_hash   (or node_hash when layers == [])

The anchor's ``proof`` field (base64 in the bundle, decoded to bytes by ``verify_anchor``) is the **UTF-8 JSON**
of a proof object with those hex fields; ``canonical_root`` is the ``value_digest`` the anchor stamps.

Fail-closed: any structural problem, hash mismatch, or ascent inconsistency returns ``{"ok": False, ...}``.
Never raises for an ordinary bad proof.
"""

from __future__ import annotations

import hashlib
import json
from typing import Optional

ANCHOR_TYPE = "chia-datalayer/v1"

# CLVM tree-hash / node-hash domain-separation prefixes (Chia DataLayer Merkle set).
_ATOM_PREFIX = b"\x01"   # sha256(0x01 ‖ atom) = CLVM tree hash of an atom
_NODE_PREFIX = b"\x02"   # sha256(0x02 ‖ left ‖ right) = internal/leaf node hash

_HASH_LEN = 32           # sha256 digest length
_MAX_LAYERS = 256        # a DataLayer tree of 2**256 leaves is absurd; bound the ascent (DoS guard)
_MAX_PROOF_BYTES = 131072  # real chia-datalayer proofs are ~2.5 KB; cap the input before json.loads (DoS guard)


def _h(*parts: bytes) -> bytes:
    m = hashlib.sha256()
    for p in parts:
        m.update(p)
    return m.digest()


def _hexatom(value, field: str) -> bytes:
    """Decode an arbitrary-length hex string (optionally 0x-prefixed) to bytes. DataLayer keys/values are
    atoms of any length — only the HASHES are fixed at 32 bytes (see _hexbytes)."""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a hex string")
    s = value[2:] if value[:2] in ("0x", "0X") else value
    return bytes.fromhex(s)   # raises ValueError on non-hex / odd length


def _hexbytes(value, field: str) -> bytes:
    """Decode a 32-byte hash hex string (optionally 0x-prefixed) to bytes, else raise ValueError."""
    b = _hexatom(value, field)
    if len(b) != _HASH_LEN:
        raise ValueError(f"{field} must be {_HASH_LEN} bytes (got {len(b)})")
    return b


def clvm_atom_hash(atom: bytes) -> bytes:
    """CLVM tree hash of a raw atom: sha256(0x01 ‖ atom). Public helper (Paket 1 anchor-add reuses it)."""
    return _h(_ATOM_PREFIX, atom)


def leaf_node_hash(key_clvm_hash: bytes, value_clvm_hash: bytes) -> bytes:
    """DataLayer leaf hash: sha256(0x02 ‖ key_clvm_hash ‖ value_clvm_hash)."""
    return _h(_NODE_PREFIX, key_clvm_hash, value_clvm_hash)


def merkle_root_from_layers(node_hash: bytes, inclusion_layers: list) -> bytes:
    """Recompute the DataLayer root by ascending ``inclusion_layers`` from ``node_hash``.

    Each layer is ``{"other_hash_side": 0|1, "other_hash": hex, "combined_hash": hex}``. ``other_hash_side``
    is the side of the SIBLING: 0 = sibling on the LEFT → sha256(0x02 ‖ other ‖ cur); 1 = sibling on the
    RIGHT → sha256(0x02 ‖ cur ‖ other). Each layer's declared ``combined_hash`` MUST equal the recomputed
    value (fail-closed) — this is what makes the proof self-consistent, not just plausible.

    Returns the root bytes. Raises ValueError on any structural/consistency problem.
    """
    if not isinstance(inclusion_layers, list):
        raise ValueError("inclusion_layers must be a list")
    if len(inclusion_layers) > _MAX_LAYERS:
        raise ValueError("inclusion_layers too deep")
    cur = node_hash
    for i, layer in enumerate(inclusion_layers):
        if not isinstance(layer, dict):
            raise ValueError(f"layer {i} must be an object")
        side = layer.get("other_hash_side")
        if side not in (0, 1):
            raise ValueError(f"layer {i} other_hash_side must be 0 (LEFT) or 1 (RIGHT)")
        other = _hexbytes(layer.get("other_hash"), f"layer {i} other_hash")
        declared = _hexbytes(layer.get("combined_hash"), f"layer {i} combined_hash")
        combined = _h(_NODE_PREFIX, other, cur) if side == 0 else _h(_NODE_PREFIX, cur, other)
        if combined != declared:
            raise ValueError(f"layer {i} combined_hash inconsistent with the recomputed hash")
        cur = combined
    return cur


def verify_offline_merkle(proof_obj: dict, canonical_root: bytes) -> dict:
    """Pure offline verification (level i). ``proof_obj`` is the decoded chia-datalayer proof dict.

    The BINDING to the target is via the DataLayer KEY: the anchor's ``canonicalRoot`` IS the key stored in
    the store (``key = canonicalRoot``), so the proof must carry the raw ``key``, it must EQUAL
    ``canonical_root``, and it must be the atom that hashes (``sha256(0x01‖key)``) to ``key_clvm_hash`` — whose
    leaf ascends through ``inclusion_layers`` to ``published_root``. This ties ``canonical_root``
    cryptographically to the Merkle path; an unrelated (even genuine) proof for a DIFFERENT key can no longer
    be relabelled to this target by swapping a decoupled digest field.

    Checks, all fail-closed:
      1. raw ``key`` present AND == ``canonical_root`` AND ``sha256(0x01‖key) == key_clvm_hash``
      2. (optional) raw ``value`` → ``sha256(0x01‖value) == value_clvm_hash``
      3. leaf ``node_hash == sha256(0x02‖key_clvm‖value_clvm)`` (when declared)
      4. ascending ``inclusion_layers`` reproduces ``published_root`` (each layer's combined_hash self-consistent)

    Proves ONLY that ``canonical_root`` is a key included under ``published_root``; NOT that ``published_root``
    is on-chain (that is level ii/iii, needs Chia software — see docs/ANCHORS.md).
    """
    try:
        key_clvm = _hexbytes(proof_obj.get("key_clvm_hash"), "key_clvm_hash")
        value_clvm = _hexbytes(proof_obj.get("value_clvm_hash"), "value_clvm_hash")
        published_root = _hexbytes(proof_obj.get("published_root"), "published_root")
        layers = proof_obj.get("inclusion_layers")

        # (1) BINDING — the raw DataLayer key IS the target canonicalRoot, and it is the atom under key_clvm_hash.
        raw_key = proof_obj.get("key")
        if not isinstance(raw_key, str) or not raw_key:
            return {"ok": False, "detail": "proof missing the raw key (required to bind canonicalRoot to the leaf)"}
        key_bytes = _hexatom(raw_key, "key")
        if key_bytes != canonical_root:
            return {"ok": False, "detail": "the anchored DataLayer key does not equal the target canonicalRoot (cross-target/tampered/forged)"}
        if clvm_atom_hash(key_bytes) != key_clvm:
            return {"ok": False, "detail": "key_clvm_hash does not match sha256(0x01 || key)"}

        # (2) optional: raw value atom (ANY length) → value_clvm_hash
        raw_value = proof_obj.get("value")
        if isinstance(raw_value, str) and raw_value:
            if clvm_atom_hash(_hexatom(raw_value, "value")) != value_clvm:
                return {"ok": False, "detail": "value_clvm_hash does not match sha256(0x01 || value)"}

        # (3) leaf hash
        leaf = leaf_node_hash(key_clvm, value_clvm)
        declared_node = proof_obj.get("node_hash")
        if declared_node is not None and _hexbytes(declared_node, "node_hash") != leaf:
            return {"ok": False, "detail": "node_hash does not match sha256(0x02 || key_clvm || value_clvm)"}

        # (4) ascend to the root
        root = merkle_root_from_layers(leaf, layers if layers is not None else [])
        if root != published_root:
            return {"ok": False, "detail": "inclusion_layers do not reproduce published_root (not included)"}

    except ValueError as exc:
        return {"ok": False, "detail": f"malformed chia-datalayer proof: {exc}"}
    return {"ok": True, "detail": "chia-datalayer merkle: canonicalRoot (as DataLayer key) included under published_root (level i, offline; chain binding NOT checked here)"}


def verify_chia_datalayer(proof: bytes, canonical_root: bytes, *, frozen: Optional[dict] = None,
                          now: Optional[int] = None) -> dict:
    """Registered anchor verifier for ``chia-datalayer/v1`` (see ``register_anchor_type``).

    ``proof`` is the UTF-8 JSON of the proof object; ``canonical_root`` is the target's root bytes. Returns
    ``{"ok", "warn", "status", "detail"}``, fail-closed. LEVEL i ONLY: proves the Merkle inclusion under the
    published root offline; it deliberately does NOT assert the chain binding (an anchor that is Merkle-valid
    but whose published_root was never on-chain would pass HERE — the honest, documented boundary; a relying
    party who needs the chain binding runs level ii/iii with Chia software, see docs/ANCHORS.md).
    """
    if not isinstance(proof, (bytes, bytearray)):
        return {"ok": False, "warn": False, "status": "fail", "detail": "chia-datalayer proof must be bytes"}
    if len(proof) > _MAX_PROOF_BYTES:
        return {"ok": False, "warn": False, "status": "fail", "detail": f"chia-datalayer proof too large (> {_MAX_PROOF_BYTES} bytes)"}
    # Unconditional fail-closed backstop: a verifier must NEVER crash its caller on a hostile proof. Enumerating
    # exception types (ValueError, ...) misses RecursionError (deeply nested JSON), MemoryError, or a TypeError
    # from a non-bytes canonical_root — all of which a caller-controlled proof could trigger. Catch everything.
    try:
        proof_obj = json.loads(bytes(proof).decode("utf-8"))
        if not isinstance(proof_obj, dict):
            return {"ok": False, "warn": False, "status": "fail", "detail": "chia-datalayer proof JSON must be an object"}
        res = verify_offline_merkle(proof_obj, bytes(canonical_root))
    except Exception as exc:   # noqa: BLE001 - deliberate fail-closed backstop for ANY hostile input
        return {"ok": False, "warn": False, "status": "fail", "detail": f"chia-datalayer proof rejected (fail-closed): {type(exc).__name__}"}
    ok = bool(res.get("ok"))
    return {"ok": ok, "warn": False, "status": "pass" if ok else "fail", "detail": res.get("detail", "")}
