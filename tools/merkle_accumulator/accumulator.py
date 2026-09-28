#!/usr/bin/env python3
"""An append-only RFC 6962 accumulator: the root and the new leaf's path without rebuilding the history.

emit_bundle (src/proofbundle/emit.py) builds `list(prior_leaves) + [payload]` and recomputes the root and
the inclusion path over the whole list on every call: about 4(n+1) SHA-256 calls for a history of n
leaves (counted by benchmarks/runtime_baseline/run.py). This accumulator keeps what an append needs and
nothing it can recompute from that.

WHAT IT KEEPS, AND WHAT THAT IS ENOUGH FOR
- The frontier: the roots of the perfect subtrees that the binary decomposition of the tree size gives,
  largest (leftmost) first, one per set bit of the size. From it an append computes the new root and the
  new leaf's inclusion path with one leaf hash, one node hash per carry, and one per remaining frontier
  root: at most 1 + 2 * floor(log2(n)) + 1 hashes for tree size n, whatever the history. The root is the
  frontier folded from the right; the path is the carried-away roots in the order they merged, then the
  remaining frontier roots from right to left. Both are the RFC 6962 values, byte for byte (tested
  against merkle_tree_hash and inclusion_proof at every size up to 2^12 + 1).
- Optionally, the leaf hashes in order (32 bytes per leaf). The frontier alone cannot give a proof for an
  older leaf or a consistency proof from an older size: those need nodes the frontier merged away. With
  the leaf hashes kept, `inclusion_proof_at` and `consistency_proof_from` give them, identical to the
  merkle module's; each costs O(n) node hashes, because interior nodes are not stored. Keeping every
  interior node (about 2n hashes) would bring that to O(log n); it is not done. Without the leaf hashes,
  the limit is: the root at the current size and the path of the leaf just appended, nothing older.

THE ARGUMENT IS LEAF DATA, as in merkle_tree_hash: `append(data)` applies the leaf hash itself (RFC 6962
section 2.1, the reading pinned in tests/test_merkle_zwei_lesarten_vektoren.py).

PERSISTED STATE AND THE RESTART RULE
`state(signer)` returns the frontier, the size and the root, signed by the emitter's Ed25519 key over the
RFC 8785 form of the state; the signed content says what it is (`what_is_signed`), so a state signature can
never be read as a receipt of an event. `MerkleAccumulator.restore(state, public_key)` refuses (raises
AccumulatorStateError) a state whose signature does not verify under the pinned key, whose format is
another, whose frontier does not have one root per set bit of the size, whose root is not the fold of its
frontier, or, when leaf hashes are given, whose leaf hashes do not reproduce the frontier and the size. It
never rebuilds a refused state; rebuilding from the leaves is `from_leaves`, a separate and deliberate
call.

A BATCH ROOT IS ANOTHER STATEMENT. emit_bundle signs each event's payload; the tree root in the bundle is
not signed. The state signature signs a tree state, not an event, and says so in its content. Nothing here
turns one into the other.
"""
from __future__ import annotations

import base64
import hashlib
from typing import List, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import merkle
from proofbundle._wire_b64 import decode_b64
from proofbundle.canonical import canonicalize_statement
from proofbundle.emit import SCHEMA
from proofbundle.errors import ProofBundleError
from proofbundle.signature import verify_ed25519_pinned

STATE_FORMAT = "proofbundle-merkle-accumulator-state/1"
WHAT_IS_SIGNED = ("the state of an append-only RFC 6962 tree (its size, frontier and root), not any event; "
                  "no receipt of an event may be read from this signature")


class AccumulatorStateError(ValueError):
    """A persisted state that does not verify. It is refused, never rebuilt."""


def _leaf(data: bytes) -> bytes:
    return merkle.leaf_hash(data)          # looked up at call time, so a counter can wrap it


def _node(left: bytes, right: bytes) -> bytes:
    return merkle._node_hash(left, right)  # noqa: SLF001 - the one RFC 6962 node hash of the package


class MerkleAccumulator:
    """Append-only; `size` leaves so far; `frontier` as (height, root) pairs, leftmost first."""

    def __init__(self, keep_leaf_hashes: bool = False) -> None:
        self.size = 0
        self.frontier: List[tuple] = []
        self.leaf_hashes: Optional[List[bytes]] = [] if keep_leaf_hashes else None

    def copy(self) -> "MerkleAccumulator":
        neu = MerkleAccumulator()
        neu.size, neu.frontier = self.size, list(self.frontier)
        neu.leaf_hashes = None if self.leaf_hashes is None else list(self.leaf_hashes)
        return neu

    # -- appending ----------------------------------------------------------------------------------------

    def append(self, data: bytes) -> tuple:
        """Append one leaf's data. Returns (root, inclusion path of that leaf): what merkle_tree_hash and
        inclusion_proof over the whole list would give."""
        wert = _leaf(data)
        if self.leaf_hashes is not None:
            self.leaf_hashes.append(wert)
        hoehe, pfad = 0, []
        while self.frontier and self.frontier[-1][0] == hoehe:
            links = self.frontier.pop()[1]
            pfad.append(links)
            wert = _node(links, wert)
            hoehe += 1
        self.frontier.append((hoehe, wert))
        self.size += 1
        wurzel = wert
        for _, links in reversed(self.frontier[:-1]):
            pfad.append(links)
            wurzel = _node(links, wurzel)
        return wurzel, pfad

    def root(self) -> bytes:
        if not self.frontier:
            return hashlib.sha256(b"").digest()   # merkle_tree_hash([]), RFC 6962 MTH of the empty list
        wurzel = self.frontier[-1][1]
        for _, links in reversed(self.frontier[:-1]):
            wurzel = _node(links, wurzel)
        return wurzel

    # -- later proofs, from the kept leaf hashes ------------------------------------------------------------

    def _need_leaf_hashes(self) -> List[bytes]:
        if self.leaf_hashes is None:
            raise ValueError("this accumulator keeps no leaf hashes: only the root and the path of the leaf "
                             "just appended are available")
        return self.leaf_hashes

    def inclusion_proof_at(self, index: int) -> List[bytes]:
        blaetter = self._need_leaf_hashes()
        if not 0 <= index < len(blaetter):
            raise ValueError("index out of range")
        return _inclusion(blaetter, index)

    def consistency_proof_from(self, first: int) -> List[bytes]:
        blaetter = self._need_leaf_hashes()
        if not 0 < first <= len(blaetter):
            raise ValueError("require 0 < first <= size")
        return _subproof(first, blaetter, True)

    # -- persisting ----------------------------------------------------------------------------------------

    def _unsigned_state(self) -> dict:
        return {"format": STATE_FORMAT, "what_is_signed": WHAT_IS_SIGNED, "tree_size": self.size,
                "frontier": [{"height": h, "root": r.hex()} for h, r in self.frontier], "root": self.root().hex(),
                "leaf_hashes_sha256": (hashlib.sha256(b"".join(self.leaf_hashes)).hexdigest()
                                       if self.leaf_hashes is not None else None)}

    def state(self, signer: Ed25519PrivateKey) -> dict:
        inhalt = self._unsigned_state()
        signatur = signer.sign(canonicalize_statement(inhalt))
        return {"state": inhalt, "signature": base64.b64encode(signatur).decode("ascii")}

    @classmethod
    def restore(cls, gespeichert: dict, public_key: bytes, leaf_hashes: Optional[List[bytes]] = None
                ) -> "MerkleAccumulator":
        """Restart from a persisted state. Refuses, never rebuilds: see the module docstring."""
        # The signature is decoded by the house's strict decoder (one wire form per signature), the state
        # canonicalized as it was signed, and the pinned key checked as a trust anchor: a malformed,
        # non-canonical or low-order key refuses the state before any signature arithmetic.
        try:
            inhalt, signatur = gespeichert["state"], decode_b64(gespeichert["signature"])
            nachricht = canonicalize_statement(inhalt)
        except (KeyError, TypeError, ValueError, ProofBundleError) as exc:
            raise AccumulatorStateError(f"the state's signature does not verify under the pinned key "
                                        f"({type(exc).__name__})") from exc
        if not verify_ed25519_pinned(public_key, signatur, nachricht):
            raise AccumulatorStateError("the state's signature does not verify under the pinned key")
        if inhalt.get("format") != STATE_FORMAT or inhalt.get("what_is_signed") != WHAT_IS_SIGNED:
            raise AccumulatorStateError("the state is not in the format this accumulator writes")
        groesse = inhalt.get("tree_size")
        if type(groesse) is not int or groesse < 0:
            raise AccumulatorStateError("the state's tree_size is not a size")
        try:
            front = [(int(e["height"]), bytes.fromhex(e["root"])) for e in inhalt["frontier"]]
        except (KeyError, TypeError, ValueError) as exc:
            raise AccumulatorStateError("the state's frontier is not a list of height and root") from exc
        hoehen = [h for h, _ in front]
        erwartet = [i for i in range(groesse.bit_length() - 1, -1, -1) if groesse >> i & 1]
        if hoehen != erwartet or any(len(r) != 32 for _, r in front):
            raise AccumulatorStateError("the frontier does not have one root per set bit of the size")
        neu = cls(keep_leaf_hashes=leaf_hashes is not None)
        neu.size, neu.frontier = groesse, front
        if neu.root().hex() != inhalt.get("root"):
            raise AccumulatorStateError("the stated root is not the fold of the frontier")
        if leaf_hashes is not None:
            if len(leaf_hashes) != groesse or hashlib.sha256(b"".join(leaf_hashes)).hexdigest() != inhalt.get(
                    "leaf_hashes_sha256"):
                raise AccumulatorStateError("the leaf hashes are not the ones the state was written with")
            probe = cls._frontier_from_leaf_hashes(leaf_hashes)
            if probe != front:
                raise AccumulatorStateError("the leaf hashes do not reproduce the frontier")
            neu.leaf_hashes = list(leaf_hashes)
        return neu

    @staticmethod
    def _frontier_from_leaf_hashes(hashes: List[bytes]) -> list:
        front: list = []
        for wert in hashes:
            hoehe = 0
            while front and front[-1][0] == hoehe:
                wert = _node(front.pop()[1], wert)
                hoehe += 1
            front.append((hoehe, wert))
        return front

    @classmethod
    def from_leaves(cls, leaves: List[bytes], keep_leaf_hashes: bool = False) -> "MerkleAccumulator":
        """A deliberate rebuild from the whole history: O(n) hashes, never done by `restore`."""
        neu = cls(keep_leaf_hashes=keep_leaf_hashes)
        for blatt in leaves:
            neu.append(blatt)
        return neu


def _tree_hash(hashes: List[bytes]) -> bytes:
    n = len(hashes)
    if n == 1:
        return hashes[0]
    k = 1
    while k * 2 < n:
        k *= 2
    return _node(_tree_hash(hashes[:k]), _tree_hash(hashes[k:]))


def _inclusion(hashes: List[bytes], m: int) -> List[bytes]:
    n = len(hashes)
    if n == 1:
        return []
    k = 1
    while k * 2 < n:
        k *= 2
    if m < k:
        return _inclusion(hashes[:k], m) + [_tree_hash(hashes[k:])]
    return _inclusion(hashes[k:], m - k) + [_tree_hash(hashes[:k])]


def _subproof(m: int, hashes: List[bytes], b: bool) -> List[bytes]:
    n = len(hashes)
    if m == n:
        return [] if b else [_tree_hash(hashes)]
    k = 1
    while k * 2 < n:
        k *= 2
    if m <= k:
        return _subproof(m, hashes[:k], b) + [_tree_hash(hashes[k:])]
    return _subproof(m - k, hashes[k:], False) + [_tree_hash(hashes[:k])]


def emit_bundle_incremental(payload: bytes, signer: Ed25519PrivateKey, accumulator: MerkleAccumulator) -> dict:
    """The bundle emit_bundle(payload, signer, prior_leaves=<the accumulator's leaves>) returns, built from
    the accumulator: the same bytes, the same per-event signature over the payload. Appends the payload."""
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415

    index = accumulator.size
    wurzel, pfad = accumulator.append(payload)
    b64 = lambda b: base64.b64encode(b).decode("ascii")  # noqa: E731 - the encoding emit.py uses
    oeffentlich = signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {
        "schema": SCHEMA,
        "payload_b64": b64(payload),
        "signature": {"alg": "ed25519", "public_key_b64": b64(oeffentlich), "sig_b64": b64(signer.sign(payload))},
        "merkle": {"hash_alg": "sha256-rfc6962", "leaf_index": index, "tree_size": accumulator.size,
                   "inclusion_proof_b64": [b64(p) for p in pfad], "root_b64": b64(wurzel)},
    }
