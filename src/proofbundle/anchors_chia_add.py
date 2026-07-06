"""chia-datalayer/v1 anchor WRITER / EXPORTER (Paket 1) — needs the ``[chia]`` extra + a reachable Chia
DataLayer node (this is the ONLY chia-dependent part; VERIFYING an anchor offline needs neither, see
``anchors_chia.py``).

``export_anchor`` turns an existing (store, key) into a portable ``chia-datalayer/v1`` anchor dict whose
offline proof ``verify_chia_datalayer`` accepts. ``anchor_add`` is the full flow: insert the digest, wait
for on-chain confirmation, then export. A NETWORK/NODE FAILURE NEVER DAMAGES ANYTHING — ``anchor_add``
returns the new anchor or raises cleanly; it never writes a partial/half-anchor.

Access is via the stable ``chia rpc data_layer|full_node <method> '<json>'`` subprocess surface (the Python
imports move between Chia versions; the JSON-RPC wire is stable). RPC is local + cert-authed; never exposed.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import time
from typing import Optional

from .anchors_chia import ANCHOR_TYPE, verify_offline_merkle

_CHIA_BIN = os.getenv("CHIA_CLI", shutil.which("chia") or "chia")


class ChiaRpcError(RuntimeError):
    """A Chia RPC/CLI call failed. Fail-closed: the caller aborts, no partial anchor is written."""


def _rpc(service: str, method: str, payload: dict, *, timeout: int = 60) -> dict:
    """Call ``chia rpc <service> <method> '<json>'`` and return the parsed dict. Raises ChiaRpcError on
    any failure (missing binary, timeout, non-zero exit, non-JSON, ``success:false``)."""
    try:
        proc = subprocess.run(
            [_CHIA_BIN, "rpc", service, method, json.dumps(payload)],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except FileNotFoundError as exc:
        raise ChiaRpcError(f"chia binary not found ({_CHIA_BIN}); install proofbundle[chia] + a node") from exc
    except subprocess.TimeoutExpired as exc:
        raise ChiaRpcError(f"chia rpc {service} {method} timed out") from exc
    if proc.returncode != 0:
        raise ChiaRpcError(f"chia rpc {service} {method} exit {proc.returncode}: {(proc.stderr or proc.stdout)[:200]}")
    try:
        data = json.loads(proc.stdout)
    except ValueError as exc:
        raise ChiaRpcError(f"chia rpc {service} {method}: non-JSON response") from exc
    if isinstance(data, dict) and data.get("success") is False:
        raise ChiaRpcError(f"chia rpc {service} {method}: {data.get('error', 'success=false')}")
    return data


def _hx(b: bytes) -> str:
    return "0x" + b.hex()


def export_anchor(store_id: str, *, canonical_root: bytes, target: str = "receipt",
                  network: str = "mainnet", value: Optional[str] = None) -> dict:
    """Build a ``chia-datalayer/v1`` anchor from live ``get_proof`` + ``get_root`` (+ best-effort
    ``get_coin_record`` for height/timestamp). The DataLayer KEY IS the target's ``canonical_root`` (that is
    the whole binding — see anchors_chia.verify_offline_merkle), so the key is derived here, never passed in
    independently. Returns the anchor dict (self-verifying offline before emit). Fail-closed.
    """
    key = _hx(bytes(canonical_root))   # key == canonicalRoot: the binding the verifier enforces
    gp = _rpc("data_layer", "get_proof", {"store_id": store_id, "keys": [key]})
    proofs = ((gp.get("proof") or {}).get("store_proofs") or {}).get("proofs") or []
    if not proofs:
        raise ChiaRpcError("get_proof returned no proof for the key (not in the store / not confirmed)")
    pr = proofs[0]
    root_resp = _rpc("data_layer", "get_root", {"id": store_id})
    published_root = root_resp.get("hash")
    if not published_root or set(published_root.replace("0x", "")) == {"0"}:
        raise ChiaRpcError("store has no confirmed published root yet")

    coin_id = (gp.get("proof") or {}).get("coin_id")
    inner_puzzle_hash = (gp.get("proof") or {}).get("inner_puzzle_hash")
    block_height = None
    root_timestamp = None
    if coin_id:                                   # best-effort: height + timestamp from the full node (Stufe iii material)
        try:
            cr = _rpc("full_node", "get_coin_record_by_name", {"name": coin_id}, timeout=20)
            rec = cr.get("coin_record") or {}
            block_height = rec.get("confirmed_block_index")
            root_timestamp = rec.get("timestamp")
        except ChiaRpcError:
            pass                                  # height/timestamp are Stufe-iii extras; absence is not fatal

    proof_obj = {
        "store_id": store_id, "key": key,   # key == canonicalRoot (the binding)
        "key_clvm_hash": pr["key_clvm_hash"], "value_clvm_hash": pr["value_clvm_hash"],
        "node_hash": pr["node_hash"], "inclusion_layers": pr.get("layers", []),
        "published_root": published_root,
        "coin_id": coin_id, "inner_puzzle_hash": inner_puzzle_hash,
        "block_height": block_height, "root_timestamp": root_timestamp, "network": network,
    }
    if value is not None:
        proof_obj["value"] = value if value.startswith(("0x", "0X")) else "0x" + value

    # self-check BEFORE returning: an exported anchor MUST verify offline, else we never emit it (No-Fake).
    chk = verify_offline_merkle(proof_obj, bytes(canonical_root))
    if not chk.get("ok"):
        raise ChiaRpcError(f"exported anchor failed its own offline verification: {chk.get('detail')}")

    return {
        "type": ANCHOR_TYPE, "target": target,
        "canonicalRoot": base64.b64encode(bytes(canonical_root)).decode(),
        "proof": base64.b64encode(json.dumps(proof_obj).encode()).decode(),
    }


def _wait_confirmed(store_id: str, prev_root: Optional[str], *, timeout: int = 180, poll: int = 5) -> None:
    """Block until the store's published root advances past ``prev_root`` (the batch_update confirmed).
    Raises ChiaRpcError on timeout. ``poll`` uses monotonic sleep; no busy loop."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        root = _rpc("data_layer", "get_root", {"id": store_id}).get("hash")
        if root and root != prev_root and set(root.replace("0x", "")) != {"0"}:
            return
        time.sleep(poll)
    raise ChiaRpcError("timed out waiting for the batch_update root to confirm on-chain")


def anchor_add(canonical_root_hex: str, *, store_id: str, value_digest_hex: Optional[str] = None,
               target: str = "receipt", network: str = "mainnet", fee: int = 100_000_000,
               wait: bool = True) -> dict:
    """Full flow: insert ``key=canonicalRoot`` (value = ``value_digest`` or the canonicalRoot itself) into the
    store, wait for on-chain confirmation, then export the anchor. Idempotent: a key already present ("Key
    already present") is treated as "already anchored" and re-exported, not an error. Fail-closed: a network
    failure raises ChiaRpcError and writes NOTHING partial (the caller keeps its receipt untouched)."""
    canonical_root_hex = canonical_root_hex if canonical_root_hex.startswith(("0x", "0X")) else "0x" + canonical_root_hex
    canonical_root = bytes.fromhex(canonical_root_hex[2:])
    if len(canonical_root) != 32:
        raise ValueError("canonical_root must be a 32-byte hex digest")
    value_hex = value_digest_hex or canonical_root_hex
    value_hex = value_hex if value_hex.startswith(("0x", "0X")) else "0x" + value_hex

    prev_root = _rpc("data_layer", "get_root", {"id": store_id}).get("hash")
    changelist = [{"action": "insert", "key": canonical_root_hex, "value": value_hex}]
    already = False
    try:
        _rpc("data_layer", "batch_update",
             {"id": store_id, "changelist": changelist, "fee": fee, "submit_on_chain": True})
    except ChiaRpcError as exc:
        if "already present" in str(exc).lower():
            already = True                        # idempotent: the digest is already anchored
        else:
            raise                                 # any other failure → clean abort, nothing written
    if wait and not already:
        _wait_confirmed(store_id, prev_root)
    return export_anchor(store_id, canonical_root=canonical_root,
                         target=target, network=network, value=value_hex)
