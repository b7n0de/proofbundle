"""Markovian provenance anchor (EXPERIMENTAL; third-party extension example for docs/ANCHORS.md).

A worked example of a *third-party* anchor ``type`` registered through
:func:`proofbundle.anchors.register_anchor_type`. It shows how an outside protocol plugs its own
evidence into the generic ``anchors[]`` layer without touching proofbundle's core, and it is deliberately
NOT wired into the built-in set (``_ensure_builtin_types``) — a third-party type is opt-in by design.

**What it proves.** A ``markovian-provenance/v1`` stamp is an *issuer-attributable* commitment: it binds
the committed data to a wallet via ``merkle_root = sha256(data_hash ":" salt ":" wallet)``, and the data
itself is Bitcoin-anchored with OpenTimestamps. A verified anchor therefore says: *the target canonical
root was committed by wallet W and existed by the OTS-attested Bitcoin block time.* The time is
trust-minimized (Bitcoin PoW time); the issuer binding is self-consistent inside the stamp envelope.

**Composition, not reinvention.** The Bitcoin time proof is delegated verbatim to the built-in
``opentimestamps`` verifier (:func:`proofbundle.anchors_ots.verify_opentimestamps`), inheriting its exact
fail-closed lifecycle (PENDING -> WARN; upgraded-without-header -> honest not-pass; upgraded + supplied
block header -> confirmed). This type only adds the Markovian envelope checks on top; it never
re-implements the Bitcoin discipline.

``proof`` is UTF-8 JSON: ``{schema, data_hash, salt, wallet, merkle_root, zk_commitment?, block_height?,
stamped_at?, ots}`` where ``ots`` is base64 of the detached OpenTimestamps proof over the canonical root.
``canonicalRoot`` is the exact bytes the stamp committed (the stamp's ``data_hash``).

Register it explicitly (that it is not a core built-in is the point of a third-party type)::

    from proofbundle.anchors_markovian import register
    register()   # anchors[] entries with type "markovian-provenance/v1" now verify
"""
from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Optional

ANCHOR_TYPE = "markovian-provenance/v1"


def _fail(status: str, detail: str) -> dict:
    return {"ok": False, "warn": False, "status": status, "detail": detail}


def verify_markovian(proof: bytes, canonical_root: bytes, *, frozen: dict,
                     now: Optional[int] = None) -> dict:
    """Fail-closed verifier for a ``markovian-provenance/v1`` anchor. Returns {ok, warn, status, detail}.

    Steps (any doubt -> not ok; never raises for an ordinary bad proof):
      1. parse the JSON envelope;
      2. schema is ``markovian-provenance/v1``;
      3. binding: ``data_hash`` equals the target ``canonical_root`` (hex);
      4. envelope integrity: ``merkle_root == sha256(data_hash ":" salt ":" wallet)`` (wallet bound to data);
      5. Bitcoin time: delegate the embedded OTS proof to the built-in opentimestamps verifier.
    The final status/warn mirror the OTS verifier (pending / upgraded_unverified / confirmed); a PASS also
    names the committing wallet and Markovian chain height.
    """
    # 1. parse (WP-C1: strict — a duplicated key in the envelope is a parser differential over
    # which wallet/merkle_root was committed; BundleFormatError keeps the never-raise contract)
    try:
        from ._strict_json import loads_strict  # noqa: PLC0415
        env = loads_strict(proof.decode("utf-8"))
        if not isinstance(env, dict):
            raise ValueError("envelope is not a JSON object")
    except (UnicodeDecodeError, ValueError) as exc:
        return _fail("malformed", f"markovian proof is not valid JSON: {exc}")
    except Exception as exc:   # BundleFormatError (dup key) → clean fail, never a raise
        return _fail("malformed", f"markovian proof rejected: {exc}")

    # 2. schema
    if env.get("schema") != ANCHOR_TYPE:
        return _fail("bad_schema", f"markovian proof schema must be {ANCHOR_TYPE!r}")

    data_hash = env.get("data_hash")
    salt = env.get("salt")
    wallet = env.get("wallet")
    merkle_root = env.get("merkle_root")
    ots_b64 = env.get("ots")
    for name, val in (("data_hash", data_hash), ("salt", salt), ("wallet", wallet),
                      ("merkle_root", merkle_root), ("ots", ots_b64)):
        if not isinstance(val, str) or not val:
            return _fail("bad_fields", f"markovian envelope field {name!r} missing or not a string")
    # the loop above guarantees these are non-empty str; narrow explicitly so the type checker follows
    assert isinstance(data_hash, str) and isinstance(ots_b64, str)

    # 3. binding: the stamp must commit to EXACTLY the target canonical root
    try:
        if bytes.fromhex(data_hash) != canonical_root:
            return _fail("unbound", "markovian data_hash does not match the target canonical root")
    except ValueError:
        return _fail("bad_fields", "markovian data_hash is not valid hex")

    # 4. envelope integrity: the wallet is bound to the data inside the stamp
    recomputed = hashlib.sha256(f"{data_hash}:{salt}:{wallet}".encode("utf-8")).hexdigest()
    if recomputed != merkle_root:
        return _fail("envelope_mismatch",
                     "markovian merkle_root != sha256(data_hash:salt:wallet) — envelope inconsistent/tampered")

    # 5. Bitcoin time: delegate to the built-in OpenTimestamps verifier (compose, don't reinvent)
    try:
        ots_proof = base64.b64decode(ots_b64, validate=True)
    except (ValueError, binascii.Error):
        return _fail("bad_fields", "markovian ots field is not valid base64")
    try:
        from .anchors_ots import verify_opentimestamps  # noqa: PLC0415
    except ImportError:
        return _fail("no_lib",
                     "markovian anchor needs proofbundle[anchors] (opentimestamps) for the Bitcoin proof")

    ots_res = verify_opentimestamps(ots_proof, canonical_root, frozen=frozen, now=now)
    who = f"Markovian wallet {wallet}"
    chain = env.get("block_height")
    chain_part = f", Markovian chain block {chain}" if chain is not None else ""
    if ots_res.get("ok"):
        return {"ok": True, "warn": False, "status": "confirmed",
                "detail": f"canonical root committed by {who}{chain_part}; {ots_res.get('detail', '')}"}
    # not a full anchor yet — carry the OTS lifecycle status/warn verbatim, framed as Markovian
    return {"ok": False, "warn": bool(ots_res.get("warn")), "status": ots_res.get("status", "fail"),
            "detail": f"markovian stamp envelope valid ({who}{chain_part}) but Bitcoin proof not verified: "
                      f"{ots_res.get('detail', '')}"}


def register() -> None:
    """Register this third-party type so ``anchors[]`` entries of type ``markovian-provenance/v1`` verify."""
    from .anchors import register_anchor_type  # noqa: PLC0415
    register_anchor_type(ANCHOR_TYPE, verify_markovian)
