"""Shared opt-in helper for the framework integrations (inspect_ai hook, pytest plugin) — v1.0.

THE TOP RULE (opt-in safety): an integration must NEVER silently write a file or alter a host run. It emits
a receipt ONLY when the user explicitly turns it on — the ``PROOFBUNDLE_EMIT=1`` environment variable, or a
framework flag that maps to it. A security tool that surprises you loses trust. Every function here is a
no-op unless emission is enabled, catches its own errors (an integration must never fail the host run), and
imports the crypto lazily (this module is only imported from inside a hook body, never at framework startup).

Configuration (all optional, all env):
  PROOFBUNDLE_EMIT       "1" to enable emission (the master opt-in). Anything else = disabled.
  PROOFBUNDLE_KEY        path to a 32-byte raw Ed25519 seed to sign with. If unset, an EPHEMERAL key is
                         generated (a warning is printed; the receipt is self-verifiable but not tied to a
                         durable identity).
  PROOFBUNDLE_OUT        output path: a file, or a directory (the default file name is written into it).
                         Default: the default file name in the current directory.
  PROOFBUNDLE_METRIC     which metric to bind (else the integration's first/most-relevant metric).
  PROOFBUNDLE_COMPARATOR ">=" | ">" | "<=" | "<"  (default ">=").
  PROOFBUNDLE_THRESHOLD  decimal string (default "0") — the pass/fail threshold to assert.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

DEFAULT_COMPARATOR = ">="
DEFAULT_THRESHOLD = "0"


def emit_enabled(flag: bool = False) -> bool:
    """The master opt-in gate. True only if PROOFBUNDLE_EMIT == "1" OR an explicit framework flag is set."""
    return flag or os.environ.get("PROOFBUNDLE_EMIT") == "1"


def emit_config() -> dict:
    """Read the (metric, comparator, threshold) emission config from the environment, with safe defaults."""
    return {
        "metric": os.environ.get("PROOFBUNDLE_METRIC"),
        "comparator": os.environ.get("PROOFBUNDLE_COMPARATOR") or DEFAULT_COMPARATOR,
        "threshold": os.environ.get("PROOFBUNDLE_THRESHOLD") or DEFAULT_THRESHOLD,
    }


def _resolve_signer():
    """Return (signer, is_ephemeral). Loads PROOFBUNDLE_KEY if set, else generates an ephemeral key."""
    from .emit import generate_signer, load_signer  # noqa: PLC0415 — lazy: only on actual emit
    key_path = os.environ.get("PROOFBUNDLE_KEY")
    if key_path:
        return load_signer(key_path), False
    return generate_signer(), True


def _output_path(default_name: str) -> Path:
    """Resolve the output file path from PROOFBUNDLE_OUT (file or directory) or the default name in cwd."""
    out = os.environ.get("PROOFBUNDLE_OUT")
    if not out:
        return Path.cwd() / default_name
    p = Path(out)
    if p.is_dir() or out.endswith(os.sep):
        return p / default_name
    return p


def emit_claim_receipt(claim: dict, default_name: str) -> Optional[str]:
    """Sign ``claim`` into an eval receipt and write it to the resolved output path. Returns the path, or
    None on any failure (an integration must never raise into the host run). Assumes emission is enabled
    (the caller checks ``emit_enabled`` first)."""
    try:
        from .evalclaim import emit_eval_receipt  # noqa: PLC0415 — lazy
        import json  # noqa: PLC0415

        signer, ephemeral = _resolve_signer()
        if ephemeral:
            print("[proofbundle] PROOFBUNDLE_KEY not set — signing with an EPHEMERAL key "
                  "(receipt is self-verifiable but not bound to a durable identity).")
        bundle = emit_eval_receipt(claim, signer)
        out = _output_path(default_name)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        print(f"[proofbundle] wrote signed eval receipt → {out}")
        return str(out)
    except Exception as e:  # noqa: BLE001 — never let emission break the host run
        print(f"[proofbundle] receipt emission skipped ({type(e).__name__}: {e})")
        return None
