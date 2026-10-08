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
  PROOFBUNDLE_THRESHOLD  decimal string — the pass/fail threshold to assert. REQUIRED for emission:
                         there is deliberately no default. With the former default "0" every
                         non-negative score yielded passed=true — a vacuous verdict that reads like
                         a result (measured live 2026-08-22: a run scoring mean 0.0 produced
                         passed=true). Who wants pure binding without a verdict sets it explicitly.

SCITT (EXPERIMENTAL, 6.4.0; the inspect_ai hook only):
  PROOFBUNDLE_SCITT          "1" to also sign a SCITT Signed Statement over the receipt, with the key that
                             signed the receipt, next to it as ``<receipt>.scitt.cose``. Offline.
  PROOFBUNDLE_SCITT_ISSUER   CWT iss of the statement (required with PROOFBUNDLE_SCITT).
  PROOFBUNDLE_SCITT_SUBJECT  CWT sub of the statement (required with PROOFBUNDLE_SCITT).
  PROOFBUNDLE_SCITT_SERVICE  a Transparency Service URL for registration. Registration is not built in this
                             version: the statement is not submitted, and no connection is opened.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

DEFAULT_COMPARATOR = ">="


def emit_enabled(flag: bool = False) -> bool:
    """The master opt-in gate. True only if PROOFBUNDLE_EMIT == "1" OR an explicit framework flag is set.

    The flag opts in only as the exact ``True``. ``flag or ...`` read it by its truth, so ``"false"``,
    ``"no"``, ``1`` or ``[0]`` turned emission on and the value itself was returned. This gate does not
    raise for a flag that is not a bool, unlike the switches that route through
    ``_membership.require_switch``: the pytest plugin calls it outside its own ``try``, and an integration
    must never fail the host run (module docstring). A value that is not a bool leaves the gate to the
    environment variable, as leaving the flag out does."""
    return flag is True or os.environ.get("PROOFBUNDLE_EMIT") == "1"


def emit_config() -> dict:
    """Read the (metric, comparator, threshold) emission config from the environment.

    ``threshold`` is None when PROOFBUNDLE_THRESHOLD is unset — the integrations then SKIP emission
    with a clear message instead of asserting a vacuous passed=true against a default of 0."""
    return {
        "metric": os.environ.get("PROOFBUNDLE_METRIC"),
        "comparator": os.environ.get("PROOFBUNDLE_COMPARATOR") or DEFAULT_COMPARATOR,
        "threshold": os.environ.get("PROOFBUNDLE_THRESHOLD") or None,
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


def emit_claim_receipt(claim: dict, default_name: str, *, scitt: bool = False) -> Optional[str]:
    """Sign ``claim`` into an eval receipt and write it to the resolved output path. Returns the path, or
    None on any failure (an integration must never raise into the host run). Assumes emission is enabled
    (the caller checks ``emit_enabled`` first). With ``scitt`` a SCITT Signed Statement over the receipt
    is written next to it (``_emit_scitt_statement``); its failure never costs the receipt."""
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
        if scitt:
            _emit_scitt_statement(bundle, signer, out)
        return str(out)
    except Exception as e:  # noqa: BLE001 — never let emission break the host run
        print(f"[proofbundle] receipt emission skipped ({type(e).__name__}: {e})")
        return None


def _emit_scitt_statement(bundle: dict, signer, receipt_path: Path) -> Optional[str]:
    """Step 1 of the SCITT flag: a Signed Statement over the receipt, signed with the receipt's own key,
    written next to it. Step 2 (registration) would only follow a configured service URL; it is not built
    in this version, so nothing is submitted and no connection is opened either way. Never raises."""
    try:
        issuer = os.environ.get("PROOFBUNDLE_SCITT_ISSUER")
        subject = os.environ.get("PROOFBUNDLE_SCITT_SUBJECT")
        if not issuer or not subject:
            missing = [name for name, value in (("PROOFBUNDLE_SCITT_ISSUER", issuer),
                                                ("PROOFBUNDLE_SCITT_SUBJECT", subject)) if not value]
            print(f"[proofbundle] PROOFBUNDLE_SCITT=1 needs {' and '.join(missing)} — SCITT statement "
                  "skipped (the receipt is written)")
            return None
        from .scitt_statement import sign_statement  # noqa: PLC0415 — lazy
        data = sign_statement(bundle, signer, issuer=issuer, subject=subject)
        name = receipt_path.name[:-len(".json")] if receipt_path.name.endswith(".json") else receipt_path.name
        path = receipt_path.with_name(name + ".scitt.cose")
        path.write_bytes(data)
        print(f"[proofbundle] wrote SCITT signed statement → {path} (not registered)")
        service = os.environ.get("PROOFBUNDLE_SCITT_SERVICE")
        if service:
            print(f"[proofbundle] PROOFBUNDLE_SCITT_SERVICE is {service!r}, but registration is not built in "
                  "this version: the statement was not submitted")
        return str(path)
    except Exception as e:  # noqa: BLE001 — never let the statement break the host run or the receipt
        print(f"[proofbundle] SCITT statement skipped ({type(e).__name__}: {e})")
        return None
