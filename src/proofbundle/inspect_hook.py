"""inspect_ai end-of-task hook — opt-in auto-emit of a signed eval receipt (v1.0).

Registered via the ``inspect_ai`` entry-point group (see ``_inspect_registry``). When a task ends, and ONLY
when the user has opted in (``PROOFBUNDLE_EMIT=1``), this builds a signed proofbundle receipt from the eval
log and writes it out — never silently, never failing the eval. The heavy crypto is imported lazily inside
the hook body, so merely installing proofbundle does not slow inspect's startup.

Requires ``inspect_ai>=0.3.112`` (the generic lifecycle hooks + ``on_task_end``). Reuses the existing
``from_inspect_ai_log`` adapter — ``data.log`` is already an EvalLog, so no re-read of the .eval file for a
normal ``eval()``. For an ``eval_set()`` the log may be header-only; then we fall back to reading the log
from ``data.log.location`` to recover the results.
"""
from __future__ import annotations

import os

from inspect_ai.hooks import Hooks, hooks


def _emit_enabled() -> bool:
    # kept inline + cheap: enabled() is consulted before every hook invocation (potentially per sample)
    return os.environ.get("PROOFBUNDLE_EMIT") == "1"


def _first_metric(log) -> str:
    """The first score's first metric name from an EvalLog, as a sensible default binding target."""
    results = getattr(log, "results", None)
    for score in (getattr(results, "scores", None) or []):
        metrics = getattr(score, "metrics", None) or {}
        for name in metrics:
            return name
    return "accuracy"


@hooks(name="proofbundle_hooks", description="Emit a signed proofbundle eval receipt at end of task (opt-in via PROOFBUNDLE_EMIT)")
class ProofbundleHooks(Hooks):
    def enabled(self) -> bool:
        return _emit_enabled()

    async def on_task_end(self, data) -> None:
        if not _emit_enabled():
            return
        try:
            from datetime import datetime, timezone  # noqa: PLC0415

            from ._integration import emit_claim_receipt, emit_config  # noqa: PLC0415
            from .adapters.inspect_ai import from_inspect_ai_log  # noqa: PLC0415

            log = data.log
            # header-only (eval_set) fallback: if results are missing, re-read the full log from its location
            if getattr(log, "results", None) is None and getattr(log, "location", None):
                from inspect_ai.log import read_eval_log  # noqa: PLC0415
                log = read_eval_log(str(log.location))

            cfg = emit_config()
            metric = cfg["metric"] or _first_metric(log)
            claim, _ = from_inspect_ai_log(log, metric, comparator=cfg["comparator"],
                                           threshold=cfg["threshold"],
                                           timestamp=datetime.now(timezone.utc).isoformat())
            eval_id = getattr(data, "eval_id", None) or "eval"
            emit_claim_receipt(claim, f"proofbundle_receipt_{eval_id}.json")
        except Exception as e:  # noqa: BLE001 — an integration must never fail the host eval
            print(f"[proofbundle] inspect_ai receipt emission skipped ({type(e).__name__}: {e})")
