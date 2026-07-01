"""Adapter for UK AISI inspect_ai eval-log JSON (file-based, no framework import)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from ..evalclaim import build_eval_claim


def from_inspect_ai_log(path, metric: str, *, comparator: str, threshold: str, timestamp: str,
                        model_salt: Optional[bytes] = None, dataset_salt: Optional[bytes] = None):
    """Read an inspect_ai eval-log JSON and build an eval claim.

    Expects: {"eval": {"task": ..., "model": ..., "dataset": {"name": ...}},
    "results": {"total_samples": n, "scores": [{"metrics": {metric: {"value": <number>}}}]}}.
    Returns (claim, salts).
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    ev = data.get("eval", {})
    scores = data.get("results", {}).get("scores", [])
    value = None
    for s in scores:
        m = s.get("metrics", {})
        if metric in m:
            value = m[metric].get("value")
            break
    if value is None:
        raise ValueError(f"metric {metric!r} not found in inspect_ai scores")
    n = int(data.get("results", {}).get("total_samples") or 0)
    return build_eval_claim(
        suite=str(ev.get("task", "inspect_ai")), suite_version=str(ev.get("task_version", "1")),
        metric=metric, comparator=comparator, threshold=threshold, score=repr(value), n=n,
        model_id=str(ev.get("model", "unknown")),
        dataset_id=str(ev.get("dataset", {}).get("name", ev.get("task", "unknown"))),
        issuer="", timestamp=timestamp, model_salt=model_salt, dataset_salt=dataset_salt)
