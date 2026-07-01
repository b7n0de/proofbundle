"""Adapter for EleutherAI lm-evaluation-harness results.json (file-based, no framework import)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from ..evalclaim import build_eval_claim


def from_lm_eval_results(path, task: str, metric: str, *, comparator: str, threshold: str,
                         timestamp: str, model_salt: Optional[bytes] = None,
                         dataset_salt: Optional[bytes] = None):
    """Read an lm-evaluation-harness results.json and build an eval claim for `task`/`metric`.

    Expects the standard shape: {"results": {task: {metric: <number>, ...}, ...},
    "n-samples": {task: {"effective": n}}, "config"/"model_name": ...}. The score is read as a
    STRING to avoid float canonicalization issues. Returns (claim, salts).
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    res = data.get("results", {}).get(task)
    if res is None or metric not in res:
        raise ValueError(f"task/metric not found in results: {task}/{metric}")
    score = repr(res[metric]) if not isinstance(res[metric], str) else res[metric]
    n = int(data.get("n-samples", {}).get(task, {}).get("effective")
            or data.get("n-samples", {}).get(task, {}).get("original") or 0)
    model_id = str(data.get("model_name") or data.get("config", {}).get("model") or "unknown")
    return build_eval_claim(
        suite=task, suite_version=str(data.get("config", {}).get("model_source", "lm-eval")),
        metric=metric, comparator=comparator, threshold=threshold, score=str(score), n=n,
        model_id=model_id, dataset_id=task, issuer="", timestamp=timestamp,
        model_salt=model_salt, dataset_salt=dataset_salt)
