"""Adapter for EleutherAI lm-evaluation-harness results_*.json (file-based, NO lm_eval import).

Parses the exported result JSON only — no runtime dependency on lm_eval, no runner rebuild.

Real 0.4.x format (validated against a genuine harness run, see tests/fixtures/lm_eval_arc_easy_real.json):
the metric keys carry a *filter suffix*, e.g. `"acc,none"`, and the standard error is a **sibling** key
`"acc_stderr,none"` (not nested). So a caller asking for metric `"acc"` is matched against `"acc,none"`
(or `"acc,<filter>"`). Provenance (git_hash, harness/task version, n-shot) is copied into the receipt's
optional `provenance` field so a verifier can trace exactly which run produced it.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from ..evalclaim import build_eval_claim


def _find_metric(res: dict, metric: str):
    """Return (value, stderr, matched_key) for `metric`, handling the `metric,<filter>` suffix format.

    Prefers an exact `metric` key, then `metric,none`, then any `metric,<filter>`. The stderr sibling is
    `metric_stderr,<same filter>`."""
    if metric in res:                       # bare key (older/simple exports)
        stderr = res.get(f"{metric}_stderr")
        return res[metric], stderr, metric
    if f"{metric},none" in res:
        return res[f"{metric},none"], res.get(f"{metric}_stderr,none"), f"{metric},none"
    for key in res:                         # any filter, e.g. metric,custom-filter
        if key == metric or (key.startswith(f"{metric},") and not key.startswith(f"{metric}_stderr")):
            flt = key.split(",", 1)[1] if "," in key else "none"
            return res[key], res.get(f"{metric}_stderr,{flt}"), key
    return None, None, None


def from_lm_eval_results(path, task: str, metric: str, *, comparator: str, threshold: str,
                         timestamp: str, model_salt: Optional[bytes] = None,
                         dataset_salt: Optional[bytes] = None):
    """Read an lm-evaluation-harness results_*.json and build an eval claim for `task`/`metric`.

    `metric` is the bare name (e.g. "acc"); the real key may be "acc,none". The score is read as a STRING
    to avoid float canonicalization issues. Returns (claim, salts).
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    res = data.get("results", {}).get(task)
    if res is None:
        raise ValueError(f"task not found in results: {task!r}")
    value, stderr, matched = _find_metric(res, metric)
    if value is None:
        raise ValueError(f"metric {metric!r} not found in results[{task!r}] "
                         f"(available: {sorted(k for k in res if ',' in k)})")
    score = value if isinstance(value, str) else repr(value)

    n_samples = data.get("n-samples", {}).get(task, {})
    n = int(n_samples.get("effective") or n_samples.get("original") or res.get("sample_len") or 0)
    cfg = data.get("config", {})
    model_id = str(cfg.get("model_name") or cfg.get("model") or "unknown")
    if cfg.get("model_args"):
        model_id = f"{model_id}::{cfg['model_args']}"   # include args so the commitment pins the exact model

    provenance = {"harness": "lm-evaluation-harness", "matched_metric_key": matched}
    if data.get("git_hash"):
        provenance["git_hash"] = str(data["git_hash"])
    if data.get("versions", {}).get(task) is not None:
        provenance["task_version"] = str(data["versions"][task])
    if data.get("n-shot", {}).get(task) is not None:
        provenance["n_shot"] = str(data["n-shot"][task])
    if stderr is not None:
        provenance["stderr"] = repr(stderr) if not isinstance(stderr, str) else stderr

    return build_eval_claim(
        suite=task, suite_version=str(data.get("versions", {}).get(task, "lm-eval")),
        metric=metric, comparator=comparator, threshold=threshold, score=str(score), n=n,
        model_id=model_id, dataset_id=task, issuer="", timestamp=timestamp,
        provenance=provenance, model_salt=model_salt, dataset_salt=dataset_salt)
