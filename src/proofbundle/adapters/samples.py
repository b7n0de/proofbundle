"""Per-sample record extractors for the v1.5 sample tree (file-based, no framework imports).

Each extractor maps a framework's per-sample export into small, canonical leaf records for
:func:`proofbundle.persample.build_sample_tree`. Records are returned in canonical order
(sorted by the framework's stable sample identity) — the tree builder assigns and embeds `idx`.

Privacy layering (two-layer hiding, per the v1.5 design): records carry the framework's
CONTENT HASHES (or compact result fields), never benchmark plaintext — so opening a sample for
audit reveals the model's result without necessarily revealing the benchmark item's text.
lm-evaluation-harness conveniently already emits per-doc `doc_hash`/`prompt_hash`/`target_hash`
(SHA-256, verified against lm_eval/evaluator.py) — note these are UNSALTED upstream hashes and
therefore linkable on their own; hiding comes from the salted disclosure wrapping them, which is
why they go INSIDE the leaf, never beside it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List


def samples_from_lm_eval_jsonl(path) -> List[dict]:
    """Read an lm-evaluation-harness ``--log_samples`` JSONL (samples_<task>_*.jsonl) into leaf
    records: (doc_id, filter, doc/prompt/target hashes, filtered responses, metric values).

    Sorted by (doc_id, filter). Metric values are stringified (leaves are transport artifacts;
    numeric canonicalization stays out of the commitment)."""
    records = []
    for line_no, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {line_no}: not valid JSON") from exc
        if not isinstance(row, dict) or "doc_id" not in row:
            raise ValueError(f"line {line_no}: not an lm-eval sample row")
        doc_id = row.get("doc_id")
        if isinstance(doc_id, bool) or not isinstance(doc_id, int):
            raise ValueError(f"line {line_no}: doc_id missing or not an integer")
        metrics = row.get("metrics") or []
        rec = {"id": doc_id, "epoch": 1, "filter": str(row.get("filter", "none")),
               "doc_hash": str(row.get("doc_hash", "")),
               "prompt_hash": str(row.get("prompt_hash", "")),
               "target_hash": str(row.get("target_hash", "")),
               "filtered_resps": [str(r) for r in (row.get("filtered_resps") or [])],
               "metrics": {m: str(row[m]) for m in metrics if m in row}}
        records.append(rec)
    if not records:
        raise ValueError("no sample rows found")
    records.sort(key=lambda r: (r["id"], r["filter"]))
    return records


def samples_from_promptfoo_results(path) -> List[dict]:
    """Read a promptfoo results.json (summary v3) into leaf records:
    (testIdx, promptIdx, provider, success, score). Sorted by (testIdx, promptIdx, provider)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    summary = data.get("results")
    if not isinstance(summary, dict) or summary.get("version") != 3:
        raise ValueError("not a promptfoo v3 output file (see adapters.promptfoo)")
    records = []
    for i, row in enumerate(summary.get("results") or []):
        if not isinstance(row, dict):
            raise ValueError(f"results[{i}] is not an object")
        test_idx, prompt_idx = row.get("testIdx"), row.get("promptIdx")
        for name, val in (("testIdx", test_idx), ("promptIdx", prompt_idx)):
            if isinstance(val, bool) or not isinstance(val, int):
                raise ValueError(f"results[{i}].{name} missing or not an integer")
        success = row.get("success")
        if not isinstance(success, bool):
            raise ValueError(f"results[{i}].success missing or not a boolean")
        prov = row.get("provider")
        provider = str(prov.get("id")) if isinstance(prov, dict) else str(prov or "unknown")
        records.append({"id": test_idx, "epoch": 1, "prompt_idx": prompt_idx,
                        "provider": provider, "success": success,
                        "score": str(row.get("score", ""))})
    if not records:
        raise ValueError("no result rows found")
    records.sort(key=lambda r: (r["id"], r["prompt_idx"], r["provider"]))
    return records
