"""Adapter for promptfoo `eval -o results.json` output (file-based, NO promptfoo import) — v1.4.

Parses the exported OutputFile JSON only. Format verified 2026-07-02 against promptfoo `main`
(`src/types/index.ts` OutputFile / EvaluateSummaryV3 / EvaluateStats, `src/util/output.ts`
writeOutput): top level carries `evalId`, `results`, `config`, `metadata`; the current summary is
**version 3** (`results.version == 3`) with whole-run aggregates in `results.stats` as
`successes` / `failures` / `errors`. The metric emitted is **pass_rate** = successes / (successes
+ failures + errors), rendered as a fixed-point decimal string (the claim schema takes decimal
strings, never floats).

Version honesty: legacy files with `results.version` 1/2 have a different shape (`table` instead
of `prompts`) and are REJECTED with a clear message rather than half-parsed; the "v4" storage
version never appears in output files (they still say `version: 3`). Redaction flags
(`PROMPTFOO_STRIP_*`) only affect prompt/response bodies — nothing this adapter reads.
"""
from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from pathlib import Path
from typing import Optional

from ..evalclaim import build_eval_claim

_SCALE = 6  # pass_rate decimal places — fixed-point, schema-conformant


def _pass_rate(successes: int, failures: int, errors: int) -> "tuple[str, int]":
    total = successes + failures + errors
    if total <= 0:
        raise ValueError("promptfoo results contain no test outcomes (stats all zero)")
    rate = (Decimal(successes) / Decimal(total)).quantize(Decimal(1).scaleb(-_SCALE))
    return f"{rate:.{_SCALE}f}", total


def from_promptfoo_results(path, *, comparator: str, threshold: str, timestamp: str,
                           model_salt: Optional[bytes] = None,
                           dataset_salt: Optional[bytes] = None):
    """Read a promptfoo results.json (summary v3) and build an eval claim over the run's
    pass_rate. Returns (claim, salts).

    - suite = `config.description` when present, else the `evalId` (the run's identity).
    - model_id = the sorted, de-duplicated provider ids of the run (a promptfoo eval may span
      several providers; the salted commitment pins the exact set).
    - dataset_id = sha256 over the canonical JSON of `config.tests` (the test suite IS the
      dataset; promptfoo's internal datasetId is not exported) — prefixed so the derivation is
      explicit and reproducible.
    - provenance: promptfooVersion, evalId, summary timestamp, per-outcome counts.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("results"), dict):
        raise ValueError("not a promptfoo output file (missing results object)")
    summary = data["results"]
    version = summary.get("version")
    if version != 3:
        raise ValueError(
            f"unsupported promptfoo summary version {version!r} — this adapter parses the "
            "current version 3 (legacy v1/v2 files use a different 'table' shape; re-export "
            "with a current promptfoo)")
    stats = summary.get("stats")
    if not isinstance(stats, dict):
        raise ValueError("promptfoo results.stats missing")
    counts = {}
    for key in ("successes", "failures", "errors"):
        val = stats.get(key, 0)
        if isinstance(val, bool) or not isinstance(val, int) or val < 0:
            raise ValueError(f"promptfoo stats.{key} must be a non-negative integer")
        counts[key] = val
    score, n = _pass_rate(counts["successes"], counts["failures"], counts["errors"])

    config = data.get("config") or {}
    eval_id = data.get("evalId")
    suite = str(config.get("description") or eval_id or "promptfoo-run")

    providers = set()
    for res in summary.get("results", []):
        prov = (res or {}).get("provider")
        if isinstance(prov, dict) and prov.get("id"):
            providers.add(str(prov["id"]))
        elif isinstance(prov, str):
            providers.add(prov)
    for prov in config.get("providers") or []:
        if isinstance(prov, str):
            providers.add(prov)
        elif isinstance(prov, dict) and prov.get("id"):
            providers.add(str(prov["id"]))
    model_id = "+".join(sorted(providers)) if providers else "unknown:promptfoo-provider"

    tests = config.get("tests")
    tests_canonical = json.dumps(tests, sort_keys=True, separators=(",", ":")) if tests else ""
    dataset_id = ("promptfoo-tests-sha256:"
                  + hashlib.sha256(tests_canonical.encode("utf-8")).hexdigest())

    metadata = data.get("metadata") or {}
    provenance = {"harness": "promptfoo",
                  "successes": str(counts["successes"]), "failures": str(counts["failures"]),
                  "errors": str(counts["errors"])}
    if eval_id:
        provenance["eval_id"] = str(eval_id)
    if metadata.get("promptfooVersion"):
        provenance["promptfoo_version"] = str(metadata["promptfooVersion"])
    if summary.get("timestamp"):
        provenance["run_timestamp"] = str(summary["timestamp"])

    return build_eval_claim(
        suite=suite, suite_version=f"promptfoo-summary-v{version}",
        metric="pass_rate", comparator=comparator, threshold=threshold, score=score, n=n,
        model_id=model_id, dataset_id=dataset_id, issuer="", timestamp=timestamp,
        provenance=provenance, model_salt=model_salt, dataset_salt=dataset_salt)
