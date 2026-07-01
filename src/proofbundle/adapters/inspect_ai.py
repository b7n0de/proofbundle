"""Adapter for UK AISI inspect_ai eval logs — via the STABLE API, optional extra `proofbundle[inspect]`.

Unlike the v0.4 file-based reader, this uses the stable `inspect_ai.log.read_eval_log(path,
header_only=True)` API (the `.eval` on-disk format + its pydantic schema change between versions, see
inspect_ai issue 834; the stable API is robust). inspect_ai is imported LAZILY inside the function, so
the proofbundle core stays dependency-free — only `pip install "proofbundle[inspect]"` pulls it.

Object model (inspect_ai): `log.eval.task` is the suite; `log.results.scores` is a list of EvalScore;
`EvalScore.metrics` is a dict name→EvalMetric; `EvalMetric.value` is the number. threshold, comparator
and thus `passed` are set by proofbundle, NOT read from the log. model_id/dataset_id become salted
commitments (never plaintext in the payload).
"""
from __future__ import annotations

from typing import Optional

from ..evalclaim import build_eval_claim


class InspectAdapterError(RuntimeError):
    """Raised when inspect_ai is missing or the log lacks the expected structure (no bare AttributeError)."""


def from_inspect_ai_log(path, metric: str, *, comparator: str, threshold: str, timestamp: str,
                        model_salt: Optional[bytes] = None, dataset_salt: Optional[bytes] = None):
    """Read an inspect_ai eval log via the stable API and build an eval claim for `metric`.

    Returns (claim, salts). Raises InspectAdapterError if inspect_ai is unavailable or the log is
    missing the expected attributes — a clear error instead of an opaque AttributeError.
    """
    try:
        from inspect_ai.log import read_eval_log  # noqa: PLC0415 — lazy: keeps the core dependency-free
    except ImportError as e:
        raise InspectAdapterError(
            "inspect_ai is required for this adapter — install with: pip install \"proofbundle[inspect]\"") from e

    try:
        log = read_eval_log(str(path), header_only=True)
    except Exception as e:  # noqa: BLE001 — surface any read/parse failure as a clear adapter error
        raise InspectAdapterError(f"could not read inspect_ai log {path!r}: {e}") from e

    ev = getattr(log, "eval", None)
    results = getattr(log, "results", None)
    if ev is None or results is None:
        raise InspectAdapterError("inspect_ai log missing .eval or .results (empty or malformed log)")

    value = None
    for score in (getattr(results, "scores", None) or []):
        metrics = getattr(score, "metrics", None) or {}
        if metric in metrics:
            value = getattr(metrics[metric], "value", None)
            break
    if value is None:
        raise InspectAdapterError(f"metric {metric!r} not found in any score.metrics of the log")

    suite = str(getattr(ev, "task", "inspect_ai"))
    model_id = str(getattr(ev, "model", "unknown"))
    dataset = getattr(ev, "dataset", None)
    dataset_id = str(getattr(dataset, "name", None) or suite)

    # Provenance parity with the lm-eval adapter: inspect_ai exposes the same run provenance for free.
    provenance = {"harness": "inspect_ai"}
    revision = getattr(ev, "revision", None)
    commit = getattr(revision, "commit", None)
    if commit:
        provenance["git_hash"] = str(commit)
    packages = getattr(ev, "packages", None) or {}
    if isinstance(packages, dict) and packages.get("inspect_ai"):
        provenance["harness_version"] = str(packages["inspect_ai"])
    tv = getattr(ev, "task_version", None)
    if tv is not None:
        provenance["task_version"] = str(tv)

    return build_eval_claim(
        suite=suite, suite_version=str(getattr(ev, "task_version", "1")),
        metric=metric, comparator=comparator, threshold=threshold, score=repr(value),
        n=int(getattr(results, "total_samples", 0) or 0),
        model_id=model_id, dataset_id=dataset_id, issuer="", timestamp=timestamp,
        provenance=provenance, model_salt=model_salt, dataset_salt=dataset_salt)
