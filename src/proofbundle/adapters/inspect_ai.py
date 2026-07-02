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


def _score_str(value) -> str:
    """Render a metric value as a PLAIN decimal string (no scientific notation) that build_eval_claim
    accepts. ``repr(float)`` emits '1e-05'/'1e+20' for very small/large values, which the claim's decimal
    pattern rejects — so numbers are formatted fixed-point (like the pytest plugin's ``_fmt``)."""
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise InspectAdapterError("metric value must be finite")
        return format(value, ".12f").rstrip("0").rstrip(".") or "0"
    return str(value)


def from_inspect_ai_log(path, metric: str, *, comparator: str, threshold: str, timestamp: str,
                        model_salt: Optional[bytes] = None, dataset_salt: Optional[bytes] = None):
    """Read an inspect_ai eval log via the stable API and build an eval claim for `metric`.

    ``path`` may be a path/str to a ``.eval`` log OR an already-loaded EvalLog object (e.g. the inspect_ai
    hook's ``data.log``). Returns (claim, salts). Raises InspectAdapterError if inspect_ai is unavailable
    or the log is missing the expected attributes — a clear error instead of an opaque AttributeError.
    """
    # An already-loaded EvalLog (has .eval + .results) is used directly — no re-read from disk.
    if hasattr(path, "eval") and hasattr(path, "results"):
        log = path
    else:
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

    # v1.8 (external review): run-id + config-hash + LOG-NATIVE timestamp so a receipt traces back
    # to the exact run. inspect_ai: eval.run_id (unique run id), eval.created (UTC datetime string),
    # eval.task_args (the config material — no native config hash exists, so we compute one).
    from ._provenance import add_provenance  # noqa: PLC0415
    task_args = getattr(ev, "task_args", None)
    add_provenance(provenance, run_id=getattr(ev, "run_id", None),
                   config=task_args if isinstance(task_args, dict) else None,
                   log_timestamp=getattr(ev, "created", None))

    return build_eval_claim(
        suite=suite, suite_version=str(getattr(ev, "task_version", "1")),
        metric=metric, comparator=comparator, threshold=threshold, score=_score_str(value),
        n=int(getattr(results, "total_samples", 0) or 0),
        model_id=model_id, dataset_id=dataset_id, issuer="", timestamp=timestamp,
        provenance=provenance, model_salt=model_salt, dataset_salt=dataset_salt)
