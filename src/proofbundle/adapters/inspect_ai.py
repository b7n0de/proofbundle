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

from typing import Any, Optional

from ..budget import render_safe
from ..evalclaim import build_eval_claim


class InspectAdapterError(RuntimeError):
    """Raised when inspect_ai is missing or the log lacks the expected structure (no bare AttributeError)."""


def _text(wert, feld: str) -> str:
    """``str(wert)`` for a log or caller value this adapter writes as text, or InspectAdapterError.

    `str()` has no answer for `10**5000` (ValueError, the int->str cap), a nesting deeper than the
    interpreter allows (RecursionError) or an object whose `__str__` raises; measured with the lens
    run 10 generator on d6d89763, `capture=10**5000` escaped raw, and an EvalLog handed over as an
    object carries its attributes from the same place. A shortened text would sign a value the log
    does not hold, so the log is refused."""
    try:
        return str(wert)
    except Exception as exc:  # noqa: BLE001 — str() runs the value's own code; any failure is "no text"
        raise InspectAdapterError(f"{feld} has no text form: {render_safe(wert)} ({type(exc).__name__})") from exc


def _score_str(value) -> str:
    """Render a metric value as a PLAIN decimal string (no scientific notation) that build_eval_claim
    accepts. ``repr(float)`` emits '1e-05'/'1e+20' for very small/large values, which the claim's decimal
    pattern rejects — so numbers are formatted fixed-point (like the pytest plugin's ``_fmt``)."""
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return _text(value, "metric value")
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise InspectAdapterError("metric value must be finite")
        return format(value, ".12f").rstrip("0").rstrip(".") or "0"
    return _text(value, "metric value")


def from_inspect_ai_log(path, metric: str, *, comparator: str, threshold: str, timestamp: str,
                        model_salt: Optional[bytes] = None, dataset_salt: Optional[bytes] = None,
                        capture: str = "persisted_log_reader"):
    """Read an inspect_ai eval log via the stable API and build an eval claim for `metric`.

    ``path`` may be a path/str to a ``.eval`` log OR an already-loaded EvalLog object (e.g. the inspect_ai
    hook's ``data.log``). Returns (claim, salts). Raises InspectAdapterError if inspect_ai is unavailable
    or the log is missing the expected attributes — a clear error instead of an opaque AttributeError.

    ``capture`` names HOW the log reached this adapter and is written into the receipt's provenance as
    ``capture_mechanism`` (adversarial re-check 2026-08-22: a hook-emitted receipt and a much-later
    reader-emitted one were byte-indistinguishable). Three named values: ``persisted_log_reader``
    (default — this call read a stored log), ``lifecycle_hook`` (live ``data.log`` inside the producing
    process), ``lifecycle_hook_log_reread`` (hook-triggered, but the log was re-read from disk, e.g. the
    header-only ``eval_set`` fallback).
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
            raise InspectAdapterError(f"could not read inspect_ai log {render_safe(path)}: {e}") from e

    ev = getattr(log, "eval", None)
    results = getattr(log, "results", None)
    if ev is None or results is None:
        raise InspectAdapterError("inspect_ai log missing .eval or .results (empty or malformed log)")

    value = None
    matched_score = None
    for score in (getattr(results, "scores", None) or []):
        metrics = getattr(score, "metrics", None) or {}
        if metric in metrics:
            value = getattr(metrics[metric], "value", None)
            matched_score = score
            break
    if value is None or matched_score is None:
        raise InspectAdapterError(f"metric {render_safe(metric)} not found in any score.metrics of the log")

    suite = _text(getattr(ev, "task", "inspect_ai"), "eval.task")
    model_id = _text(getattr(ev, "model", "unknown"), "eval.model")
    dataset = getattr(ev, "dataset", None)
    dataset_id = _text(getattr(dataset, "name", None) or suite, "eval.dataset.name")

    # Provenance parity with the lm-eval adapter: inspect_ai exposes the same run provenance for free.
    provenance: dict[str, Any] = {"harness": "inspect_ai", "capture_mechanism": _text(capture, "capture")}
    revision = getattr(ev, "revision", None)
    commit = getattr(revision, "commit", None)
    if commit:
        provenance["git_hash"] = _text(commit, "eval.revision.commit")
    packages = getattr(ev, "packages", None) or {}
    # v5.0.0: explicit reporting status beside each harness-reported version (see _provenance).
    from ._provenance import bind_reported_version  # noqa: PLC0415
    bind_reported_version(
        provenance, "harness_version",
        packages.get("inspect_ai") if isinstance(packages, dict) else None,
        reason="the inspect_ai eval log carried no `packages['inspect_ai']` entry")
    bind_reported_version(
        provenance, "task_version", getattr(ev, "task_version", None),
        reason="the inspect_ai eval spec carried no `task_version`")

    # Bind the metric to the scorer that produced it. Without these fields, a deterministic scorer
    # and an LLM judge can emit byte-identical claims when their aggregate numbers match. We record
    # objective identity/configuration facts only; no reliability class is inferred here.
    scorer = getattr(matched_score, "scorer", None)
    if scorer:
        provenance["scorer"] = _text(scorer, "score.scorer")
    score_name = getattr(matched_score, "name", None)
    if score_name:
        provenance["score_name"] = _text(score_name, "score.name")
    reducer = getattr(matched_score, "reducer", None)
    if reducer:
        provenance["score_reducer"] = _text(reducer, "score.reducer")
    scored_samples = getattr(matched_score, "scored_samples", None)
    unscored_samples = getattr(matched_score, "unscored_samples", None)
    for name, count in (("scored_samples", scored_samples), ("unscored_samples", unscored_samples)):
        if isinstance(count, int) and not isinstance(count, bool) and count >= 0:
            provenance[name] = count
    params = getattr(matched_score, "params", None)
    if isinstance(params, dict) and params:
        from ._provenance import config_hash
        params_hash = config_hash(params)
        if params_hash:
            provenance["scorer_params_hash"] = params_hash

    # v1.8 (external review): run-id + config-hash + LOG-NATIVE timestamp so a receipt traces back
    # to the exact run. inspect_ai: eval.run_id (unique run id), eval.created (UTC datetime string),
    # eval.task_args (the config material — no native config hash exists, so we compute one).
    from ._provenance import add_provenance  # noqa: PLC0415
    task_args = getattr(ev, "task_args", None)
    add_provenance(provenance, run_id=getattr(ev, "run_id", None),
                   config=task_args if isinstance(task_args, dict) else None,
                   log_timestamp=getattr(ev, "created", None))

    # EvalScore.scored_samples is the population the selected metric was actually computed over.
    # total_samples can include unscored samples, so using it would overstate the signed claim's n.
    metric_n = (scored_samples if isinstance(scored_samples, int)
                and not isinstance(scored_samples, bool) and scored_samples >= 0
                else int(getattr(results, "total_samples", 0) or 0))

    return build_eval_claim(
        suite=suite, suite_version=_text(getattr(ev, "task_version", "1"), "eval.task_version"),
        metric=metric, comparator=comparator, threshold=threshold, score=_score_str(value),
        n=metric_n,
        model_id=model_id, dataset_id=dataset_id, issuer="", timestamp=timestamp,
        provenance=provenance, model_salt=model_salt, dataset_salt=dataset_salt)
