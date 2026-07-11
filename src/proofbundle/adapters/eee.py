"""Adapter: an Every Eval Ever (EEE) dataset record → a signed proofbundle eval receipt (v0.9).

Every Eval Ever (evaleval/every_eval_ever, MIT) is the community aggregation schema for eval metadata —
it has no cryptography. This converter is strictly additive: it reads an EEE aggregate JSON and builds a
signed, selectively-disclosable proofbundle receipt from it.

IMPORTANT: `every_eval_ever` is NOT imported at runtime — it requires Python 3.12+ (pydantic/numpy/pandas/
duckdb), while proofbundle stays 3.10+. We parse the EEE JSON directly and OPTIONALLY validate it against the
vendored `eee_eval_schema.json` (schema version 0.2.2, MIT) using `jsonschema` if available.

Field mapping (verified 2026-07 against schemas/eval.schema.json v0.2.2):
  - model_info.id                                            → model_id
  - evaluation_results[i].evaluation_name                    → suite / task
  - evaluation_results[i].source_data.dataset_name           → dataset_id (required in every source variant)
  - metric_config.metric_name | metric_id | metric_kind      → metric (all optional; fallback chain)
  - score_details.score                                      → score
  - score_details.uncertainty.standard_error.value           → provenance.stderr
  - eval_library.{name,version}                              → provenance.harness / harness_version
Gotcha handled: metric_config with score_type == "levels" is an integer level index; -1 with
has_unknown_level == true means Unknown and is rejected (not silently mapped to 0).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Union

from ..evalclaim import build_eval_claim
from ._provenance import add_provenance

_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "eee_eval_schema.json"
_SCHEMA_VERSION = "0.2.2"


class EEEAdapterError(ValueError):
    """Raised when the EEE record is missing the expected structure — a clear error, not a bare KeyError."""


def _load(source: Union[str, Path, dict]) -> dict:
    if isinstance(source, dict):
        return source
    try:
        return json.loads(Path(source).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise EEEAdapterError(f"could not read EEE dataset {source!r}: {e}") from e


def _validate(record: dict) -> None:
    """Best-effort schema validation against the vendored EEE schema (skipped if jsonschema/schema absent)."""
    try:
        import jsonschema  # noqa: PLC0415
    except ImportError:
        return
    if not _SCHEMA_PATH.is_file():
        return
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    try:
        jsonschema.validate(record, schema)
    except jsonschema.ValidationError as e:
        raise EEEAdapterError(f"EEE record does not validate against schema {_SCHEMA_VERSION}: {e.message}") from e


def _num_to_decimal_str(x) -> str:
    """Format a JSON number as a plain decimal string (no exponent) for build_eval_claim's pattern."""
    if isinstance(x, bool) or not isinstance(x, (int, float)):
        raise EEEAdapterError(f"score must be a number, got {type(x).__name__}")
    if isinstance(x, int):
        return str(x)
    if x != x or x in (float("inf"), float("-inf")):   # NaN/Inf
        raise EEEAdapterError("score must be finite")
    s = repr(x)
    if "e" in s or "E" in s:                             # avoid exponent form (build_eval_claim rejects it)
        s = f"{x:.12f}".rstrip("0").rstrip(".")
    return s


def _pick_metric(metric_config: dict) -> str:
    for key in ("metric_name", "metric_id", "metric_kind"):
        v = metric_config.get(key)
        if isinstance(v, str) and v:
            return v
    return "score"


def _extract_score(score_details: dict, metric_config: dict) -> str:
    if "score" not in score_details:
        raise EEEAdapterError("evaluation_results[].score_details.score is required")
    raw = score_details["score"]
    if metric_config.get("score_type") == "levels":
        if not isinstance(raw, (int, float)) or isinstance(raw, bool):
            raise EEEAdapterError("levels score must be an integer level index")
        idx = int(raw)
        if idx == -1 and metric_config.get("has_unknown_level"):
            raise EEEAdapterError("levels score is -1 (Unknown) — cannot build a threshold claim")
        return str(idx)
    return _num_to_decimal_str(raw)


def _record_digest(record: dict) -> str:
    """``"<alg>:<hex>"`` over the canonical EEE record JSON (WP-I3). JCS when the ``[eval]`` extra
    is present (the emit path needs it anyway), else a labeled deterministic fallback — the label
    tells a verifier which normalization produced the hex, never a silent difference."""
    import hashlib  # noqa: PLC0415
    try:
        import rfc8785  # noqa: PLC0415
        return "sha256-jcs:" + hashlib.sha256(rfc8785.dumps(record)).hexdigest()
    except (ImportError, ValueError, TypeError):
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False).encode("utf-8")
        return "sha256-sortkeys:" + hashlib.sha256(canonical).hexdigest()


def from_eee_dataset(source: Union[str, Path, dict], *, comparator: str, threshold: str,
                     timestamp: Optional[str] = None, eval_index: int = 0, metric_name: Optional[str] = None,
                     model_salt: Optional[bytes] = None, dataset_salt: Optional[bytes] = None,
                     validate: bool = True):
    """Read an EEE dataset record and build a proofbundle eval claim for one evaluation result.

    `comparator`/`threshold` set the pass/fail assertion (EEE stores the raw score, not a threshold verdict).
    `eval_index` selects which of `evaluation_results` to use; `metric_name` instead selects the first result
    whose metric matches. Returns (claim, salts). Raises EEEAdapterError on a malformed record.
    """
    record = _load(source)
    if not isinstance(record, dict):
        raise EEEAdapterError("EEE dataset must be a JSON object")
    if validate:
        _validate(record)

    model_info = record.get("model_info") or {}
    model_id = model_info.get("id")
    if not model_id:
        raise EEEAdapterError("EEE record missing model_info.id")

    results = record.get("evaluation_results")
    if not isinstance(results, list) or not results:
        raise EEEAdapterError("EEE record has no evaluation_results")

    if metric_name is not None:
        chosen = next((r for r in results if isinstance(r, dict)
                       and _pick_metric(r.get("metric_config") or {}) == metric_name), None)
        if chosen is None:
            raise EEEAdapterError(f"no evaluation_result with metric {metric_name!r}")
    else:
        if eval_index < 0 or eval_index >= len(results):
            raise EEEAdapterError(f"eval_index {eval_index} out of range (0..{len(results) - 1})")
        chosen = results[eval_index]
    if not isinstance(chosen, dict):
        raise EEEAdapterError("evaluation_results item is not an object")

    metric_config = chosen.get("metric_config") or {}
    score_details = chosen.get("score_details") or {}
    source_data = chosen.get("source_data") or {}

    suite = chosen.get("evaluation_name")
    if not suite:
        raise EEEAdapterError("evaluation_results[].evaluation_name is required")
    dataset_id = source_data.get("dataset_name") or str(suite)   # dataset_name is required in EEE; defensive fallback
    metric = _pick_metric(metric_config)
    score = _extract_score(score_details, metric_config)

    eval_library = record.get("eval_library") or {}
    ts = timestamp or chosen.get("evaluation_timestamp") or record.get("retrieved_timestamp")
    if not ts:
        raise EEEAdapterError("no timestamp: pass timestamp= or set retrieved_timestamp/evaluation_timestamp")

    provenance = {"source": "every_eval_ever", "eee_schema_version": record.get("schema_version") or _SCHEMA_VERSION}
    # WP-I3: bind the receipt to the EXACT source record — the only adapter without a provenance
    # binding. sha256 over the RFC-8785 (JCS) canonical record JSON, labeled with the algorithm
    # (fallback sort_keys, labeled, mirrors adapters/_provenance.config_hash). Privacy note: the
    # record contains model_info.id in cleartext, but a sha256 DIGEST of the full record does not
    # disclose it (and, unlike the receipt's salted commitment, the digest binds the WHOLE record,
    # scores and timestamps included — enough entropy that the id is not enumerable from it).
    provenance["eee_record_sha256"] = _record_digest(record)
    # the RESULT-level id is traceability metadata; the TOP-level evaluation_id embeds the model id
    # in cleartext and stays deliberately excluded (see the note below). Guard the result id the
    # same way: if a producer embedded the model id in it, drop it rather than leak.
    _rid = chosen.get("evaluation_result_id")
    if isinstance(_rid, str) and _rid and str(model_id) not in _rid:
        add_provenance(provenance, run_id=_rid)
    if eval_library.get("name"):
        provenance["harness"] = str(eval_library["name"])
    if eval_library.get("version"):
        provenance["harness_version"] = str(eval_library["version"])
    # NOTE: the EEE `evaluation_id` (format eval_name/model_id/timestamp) embeds the model id in cleartext,
    # which would defeat proofbundle's salted model commitment (a receipt is meant to hide the model). So it
    # is deliberately NOT copied into provenance — the receipt keeps the model private by design.
    if metric_config.get("metric_id"):
        provenance["metric_id"] = str(metric_config["metric_id"])
    if metric_config.get("score_type"):
        provenance["score_type"] = str(metric_config["score_type"])
    se = ((score_details.get("uncertainty") or {}).get("standard_error") or {}).get("value")
    if isinstance(se, (int, float)) and not isinstance(se, bool):
        provenance["stderr"] = str(se)
    rel = (record.get("source_metadata") or {}).get("evaluator_relationship")
    if rel:
        provenance["evaluator_relationship"] = str(rel)

    return build_eval_claim(
        suite=str(suite), suite_version=str(eval_library.get("version") or "unknown"),
        metric=metric, comparator=comparator, threshold=threshold, score=score,
        n=int((score_details.get("uncertainty") or {}).get("num_samples") or 0),
        model_id=str(model_id), dataset_id=str(dataset_id), issuer="", timestamp=str(ts),
        provenance=provenance, model_salt=model_salt, dataset_salt=dataset_salt)
