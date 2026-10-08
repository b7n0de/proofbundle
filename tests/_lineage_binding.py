"""Test helper for Nachtrag 48/48b (`KRAXO-CLOUD-N46B-N48B-BINDUNG-NACH-REVIEW-01`, Z309, F2).

evaluate_relations_policy now satisfies a relation_signer rule only when the lineage result is bound to the
verified successor receipt for exactly the successor key and relation data it judges (an origin token a passing
verify stamps). A test that exercises relation_signer in isolation (a hand-built lineage, not a full verify)
uses this to stamp the lineage exactly as a passing verify_decision_receipt / verify_outcome_receipt /
verify_relation_statement would — an honest simulation of the verifier's output.
"""
from __future__ import annotations

from typing import Any

from proofbundle.relation import _stamp_lineage_origin


def bound_lineage(lineage_result: dict, successor_key_b64: str) -> dict:
    """Stamp ``lineage_result`` (in place) with the successor key it was verified under, and return it."""
    _stamp_lineage_origin(lineage_result, successor_key_b64)
    return lineage_result


def bound_lineage_copy(lineage_result: dict, successor_key_b64: str) -> dict:
    """A shallow copy of ``lineage_result`` stamped for ``successor_key_b64`` (leaves the original unstamped)."""
    out: dict[str, Any] = dict(lineage_result)
    _stamp_lineage_origin(out, successor_key_b64)
    return out
