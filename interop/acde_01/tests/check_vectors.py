"""Run every derived vector and check the bookkeeping that ties vectors to requirements."""
from __future__ import annotations

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, "vectors")]

import build  # noqa: E402
import evaluate  # noqa: E402
import generate_vectors  # noqa: E402

with open(os.path.join(ROOT, "vectors", "acde01_vectors.json"), encoding="ascii") as fh:
    COMMITTED = json.load(fh)
with open(os.path.join(ROOT, "requirements.json"), encoding="ascii") as fh:
    REQS = json.load(fh)
with open(os.path.join(ROOT, "requirements_map.json"), encoding="ascii") as fh:
    MAP = json.load(fh)
VECTORS = [evaluate.expand(v, COMMITTED) for v in COMMITTED["vectors"]]


@pytest.mark.parametrize("vec", VECTORS, ids=[v["id"] for v in VECTORS])
def test_vector(vec):
    ok, fails, _ = evaluate.evaluate(vec)
    assert ok, fails


def test_committed_vectors_equal_a_fresh_generation():
    with open(os.path.join(ROOT, "vectors", "acde01_vectors.json"), "rb") as fh:
        assert fh.read() == generate_vectors.render()


def test_vector_ids_unique():
    ids = [v["id"] for v in VECTORS]
    assert len(ids) == len(set(ids))


def test_every_requirement_is_categorised():
    ids = [r["id"] for r in REQS["requirements"]]
    assert sorted(ids) == sorted(MAP["requirements"])
    for rid, e in MAP["requirements"].items():
        assert e["category"] in MAP["categories"], rid
        if e["category"] == "ambiguity":
            assert len(e["readings"]) >= 2 and e["implemented"] and e["text_refs"], rid
        if e["category"] == "not_implemented":
            assert e["reason"], rid


def test_implemented_requirements_have_a_positive_and_a_negative_vector():
    cov = {}
    for v in VECTORS:
        for r, pol in build.requirement_polarity(v):
            cov.setdefault(r, set()).add(pol)
    known = {r["id"] for r in REQS["requirements"]}
    assert set(cov) <= known, sorted(set(cov) - known)
    for rid, e in MAP["requirements"].items():
        if e["category"] in ("agreement", "ambiguity") and rid != "SA.MCC-1":
            assert cov.get(rid) == {"positive", "negative"}, (rid, sorted(cov.get(rid, [])))
        if e["category"] == "not_implemented":
            assert rid not in cov, rid


def test_every_conformance_case_has_a_vector():
    """SA.MCC-1: machine-readable vectors for at least the 30 minimum conformance cases."""
    cases = {c for v in VECTORS for c in v["conformance_cases"]}
    assert cases >= set(range(1, 31)), sorted(set(range(1, 31)) - cases)


def test_requirement_index_counts():
    assert REQS["sha256"] == "2f0356fcb834ba6b80970721273cd8e2e0b2cc19ef1f89a0205a78991653fabf"
    assert REQS["line_count"] == 2576
    assert REQS["requirement_count"] == len(REQS["requirements"]) == 130
