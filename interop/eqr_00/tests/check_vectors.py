"""Run every derived vector and check the bookkeeping that ties vectors to requirements."""
from __future__ import annotations

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, "vectors")]

import build  # noqa: E402
import evaluate  # noqa: E402
import generate_vectors  # noqa: E402
from eqr00.wire import decode_json  # noqa: E402


def _read(name):
    with open(os.path.join(ROOT, name), "rb") as fh:
        return decode_json(fh.read())


COMMITTED = _read(os.path.join("vectors", "eqr00_vectors.json"))
REQS = _read("requirements.json")
MAP = _read("requirements_map.json")
VECTORS = COMMITTED["vectors"]


@pytest.mark.parametrize("vec", VECTORS, ids=[v["id"] for v in VECTORS])
def test_vector(vec):
    ok, fails, _ = evaluate.evaluate(vec)
    assert ok, fails


def test_committed_vectors_equal_a_fresh_generation():
    with open(os.path.join(ROOT, "vectors", "eqr00_vectors.json"), "rb") as fh:
        assert fh.read() == generate_vectors.render()


def test_vector_ids_unique_and_both_polarities_present():
    ids = [v["id"] for v in VECTORS]
    assert len(ids) == len(set(ids))
    assert {v["polarity"] for v in VECTORS} == {"positive", "negative"}


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
        if e["category"] in ("agreement", "ambiguity"):
            assert cov.get(rid) == {"positive", "negative"}, (rid, sorted(cov.get(rid, [])))
        if e["category"] == "not_implemented":
            assert rid not in cov, rid


def test_signed_vectors_carry_only_public_keys():
    """The test keys sign the vectors; their private halves never enter the file."""
    with open(os.path.join(ROOT, "vectors", "eqr00_vectors.json"), "rb") as fh:
        raw = fh.read()
    assert b'"d":' not in raw and b"PRIVATE" not in raw


def test_requirement_index_counts():
    assert REQS["sha256"] == "e9d47a647af3d1474f3c4fdcc286d6dae3d60a2a378e1f86741e4e95cb81bd5d"
    assert REQS["line_count"] == 1064
    assert REQS["requirement_count"] == len(REQS["requirements"]) == 30
