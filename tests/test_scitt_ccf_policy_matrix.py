"""The policy-boundary matrix, tools/scitt_ccf_external/differential_corpus_round3/matrix.json.

The matrix is derived from the stored bytes of the corpus's rounds 1 and 2 alone. These tests hold it
to what `policy_matrix.py` derives, the README table to the matrix, and the measured statements of the
README to the rows: the counts, the data-hash through three encoders, the error text of every
refusal, and what our reader does with the unprotected bucket. The expected-policy column stays
PENDING until the reviewed design names a source per row.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / "tools" / "scitt_ccf_external"
MATRIX = TOOLS / "differential_corpus_round3" / "matrix.json"
README = TOOLS / "differential_corpus_round3" / "README.md"

needs_cbor2 = pytest.mark.skipif(importlib.util.find_spec("cbor2") is None,
                                 reason="the scitt-ccf reader and the corpus readings need cbor2")


def _tool():
    name = "_scitt_ccf_policy_matrix"
    if name not in sys.modules:
        if str(TOOLS) not in sys.path:
            sys.path.insert(0, str(TOOLS))
        spec = importlib.util.spec_from_file_location(name, TOOLS / "policy_matrix.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    return sys.modules[name]


def _matrix() -> dict:
    return json.loads(MATRIX.read_text(encoding="utf-8"))


def _rows() -> dict:
    return {r["vector"]: r for r in _matrix()["rows"]}


@needs_cbor2
def test_the_matrix_is_what_the_tool_derives_from_the_stored_bytes():
    derived = _tool().derive()
    assert json.dumps(derived, indent=1, ensure_ascii=False) + "\n" == MATRIX.read_text(encoding="utf-8")


def test_the_readme_table_is_the_matrix():
    tool = _tool()
    text = README.read_text(encoding="utf-8")
    table = text.split(tool.BEGIN, 1)[1].split(tool.END, 1)[0]
    assert table.strip() == tool.table(_matrix()).strip()


def test_one_row_per_vector_of_rounds_1_and_2_and_the_counts_the_readme_states():
    rows = _matrix()["rows"]
    assert len(rows) == 64
    for number, corpus in ((1, "differential_corpus"), (2, "differential_corpus_round2")):
        man = json.loads((TOOLS / corpus / "manifest.json").read_text(encoding="utf-8"))
        assert [r["vector"] for r in rows if r["round"] == number] == [f"r{number}/{v}" for v in man["vectors"]]
    accepted = [r for r in rows if r["accepted_refused"] == "accepted"]
    assert (len(accepted), len(rows) - len(accepted)) == (48, 16)
    counts = _matrix()["counts"]
    for key, want in {"r1/a": (13, 0), "r1/b": (2, 2), "r1/c": (3, 2), "r1/d": (3, 2), "r1/e": (3, 0),
                      "r1/f": (3, 0), "r2/g": (8, 1), "r2/h": (5, 4), "r2/i": (3, 5), "r2/j": (2, 0)}.items():
        assert (counts[key]["accepted"], counts[key]["refused"]) == want, key


def test_every_accepted_row_matches_the_preimage_rule_through_three_encoders():
    for r in _matrix()["rows"]:
        d = r["data_hash_match"]
        if r["accepted_refused"] == "accepted":
            assert (d["own"], d["cbor2"], d["evercbor"]) == (True, True, True), r["vector"]
        else:
            assert d["text"] == "n/a: refused, no receipt" and d["receipt_data_hash"] is None, r["vector"]


def test_every_accepted_unprotected_mutation_commits_to_the_controls_data_hash():
    rows = _rows()
    same = {v for v, r in rows.items() if r["data_hash_match"].get("equals_round_control")}
    unprotected = {f"r1/a{i:02d}" for i in range(1, 14)} | {"r1/e01", "r1/e02", "r1/e03"} | \
                  {f"r2/h0{i}" for i in range(5, 10)}
    for v in rows:
        if any(v.startswith(p + "-") for p in unprotected):
            assert v in same, v
            assert "[394]" in rows[v]["committed_representation"], v
    assert len(same) == 34


def test_every_refusal_carries_its_error_text_and_nothing_accepted_is_read_as_interpreted():
    for r in _matrix()["rows"]:
        if r["accepted_refused"] == "refused":
            assert r["parser_visible_interpretation"] == f"error text: {r['service']['error']}", r["vector"]
            assert r["service"]["error"], r["vector"]
        else:
            assert r["parser_visible_interpretation"].startswith("NOT MEASURABLE: "), r["vector"]
        assert r["expected_policy_result"].startswith("PENDING: "), r["vector"]


def test_the_unprotected_bucket_never_leads_our_reader_to_accept():
    # Emptying the unprotected map changes our reader's statement-side verdict only from a refusal to a
    # confirmation: what stands in that bucket can make the reader refuse, never accept.
    changed = {}
    for r in _matrix()["rows"]:
        if not r["reader_unprotected_effect"].startswith("none"):
            changed[r["vector"].split("-")[0]] = r["reader_unprotected_effect"]
            assert r["our_reader_submitted"]["statement_status"] != "confirmed", r["vector"]
            assert r["reader_unprotected_effect"].endswith("confirmed with the unprotected map emptied")
    assert sorted(changed) == ["r1/a09", "r1/a10", "r2/h03", "r2/h04", "r2/h05", "r2/h06", "r2/h07", "r2/h08",
                               "r2/h09"]


def test_our_reader_is_never_less_strict_than_the_service():
    against = [r["reader_against_service"] for r in _matrix()["rows"]]
    assert not [a for a in against if a.startswith("less strict")]
    assert sum(a.startswith("stricter") for a in against) == 24
