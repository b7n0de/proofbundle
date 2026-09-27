"""The policy-boundary matrix, tools/scitt_ccf_external/differential_corpus_round3/matrix.json.

The matrix is derived from the stored bytes of the corpus's three rounds (design version 2 of the owner
order of 2026-09-27). These tests hold it to what `policy_matrix.py` derives, the README table to the
matrix, and the measured statements of the README to the rows: the counts, the data-hash rule, the
error text of every refusal, round 3's predictions and states, the two-key experiment, what our reader
does with the unprotected bucket, and the one row where our reader was less strict than the service.
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
NORMATIVE = TOOLS / "differential_corpus_round3" / "normative.json"
SOURCES = TOOLS / "differential_corpus_round3" / "sources.json"
CLASSES = ("explicit rejection required", "mandatory input constraint violated", "conditional processing requirement",
           "permitted form, admission policy dependent", "implementation/profile restriction",
           "no applicable placement rule established in the named sources")

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


def test_one_row_per_vector_of_three_rounds_and_the_counts_the_readme_states():
    rows = _matrix()["rows"]
    assert len(rows) == 84
    for number, corpus in ((1, "differential_corpus"), (2, "differential_corpus_round2"),
                           (3, "differential_corpus_round3")):
        man = json.loads((TOOLS / corpus / "manifest.json").read_text(encoding="utf-8"))
        assert [r["vector"] for r in rows if r["round"] == number] == [f"r{number}/{v}" for v in man["vectors"]]
    accepted = [r for r in rows if r["accepted_refused"] == "accepted"]
    assert (len(accepted), len(rows) - len(accepted)) == (62, 22)
    counts = _matrix()["counts"]
    for key, want in {"r1/a": (13, 0), "r1/b": (2, 2), "r1/c": (3, 2), "r1/d": (3, 2), "r1/e": (3, 0),
                      "r1/f": (3, 0), "r2/g": (8, 1), "r2/h": (5, 4), "r2/i": (3, 5), "r2/j": (2, 0),
                      "r3/control": (2, 0), "r3/rejection control": (0, 2),
                      "r3/implementation-regression control": (0, 1), "r3/rerun": (4, 0), "r3/mutation": (4, 1),
                      "r3/two-key control": (2, 0), "r3/two-key": (2, 2)}.items():
        assert (counts[key]["accepted"], counts[key]["refused"]) == want, key


def test_every_registered_row_matches_the_preimage_rule():
    for r in _matrix()["rows"]:
        d = r["data_hash_match"]
        if r["accepted_refused"] == "accepted":
            assert r["registration"]["state"] == "registered", r["vector"]
            if r["round"] < 3:
                assert (d["own"], d["cbor2"], d["evercbor"]) == (True, True, True), r["vector"]
            else:
                assert (d["own"], d["cbor2"], d["evercbor"]) == (True, True, None), r["vector"]
                assert "evercbor NOT MEASURED" in d["text"], r["vector"]
        else:
            assert d["text"] == "NOT MEASURABLE: refused, no receipt" and d["receipt_data_hash"] is None, r["vector"]
            assert r["committed_representation"].startswith("NOT MEASURABLE: "), r["vector"]


def test_every_accepted_unprotected_mutation_commits_to_the_controls_data_hash():
    rows = _rows()
    same = {v for v, r in rows.items() if r["data_hash_match"].get("equals_round_control")}
    unprotected = {f"r1/a{i:02d}" for i in range(1, 14)} | {"r1/e01", "r1/e02", "r1/e03"} | \
                  {f"r2/h0{i}" for i in range(5, 10)} | {"r3/r-a10", "r3/r-h08", "r3/r-h07", "r3/r-h06",
                                                         "r3/b259"}
    for v in rows:
        if any(v.startswith(p + "-") for p in unprotected):
            assert v in same, v
            assert "[394]" in rows[v]["committed_representation"], v
    assert len([v for v in same if v.startswith(("r1/", "r2/"))]) == 34
    assert sorted(v for v in same if v.startswith("r3/")) == [
        "r3/b259-conflicting", "r3/control", "r3/r-a10-cwt-claims-unprotected", "r3/r-h06-alg-both-buckets-conflicting",
        "r3/r-h07-payload-hash-alg-both-buckets-conflicting", "r3/r-h08-cwt-claims-both-buckets-equal"]


def test_every_refusal_carries_its_error_text_and_nothing_accepted_is_read_as_interpreted():
    for r in _matrix()["rows"]:
        if r["accepted_refused"] == "refused":
            assert r["parser_visible_interpretation"] == f"error text: {r['service']['error']}", r["vector"]
            assert r["service"]["error"], r["vector"]
        else:
            assert r["parser_visible_interpretation"].startswith("NOT MEASURABLE: "), r["vector"]


def test_every_row_has_a_normative_class_from_the_named_sources():
    normative = json.loads(NORMATIVE.read_text(encoding="utf-8"))
    rows = _rows()
    assert sorted(normative["rows"]) == sorted(rows)
    cited = {s["cited"] for src in json.loads(SOURCES.read_text(encoding="utf-8"))["sources"] for s in src["sections"]}
    for v, n in normative["rows"].items():
        assert n["normative_class"] in CLASSES, v
        assert n["sources"] and all(s["text"] for s in n["sources"]), v
        assert {s["section"] for s in n["sources"]} <= cited, v
        if n["normative_class"] == "conditional processing requirement":
            assert n.get("condition"), v
        assert rows[v]["normative"]["normative_class"] == n["normative_class"], v


def test_round_3_outcomes_equal_the_predictions_written_before_the_run():
    for r in _matrix()["rows"]:
        if r["round"] == 3:
            assert r["registration"]["state"] in ("registered", "refused"), r["vector"]
            assert (r["registration"]["state"] == "registered") == (r["predicted"]["outcome"] == "accepted"), r["vector"]
        else:
            assert r["predicted"]["outcome"] is None and r["predicted"]["why"].startswith("NOT RECORDED"), r["vector"]


def test_the_two_key_experiment_registers_only_what_the_protected_x5chain_key_signed():
    rows = _rows()
    for v, protected_key in (("x-a-only", "A"), ("x-b-only", "B"), ("x-pa-ub-sig-a", "A"), ("x-pa-ub-sig-b", "A"),
                             ("x-pb-ua-sig-a", "B"), ("x-pb-ua-sig-b", "B")):
        r = rows[f"r3/{v}"]
        verifies = [k for k, ok in r["statement_signature_checks"]["which_key_verifies"].items() if ok]
        assert len(verifies) == 1, v
        assert (r["registration"]["state"] == "registered") == (verifies == [protected_key]), v
        if r["registration"]["state"] == "refused":
            assert "Signature verification failed" in r["registration"]["api_detail"], v


def test_the_unprotected_bucket_never_leads_our_reader_to_accept():
    # Emptying the unprotected map changes our reader's statement-side verdict only from a refusal: what
    # stands in that bucket can make the reader refuse, never accept.
    changed = {}
    for r in _matrix()["rows"]:
        if not r["reader_unprotected_effect"].startswith("none"):
            changed[r["vector"].split("-")[0] if r["round"] < 3 else r["vector"]] = r["reader_unprotected_effect"]
            assert r["our_reader_submitted"]["statement_status"] != "confirmed", r["vector"]
    assert sorted(changed) == ["r1/a09", "r1/a10", "r2/h03", "r2/h04", "r2/h05", "r2/h06", "r2/h07", "r2/h08",
                               "r2/h09", "r3/b259-conflicting", "r3/m-u2", "r3/m-u259", "r3/r-a10-cwt-claims-unprotected",
                               "r3/r-h06-alg-both-buckets-conflicting", "r3/r-h07-payload-hash-alg-both-buckets-conflicting",
                               "r3/r-h08-cwt-claims-both-buckets-equal", "r3/x-pa-ub-sig-a", "r3/x-pa-ub-sig-b",
                               "r3/x-pb-ua-sig-a", "r3/x-pb-ua-sig-b"]


def test_our_reader_is_less_strict_than_the_service_in_one_row_the_finding_of_round_3():
    """M-u15: the service refused a statement whose CWT Claims stand only unprotected, and the v1 reader
    of 531e2564 read its statement side as confirmed. Recorded as measured; the red test and the fix are
    on their own branch (claude/scitt-reader-cwt-claims, 1f07ccf3 and 56061d8d), not on PR 278."""
    against = {r["vector"]: r["reader_against_service"] for r in _matrix()["rows"]}
    assert [v for v, a in against.items() if a.startswith("less strict")] == ["r3/m-u15"]
    assert sum(a.startswith("stricter") for a in against.values()) == 35
    row = _rows()["r3/m-u15"]
    assert row["our_reader_submitted"]["statement_status"] == "confirmed"
    assert "CWT_Claims" in row["registration"]["api_detail"]
    assert row["normative"]["normative_class"] == "mandatory input constraint violated"
