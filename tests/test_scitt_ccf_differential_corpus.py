"""The differential corpus in tools/scitt_ccf_external/differential_corpus, held to its stored form.

The corpus stores raw bytes as hex text and what cannot be derived (owner answer C1 b). These tests
check the stored form in both environments, and with the [scitt] extra that summary.json and
admissibility.json are exactly what the tool derives from the raw bytes, so no derived view can
drift from the bytes it describes.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
CORPUS = REPO / "tools" / "scitt_ccf_external" / "differential_corpus"


def _tool(file: str = "differential_corpus.py"):
    name = "_scitt_ccf_" + file[:-3]
    if name not in sys.modules:
        tools = str(REPO / "tools" / "scitt_ccf_external")
        if tools not in sys.path:
            sys.path.insert(0, tools)
        spec = importlib.util.spec_from_file_location(name, REPO / "tools" / "scitt_ccf_external" / file)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    return sys.modules[name]


def _hex(path: Path) -> bytes:
    return bytes.fromhex("".join(path.read_text(encoding="ascii").split()))


def test_every_vector_is_stored_as_text_with_its_digest():
    man = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))
    assert sorted(man["vectors"]) == sorted(p.name for p in (CORPUS / "vectors").iterdir())
    assert len(man["vectors"]) == 35
    assert hashlib.sha256(_hex(CORPUS / "scitt-keys.hex")).hexdigest() == man["service_keyset"]["sha256"]
    for vid in man["vectors"]:
        d = CORPUS / "vectors" / vid
        rec = json.loads((d / "record.json").read_text(encoding="utf-8"))
        derived = {"candidate_hashes.json"} if rec["service"]["accepted"] else set()
        assert {p.name for p in d.iterdir()} == set(rec["files"]) | {"record.json"} | derived, vid
        assert ("receipt.hex" in rec["files"]) == rec["service"]["accepted"], vid
        for name, want in rec["files"].items():
            raw = _hex(d / name)
            assert (len(raw), hashlib.sha256(raw).hexdigest()) == (want["length"], want["sha256"]), (vid, name)
        assert rec["pins"] == man["pins"], vid                   # pinned per record


def test_the_corpus_holds_no_binary_file_and_no_private_key():
    for p in CORPUS.rglob("*"):
        if p.is_file():
            text = p.read_bytes()
            assert b"\x00" not in text, p                        # text only (AGENTS.md: no new binary files)
            text.decode("utf-8")
            assert b"PRIVATE KEY" not in text, p


@pytest.mark.skipif(importlib.util.find_spec("cbor2") is None, reason="the scitt-ccf reader needs the [scitt] extra")
def test_the_stored_summaries_are_what_the_tool_derives_from_the_raw_bytes():
    t = _tool()
    _records, summary, admissibility = t.derive(CORPUS)
    assert (CORPUS / "summary.json").read_text(encoding="utf-8") == t._dump(summary)
    assert (CORPUS / "admissibility.json").read_text(encoding="utf-8") == t._dump(admissibility)
    c = summary["what_the_data_hash_commits_to"]
    assert [c[k]["accepted"] for k in "abcdef"] == [13, 2, 3, 3, 3, 3]
    assert c["measured_rule_holds_for_every_accepted_vector"] is True


def test_one_byte_string_is_the_data_hash_preimage_of_every_accepted_vector():
    """The ten candidates of preimage_candidates.py, recomputed from the raw bytes by the tool's own
    reader and encoder (no cbor2). Only the tagged COSE_Sign1 with an empty unprotected map matches
    all 29, reached two ways: rebuilt from the contents (4) and cut from the returned statement (3)."""
    per, summary = _tool("preimage_candidates.py").derive(CORPUS)
    assert len(per) == 29
    matches = {row["candidate"]: row["matches"] for row in summary["table"]}
    assert [c for c, m in matches.items() if m == 29] == ["3-tagged", "4-tagged"]
    assert summary["same_bytes_in_every_accepted_vector"]["4-tagged"] == ["3-tagged", "4-tagged"]
    assert matches["1"] == 5 and matches["5-sorted-tagged"] == 14 and matches["6"] == 0
    stored = json.loads((CORPUS / "preimage_summary.json").read_text(encoding="utf-8"))
    assert {row["candidate"]: row["matches"] for row in stored["table"]} == matches


@pytest.mark.skipif(importlib.util.find_spec("cbor2") is None, reason="the foreign readings need cbor2")
def test_the_stored_candidate_hashes_are_what_the_tool_derives():
    t = _tool("preimage_candidates.py")
    per, summary = t.derive(CORPUS)
    for vid, obj in per.items():
        assert (CORPUS / "vectors" / vid / "candidate_hashes.json").read_text(encoding="utf-8") == t._dump(obj), vid
    assert (CORPUS / "preimage_summary.json").read_text(encoding="utf-8") == t._dump(summary)
    assert summary["data_hash_readers"] == {"own_reader": 29, "cbor2_agrees": 29}


#: the two vectors kept as fixtures: a label in both header buckets, accepted by the service,
#: refused by the v1 reader as submitted; (label, the same value in both buckets, file digests)
BOTH_BUCKETS = {
    "a09-x5chain-both-buckets": (33, True, {
        "request.hex": "1cc09f823f7031db19ff403ef77543c13f4d6450498c7e6a575f5fead1dc697b",
        "statement.hex": "2856c9b32cd52ae7ae3823e9374951d6691b07dc5ef694813c2fc504be7c873f"}),
    "a10-cwt-claims-unprotected": (15, False, {
        "request.hex": "438162d8f74c898e9833226658c15b09c65e1dfd6d6f8f5df7700ce3b255ef4c",
        "statement.hex": "e24d0282ef36295053f1915980ed572e5a3d85b4295713c93f66d08c50662453"}),
}


@pytest.mark.parametrize("vid", sorted(BOTH_BUCKETS))
def test_the_both_bucket_vectors_are_kept_as_submitted_and_as_returned(vid):
    t = _tool("preimage_candidates.py")
    label, equal, digests = BOTH_BUCKETS[vid]
    d = CORPUS / "vectors" / vid
    raw = {name: _hex(d / name) for name in digests}
    assert {name: hashlib.sha256(b).hexdigest() for name, b in raw.items()} == digests
    _tag, (prot, unprot, _payload, _sig) = t.sign1(raw["request.hex"])
    pmap, _end = t.parse(prot.value)
    in_prot = [v for k, v in pmap.value if k.value == label]
    in_unprot = [v for k, v in unprot.value if k.value == label]
    assert len(in_prot) == 1 and len(in_unprot) == 1
    assert (t.encode(in_prot[0], sort=False) == t.encode(in_unprot[0], sort=False)) is equal
    _tag, (_p, returned_unprot, _pl, _s) = t.sign1(raw["statement.hex"])
    assert [k.value for k, _v in returned_unprot.value] == [394]
    summary = json.loads((CORPUS / "summary.json").read_text(encoding="utf-8"))
    row = next(v for v in summary["vectors"] if v["id"] == vid)
    assert (row["v1_reader_on_submitted_bytes"], row["v1_reader_on_returned"]) == ("malformed", "confirmed")
