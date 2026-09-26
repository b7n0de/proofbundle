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
