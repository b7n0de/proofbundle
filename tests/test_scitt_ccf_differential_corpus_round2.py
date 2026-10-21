"""The second round of the differential corpus, in tools/scitt_ccf_external/differential_corpus_round2.

The round stores raw bytes as hex text and pins every vector at the moment it was registered, as the
first round does. These tests hold the stored form in both environments. With cbor2 they also check
that every derived view is what the tools derive from the raw bytes. They hold the measured outcome
to the numbers the README states, and check offline that every vector the tool builds carries a
valid signature.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
TOOLS = REPO / "tools" / "scitt_ccf_external"
CORPUS = TOOLS / "differential_corpus_round2"
PIN_COMMIT = "00101f769d872711356e080fbb089ac48589c60a"
PIN_IMAGE = "sha256:1bdd60edc1b8cfc1fb02ed516b5a5ea60d75a3ca4b5d59f128e3c61e23680380"


def _tool(file: str):
    name = "_scitt_ccf_round2_" + file[:-3]
    if name not in sys.modules:
        if str(TOOLS) not in sys.path:
            sys.path.insert(0, str(TOOLS))
        spec = importlib.util.spec_from_file_location(name, TOOLS / file)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    return sys.modules[name]


def _hex(path: Path) -> bytes:
    return bytes.fromhex("".join(path.read_text(encoding="ascii").split()))


def _manifest() -> dict:
    return json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))


def test_every_vector_is_stored_as_text_with_its_digest_and_its_own_pins():
    man = _manifest()
    assert sorted(man["vectors"]) == sorted(p.name for p in (CORPUS / "vectors").iterdir())
    assert len(man["vectors"]) == 29
    assert [p["name"] for p in man["phases"]] == ["initial", "after-configuration-change", "after-restart"]
    for vid in man["vectors"]:
        d = CORPUS / "vectors" / vid
        rec = json.loads((d / "record.json").read_text(encoding="utf-8"))
        derived = {"candidate_hashes.json"} if rec["service"]["accepted"] else set()
        assert {p.name for p in d.iterdir()} == set(rec["files"]) | {"record.json"} | derived, vid
        assert ("receipt.hex" in rec["files"]) == rec["service"]["accepted"], vid
        for name, want in rec["files"].items():
            raw = _hex(d / name)
            assert (len(raw), hashlib.sha256(raw).hexdigest()) == (want["length"], want["sha256"]), (vid, name)
        svc = rec["pins"]["service"]
        assert (svc["commit"], svc["image_id"], svc["node_version"]["ccf_version"]) == (PIN_COMMIT, PIN_IMAGE, "ccf-7.0.17"), vid
        assert "policyScript" in svc["configuration"]["policy"], vid
        assert rec["pins"]["verifier"]["tree_clean"] is True, vid
        assert (CORPUS / rec["phase"]["keyset"]).is_file(), vid


def test_the_round_holds_no_binary_file_and_no_private_key():
    for p in CORPUS.rglob("*"):
        if p.is_file():
            text = p.read_bytes()
            assert b"\x00" not in text, p
            text.decode("utf-8")
            assert b"PRIVATE KEY" not in text, p


def test_one_byte_string_is_the_data_hash_preimage_of_every_accepted_vector_of_the_round():
    """Recomputed by preimage_candidates.py's own reader and encoder, without cbor2. The protected map
    re-encoded (4-deep) misses exactly the 8 accepted g vectors, whose protected map is not core
    deterministic: the service hashes the protected bytes as sent. Every request of this round has
    preferred heads, so the request with its unprotected map emptied (11) is the same bytes as 4."""
    per, summary = _tool("preimage_candidates.py").derive(CORPUS)
    assert len(per) == 19
    matches = {row["candidate"]: row["matches"] for row in summary["table"]}
    assert [c for c, m in matches.items() if m == 19] == ["3-tagged", "4-tagged", "11"]
    assert summary["same_bytes_in_every_accepted_vector"]["4-tagged"] == ["3-tagged", "4-tagged", "11"]
    not_deterministic = sorted(v for v, o in per.items() if not o["facts"]["protected_content_is_core_deterministic"])
    assert not_deterministic == sorted(v for v in per if v.startswith("g"))
    assert len(not_deterministic) == 8
    assert matches["4-deep-tagged"] == 11
    per_class = {k: (v["vectors"], v["accepted"], v["refused"], v["preimage_rule_holds"]) for k, v in summary["per_class"].items()}
    assert per_class == {"control": (1, 1, 0, 1), "g": (9, 8, 1, 8), "h": (9, 5, 4, 5), "i": (8, 3, 5, 3), "j": (2, 2, 0, 2)}
    assert sorted(v for v in per if not per[v]["candidates"]["4-deep-tagged"]["equals_data_hash"]) == not_deterministic


@pytest.mark.skipif(importlib.util.find_spec("cbor2") is None, reason="the scitt-ccf reader and the foreign readings need cbor2")
def test_the_stored_views_are_what_the_tools_derive_from_the_raw_bytes():
    t = _tool("differential_corpus_round2.py")
    _records, summary, admissibility = t.derive(CORPUS)
    assert (CORPUS / "summary.json").read_text(encoding="utf-8") == t._dump(summary)
    assert (CORPUS / "admissibility.json").read_text(encoding="utf-8") == t._dump(admissibility)
    c = summary["classes"]
    assert [(c[k]["vectors"], c[k]["accepted"]) for k in "ghij"] == [(9, 8), (9, 5), (8, 3), (2, 2)]
    assert summary["preimage_rule_holds_for_every_accepted_vector"] is True
    assert c["j"]["data_hash_equals_control"] == ["j01-after-configuration-change", "j02-after-restart"]
    assert all(v["receipt_signature_valid"] for v in summary["vectors"] if v["accepted"])
    p = _tool("preimage_candidates.py")
    per, psummary = p.derive(CORPUS)
    for vid, obj in per.items():
        assert (CORPUS / "vectors" / vid / "candidate_hashes.json").read_text(encoding="utf-8") == p._dump(obj), vid
    assert (CORPUS / "preimage_summary.json").read_text(encoding="utf-8") == p._dump(psummary)
    assert psummary["data_hash_readers"] == {"own_reader": 19, "cbor2_agrees": 19}


def test_every_vector_the_tool_builds_carries_a_valid_signature():
    """Offline, with a fresh signer: the tool's 27 vectors of classes g, h and i, each checked against
    the signer's key over its own protected bytes and payload."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils

    t = _tool("differential_corpus_round2.py")
    c = _tool("preimage_candidates.py")
    key, chain, did, _spki = t.P.make_signer()
    built = t.vectors(key, chain, did, hashlib.sha256(b"payload").digest())
    assert len(built) == 27
    assert {cls for _v, cls, _b, _w, _r in built} == {"control", "g", "h", "i"}
    for vid, _cls, _base, _what, raw in built:
        _tag, (prot, _unprot, payload, sig) = c.sign1(raw)
        tbs = t.R.sig_structure(prot.value, payload.value)
        der = utils.encode_dss_signature(int.from_bytes(sig.value[:32], "big"), int.from_bytes(sig.value[32:], "big"))
        try:
            key.public_key().verify(der, tbs, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            pytest.fail(f"{vid}: the signature does not verify over its own protected bytes")
