"""The reader of Certisyn's sealed containment records (``certisyn/containment-public/v1``), against the pilot pack.

The pack is copied unchanged from Certisyn-Inc/certisyn-drafts pull request 12 (commit 8c01cd7a, directory
interop/containment-pilot, Apache-2.0, see the NOTICE beside it) into examples/certisyn_containment_pilot/pack/. Its
FORMAT.md is the specification. The scope of the reader is integrity, and nothing in this file claims more.

What is measured here:
  * every line of MANIFEST.sha256 holds, and pack/ holds nothing else;
  * the trust configuration is the key pinned on 2026-10-27, and only that key decides a signature;
  * the thirteen vectors, submitted as the pack's run-all.mjs submits them, give the outcome expected.json names, and
    each refusal fails at exactly the step that its description in expected.json names, and at no other; N11 is the
    record and the seal for sandbox-1 to sandbox-2 with the input of the other record, refused at input_digest alone;
  * the key printed in a seal is never used, and a small-order trusted key is refused before any signature arithmetic;
  * the canonical bytes the pack publishes are the bytes this reader digests;
  * a refusal names every failed step it reaches, the reader never raises on what a sender controls, and every result
    says that its scope is integrity;
  * the reproducible example prints exactly expected_output.txt and exits 0.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "examples" / "certisyn_containment_pilot"
PACK = EXAMPLE / "pack"

#: The pilot key as it was pinned on 2026-10-27, after the same key was read on three channels. It stands here, apart
#: from KEY.json, so that a changed KEY.json cannot move the key this test trusts.
PINNED_KEY_B64 = "eW00ut110zNXQqgrLjoiFnAezY/OlQM9frgUFeAjzzc="
PINNED_KEY_SHA256 = "6d6ead37c11a2f09a6ec4d17b38d8ea0e9227234a27f6316e7c8e2bcbe0758b6"
PINNED_KEY = base64.b64decode(PINNED_KEY_B64)

#: The files proofbundle added beside pack/.
ADDED = {"LICENSE.author", "NOTICE", "PROVENANCE.json", "README.md", "expected_output.txt", "verify_all.py"}

#: The SHA-256 of the Apache License 2.0 text as the Apache Software Foundation publishes it (LICENSE-2.0.txt), the same
#: bytes as conformance/cap1/vectors/LICENSE.author.
APACHE_2_0_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"

#: The step each refusal fails at, read from the vectors before the reader existed, by comparing each record and seal
#: with P01's. A refusal vector gets an input file only where expected.json names one, as in the pack's run-all.mjs.
EXPECTED_FAILED_STEPS = {
    "N01": {"result_digest"},   # the verdict changed in the record, the seal untouched
    "N02": {"result_digest"},   # detection_floor_bits_per_second changed in the record
    "N03": {"result_digest"},   # input_digest swapped for the one of another record
    "N04": {"signature"},       # P01's record and message, signed by another key that the seal itself names
    "N05": {"signature"},       # one bit of P01's signature flipped
    "N06": {"seal_domain"},     # only the seal's domain replaced; its message and signature are P01's
    "N07": {"signed_message"},  # P01's record with the seal of P02, which is valid for P02
    "N08": {"parse"},           # verdict repeated with the same value
    "N09": {"parse"},           # verdict repeated through an escaped spelling
    "N10": {"parse"},           # schema repeated with a different value
    "N11": {"input_digest"},    # P01's record and seal with P02's input file
}


@pytest.fixture(scope="module")
def reader():
    from proofbundle import containment
    return containment


def _read(name: str) -> bytes:
    return (PACK / name).read_bytes()


def _verify(reader, record_id: str, seal_id: str | None = None, input_id: str | None = None, *,
            key: object = PINNED_KEY, seal: bytes | None = None) -> dict:
    return reader.verify_containment_record(
        _read(f"vectors/{record_id}.record.json"),
        seal if seal is not None else _read(f"vectors/{seal_id or record_id}.seal.json"),
        trusted_key=key,
        input_series=_read(f"inputs/{input_id}.input.json") if input_id else None)


def _failed(result: dict) -> set:
    return {f["step"] for f in result["failures"]}


def _expected() -> dict:
    return json.loads(_read("expected.json"))


# ── the pack ────────────────────────────────────────────────────────────────────────────────────────────────────────

def test_every_line_of_the_manifest_holds_and_the_pack_holds_nothing_else():
    lines = _read("MANIFEST.sha256").decode("ascii").splitlines()
    listed = {}
    for line in lines:
        digest, _, path = line.partition("  ")
        assert len(digest) == 64 and path.startswith("./"), line
        listed[path[2:]] = digest
    assert len(listed) == len(lines) == 36
    for path, digest in listed.items():
        assert hashlib.sha256(_read(path)).hexdigest() == digest, path
    # The manifest does not list itself; it is the 37th file of the copied pack.
    present = {p.relative_to(PACK).as_posix() for p in PACK.rglob("*") if p.is_file()}
    assert present == set(listed) | {"MANIFEST.sha256"}
    beside = {p.name for p in EXAMPLE.iterdir() if p.is_file()}
    assert beside == ADDED


def test_the_provenance_names_the_pull_request_the_commit_the_path_and_the_license():
    provenance = json.loads((EXAMPLE / "PROVENANCE.json").read_bytes())
    assert provenance["repository"] == "https://github.com/Certisyn-Inc/certisyn-drafts"
    assert provenance["pull_request"] == 12
    assert provenance["commit"] == "8c01cd7a543d9e7359238958355d491f7923cf58"
    assert (provenance["path"], provenance["copied_to"]) == ("interop/containment-pilot", "pack")
    assert provenance["license"] == "Apache-2.0"
    assert (provenance["copied_files"], provenance["listed_in_manifest"]) == (37, 36)
    assert hashlib.sha256((EXAMPLE / "LICENSE.author").read_bytes()).hexdigest() == APACHE_2_0_SHA256
    assert "Apache-2.0 for the verifier and vectors" in _read("README.md").decode("utf-8")
    notice = (EXAMPLE / "NOTICE").read_text(encoding="utf-8")
    assert "8c01cd7a543d9e7359238958355d491f7923cf58" in notice and "Apache License, Version 2.0" in notice


# ── the trust configuration ────────────────────────────────────────────────────────────────────────────────────────

def test_the_trust_configuration_is_the_pinned_key(reader):
    key = reader.load_trusted_key(_read("KEY.json"))
    assert key == PINNED_KEY
    assert hashlib.sha256(key).hexdigest() == PINNED_KEY_SHA256


@pytest.mark.parametrize("change", [
    {"algorithm": "ecdsa-p256"},
    {"ed25519_pub_hex": "00" * 32},
    {"pub_sha256": "00" * 32},
    {"ed25519_pub_b64": base64.b64encode(b"\x01" + b"\x00" * 31).decode("ascii"), "ed25519_pub_hex": None,
     "pub_sha256": None},
    {"ed25519_pub_b64": "not base64!"},
])
def test_a_trust_configuration_that_disagrees_with_itself_or_holds_a_weak_key_is_refused(reader, change):
    config = json.loads(_read("KEY.json"))
    for name, value in change.items():
        if value is None:
            config.pop(name)
        else:
            config[name] = value
    with pytest.raises(ValueError):
        reader.load_trusted_key(json.dumps(config))


def test_a_trust_configuration_with_a_repeated_name_is_refused(reader):
    text = _read("KEY.json").decode("utf-8").replace('"algorithm": "ed25519",',
                                                     '"algorithm": "ed25519", "algorithm": "ed25519",')
    with pytest.raises(ValueError):
        reader.load_trusted_key(text)


# ── the thirteen vectors ───────────────────────────────────────────────────────────────────────────────────────────

def test_the_refusal_table_covers_exactly_the_refusals_of_expected_json():
    assert set(EXPECTED_FAILED_STEPS) == {n["id"] for n in _expected()["refuse"]}
    assert len(_expected()["accept"]) + len(EXPECTED_FAILED_STEPS) == 13


@pytest.mark.parametrize("vector", ["P01", "P02"])
def test_an_accept_vector_is_accepted_with_its_input(reader, vector):
    assert vector in _expected()["accept"]
    result = _verify(reader, vector, input_id=vector)
    assert result["outcome"] == "ACCEPT", result["failures"]
    assert result["failures"] == []
    assert set(result["steps"].values()) == {"pass"}


@pytest.mark.parametrize("vector", sorted(EXPECTED_FAILED_STEPS))
def test_a_refusal_vector_fails_at_its_own_step_and_at_no_other(reader, vector):
    # Submitted as run-all.mjs submits it: the record of the `record` field, the input of the `input` field.
    entry = next(n for n in _expected()["refuse"] if n["id"] == vector)
    input_id = entry.get("input", vector)
    result = _verify(reader, entry.get("record", vector),
                     input_id=input_id if (PACK / "inputs" / f"{input_id}.input.json").is_file() else None)
    assert result["outcome"] == "REFUSE"
    assert _failed(result) == EXPECTED_FAILED_STEPS[vector], result["failures"]


def test_n11_is_the_record_for_sandbox_1_to_sandbox_2_with_the_input_of_the_other_record(reader):
    entry = next(n for n in _expected()["refuse"] if n["id"] == "N11")
    assert (entry["record"], entry["input"]) == ("P01", "P02")
    record = json.loads(_read("vectors/P01.record.json"))
    assert record["subject_ref"].startswith("synthetic-pilot host-A: sandbox-1 to sandbox-2")
    # The control: the same record and seal with their own input are accepted, so input_digest alone decides N11.
    assert _verify(reader, "P01", input_id="P01")["outcome"] == "ACCEPT"


def test_the_example_prints_its_expected_output_and_exits_0():
    env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
    run = subprocess.run([sys.executable, str(EXAMPLE / "verify_all.py")], capture_output=True, env=env, timeout=120)
    assert run.returncode == 0, run.stderr.decode("utf-8", "replace")
    assert run.stdout == (EXAMPLE / "expected_output.txt").read_bytes()


def test_without_an_input_the_record_is_accepted_and_the_result_says_the_input_was_not_supplied(reader):
    result = _verify(reader, "P01")
    assert result["outcome"] == "ACCEPT"
    assert result["steps"]["input_digest"] == "not_supplied"


def test_an_input_with_a_repeated_name_is_refused_at_input_digest(reader):
    text = _read("inputs/P01.input.json").replace(b'{"x":', b'{"x":[],"x":', 1)
    result = reader.verify_containment_record(_read("vectors/P01.record.json"), _read("vectors/P01.seal.json"),
                                              trusted_key=PINNED_KEY, input_series=text)
    assert _failed(result) == {"input_digest"}


def test_a_record_of_another_schema_is_refused_at_schema(reader):
    # No vector changes the schema alone, so without this case a reader that skipped step 2 would pass every vector.
    record = json.loads(_read("vectors/P01.record.json"))
    record["schema"] = "certisyn/containment-public/v2"
    result = reader.verify_containment_record(json.dumps(record), _read("vectors/P01.seal.json"),
                                              trusted_key=PINNED_KEY)
    assert _failed(result) == {"schema", "result_digest"}


def test_a_seal_whose_message_digest_does_not_recompute_is_refused_at_signed_message(reader):
    # No vector touches signed_message_sha256 alone; this case is the one that sees the second check of step 6.
    result = _verify(reader, "P01", seal=_seal_with("P01", signed_message_sha256="00" * 32))
    assert _failed(result) == {"signed_message"}


def test_a_seal_of_another_algorithm_is_refused_at_seal_domain(reader):
    # N06 replaces the domain; this case replaces the algorithm, the other half of step 5.
    result = _verify(reader, "P01", seal=_seal_with("P01", algorithm="ed448"))
    assert _failed(result) == {"seal_domain"}


def test_a_seal_with_a_repeated_name_is_refused_at_parse(reader):
    seal = _read("vectors/P01.seal.json").replace(b'"algorithm": "ed25519",',
                                                  b'"algorithm": "ed25519", "algorithm": "ed25519",')
    result = _verify(reader, "P01", seal=seal)
    assert _failed(result) == {"parse"}


# ── the key ─────────────────────────────────────────────────────────────────────────────────────────────────────────

def _seal_with(seal_id: str, **fields) -> bytes:
    seal = json.loads(_read(f"vectors/{seal_id}.seal.json"))
    seal.update(fields)
    return json.dumps(seal).encode("utf-8")


def test_the_key_printed_in_a_seal_is_never_used(reader):
    other = json.loads(_read("vectors/N04.seal.json"))
    # P01's seal naming the other key is still P01's seal: the printed key is informational.
    result = _verify(reader, "P01", seal=_seal_with("P01", ed25519_pub_b64=other["ed25519_pub_b64"],
                                                     key_id=other["key_id"]))
    assert result["outcome"] == "ACCEPT"
    # A seal without a printed key at all is read the same way.
    seal = json.loads(_read("vectors/P01.seal.json"))
    del seal["ed25519_pub_b64"], seal["key_id"]
    assert _verify(reader, "P01", seal=json.dumps(seal).encode("utf-8"))["outcome"] == "ACCEPT"
    # N04 names its own signer, and that does not help it.
    assert _failed(_verify(reader, "N04")) == {"signature"}


def test_the_trusted_key_decides_and_reports_which_key_it_was(reader):
    other = base64.b64decode(json.loads(_read("vectors/N04.seal.json"))["ed25519_pub_b64"])
    assert _failed(_verify(reader, "P01", key=other)) == {"signature"}
    assert _verify(reader, "N04", key=other)["outcome"] == "ACCEPT"
    assert _verify(reader, "P01")["trusted_key_sha256"] == PINNED_KEY_SHA256


def test_a_small_order_trusted_key_is_refused_before_any_signature_arithmetic(reader):
    from proofbundle.signature import verify_ed25519
    identity = b"\x01" + b"\x00" * 31
    forged = identity + b"\x00" * 32   # R = identity, S = 0: verifies for every message under the identity point
    seal = json.loads(_read("vectors/P01.seal.json"))
    # The precondition: under the bare profile the forgery is live, so the refusal below is the reader's doing.
    assert verify_ed25519(identity, forged, seal["signed_message"].encode("utf-8"))
    result = _verify(reader, "P01", key=identity,
                     seal=_seal_with("P01", signature_b64=base64.b64encode(forged).decode("ascii")))
    assert result["outcome"] == "REFUSE"
    assert _failed(result) == {"signature"}


# ── the canonical form ─────────────────────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("vector", ["P01", "P02"])
def test_the_canonical_bytes_of_the_pack_are_the_bytes_the_reader_digests(reader, vector):
    from proofbundle._strict_json import loads_strict
    from proofbundle.canonical import canonicalize_statement
    record = loads_strict(_read(f"vectors/{vector}.record.json"))
    body = {name: value for name, value in record.items() if name != "result_digest"}
    published = _read(f"canonical/{vector}.record-body.canonical.json")
    assert canonicalize_statement(body) == published
    assert hashlib.sha256(published).hexdigest() == record["result_digest"]
    published_input = _read(f"canonical/{vector}.input.canonical.json")
    assert canonicalize_statement(loads_strict(_read(f"inputs/{vector}.input.json"))) == published_input
    assert hashlib.sha256(published_input).hexdigest() == record["input_digest"]


# ── what every result says ─────────────────────────────────────────────────────────────────────────────────────────

def test_a_refusal_names_every_failed_step_it_reaches(reader):
    record = _read("vectors/N01.record.json")
    seal = _seal_with("P01", domain="certisyn/twin-determination-seal/v1",
                      signature_b64=json.loads(_read("vectors/N05.seal.json"))["signature_b64"])
    result = reader.verify_containment_record(record, seal, trusted_key=PINNED_KEY)
    assert _failed(result) == {"result_digest", "seal_domain", "signature"}
    # An unreadable record leaves the seal's own steps running.
    result = _verify(reader, "N08", seal_id="N06")
    assert _failed(result) == {"parse", "seal_domain"}
    assert result["steps"]["schema"] == "not_reached"


@pytest.mark.parametrize("record,seal,key", [
    (None, None, None),
    (1, b"{}", PINNED_KEY),
    (b"", b"", PINNED_KEY),
    (b"\xff\xfe", b"[]", PINNED_KEY),
    ("[]", "{}", PINNED_KEY),
    ('{"schema": 1, "result_digest": []}', '{"signed_message": 7, "signature_b64": {}}', PINNED_KEY),
    (b'{"a": NaN}', b'{"a": 1e400}', PINNED_KEY),
    ("{" * 5000, "[" * 5000, PINNED_KEY),
    (None, None, "not a key"),
    (None, None, b"\x00" * 31),
])
def test_the_reader_never_raises_on_what_a_sender_controls(reader, record, seal, key):
    result = reader.verify_containment_record(record, seal, trusted_key=key)
    assert result["outcome"] == "REFUSE"
    assert result["failures"]


def test_a_malformed_trusted_key_refuses_a_good_pair(reader):
    for key in (None, "eW00ut110zNXQqgrLjoiFnAezY/OlQM9frgUFeAjzzc=", PINNED_KEY[:31], 7):
        result = _verify(reader, "P01", input_id="P01", key=key)
        assert result["outcome"] == "REFUSE"
        assert _failed(result) == {"signature"}


def test_every_result_says_its_scope_is_integrity(reader):
    assert reader.SCOPE == "integrity"
    assert "integrity" in reader.SCOPE_NOTE.lower()
    assert reader.__doc__ and "INTEGRITY ONLY" in reader.__doc__
    for result in (_verify(reader, "P01", input_id="P01"), _verify(reader, "N01"),
                   reader.verify_containment_record(None, None, trusted_key=None)):
        assert result["scope"] == "integrity"
        assert result["scope_note"] == reader.SCOPE_NOTE
        assert result["format"] == "certisyn/containment-public/v1"


def test_the_steps_are_the_seven_of_format_md_section_6_in_their_order(reader):
    assert reader.STEPS == ("parse", "schema", "result_digest", "input_digest", "seal_domain", "signed_message",
                            "signature")
    assert list(_verify(reader, "P01")["steps"]) == list(reader.STEPS)


@pytest.mark.parametrize("kind", ["iterator", "released_memoryview"])
def test_a_trust_configuration_refused_before_the_body_still_raises_value_error(reader, kind):
    if kind == "iterator":
        value = iter([b"{}"])
    else:
        value = memoryview(b"{}")
        value.release()
    with pytest.raises(ValueError):
        reader.load_trusted_key(value)
