"""The strict reader of tools/scitt_ccf_external/pr31_strict_reader on all 66 receipts next to it.

Pull request 31 to the CCF receipt profile requires a Verifier to reject a proof that is not valid CBOR, in particular
one whose map has a duplicate key (commits eb01db3f and 820c5e4e), and a receipt whose vdp map is not valid CBOR or
does not match verifiable-proofs (commit f6d4eb04). The data-hash preimage carries an empty unprotected header map,
which this reader writes as the one byte a0.

Every receipt in ``probes/index.json`` and ``vectors/vectors.json`` is read: the verdict of each probe and the whole
line of each vector are held against the file, and the reasons of the probes that matter for pull request 31 by
name. The twins are the controls. Three counter-probes run an earlier reading on the same bytes and show that these
cases would be green against it: without the check of the whole vdp map; with labels looked up as Python values, so
that 1.0 and ``true`` are read as 1; and, where cbor2 is installed, with cbor2 decoding, where the last value of a
duplicate key wins.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from collections.abc import Mapping
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
HERE = REPO / "tools" / "scitt_ccf_external" / "pr31_strict_reader"
PROBES = json.loads((HERE / "probes" / "index.json").read_text(encoding="utf-8"))
VECTORS = json.loads((HERE / "vectors" / "vectors.json").read_text(encoding="utf-8"))


def _module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


READER = _module("_pr31_strict_reader", HERE / "reader.py")
GEN = _module("_pr31_make_vectors", HERE / "make_vectors.py")


def _probe(name: str, reader=READER) -> str:
    entry = PROBES["probes"][name]
    return reader.verdict((HERE / "probes" / entry["file"]).read_bytes(), (HERE / "probes" / "keys.cbor").read_bytes(),
                          digest=bytes.fromhex(PROBES["data_hash_hex"]))


def _vector(name: str, reader=READER) -> str:
    entry = VECTORS[name]
    receipt = (HERE / "vectors" / f"{name}.cose").read_bytes()
    keys = (HERE / "vectors" / entry.get("keys", "keys.cbor")).read_bytes()
    if entry.get("statement"):
        return reader.verdict(receipt, keys, statement_raw=(HERE / "vectors" / entry["statement"]).read_bytes())
    return reader.verdict(receipt, keys, digest=bytes.fromhex(entry["data_hash_hex"]))


def test_the_files_carry_24_probes_and_42_vectors():
    assert len(PROBES["probes"]) == 24
    assert len(VECTORS) == 42


@pytest.mark.parametrize("name", sorted(PROBES["probes"]))
def test_every_probe_gets_its_strict_verdict(name):
    assert _probe(name).split()[0] == PROBES["probes"][name]["expected_strict"]


@pytest.mark.parametrize("name", sorted(VECTORS))
def test_every_vector_gets_its_whole_strict_line(name):
    assert _vector(name) == VECTORS[name]["strict_line"]
    assert VECTORS[name]["strict_line"].split()[0] == VECTORS[name]["strict"]


def _signs_deterministically() -> bool:
    from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415

    try:
        ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
    except TypeError:
        return False
    return True


def test_the_vectors_in_the_tree_are_those_the_generator_writes(tmp_path):
    """make_vectors.py is deterministic (RFC 6979), so the files can be checked, not trusted. Deterministic ECDSA came
    with cryptography 43.0.0; under the declared floor 42 no run can write the vectors, and the test says so."""
    if not _signs_deterministically():
        pytest.skip("NOT MEASURED: this cryptography has no deterministic ECDSA (added in 43.0.0)")
    GEN.main(["make_vectors.py", str(tmp_path)])
    written = sorted(p.name for p in tmp_path.iterdir())
    assert written == sorted(p.name for p in (HERE / "vectors").iterdir())
    for name in written:
        assert (tmp_path / name).read_bytes() == (HERE / "vectors" / name).read_bytes(), name


@pytest.mark.parametrize("name, reason", [
    ("duplicate_key_2", "FAIL cbor_proof: duplicate map key 2"),
    ("plus_empty_consistency_array", "FAIL vdp_empty"),
    ("bytes_after_the_proof", "FAIL cbor_proof: 1 byte(s) after the data item"),
    ("evidence_invalid_utf8", "FAIL cbor_proof: text string is not valid UTF-8"),
    ("two_proofs_different_roots", "FAIL roots"),
])
def test_the_probes_of_pull_request_31_are_refused_for_their_reason(name, reason):
    assert _probe(name) == reason


@pytest.mark.parametrize("name, reason", [
    ("dup_leaf_first", "FAIL cbor_proof: duplicate map key 1"),
    ("dup_leaf_last", "FAIL cbor_proof: duplicate map key 1"),
    ("dup_path_first", "FAIL cbor_proof: duplicate map key 2"),
    ("dup_path_last", "FAIL cbor_proof: duplicate map key 2"),
    ("vdp_duplicate_key", "FAIL cbor_receipt: duplicate map key -1"),
    ("vdp_empty_consistency", "FAIL vdp_empty"),
    ("vdp_unknown_key", "FAIL vdp_key"),
    ("empty_map_b8_00", "FAIL digest_mismatch"),
    ("empty_map_bf_ff", "FAIL digest_mismatch"),
])
def test_the_vectors_are_refused_for_their_reason(name, reason):
    assert _vector(name) == reason


@pytest.mark.parametrize("name", ["dup_twin", "vdp_twin", "empty_map_a0"])
def test_control_the_twins_and_the_a0_preimage_pass(name):
    assert _vector(name).startswith("PASS ")


def test_counter_probe_without_the_vdp_check_the_vdp_cases_pass(monkeypatch):
    """The earlier reading checked only the inclusion-proof array; it passed these receipts (measured 2026-10-15)."""
    monkeypatch.setattr(READER, "_check_vdp", lambda unprotected: unprotected.get(READER.VDP))
    assert _probe("plus_empty_consistency_array").startswith("PASS ")
    assert _vector("vdp_empty_consistency").startswith("PASS ")
    assert _vector("vdp_unknown_key").startswith("PASS ")


LABEL_CASES = ["label_leaf_float_1_0", "label_leaf_true", "label_path_float_2_0", "label_vdp_float_minus_1_0",
               "label_unprotected_float_396_0", "label_protected_alg_true"]


def test_counter_probe_with_labels_read_as_python_values_the_label_cases_pass(monkeypatch):
    """1.0 == 1 and True == 1 in Python, with the same hash: a reader that looks labels up as Python values reads these
    receipts as valid (the reader of 2026-10-15 did). The signature over the root stays valid, because only the
    unprotected part changed for the first five."""
    monkeypatch.setattr(READER, "_labels", lambda m: True)
    monkeypatch.setattr(READER, "_int", lambda v: isinstance(v, (int, float)))
    for name in LABEL_CASES:
        assert _vector(name) == VECTORS["vdp_twin"]["strict_line"], name


@pytest.mark.parametrize("major, n, head", [
    (0, 0, "00"), (0, 23, "17"), (0, 24, "1818"), (0, 255, "18ff"), (0, 256, "190100"), (0, 65535, "19ffff"),
    (0, 65536, "1a00010000"), (0, 2**32 - 1, "1affffffff"), (0, 2**32, "1b0000000100000000"),
    (0, 2**64 - 1, "1bffffffffffffffff"), (2, 24, "5818"), (3, 10, "6a"), (4, 4, "84"),
])
def test_the_signed_structure_writes_every_head_width(major, n, head):
    """RFC 8949 Section 3: an argument below 24 sits in the initial byte, larger ones follow in one, two, four or eight
    bytes. The table is written from the RFC, not from a run; a protected header of 24 or of 65 536 bytes needs them."""
    assert READER._head(major, n) == bytes.fromhex(head)


def test_an_argument_beyond_64_bits_has_no_head():
    with pytest.raises(ValueError):
        READER._head(0, 2**64)


def _statement(tag: bytes, array_head: bytes, unprotected: bytes) -> tuple:
    prot = GEN.bs(GEN.cmap([(GEN.uint(1), GEN.uint(-7))]))
    payload, signature = GEN.bs(b"payload"), GEN.bs(b"\x00" * 64)
    raw = tag + array_head + prot + unprotected + payload + signature + (b"\xff" if array_head == b"\x9f" else b"")
    expected = tag + array_head + prot + b"\xa0" + payload + signature + (b"\xff" if array_head == b"\x9f" else b"")
    return raw, hashlib.sha256(expected).digest()


@pytest.mark.parametrize("tag", [b"\xd2", b"\xd8\x12", b"\xd9\x00\x12", b"\xda\x00\x00\x00\x12",
                                 b"\xdb" + (18).to_bytes(8, "big")])
@pytest.mark.parametrize("array_head", [b"\x84", b"\x98\x04", b"\x99\x00\x04", b"\x9a\x00\x00\x00\x04", b"\x9f"])
@pytest.mark.parametrize("unprotected", [b"\xa0", b"\xbf\xff", b"\xa1\x18\x63\x61\x78", b"\xb8\x01\x01\x81\x02"])
def test_the_statement_digest_replaces_only_the_unprotected_header_in_every_head_width(tag, array_head, unprotected):
    """The oracle writes the expected preimage from the same parts: tag, array head, protected header, a0, payload,
    signature. Every width of the tag head and the array head is covered, so a reader that knows only d2 84 fails."""
    raw, expected = _statement(tag, array_head, unprotected)
    assert READER.statement_digest(raw) == expected


@pytest.mark.parametrize("raw, reason", [
    (b"\x84" + GEN.bs(b"\xa0") + b"\xa0" + GEN.bs(b"p") + GEN.bs(b"s"), "statement_tag"),
    (b"\xd1\x84" + GEN.bs(b"\xa0") + b"\xa0" + GEN.bs(b"p") + GEN.bs(b"s"), "statement_tag"),
    (b"\xd2\x83" + GEN.bs(b"\xa0") + b"\xa0" + GEN.bs(b"p"), "statement_struct"),
    (b"\xd2\x84" + GEN.bs(b"\xa0") + GEN.bs(b"\xa0") + GEN.bs(b"p") + GEN.bs(b"s"), "statement_struct"),
])
def test_a_statement_of_another_form_is_refused(raw, reason):
    with pytest.raises(READER.Fail) as exc:
        READER.statement_digest(raw)
    assert str(exc.value) == reason


@pytest.mark.parametrize("keys, line", [
    (b"\xa0", "FAIL keys"),
    (b"\x81\xa1\x01\x02", "FAIL keys"),
    (b"\x81\xa2\x01\xf9\x40\x00\x20\x02", "FAIL keys"),
    (b"-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n", "FAIL keys"),
])
def test_a_key_set_of_another_form_is_a_fail_line_not_an_exception(keys, line):
    receipt = (HERE / "vectors" / "vdp_twin.cose").read_bytes()
    assert READER.verdict(receipt, keys, digest=bytes.fromhex(VECTORS["vdp_twin"]["data_hash_hex"])) == line


def _keyset(kty: bytes = b"\x02", crv: bytes = b"\x02", kty_label: bytes = b"\x01", crv_label: bytes = b"\x20",
            x: bytes | None = None, y: bytes | None = None, kid: bool = True, x_item: bytes | None = None,
            y_item: bytes | None = None) -> bytes:
    """The test key set of make_vectors.py with one label, value or coordinate written as another data item."""
    pn = GEN.SK.public_key().public_numbers()
    x = pn.x.to_bytes(48, "big") if x is None else x
    y = pn.y.to_bytes(48, "big") if y is None else y
    return GEN.arr([GEN.cmap([(kty_label, kty)] + ([(GEN.uint(2), GEN.bs(GEN.KID))] if kid else [])
                             + [(crv_label, crv), (GEN.uint(-2), x_item or GEN.bs(x)),
                                (GEN.uint(-3), y_item or GEN.bs(y))])])


@pytest.mark.parametrize("keys, line", [
    (_keyset(), None),
    (_keyset(kty=b"\xf9\x40\x00"), "FAIL keys"),
    (_keyset(crv=b"\xf9\x40\x00"), "FAIL keys"),
    (_keyset(kty_label=b"\xf5"), "FAIL keys"),
    (_keyset(crv_label=b"\xf9\xbc\x00"), "FAIL keys"),
    (_keyset(y=b"\x01" * 48), "FAIL keys"),
    (_keyset(x=b"", y=b""), "FAIL keys"),
    (_keyset(x=b"\x00" * 48, y=b"\x00" * 48), "FAIL keys"),
    (_keyset(x_item=GEN.ts(b"x")), "FAIL keys"),
    (_keyset(y_item=GEN.uint(5)), "FAIL keys"),
    (_keyset(kid=False), None),
])
def test_a_key_whose_type_or_curve_is_not_an_integer_is_refused(keys, line):
    """A complete key, so the only difference is the data item: 2.0 for the key type EC2 or the curve P-384, true for
    the label 1, -1.0 for the label -1, a text or an integer for a coordinate. The first row is the control and
    verifies; a key without kid verifies too, because the receipt's kid selects among keys only where keys carry one."""
    receipt = (HERE / "vectors" / "vdp_twin.cose").read_bytes()
    got = READER.verdict(receipt, keys, digest=bytes.fromhex(VECTORS["vdp_twin"]["data_hash_hex"]))
    assert got == (line or VECTORS["vdp_twin"]["strict_line"])


@pytest.mark.parametrize("zeros, line", [(0, None), (1, "FAIL signature"), (2, "FAIL signature")])
def test_a_signature_longer_than_the_curve_is_refused_where_r_and_s_still_read_right(zeros, line):
    """RFC 9053 Section 2.1 fixes the length of r and of s. Zero bytes between r and s leave both numbers intact when
    the signature is cut at the length of the curve, so only the length check refuses these receipts; signature_padded,
    with a zero byte in front of each, would fail on its numbers as well. No key is needed: the bytes of vdp_twin are
    rewritten, and zeros=0 is the control that rewrites them unchanged."""
    raw = (HERE / "vectors" / "vdp_twin.cose").read_bytes()
    assert raw[-98:-96] == b"\x58\x60"
    sig = raw[-96:]
    longer = raw[:-98] + GEN.bs(sig[:48] + b"\x00" * zeros + sig[48:])
    got = READER.verdict(longer, (HERE / "vectors" / "keys.cbor").read_bytes(),
                         digest=bytes.fromhex(VECTORS["vdp_twin"]["data_hash_hex"]))
    assert got == (line or VECTORS["vdp_twin"]["strict_line"])


def test_the_command_line_runs_as_a_script_as_the_readme_shows(tmp_path):
    """The README runs reader.py as a script from the repository root, which puts src on the path itself."""
    import subprocess  # noqa: PLC0415
    import sys  # noqa: PLC0415

    receipt, keys = HERE / "vectors" / "vdp_twin.cose", HERE / "vectors" / "keys.cbor"
    r = subprocess.run([sys.executable, str(HERE / "reader.py"), str(receipt), str(keys), "--digest",
                        VECTORS["vdp_twin"]["data_hash_hex"]], capture_output=True, text=True, cwd=tmp_path,
                       env={"PATH": "/usr/bin:/bin"}, timeout=120)
    assert (r.returncode, r.stdout.strip()) == (0, VECTORS["vdp_twin"]["strict_line"]), r.stderr[-400:]
    stmt = HERE / "vectors" / "statement.cose"
    r = subprocess.run([sys.executable, str(HERE / "reader.py"), str(HERE / "vectors" / "empty_map_a0.cose"), str(keys),
                        "--statement", str(stmt)], capture_output=True, text=True, cwd=tmp_path,
                       env={"PATH": "/usr/bin:/bin"}, timeout=120)
    assert (r.returncode, r.stdout.strip()) == (0, VECTORS["empty_map_a0"]["strict_line"]), r.stderr[-400:]


def test_a_reason_that_quotes_a_text_key_reaches_an_ascii_stream(tmp_path):
    """A duplicate text key appears in the reason; an output stream that cannot encode it still gets one line."""
    import subprocess  # noqa: PLC0415
    import sys  # noqa: PLC0415

    dup = GEN.proof([(GEN.ts("\u00e9".encode()), GEN.uint(1)), (GEN.ts("\u00e9".encode()), GEN.uint(2))])
    unprotected = GEN.cmap([(GEN.uint(396), GEN.cmap([GEN.inclusion(dup)]))])
    rec = tmp_path / "dup_text_key.cose"
    # No signature is needed: the duplicate key is refused before any signature is checked.
    rec.write_bytes(b"\xd2" + GEN.arr([GEN.bs(GEN.protected()), unprotected, b"\xf6", GEN.bs(b"\x00" * 96)]))
    r = subprocess.run([sys.executable, str(HERE / "reader.py"), str(rec), str(HERE / "vectors" / "keys.cbor"),
                        "--digest", VECTORS["vdp_twin"]["data_hash_hex"]], capture_output=True, cwd=tmp_path,
                       env={"PATH": "/usr/bin:/bin", "PYTHONIOENCODING": "ascii"}, timeout=120)
    assert r.returncode == 0, r.stderr[-400:]
    assert r.stdout.decode("utf-8").strip() == "FAIL cbor_proof: duplicate map key '\u00e9'"


def test_the_command_line_prints_the_line_and_exits_2_when_a_file_cannot_be_read(tmp_path, capsys):
    receipt, keys = HERE / "vectors" / "vdp_twin.cose", HERE / "vectors" / "keys.cbor"
    digest = VECTORS["vdp_twin"]["data_hash_hex"]
    assert READER.main([str(receipt), str(keys), "--digest", digest]) == 0
    assert capsys.readouterr().out.strip() == VECTORS["vdp_twin"]["strict_line"]
    assert READER.main([str(tmp_path / "missing.cose"), str(keys), "--digest", digest]) == 2


def test_counter_probe_with_cbor2_the_last_value_of_a_duplicate_key_wins(monkeypatch):
    """With cbor2 in place of the strict helper, a duplicate key no longer stops the reader: the receipt signed for
    the last value passes, the one signed for the first fails on its signature. That is the earlier reading."""
    cbor2 = pytest.importorskip("cbor2")

    def lift(v):
        # cbor2 6 returns an array under a tag as a tuple and a map there as a frozendict (measured with 6.1.4);
        # both are read back as the strict helper's list and dict.
        if isinstance(v, cbor2.CBORTag):
            return READER.Tag(v.tag, lift(v.value))
        if isinstance(v, (list, tuple)):
            return [lift(x) for x in v]
        if isinstance(v, Mapping):
            return {k: lift(x) for k, x in v.items()}
        return v

    monkeypatch.setattr(READER, "strict", lambda b, what: lift(cbor2.loads(b)))
    assert _probe("duplicate_key_2").startswith("PASS ")
    assert _vector("dup_leaf_last").startswith("PASS ")
    assert _vector("dup_path_last").startswith("PASS ")
    assert _vector("dup_leaf_first") == "FAIL signature"
    assert _vector("dup_path_first") == "FAIL signature"
