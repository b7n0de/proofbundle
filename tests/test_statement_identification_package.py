"""The statement identification package's checker, held to what its README says it checks.

docs/scitt/statement_identification/package/verify.py is run as a user runs it, on a copy of the
package, once per case, with one change per case. The cases start from the sixteen of the external
review of 27 September 2026 (PR 298, commit fb1c1786) and add the ones the owner's order of the same
day names: every reference carried in a signed protected header is listed in references.json and every
listed one is carried; every manifest field is compared with the files or named as a description, and
an unknown field fails (Codex thread 4217204734); malformed input ends on the
documented FAILED line with exit 1, never in an uncaught exception; and the envelope experiment is two
separately labelled cases, tag 18 kept with an unprotected parameter added, and the tag removed.

Where a case changes the bytes of a statement without changing what is signed, it updates only the
unsigned manifest's whole-object digest and size, as the review did: no signature is forged.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("cbor2") is None or importlib.util.find_spec("cryptography") is None,
    reason="the package checker needs cbor2 and cryptography")

REPO = Path(__file__).resolve().parents[1]
PACKAGE = REPO / "docs" / "scitt" / "statement_identification" / "package"
ORIGINAL, AUDIT, CORRECTION = "01-original.cose.hex", "02-audit.cose.hex", "03-correction.cose.hex"


# ------------------------------------------------------------------------------------------------
# A copy of the package, one change, one run
# ------------------------------------------------------------------------------------------------
@pytest.fixture
def pkg(tmp_path) -> Path:
    dst = tmp_path / "package"
    shutil.copytree(PACKAGE, dst)
    return dst


def run(pkg: Path, *flags) -> "tuple[int, list, str]":
    p = subprocess.run([sys.executable, *flags, str(pkg / "verify.py"), str(pkg)], capture_output=True,
                       text=True, timeout=120)
    return p.returncode, p.stdout.strip().splitlines(), p.stderr


def read(pkg: Path, name: str) -> bytes:
    return bytes.fromhex("".join((pkg / name).read_text(encoding="ascii").split()))


def write(pkg: Path, name: str, data: bytes, *, manifest: bool = True) -> None:
    text = data.hex()
    (pkg / name).write_text("\n".join(text[i:i + 64] for i in range(0, len(text), 64)) + "\n", encoding="ascii")
    if manifest:      # the unsigned manifest describes the new whole object; nothing signed changes
        edit_manifest(pkg, lambda d: d["statements"][name].update(
            sha256_cose_sign1=hashlib.sha256(data).hexdigest(), size_bytes=len(data)))


def edit_manifest(pkg: Path, change) -> None:
    path = pkg / "references.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    change(doc)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def unprotected_offset(raw: bytes) -> int:
    """Where the unprotected map starts: after tag 18 (d2), the array head (84) and the protected bstr."""
    head = raw[2]
    if 0x40 <= head < 0x58:
        return 3 + head - 0x40
    width = {0x58: 1, 0x59: 2}[head]
    return 3 + width + int.from_bytes(raw[3:3 + width], "big")


def parts(data: bytes) -> list:
    import cbor2
    return list(cbor2.loads(data).value)


def tagged(body: list) -> bytes:
    import cbor2
    return cbor2.dumps(cbor2.CBORTag(18, body))


def assert_failed_cleanly(rc: int, out: list, err: str) -> None:
    """The documented failure: exit 1, the summary line FAILED, no uncaught exception."""
    assert rc == 1, out + [err]
    assert out and out[-1].startswith("FAILED: "), out
    assert "Traceback" not in err, err


def fails_naming(out: list, *words) -> bool:
    return any(line.startswith("FAIL ") and all(w.lower() in line.lower() for w in words) for line in out)


# ------------------------------------------------------------------------------------------------
# Guards: green before and after. Review cases 1 to 7.
# ------------------------------------------------------------------------------------------------
class TestWhatTheCheckerAlreadyRefused:
    def test_the_package_as_committed_is_all_ok(self, pkg):
        rc, out, err = run(pkg)
        assert rc == 0 and out[-1] == "ALL OK: 0 check(s) failed", out + [err]
        assert not [line for line in out if line.startswith("FAIL")]

    def test_python_minus_o_gives_the_same_lines(self, pkg):
        assert run(pkg, "-O")[:2] == run(pkg)[:2]

    def test_a_signature_bit_flip_fails(self, pkg):
        body = parts(read(pkg, ORIGINAL))
        body[3] = bytes([body[3][0] ^ 1]) + body[3][1:]
        write(pkg, ORIGINAL, tagged(body))
        rc, out, err = run(pkg)
        assert_failed_cleanly(rc, out, err)

    def test_a_payload_bit_flip_fails(self, pkg):
        body = parts(read(pkg, ORIGINAL))
        body[2] = bytes([body[2][0] ^ 1]) + body[2][1:]
        write(pkg, ORIGINAL, tagged(body))
        rc, out, err = run(pkg)
        assert_failed_cleanly(rc, out, err)

    def test_the_wrong_issuer_key_fails(self, pkg):
        shutil.copy(pkg / "auditor.pub.pem", pkg / "issuer.pub.pem")
        rc, out, err = run(pkg)
        assert_failed_cleanly(rc, out, err)

    def test_a_changed_signed_reference_digest_fails(self, pkg):
        import cbor2
        body = parts(read(pkg, AUDIT))
        header = cbor2.loads(body[0])
        header[-70001][0][2] = bytes(32)
        body[0] = cbor2.dumps(header)
        write(pkg, AUDIT, tagged(body))
        rc, out, err = run(pkg)
        assert_failed_cleanly(rc, out, err)

    def test_a_manifest_target_moved_to_03_fails(self, pkg):
        edit_manifest(pkg, lambda d: d["references"][0].update(to=CORRECTION))
        rc, out, err = run(pkg)
        assert_failed_cleanly(rc, out, err)


# ------------------------------------------------------------------------------------------------
# Gap 1, completeness: carried references and listed references are the same set. Review cases 8, 9.
# ------------------------------------------------------------------------------------------------
class TestCompleteness:
    def test_both_references_removed_from_the_manifest_fail(self, pkg):
        edit_manifest(pkg, lambda d: d.update(references=[]))
        rc, out, err = run(pkg)
        assert_failed_cleanly(rc, out, err)
        assert fails_naming(out, AUDIT, "not listed") and fails_naming(out, CORRECTION, "not listed")

    def test_the_audit_reference_removed_from_the_manifest_fails(self, pkg):
        edit_manifest(pkg, lambda d: d["references"].pop(0))
        rc, out, err = run(pkg)
        assert_failed_cleanly(rc, out, err)
        assert fails_naming(out, AUDIT, "not listed")

    def test_a_statement_file_the_manifest_does_not_list_fails(self, pkg):
        shutil.copy(pkg / AUDIT, pkg / "04-unlisted.cose.hex")
        rc, out, err = run(pkg)
        assert_failed_cleanly(rc, out, err)
        assert fails_naming(out, "04-unlisted.cose.hex")


# ------------------------------------------------------------------------------------------------
# Gap 2, the descriptive manifest fields are checked. Review cases 10, 11.
# ------------------------------------------------------------------------------------------------
class TestManifestFields:
    def test_a_digest_algorithm_the_signed_reference_does_not_name_fails(self, pkg):
        edit_manifest(pkg, lambda d: d["references"][0].update(digest_algorithm="SHA-512 (COSE algorithm -44)"))
        rc, out, err = run(pkg)
        assert_failed_cleanly(rc, out, err)
        assert fails_naming(out, "digest_algorithm")

    def test_a_size_that_is_not_the_files_fails(self, pkg):
        edit_manifest(pkg, lambda d: d["statements"][ORIGINAL].update(size_bytes=1))
        rc, out, err = run(pkg)
        assert_failed_cleanly(rc, out, err)
        assert fails_naming(out, ORIGINAL, "size_bytes")


    def test_covered_bytes_that_do_not_describe_the_signed_bytes_fail(self, pkg):
        """Codex thread 4217204734: `covered_bytes` was never read, so a manifest claiming the signature is
        covered reached ALL OK."""
        edit_manifest(pkg, lambda d: d["references"][0].update(
            covered_bytes="the bytes of the whole referenced COSE_Sign1, tag and signature included"))
        rc, out, err = run(pkg)
        assert_failed_cleanly(rc, out, err)
        assert fails_naming(out, "reference 0", "covered_bytes")

    def test_an_unknown_manifest_field_fails(self, pkg):
        for where, change in (("reference", lambda d: d["references"][1].update(signature_covered=True)),
                              ("statement", lambda d: d["statements"][AUDIT].update(note="x")),
                              ("top", lambda d: d.update(version="2"))):
            edit_manifest(pkg, change)
            rc, out, err = run(pkg)
            assert_failed_cleanly(rc, out, err)
            assert fails_naming(out, f"manifest {where}", "unknown")
            shutil.copy(PACKAGE / "references.json", pkg / "references.json")

    def test_a_missing_checked_field_fails_and_a_description_may_change(self, pkg):
        edit_manifest(pkg, lambda d: d["references"][0].pop("covered_bytes"))
        assert fails_naming(run(pkg)[1], "manifest reference 0", "missing")
        shutil.copy(PACKAGE / "references.json", pkg / "references.json")
        edit_manifest(pkg, lambda d: d["references"][0].update(why_these_bytes="reworded"))
        rc, out, err = run(pkg)
        assert rc == 0 and out[-1] == "ALL OK: 0 check(s) failed", out + [err]


# ------------------------------------------------------------------------------------------------
# Rebuilding: what changes and what stays (Codex thread 4217204745)
# ------------------------------------------------------------------------------------------------
class TestRebuilding:
    def test_two_rebuilds_differ_in_every_key_dependent_value_and_keep_the_fixed_ones(self, tmp_path):
        import cbor2
        builds = []
        for i in range(2):
            dst = tmp_path / f"build{i}"
            shutil.copytree(PACKAGE, dst)
            subprocess.run([sys.executable, str(dst / "build.py")], check=True, capture_output=True, timeout=120)
            rc, out, err = run(dst)
            assert rc == 0 and out[-1] == "ALL OK: 0 check(s) failed", out + [err]
            doc = json.loads((dst / "references.json").read_text(encoding="utf-8"))
            payload = json.loads(cbor2.loads(read(dst, ORIGINAL)).value[2])
            builds.append((doc, payload))
        (doc_a, pay_a), (doc_b, pay_b) = builds
        for name in (ORIGINAL, AUDIT, CORRECTION):
            for field in ("sha256_to_be_signed", "sha256_cose_sign1"):
                assert doc_a["statements"][name][field] != doc_b["statements"][name][field], (name, field)
        assert [r["digest"] for r in doc_a["references"]] != [r["digest"] for r in doc_b["references"]]
        assert pay_a["sha256"] == pay_b["sha256"], "the artifact digest comes from fixed bytes"
        text = " ".join((PACKAGE / "README.md").read_text(encoding="utf-8").split())
        assert "Every signature and every digest then differs" not in text
        assert "What build.py derives from fixed inputs only stays the same" in text


# ------------------------------------------------------------------------------------------------
# Gap 3, well-formedness, and malformed input on the FAILED path. Review cases 12 to 15.
# ------------------------------------------------------------------------------------------------
class TestWellFormedness:
    def test_an_unprotected_header_that_is_not_a_map_fails(self, pkg):
        body = parts(read(pkg, ORIGINAL))
        body[1] = 0
        write(pkg, ORIGINAL, tagged(body))
        rc, out, err = run(pkg)
        assert_failed_cleanly(rc, out, err)
        assert fails_naming(out, ORIGINAL, "unprotected")

    def test_a_duplicate_unprotected_key_fails(self, pkg):
        raw = read(pkg, ORIGINAL)
        i = unprotected_offset(raw)
        assert raw[i] == 0xA0            # the empty unprotected map
        dup = raw[:i] + b"\xa2\x18\x63\x01\x18\x63\x02" + raw[i + 1:]     # {99: 1, 99: 2}
        write(pkg, ORIGINAL, dup)
        rc, out, err = run(pkg)
        assert_failed_cleanly(rc, out, err)
        assert fails_naming(out, ORIGINAL, "duplicate")

    def test_trailing_input_after_the_item_fails(self, pkg):
        write(pkg, ORIGINAL, read(pkg, ORIGINAL) + b"\x00")
        rc, out, err = run(pkg)
        assert_failed_cleanly(rc, out, err)
        assert fails_naming(out, ORIGINAL, "trailing")

    def test_protected_contents_that_are_an_array_fail_on_the_failed_path(self, pkg):
        import cbor2
        body = parts(read(pkg, ORIGINAL))
        body[0] = cbor2.dumps([1, -8])
        write(pkg, ORIGINAL, tagged(body))
        rc, out, err = run(pkg)
        assert_failed_cleanly(rc, out, err)
        assert fails_naming(out, ORIGINAL, "protected")

    def test_a_duplicate_protected_key_is_named(self, pkg):
        body = parts(read(pkg, ORIGINAL))
        prot = body[0]
        body[0] = bytes([prot[0] + 1]) + prot[1:] + b"\x01\x27"      # alg (1) again, -8
        write(pkg, ORIGINAL, tagged(body))
        rc, out, err = run(pkg)
        assert_failed_cleanly(rc, out, err)
        assert fails_naming(out, ORIGINAL, "duplicate")

    def test_a_payload_that_is_not_a_byte_string_fails_on_the_failed_path(self, pkg):
        body = parts(read(pkg, ORIGINAL))
        body[2] = body[2].decode("utf-8")
        write(pkg, ORIGINAL, tagged(body))
        rc, out, err = run(pkg)
        assert_failed_cleanly(rc, out, err)
        assert fails_naming(out, ORIGINAL, "payload")


# ------------------------------------------------------------------------------------------------
# Gap 4, the envelope experiment split into two labelled cases, no Receipt claimed
# ------------------------------------------------------------------------------------------------
class TestTheEnvelopeExperiment:
    def test_two_separately_labelled_cases(self, pkg):
        rc, out, _err = run(pkg)
        assert rc == 0
        kept = [line for line in out if "tag 18 kept" in line and "unprotected parameter added" in line]
        removed = [line for line in out if "tag 18 removed" in line and "generic COSE" in line]
        assert len(kept) == 1 and kept[0].startswith("OK ")
        assert len(removed) == 1 and removed[0].startswith("OK ")
        assert "not an RFC 9943 Signed Statement" in removed[0]

    def test_no_line_calls_the_added_parameter_a_receipt(self, pkg):
        _rc, out, _err = run(pkg)
        assert not [line for line in out if "receipt" in line.lower()]
