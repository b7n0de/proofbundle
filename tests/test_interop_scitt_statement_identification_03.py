"""interop/scitt-statement-identification-03: the cases of the draft check, and the checker can fail.

check_cases.py recomputes the four axes of Section 6 of draft-gruszka-scitt-statement-identification-03 for C1 to C14
and for the five further results Appendix A.3 states in words; the folder holds 19 of 19. That alone could come from a
checker that answers from the expected values, so each planted change below, to the input of one case or to the checker
itself, must turn exactly the named check into a mismatch. tools/build_cases.py, run on the unmodified draft text the
folder carries, must write the case files byte for byte. The cryptography package, an independent Ed25519 verifier,
must agree with the checker's signature rules on every case whose R and A have order L, and both must accept test 1 of
RFC 8032 Section 7.1. Three inputs the draft names but no case carries, a text that is not UTF-8 and a repeated map key
in the protected header and a signature whose S is not below L, must be refused as the draft says.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

# The repository root by name, as tests/conftest.py derives repo-context modules: the sdist does not ship interop/,
# and from an extracted sdist this module is then skipped as N/A instead of failing on a missing file.
ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / "interop" / "scitt-statement-identification-03"
CHECKER = FOLDER / "check_cases.py"
BUILDER = FOLDER / "tools" / "build_cases.py"
DRAFT = FOLDER / "draft-gruszka-scitt-statement-identification-03.txt"


def _run(folder: Path = FOLDER, checker: Path | None = None) -> subprocess.CompletedProcess:
    checker = checker or folder / "check_cases.py"
    return subprocess.run([sys.executable, "-I", "-B", str(checker), "--cases", str(folder / "cases")],
                          capture_output=True, text=True, timeout=300)


def _summary(p: subprocess.CompletedProcess) -> tuple:
    found = re.findall(r"^(\d+) of (\d+) checks match \((\d+) case files\)$", p.stdout, re.M)
    assert len(found) == 1, p.stdout[-600:]
    return tuple(int(x) for x in found[0])


def _mismatches(p: subprocess.CompletedProcess) -> set:
    found = re.findall(r"^mismatch: (.*)$", p.stdout, re.M)
    return set(found[0].split(", ")) if found else set()


def _module():
    """check_cases.py as a module, loaded without writing a bytecode cache into the folder."""
    old, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        spec = importlib.util.spec_from_file_location("scitt_check_cases_03", CHECKER)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = old
    return mod


def _copy(tmp_path: Path) -> Path:
    dst = tmp_path / "folder"
    shutil.copytree(FOLDER, dst, ignore=shutil.ignore_patterns("__pycache__"))
    return dst


def _obj(data: bytes) -> dict:
    return {"base64": base64.b64encode(data).decode("ascii"), "length": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def _raw(o: dict) -> bytes:
    return base64.b64decode(o["base64"])


def _case(folder: Path, cid: str) -> dict:
    return json.loads((folder / "cases" / (cid + ".json")).read_text(encoding="utf-8"))


def _put(folder: Path, cid: str, case: dict) -> None:
    (folder / "cases" / (cid + ".json")).write_text(json.dumps(case, indent=1, sort_keys=True) + "\n",
                                                    encoding="utf-8")


# ---------------------------------------------------------------------------------------------------------------


def test_every_case_and_every_variant_matches():
    p = _run()
    assert p.returncode == 0, p.stdout[-800:]
    assert _summary(p) == (19, 19, 14)
    assert _mismatches(p) == set()


def test_the_builder_writes_the_case_files_byte_for_byte_from_the_draft_text(tmp_path):
    assert hashlib.sha256(DRAFT.read_bytes()).hexdigest() == (
        "9176957ab9f3a4f4daca9dde67b3bcbb812417697f20e813c3ef3102c85bd95c")
    out = tmp_path / "out"
    p = subprocess.run([sys.executable, "-I", "-B", str(BUILDER), str(DRAFT), str(out)], capture_output=True,
                       text=True, timeout=300)
    assert p.returncode == 0, (p.stdout + p.stderr)[-800:]
    assert re.search(r"^\d+ checks against the text of draft-gruszka-scitt-statement-identification-03$", p.stdout,
                     re.M), p.stdout[-400:]
    written = sorted(x.relative_to(out).as_posix() for x in out.rglob("*") if x.is_file())
    assert len(written) == 16, written
    for rel in written:
        assert (out / rel).read_bytes() == (FOLDER / rel).read_bytes(), rel


def test_the_manifest_names_every_file_with_its_hash():
    listed = {}
    for line in (FOLDER / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        listed[name] = digest
    on_disk = {x.relative_to(FOLDER).as_posix() for x in FOLDER.rglob("*")
               if x.is_file() and "__pycache__" not in x.parts} - {"MANIFEST.sha256"}
    assert set(listed) == on_disk
    for name, digest in listed.items():
        assert hashlib.sha256((FOLDER / name).read_bytes()).hexdigest() == digest, name


def test_the_scripts_use_the_standard_library_only():
    for script in (CHECKER, BUILDER):
        names = set()
        for node in ast.walk(ast.parse(script.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                names |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and not node.level:
                names.add(node.module.split(".")[0])
        assert names and names <= set(sys.stdlib_module_names), (script.name, names - set(sys.stdlib_module_names))


# ---------------------------------------------------------------------------------------------------------------
# Planted changes to the input of one case: the checker computes from the inputs, so exactly that case turns.


def _flip_expected(case):
    case["expected"]["match"] = "MATCH"


def _empty_aad(case):
    case["inputs"]["external_aad"] = _obj(b"")


def _tagged_candidate_for_c9(case):
    case["inputs"]["candidate"] = _obj(b"\xd2" + _raw(case["inputs"]["candidate"]))


def _scheme_alg_minus_16(case):
    case["inputs"]["scheme"]["alg"] = -16


def _payload_of_01_supplied(case):
    case["inputs"]["detached_payload"] = case["variants"][0]["change"]["detached_payload"]


def _signature_of_01(case):
    case["inputs"]["candidate"] = _obj(_raw(_case(FOLDER, "C1")["inputs"]["candidate"]))


INPUT_CHANGES = {
    "C2": _flip_expected,
    "C7": _empty_aad,
    "C9": _tagged_candidate_for_c9,
    "C10": _scheme_alg_minus_16,
    "C8": _payload_of_01_supplied,
    "C6": _signature_of_01,
}


@pytest.mark.parametrize("cid", sorted(INPUT_CHANGES))
def test_a_planted_input_turns_exactly_its_case(tmp_path, cid):
    folder = _copy(tmp_path)
    case = _case(folder, cid)
    INPUT_CHANGES[cid](case)
    _put(folder, cid, case)
    p = _run(folder)
    assert p.returncode == 1, p.stdout[-600:]
    assert _mismatches(p) == {cid}, p.stdout[-600:]


def test_a_case_file_whose_bytes_differ_from_their_hash_is_an_error_not_a_result(tmp_path):
    folder = _copy(tmp_path)
    case = _case(folder, "C1")
    case["inputs"]["candidate"]["sha256"] = "0" * 64
    _put(folder, "C1", case)
    p = _run(folder)
    assert p.returncode == 1 and _mismatches(p) == {"C1.json"}, p.stdout[-600:]
    assert "differ from their sha256" in p.stdout


# ---------------------------------------------------------------------------------------------------------------
# Planted defects in the checker: each one the cases of the draft catch, at the check that shows it.

CHECKER_DEFECTS = {
    "external_aad left out of ToBeSigned": (
        'tbs = None if payload is None else to_be_signed(body_protected, aad, payload)',
        'tbs = None if payload is None else to_be_signed(body_protected, b"", payload)', {"C7"}),
    "tag 18 not read": ('"is_scitt": tagged, "sig_valid": sig_valid}', '"is_scitt": True, "sig_valid": sig_valid}',
                        {"C9"}),
    "a supplied payload used although the candidate carries one": (
        "    if payload is None:\n        payload = detached\n",
        "    if payload is None or detached is not None:\n        payload = detached\n",
        {"C1 / with 32 zero bytes supplied as detached payload"}),
    "digest length not read": ("    if len(dig.value) != HASHES[alg.value][1]:\n        return False\n", "", {"C13"}),
    "scheme name not compared": ('return alg.value == scheme["alg"] and name.value == scheme["name"]',
                                 'return alg.value == scheme["alg"]', {"C14"}),
    "scheme alg not compared": ('return alg.value == scheme["alg"] and name.value == scheme["name"]',
                                'return name.value == scheme["name"]', {"C10"}),
    "rule 2 left out and the cofactored equation": (
        'if rules == "section6":\n        for pt in (a_pt, r_pt):',
        'rules = "no-rule-2-cofactored"\n    if rules == "section6":\n        for pt in (a_pt, r_pt):',
        {"C11", "C11 / with rule 2 left out and the cofactorless equation"}),
    "the cofactored equation read as the cofactorless one": (
        "        return _equal(_mul(8, left), _mul(8, right))", "        return _equal(left, right)",
        {"C11 / with rule 2 left out and the cofactored equation"}),
    "a missing detached payload read as empty": ("    if payload is None:\n        payload = detached\n",
                                                 "    if payload is None:\n        payload = detached or b\"\"\n",
                                                 {"C8"}),
}


@pytest.mark.parametrize("name", sorted(CHECKER_DEFECTS))
def test_a_planted_defect_in_the_checker_is_caught(tmp_path, name):
    old, new, expected = CHECKER_DEFECTS[name]
    folder = _copy(tmp_path)
    source = (folder / "check_cases.py").read_text(encoding="utf-8")
    assert source.count(old) == 1, name
    (folder / "check_cases.py").write_text(source.replace(old, new), encoding="utf-8")
    p = _run(folder)
    assert p.returncode == 1, p.stdout[-600:]
    assert _mismatches(p) == expected, p.stdout[-600:]


# ---------------------------------------------------------------------------------------------------------------
# An independent verifier, and inputs the draft names that no case carries

RFC8032_TEST1 = {
    "seed": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "public": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "signature": ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46"
                  "bd25bf5f0595bbe24655141438e7a100b"),
}


def test_the_checker_s_ed25519_reproduces_rfc8032_test_1():
    cc = _module()
    assert cc.public_key_from_seed(bytes.fromhex(RFC8032_TEST1["seed"])).hex() == RFC8032_TEST1["public"]
    pub, sig = bytes.fromhex(RFC8032_TEST1["public"]), bytes.fromhex(RFC8032_TEST1["signature"])
    assert cc.ed25519_rules(pub, sig, b"") is True
    assert cc.ed25519_rules(pub, sig, b"x") is False


def _signed_inputs():
    """(label, public key, signature, ToBeSigned) for every check whose sig_valid the four rules decide."""
    cc = _module()
    for path in sorted((FOLDER / "cases").glob("C*.json")):
        case = json.loads(path.read_text(encoding="utf-8"))
        inputs = cc.case_inputs(case["inputs"], case["id"])
        jobs = [(case["id"], inputs)]
        for v in case.get("variants") or []:
            if "rules" in v:
                continue
            changed = dict(inputs)
            for k, val in v["change"].items():
                changed[k] = _raw(val)
            jobs.append((case["id"] + " / " + v["name"], changed))
        for label, inp in jobs:
            read = cc.read_candidate(inp["candidate"])
            if read is None:
                continue
            _tagged, prot, payload, sig = read
            payload = inp["detached_payload"] if payload is None else payload
            if payload is None or len(sig) != 64:
                continue
            yield label, inp["public_key"], sig, cc.to_be_signed(prot, inp["external_aad"], payload)


def test_an_independent_ed25519_verifier_agrees_on_every_case_but_c11():
    from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: PLC0415
    cc = _module()
    seen = []
    for label, pub, sig, tbs in _signed_inputs():
        if label.startswith("C11"):
            continue  # R of mixed order: the case where verifiers may differ, decided by rule 2 of Section 6
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, tbs)
            independent = True
        except InvalidSignature:
            independent = False
        assert cc.ed25519_rules(pub, sig, tbs) is independent, label
        seen.append(label)
    assert len(seen) >= 14, seen


def _c1_inputs():
    cc = _module()
    return cc, cc.case_inputs(_case(FOLDER, "C1")["inputs"], "C1")


def test_a_text_that_is_not_utf8_in_the_protected_header_is_not_a_statement():
    # Section 6: such a candidate has is_scitt False, sig_valid None, and match NO_MATCH under a usable reference.
    cc, inputs = _c1_inputs()
    cand = inputs["candidate"]
    at = cand.index(b"application/json")
    inputs = dict(inputs, candidate=cand[:at] + b"\xff" + cand[at + 1:])
    assert cc.axes(inputs) == {"ref_usable": True, "match": "NO_MATCH", "is_scitt": False, "sig_valid": None}


def test_a_repeated_key_in_the_protected_header_is_not_a_statement():
    # The content type label 3 written as label 1, which the map already holds for the algorithm.
    cc, inputs = _c1_inputs()
    cand = inputs["candidate"]
    at = cand.index(b"\x03\x70application/json")
    inputs = dict(inputs, candidate=cand[:at] + b"\x01" + cand[at + 1:])
    assert cc.axes(inputs) == {"ref_usable": True, "match": "NO_MATCH", "is_scitt": False, "sig_valid": None}


def test_a_signature_whose_s_is_not_below_l_is_refused_by_both_verifiers():
    from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: PLC0415
    cc, inputs = _c1_inputs()
    _tagged, prot, payload, sig = cc.read_candidate(inputs["candidate"])
    tbs = cc.to_be_signed(prot, b"", payload)
    assert cc.ed25519_rules(inputs["public_key"], sig, tbs) is True
    s_plus_l = (int.from_bytes(sig[32:], "little") + cc.L).to_bytes(32, "little")
    assert cc.ed25519_rules(inputs["public_key"], sig[:32] + s_plus_l, tbs) is False
    with pytest.raises(InvalidSignature):
        Ed25519PublicKey.from_public_bytes(inputs["public_key"]).verify(sig[:32] + s_plus_l, tbs)
