"""`proofbundle scitt match`, the reader of draft-gruszka-scitt-statement-identification-03, against its 14 cases.

The oracle is ``interop/scitt-statement-identification-03/check_cases.py``, a checker of its own written with the
Python standard library only; this reader shares no code with it. Every expected value comes from the case files of
that folder, whose bytes come from Appendix A of the draft.

What is held here:

* the 14 cases and their variants under the rules of Section 6, through the real command line: ``ref_usable``,
  ``match`` and ``is_scitt`` as the draft gives them, the exit code of the match, and the ``signature`` axis equal
  to the draft's ``sig_valid`` on every one of them;
* missing inputs are never a match: no ``--external-aad``, no detached payload, an unusable reference;
* the scheme is the caller's: C14 stays incompatible under ToBeSigned, and WholeBytes is the digest of the candidate
  bytes as given (the "candidate SHA-256 (whole COSE_Sign1)" of every case);
* input the reader does not read gives no verdict (exit 2), never "not a statement";
* the two inputs where the ``signature`` axis and the draft's ``sig_valid`` differ (an R at the neutral point, a key
  of mixed order), so that the boundary the documentation names stays measured;
* single-byte mutants of three candidates, judged by the reader and by the oracle: wherever the reader gives a
  verdict it is the oracle's.
"""
from __future__ import annotations

import ast
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path

import pytest

from proofbundle import cli
from proofbundle.scitt_statement_id import SCHEMES, NoVerdict, match_statement

REPO = Path(__file__).resolve().parents[1]
FOLDER = REPO / "interop" / "scitt-statement-identification-03"


def _oracle():
    spec = importlib.util.spec_from_file_location("_scitt_id_03_oracle", FOLDER / "check_cases.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ORACLE = _oracle()


def _bytes(obj):
    return None if obj is None else base64.b64decode(obj["base64"])


def _cases():
    out = []
    for path in sorted((FOLDER / "cases").glob("C*.json"), key=lambda p: (len(p.name), p.name)):
        case = json.loads(path.read_text(encoding="utf-8"))
        inputs = case["inputs"]
        jobs = [(case["id"], {}, case["expected"])]
        for v in case.get("variants") or []:
            if v.get("rules", "section6") == "section6":
                jobs.append((f"{case['id']} / {v['name']}", v.get("change") or {}, v["expected"]))
        for label, change, expected in jobs:
            out.append(pytest.param(inputs, change, expected, id=label))
    return out


CASES = _cases()


def _run(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = cli.main(argv)
    return code, out.getvalue()


def _files(tmp_path, **parts):
    paths = {}
    for name, data in parts.items():
        if data is not None:
            p = tmp_path / name
            p.write_bytes(data)
            paths[name] = str(p)
    return paths


def _match(tmp_path, reference, candidate, *, scheme="ToBeSigned", alg=-16, aad=b"", detached=None, pub=None):
    paths = _files(tmp_path, reference=reference, candidate=candidate, aad=aad, detached=detached)
    argv = ["scitt", "match", paths["candidate"], "--reference", paths["reference"], "--scheme", scheme,
            "--alg", str(alg), "--json"]
    if "aad" in paths:
        argv += ["--external-aad", paths["aad"]]
    if "detached" in paths:
        argv += ["--detached-payload", paths["detached"]]
    if pub is not None:
        argv += ["--pub", base64.b64encode(pub).decode()]
    code, out = _run(argv)
    return code, json.loads(out)


def test_the_cases_are_all_there():
    assert len({p.id.split(" / ")[0] for p in CASES}) == 14
    assert len(CASES) == 17, "14 cases and the variants of C1, C7 and C8 under the rules of Section 6"


@pytest.mark.parametrize("inputs, change, expected", CASES)
def test_every_case_through_the_command_line(tmp_path, inputs, change, expected):
    aad = _bytes(change.get("external_aad", inputs["external_aad"]))
    detached = _bytes(change.get("detached_payload", inputs["detached_payload"]))
    code, res = _match(tmp_path, _bytes(inputs["reference"]), _bytes(inputs["candidate"]),
                       scheme=inputs["scheme"]["name"], alg=inputs["scheme"]["alg"], aad=aad, detached=detached,
                       pub=_bytes(inputs["stated_key"]["public_key"]))
    for axis in ("ref_usable", "match", "is_scitt"):
        if axis in expected:
            assert res[axis] == expected[axis], axis
    if "sig_valid" in expected:
        assert res["signature"] == expected["sig_valid"]
    assert res["sig_valid"] is None and "rule 2" in res["sig_valid_reason"]
    assert code == {"MATCH": 0, "NO_MATCH": 1, "INDETERMINATE": 3}[res["match"]]


def _c(case_id):
    return json.loads((FOLDER / "cases" / f"{case_id}.json").read_text(encoding="utf-8"))["inputs"]


def test_without_external_aad_there_is_no_match(tmp_path):
    i = _c("C1")
    code, res = _match(tmp_path, _bytes(i["reference"]), _bytes(i["candidate"]), aad=None)
    assert (code, res["match"], res["digest"]) == (3, "INDETERMINATE", None)
    assert any("external_aad is not supplied" in r for r in res["reasons"])


def test_an_empty_file_is_a_supplied_empty_external_aad(tmp_path):
    i = _c("C1")
    code, res = _match(tmp_path, _bytes(i["reference"]), _bytes(i["candidate"]), aad=b"")
    assert (code, res["match"]) == (0, "MATCH")


def test_a_nil_payload_without_a_detached_payload_is_never_a_match(tmp_path):
    i = _c("C8")
    code, res = _match(tmp_path, _bytes(i["reference"]), _bytes(i["candidate"]),
                       pub=_bytes(i["stated_key"]["public_key"]))
    assert (code, res["match"], res["signature"]) == (3, "INDETERMINATE", None)


def test_c14_stays_incompatible_under_tobesigned_and_there_is_no_fallback(tmp_path):
    i = _c("C14")
    code, res = _match(tmp_path, _bytes(i["reference"]), _bytes(i["candidate"]))
    assert (code, res["ref_usable"], res["match"]) == (3, False, "INDETERMINATE")
    # Under WholeBytes the same reference is compatible, and it is compared, not reinterpreted: its digest is the
    # ToBeSigned digest of statement 01, not the digest of the whole object.
    code, res = _match(tmp_path, _bytes(i["reference"]), _bytes(i["candidate"]), scheme="WholeBytes", aad=None)
    assert (code, res["ref_usable"], res["match"]) == (1, True, "NO_MATCH")


@pytest.mark.parametrize("inputs, change, expected", CASES)
def test_wholebytes_is_the_digest_of_the_candidate_as_given(tmp_path, inputs, change, expected):
    """The digest under WholeBytes is the "candidate SHA-256 (whole COSE_Sign1)" each case of Appendix A.3 gives."""
    candidate = _bytes(inputs["candidate"])
    reference = bytes([0x83, 0x2F, 0x6A]) + b"WholeBytes" + b"\x58\x20" + hashlib.sha256(candidate).digest()
    res = match_statement(reference, candidate, scheme="WholeBytes", alg=-16)
    assert res["digest"] == inputs["candidate"]["sha256"]
    assert (res["ref_usable"], res["match"]) == (True, "MATCH")


def test_wholebytes_tells_c5_and_c12_from_statement_01_where_tobesigned_does_not(tmp_path):
    whole_01 = hashlib.sha256(_bytes(_c("C1")["candidate"])).digest()
    reference = bytes([0x83, 0x2F, 0x6A]) + b"WholeBytes" + b"\x58\x20" + whole_01
    for case_id in ("C5", "C12"):
        i = _c(case_id)
        candidate = _bytes(i["candidate"])
        assert match_statement(reference, candidate, scheme="WholeBytes", alg=-16)["match"] == "NO_MATCH"
        assert match_statement(_bytes(i["reference"]), candidate, scheme="ToBeSigned", alg=-16,
                               external_aad=b"")["match"] == "MATCH"


#: The eight hash functions, written here from RFC 9054 and the IANA COSE Algorithms registry, not taken from the reader.
INDEPENDENT_DIGESTS = {
    -14: lambda b: hashlib.sha1(b).digest(),
    -15: lambda b: hashlib.sha256(b).digest()[:8],
    -16: lambda b: hashlib.sha256(b).digest(),
    -17: lambda b: hashlib.new("sha512_256", b).digest(),
    -18: lambda b: hashlib.shake_128(b).digest(32),
    -43: lambda b: hashlib.sha384(b).digest(),
    -44: lambda b: hashlib.sha512(b).digest(),
    -45: lambda b: hashlib.shake_256(b).digest(64),
}


def _cbor_reference(alg: int, scheme: str, digest: bytes) -> bytes:
    """The array [alg, scheme, digest] in the preferred encoding, for the negative algs and lengths used here."""
    n = -1 - alg
    head_alg = bytes([0x20 + n]) if n < 24 else bytes([0x38, n])
    head_digest = bytes([0x40 + len(digest)]) if len(digest) < 24 else bytes([0x58, len(digest)])
    return b"\x83" + head_alg + bytes([0x60 + len(scheme)]) + scheme.encode() + head_digest + digest


@pytest.mark.parametrize("alg", sorted(INDEPENDENT_DIGESTS))
@pytest.mark.parametrize("scheme", ["ToBeSigned", "WholeBytes"])
def test_every_hash_function_matches_its_own_digest_and_no_other(tmp_path, alg, scheme):
    i = _c("C1")
    candidate = _bytes(i["candidate"])
    covered = ORACLE.to_be_signed(ORACLE.read_candidate(candidate)[1], b"", ORACLE.read_candidate(candidate)[2]) \
        if scheme == "ToBeSigned" else candidate
    want = INDEPENDENT_DIGESTS[alg](covered)
    code, res = _match(tmp_path, _cbor_reference(alg, scheme, want), candidate, scheme=scheme, alg=alg)
    assert (code, res["ref_usable"], res["match"], res["digest"]) == (0, True, "MATCH", want.hex())
    other = bytes([want[0] ^ 1]) + want[1:]
    code, res = _match(tmp_path, _cbor_reference(alg, scheme, other), candidate, scheme=scheme, alg=alg)
    assert (code, res["match"]) == (1, "NO_MATCH")


def test_wholebytes_reads_the_candidate_before_it_hashes(tmp_path):
    """A candidate that is not a statement is not one under WholeBytes either, even when the reference holds the
    digest of exactly its bytes."""
    candidate = b"\x00"
    code, res = _match(tmp_path, _cbor_reference(-16, "WholeBytes", hashlib.sha256(candidate).digest()), candidate,
                       scheme="WholeBytes", aad=None)
    assert (code, res["ref_usable"], res["match"], res["is_scitt"], res["digest"]) == (1, True, "NO_MATCH", False, None)


def _tagged(protected: bytes, unprotected: bytes, payload: bytes, signature: bytes) -> bytes:
    def bstr(b):
        return (bytes([0x40 + len(b)]) if len(b) < 24 else b"\x58" + bytes([len(b)])) + b
    return b"\xd2\x84" + bstr(protected) + unprotected + bstr(payload) + bstr(signature)


def test_a_candidate_that_is_not_a_statement_is_no_match_under_a_usable_reference(tmp_path):
    i = _c("C1")
    duplicate = _tagged(b"", b"\xa2\x01\x00\x01\x00", b"x", b"\x00" * 64)       # {1: 0, 1: 0}
    code, res = _match(tmp_path, _bytes(i["reference"]), duplicate)
    assert (code, res["match"], res["is_scitt"], res["signature"]) == (1, "NO_MATCH", False, None)
    bad_text = _tagged(b"\xa1\x01\x62\xc3\x28", b"\xa0", b"x", b"\x00" * 64)    # protected {1: invalid UTF-8}
    code, res = _match(tmp_path, _bytes(i["reference"]), bad_text)
    assert (code, res["match"], res["is_scitt"]) == (1, "NO_MATCH", False)
    code, res = _match(tmp_path, _bytes(_c("C13")["reference"]), duplicate)
    assert (code, res["match"]) == (3, "INDETERMINATE")


@pytest.mark.parametrize("aad", [b"", None])
def test_a_signature_that_is_not_64_bytes_is_false_even_without_a_tobesigned(aad):
    """Section 6: after the read check, a signature that is not 64 bytes gives sig_valid False; the ToBeSigned is not
    needed for that, so a missing external_aad does not make it null."""
    i = _c("C1")
    candidate = _tagged(b"", b"\xa0", b"review", b"\x01" * 63)
    res = match_statement(_bytes(i["reference"]), candidate, scheme="ToBeSigned", alg=-16, external_aad=aad,
                          public_key=_bytes(i["stated_key"]["public_key"]))
    assert res["signature"] is False
    assert ORACLE.axes({"reference": _bytes(i["reference"]), "candidate": candidate,
                        "scheme": {"alg": -16, "name": "ToBeSigned"}, "external_aad": aad, "detached_payload": None,
                        "public_key": _bytes(i["stated_key"]["public_key"])})["sig_valid"] is False


def test_a_key_the_reader_does_not_represent_gives_no_verdict(tmp_path):
    """1 and true are two keys under RFC 8949 Section 5.6.1, and the oracle reads the candidate as a statement; this
    reader cannot keep both in one map, so it gives no verdict instead of calling it no statement."""
    candidate = _tagged(b"", b"\xa2\x01\x00\xf5\x00", b"x", b"\x00" * 64)       # {1: 0, true: 0}
    assert ORACLE.read_candidate(candidate) is not None
    i = _c("C1")
    with pytest.raises(NoVerdict):
        match_statement(_bytes(i["reference"]), candidate, scheme="ToBeSigned", alg=-16, external_aad=b"")
    paths = _files(tmp_path, reference=_bytes(i["reference"]), candidate=candidate)
    code, out = _run(["scitt", "match", paths["candidate"], "--reference", paths["reference"], "--scheme",
                      "ToBeSigned", "--alg", "-16", "--json"])
    assert code == 2 and json.loads(out)["verdict"] is None


def test_input_over_the_depth_budget_gives_no_verdict():
    candidate = b"\xd2\x84\x40\xa1\x01" + b"\x81" * 70 + b"\x00" + b"\x41x\x40"
    with pytest.raises(NoVerdict):
        match_statement(_bytes(_c("C1")["reference"]), candidate, scheme="ToBeSigned", alg=-16, external_aad=b"")


# The two inputs where the signature axis and Section 6 sig_valid differ, built with the oracle's own arithmetic.

def _issuer_seed():
    keys = json.loads((FOLDER / "test_keys.json").read_text(encoding="utf-8"))["keys"]
    return bytes.fromhex(keys["issuer"]["ed25519_seed_hex"])


def _secret_scalar(seed: bytes) -> int:
    a = int.from_bytes(hashlib.sha512(seed).digest()[:32], "little")
    return (a & ((1 << 254) - 8)) | (1 << 254)


def _sign(a: int, public: bytes, message: bytes, *, r_scalar: int | None = None, r_bytes: bytes | None = None):
    o = ORACLE
    r_enc = r_bytes if r_bytes is not None else o._encode_point(o._mul(r_scalar, o.BASE))
    k = int.from_bytes(hashlib.sha512(r_enc + public + message).digest(), "little") % o.L
    s = ((r_scalar or 0) + k * a) % o.L
    return r_enc + s.to_bytes(32, "little"), k


def _reference_for(tbs: bytes) -> bytes:
    return bytes([0x83, 0x2F, 0x6A]) + b"ToBeSigned" + b"\x58\x20" + hashlib.sha256(tbs).digest()


def test_an_r_at_the_neutral_point_verifies_in_the_library_and_not_under_section_6():
    a = _secret_scalar(_issuer_seed())
    public = ORACLE._encode_point(ORACLE._mul(a, ORACLE.BASE))
    tbs = ORACLE.to_be_signed(b"", b"", b"review")
    neutral = (1).to_bytes(32, "little")
    signature, _k = _sign(a, public, tbs, r_bytes=neutral)
    candidate = _tagged(b"", b"\xa0", b"review", signature)
    res = match_statement(_reference_for(tbs), candidate, scheme="ToBeSigned", alg=-16, external_aad=b"",
                          public_key=public)
    assert (res["match"], res["signature"]) == ("MATCH", True)
    assert ORACLE.ed25519_rules(public, signature, tbs) is False


def test_a_key_of_mixed_order_verifies_in_the_library_and_not_under_section_6():
    o = ORACLE
    a = _secret_scalar(_issuer_seed())
    order_two = o._decode_point(((o.P - 1)).to_bytes(32, "little"))     # (0, -1), the point of order 2
    mixed = o._encode_point(o._add(o._mul(a, o.BASE), order_two))
    tbs = o.to_be_signed(b"", b"", b"review")
    for r in range(1, 64):                                               # until k is even, k*T is the neutral point
        signature, k = _sign(a, mixed, tbs, r_scalar=r)
        if k % 2 == 0:
            break
    else:
        pytest.fail("no even k in 63 nonces")
    candidate = _tagged(b"", b"\xa0", b"review", signature)
    res = match_statement(_reference_for(tbs), candidate, scheme="ToBeSigned", alg=-16, external_aad=b"",
                          public_key=mixed)
    assert (res["match"], res["signature"]) == ("MATCH", True)
    assert o.ed25519_rules(mixed, signature, tbs) is False


@pytest.mark.parametrize("case_id", ["C1", "C9", "C12"])
def test_single_byte_mutants_agree_with_the_oracle_wherever_the_reader_gives_a_verdict(case_id, monkeypatch):
    # Only ref_usable, match and is_scitt are compared, and none of them reads the signature; the oracle's
    # pure-Python curve arithmetic is left out so that some three thousand mutants stay within seconds.
    monkeypatch.setattr(ORACLE, "ed25519_rules", lambda *a, **k: None)
    i = _c(case_id)
    reference, candidate = _bytes(i["reference"]), _bytes(i["candidate"])
    judged = no_verdict = 0
    for pos in range(len(candidate)):
        for mask in (0x01, 0x20, 0x80):
            mutant = candidate[:pos] + bytes([candidate[pos] ^ mask]) + candidate[pos + 1:]
            try:
                got = match_statement(reference, mutant, scheme="ToBeSigned", alg=-16, external_aad=b"")
            except NoVerdict:
                no_verdict += 1
                continue
            want = ORACLE.axes({"reference": reference, "candidate": mutant, "scheme": {"alg": -16, "name": "ToBeSigned"},
                                "external_aad": b"", "detached_payload": None,
                                "public_key": _bytes(i["stated_key"]["public_key"])})
            assert {k: got[k] for k in ("ref_usable", "match", "is_scitt")} == \
                   {k: want[k] for k in ("ref_usable", "match", "is_scitt")}, (pos, mask)
            judged += 1
    assert judged > 3 * len(candidate) * 0.9, (judged, no_verdict)


@pytest.mark.parametrize("argv_tail, words", [
    (["--scheme", "ToBeSigned", "--detached", "D"], "unrecognized arguments: --detached D"),
    (["--scheme", "COSE_Sign1"], "invalid choice"),
])
def test_the_command_line_refuses_an_abbreviation_and_an_unknown_scheme(argv_tail, words):
    err = io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()), pytest.raises(SystemExit) as ctx:
        cli.main(["scitt", "match", "C", "--reference", "R", "--alg", "-16"] + argv_tail)
    assert ctx.value.code == 2 and words in err.getvalue()


@pytest.mark.parametrize("extra, words", [
    (["--alg", "-7"], "names no hash function"),
    (["--pub", base64.b64encode(b"\x01" * 31).decode()], "32 bytes"),
    (["--external-aad", ""], "cannot read --external-aad"),
])
def test_a_wrong_option_is_exit_2(tmp_path, extra, words):
    i = _c("C1")
    paths = _files(tmp_path, reference=_bytes(i["reference"]), candidate=_bytes(i["candidate"]))
    argv = ["scitt", "match", paths["candidate"], "--reference", paths["reference"], "--scheme", "ToBeSigned"]
    argv += extra if "--alg" in extra else ["--alg", "-16"] + extra
    code, out = _run(argv + ["--json"])
    assert code == 2 and words in json.loads(out)["error"]


def test_the_parser_offers_exactly_the_schemes_of_the_reader():
    assert cli._SCITT_SCHEMES == SCHEMES


def test_no_verify_path_imports_the_reader():
    """The reader is reached through `scitt match` only: no module under src/ imports it, and cli.py imports it inside
    the command, not at module level."""
    for path in sorted((REPO / "src" / "proofbundle").rglob("*.py")):
        if path.name == "scitt_statement_id.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").endswith("scitt_statement_id"):
                assert path.name == "cli.py", path
                func = next(f for f in ast.walk(tree) if isinstance(f, ast.FunctionDef)
                            and any(n is node for n in ast.walk(f)))
                assert func.name == "_cmd_scitt_match", func.name
