"""Two findings of the second Codex review of pull request 369, and the neighbour the fix of the first one
exposed, each held as a case that fails on the verifier of 49869b53 and passes on the fix.

1. Thread 4325126781: the body was parsed with `json.loads`, which keeps the LAST of two members of one
   name. A body with two `candidate` members, the second one matching the manifest, passed `before` with
   exit 0, while a reader that keeps the first member saw other digests. The same parse read the manifest.
   Every JSON file of the package is now read with the package's strict reader, and a name given twice is
   a finding.
2. Thread 4325126812: `after` compared the files with the manifest that lay in the package when it ran. A
   manifest replaced together with its body and payload, digests updated and the new payload signed,
   verified, because the expectation came from the replacement itself. `before` now prints the digest of
   the manifest it reviewed, and `after` is bound to it: another manifest is a finding, and without the
   digest `after` assembles nothing and answers NOT MEASURABLE.
3. The neighbour: `after` read the payload once for the signature and again for its digest, and the body
   for its digest, again for the derivation and a third time for the preview. A file swapped between two
   reads was judged in one form and used in another. Every file is read once now, in both phases.

Each case builds a real package on disk, as the sibling files do.
"""
from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import re

import pytest

from tests.test_verify_signing_package import HEAD, PUB_B64, SK, _canon, _package, _reviewed, _sign, vsp


def _digest(p: pathlib.Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _set_manifest(pkg: pathlib.Path, change) -> None:
    m = json.loads((pkg / vsp.DEFAULT_MANIFEST).read_text())
    change(m)
    (pkg / vsp.DEFAULT_MANIFEST).write_text(json.dumps(m), encoding="utf-8")


# ── 1. a name given twice is a finding, in every file of the package ────────────────────────────────

def _body_with_two_candidates(pkg: pathlib.Path) -> None:
    """Codex's case: two `candidate` members with the same commit and other digests. The LAST one is the
    manifest's, so a last-wins parse agrees with every digest; a first-wins reader sees the other one."""
    body = json.loads((pkg / "art.body.json").read_text())
    first = dict(body["candidate"], tree_digest="1" * 64, sdist_sha256="2" * 64, wheel_sha256="3" * 64)
    rest = {k: v for k, v in body.items() if k != "candidate"}
    text = ('{"candidate": ' + json.dumps(first) + ", "
            + json.dumps(rest)[1:-1] + ', "candidate": ' + json.dumps(body["candidate"]) + "}\n")
    (pkg / "art.body.json").write_text(text, encoding="utf-8")
    payload = _canon(json.loads(text))
    (pkg / "art.payload.bin").write_bytes(payload)
    _set_manifest(pkg, lambda m: m["artifacts"][0].update(
        body_sha256=_digest(pkg / "art.body.json"), payload_sha256=hashlib.sha256(payload).hexdigest()))


def test_a_body_with_a_name_given_twice_is_a_finding_before_signing(tmp_path, capsys):
    pkg = _package(tmp_path)
    _body_with_two_candidates(pkg)
    # PRECONDITION: the two readers really disagree, so the case is about the parse and not a digest.
    text = (pkg / "art.body.json").read_text()
    pairs = json.loads(text, object_pairs_hook=lambda p: p)
    both = [dict(v) for k, v in pairs if k == "candidate"]
    assert len(both) == 2 and both[0] != both[1]
    assert json.loads(text)["candidate"] == both[1], "json.loads keeps the last member"
    assert both[1] == json.loads((pkg / vsp.DEFAULT_MANIFEST).read_text())["candidate"]
    rc = vsp.before(pkg, anchor_pubkey=PUB_B64, expected_head=HEAD)
    out = capsys.readouterr().out
    assert rc == 1
    assert "not strict JSON" in out and "candidate" in out
    assert "everything checked and consistent" not in out


def test_a_body_with_a_name_given_twice_assembles_no_preview_after_signing(tmp_path, capsys):
    pkg = _package(tmp_path)
    _body_with_two_candidates(pkg)
    rc = vsp.after(pkg, "art", _sign(pkg), anchor_pubkey=PUB_B64, reviewed_manifest_sha256=_reviewed(pkg))
    out = capsys.readouterr().out
    assert rc == 1
    assert "not strict JSON" in out
    assert not (pkg / "art.signed.json").exists()


@pytest.mark.parametrize("where", ["top level", "artifact entry", "candidate block"])
def test_a_manifest_with_a_name_given_twice_stops_the_run(tmp_path, where):
    pkg = _package(tmp_path)
    text = (pkg / vsp.DEFAULT_MANIFEST).read_text()
    if where == "top level":
        text = text.replace('"artifacts":', '"anchor": {"public_key_b64": "x"}, "artifacts":', 1)
    elif where == "artifact entry":
        text = text.replace('"payload_sha256":', '"payload_sha256": "' + "0" * 64 + '", "payload_sha256":', 1)
    else:
        text = text.replace('"tree_digest":', '"tree_digest": "' + "1" * 64 + '", "tree_digest":', 1)
    (pkg / vsp.DEFAULT_MANIFEST).write_text(text, encoding="utf-8")
    for run in (lambda: vsp.before(pkg, anchor_pubkey=PUB_B64),
                lambda: vsp.after(pkg, "art", _sign(pkg), anchor_pubkey=PUB_B64)):
        with pytest.raises(SystemExit) as ctx:
            run()
        assert "not readable JSON" in str(ctx.value) and "duplicate" in str(ctx.value), where


def test_a_body_that_is_not_json_is_a_finding_not_a_traceback(tmp_path, capsys):
    """The neighbour in `before`: the candidate check parsed the body outside any handler."""
    pkg = _package(tmp_path)
    (pkg / "art.body.json").write_text("{not json", encoding="utf-8")
    _set_manifest(pkg, lambda m: m["artifacts"][0].__setitem__("body_sha256", _digest(pkg / "art.body.json")))
    rc = vsp.before(pkg, anchor_pubkey=PUB_B64)
    assert rc == 1
    assert "not strict JSON" in capsys.readouterr().out


def test_without_the_strict_reader_the_body_is_NOT_MEASURABLE(tmp_path, monkeypatch, capsys):
    pkg = _package(tmp_path)
    real = vsp._strict_reader
    calls = {"n": 0}

    def manifest_only():
        calls["n"] += 1
        return real() if calls["n"] == 1 else (None, "simulated: no proofbundle._strict_json")
    monkeypatch.setattr(vsp, "_strict_reader", manifest_only)
    rc = vsp.before(pkg, anchor_pubkey=PUB_B64, expected_head=HEAD)
    out = capsys.readouterr().out
    assert rc == 2
    assert "NOT MEASURABLE" in out


def test_without_the_strict_reader_the_manifest_is_NOT_MEASURABLE(tmp_path, monkeypatch, capsys):
    pkg = _package(tmp_path)
    monkeypatch.setattr(vsp, "_strict_reader", lambda: (None, "simulated: no proofbundle._strict_json"))
    with pytest.raises(SystemExit) as ctx:
        vsp.before(pkg, anchor_pubkey=PUB_B64)
    assert ctx.value.code == 2
    assert "NOT MEASURABLE" in capsys.readouterr().out


# ── 2. after is bound to the manifest before reviewed ──────────────────────────────────────────────────

def _replace_coherently(pkg: pathlib.Path) -> None:
    """Codex's case: manifest, body and payload replaced together, every digest updated."""
    body = json.loads((pkg / "art.body.json").read_text())
    body["version"] = "9.9.9"
    (pkg / "art.body.json").write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    payload = _canon(body)
    (pkg / "art.payload.bin").write_bytes(payload)
    _set_manifest(pkg, lambda m: m["artifacts"][0].update(
        body_sha256=_digest(pkg / "art.body.json"), payload_sha256=hashlib.sha256(payload).hexdigest()))


def test_before_prints_the_digest_of_the_manifest_it_reviewed(tmp_path, capsys):
    pkg = _package(tmp_path)
    assert vsp.before(pkg, anchor_pubkey=PUB_B64, expected_head=HEAD) == 0
    out = capsys.readouterr().out
    m = re.search(r"manifest\s*:\s*sha256 ([0-9a-f]{64})", out)
    assert m and m.group(1) == _reviewed(pkg), out[:400]
    assert "--reviewed-manifest-sha256" in out


def test_a_manifest_replaced_with_its_files_after_before_is_refused(tmp_path, capsys):
    pkg = _package(tmp_path)
    assert vsp.before(pkg, anchor_pubkey=PUB_B64, expected_head=HEAD) == 0
    reviewed = re.search(r"manifest\s*:\s*sha256 ([0-9a-f]{64})", capsys.readouterr().out).group(1)
    _replace_coherently(pkg)
    sig = _sign(pkg)
    rc = vsp.after(pkg, "art", sig, anchor_pubkey=PUB_B64, reviewed_manifest_sha256=reviewed)
    out = capsys.readouterr().out
    assert rc == 1
    assert "not the manifest" in out and "reviewed" in out
    assert not (pkg / "art.signed.json").exists()
    # ANTI-PARITY: the same replaced package, bound to its own manifest, verifies. The refusal above is
    # the binding, not the replacement or the signature.
    assert vsp.after(pkg, "art", sig, anchor_pubkey=PUB_B64, reviewed_manifest_sha256=_reviewed(pkg)) == 0
    assert (pkg / "art.signed.json").is_file()


@pytest.mark.parametrize("form", ["upper case", "a prefix", "a trailing newline", "sha256: prefixed"])
def test_through_the_python_api_only_the_exact_digest_binds(tmp_path, capsys, form):
    """The command line refuses another spelling through its argument type; the function compares exactly.
    The reading of round two measured that a prefix or case-blind comparison passed every other case."""
    pkg = _package(tmp_path)
    exact = _reviewed(pkg)
    given = {"upper case": exact.upper(), "a prefix": exact[:16], "a trailing newline": exact + "\n",
             "sha256: prefixed": "sha256:" + exact}[form]
    rc = vsp.after(pkg, "art", _sign(pkg), anchor_pubkey=PUB_B64, reviewed_manifest_sha256=given)
    assert rc == 1, form
    assert not (pkg / "art.signed.json").exists(), form


def test_after_without_the_reviewed_digest_assembles_nothing(tmp_path, capsys):
    pkg = _package(tmp_path)
    rc = vsp.after(pkg, "art", _sign(pkg), anchor_pubkey=PUB_B64)
    out = capsys.readouterr().out
    assert rc == 2
    assert "NOT MEASURABLE" in out and "--reviewed-manifest-sha256" in out
    assert not (pkg / "art.signed.json").exists()


def test_the_command_line_carries_the_digest_and_refuses_another_form(tmp_path, capsys):
    pkg = _package(tmp_path)
    sig = _sign(pkg)
    base = ["after", "--package", str(pkg), "--artifact", "art", "--signature", str(sig), "--anchor-pubkey", PUB_B64]
    assert vsp.main(base + ["--reviewed-manifest-sha256", _reviewed(pkg)]) == 0
    capsys.readouterr()
    with pytest.raises(SystemExit) as ctx:
        vsp.main(base + ["--reviewed-manifest-sha256", _reviewed(pkg)[:16]])
    assert ctx.value.code == 2
    assert "64 lower-case hex" in capsys.readouterr().err


# ── 3. every file is read once ───────────────────────────────────────────────────────────────────────

@pytest.fixture
def reads(monkeypatch):
    """Counts every read of a file by resolved path, through both readers a script would use."""
    counted: dict[str, int] = {}
    real_bytes, real_text = pathlib.Path.read_bytes, pathlib.Path.read_text

    def read_bytes(self):
        key = str(self.resolve())
        counted[key] = counted.get(key, 0) + 1
        return real_bytes(self)

    def read_text(self, *a, **k):
        key = str(self.resolve())
        counted[key] = counted.get(key, 0) + 1
        return real_text(self, *a, **k)
    monkeypatch.setattr(pathlib.Path, "read_bytes", read_bytes)
    monkeypatch.setattr(pathlib.Path, "read_text", read_text)
    return counted


@pytest.mark.parametrize("phase", ["before", "after"])
def test_each_file_of_the_package_is_read_once(tmp_path, capsys, reads, phase):
    pkg = _package(tmp_path)
    sig = _sign(pkg)
    reviewed = hashlib.sha256(open(pkg / vsp.DEFAULT_MANIFEST, "rb").read()).hexdigest()
    reads.clear()
    if phase == "before":
        assert vsp.before(pkg, anchor_pubkey=PUB_B64, expected_head=HEAD) == 0
    else:
        assert vsp.after(pkg, "art", sig, anchor_pubkey=PUB_B64, reviewed_manifest_sha256=reviewed) == 0
    for name in (vsp.DEFAULT_MANIFEST, "art.body.json", "art.payload.bin"):
        assert reads.get(str((pkg / name).resolve())) == 1, (phase, name, reads)


def test_a_body_swapped_after_its_first_read_is_never_seen(tmp_path, capsys, monkeypatch):
    """The race a second read opens, executed: the body reads as checked once and as another text from
    then on. At 49869b53 the derivation read it a second time and refused the package, and a swap at the
    third read put the swapped version into the preview. Read once, the swapped text is never seen, and
    any later read of the body for the preview fails this case (the reading of round two measured a
    mutant that passed a version of this case which swapped only at the third read)."""
    pkg = _package(tmp_path)
    sig = _sign(pkg)
    reviewed = _reviewed(pkg)
    body_path = str((pkg / "art.body.json").resolve())
    swapped = json.dumps(dict(json.loads((pkg / "art.body.json").read_text()), version="6.6.6"))
    seen = {"n": 0}
    real_bytes, real_text = pathlib.Path.read_bytes, pathlib.Path.read_text

    def read_bytes(self):
        if str(self.resolve()) == body_path:
            seen["n"] += 1
            if seen["n"] > 1:
                return swapped.encode("utf-8")
        return real_bytes(self)

    def read_text(self, *a, **k):
        if str(self.resolve()) == body_path:
            seen["n"] += 1
            if seen["n"] > 1:
                return swapped
        return real_text(self, *a, **k)
    monkeypatch.setattr(pathlib.Path, "read_bytes", read_bytes)
    monkeypatch.setattr(pathlib.Path, "read_text", read_text)
    assert vsp.after(pkg, "art", sig, anchor_pubkey=PUB_B64, reviewed_manifest_sha256=reviewed) == 0
    monkeypatch.undo()
    assert json.loads((pkg / "art.signed.json").read_text())["version"] == "1.2.3"


def test_two_entries_that_name_the_same_file_read_it_once(tmp_path, capsys, reads):
    """The reading of round two: two artefact entries with the same body and payload read each file twice
    in `before`. The bytes are kept by resolved path now, so both entries judge the same bytes."""
    pkg = _package(tmp_path)
    _set_manifest(pkg, lambda m: m["artifacts"].append(dict(m["artifacts"][0], name="art2")))
    reads.clear()
    assert vsp.before(pkg, anchor_pubkey=PUB_B64, expected_head=HEAD) == 0
    for name in ("art.body.json", "art.payload.bin"):
        assert reads.get(str((pkg / name).resolve())) == 1, (name, reads)


@pytest.mark.parametrize("key,value", [("anchor", "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="),
                                       ("candidate", ["a" * 40]), ("candidate", "a" * 40)])
def test_a_manifest_member_of_the_wrong_shape_stops_the_run(tmp_path, key, value):
    """The neighbour in the class this round closes: a member of the wrong shape raised AttributeError."""
    pkg = _package(tmp_path)
    _set_manifest(pkg, lambda m: m.__setitem__(key, value))
    for run in (lambda: vsp.before(pkg, anchor_pubkey=PUB_B64),
                lambda: vsp.after(pkg, "art", _sign(pkg), anchor_pubkey=PUB_B64)):
        with pytest.raises(SystemExit) as ctx:
            run()
        assert f"`{key}`" in str(ctx.value) and "not as an object" in str(ctx.value), (key, value)


@pytest.mark.parametrize("field", ["body_sha256", "payload_sha256"])
def test_a_digest_the_manifest_does_not_give_is_a_finding_in_both_phases(tmp_path, capsys, field):
    """A digest that is not there is not a match. The reading of round two left a mutant alive that skipped
    the comparison when the manifest gave no digest."""
    pkg = _package(tmp_path)
    sig = _sign(pkg)
    _set_manifest(pkg, lambda m: m["artifacts"][0].pop(field))
    assert vsp.before(pkg, anchor_pubkey=PUB_B64, expected_head=HEAD) == 1, field
    assert vsp.after(pkg, "art", sig, anchor_pubkey=PUB_B64, reviewed_manifest_sha256=_reviewed(pkg)) == 1, field
    assert not (pkg / "art.signed.json").exists(), field


def test_a_body_candidate_of_the_wrong_shape_is_a_finding(tmp_path, capsys):
    pkg = _package(tmp_path)
    body = json.loads((pkg / "art.body.json").read_text())
    body["candidate"] = HEAD
    (pkg / "art.body.json").write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    payload = _canon(body)
    (pkg / "art.payload.bin").write_bytes(payload)
    _set_manifest(pkg, lambda m: m["artifacts"][0].update(
        body_sha256=_digest(pkg / "art.body.json"), payload_sha256=hashlib.sha256(payload).hexdigest()))
    rc = vsp.before(pkg, anchor_pubkey=PUB_B64, expected_head=HEAD)
    out = capsys.readouterr().out
    assert rc == 1
    assert "candidate is a str in the body" in out


def test_a_missing_payload_after_signing_is_a_finding_not_a_traceback(tmp_path, capsys):
    """The neighbour in `after`: the payload was read before any check, so a missing one raised."""
    pkg = _package(tmp_path)
    sig = _sign(pkg)
    (pkg / "art.payload.bin").unlink()
    rc = vsp.after(pkg, "art", sig, anchor_pubkey=PUB_B64, reviewed_manifest_sha256=_reviewed(pkg))
    out = capsys.readouterr().out
    assert rc == 1
    assert "payload" in out and "MISSING" in out
    assert not (pkg / "art.signed.json").exists()


def test_the_signature_file_is_read_as_given(tmp_path, capsys):
    """Counter-direction for the binding: a good package with its digest still verifies and assembles."""
    pkg = _package(tmp_path)
    sig = pkg / "art.sig.b64"
    sig.write_text(base64.b64encode(SK.sign((pkg / "art.payload.bin").read_bytes())).decode("ascii"),
                   encoding="utf-8")
    assert vsp.after(pkg, "art", sig, anchor_pubkey=PUB_B64, reviewed_manifest_sha256=_reviewed(pkg)) == 0
    assert "VERIFIES over exactly these bytes" in capsys.readouterr().out
    assert (pkg / "art.signed.json").is_file()
