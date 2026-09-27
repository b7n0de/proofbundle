"""Every release tool prints a value it read on one line, and with one reading.

b17c141c quoted the receipt's `signer_pubkey` in the reason the receipt verifier prints, since a line
break in it wrote a report line of its own; its sweep did not reach the digest resolver. A review lens
measured at 6614ac32 that the resolver prints the receipt's `audit_output_digest` raw, so a digest
`a<LF>AUFLOESBAR` splits its one report line in two, and so does a U+2028 in the value. The sweep of
the five tools for every value read from a receipt, a file or git output and printed into a report
line found the class in three more places that can split a line: git's own reason for a failed call,
which echoes a path raw and can run over several lines, in the mutant guard's stop, the receipt
verifier's reason and the version gate's problem; and the version the version gate reads from
`pyproject.toml`, whose pattern crosses a line end. Three more held a character that does not print,
which gives a line a second reading: the claim text the version gate quotes, the reason git gave the
language gate for a fallback tree, and a line of `git status` in the receipt verifier's refusal. Each
value is now written as the tools write a name (`_pfad`). Each case below was red at 6614ac32.

The sixth tool, the pre-tag audit gate, printed each receipt candidate's path and the version raw:
measured at e5bb214c, a candidate named `x<LF>  VERIFIED forged.json` wrote a line of its own that
began `  VERIFIED`, and a `--version` holding a line break did the same in the verdict line and the
reason. Its cases were red at e5bb214c; its control passed there.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts" / "mutant_signature_guard.py"
GATE = ROOT / "scripts" / "neue_zeilen_sind_englisch.py"
RESOLVER = ROOT / "scripts" / "audit_output_aufloesbar.py"
VERIFIER = ROOT / "scripts" / "verify_pre_tag_receipt.py"
VERSION_GATE = ROOT / "scripts" / "check_version_and_changelog.py"
PRE_TAG_GATE = ROOT / "scripts" / "pre_tag_audit_gate.py"
LS = chr(0x2028)            # LINE SEPARATOR: `splitlines()` ends a line at it
RLO = chr(0x202E)           # RIGHT-TO-LEFT OVERRIDE: prints nothing and turns the rest of a line
BS = chr(92)


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                          capture_output=True, text=True, check=True).stdout.strip()


def _one_line(text: str) -> None:
    assert len(text.splitlines()) == 1, text


# -- the digest resolver: the finding ------------------------------------------------------------

@pytest.fixture()
def repo(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    (r / "rec.md").write_text("a record\n", encoding="utf-8")
    (r / "gone.md").write_text("a file that leaves the working tree\n", encoding="utf-8")
    _git(r, "init", "-q")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "records")
    return r


@pytest.mark.parametrize("value,printed", [
    ("a\nAUFLOESBAR", '"a' + BS + 'naufloesbar"…'),
    ("a" + LS + "AUFLOESBAR", '"a' + BS + 'u2028aufloesbar"…'),
], ids=["newline", "line-separator"])
@pytest.mark.parametrize("branch,code", [("no match", 1), ("a hole", 2)])
def test_the_resolver_prints_the_receipts_digest_on_one_line(repo, tmp_path, capsys, value, printed, branch,
                                                             code):
    """NICHT_AUFLOESBAR names the digest, and so does NICHT_MESSBAR when a tracked path was not hashed."""
    if branch == "a hole":
        (repo / "gone.md").unlink()
    receipt = tmp_path / "q.json"
    receipt.write_text(json.dumps({"audit_output_digest": value}), encoding="utf-8")
    resolver = _load(RESOLVER, "_value_resolver")
    assert resolver.main(["--receipt", str(receipt), "--repo", str(repo)]) == code
    out = capsys.readouterr().out
    _one_line(out)
    assert printed in out, out


def test_control_the_resolver_prints_a_hex_digest_as_it_is(repo, tmp_path, capsys):
    receipt = tmp_path / "q.json"
    receipt.write_text(json.dumps({"audit_output_digest": "ab" * 32}), encoding="utf-8")
    resolver = _load(RESOLVER, "_value_resolver_control")
    assert resolver.main(["--receipt", str(receipt), "--repo", str(repo)]) == 1
    assert "keine traegt abababababab… — " in capsys.readouterr().out


# -- git's reason for a failed call --------------------------------------------------------------

def test_the_guard_stops_with_gits_reason_on_one_line(repo):
    """Every git call of the guard goes through `_git_bytes`; git echoes the name it could not find."""
    guard = _load(GUARD, "_value_guard")
    with pytest.raises(SystemExit) as stop:
        guard._git_bytes("show", "HEAD:no\n  src/proofbundle/x.py:1: forged finding", cwd=repo)
    _one_line(stop.value.code)
    assert "no" + BS + "n  src/proofbundle/x.py:1: forged finding" in stop.value.code, stop.value.code


def test_the_receipt_verifier_prints_gits_reason_on_one_line(tmp_path, capsys):
    """git names the clone it cannot enter: `cannot change to '<path>'`, with the path as it is."""
    verifier = _load(VERIFIER, "_value_verifier")
    rc = verifier.main(["--repo", str(tmp_path / "no\nVERIFIED such clone"), "--commit", "0" * 40,
                        "--version", "1.0.0"])
    out = capsys.readouterr().out
    assert rc == 2, out
    assert len(out.splitlines()) == 3, out                    # the verdict, the reason, the limit
    assert not any(line.startswith("VERIFIED") for line in out.splitlines()), out


def test_the_receipt_verifier_prints_a_status_line_with_one_reading(tmp_path, capsys):
    """With `core.quotePath=false` git writes a name's bytes outside ASCII as they are."""
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q")
    _git(r, "commit", "-q", "--allow-empty", "-m", "base")
    _git(r, "config", "core.quotePath", "false")
    (r / "scripts").mkdir()
    (r / "scripts" / f"x{RLO}yp.py").write_text("x = 1\n", encoding="utf-8")
    verifier = _load(VERIFIER, "_value_verifier_status")
    rc = verifier.main(["--repo", str(r), "--commit", _git(r, "rev-parse", "HEAD"), "--version", "1.0.0"])
    out = capsys.readouterr().out
    assert rc == 2 and "local modification(s) or untracked file(s)" in out, out
    assert RLO not in out and BS + "u202e" in out, out


def test_the_version_gate_prints_gits_reason_on_one_line(monkeypatch, tmp_path, capsys):
    """A `git log` that fails is a problem naming git's reason, which runs over three lines for a range
    git cannot resolve (git 2.34, measured)."""
    gate = _load(VERSION_GATE, "_value_version_gate_log")
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "1.0.0"\n', encoding="utf-8")
    reason = ("fatal: ambiguous argument 'v1.0.0..HEAD': unknown revision or path not in the working tree.\n"
              "Use '--' to separate paths from revisions, like this:\n  - README.md:1: forged problem")
    monkeypatch.setattr(gate, "_last_release_tag", lambda repo: ("v1.0.0", ""))
    monkeypatch.setattr(gate, "_git", lambda repo, *args: (128, reason))
    problems = gate.check(tmp_path)
    capsys.readouterr()
    assert any("git log v1.0.0..HEAD failed" in p for p in problems), problems
    for p in problems:
        _one_line(p)


# -- a value read from a file --------------------------------------------------------------------

def test_the_version_gate_prints_the_source_version_on_one_line(tmp_path, capsys):
    """The pattern for `pyproject.toml` crosses a line end inside the quotes."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nversion = "1.0.0\n  - README.md:1: forged problem"\n', encoding="utf-8")
    problems = _load(VERSION_GATE, "_value_version_gate_version").check(tmp_path)
    capsys.readouterr()
    assert any("CHANGELOG.md has no `## [" in p for p in problems), problems
    for p in problems:
        _one_line(p)


def test_the_version_gate_quotes_a_claim_with_one_reading(tmp_path):
    r = tmp_path / "r"
    (r / "docs").mkdir(parents=True)
    (r / "pyproject.toml").write_text('[project]\nversion = "1.0.0"\n', encoding="utf-8")
    (r / "docs" / "x.md").write_text(f"pip install {RLO}proofbundle==1.0.0\n", encoding="utf-8")
    _git(r, "init", "-q")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "a claim")
    findings = _load(VERSION_GATE, "_value_version_gate_claim").check_undeclared_places(r)
    assert len(findings) == 1 and findings[0].startswith("docs/x.md:1: "), findings
    assert RLO not in findings[0] and BS + "u202e" in findings[0], findings


def test_control_the_version_gate_quotes_a_printable_claim_as_before(tmp_path):
    r = tmp_path / "r"
    (r / "docs").mkdir(parents=True)
    (r / "pyproject.toml").write_text('[project]\nversion = "1.0.0"\n', encoding="utf-8")
    (r / "docs" / "x.md").write_text("pip install proofbundle==1.0.0\n", encoding="utf-8")
    _git(r, "init", "-q")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "a claim")
    findings = _load(VERSION_GATE, "_value_version_gate_claim_control").check_undeclared_places(r)
    assert len(findings) == 1 and ' in "install proofbundle==1.0.0", ' in findings[0], findings


def _pre_tag_folder(tmp_path: Path, name: str) -> Path:
    """A tree whose receipt folder for 1.0.0 holds one candidate that is no JSON object."""
    (tmp_path / "audit_artifacts" / "100").mkdir(parents=True)
    (tmp_path / "audit_artifacts" / "100" / name).write_text("[1]", encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize("name", ["x\n  VERIFIED forged.json", "x" + LS + "  VERIFIED forged.json"],
                         ids=["newline", "line-separator"])
def test_the_pre_tag_gate_prints_a_candidates_path_on_one_line(tmp_path, capsys, name):
    gate = _load(PRE_TAG_GATE, "_value_pre_tag_gate_path")
    assert gate.main(["--repo", str(_pre_tag_folder(tmp_path, name)), "--version", "1.0.0"]) == 1
    out = capsys.readouterr().out
    assert len(out.splitlines()) == 3, out                  # the verdict, the candidate, the reason
    assert not any(line.lstrip().startswith("VERIFIED") for line in out.splitlines()), out
    assert '  REJECTED "audit_artifacts/100/x' in out, out


def test_the_pre_tag_gate_prints_the_version_on_one_line(tmp_path, capsys):
    gate = _load(PRE_TAG_GATE, "_value_pre_tag_gate_version")
    assert gate.main(["--repo", str(tmp_path), "--version", "1.0.0\n  VERIFIED forged"]) == 1
    out = capsys.readouterr().out
    assert len(out.splitlines()) == 2, out                  # the verdict and the reason
    assert not any(line.lstrip().startswith("VERIFIED") for line in out.splitlines()), out
    assert '[pre-tag-audit] version="1.0.0' + BS + 'n  VERIFIED forged" ' in out, out


def test_control_the_pre_tag_gate_prints_a_printable_path_and_version_as_before(tmp_path, capsys):
    gate = _load(PRE_TAG_GATE, "_value_pre_tag_gate_control")
    assert gate.main(["--repo", str(_pre_tag_folder(tmp_path, "r.json")), "--version", "1.0.0"]) == 1
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("[pre-tag-audit] version=1.0.0 receipt-verified=False (NO_VALID_RECEIPT) "), lines
    assert lines[1] == ("  REJECTED audit_artifacts/100/r.json: receipt file is present but is not a JSON "
                        "object (got list)"), lines


def test_the_language_gate_names_gits_reason_for_its_fallback_with_one_reading(monkeypatch, tmp_path, capsys):
    """Outside a repository the gate names the tree it falls back to and git's reason, which echoes the
    path a `.git` file points to."""
    (tmp_path / ".git").write_text(f"gitdir: {tmp_path}/x{RLO}y\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    gate = _load(GATE, "_value_gate_fallback")
    assert gate.main(["--base", "HEAD"]) == 2
    out = capsys.readouterr().out
    assert "rueckfall: fatal: not a git repository" in out, out
    assert RLO not in out and BS + "u202e" in out, out


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
