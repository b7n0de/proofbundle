"""A path git lists is read as git names it, not in its quoted display form.

Without -z git quotes a path that holds a byte outside ASCII, a double quote, a backslash or a control
character: `"docs/pr\\303\\274fung.md"`. Read as a name, that string opens no file. Measured on
2026-09-26 in throwaway repositories, one case per reader, each against the state before the fix:

- the release-integrity gate's sweep for undeclared current-version claims (Check 6) reported the
  claim in `docs/a.md` and not the same claim in `docs/prüfung.md`;
- the check whether a signed audit-output digest resolves said NICHT_AUFLOESBAR for a tracked record
  under such a name, and did not count it among the files it hashed;
- the third-party receipt verifier did not see a receipt under such a name at all, because the quoted
  line ends in `.json"`.

The readers now take the list with -z, as bytes, and decode each name the way Python decodes a file
name. The bytes matter as well: through a text decoder, one name that is not UTF-8 emptied the whole
list, which the quoted form had prevented because it is ASCII.

Each case pins git's own defaults (no global or system configuration), because `core.quotePath=false`
in a developer's configuration would hide the quoting these cases are about.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
QUOTED = "prüfung"


def _load(rel: str, name: str):
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _git_defaults(tmp_path, monkeypatch):
    """git as it ships: no global or system configuration can switch the quoting off."""
    empty = tmp_path / "empty-gitconfig"
    empty.write_text("", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(empty))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_AUTHOR_NAME", "t")
    monkeypatch.setenv("GIT_AUTHOR_EMAIL", "t@t")
    monkeypatch.setenv("GIT_COMMITTER_NAME", "t")
    monkeypatch.setenv("GIT_COMMITTER_EMAIL", "t@t")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          check=True).stdout


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q")
    for rel, text in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    return repo


def test_git_quotes_the_names_these_cases_use(tmp_path):
    """The premise, measured: without -z the name comes back quoted. If git stopped quoting, the
    cases below would pass against the old readers too and prove nothing."""
    repo = _repo(tmp_path, {f"docs/{QUOTED}.md": "x\n"})
    assert _git(repo, "ls-files").strip() == '"docs/pr\\303\\274fung.md"'


def test_the_version_gate_sweeps_a_file_whose_name_git_quotes(tmp_path):
    cv = _load("scripts/check_version_and_changelog.py", "_gp_version_gate")
    repo = _repo(tmp_path, {"docs/a.md": "current release: 9.9.9\n",
                            f"docs/{QUOTED}.md": "current release: 9.9.9\n"})
    found = sorted(p.split(":")[0] for p in cv.check_undeclared_places(repo, "9.9.9"))
    assert found == ["docs/a.md", f"docs/{QUOTED}.md"], found


def test_a_name_that_is_not_utf8_does_not_empty_the_sweep(tmp_path):
    """Through a text decoder this name raised, and the gate's git helper turned that into an empty
    list: the sweep read no file at all and stayed green."""
    cv = _load("scripts/check_version_and_changelog.py", "_gp_version_gate_bytes")
    repo = _repo(tmp_path, {"docs/a.md": "current release: 9.9.9\n",
                            f"docs/{QUOTED}.md": "current release: 9.9.9\n"})
    try:
        fd = os.open(os.fsencode(repo) + b"/docs/\xff.md", os.O_WRONLY | os.O_CREAT, 0o644)
    except OSError as exc:
        pytest.skip(f"this file system refuses a name that is not UTF-8: {exc}")
    os.write(fd, b"x\n")
    os.close(fd)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "a name that is not UTF-8")
    found = sorted(p.split(":")[0] for p in cv.check_undeclared_places(repo, "9.9.9"))
    assert found == ["docs/a.md", f"docs/{QUOTED}.md"], found


def test_a_record_under_a_quoted_name_resolves_and_is_counted(tmp_path):
    ao = _load("scripts/audit_output_aufloesbar.py", "_gp_resolvable")
    repo = _repo(tmp_path, {f"audit_artifacts/{QUOTED}.md": "the record\n", "README.md": "# r\n"})
    digest = ao.sha256_text((repo / "audit_artifacts" / f"{QUOTED}.md").read_text(encoding="utf-8"))
    result = ao.aufloesbar({"audit_output_digest": digest}, repo)
    assert result["zustand"] == "AUFLOESBAR", result
    assert result["treffer"] == [f"audit_artifacts/{QUOTED}.md"], result
    assert result["geprueft"] == 2, result


def _write_bytes_name(repo: Path, raw_rel: bytes, content: bytes) -> str:
    """Write a file whose name is raw bytes (not UTF-8) and return the name as Python decodes it."""
    try:
        fd = os.open(os.fsencode(repo) + b"/" + raw_rel, os.O_WRONLY | os.O_CREAT, 0o644)
    except OSError as exc:
        pytest.skip(f"this file system refuses a name that is not UTF-8: {exc}")
    os.write(fd, content)
    os.close(fd)
    return os.fsdecode(raw_rel)


def test_a_record_under_a_name_that_is_not_utf8_resolves(tmp_path):
    """Decoded with `replace` instead of os.fsdecode, the name opened no file and the record was not
    counted (a lens measured that mutation passing every other case here, 2026-09-26)."""
    ao = _load("scripts/audit_output_aufloesbar.py", "_gp_resolvable_bytes")
    repo = _repo(tmp_path, {"README.md": "# r\n", "audit_artifacts/keep.md": "x\n"})
    name = _write_bytes_name(repo, b"audit_artifacts/\xff.md", b"the record\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "a record whose name is not UTF-8")
    result = ao.aufloesbar({"audit_output_digest": ao.sha256_text("the record\n")}, repo)
    assert result["zustand"] == "AUFLOESBAR", result
    assert result["treffer"] == [name], result
    assert result["geprueft"] == 3, result


def test_the_verifier_reads_a_receipt_named_in_bytes_that_are_not_utf8(tmp_path):
    """Decoded with `replace`, the name sent to `git show` was not the name in the tree, and the
    receipt was reported unreadable from the commit instead of being read."""
    vp = _load("scripts/verify_pre_tag_receipt.py", "_gp_verifier_bytes")
    repo = _repo(tmp_path, {"audit_artifacts/999/.keep": ""})
    name = _write_bytes_name(repo, b"audit_artifacts/999/\xff.json", b"not json")
    (repo / "scripts").mkdir()
    shutil.copy(REPO / "scripts" / "pre_tag_audit_gate.py", repo / "scripts" / "pre_tag_audit_gate.py")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "a receipt whose name is not UTF-8")
    commit = _git(repo, "rev-parse", "HEAD").strip()
    result = vp.measure(repo, commit, "9.9.9")
    assert [r["path"] for r in result["rejected"]] == [name], result
    assert "not readable JSON" in result["rejected"][0]["reason"], result


def _cli(script: str, *args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-B", str(REPO / script), *args], capture_output=True,
                          cwd=str(cwd))


@pytest.mark.parametrize("form", [["--json"], []], ids=["json", "text"])
def test_the_resolver_reports_a_name_that_is_not_utf8(tmp_path, form):
    """Read as git names it, the name carries a surrogate, and a strict stdout raised on it with
    exit 1, the exit code of a finding (measured 2026-09-26). The name is written escaped now."""
    ao = _load("scripts/audit_output_aufloesbar.py", "_gp_resolvable_cli")
    repo = _repo(tmp_path, {"README.md": "# r\n", "audit_artifacts/keep.md": "x\n"})
    name = _write_bytes_name(repo, b"audit_artifacts/\xff.md", b"the record\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "a record whose name is not UTF-8")
    receipt = tmp_path / "receipt.json"
    receipt.write_text(json.dumps({"audit_output_digest": ao.sha256_text("the record\n")}),
                       encoding="utf-8")
    p = _cli("scripts/audit_output_aufloesbar.py", "--receipt", str(receipt), "--repo", str(repo),
             *form, cwd=repo)
    assert b"Traceback" not in p.stderr, p.stderr.decode("utf-8", "replace")
    out = p.stdout.decode("utf-8")
    assert p.returncode == 0, out
    if form:
        assert json.loads(out)["treffer"] == [name], out


@pytest.mark.parametrize("form", [["--json"], []], ids=["json", "text"])
def test_the_verifier_reports_a_name_that_is_not_utf8(tmp_path, form):
    """The same for the receipt verifier: the rejection is reported, the name escaped."""
    repo = _repo(tmp_path, {"audit_artifacts/999/.keep": ""})
    name = _write_bytes_name(repo, b"audit_artifacts/999/\xff.json", b"not json")
    (repo / "scripts").mkdir()
    shutil.copy(REPO / "scripts" / "pre_tag_audit_gate.py", repo / "scripts" / "pre_tag_audit_gate.py")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "a receipt whose name is not UTF-8")
    commit = _git(repo, "rev-parse", "HEAD").strip()
    p = _cli("scripts/verify_pre_tag_receipt.py", "--repo", str(repo), "--commit", commit,
             "--version", "9.9.9", *form, cwd=repo)
    assert b"Traceback" not in p.stderr, p.stderr.decode("utf-8", "replace")
    out = p.stdout.decode("utf-8")
    assert p.returncode == 1, out
    if form:
        assert [r["path"] for r in json.loads(out)["rejected"]] == [name], out
    else:
        assert chr(92) + "udcff.json" in out, out


def test_the_verifier_sees_a_receipt_under_a_quoted_name(tmp_path):
    """The receipt is not valid JSON on purpose: the question is whether the verifier sees the file.
    Before the fix the answer was "no receipt under audit_artifacts/999/"."""
    vp = _load("scripts/verify_pre_tag_receipt.py", "_gp_verifier")
    repo = _repo(tmp_path, {f"audit_artifacts/999/{QUOTED}.json": "not json"})
    (repo / "scripts").mkdir()
    shutil.copy(REPO / "scripts" / "pre_tag_audit_gate.py", repo / "scripts" / "pre_tag_audit_gate.py")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "the gate the receipt would bind")
    commit = _git(repo, "rev-parse", "HEAD").strip()
    result = vp.measure(repo, commit, "9.9.9")
    assert result["verdict"] == "NOT_VERIFIED", result
    assert [r["path"] for r in result["rejected"]] == [f"audit_artifacts/999/{QUOTED}.json"], result
