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
        fd = os.open(os.fsencode(repo) + b"/docs/\xff.md", os.O_WRONLY | os.O_CREAT, 0o600)
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
        fd = os.open(os.fsencode(repo) + b"/" + raw_rel, os.O_WRONLY | os.O_CREAT, 0o600)
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
    """The same for the receipt verifier: the rejection is reported, the name escaped.

    The verifier judges only the checkout it runs from, so it runs from the built repository, which
    carries its scripts and the package, the way tests/test_verify_pre_tag_receipt_third_party.py
    builds one."""
    repo = _repo(tmp_path, {"audit_artifacts/999/.keep": "", ".gitignore": "__pycache__/\n"})
    name = _write_bytes_name(repo, b"audit_artifacts/999/\xff.json", b"not json")
    (repo / "scripts").mkdir()
    for script in ("pre_tag_receipt.py", "pre_tag_audit_gate.py", "pre_tag_receipt_lib.py",
                   "sign_readiness_artifact.py", "verify_pre_tag_receipt.py"):
        shutil.copy(REPO / "scripts" / script, repo / "scripts" / script)
    shutil.copytree(REPO / "src" / "proofbundle", repo / "src" / "proofbundle",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "a receipt whose name is not UTF-8")
    commit = _git(repo, "rev-parse", "HEAD").strip()
    env = dict(os.environ, PYTHONPATH=f"{repo}/src:{repo}/scripts")
    p = subprocess.run([sys.executable, "-B", "scripts/verify_pre_tag_receipt.py", "--repo", ".",
                        "--commit", commit, "--version", "9.9.9", *form], capture_output=True,
                       cwd=str(repo), env=env)
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


# -- the counter-reading of pull request 375 at b493f939: F5, F7, F8 and F11 ---------------------

#: A name with a letter outside ASCII and one outside Latin-1, so that both output encodings below
#: meet a character they cannot write.
WIDE = "prüfung\U0001f600"


@pytest.mark.parametrize("encoding", ["ascii", "latin-1"])
def test_F5_the_json_form_of_the_resolver_stays_json_under_any_output_encoding(tmp_path, encoding):
    """F5 (P3): `errors="backslashreplace"` wrote `\\xfc` for `ü` and `\\U0001f600` for an emoji into the
    JSON form when stdout was not UTF-8. Neither is a JSON escape, so the output was no JSON, with
    exit 0. The JSON form writes every character outside ASCII as its JSON escape now."""
    ao = _load("scripts/audit_output_aufloesbar.py", "_gp_resolvable_f5")
    rel = f"audit_artifacts/{WIDE}.md"
    repo = _repo(tmp_path, {"README.md": "# r\n", rel: "the record\n"})
    receipt = tmp_path / "receipt.json"
    receipt.write_text(json.dumps({"audit_output_digest": ao.sha256_text("the record\n")}),
                       encoding="utf-8")
    p = subprocess.run([sys.executable, "-B", str(REPO / "scripts" / "audit_output_aufloesbar.py"),
                        "--receipt", str(receipt), "--repo", str(repo), "--json"],
                       capture_output=True, cwd=str(repo), env=dict(os.environ, PYTHONIOENCODING=encoding))
    assert p.returncode == 0, p.stdout + p.stderr
    assert json.loads(p.stdout.decode(encoding))["treffer"] == [rel], p.stdout


@pytest.mark.parametrize("encoding", ["ascii", "latin-1"])
def test_F5_the_json_form_of_the_language_gate_stays_json_under_any_output_encoding(tmp_path, encoding):
    """F5 for the language gate: its finding names the file, and the name went into the JSON form
    with a backslash escape that JSON does not know."""
    repo = _repo(tmp_path, {"m.py": "x = 1\n"})
    base = _git(repo, "rev-parse", "HEAD").strip()
    (repo / "docs").mkdir()
    (repo / "docs" / f"{WIDE}.md").write_text("Diese Zeile ist deutsch und die Pruefung muss sie sehen.\n",
                                              encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "a German line under a wide name")
    p = subprocess.run([sys.executable, "-B", str(REPO / "scripts" / "neue_zeilen_sind_englisch.py"),
                        "--base", base, "--repo", str(repo), "--json"], capture_output=True,
                       cwd=str(repo), env=dict(os.environ, PYTHONIOENCODING=encoding))
    assert p.returncode == 1, p.stdout + p.stderr
    assert json.loads(p.stdout.decode(encoding))["befunde"][0]["datei"] == f"docs/{WIDE}.md", p.stdout


@pytest.mark.parametrize("encoding", ["ascii", "latin-1"])
def test_F5_the_json_form_of_the_verifier_stays_json_under_any_output_encoding(tmp_path, encoding):
    """F5 for the receipt verifier, built as in `test_the_verifier_reports_a_name_that_is_not_utf8`."""
    repo = _repo(tmp_path, {f"audit_artifacts/999/{WIDE}.json": "not json",
                            ".gitignore": "__pycache__/\n"})
    (repo / "scripts").mkdir()
    for script in ("pre_tag_receipt.py", "pre_tag_audit_gate.py", "pre_tag_receipt_lib.py",
                   "sign_readiness_artifact.py", "verify_pre_tag_receipt.py"):
        shutil.copy(REPO / "scripts" / script, repo / "scripts" / script)
    shutil.copytree(REPO / "src" / "proofbundle", repo / "src" / "proofbundle",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "a receipt under a wide name")
    commit = _git(repo, "rev-parse", "HEAD").strip()
    env = dict(os.environ, PYTHONPATH=f"{repo}/src:{repo}/scripts", PYTHONIOENCODING=encoding)
    p = subprocess.run([sys.executable, "-B", "scripts/verify_pre_tag_receipt.py", "--repo", ".",
                        "--commit", commit, "--version", "9.9.9", "--json"], capture_output=True,
                       cwd=str(repo), env=env)
    assert p.returncode == 1, p.stdout + p.stderr
    rejected = json.loads(p.stdout.decode(encoding))["rejected"]
    assert [r["path"] for r in rejected] == [f"audit_artifacts/999/{WIDE}.json"], p.stdout


def test_F7_the_readiness_tree_digest_does_not_follow_core_quotepath(tmp_path, monkeypatch):
    """F7 (P3): the sweep lets `sign_readiness_artifact.tree_digest` read the quoted form because it is
    "the same digest as pre_tag_receipt_lib.subject_tree_digest". That one pins `core.quotePath=true`,
    this one did not, and under `core.quotePath=false` it hashed another text for the same tree
    (87bbdcd3 against ddd9bad7 in the report). It pins the setting now."""
    sra = _load("scripts/sign_readiness_artifact.py", "_gp_sra_f7")
    repo = _repo(tmp_path, {f"docs/{QUOTED}.md": "x\n", "README.md": "# r\n"})
    default = sra.tree_digest(repo)
    cfg = tmp_path / "quotepath-false"
    cfg.write_text("[core]\n\tquotePath = false\n", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))
    assert _git(repo, "ls-tree", "-r", "HEAD").count('"') == 0, "the setting must reach git here"
    assert sra.tree_digest(repo) == default
    lib = _load("scripts/pre_tag_receipt_lib.py", "_gp_lib_f7")
    assert lib.subject_tree_digest(repo) == default, "the reason of the sweep names this digest"


@pytest.mark.parametrize("edge", ["{} ", " {}"], ids=["trailing", "leading"])
def test_F8_a_name_with_a_space_at_its_edge_is_no_evidence_path(tmp_path, edge):
    """F8 (P3): the matrix read `diff --name-only` line by line with `strip()`, so a later commit that
    added `audit_artifacts/360/fuzz_soak_latest.json ` (git does not quote a space) counted as a commit
    of the evidence file itself. The tree digest after it still refused, so this was a second bar
    that held, not a pass; the list is read with -z now and no name is trimmed."""
    sys.path.insert(0, str(REPO / "scripts"))
    try:
        acm = _load("scripts/audit_candidate_matrix.py", "_gp_acm_f8")
        evidence = _load("scripts/sign_readiness_artifact.py", "sign_readiness_artifact").MUTABLE_EVIDENCE_RELS[0]
    finally:
        sys.path.remove(str(REPO / "scripts"))
    repo = _repo(tmp_path, {"README.md": "# r\n"})
    bound = _git(repo, "rev-parse", "HEAD").strip()
    lookalike = repo / edge.format(evidence)
    lookalike.parent.mkdir(parents=True, exist_ok=True)
    lookalike.write_text("{}\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "a lookalike of the evidence file")
    live = _git(repo, "rev-parse", "HEAD").strip()
    allowed, reason = acm._evidenz_relation_erlaubt(repo, bound, live)
    assert allowed is False, reason


def test_F11_the_mutation_gate_lists_a_name_that_is_not_utf8(tmp_path):
    """F11 (P3): `mutation_check._tracked_files` read `ls-files -z` with a strict text decoder and
    raised on a name that is not UTF-8, and `_dateien_des_baums` decoded with `errors="replace"`, so
    such a name opened no file and fell out of the list that feeds the test selection. Both decode
    the way Python decodes a file name now."""
    mc = _load("scripts/mutation_check.py", "_gp_mc_f11")
    repo = _repo(tmp_path, {"README.md": "# r\n"})
    name = _write_bytes_name(repo, b"t\xff.py", b"x = 1\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "a name that is not UTF-8")
    assert name in mc._tracked_files(repo)
    assert name in mc._dateien_des_baums(repo)


def test_F11_the_release_renderer_reads_a_change_under_a_name_that_is_not_utf8(tmp_path):
    """F11 for `render_release.liefert_dasselbe_paket`: `diff --name-only -z` through a strict text
    decoder raised `UnicodeDecodeError`, which `except (OSError, SubprocessError)` does not catch. The
    path is named in the refusal now, and a name under `release_notes/` still ships the same package."""
    rr = _load("scripts/render_release.py", "_gp_rr_f11")
    repo = _repo(tmp_path, {"README.md": "# r\n", "release_notes/keep.md": "x\n"})
    described = _git(repo, "rev-parse", "HEAD").strip()
    _write_bytes_name(repo, b"release_notes/\xff.md", b"notes\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "notes under a name that is not UTF-8")
    assert rr.liefert_dasselbe_paket(repo, described, _git(repo, "rev-parse", "HEAD").strip()) is None
    name = _write_bytes_name(repo, b"src\xff.py", b"x = 1\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "a shipped change under a name that is not UTF-8")
    reason = rr.liefert_dasselbe_paket(repo, described, _git(repo, "rev-parse", "HEAD").strip())
    assert reason is not None and name in reason, reason
