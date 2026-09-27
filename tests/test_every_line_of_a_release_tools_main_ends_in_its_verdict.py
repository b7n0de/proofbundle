"""Every line of a release tool's `main` ends in that tool's own verdict for what it could not judge.

Since b17c141c each of the five release tools holds an exception no branch names to its own verdict,
but only around its judging call; the other lines of `main` stood outside that catch. A review lens
measured at 6614ac32, and on main at 10f3466b: a `--repo` that is a symlink to itself
(`ln -s loop2 loop2`) raised `RuntimeError: Symlink loop` in `Path.resolve()` and ended the resolver,
the version gate, the language gate and the receipt verifier with a traceback and exit 1, the code
of a finding in three of them. The version gate also read the source version a second time in `main`
and caught only `_NichtLesbar` there.

The cases below raise at lines of `main` that stood outside the catch: the symlink loop where a tool
resolves its `--repo` (the mutant guard takes no path, git names its tree), an exception planted at
the first line after the arguments are parsed, the version gate's second read, and a stdout that
refuses the printed verdict. Each tool now ends such a run in its own verdict: exit 2 with the reason
in the guard, the language gate, the resolver and the receipt verifier, and one problem with exit 1
in the version gate. Each case was red at 6614ac32 (measured on Python 3.10).

A sixth tool, the pre-tag audit gate, which release.yml runs before the build, had the same `main`:
measured at e5bb214c, `--repo loop2` ended it with a traceback and exit 1 and no verdict line. It now
ends such a run in its own state for a run that cannot say what it judges, `not_determinable`, with
the reason and exit 1, the code it gives every run without a valid receipt. Its cases below were red
at e5bb214c.
"""
from __future__ import annotations

import contextlib
import errno
import importlib.util
import io
import json
import pathlib
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts" / "mutant_signature_guard.py"
GATE = ROOT / "scripts" / "neue_zeilen_sind_englisch.py"
RESOLVER = ROOT / "scripts" / "audit_output_aufloesbar.py"
VERIFIER = ROOT / "scripts" / "verify_pre_tag_receipt.py"
VERSION_GATE = ROOT / "scripts" / "check_version_and_changelog.py"
PRE_TAG_GATE = ROOT / "scripts" / "pre_tag_audit_gate.py"
COMMIT = "0" * 40
STOPPED = "the run stopped on an unexpected exception at "
#: `Path.resolve()` raises a RuntimeError on a symlink loop before Python 3.13; from 3.13 on it raises
#: nothing in non-strict mode (the pathlib documentation), and the tool meets the loop at its next read
#: of the tree instead. The exit code and the state are the same either way; only the reason differs.
RAISES_ON_A_LOOP = sys.version_info < (3, 13)


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(script: Path, *args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-B", str(script), *args], cwd=str(cwd),
                          capture_output=True, text=True, timeout=300)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                          capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture()
def loop(tmp_path):
    """A directory holding `loop2`, a symlink to itself, and a receipt `rc.json` beside it."""
    (tmp_path / "loop2").symlink_to("loop2")
    (tmp_path / "rc.json").write_text(json.dumps({"audit_output_digest": "a" * 64}), encoding="utf-8")
    return tmp_path


def _no_traceback(r: subprocess.CompletedProcess) -> None:
    assert "Traceback" not in r.stderr, r.stderr


# -- the symlink loop, run as the finding ran it --------------------------------------------------

@pytest.mark.parametrize("form", ["text", "json"])
def test_the_resolver_ends_a_repo_it_cannot_resolve_as_nicht_messbar(loop, form):
    r = _run(RESOLVER, "--receipt", "rc.json", "--repo", "loop2", *(["--json"] if form == "json" else []),
             cwd=loop)
    _no_traceback(r)
    assert r.returncode == 2, r.stdout + r.stderr
    grund = json.loads(r.stdout)["grund"] if form == "json" else r.stdout
    if form == "text":
        assert len(r.stdout.splitlines()) == 1, r.stdout
        assert r.stdout.startswith("audit_output_digest: NICHT_MESSBAR — "), r.stdout
    else:
        assert json.loads(r.stdout)["zustand"] == "NICHT_MESSBAR", r.stdout
    if RAISES_ON_A_LOOP:
        assert STOPPED in grund and "RuntimeError: Symlink loop from" in grund, grund


def test_the_version_gate_ends_a_repo_it_cannot_resolve_as_one_problem(loop):
    r = _run(VERSION_GATE, "--repo", "loop2", cwd=loop)
    _no_traceback(r)
    assert r.returncode == 1, r.stdout + r.stderr
    assert r.stdout.startswith("check_version_and_changelog: FAIL\n"), r.stdout
    if RAISES_ON_A_LOOP:
        problems = [line for line in r.stdout.splitlines() if line.startswith("  - ")]
        assert len(problems) == 1 and STOPPED in problems[0], r.stdout
        assert "RuntimeError: Symlink loop from" in problems[0], r.stdout


@pytest.mark.parametrize("form", ["text", "json"])
def test_the_language_gate_ends_a_repo_it_cannot_resolve_as_not_measurable(loop, form):
    r = _run(GATE, "--repo", "loop2", "--base", "HEAD~1", *(["--json"] if form == "json" else []),
             cwd=loop)
    _no_traceback(r)
    assert r.returncode == 2, r.stdout + r.stderr
    if form == "json":
        d = json.loads(r.stdout)
        assert (d["urteil"], d["rc"]) == ("NOT MEASURABLE", 2), d
        grund = d["grund"]
    else:
        assert r.stdout.startswith("new-lines-english: NOT MEASURABLE · "), r.stdout
        grund = r.stdout
    if RAISES_ON_A_LOOP:
        assert STOPPED in grund and "RuntimeError: Symlink loop from" in grund, grund
        assert "loop2" in (d["gemessener_baum"] if form == "json" else r.stdout.splitlines()[0])


@pytest.mark.parametrize("form", ["text", "json"])
def test_the_receipt_verifier_ends_a_clone_it_cannot_resolve_as_not_measurable(loop, form):
    r = _run(VERIFIER, "--repo", "loop2", "--commit", COMMIT, "--version", "1.0.0",
             *(["--json"] if form == "json" else []), cwd=loop)
    _no_traceback(r)
    assert r.returncode == 2, r.stdout + r.stderr
    if form == "json":
        d = json.loads(r.stdout)
        assert d["verdict"] == "NOT_MEASURABLE", d
        reason = d["reason"]
    else:
        assert r.stdout.startswith("[pre-tag-receipt] verdict=NOT_MEASURABLE "), r.stdout
        reason = r.stdout
    if RAISES_ON_A_LOOP:
        assert STOPPED in reason and "RuntimeError: Symlink loop from" in reason, reason


@pytest.mark.parametrize("form", ["text", "json"])
def test_the_pre_tag_gate_ends_a_repo_it_cannot_resolve_as_not_determinable(loop, form):
    r = _run(PRE_TAG_GATE, "--repo", "loop2", "--version", "1.0.0", *(["--json"] if form == "json" else []),
             cwd=loop)
    _no_traceback(r)
    assert r.returncode == 1, r.stdout + r.stderr
    if form == "json":
        d = json.loads(r.stdout)
        assert (d["ok"], d["state"], d["version"]) == (False, "not_determinable", "1.0.0"), d
        reason = d["reason"]
    else:
        lines = r.stdout.splitlines()
        assert len(lines) == 2 and lines[0].startswith("[pre-tag-audit] version=1.0.0 receipt-verified=False "), lines
        reason = lines[1]
    if RAISES_ON_A_LOOP:
        assert STOPPED in reason and "RuntimeError: Symlink loop from" in reason, reason


# -- an exception planted at the first line after the arguments are parsed -----------------------

class _RefusingSetUp(io.StringIO):
    """A stdout whose set-up raises: the guard's first line after its arguments are parsed."""

    def reconfigure(self, **kwargs):
        raise RuntimeError("planted in the stream set-up")


def test_the_guard_ends_a_planted_exception_after_its_arguments_in_its_stop(monkeypatch):
    guard = _load(GUARD, "_main_guard_planted")
    monkeypatch.setattr(sys, "stdout", _RefusingSetUp())
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        rc = guard.main(["--staged"])
    assert rc == 2, err.getvalue()
    assert err.getvalue().startswith("mutant_signature_guard: " + STOPPED), err.getvalue()
    assert "RuntimeError: planted in the stream set-up, so the change is not judged (fail closed)" \
        in err.getvalue(), err.getvalue()


def test_the_language_gate_ends_a_planted_exception_after_its_arguments_as_not_measurable(
        monkeypatch, capsys, tmp_path):
    gate = _load(GATE, "_main_gate_planted")

    def planted(vorgabe=None):
        raise ValueError("planted where the tree is named")

    monkeypatch.setattr(gate, "_gemessener_baum", planted)
    rc = gate.main(["--repo", str(tmp_path), "--base", "HEAD", "--json"])
    d = json.loads(capsys.readouterr().out)
    assert (rc, d["urteil"], d["rc"], d["befunde"]) == (2, "NOT MEASURABLE", 2, []), d
    assert "ValueError: planted where the tree is named, so the range was not judged" in d["grund"], d
    assert d["gemessener_baum"] == str(tmp_path), d


def test_the_resolver_ends_a_planted_exception_after_its_arguments_as_nicht_messbar(
        monkeypatch, capsys, loop):
    resolver = _load(RESOLVER, "_main_resolver_planted")

    def planted(p, cap):
        raise ValueError("planted where the receipt is read")

    monkeypatch.setattr(resolver, "_bytes_bis", planted)
    rc = resolver.main(["--receipt", str(loop / "rc.json"), "--repo", str(loop)])
    out = capsys.readouterr().out
    assert rc == 2 and len(out.splitlines()) == 1, out
    assert out.startswith("audit_output_digest: NICHT_MESSBAR — " + STOPPED), out
    assert "ValueError: planted where the receipt is read, so nothing was resolved" in out, out


def _planted_resolve(self, strict=False):
    raise ValueError("planted where the path is resolved")


def test_the_receipt_verifier_ends_a_planted_exception_after_its_arguments_as_not_measurable(
        monkeypatch, capsys, tmp_path):
    verifier = _load(VERIFIER, "_main_verifier_planted")
    monkeypatch.setattr(pathlib.Path, "resolve", _planted_resolve)
    rc = verifier.main(["--repo", str(tmp_path), "--commit", COMMIT, "--version", "1.0.0"])
    out = capsys.readouterr().out
    assert rc == 2, out
    assert out.startswith("[pre-tag-receipt] verdict=NOT_MEASURABLE "), out
    assert "ValueError: planted where the path is resolved, so the commit was not judged" in out, out


def test_the_version_gate_ends_a_planted_exception_after_its_arguments_as_one_problem(
        monkeypatch, capsys, tmp_path):
    gate = _load(VERSION_GATE, "_main_version_gate_planted")
    monkeypatch.setattr(sys, "argv", ["check_version_and_changelog.py", "--repo", str(tmp_path)])
    monkeypatch.setattr(pathlib.Path, "resolve", _planted_resolve)
    rc = gate.main()
    lines = capsys.readouterr().out.splitlines()
    assert rc == 1, lines
    assert lines[0] == "check_version_and_changelog: FAIL" and len(lines) == 2, lines
    assert lines[1].startswith("  - " + STOPPED), lines
    assert "ValueError: planted where the path is resolved" in lines[1], lines


def test_the_pre_tag_gate_ends_a_planted_exception_after_its_arguments_as_not_determinable(
        monkeypatch, capsys, tmp_path):
    gate = _load(PRE_TAG_GATE, "_main_pre_tag_gate_planted")

    def planted(repo, version=None):
        raise ValueError("planted where the receipt is judged")

    monkeypatch.setattr(gate, "evaluate", planted)
    rc = gate.main(["--repo", str(tmp_path), "--version", "1.0.0", "--json"])
    d = json.loads(capsys.readouterr().out)
    assert (rc, d["ok"], d["state"]) == (1, False, "not_determinable"), d
    assert d["reason"].startswith(STOPPED), d
    assert "ValueError: planted where the receipt is judged, so no receipt was judged" in d["reason"], d


def test_the_version_gate_reads_the_source_version_again_within_its_verdict(monkeypatch, capsys, tmp_path):
    """`main` reads the source version a second time and caught only `_NichtLesbar` there, so an
    exception `check` had reported as a problem ended the run with a traceback. It stays one problem."""
    gate = _load(VERSION_GATE, "_main_version_gate_second_read")

    def planted(repo):
        raise ValueError("planted in a source read")

    monkeypatch.setattr(gate, "_init_version", planted)
    monkeypatch.setattr(sys, "argv", ["check_version_and_changelog.py", "--repo", str(tmp_path)])
    rc = gate.main()
    lines = capsys.readouterr().out.splitlines()
    assert rc == 1, lines
    assert lines[0] == "check_version_and_changelog: FAIL" and len(lines) == 2, lines
    assert "ValueError: planted in a source read" in lines[1], lines


# -- a stdout that refuses the printed verdict ----------------------------------------------------

class _RefusingWrites(io.StringIO):
    """A stdout that takes its set-up and refuses every write, as a pipe does whose reader has gone."""

    def reconfigure(self, **kwargs):
        return None

    def write(self, s):
        raise OSError(errno.EPIPE, "planted: the reader of stdout has gone")


def _guard_in(repo: Path):
    guard = _load(GUARD, "_main_guard_refused_stdout")
    guard._repo_root = lambda: repo
    return guard.main, ["--staged"]


@pytest.mark.parametrize("tool,code,first", [
    ("guard", 2, "mutant_signature_guard: " + STOPPED),
    ("language gate", 2, "new-lines-english: NOT MEASURABLE · "),
    ("resolver", 2, "audit_output_digest: NICHT_MESSBAR — "),
    ("receipt verifier", 2, "[pre-tag-receipt] verdict=NOT_MEASURABLE "),
    ("version gate", 1, "check_version_and_changelog: FAIL\n"),
    ("pre-tag audit gate", 1, "[pre-tag-audit] state=not_determinable ")])
def test_a_verdict_stdout_refuses_goes_to_stderr_with_the_tools_code(monkeypatch, tmp_path, tool, code,
                                                                     first):
    """The verdict was printed outside the catch in each tool; a write that fails there raised out of
    `main`. The tool's code for what it could not judge stands, and the reason goes to stderr."""
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q")
    (tmp_path / "rc.json").write_text(json.dumps({"audit_output_digest": "a" * 64}), encoding="utf-8")
    if tool == "guard":
        main, argv = _guard_in(repo)
    elif tool == "language gate":
        main, argv = _load(GATE, "_main_gate_refused").main, ["--repo", str(repo), "--base", "HEAD"]
    elif tool == "resolver":
        main = _load(RESOLVER, "_main_resolver_refused").main
        argv = ["--receipt", str(tmp_path / "rc.json"), "--repo", str(repo)]
    elif tool == "receipt verifier":
        main = _load(VERIFIER, "_main_verifier_refused").main
        argv = ["--repo", str(repo), "--commit", COMMIT, "--version", "1.0.0"]
    elif tool == "pre-tag audit gate":
        main, argv = _load(PRE_TAG_GATE, "_main_pre_tag_gate_refused").main, ["--repo", str(repo), "--version", "1.0.0"]
    else:
        gate = _load(VERSION_GATE, "_main_version_gate_refused")
        monkeypatch.setattr(sys, "argv", ["check_version_and_changelog.py", "--repo", str(repo)])
        main, argv = (lambda _argv: gate.main()), None
    monkeypatch.setattr(sys, "stdout", _RefusingWrites())
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        rc = main(argv)
    assert rc == code, err.getvalue()
    assert err.getvalue().startswith(first), err.getvalue()
    assert STOPPED in err.getvalue() and "BrokenPipeError" in err.getvalue(), err.getvalue()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
