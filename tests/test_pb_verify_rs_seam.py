"""The Rust second verifier reaches a test through one seam, and CI cannot skip it away.

Owner note of 2026-09-28 on Z281, three properties, each with cases that fail without it:

- ORDER: no test finds the binary by looking for the file or builds it on its own; every test asks
  tests/_pb_verify_rs.py at run time. Measured on 0ace3039 under pytest-xdist with four workers:
  three tests skipped in one run and passed in the next two, depending on whether another module
  had built the binary first.
- ONE BUILD: without a pinned binary the seam builds once per process, under an exclusive file lock,
  so parallel workers wait for each other instead of racing.
- NO EMPTY GREEN: where PROOFBUNDLE_REQUIRE_PB_VERIFY_RS=1, a missing binary fails the test.
"""
from __future__ import annotations

import os
import pathlib
import re
import subprocess
import sys
import textwrap
import unittest

import pytest

try:
    import _pb_verify_rs  # tests/_pb_verify_rs.py, the one way to the binary
except ModuleNotFoundError:  # `python -m unittest tests.<module>` puts the root on sys.path
    from tests import _pb_verify_rs

seam = _pb_verify_rs

TESTS = pathlib.Path(__file__).resolve().parent


@pytest.fixture
def fresh(monkeypatch, tmp_path):
    """The seam with an empty cache, pointed at a scratch Rust directory, both variables unset."""
    monkeypatch.setattr(seam, "_CACHE", {})
    rust = tmp_path / "pb_verify_rs"
    rust.mkdir()
    (rust / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
    monkeypatch.setattr(seam, "RUST_DIR", rust)
    monkeypatch.setattr(seam, "RELEASE_BIN", rust / "target" / "release" / "pb_verify_rs")
    monkeypatch.setattr(seam, "LOCK_FILE", rust / "target" / ".lock")
    monkeypatch.delenv(seam.PINNED_ENV, raising=False)
    monkeypatch.delenv(seam.REQUIRED_ENV, raising=False)
    return rust


def _fake_build(calls, rust):
    def run(cmd, cwd=None, **kwargs):
        calls.append((list(cmd), pathlib.Path(cwd)))
        binary = rust / "target" / "release" / "pb_verify_rs"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(b"\x7fELF")
        return subprocess.CompletedProcess(cmd, 0, "", "")
    return run


def test_a_pinned_binary_is_used_as_given_and_nothing_is_built(fresh, monkeypatch, tmp_path):
    pinned = tmp_path / "built" / "pb_verify_rs"
    pinned.parent.mkdir()
    pinned.write_bytes(b"\x7fELF")
    monkeypatch.setenv(seam.PINNED_ENV, str(pinned))
    monkeypatch.setattr(seam.subprocess, "run", lambda *a, **k: pytest.fail("built despite a pin"))
    assert seam.binary_or_skip() == pinned


def test_a_pin_that_names_no_file_is_absent_not_built(fresh, monkeypatch, tmp_path):
    monkeypatch.setenv(seam.PINNED_ENV, str(tmp_path / "missing"))
    monkeypatch.setattr(seam.subprocess, "run", lambda *a, **k: pytest.fail("built despite a pin"))
    path, why = seam.locate()
    assert path is None and "names no file" in why


def test_without_a_pin_the_seam_builds_once_per_process(fresh, monkeypatch):
    calls = []
    monkeypatch.setattr(seam.shutil, "which", lambda name: "/usr/bin/cargo")
    monkeypatch.setattr(seam.subprocess, "run", _fake_build(calls, fresh))
    first, second = seam.binary_or_skip(), seam.binary_or_skip()
    assert first == second == fresh / "target" / "release" / "pb_verify_rs"
    assert calls == [(["cargo", "build", "--release"], fresh)]


def test_the_build_runs_under_an_exclusive_lock(fresh, monkeypatch):
    fcntl = pytest.importorskip("fcntl")
    order = []
    monkeypatch.setattr(seam.shutil, "which", lambda name: "/usr/bin/cargo")
    monkeypatch.setattr(fcntl, "flock", lambda fd, op: order.append(("lock", op)))
    build = _fake_build([], fresh)
    monkeypatch.setattr(seam.subprocess, "run", lambda *a, **k: (order.append(("build",)), build(*a, **k))[1])
    seam.binary_or_skip()
    assert order == [("lock", fcntl.LOCK_EX), ("build",)]


@pytest.mark.parametrize("absence", ["no-cargo", "no-sources", "build-fails"])
def test_an_absent_binary_skips_and_fails_where_ci_requires_it(fresh, monkeypatch, absence):
    if absence == "no-cargo":
        monkeypatch.setattr(seam.shutil, "which", lambda name: None)
    elif absence == "no-sources":
        (fresh / "Cargo.toml").unlink()
    else:
        monkeypatch.setattr(seam.shutil, "which", lambda name: "/usr/bin/cargo")
        monkeypatch.setattr(seam.subprocess, "run",
                            lambda cmd, **k: subprocess.CompletedProcess(cmd, 101, "", "error: boom"))
    with pytest.raises(unittest.SkipTest, match="NOT MEASURED"):
        seam.binary_or_skip()
    monkeypatch.setenv(seam.REQUIRED_ENV, "1")
    with pytest.raises(AssertionError, match=seam.REQUIRED_ENV):
        seam.binary_or_skip()


@pytest.mark.parametrize("value", ["", "0", "true", "yes", " 1x"])
def test_only_the_value_1_requires_the_binary(fresh, monkeypatch, value):
    monkeypatch.setenv(seam.REQUIRED_ENV, value)
    assert seam.required() is False


def test_two_processes_build_one_after_the_other(fresh, tmp_path):
    """Executed, not mocked: two interpreters race for the seam with a stand-in cargo that sleeps and
    logs its start and end. Under the lock the two builds do not overlap."""
    pytest.importorskip("fcntl")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "builds.log"
    cargo = bindir / "cargo"
    cargo.write_text(textwrap.dedent(f"""\
        #!/bin/sh
        echo "start $(date +%s%N)" >> {log}
        sleep 1
        mkdir -p target/release && printf 'x' > target/release/pb_verify_rs
        echo "end $(date +%s%N)" >> {log}
        """), encoding="utf-8")
    cargo.chmod(0o755)
    script = textwrap.dedent(f"""\
        import pathlib, sys
        sys.path.insert(0, {str(TESTS)!r})
        import _pb_verify_rs as s
        s.RUST_DIR = pathlib.Path({str(fresh)!r})
        s.RELEASE_BIN = s.RUST_DIR / "target" / "release" / "pb_verify_rs"
        s.LOCK_FILE = s.RUST_DIR / "target" / ".lock"
        print(s.binary_or_skip())
        """)
    env = {**os.environ, "PATH": f"{bindir}:{os.environ.get('PATH', '')}"}
    env.pop(seam.PINNED_ENV, None)
    procs = [subprocess.Popen([sys.executable, "-c", script], env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True) for _ in range(2)]
    outs = [p.communicate(timeout=60) for p in procs]
    assert [p.returncode for p in procs] == [0, 0], outs
    marks = [line.split() for line in log.read_text(encoding="utf-8").splitlines()]
    assert [m[0] for m in marks] == ["start", "end", "start", "end"], marks


# ------------------------------------------------------------------------------------------------
# The class, swept: no test builds the binary or looks for its file on its own
# ------------------------------------------------------------------------------------------------

_OWN_BUILD = re.compile(r"""["']cargo["']\s*,\s*["']build["']""")
_COLLECTION_SKIP = re.compile(r"@(?:pytest\.mark\.skipif|unittest\.skip(?:If|Unless))\((?:(?!\n\s*def ).)*?"
                              r"(?:pb_verify_rs|\bBIN\b|_binary|RUST_BIN)", re.S)
_FILE_LOOKUP = re.compile(r"\b(?:RUST_)?BIN\w*\.(?:exists|is_file)\(\)")
#: A skip for a binary that is not built, raised by the test itself instead of the seam. A skip for
#: absent Rust SOURCES (an unpacked sdist has no src/main.rs) is a different question and stays.
_OWN_SKIP = re.compile(r"""(?:pytest\.skip|skipTest|SkipTest)\(\s*f?["'][^"']*(?:cargo|built|gebaut)""")
#: A name bound to a path under `target/debug` or `target/release`. `_FILE_LOOKUP` caught a lookup only through a
#: name with BIN in it; `for b in (RUST, RUST_DEBUG): if b.exists()` passed unseen (pull request 309, after Codex
#: thread 4217981884). `_looks_up_a_bound_path` reads the syntax tree for both forms.
_TARGET_PATH = re.compile(r"""["']target["']\s*/\s*["'](?:debug|release)["']""")


def _looks_up_a_bound_path(text: str) -> bool:
    """Whether the module calls `.exists()` or `.is_file()` on a name bound to a target path, directly or as the
    variable of a loop over a tuple or list that holds such a name."""
    import ast  # noqa: PLC0415
    try:
        baum = ast.parse(text)
    except SyntaxError:
        return False
    namen = {z.id for k in ast.walk(baum) if isinstance(k, ast.Assign) and _TARGET_PATH.search(ast.unparse(k.value))
             for z in k.targets if isinstance(z, ast.Name)}
    if not namen:
        return False
    schleifen = {k.target.id for k in ast.walk(baum)
                 if isinstance(k, ast.For) and isinstance(k.target, ast.Name) and isinstance(k.iter, (ast.Tuple, ast.List))
                 and any(isinstance(e, ast.Name) and e.id in namen for e in k.iter.elts)}
    return any(isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute) and k.func.attr in ("exists", "is_file")
               and isinstance(k.func.value, ast.Name) and k.func.value.id in namen | schleifen
               for k in ast.walk(baum))
_SEAM_AND_ITS_TEST = {"_pb_verify_rs.py", "test_pb_verify_rs_seam.py"}


def offenders(sources: dict) -> list:
    found = []
    for name, text in sorted(sources.items()):
        if name in _SEAM_AND_ITS_TEST or "pb_verify_rs" not in text:
            continue
        if _OWN_BUILD.search(text):
            found.append(f"{name}: builds the binary itself")
        if _COLLECTION_SKIP.search(text):
            found.append(f"{name}: decides a Rust skip at collection")
        if _FILE_LOOKUP.search(text):
            found.append(f"{name}: looks for the binary's file itself")
        if _OWN_SKIP.search(text):
            found.append(f"{name}: skips for a missing binary itself")
        if _looks_up_a_bound_path(text) and not _FILE_LOOKUP.search(text):
            found.append(f"{name}: looks for the binary's file itself")
    return found


def test_no_test_builds_or_looks_for_the_binary_on_its_own():
    sources = {p.name: p.read_text(encoding="utf-8") for p in TESTS.glob("*.py")}
    assert offenders(sources) == []


def test_catch_proof_the_sweep_finds_both_forms_it_replaced():
    builder = ('RUST_BIN = RUST_DIR / "target" / "release" / "pb_verify_rs"\n'
               'b = subprocess.run(["cargo", "build", "--release"], cwd=RUST_DIR)\n')
    checker = ('BIN = REPO / "tools" / "pb_verify_rs" / "target" / "release" / "pb_verify_rs"\n'
               '@pytest.mark.skipif(not BIN.is_file(),\n                    reason="not built")\n'
               'def test_x():\n    pass\n')
    unit = ('BIN = ROOT / "tools" / "pb_verify_rs" / "target" / "debug" / "pb_verify_rs"\n'
            'class T(unittest.TestCase):\n'
            '    @unittest.skipUnless(_binary_available(), "pb_verify_rs not cargo-built")\n'
            '    def test_y(self):\n        pass\n')
    assert set(offenders({"test_builder.py": builder})) == {"test_builder.py: builds the binary itself"}
    assert set(offenders({"test_checker.py": checker})) == {
        "test_checker.py: decides a Rust skip at collection",
        "test_checker.py: looks for the binary's file itself"}
    assert set(offenders({"test_unit.py": unit})) == {"test_unit.py: decides a Rust skip at collection"}
    schleife = ('RUST = REPO / "tools" / "pb_verify_rs" / "target" / "release" / "pb_verify_rs"\n'
                'RUST_DEBUG = REPO / "tools" / "pb_verify_rs" / "target" / "debug" / "pb_verify_rs"\n'
                'def _rust_bin():\n    for b in (RUST, RUST_DEBUG):\n        if b.exists():\n            return b\n')
    assert set(offenders({"test_loop.py": schleife})) == {"test_loop.py: looks for the binary's file itself"}
    nur_genannt = ('# tools/pb_verify_rs/target/release/pb_verify_rs is a build artefact\n'
                   'RUST_BIN = RUST_DIR / "target" / "release" / "pb_verify_rs"\n'
                   'def binary():\n    return seam.binary_or_skip()\n')
    assert offenders({"test_named.py": nur_genannt}) == []


def test_crosscheck_measures_the_binary_the_seam_pins(monkeypatch, tmp_path):
    """Codex thread 4217981884: a test validated the seam's binary and then ran crosscheck.py, which chose
    target/debug first and ignored the pin. With the pin set, crosscheck's binary is the pinned one."""
    import importlib.util
    pinned = tmp_path / "built" / "pb_verify_rs"
    monkeypatch.setenv(seam.PINNED_ENV, str(pinned))
    spec = importlib.util.spec_from_file_location("_crosscheck_pin", seam.RUST_DIR / "crosscheck.py")
    modul = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modul)
    assert modul.BIN == pinned
    assert "pinned by PROOFBUNDLE_PB_VERIFY_RS" in modul._binaer_herkunft()
