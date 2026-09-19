"""A planted bytecode cache must make the gate red, and the planted body must really run.

WHY THIS FILE EXISTS. Measured 2026-09-19 on this checkout: a cache file whose header still carries
the source's mtime and size is executed WITHOUT the interpreter looking at the source again, and
``__pycache__/`` is in ``.gitignore``, so such a file never appears in ``git status``. Seven cache
files were present on the tree at the time and git reported none of them.

Two defences were measured and neither defends against this:

    --check-hash-based-pycs always   ran the planted body   (it governs PEP 552 caches only)
    -B / PYTHONDONTWRITEBYTECODE     ran the planted body   (it stops writing, not reading)

THE ANTI-TAUTOLOGY CASE IS THE IMPORTANT ONE. A gate that reports MISMATCH proves nothing on its
own: it might be flagging a difference that has no effect. One case here therefore executes the
planted module in a fresh interpreter and asserts that the POISONED body ran while the source on
disk still says otherwise. Without it, this file would test a diff instead of a danger.
"""
from __future__ import annotations

import importlib.util
import py_compile
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
GATE = REPO / "scripts" / "pyc_integrity_gate.py"

HEADER_LEN = 16
HONEST = "def leaf_hash(data):\n    return b'HONEST:' + data\n"
POISON = "def leaf_hash(data):\n    return b'POISONED'\n"


def _gate(root: Path) -> dict:
    """Load the gate module and ask it for its verdict over ``root``."""
    spec = importlib.util.spec_from_file_location("pyc_gate_under_test", GATE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.survey(root)


def _package(tmp_path: Path, body: str = HONEST) -> tuple[Path, Path]:
    """A tiny importable package with one compiled module. Returns (root, cache file)."""
    pkg = tmp_path / "victimpkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    src = pkg / "leafy.py"
    src.write_text(body, encoding="utf-8")
    py_compile.compile(str(src), doraise=True)
    return tmp_path, Path(importlib.util.cache_from_source(str(src)))


def _plant(cache: Path, tmp_path: Path) -> None:
    """Replace the cached body while KEEPING the honest header, which is the whole trick."""
    evil_dir = tmp_path / "evil"
    evil_dir.mkdir(exist_ok=True)
    evil_src = evil_dir / "leafy.py"
    evil_src.write_text(POISON, encoding="utf-8")
    py_compile.compile(str(evil_src), doraise=True)
    evil_cache = Path(importlib.util.cache_from_source(str(evil_src)))
    honest = cache.read_bytes()
    cache.write_bytes(honest[:HEADER_LEN] + evil_cache.read_bytes()[HEADER_LEN:])


def test_a_clean_tree_is_CLEAN():  # noqa: N802
    """The gate must not be red on an untouched tree. A permanently red check teaches people to
    ignore it, and the repository says as much in its own English gate."""
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        root, _ = _package(Path(d))
        assert _gate(root)["verdict"] == "CLEAN"


def test_THE_CATCH_a_planted_cache_is_found(tmp_path: Path):  # noqa: N802
    """C4: the planted file must make the gate red, and it must name the file."""
    root, cache = _package(tmp_path)
    assert _gate(root)["verdict"] == "CLEAN", "the fixture must start clean, or the case proves nothing"
    _plant(cache, tmp_path)
    e = _gate(root)
    assert e["verdict"] == "FINDINGS", e
    kinds = {b["state"] for b in e["findings"]}
    assert "MISMATCH" in kinds, e["findings"]
    assert any("leafy" in b["file"] for b in e["findings"]), e["findings"]


def test_ANTI_TAUTOLOGY_the_planted_body_really_runs(tmp_path: Path):  # noqa: N802
    """The finding must describe a danger, not a diff.

    The source on disk still says HONEST. A fresh interpreter is asked which body it executed; if
    it answered HONEST, the gate above would be flagging something without effect and this whole
    file would be theatre.
    """
    root, cache = _package(tmp_path)
    src = root / "victimpkg" / "leafy.py"
    _plant(cache, tmp_path)
    assert "HONEST" in src.read_text(encoding="utf-8"), "the source must be untouched"
    code = (f"import sys; sys.path.insert(0, {str(root)!r})\n"
            "from victimpkg.leafy import leaf_hash\n"
            "print(leaf_hash(b'x').decode())\n")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-400:]
    assert r.stdout.strip() == "POISONED", (
        f"the planted body did not run ({r.stdout.strip()!r}), so the gate would be guarding "
        "against something that cannot happen on this interpreter")


def test_the_named_defences_do_NOT_defend(tmp_path: Path):
    """Both flags people reach for were measured and neither stops the planted body.

    This is kept as a case rather than a comment so that a future interpreter which DOES stop it
    makes this go red, and the claim in the gate's own head gets revisited instead of aging.
    """
    root, cache = _package(tmp_path)
    _plant(cache, tmp_path)
    code = (f"import sys; sys.path.insert(0, {str(root)!r})\n"
            "from victimpkg.leafy import leaf_hash\n"
            "print(leaf_hash(b'x').decode())\n")
    for flags in (["--check-hash-based-pycs", "always"], ["-B"]):
        r = subprocess.run([sys.executable, *flags, "-c", code], capture_output=True, text=True)
        assert r.stdout.strip() == "POISONED", (
            f"{flags} now stops the planted body; the gate's head says it does not, and that "
            "sentence has to be corrected")


def test_an_orphan_cache_fails_CLOSED(tmp_path: Path):  # noqa: N802
    """A cache file with no source cannot be compared, and unknown is not permission."""
    root, cache = _package(tmp_path)
    (root / "victimpkg" / "leafy.py").unlink()
    e = _gate(root)
    assert e["verdict"] == "FINDINGS", e
    assert {b["state"] for b in e["findings"]} == {"ORPHAN"}, e["findings"]
    assert cache.exists()


def test_a_cache_for_another_interpreter_is_SKIPPED_and_not_counted_as_passed(tmp_path: Path):  # noqa: N802
    """Honest limit made executable: a foreign cache tag is skipped, never silently passed.

    The verdict here is EMPTY rather than CLEAN, and that is the point. A run whose only file was
    skipped has examined nothing, so calling it clean would turn an unmeasured tree into a pass —
    the same green-tick-over-an-empty-set shape the gate names in its own head.
    """
    root, cache = _package(tmp_path)
    foreign = cache.with_name("leafy.cpython-01.pyc")
    cache.rename(foreign)
    e = _gate(root)
    assert e["verdict"] == "EMPTY", e
    assert e["skipped_other_interpreter"] == 1, e
    assert e["checked"] == 0, (
        "a skipped file must not be counted among the checked ones, or the gate reports a number "
        "that reads like coverage it does not have")


def test_AN_EMPTY_RUN_IS_NAMED_not_folded_into_the_pass(tmp_path: Path):  # noqa: N802
    """A green tick over an empty set is one of this project's own false-green classes.

    A fresh checkout holds no cache files, so a job that scans one reports success having examined
    nothing. The verdict for that is EMPTY rather than CLEAN, and the caller can turn it into a
    failure. Without this distinction the gate would be at its loudest exactly where it knows
    least.
    """
    e = _gate(tmp_path)
    assert e["verdict"] == "EMPTY", e
    assert e["checked"] == 0, e


@pytest.mark.parametrize("payload", ["", "x"])
def test_a_truncated_cache_is_UNREADABLE_not_OK(tmp_path: Path, payload: str):  # noqa: N802
    """A cache shorter than its header is a broken file, and broken is not a pass."""
    root, cache = _package(tmp_path)
    cache.write_bytes(payload.encode())
    e = _gate(root)
    assert e["verdict"] == "FINDINGS", e
    assert {b["state"] for b in e["findings"]} == {"UNREADABLE"}, e["findings"]
