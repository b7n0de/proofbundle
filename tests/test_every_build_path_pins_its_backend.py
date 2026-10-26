"""Every workflow job that builds a distribution builds it with the pinned frontend and backend.

FINDING (probe run for 6.4.0, 2026-10-26, blocker B6). The isolated build took the newest setuptools
that `[build-system] requires` allows, and the wheel names it: at 58de280a, setuptools 84.2.1 built the
wheel ccefd4fd and setuptools 80.9.0 built b40dc656 from the same commit, with the same sdist. A probe
build before the tag and the tag run itself could therefore publish different wheels.

THE CLASS: a pin placed on one build path while the promise "the release builds the bytes the probe
built" holds for all of them. Four jobs build today (release.yml, two jobs of
published-artifact-gate.yml, reusable-build-attest.yml), and a fifth one would inherit the promise and
not the pin. So this file measures the SET of steps that install the frontend or build, as
`test_der_riegel_steht_auf_jedem_bauweg.py` does for the key-material gate.

AND THE PIN IS READ BACK FROM THE ARTEFACT. pip 26.2 stopped reading PIP_CONSTRAINT for its own
isolated builds; `python -m build` still installs through a plain `pip install` that reads it
(measured with pip 26.2.2). A later change there would drop the pin without any step failing, so each
step that builds a wheel checks the wheel's generator (`build_reproducible.py --expect-backend-from`).
That check stood on release.yml alone at first, while reusable-build-attest.yml attests and uploads a
wheel of its own (seen by the lens on the 6.4.0 preparation, 2026-10-26); the rule is therefore one
about the set of wheel builds, as the pin rule is one about the set of build steps.

HONEST LIMIT: measured is the text of the workflow files of this tree and the logic of the read-back
on wheels built here. A build outside these files is not seen; this is a lower bound, not a guarantee.
"""
from __future__ import annotations

import importlib.util
import pathlib
import re
import zipfile

import pytest

yaml = pytest.importorskip("yaml", reason="NOT MEASURABLE: PyYAML is missing")

REPO = pathlib.Path(__file__).resolve().parents[1]
ABLAEUFE = REPO / ".github" / "workflows"
CONSTRAINTS_REL = ".github/build-constraints.txt"
CONSTRAINTS = REPO / CONSTRAINTS_REL
PIN_ENV = "${{ github.workspace }}/" + CONSTRAINTS_REL

#: What counts as a build step. `--check` counts too: it builds twice, and its digest is read as the
#: digest of the commit.
BAUT = ("python -m build", "build_reproducible.py")
#: An install of the build frontend.
INSTALLIERT_BUILD = re.compile(r"\bpip install\b[^\n]*(?<![\w./-])build(?![\w./\[-])")
#: The names the order fixes; the file may pin more.
PFLICHT = ("build", "setuptools", "wheel")


def _baut_oder_installiert(run: str) -> bool:
    return any(b in run for b in BAUT) or bool(INSTALLIERT_BUILD.search(run))


#: A direct call of the frontend. `python -m pip install build` is not one.
DIREKT = re.compile(r"\bpython3? -m build\b")


def _befehle(run: str) -> str:
    """The commands of a `run:` block, without its comment lines and joined into one line."""
    zeilen = [z for z in run.splitlines() if not z.strip().startswith("#")]
    return " ".join(" ".join(zeilen).replace("\\", " ").split())


def _baut_wheel(befehle: str) -> bool:
    """A step builds a wheel when it calls the frontend without `--sdist`, or asks for `--with-wheel`."""
    if "--with-wheel" in befehle:
        return True
    return bool(DIREKT.search(befehle)) and "--sdist" not in befehle


def _schritte():
    if not ABLAEUFE.is_dir():
        pytest.skip(f"NOT MEASURABLE: {ABLAEUFE} is missing")
    for datei in sorted(ABLAEUFE.glob("*.yml")):
        d = yaml.safe_load(datei.read_text(encoding="utf-8")) or {}
        for name, job in (d.get("jobs") or {}).items():
            for schritt in job.get("steps") or []:
                yield datei.name, name, schritt


def _lade_bauskript():
    pfad = REPO / "scripts" / "build_reproducible.py"
    if not pfad.is_file():
        pytest.skip(f"NOT MEASURABLE: {pfad} is missing")
    spec = importlib.util.spec_from_file_location("_build_reproducible_backend_pin", pfad)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_there_are_build_steps_at_all():
    """[COUNTS] A rule over an empty set measures nothing, so the set is counted first."""
    bauend = [(f, j) for f, j, s in _schritte() if _baut_oder_installiert(str(s.get("run") or ""))]
    assert len({(f, j) for f, j in bauend}) >= 4, bauend


def test_the_constraints_file_pins_each_named_package_exactly():
    """[COUNTS] Each line is `name==version`; build, setuptools and wheel are among them."""
    if not CONSTRAINTS.is_file():
        pytest.fail(f"{CONSTRAINTS_REL} is missing")
    gepinnt = {}
    for zeile in CONSTRAINTS.read_text(encoding="utf-8").splitlines():
        teil = zeile.split("#", 1)[0].strip()
        if not teil:
            continue
        m = re.fullmatch(r"([A-Za-z0-9_.-]+)==([0-9][0-9A-Za-z.]*)", teil)
        assert m, f"not an exact pin: {zeile!r}"
        gepinnt[m.group(1).lower().replace("_", "-")] = m.group(2)
    for name in PFLICHT:
        assert name in gepinnt, (name, gepinnt)


def test_every_step_that_installs_the_frontend_or_builds_reads_the_pins():
    """[COUNTS] The finding itself, as a statement about the set of steps."""
    ohne = []
    for datei, job, schritt in _schritte():
        run = str(schritt.get("run") or "")
        if not _baut_oder_installiert(run):
            continue
        wert = (schritt.get("env") or {}).get("PIP_CONSTRAINT")
        if wert != PIN_ENV:
            ohne.append(f"{datei}:{job}: {schritt.get('name') or run[:40]!r} has PIP_CONSTRAINT={wert!r}")
        if "--upgrade build" in run or "-U build" in run:
            ohne.append(f"{datei}:{job}: installs build with an upgrade, which no pin should need")
    assert not ohne, ohne


def test_every_step_that_builds_a_wheel_reads_the_pin_back_from_it():
    """[COUNTS] Each wheel a workflow builds is checked against the file, by the step that builds it.

    A direct `python -m build` in such a step builds a wheel the read-back does not see, so it counts
    as a step without the check even when `--expect-backend-from` stands beside it."""
    gefunden, ohne = [], []
    for datei, job, schritt in _schritte():
        befehle = _befehle(str(schritt.get("run") or ""))
        if not _baut_wheel(befehle):
            continue
        gefunden.append(f"{datei}:{job}")
        if DIREKT.search(befehle) or f"--expect-backend-from {CONSTRAINTS_REL}" not in befehle:
            ohne.append(f"{datei}:{job}: {schritt.get('name')!r} builds a wheel without the read-back")
    assert {"release.yml:build-and-attest", "reusable-build-attest.yml:build-attest"} <= set(gefunden), (
        gefunden)
    assert not ohne, ohne


def _jobs():
    if not ABLAEUFE.is_dir():
        pytest.skip(f"NOT MEASURABLE: {ABLAEUFE} is missing")
    for datei in sorted(ABLAEUFE.glob("*.yml")):
        d = yaml.safe_load(datei.read_text(encoding="utf-8")) or {}
        for name, job in (d.get("jobs") or {}).items():
            yield datei.name, name, job.get("steps") or []


def test_every_job_that_builds_takes_the_epoch_from_the_full_history():
    """[COUNTS] The bytes a job builds are the bytes of the commit only with the epoch release.yml uses.

    `head_commit_epoch` needs the history back to the last shipped change, and a clone of depth 1
    returns the time of its boundary instead. This stood on the byte-freeze job alone at first, while
    reusable-build-attest.yml attests and uploads what it builds and hermetic-cleanroom tests what it
    calls the published bytes, both from a clone of depth 1 (2026-10-26). So it is a rule about every
    job that builds, as the pin rule is."""
    gefunden, flach = [], []
    for datei, job, schritte in _jobs():
        if not any(any(b in _befehle(str(s.get("run") or "")) for b in BAUT) for s in schritte):
            continue
        gefunden.append(f"{datei}:{job}")
        checkout = [s for s in schritte if str(s.get("uses") or "").startswith("actions/checkout@")]
        if len(checkout) != 1 or (checkout[0].get("with") or {}).get("fetch-depth") != 0:
            flach.append(f"{datei}:{job}: checkout {[s.get('with') for s in checkout]!r}")
    assert len(gefunden) >= 4, gefunden
    assert not flach, flach


def _wheel(pfad: pathlib.Path, wheel_text: str | None, *, zweites: bool = False) -> pathlib.Path:
    with zipfile.ZipFile(pfad, "w") as z:
        z.writestr("proofbundle/__init__.py", "")
        if wheel_text is not None:
            z.writestr("proofbundle-6.4.0.dist-info/WHEEL", wheel_text)
            if zweites:
                z.writestr("other-1.0.dist-info/WHEEL", wheel_text)
    return pfad


def test_the_read_back_accepts_the_pinned_backend_and_refuses_every_other(tmp_path):
    """[COUNTS] At the function: the pinned generator passes; another version, a missing generator, a
    missing or doubled WHEEL file and a file without a setuptools pin each refuse."""
    mod = _lade_bauskript()
    c = tmp_path / "c.txt"
    c.write_text("# pins\nbuild==1.6.1\nsetuptools==84.2.1  # backend\nwheel==0.48.0\n")
    kopf = "Wheel-Version: 1.0\nGenerator: setuptools ({})\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    gut = _wheel(tmp_path / "gut.whl", kopf.format("84.2.1"))
    assert mod.backend_mismatch(gut, c) is None
    anders = _wheel(tmp_path / "anders.whl", kopf.format("80.9.0"))
    assert "80.9.0" in mod.backend_mismatch(anders, c)
    ohne_zeile = _wheel(tmp_path / "ohne.whl", "Wheel-Version: 1.0\nTag: py3-none-any\n")
    assert "no generator" in mod.backend_mismatch(ohne_zeile, c)
    ohne_datei = _wheel(tmp_path / "leer.whl", None)
    assert "no generator" in mod.backend_mismatch(ohne_datei, c)
    doppelt = _wheel(tmp_path / "doppelt.whl", kopf.format("84.2.1"), zweites=True)
    assert "no generator" in mod.backend_mismatch(doppelt, c)
    ohne_pin = tmp_path / "ohne_pin.txt"
    ohne_pin.write_text("setuptools>=68\nwheel==0.48.0\n")
    assert "pins no setuptools" in mod.backend_mismatch(gut, ohne_pin)


def test_FANG_the_step_predicate_counts_installs_and_builds_and_nothing_else():
    """[COUNTS] Counter-direction: the predicate must not miss a form and must not count prose."""
    assert _baut_oder_installiert("python -m pip install build")
    assert _baut_oder_installiert("python -m pip install --upgrade build")
    assert _baut_oder_installiert("python scripts/build_reproducible.py --check")
    assert _baut_oder_installiert("python -m build --wheel --outdir dist")
    assert not _baut_oder_installiert('python -m pip install "cryptography>=42"')
    assert not _baut_oder_installiert('/tmp/clean/bin/pip install --quiet "${SDIST}[test]"')
    assert not _baut_oder_installiert("pip install build-tools-other")
    assert not _baut_oder_installiert("echo no build here")


def test_FANG_the_wheel_predicate_sees_each_form_of_a_wheel_build():
    """[COUNTS] Counter-direction for the read-back rule: every form of a wheel build counts, an sdist
    build and an install of the frontend do not, and a comment line is not a command."""
    assert _baut_wheel(_befehle("python -m build --wheel --outdir dist"))
    assert _baut_wheel(_befehle("python3 -m build --outdir dist"))
    assert _baut_wheel(_befehle("python scripts/build_reproducible.py --outdir dist \\\n  --with-wheel"))
    assert not _baut_wheel(_befehle("python -m build --sdist --outdir dist"))
    assert not _baut_wheel(_befehle("python -m pip install build"))
    assert not _baut_wheel(_befehle("python scripts/build_reproducible.py --outdir dist"))
    assert not _baut_wheel(_befehle("# python -m build --wheel, as the old step did\necho done"))
    alt = _befehle("python scripts/build_reproducible.py --outdir dist\npython -m build --wheel --outdir dist")
    assert _baut_wheel(alt) and DIREKT.search(alt)


def test_the_limit_of_the_measurement_is_in_the_text():
    """[COUNTS] A text measurement over workflow files is a lower bound, and that belongs here."""
    q = pathlib.Path(__file__).read_text(encoding="utf-8")
    assert "HONEST LIMIT" in q and "lower bound" in q
