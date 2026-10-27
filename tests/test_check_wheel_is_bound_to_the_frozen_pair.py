"""`--check-wheel` binds the sdist it built and both wheels to the frozen candidate pair.

FINDING (external review of the 6.4.0 preparation, 2026-10-26, RELEASEPLAN P1 and DIFF D2).
`measure_wheel_from_sdist` builds a direct wheel, a new sdist and a wheel from that sdist, and reports
the two wheel digests with `identical`. It did not report the sdist it built, and nothing compared its
three digests with the pair the release plan freezes. A green `identical: true` therefore said that two
fresh wheels agree with each other, not that the frozen sdist gives the frozen wheel. The plan's rule
for the wheel needs exactly that link: the sdist digest of the measurement equals the frozen sdist, and
both wheel digests equal the frozen wheel, which the read-back of `--expect-backend-from` has checked.

The builds are replaced by finished files, so what is measured is how the measurement reports and
compares, not a real build.
"""
from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import pathlib
import tarfile

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]


def _lade_bauskript():
    pfad = REPO / "scripts" / "build_reproducible.py"
    if not pfad.is_file():
        pytest.skip(f"NOT MEASURABLE: {pfad} is missing")
    spec = importlib.util.spec_from_file_location("_build_reproducible_frozen_pair", pfad)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _sdist(pfad: pathlib.Path) -> pathlib.Path:
    """A small real sdist with one root folder, as `measure_wheel_from_sdist` unpacks it."""
    roh = io.BytesIO()
    with tarfile.open(fileobj=roh, mode="w") as tf:
        daten = b"[project]\nname = 'proofbundle'\n"
        ti = tarfile.TarInfo("proofbundle-6.4.0/pyproject.toml")
        ti.size = len(daten)
        tf.addfile(ti, io.BytesIO(daten))
    pfad.parent.mkdir(parents=True, exist_ok=True)
    # A fixed gzip time, so that the same archive has the same digest at every call.
    pfad.write_bytes(gzip.compress(roh.getvalue(), mtime=0))
    return pfad


def _sha(pfad: pathlib.Path) -> str:
    return hashlib.sha256(pfad.read_bytes()).hexdigest()


def _ersetze_bau(mod, monkeypatch, *, direkt: bytes, aus_sdist: bytes):
    """The two builds become files: the sdist is a fixed archive, the wheel of the tree carries
    `direkt` and the wheel built from the unpacked sdist carries `aus_sdist`."""
    def bau_sdist(outdir, epoch, **k):
        p = _sdist(pathlib.Path(outdir) / "proofbundle-6.4.0.tar.gz")
        return p, _sha(p)

    def bau_wheel(quelle, outdir, epoch, **k):
        outdir = pathlib.Path(outdir)
        outdir.mkdir(parents=True, exist_ok=True)
        p = outdir / "proofbundle-6.4.0-py3-none-any.whl"
        p.write_bytes(direkt if pathlib.Path(quelle) == mod.REPO else aus_sdist)
        return p, _sha(p)

    monkeypatch.setattr(mod, "build_normalized", bau_sdist)
    monkeypatch.setattr(mod, "build_normalized_wheel", bau_wheel)


def _sdist_digest(tmp_path) -> str:
    return _sha(_sdist(tmp_path / "ref" / "proofbundle-6.4.0.tar.gz"))


def test_the_measurement_reports_the_sdist_it_built(tmp_path, monkeypatch):
    """[COUNTS] The result names the digest of its own sdist, so that it can be compared at all."""
    mod = _lade_bauskript()
    _ersetze_bau(mod, monkeypatch, direkt=b"W", aus_sdist=b"W")
    r = mod.measure_wheel_from_sdist(1700000000)
    assert r["sha256_sdist"] == _sdist_digest(tmp_path), r
    assert r["identical"] is True


def _main(mod, argv, capsys):
    try:
        rc = mod.main(argv)
    except SystemExit as e:
        rc = ("exit", e.code)
    return rc, capsys.readouterr().out


def test_check_wheel_passes_only_when_all_three_digests_are_the_frozen_pair(tmp_path, monkeypatch,
                                                                             capsys):
    """[COUNTS] Control and counter-cases: equal to the frozen pair passes; two equal wheels that are
    not the frozen wheel, a frozen wheel that only one side matches, and another sdist each fail."""
    mod = _lade_bauskript()
    sd = _sdist_digest(tmp_path)
    w = hashlib.sha256(b"W").hexdigest()
    anders = hashlib.sha256(b"V").hexdigest()
    epoch = ["--epoch", "1700000000"]

    _ersetze_bau(mod, monkeypatch, direkt=b"W", aus_sdist=b"W")
    rc, out = _main(mod, ["--check-wheel", "--json", "--frozen-pair", sd, w, *epoch], capsys)
    assert rc == 0, out
    r = json.loads(out)
    assert r["bound_to_frozen_pair"] is True and r["identical"] is True, r

    # Two wheels equal to each other, neither the frozen one: `identical` alone would pass.
    rc, out = _main(mod, ["--check-wheel", "--json", "--frozen-pair", sd, anders, *epoch], capsys)
    r = json.loads(out)
    assert rc == 1 and r["identical"] is True and r["bound_to_frozen_pair"] is False, (rc, r)

    # The sdist of the measurement is not the frozen sdist.
    rc, out = _main(mod, ["--check-wheel", "--json", "--frozen-pair", "0" * 64, w, *epoch], capsys)
    assert rc == 1 and json.loads(out)["bound_to_frozen_pair"] is False, out

    # Only the direct wheel is the frozen one; the wheel from the sdist differs.
    _ersetze_bau(mod, monkeypatch, direkt=b"W", aus_sdist=b"V")
    rc, out = _main(mod, ["--check-wheel", "--json", "--frozen-pair", sd, w, *epoch], capsys)
    r = json.loads(out)
    assert rc == 1 and r["identical"] is False and r["bound_to_frozen_pair"] is False, (rc, r)

    # Only the wheel from the sdist is the frozen one; the direct wheel differs. The binding names
    # both wheels, so a binding that read the second one alone is seen here (lens on the earlier head).
    _ersetze_bau(mod, monkeypatch, direkt=b"V", aus_sdist=b"W")
    rc, out = _main(mod, ["--check-wheel", "--json", "--frozen-pair", sd, w, *epoch], capsys)
    r = json.loads(out)
    assert rc == 1 and r["bound_to_frozen_pair"] is False, (rc, r)

    # Prose output names the binding too, and fails the same way.
    _ersetze_bau(mod, monkeypatch, direkt=b"W", aus_sdist=b"W")
    rc, out = _main(mod, ["--check-wheel", "--frozen-pair", sd, anders, *epoch], capsys)
    assert rc == 1 and "NOT THE FROZEN PAIR" in out, out


def test_the_frozen_pair_is_refused_where_it_would_bind_nothing(tmp_path, monkeypatch, capsys):
    """[COUNTS] Without `--check-wheel`, or with a value that is not 64 lower-case hex digits, the
    switch is a usage error instead of a comparison that did not run.

    LIMIT, named: at the code before the switch existed each argv here was a usage error too, as an
    unknown option; these cases hold the new switch to its refusals, they are no red case of the
    finding (that is the test above)."""
    mod = _lade_bauskript()
    _ersetze_bau(mod, monkeypatch, direkt=b"W", aus_sdist=b"W")
    w = hashlib.sha256(b"W").hexdigest()
    for argv in (["--frozen-pair", "a" * 64, w],
                 ["--check", "--frozen-pair", "a" * 64, w],
                 ["--check-wheel", "--frozen-pair", "A" * 64, w],
                 ["--check-wheel", "--frozen-pair", "a" * 63, w],
                 ["--check-wheel", "--frozen-pair", "a" * 65, w],
                 ["--check-wheel", "--frozen-pair", "a" * 64 + "\n", w],
                 ["--check-wheel", "--frozen-pair", "a" * 64]):
        rc, _ = _main(mod, [*argv, "--epoch", "1700000000"], capsys)
        assert rc == ("exit", 2), (argv, rc)
