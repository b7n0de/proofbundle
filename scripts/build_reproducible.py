#!/usr/bin/env python3
"""Fundament F2 — deterministic, byte-reproducible sdist build.

Front-Loading (§3): a hermetic + reproducible packaging story built NOW (with 3.3.1) means every
later release inherits it with no repackaging. Research finding (reproducible-builds.org,
pypa/setuptools#2133): setuptools does NOT natively honour ``SOURCE_DATE_EPOCH`` for a byte-identical
sdist tarball (member mtimes, uid/gid, order and the gzip header still vary). So this script does the
robust thing: it builds the sdist, then NORMALISES the tarball to a canonical form:

  * every member mtime set to ``SOURCE_DATE_EPOCH`` (default: the HEAD commit time),
  * uid/gid = 0, uname/gname = "" (no build-host identity leaks into the artifact),
  * mode normalised (dirs 0755, files 0644), members sorted by name,
  * re-gzipped with a zeroed gzip header timestamp.

Two runs of ``--check`` then produce a BYTE-IDENTICAL sdist — proven, not asserted. This is the same
technique Debian's ``strip-nondeterminism`` applies; here it is inlined with no extra dependency.

CLI:
  python scripts/build_reproducible.py [--outdir DIR] [--epoch N]   # build one normalised sdist
  python scripts/build_reproducible.py --check                      # build twice, prove byte-identical
  python scripts/build_reproducible.py --check --json               # the same, machine-readable

  python scripts/build_reproducible.py --check-wheel                # wheel-from-sdist == direct build

Exit 0 on success; ``--check`` exits non-zero if the two normalised sdists differ.

DIE ZWEITE HAELFTE DES BYTE-FREEZE (``--check-wheel``, hinzugefuegt 2026-09-07). Der Release-Standard
6.0.0 verlangt beides: zwei byte-identische sdists UND ein wheel aus dem sdist, das byteweise dem
direkt gebauten gleicht. Nur die erste Haelfte hatte eine Messstelle; die zweite stand im
fail-closed-Satz und wurde von nichts gemessen. Siehe ``measure_wheel_from_sdist``.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def head_commit_epoch() -> int:
    """The HEAD commit time (a stable, content-derived epoch). Falls back to a fixed constant if git
    is unavailable (still deterministic, just not commit-derived)."""
    try:
        out = subprocess.run(["git", "-C", str(REPO), "log", "-1", "--format=%ct"],
                             capture_output=True, text=True, check=True)
        return int(out.stdout.strip())
    except (subprocess.CalledProcessError, OSError, ValueError):
        return 1700000000  # deterministic fallback (2023-11-14T22:13:20Z)


def _build_sdist(outdir: Path, epoch: int, *, no_isolation: bool = False) -> Path:
    env = dict(os.environ)
    env["SOURCE_DATE_EPOCH"] = str(epoch)
    outdir.mkdir(parents=True, exist_ok=True)
    # Isolation (default, like release.yml's `python -m build`) fetches a consistent, modern
    # setuptools/wheel — the reproducibility is achieved by the post-build normalisation, not by the
    # build backend. --no-isolation is offered for an offline build host that already has the deps.
    cmd = [sys.executable, "-m", "build", "--sdist", "--outdir", str(outdir)]
    if no_isolation:
        cmd.insert(4, "--no-isolation")
    subprocess.run(cmd, cwd=str(REPO), env=env, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    tars = sorted(outdir.glob("*.tar.gz"))
    if not tars:
        raise RuntimeError(f"no sdist produced in {outdir}")
    return tars[-1]


def normalize_sdist(src: Path, dst: Path, epoch: int) -> str:
    """Rewrite ``src`` (.tar.gz) to a canonical, deterministic ``dst`` (.tar.gz). Returns dst sha256."""
    members: list[tuple[tarfile.TarInfo, bytes]] = []
    with tarfile.open(src, "r:gz") as tf:
        for m in tf.getmembers():
            data = b""
            if m.isreg():
                f = tf.extractfile(m)
                data = f.read() if f is not None else b""
            members.append((m, data))
    members.sort(key=lambda pair: pair[0].name)

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as out:
        for m, data in members:
            ti = tarfile.TarInfo(name=m.name)
            ti.size = len(data)
            ti.mtime = epoch
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            ti.type = m.type
            if m.isdir():
                ti.mode = 0o755
            else:
                ti.mode = 0o644
            if m.islnk() or m.issym():
                ti.linkname = m.linkname
            out.addfile(ti, io.BytesIO(data) if data else None)

    # gzip with a zeroed header timestamp (mtime=0) so the compressed wrapper is deterministic too.
    tar_bytes = raw.getvalue()
    with open(dst, "wb") as fh:
        with gzip.GzipFile(filename="", mode="wb", fileobj=fh, mtime=0) as gz:
            gz.write(tar_bytes)
    return hashlib.sha256(dst.read_bytes()).hexdigest()


def build_normalized(outdir: Path, epoch: int, *, no_isolation: bool = False) -> tuple[Path, str]:
    with tempfile.TemporaryDirectory(prefix="pb_sdist_") as td:
        raw = _build_sdist(Path(td), epoch, no_isolation=no_isolation)
        outdir.mkdir(parents=True, exist_ok=True)
        dst = outdir / raw.name
        digest = normalize_sdist(raw, dst, epoch)
    return dst, digest


#: Schema des maschinenlesbaren Ergebnisses. Es gibt es, weil der Aufrufer sonst PROSA lesen muss:
#: `audit_candidate_matrix.c9_1_two_sdists_identical` leitete sein Urteil aus den Teilzeichenketten
#: "reproducible ok" / "byte-identical" / "not reproducible" der Standardausgabe ab. Eine
#: freigabeentscheidende Zeile, die einen Satz liest, aendert ihr Urteil, sobald jemand den Satz
#: umformuliert (Tiefen-Gate 2026-09-05, Sweep der Klasse A).
MEASUREMENT_SCHEMA = "proofbundle.reproducible_sdist_check.v1"


def measure_reproducible(epoch: int, *, no_isolation: bool = False) -> dict:
    """Zwei normalisierte sdists bauen und STRUKTURIERT berichten. Keine Prosa im Ergebnis."""
    with tempfile.TemporaryDirectory(prefix="pb_repro_a_") as a, \
         tempfile.TemporaryDirectory(prefix="pb_repro_b_") as b:
        _, da = build_normalized(Path(a), epoch, no_isolation=no_isolation)
        _, db = build_normalized(Path(b), epoch, no_isolation=no_isolation)
    return {"schema": MEASUREMENT_SCHEMA, "reproducible": da == db,
            "sha256_a": da, "sha256_b": db, "epoch": epoch}


#: Schema der ZWEITEN Haelfte des Byte-Freeze. Eigene Kennung, weil es eine andere Aussage ist:
#: die erste sagt „zweimal bauen ergibt dasselbe sdist", diese sagt „aus dem ausgelieferten sdist
#: entsteht dasselbe wheel wie aus dem Baum".
WHEEL_MEASUREMENT_SCHEMA = "proofbundle.wheel_from_sdist_check.v1"


def _build_wheel(quelle: Path, outdir: Path, epoch: int, *, no_isolation: bool = False) -> Path:
    """Ein wheel aus ``quelle`` bauen. KEINE Nachnormalisierung — und das ist Absicht.

    Die sdist-Seite normalisiert nach dem Bau, weil setuptools ``SOURCE_DATE_EPOCH`` fuer den
    tar-Container nicht ehrt. Fuer das wheel ehrt es ihn (die zip-Eintraege tragen die Epoche), und
    eine Normalisierung hier wuerde genau den Unterschied wegbuegeln, den diese Messung finden soll.
    Wer zwei verschiedene wheels gleichmacht, misst seine Normalisierung, nicht den Bau.
    """
    env = dict(os.environ)
    env["SOURCE_DATE_EPOCH"] = str(epoch)
    outdir.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, "-m", "build", "--wheel", "--outdir", str(outdir)]
    if no_isolation:
        cmd.insert(4, "--no-isolation")
    subprocess.run(cmd, cwd=str(quelle), env=env, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    whls = sorted(outdir.glob("*.whl"))
    if not whls:
        raise RuntimeError(f"no wheel produced in {outdir} (source {quelle})")
    return whls[-1]


def measure_wheel_from_sdist(epoch: int, *, no_isolation: bool = False) -> dict:
    """Die zweite Haelfte des Byte-Freeze: wheel AUS DEM SDIST gegen wheel AUS DEM BAUM.

    WARUM ES DIESE FUNKTION GIBT. Der Release-Standard 6.0.0 vom 05.09.2026 nennt in seinem
    fail-closed-Satz „Byte-Freeze mit zwei byte-identischen sdists UND wheel aus sdist byteweise
    gleich dem direkt gebauten". Die erste Haelfte misst ``measure_reproducible``. Die zweite hatte
    am 2026-09-07 KEINE Messstelle: dieses Skript baute ueberhaupt keine wheels, unter ``scripts/``
    gab es kein weiteres Werkzeug dafuer, und die Audit-Matrix liest ``candidate.wheel_sha256``
    ausdruecklich ohne ihn nachzurechnen. Eine Bedingung im fail-closed-Satz ohne Messstelle gilt
    stillschweigend als gruen, ohne je gemessen worden zu sein — das ist teurer als eine rote Zeile.

    GEBAUT WIRD AUS DEM NORMALISIERTEN SDIST, nicht aus dem rohen: das normalisierte ist das, was
    ausgeliefert wird und was ein Nutzer herunterlaedt. Eine Messung gegen das rohe wuerde eine
    Datei pruefen, die niemand bekommt.
    """
    with tempfile.TemporaryDirectory(prefix="pb_wheel_") as td:
        arbeit = Path(td)
        direkt = _build_wheel(REPO, arbeit / "direkt", epoch, no_isolation=no_isolation)
        sdist, _ = build_normalized(arbeit / "sd", epoch, no_isolation=no_isolation)
        entpackt = arbeit / "aus"
        entpackt.mkdir()
        with tarfile.open(sdist, "r:gz") as tf:
            tf.extractall(entpackt)           # noqa: S202 — eigenes, soeben gebautes Archiv
        wurzeln = [q for q in entpackt.iterdir() if q.is_dir()]
        if len(wurzeln) != 1:
            raise RuntimeError(f"sdist entpackt nicht zu genau einem Wurzelordner: {wurzeln}")
        aus_sdist = _build_wheel(wurzeln[0], arbeit / "aus_sdist", epoch, no_isolation=no_isolation)
        ha = hashlib.sha256(direkt.read_bytes()).hexdigest()
        hb = hashlib.sha256(aus_sdist.read_bytes()).hexdigest()
        return {"schema": WHEEL_MEASUREMENT_SCHEMA, "identical": ha == hb,
                "sha256_direct": ha, "sha256_from_sdist": hb,
                "name_direct": direkt.name, "name_from_sdist": aus_sdist.name, "epoch": epoch}


def check_wheel_from_sdist(epoch: int, *, no_isolation: bool = False, as_json: bool = False) -> int:
    r = measure_wheel_from_sdist(epoch, no_isolation=no_isolation)
    if as_json:
        import json as _json  # noqa: PLC0415
        print(_json.dumps(r, sort_keys=True))
    elif r["identical"]:
        print("WHEEL FREEZE OK: wheel from the shipped sdist is byte-identical to the direct build"
              f"\n  sha256={r['sha256_direct']}\n  epoch={epoch}")
    else:
        print("WHEEL FREEZE FAILED: the two wheels differ"
              f"\n  direct     = {r['sha256_direct']}\n  from sdist = {r['sha256_from_sdist']}")
    return 0 if r["identical"] else 1


def check_reproducible(epoch: int, *, no_isolation: bool = False, as_json: bool = False) -> int:
    r = measure_reproducible(epoch, no_isolation=no_isolation)
    da, db = r["sha256_a"], r["sha256_b"]
    if as_json:
        import json as _json  # noqa: PLC0415
        print(_json.dumps(r, sort_keys=True))
    elif r["reproducible"]:
        print(f"REPRODUCIBLE OK: two normalised sdists are byte-identical\n  sha256={da}\n  epoch={epoch}")
    else:
        print(f"NOT REPRODUCIBLE: sdist sha256 differ\n  run A={da}\n  run B={db}")
    return 0 if r["reproducible"] else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--outdir", type=Path, default=REPO / "dist",
                   help="where to write the normalised sdist (default: ./dist)")
    p.add_argument("--epoch", type=int, default=None,
                   help="SOURCE_DATE_EPOCH (default: HEAD commit time)")
    p.add_argument("--check", action="store_true",
                   help="build twice and prove the normalised sdists are byte-identical")
    p.add_argument("--check-wheel", action="store_true",
                   help="prove the wheel built FROM the shipped sdist is byte-identical to the "
                        "wheel built directly from the tree (second half of the byte freeze)")
    p.add_argument("--no-isolation", action="store_true",
                   help="pass --no-isolation to `python -m build` (offline host with build deps present)")
    p.add_argument("--json", action="store_true",
                   help="with --check: print the machine-readable measurement instead of prose")
    args = p.parse_args(argv)
    epoch = args.epoch if args.epoch is not None else head_commit_epoch()
    if args.check_wheel:
        return check_wheel_from_sdist(epoch, no_isolation=args.no_isolation, as_json=args.json)
    if args.check:
        return check_reproducible(epoch, no_isolation=args.no_isolation, as_json=args.json)
    dst, digest = build_normalized(args.outdir, epoch, no_isolation=args.no_isolation)
    print(f"built normalised sdist: {dst}\n  sha256={digest}\n  epoch={epoch}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
