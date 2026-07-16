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

Exit 0 on success; ``--check`` exits non-zero if the two normalised sdists differ.
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


def check_reproducible(epoch: int, *, no_isolation: bool = False) -> int:
    with tempfile.TemporaryDirectory(prefix="pb_repro_a_") as a, \
         tempfile.TemporaryDirectory(prefix="pb_repro_b_") as b:
        _, da = build_normalized(Path(a), epoch, no_isolation=no_isolation)
        _, db = build_normalized(Path(b), epoch, no_isolation=no_isolation)
    if da == db:
        print(f"REPRODUCIBLE OK: two normalised sdists are byte-identical\n  sha256={da}\n  epoch={epoch}")
        return 0
    print(f"NOT REPRODUCIBLE: sdist sha256 differ\n  run A={da}\n  run B={db}")
    return 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--outdir", type=Path, default=REPO / "dist",
                   help="where to write the normalised sdist (default: ./dist)")
    p.add_argument("--epoch", type=int, default=None,
                   help="SOURCE_DATE_EPOCH (default: HEAD commit time)")
    p.add_argument("--check", action="store_true",
                   help="build twice and prove the normalised sdists are byte-identical")
    p.add_argument("--no-isolation", action="store_true",
                   help="pass --no-isolation to `python -m build` (offline host with build deps present)")
    args = p.parse_args(argv)
    epoch = args.epoch if args.epoch is not None else head_commit_epoch()
    if args.check:
        return check_reproducible(epoch, no_isolation=args.no_isolation)
    dst, digest = build_normalized(args.outdir, epoch, no_isolation=args.no_isolation)
    print(f"built normalised sdist: {dst}\n  sha256={digest}\n  epoch={epoch}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
