"""3.6.1 — the sdist normalisation is byte-deterministic (PB-2026-0717-03).

setuptools does not natively produce a byte-identical sdist across two clean builds (member mtimes,
uid/gid, member order, and the gzip header timestamp all vary). scripts/build_reproducible.py fixes this
by NORMALISING the tarball to a canonical form. This test proves the core property fast and hermetically
(no double `python -m build`, which is slow and network-adjacent): two tarballs with the SAME content but
DIFFERENT member metadata AND order normalise to byte-identical bytes, and the gzip wrapper carries a
zeroed timestamp. The full two-clean-builds proof is scripts/build_reproducible.py --check (CI:
published-artifact-gate.yml). The published 3.6.0 predates this and is honestly NOT byte-reproducible.
"""
import gzip
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from scripts.build_reproducible import normalize_sdist

_EPOCH = 1721260800


def _make_tar(path: Path, members: list[tuple[str, bytes, int, int, int]]) -> None:
    """Write a .tar.gz with the given (name, data, mtime, uid, gid) members in the GIVEN order."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for name, data, mtime, uid, gid in members:
            ti = tarfile.TarInfo(name=name)
            ti.size = len(data)
            ti.mtime = mtime
            ti.uid, ti.gid = uid, gid
            ti.uname, ti.gname = "builder", "staff"
            ti.mode = 0o600
            tf.addfile(ti, io.BytesIO(data))
    with open(path, "wb") as fh:
        with gzip.GzipFile(filename="pkg-a.tar", mode="wb", fileobj=fh, mtime=99999) as gz:
            gz.write(raw.getvalue())


class SdistNormalisationIsDeterministic(unittest.TestCase):
    def test_reproducible_sdist_selfconsistent(self):
        content = [("proofbundle-3.6.1/PKG-INFO", b"meta\n"),
                   ("proofbundle-3.6.1/pyproject.toml", b"[project]\n"),
                   ("proofbundle-3.6.1/src/proofbundle/__init__.py", b"x = 1\n")]
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            # build A: one metadata set + order; build B: different mtime/uid/gid + reversed order.
            _make_tar(d / "a.tar.gz", [(n, c, 111, 1000, 1000) for n, c in content])
            _make_tar(d / "b.tar.gz", [(n, c, 222, 501, 20) for n, c in reversed(content)])
            sha_a = normalize_sdist(d / "a.tar.gz", d / "na.tar.gz", _EPOCH)
            sha_b = normalize_sdist(d / "b.tar.gz", d / "nb.tar.gz", _EPOCH)
            self.assertEqual(sha_a, sha_b,
                             "normalised sdists must be byte-identical regardless of input metadata/order")

    def test_gzip_header_timestamp_is_zeroed(self):
        content = [("proofbundle-3.6.1/PKG-INFO", b"meta\n")]
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            _make_tar(d / "a.tar.gz", [(n, c, 111, 1000, 1000) for n, c in content])
            normalize_sdist(d / "a.tar.gz", d / "na.tar.gz", _EPOCH)
            head = (d / "na.tar.gz").read_bytes()[:10]
            # gzip header MTIME is bytes 4..8, little-endian — must be zero (deterministic wrapper).
            self.assertEqual(head[4:8], b"\x00\x00\x00\x00")

    def test_member_metadata_is_normalised(self):
        content = [("proofbundle-3.6.1/PKG-INFO", b"meta\n")]
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            _make_tar(d / "a.tar.gz", [(n, c, 111, 1234, 5678) for n, c in content])
            normalize_sdist(d / "a.tar.gz", d / "na.tar.gz", _EPOCH)
            with tarfile.open(d / "na.tar.gz", "r:gz") as tf:
                m = tf.getmembers()[0]
                self.assertEqual((m.uid, m.gid, m.uname, m.gname), (0, 0, "", ""))
                self.assertEqual(m.mtime, _EPOCH)


if __name__ == "__main__":
    unittest.main()
