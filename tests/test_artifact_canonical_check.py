"""Catch-proofs for scripts/artifact_canonical_check.py.

The gap: the CI enforces the canonical build path on every pull request, and the normaliser
is bound hermetically — but nothing examines an artifact that is already on disk. That is
where the readiness artifacts of 2026-09-09 slipped through: built by hand, without the
normalised timestamps, filed, unnoticed.

So every case here BUILDS a real archive with a real defect and insists the checker names
it. A property that is only asserted over a well-formed input has never seen the state it
exists for.
"""
import gzip
import importlib.util
import io
import sys
import tarfile
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "artifact_canonical_check.py"

spec = importlib.util.spec_from_file_location("acc_ut", SCRIPT)
acc = importlib.util.module_from_spec(spec)
sys.modules["acc_ut"] = acc
spec.loader.exec_module(acc)

EPOCH = 1700000000
FREMDER_NAME = "builduser"          # stands in for a real build-host account name


def baue_wheel(pfad: Path, *, gleiche_stempel: bool) -> None:
    with zipfile.ZipFile(pfad, "w") as zf:
        for i, name in enumerate(["pkg/__init__.py", "pkg/a.py", "pkg-1.0.dist-info/RECORD"]):
            st = time.gmtime(EPOCH)[:6] if gleiche_stempel else time.gmtime(EPOCH + i * 3600)[:6]
            zf.writestr(zipfile.ZipInfo(filename=name, date_time=st), b"x = 1\n")


def baue_sdist(pfad: Path, *, mtimes_gleich=True, ids_null=True, namen_leer=True,
               gzip_stempel_null=True, sortiert=True) -> None:
    roh = io.BytesIO()
    eintraege = ["pkg-1.0/PKG-INFO", "pkg-1.0/setup.py"]
    if not sortiert:
        eintraege = list(reversed(sorted(eintraege)))
    with tarfile.open(fileobj=roh, mode="w") as tf:
        for i, name in enumerate(eintraege):
            ti = tarfile.TarInfo(name=name)
            daten = b"x\n"
            ti.size = len(daten)
            ti.mtime = EPOCH if mtimes_gleich else EPOCH + i * 3600
            ti.uid = ti.gid = 0 if ids_null else 1000
            ti.uname = ti.gname = "" if namen_leer else FREMDER_NAME
            tf.addfile(ti, io.BytesIO(daten))
    with pfad.open("wb") as fh:
        with gzip.GzipFile(filename="", mode="wb", fileobj=fh,
                           mtime=0 if gzip_stempel_null else 1789000000) as gz:
            gz.write(roh.getvalue())


class Basis(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def whl(self, **kw) -> Path:
        p = self.tmp / "probe.whl"
        baue_wheel(p, **kw)
        return p

    def sd(self, **kw) -> Path:
        p = self.tmp / "probe.tar.gz"
        baue_sdist(p, **kw)
        return p


class TestKontrolle(Basis):
    """Without these, every red below could mean the checker refuses everything."""

    def test_ein_kanonisches_wheel_besteht(self):
        self.assertEqual(acc.pruefe(self.whl(gleiche_stempel=True))["verdict"], acc.CANONICAL)

    def test_ein_kanonisches_sdist_besteht(self):
        self.assertEqual(acc.pruefe(self.sd())["verdict"], acc.CANONICAL)


class TestWheel(Basis):
    def test_VERSCHIEDENE_ZEITSTEMPEL_werden_gefangen(self):
        """The exact shape of 2026-09-09: nine distinct mtimes against one."""
        d = acc.pruefe(self.whl(gleiche_stempel=False))
        self.assertEqual(d["verdict"], acc.NOT_CANONICAL)
        self.assertEqual(d["distinct_timestamps"], 3)
        self.assertTrue(any("timestamps differ" in f for f in d["findings"]))


class TestSdist(Basis):
    def test_VERSCHIEDENE_MEMBER_MTIMES_werden_gefangen(self):
        d = acc.pruefe(self.sd(mtimes_gleich=False))
        self.assertEqual(d["verdict"], acc.NOT_CANONICAL)
        self.assertTrue(any("member mtimes differ" in f for f in d["findings"]))

    def test_NICHT_GENULLTE_UID_wird_gefangen(self):
        """A build-host identity inside a shipped artifact is the point of zeroing it."""
        d = acc.pruefe(self.sd(ids_null=False))
        self.assertEqual(d["verdict"], acc.NOT_CANONICAL)
        self.assertTrue(any("uid/gid not zeroed" in f for f in d["findings"]))

    def test_EIN_BENUTZERNAME_IM_ARCHIV_wird_gefangen(self):
        d = acc.pruefe(self.sd(namen_leer=False))
        self.assertEqual(d["verdict"], acc.NOT_CANONICAL)
        self.assertTrue(any("uname/gname not empty" in f for f in d["findings"]))

    def test_EIN_GZIP_HEADER_ZEITSTEMPEL_wird_gefangen(self):
        """The wrapper carries a clock even when every member inside is normalised."""
        d = acc.pruefe(self.sd(gzip_stempel_null=False))
        self.assertEqual(d["verdict"], acc.NOT_CANONICAL)
        self.assertTrue(any("gzip header timestamp" in f for f in d["findings"]))

    def test_UNSORTIERTE_MEMBER_werden_gefangen(self):
        d = acc.pruefe(self.sd(sortiert=False))
        self.assertEqual(d["verdict"], acc.NOT_CANONICAL)
        self.assertTrue(any("not sorted" in f for f in d["findings"]))

    def test_MEHRERE_DEFEKTE_werden_ALLE_genannt_nicht_nur_der_erste(self):
        """A checker that stops at the first finding hides the rest of the repair."""
        d = acc.pruefe(self.sd(mtimes_gleich=False, ids_null=False,
                               namen_leer=False, gzip_stempel_null=False))
        self.assertEqual(d["verdict"], acc.NOT_CANONICAL)
        self.assertGreaterEqual(len(d["findings"]), 4)


class TestDritterZustand(Basis):
    """NOT_APPLICABLE is not a pass — collapsing it into one is how a checker starts
    approving files it never opened."""

    def test_eine_unbekannte_form_ist_NICHT_ANWENDBAR_und_sagt_das(self):
        p = self.tmp / "something.bin"
        p.write_bytes(b"\x00\x01")
        d = acc.pruefe(p)
        self.assertEqual(d["verdict"], acc.NOT_APPLICABLE)
        self.assertIn("NOT a pass", d["reason"])

    def test_NICHT_ANWENDBAR_kann_den_rueckgabewert_aendern(self):
        """A verdict that cannot change an exit code is decoration."""
        p = self.tmp / "something.bin"
        p.write_bytes(b"\x00\x01")
        self.assertEqual(acc.main([str(p)]), 0)
        self.assertEqual(acc.main([str(p), "--require-applicable"]), 1)

    def test_eine_fehlende_datei_ist_NICHT_ANWENDBAR_kein_absturz(self):
        d = acc.pruefe(self.tmp / "gibt_es_nicht.whl")
        self.assertEqual(d["verdict"], acc.NOT_APPLICABLE)


class TestRueckgabewert(Basis):
    def test_ein_defektes_artefakt_ergibt_rueckgabewert_1(self):
        self.assertEqual(acc.main([str(self.whl(gleiche_stempel=False))]), 1)

    def test_ein_kanonisches_artefakt_ergibt_rueckgabewert_0(self):
        self.assertEqual(acc.main([str(self.whl(gleiche_stempel=True))]), 0)


class TestGateMetaTest(Basis):
    """Prove the cases would catch their defect if the checker lost the property."""

    def test_META_ohne_die_stempelpruefung_kommt_das_defekte_wheel_durch(self):
        quelle = SCRIPT.read_text(encoding="utf-8")
        mutiert = quelle.replace("    if len(stempel) != 1:", "    if False:")
        self.assertNotEqual(quelle, mutiert, "the mutation template no longer matches")
        ns = {"__name__": "acc_mutiert", "__file__": str(SCRIPT)}
        exec(compile(mutiert, "<mutiert: artifact_canonical_check.py>", "exec"), ns)
        p = self.whl(gleiche_stempel=False)
        self.assertEqual(acc.pruefe(p)["verdict"], acc.NOT_CANONICAL)
        self.assertEqual(ns["pruefe"](p)["verdict"], acc.CANONICAL,
                         "removing the check changed nothing — it was never binding")


if __name__ == "__main__":
    unittest.main(verbosity=2)
