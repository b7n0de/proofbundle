"""Catch-proofs for scripts/receipt_anchor.py — register entry N22.

The property under test is NOT "the tool runs". It is that the tool separates three
questions a single boolean would collapse: does the proof bind THESE bytes, what does
it attest, and is that attestation confirmed. Every earlier defect in this repository
of the same shape came from answering three questions with one word.

No network. `verify` is pure; `attach` is exercised only in its dry-run form.
"""
import importlib.util
import shutil
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "receipt_anchor.py"
ECHT = REPO / "receipts" / "agent_review" / "inspect_ai_5141.r3.receipt.json"
# a proof that really carries a bitcoin block attestation, from the conformance corpus
BESTAETIGT = REPO / "conformance" / "decision" / "crossimpl" / "confirmed-anchor-lifecycle" / "decision_receipt.jcs"


def _laden():
    spec = importlib.util.spec_from_file_location("receipt_anchor_ut", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["receipt_anchor_ut"] = mod
    spec.loader.exec_module(mod)
    return mod


try:
    ra = _laden()
    TRAGFAEHIG = True
except SystemExit:
    TRAGFAEHIG = False


@unittest.skipUnless(TRAGFAEHIG, "opentimestamps not importable on this measuring surface")
class TestAnkerPruefung(unittest.TestCase):
    def _kopie(self, quittung: Path, ziel: Path) -> Path:
        """Copy a receipt AND its anchor into a throwaway tree.

        Deliberately a real copy on disk, not a patched attribute: a catch-proof that
        sets state instead of walking the path proves nothing. That lesson cost this
        repository a whole night (register entry S59).
        """
        ziel.mkdir(parents=True, exist_ok=True)
        neu = ziel / quittung.name
        shutil.copy2(quittung, neu)
        alt_anker = quittung.with_name(quittung.name + ".ots")
        if alt_anker.is_file():
            shutil.copy2(alt_anker, neu.with_name(neu.name + ".ots"))
        return neu

    def test_der_unveraenderte_fall_bindet_und_ist_PENDING(self):
        """Control. Without it a red result proves nothing — everything could be red."""
        r = ra.verify(ECHT)
        self.assertTrue(r["binds_these_bytes"], r["reason"])
        self.assertEqual(r["verdict"], ra.PENDING, r["reason"])

    def test_EIN_GEKIPPTES_BYTE_DER_QUITTUNG_wird_GEFANGEN(self):
        """The catch-proof the order asks for: a tampered subject must not verify."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            q = self._kopie(ECHT, Path(tmp) / "fall")
            roh = bytearray(q.read_bytes())
            stelle = len(roh) // 2
            roh[stelle] ^= 0x01           # exactly one bit
            q.write_bytes(bytes(roh))
            r = ra.verify(q)
            self.assertFalse(r["binds_these_bytes"])
            self.assertEqual(r["verdict"], ra.BROKEN)
            self.assertIn("other bytes", r["reason"])

    def test_EIN_MANIPULIERTER_TOKEN_wird_GEFANGEN(self):
        """The other direction: the receipt is honest, the ANCHOR was swapped."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            q = self._kopie(ECHT, Path(tmp) / "fall")
            anker = q.with_name(q.name + ".ots")
            roh = bytearray(anker.read_bytes())
            roh[40] ^= 0xFF               # inside the committed digest region
            anker.write_bytes(bytes(roh))
            r = ra.verify(q)
            self.assertEqual(r["verdict"], ra.BROKEN, r["reason"])

    def test_ein_unlesbarer_anker_ist_BROKEN_nicht_ABSENT(self):
        """A file that is there and unreadable is not the same state as no file.

        Collapsing the two is exactly the class this register keeps finding: absence
        and present-and-wrong must never share a verdict.
        """
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            q = self._kopie(ECHT, Path(tmp) / "fall")
            q.with_name(q.name + ".ots").write_bytes(b"this is not an OTS proof")
            r = ra.verify(q)
            self.assertEqual(r["verdict"], ra.BROKEN)
            self.assertIn("not a readable OTS proof", r["reason"])

    def test_ohne_anker_ist_ABSENT_und_das_ist_kein_bestehen(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            z = Path(tmp) / "fall"
            z.mkdir()
            q = z / ECHT.name
            shutil.copy2(ECHT, q)          # receipt only, no anchor
            r = ra.verify(q)
            self.assertEqual(r["verdict"], ra.ABSENT)
            self.assertIsNone(r["binds_these_bytes"])

    @unittest.skipUnless(BESTAETIGT.is_file(), "confirmed fixture not in this tree")
    def test_eine_BESTAETIGTE_attestierung_ergibt_OK_mit_blockhoehe(self):
        """PENDING must be distinguishable from OK by a real confirmed proof.

        Without this case the tool could report PENDING for everything and stay green.
        """
        r = ra.verify(BESTAETIGT)
        self.assertEqual(r["verdict"], ra.OK, r["reason"])
        self.assertIsInstance(r["confirmed_height"], int)
        self.assertGreater(r["confirmed_height"], 0)

    def test_PENDING_ist_kein_OK_und_der_schalter_beweist_es(self):
        """A verdict that cannot change the exit code is decoration."""
        self.assertEqual(ra.main(["verify", str(ECHT)]), 0)
        self.assertEqual(ra.main(["verify", str(ECHT), "--require-confirmed"]), 1)

    def test_attach_ohne_submit_sendet_NICHTS_und_schreibt_NICHTS(self):
        """Outward-facing by default would be the defect, not the feature."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            z = Path(tmp) / "fall"
            z.mkdir()
            q = z / "neu.json"
            q.write_text('{"a":1}')
            rc = ra.attach(q, submit=False, timeout=1)
            self.assertEqual(rc, 0)
            self.assertFalse(ra.anchor_path(q).exists(),
                             "a dry run must not leave a file behind")

    def test_attach_verweigert_das_ueberschreiben_eines_vorhandenen_ankers(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            q = self._kopie(ECHT, Path(tmp) / "fall")
            self.assertEqual(ra.attach(q, submit=True, timeout=1), 1,
                             "an existing anchor must never be silently replaced")


@unittest.skipUnless(TRAGFAEHIG, "opentimestamps not importable")
class TestGateMetaTest(unittest.TestCase):
    """Prove the cases above would actually catch a defect of their class.

    A test suite that passes over a broken checker is the silent failure this repository
    has paid for repeatedly. So: plant the defect, count what falls, announce first.
    """

    def test_META_ohne_die_bindungspruefung_faellt_genau_der_fangnachweis(self):
        import tempfile
        quelle = SCRIPT.read_text(encoding="utf-8")
        # the mutation: accept any proof as binding, the exact defect the case guards
        mutiert = quelle.replace(
            'out["binds_these_bytes"] = digest_in_proof == out["receipt_sha256"]',
            'out["binds_these_bytes"] = True',
        )
        self.assertNotEqual(quelle, mutiert, "the mutation template no longer matches")
        ns: dict = {"__name__": "receipt_anchor_mutiert"}
        exec(compile(mutiert, "<mutiert: receipt_anchor.py>", "exec"), ns)
        with tempfile.TemporaryDirectory() as tmp:
            z = Path(tmp) / "fall"
            z.mkdir()
            q = z / ECHT.name
            shutil.copy2(ECHT, q)
            shutil.copy2(ECHT.with_name(ECHT.name + ".ots"), q.with_name(q.name + ".ots"))
            roh = bytearray(q.read_bytes())
            roh[len(roh) // 2] ^= 0x01
            q.write_bytes(bytes(roh))
            # clean tool: BROKEN. mutated tool: waves the tampered receipt through.
            self.assertEqual(ra.verify(q)["verdict"], ra.BROKEN)
            self.assertNotEqual(ns["verify"](q)["verdict"], ra.BROKEN,
                                "the mutation had no effect — then the case binds nothing")


if __name__ == "__main__":
    unittest.main(verbosity=2)
