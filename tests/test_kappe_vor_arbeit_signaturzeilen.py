"""Die Kappe läuft VOR der Arbeit — auch auf der C2SP-Notenfamilie und dem tlog-proof-Parser.

DIE KLASSE (Deep-Gate 6.0.0, Lauf 3, Funde L2-BDOS-C2SP-SIGLINES-01 P2 und L2-BDOS-TLOGPROOF-MERKLEPATH-INERT-01
P3; Ledger ``class_fix_landed_on_one_driver_siblings_kept_the_pre_fix_shape``). Das ``signatures``-Budget (Finding
15b) sass auf DSSE und trust_pack, die Signaturzeilen-Schleifen von ``verify_checkpoint`` und
``verify_cosignature`` hatten keine Zählkappe: eine 8-MiB-Note mit 74234 Zeilen für die keyID des eigenen vkey
trieb ~74k Ed25519-Prüfungen (gemessen 9,9 s, x63753 gegenüber der echten Note) — über die
angreifer-kontrollierte Datei ``verify-proof``. Und die ``merkle_path``-Kappe (Owner-Entscheid 2026-08-18, drei
Treiber) fehlte auf dem vierten Geschwister ``parse_tlog_proof``: 186408 Beweiszeilen wurden dekodiert, bevor
irgendetwas ablehnte.

WARUM DIE AUFRUFZAHL GEMESSEN WIRD UND NICHT DIE ZEIT: eine Zeit hängt an Last und Maschine; die Zahl der
``verify_ed25519``- bzw. ``_b64d``-Aufrufe vor der Ablehnung ist die Größe, um die es geht — wurde die Arbeit
geleistet, bevor abgelehnt wurde? Gemessen vor dem Fix: 74234 Verifikationen, 186408 Dekodierungen. Danach: 0.

MESSMETHODE des Funds, übernommen: kanonisch geformte Müll-Signaturen (R ein gültiger Punkt, S < L), damit
der TEURE Pfad läuft; Zufallsbytes werden in ~94 % der Fälle vor jeder Punktarithmetik verworfen und messen
die Kappe daher nicht.

DREI TEILE: Verhalten (Kappe greift, 0 Aufrufe) · Anti-Parität (genau an der Kappe wird verifiziert, die echte
Note und der echte Beweis bleiben gut) · Anti-Tautologie (mit gehobener Kappe werden die Aufrufe gezählt — das
Orakel hängt an der Kappe, nicht an der Ablehnung).
"""
from __future__ import annotations

import base64
import os
import unittest
from unittest import mock

from proofbundle import checkpoint, tlogproof
from proofbundle.budget import DEFAULT_BUDGET, VerificationBudget
from proofbundle.emit import emit_bundle, generate_signer
from proofbundle.errors import BundleFormatError

NAME = "log.example/x"
WNAME = "w.example/w"


def _raw(key):
    return key.public_key().public_bytes_raw()


class _Fixture:
    def __init__(self):
        self.log = generate_signer()
        self.bundle = emit_bundle(b'{"hello":"world"}', self.log, prior_leaves=[b"a", b"b", b"c"])
        root = base64.b64decode(self.bundle["merkle"]["root_b64"])
        self.note = checkpoint.sign_checkpoint(NAME, self.bundle["merkle"]["tree_size"], root, self.log, NAME)
        self.note_text = self.note.split("\n\n", 1)[0] + "\n"
        self.real_line = self.note.split("\n\n", 1)[1]
        self.vkey = checkpoint.vkey(NAME, _raw(self.log))
        self.kid = checkpoint.key_id(NAME, _raw(self.log))
        self.witness = generate_signer()
        self.wvkey = checkpoint.cosign_vkey(WNAME, _raw(self.witness))
        self.wkid = checkpoint.cosign_key_id(WNAME, _raw(self.witness))
        self.payload = base64.b64decode(self.bundle["payload_b64"])

    def _garbage(self, pub):
        s = bytearray(os.urandom(32))
        s[31] &= 0x0F                      # S < 2^252 < L: kanonisch geformt, teurer Pfad
        return pub + bytes(s)

    def log_line(self):
        return f"{checkpoint.EM_DASH} {NAME} {base64.b64encode(self.kid + self._garbage(_raw(self.log))).decode()}\n"

    def cosig_line(self):
        blob = self.wkid + (1).to_bytes(8, "big") + self._garbage(_raw(self.witness))
        return f"{checkpoint.EM_DASH} {WNAME} {base64.b64encode(blob).decode()}\n"

    def hostile_note(self, n):
        return self.note_text + "\n" + "".join(self.log_line() for _ in range(n))

    def hostile_cosigned(self, n):
        return self.note + "".join(self.cosig_line() for _ in range(n))


class _Zaehler:
    """Zählt die Ed25519-Verifikationen im Modul checkpoint."""

    def __init__(self):
        self.n = 0

    def __enter__(self):
        self._orig = checkpoint.verify_ed25519

        def zaehl(*a, **k):
            self.n += 1
            return self._orig(*a, **k)
        checkpoint.verify_ed25519 = zaehl
        return self

    def __exit__(self, *_):
        checkpoint.verify_ed25519 = self._orig


class DieKappeGreiftVorDerErstenVerifikation(unittest.TestCase):

    def setUp(self):
        self.f = _Fixture()
        self.ueber = DEFAULT_BUDGET.signatures + 1

    def test_log_signaturzeilen_ueber_der_kappe_typisiert_ohne_arbeit(self):
        with _Zaehler() as z:
            with self.assertRaises(BundleFormatError) as cm:
                checkpoint.verify_checkpoint(self.f.hostile_note(self.ueber), self.f.vkey)
        self.assertEqual(z.n, 0, f"{z.n} Verifikationen VOR der Ablehnung — die Kappe läuft nach der Arbeit")
        self.assertIn("signature lines", str(cm.exception))
        self.assertIn("before any signature", str(cm.exception))

    def test_cosignaturzeilen_ueber_der_kappe_typisiert_ohne_arbeit(self):
        with _Zaehler() as z:
            with self.assertRaises(BundleFormatError):
                checkpoint.verify_cosignature(self.f.hostile_cosigned(self.ueber), self.f.wvkey)
        self.assertEqual(z.n, 0)

    def test_witnessed_checkpoint_ueber_der_kappe(self):
        with _Zaehler() as z:
            with self.assertRaises(BundleFormatError):
                checkpoint.verify_witnessed_checkpoint(self.f.hostile_cosigned(self.ueber), self.f.vkey,
                                                       [self.f.wvkey], threshold=1)
        self.assertEqual(z.n, 0)

    def test_die_never_raise_flaeche_liefert_ein_fail_closed_verdikt(self):
        """Über verify-proof kommt die Note als Fremddatei an: Verdikt, keine Ausnahme, keine Arbeit."""
        proof = tlogproof.format_tlog_proof(
            self.f.bundle["merkle"]["leaf_index"],
            [base64.b64decode(p) for p in self.f.bundle["merkle"]["inclusion_proof_b64"]],
            self.f.hostile_note(self.ueber))
        with _Zaehler() as z:
            r = tlogproof.verify_tlog_proof(proof, self.f.payload, self.f.vkey)
        self.assertIs(r["ok"], False)
        self.assertIn("signature lines", r["detail"])
        self.assertEqual(z.n, 0)

    def test_ein_roster_ueber_dem_witnesses_budget_faellt_vor_dem_scan(self):
        roster = [self.f.wvkey] * (DEFAULT_BUDGET.witnesses + 1)
        with _Zaehler() as z:
            with self.assertRaises(BundleFormatError):
                checkpoint.verify_witnessed_checkpoint(self.f.note, self.f.vkey, roster, threshold=1)
        self.assertEqual(z.n, 1, "nur die Log-Signatur wurde geprüft, kein einziger Zeugen-Scan")


class DerBeweisParserDekodiertNichtVorDerKappe(unittest.TestCase):

    def setUp(self):
        self.f = _Fixture()
        self.line = base64.b64encode(b"\1" * 32).decode()

    def _proof(self, n):
        return f"{tlogproof.MAGIC}\nindex 0\n" + (self.line + "\n") * n + "\n" + self.f.note

    def test_zu_viele_beweiszeilen_typisiert_vor_dem_dekodieren(self):
        n = DEFAULT_BUDGET.merkle_path + 44
        with mock.patch.object(tlogproof, "_b64d", wraps=tlogproof._b64d) as dec:
            with self.assertRaises(BundleFormatError) as cm:
                tlogproof.parse_tlog_proof(self._proof(n))
        self.assertEqual(dec.call_count, 0, f"{dec.call_count} Dekodierungen vor der Ablehnung")
        self.assertIn("refused before decoding", str(cm.exception))

    def test_verify_tlog_proof_liefert_verdikt_ohne_dekodieren(self):
        n = DEFAULT_BUDGET.merkle_path + 44
        with mock.patch.object(tlogproof, "_b64d", wraps=tlogproof._b64d) as dec:
            r = tlogproof.verify_tlog_proof(self._proof(n), self.f.payload, self.f.vkey)
        self.assertIs(r["ok"], False)
        self.assertIs(r["inclusion_ok"], False)
        self.assertEqual(dec.call_count, 0)

    def test_die_kappe_ist_ohne_die_arbeit_berechenbar(self):
        """Owner-Ausnahme prüfen statt annehmen: die Zeilenzahl IST die Schrittzahl."""
        n = 8
        parsed = tlogproof.parse_tlog_proof(self._proof(n))
        self.assertEqual(len(parsed["proof"]), n)


class DieVerdikteAendernSichNicht(unittest.TestCase):
    """ANTI-PARITÄT: genau an der Kappe wird verifiziert; echte Noten und Beweise bleiben gut."""

    def setUp(self):
        self.f = _Fixture()

    def test_genau_an_der_kappe_wird_die_echte_zeile_noch_gefunden(self):
        n = DEFAULT_BUDGET.signatures - 1
        note = self.f.note_text + "\n" + "".join(self.f.log_line() for _ in range(n)) + self.f.real_line
        with _Zaehler() as z:
            r = checkpoint.verify_checkpoint(note, self.f.vkey)
        self.assertIs(r["ok"], True)
        self.assertEqual(z.n, DEFAULT_BUDGET.signatures, "unter der Kappe wird jede Zeile geprüft")

    def test_die_echte_note_und_der_echte_beweis_bleiben_gut(self):
        self.assertTrue(checkpoint.verify_checkpoint(self.f.note, self.f.vkey)["ok"])
        cosigned = checkpoint.cosign_checkpoint(self.f.note, self.f.witness, WNAME, 1_780_000_000)
        self.assertTrue(checkpoint.verify_cosignature(cosigned, self.f.wvkey)["ok"])
        proof = tlogproof.tlog_proof_for_bundle(self.f.bundle, cosigned)
        r = tlogproof.verify_tlog_proof(proof, self.f.payload, self.f.vkey, [self.f.wvkey], threshold=1)
        self.assertTrue(r["ok"], r)

    def test_ein_beweis_unter_der_kappe_wird_normal_dekodiert(self):
        FEST = 64
        self.assertLess(FEST, DEFAULT_BUDGET.merkle_path)
        line = base64.b64encode(b"\1" * 32).decode()
        text = f"{tlogproof.MAGIC}\nindex 0\n" + (line + "\n") * FEST + "\n" + self.f.note
        with mock.patch.object(tlogproof, "_b64d", wraps=tlogproof._b64d) as dec:
            tlogproof.parse_tlog_proof(text)
        self.assertGreaterEqual(dec.call_count, FEST)


class DasOrakelHaengtAnDerKappe(unittest.TestCase):
    """ANTI-TAUTOLOGIE: mit gehobener Kappe (gepflanzter Defekt) MUSS der Zähler wieder Arbeit sehen."""

    def test_ohne_kappe_wird_wieder_verifiziert(self):
        f = _Fixture()
        n = 600
        ohne_kappe = VerificationBudget(signatures=10 ** 9)
        with mock.patch.object(checkpoint, "DEFAULT_BUDGET", ohne_kappe):
            with _Zaehler() as z:
                r = checkpoint.verify_checkpoint(f.hostile_note(n), f.vkey)
        self.assertIs(r["ok"], False)
        self.assertEqual(z.n, n, "der gepflanzte Defekt (keine Kappe) wird vom Zähler nicht gesehen — "
                                 "dann misst der Test oben nichts")

    def test_ohne_kappe_wird_wieder_dekodiert(self):
        f = _Fixture()
        n = DEFAULT_BUDGET.merkle_path + 44
        line = base64.b64encode(b"\1" * 32).decode()
        text = f"{tlogproof.MAGIC}\nindex 0\n" + (line + "\n") * n + "\n" + f.note
        ohne_kappe = VerificationBudget(merkle_path=10 ** 9)
        with mock.patch.object(tlogproof, "DEFAULT_BUDGET", ohne_kappe):
            with mock.patch.object(tlogproof, "_b64d", wraps=tlogproof._b64d) as dec:
                tlogproof.parse_tlog_proof(text)
        self.assertGreaterEqual(dec.call_count, n)


if __name__ == "__main__":
    unittest.main()
