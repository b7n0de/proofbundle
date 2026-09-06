#!/usr/bin/env python3
"""Der Registerkoerper wird gegen den ANKER geprueft, nicht gegen einen zweiten Pin (Teil F).

WAS HIER ABGESICHERT WIRD, und warum es eine eigene Datei bekommt. Bis zum 2026-09-06 gab es zwei
Quellen fuer dieselbe Frage „wer darf das Findings-Register beglaubigen":

  * ``audit_artifacts/readiness_trusted_pubkeys.txt`` — der Owner-autorisierte Anker, dessen Rolle
    ``readiness_und_register_signierer_600`` heisst und dessen private Haelfte laut Owner-Karte
    OA-e10ba2ba39 „beim Owner am Mac [bleibt], nichts davon auf dem Farmer";
  * ``scripts/findings_register.PINNED_PUBKEY_B64`` — eine Konstante mit einem ANDEREN Schluessel,
    dessen private Haelfte auf dem Bauhost lag.

Beide standen nebeneinander, und nichts verglich sie. Die Rollentabelle erteilte der Rolle
ausserdem nur ``{C6.2, C6.3, C8.2}`` — die Registerzeile C12.2 fehlte, obwohl der Owner-Satz drei
Zeilen darueber sie ausdruecklich nennt. Diese Tests halten beides fest, und zwar in beide
Richtungen: der richtige Schluessel wird angenommen, jeder andere abgewiesen, und eine unmessbare
Vertrauensbasis ergibt DATA_BLOCKED statt einer Freigabe.

DIE GEGENPROBE IST TEIL DES TESTS. Ein Riegel, der ALLES abweist, ist von einem funktionierenden
nicht zu unterscheiden — deshalb signiert jeder Negativfall gegen einen Positivfall mit demselben
Aufbau und nur einem geaenderten Stueck.
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for p in (REPO / "src", REPO / "scripts"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import findings_register as fr                      # noqa: E402
import audit_candidate_matrix as m                  # noqa: E402
from cryptography.hazmat.primitives import serialization        # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from proofbundle import canonical                   # noqa: E402

#: Der Schluessel, der hier FRUEHER gepinnt war. Er darf nie wieder autorisiert sein — sonst waere
#: die zweite Quelle unter anderem Namen zurueck.
FRUEHERER_PIN = "RJPyprKWbAUi0kTKNTLP6MESoz40dYNJDN1xxRNGv2o="


def _pub_b64(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)).decode("ascii")


def _register(key: Ed25519PrivateKey, *, version: str = "6.0.0", findings=None) -> dict:
    body = {
        "schema": "proofbundle.findings_register.v1",
        "version": version,
        "generated_at": "2026-09-06T00:00:00Z",
        "findings": findings if findings is not None else [
            {"id": "X-1", "severity": "P1", "status": "closed", "note": "ok"},
        ],
    }
    sig = key.sign(canonical.canonicalize_statement(body))
    out = dict(body)
    out["signature"] = {"alg": "ed25519", "public_key_b64": _pub_b64(key),
                        "sig_b64": base64.b64encode(sig).decode("ascii")}
    return out


def _repo_mit_register(tmp: Path, register: dict) -> Path:
    ziel = tmp / "repo"
    (ziel / "audit_artifacts").mkdir(parents=True, exist_ok=True)
    (ziel / fr.REGISTER_REL).write_text(json.dumps(register, indent=2) + "\n", encoding="utf-8")
    return ziel


class RegisterSchluesselKommtAusDemAnker(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.fremd = Ed25519PrivateKey.generate()

    # ── die Rollentabelle traegt die Owner-Politik ──────────────────────────────────────────────
    def test_die_rolle_autorisiert_auch_die_registerzeile(self):
        """Owner-Karte OA-e10ba2ba39: „… C6.2, C6.3, C8.2 und den Registerkoerper"."""
        rechte = m._ANKER_ROLLEN["readiness_und_register_signierer_600"]
        self.assertIn("C12.2", rechte,
                      "die Rolle verspricht im Namen und im Owner-Satz die Registersignatur; die "
                      "Tabelle muss sie auch erteilen")
        self.assertEqual(rechte, frozenset({"C6.2", "C6.3", "C8.2", "C12.2"}),
                         "keine weitere Befugnis — die Politik sagt ausdruecklich 'nichts sonst'")

    def test_findings_register_haelt_keinen_eigenen_pin_mehr(self):
        """Zwei Quellen fuer dieselbe Autorisierung sind eine zu viel."""
        self.assertFalse(hasattr(fr, "PINNED_PUBKEY_B64"),
                         "findings_register darf keine eigene Vertrauenskonstante mehr fuehren")

    # ── fail-closed in beide Richtungen ─────────────────────────────────────────────────────────
    def test_ohne_uebergebene_schluessel_ist_das_urteil_nein(self):
        with tempfile.TemporaryDirectory() as t:
            repo = _repo_mit_register(Path(t), _register(self.key))
            r = fr.verify_and_count(repo, expected_version="6.0.0")   # authorised_pubkeys fehlt
            self.assertFalse(r["ok"])
            self.assertIn(fr.CODE_REGISTER_UNAUTHORISED_KEY, r["reason"])
            self.assertIn("no authorised key set", r["reason"])

    def test_leerer_schluesselsatz_ist_ein_anderer_grund_als_gar_keiner(self):
        with tempfile.TemporaryDirectory() as t:
            repo = _repo_mit_register(Path(t), _register(self.key))
            r = fr.verify_and_count(repo, expected_version="6.0.0", authorised_pubkeys=set())
            self.assertFalse(r["ok"])
            self.assertIn("authorises no key", r["reason"],
                          "gemessen 'niemand' und 'nicht gebunden' sind zwei Zustaende, nicht einer")

    def test_ein_fremder_schluessel_wird_abgewiesen(self):
        with tempfile.TemporaryDirectory() as t:
            repo = _repo_mit_register(Path(t), _register(self.fremd))
            r = fr.verify_and_count(repo, expected_version="6.0.0",
                                    authorised_pubkeys={_pub_b64(self.key)})
            self.assertFalse(r["ok"])
            self.assertIn(fr.CODE_REGISTER_UNAUTHORISED_KEY, r["reason"])

    def test_der_frueher_gepinnte_schluessel_ist_nicht_mehr_autorisiert(self):
        """Regressionsriegel: die zweite Quelle darf nicht unter anderem Namen zurueckkommen."""
        with tempfile.TemporaryDirectory() as t:
            repo = _repo_mit_register(Path(t), _register(self.fremd))
            r = fr.verify_and_count(repo, expected_version="6.0.0",
                                    authorised_pubkeys={FRUEHERER_PIN})
            self.assertFalse(r["ok"],
                             "ein Register, das nur der alte Farmer-Schluessel traegt, ist kein Beleg")

    # ── und die Gegenprobe: der richtige Schluessel geht durch ──────────────────────────────────
    def test_der_autorisierte_schluessel_wird_angenommen(self):
        with tempfile.TemporaryDirectory() as t:
            repo = _repo_mit_register(Path(t), _register(self.key))
            r = fr.verify_and_count(repo, expected_version="6.0.0",
                                    authorised_pubkeys={_pub_b64(self.key)})
            self.assertTrue(r["ok"], f"der autorisierte Schluessel muss durchgehen: {r['reason']}")
            self.assertEqual(r["evaluated_count"], 1)

    def test_autorisiert_aber_falsche_version_bleibt_nein(self):
        """Die Autorisierung ersetzt die Versionsbindung nicht — beide muessen halten."""
        with tempfile.TemporaryDirectory() as t:
            repo = _repo_mit_register(Path(t), _register(self.key, version="3.6.1"))
            r = fr.verify_and_count(repo, expected_version="6.0.0",
                                    authorised_pubkeys={_pub_b64(self.key)})
            self.assertFalse(r["ok"])
            self.assertIn(fr.CODE_REGISTER_VERSION_MISMATCH, r["reason"])

    # ── unmessbare Vertrauensbasis ist DATA_BLOCKED, nie PASS ───────────────────────────────────
    def test_ohne_git_ist_die_vertrauensbasis_nicht_messbar_und_c12_2_blockt(self):
        with tempfile.TemporaryDirectory() as t:
            leer = Path(t) / "kein_repo"
            leer.mkdir()
            erlaubt, grund = m._autorisierte_schluessel(leer, "C12.2")
            self.assertIsNone(erlaubt, f"ohne git darf kein Schluesselsatz entstehen: {grund}")
            zustand, detail = m.c12_2_audit_pack_zero_p0p1(leer)
            self.assertEqual(zustand, m.DATA_BLOCKED, detail)
            self.assertNotEqual(zustand, m.PASS)

    def test_im_echten_baum_autorisiert_der_anker_genau_einen_schluessel(self):
        """Gegenprobe zum vorigen Test: hier IST etwas messbar, sonst misst der Riegel nichts."""
        erlaubt, grund = m._autorisierte_schluessel(REPO, "C12.2")
        self.assertIsNotNone(erlaubt, grund)
        self.assertEqual(len(erlaubt), 1, f"{grund}: erwartet genau der Owner-Ankerschluessel")
        self.assertNotIn(FRUEHERER_PIN, erlaubt)


class DerErzeugerLiestKeinenPrivatenSchluessel(unittest.TestCase):
    """Teil F, dritte Aenderung: die Registerzeremonie darf auf dem Bauhost keinen Schluessel lesen.

    Gemessen ueber den SYNTAXBAUM, nicht ueber eine Textsuche: eine Erwaehnung im Docstring ist
    kein Codepfad, und ein Verbot, das an einer Erwaehnung haengt, ist eine Attrappe. Dieselbe
    Bauform wie `tests/test_sdist_ohne_signierwerkzeug.py`, aus demselben Grund.
    """

    def test_gen_findings_register_laedt_keine_private_haelfte(self):
        import ast
        quelle = (REPO / "scripts" / "gen_findings_register.py").read_text(encoding="utf-8")
        baum = ast.parse(quelle)
        verboten = []
        for knoten in ast.walk(baum):
            if isinstance(knoten, ast.Attribute) and knoten.attr in (
                    "from_private_bytes", "generate", "private_bytes"):
                verboten.append(knoten.attr)
            if isinstance(knoten, ast.Name) and knoten.id == "Ed25519PrivateKey":
                verboten.append("Ed25519PrivateKey")
        self.assertEqual(verboten, [],
                         "kein Codepfad in der Registerzeremonie darf eine private Haelfte lesen "
                         f"oder erzeugen — gefunden: {sorted(set(verboten))}")


if __name__ == "__main__":
    unittest.main()
