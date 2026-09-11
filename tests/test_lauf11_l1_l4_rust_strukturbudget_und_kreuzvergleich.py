"""Beide Verifizierer urteilen über dieselbe Datei gleich — auch an der Budget-Achse.

WAS HIER GESCHLOSSEN WIRD, zwei Funde aus Deep Gate Lauf 11:

`LAUF11-L1` (P0): der unabhängige Rust-Zweitverifizierer hatte **kein** Strukturbudget. Ein
echtes, RFC-8785-kanonisches, gültig signiertes DSSE-Ziel mit einem Feld über 1 MB: Python bricht
mit `exit 2` ab (`verification budget exceeded: string_len = 1333724 > limit 1000000`), Rust
meldete `exit 0` und `{"lineage":"VERIFIED"}`. Gemessen war auch die Ursache:
`grep -cEi 'budget|json_nodes|json_depth|string_len|input_bytes'` über `main.rs` → **0**, und
`read_file` war ein nacktes `std::fs::read`.

`LAUF11-L4` (P1): der Kreuzvergleich schwieg über die Fläche, die er prüfen soll — eine
eingepflanzte Regression der gerade geschlossenen Klasse liess `crosscheck.py` weiter
`CROSS-IMPL OK` melden, weil für diese Fläche kein Vektor im Korpus stand. Dritte Ausprägung
derselben Klasse: **ein Kreuzvergleich ohne Vektor für eine Fläche schweigt über sie.**

WARUM BEIDE IN EINER DATEI STEHEN: sie sind dieselbe Sache von zwei Seiten. L1 ist die Divergenz,
L4 ist der Grund, warum niemand sie gemeldet hat. Ein Budget-Fix in Rust ohne Vektor im
Kreuzvergleich wäre beim nächsten Auseinanderlaufen wieder still.

DIE ZAHLEN DÜRFEN NICHT DRIFTEN, und das wird an dem gemessen, was der Binary WIRKLICH benutzt:
`pb_verify_rs budget` gibt seine Grenzen aus, nicht sein Quelltext-Kommentar.
"""
from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _lastdeckel import gedeckelt  # noqa: E402 — LAUF11-L3, eigene Testlast gedeckelt

REPO = Path(__file__).resolve().parent.parent
RUST_DIR = REPO / "tools" / "pb_verify_rs"
RUST_BIN = RUST_DIR / "target" / "release" / "pb_verify_rs"


def _binary():
    if RUST_BIN.exists():
        return RUST_BIN
    if not RUST_DIR.is_dir() or shutil.which("cargo") is None:
        return None
    b = subprocess.run(["cargo", "build", "--release"], cwd=RUST_DIR,  # noqa: S603,S607
                       capture_output=True, text=True, timeout=1800)
    return RUST_BIN if b.returncode == 0 and RUST_BIN.exists() else None


class TestBudgetParitaet(unittest.TestCase):
    """Die Budget-Achse: dieselbe Datei, dasselbe Urteil."""

    @classmethod
    def setUpClass(cls):
        cls.rust = _binary()
        if cls.rust is None:
            raise unittest.SkipTest("NOT MEASURABLE: tools/pb_verify_rs fehlt oder cargo ist nicht "
                                    "da — die Differentialprobe lief NICHT (env_blocked, nie grün)")

    def _signiertes_ziel(self, zusatz: str | None = None):
        from proofbundle.dsse import sign_envelope
        from proofbundle.emit import generate_signer
        signer = generate_signer()
        pub = signer.public_key().public_bytes_raw()
        koerper = {"a": 1, "body": "laenger, damit padding entsteht"}
        if zusatz is not None:
            koerper["gross"] = zusatz
        env = sign_envelope(json.dumps(koerper).encode(), signer,
                            payload_type="application/vnd.test")
        return env, base64.b64encode(pub).decode("ascii")

    def _rust_urteil(self, env, pub_b64):
        with tempfile.TemporaryDirectory() as d:
            fp = Path(d) / "env.json"
            fp.write_text(json.dumps(env), encoding="utf-8")
            p = subprocess.run([str(self.rust), "verify-dsse", str(fp), pub_b64],  # noqa: S603
                               capture_output=True, text=True, timeout=120)
            return p.returncode, (p.stdout + p.stderr).strip()

    def _python_urteil(self, env, pub_b64):
        from proofbundle.dsse import verify_envelope
        try:
            return bool(verify_envelope(env, base64.b64decode(pub_b64))), ""
        except Exception as exc:  # noqa: BLE001 — eine typisierte Abweisung ist ein Urteil
            return False, f"{type(exc).__name__}: {exc}"

    def test_anti_paritaet_das_saubere_ziel_verifiziert_in_beiden(self):
        """ZUERST: ohne diese Zeile bestünde ein Rust-Binary, das ALLES abweist, jede Probe unten."""
        env, pub = self._signiertes_ziel()
        rc, aus = self._rust_urteil(env, pub)
        self.assertEqual(rc, 0, f"Kontrolle gefallen, Rust weist das saubere Ziel ab: {aus}")
        ok, grund = self._python_urteil(env, pub)
        self.assertTrue(ok, f"Kontrolle gefallen, Python weist das saubere Ziel ab: {grund}")

    def test_ein_feld_ueber_der_schranke_wird_von_BEIDEN_abgewiesen(self):
        """DER FUND. Dasselbe gültig signierte Ziel, ein Feld über `string_len` — beide Instanzen
        müssen dasselbe sagen. Vorher: Python exit 2, Rust exit 0 VERIFIED."""
        env, pub = self._signiertes_ziel("x" * 1_333_724)
        py_ok, py_grund = self._python_urteil(env, pub)
        rc, rust_aus = self._rust_urteil(env, pub)
        self.assertFalse(py_ok, "Vorbedingung verfehlt: Python nimmt das Ziel an")
        self.assertNotEqual(
            rc, 0,
            "der unabhängige Zweitverifizierer bestätigt ein Ziel, das die Referenzimplementierung "
            f"aus Sicherheitsgründen gar nicht prüft — genau die Divergenz, die eine unabhängige "
            f"Instanz wertlos macht (Python: {py_grund!r}, Rust: exit {rc} {rust_aus!r})")
        self.assertIn("budget", rust_aus.lower(),
                      f"Rust weist ab, aber nicht wegen des Budgets: {rust_aus!r}")

    def test_die_grenzen_beider_seiten_sind_dieselben(self):
        """Gegen die Drift, und gemessen am BINARY statt am Quelltext."""
        from proofbundle.budget import DEFAULT_BUDGET
        p = subprocess.run([str(self.rust), "budget"], capture_output=True,  # noqa: S603
                           text=True, timeout=60)
        self.assertEqual(p.returncode, 0, f"`pb_verify_rs budget` scheitert: {p.stderr!r}")
        rust = json.loads(p.stdout)
        abweichungen = []
        for dim, wert in sorted(rust.items()):
            py = getattr(DEFAULT_BUDGET, dim, None)
            if py != wert:
                abweichungen.append(f"{dim}: rust={wert:,} python={py}")
        self.assertEqual(
            abweichungen, [],
            "die beiden Verifizierer tragen verschiedene Schranken — dieselbe Datei bekommt damit "
            "zwei Urteile, und welches gilt, entscheidet der Zufall der Aufrufreihenfolge:\n  "
            + "\n  ".join(abweichungen))
        self.assertGreaterEqual(len(rust), 4, "der Binary nennt weniger Achsen als erwartet")

    def test_eine_zu_tiefe_verschachtelung_wird_von_BEIDEN_abgewiesen(self):
        """Die zweite Achse, damit der Fix nicht an einer einzigen Dimension hängt."""
        from proofbundle.budget import DEFAULT_BUDGET
        tiefe = gedeckelt(DEFAULT_BUDGET.json_depth, bytes_je_element=2) + 5
        roh = ("[" * tiefe) + "1" + ("]" * tiefe)
        with tempfile.TemporaryDirectory() as d:
            fp = Path(d) / "tief.json"
            fp.write_text(roh, encoding="utf-8")
            p = subprocess.run([str(self.rust), "strict-parse", str(fp)],  # noqa: S603
                               capture_output=True, text=True, timeout=120)
        self.assertNotEqual(p.returncode, 0,
                            "Rust nimmt ein Dokument an, dessen Verschachtelung über der Schranke "
                            f"liegt (Tiefe {tiefe} > {DEFAULT_BUDGET.json_depth})")


class TestKreuzvergleichHatEinenNegativenVektor(unittest.TestCase):
    """L4: der Kreuzvergleich muss die Fläche kennen, über die er urteilt."""

    def test_crosscheck_traegt_einen_budget_vektor(self):
        """Ein Kreuzvergleich ohne Vektor für eine Fläche schweigt über sie — gemessen in Lauf 11
        an einer eingepflanzten Regression, die `CROSS-IMPL OK` überlebte. Der Vektor ist der
        Unterschied zwischen 'die Flächen stimmen überein' und 'die Flächen, die ich kenne,
        stimmen überein'."""
        quelle = (RUST_DIR / "crosscheck.py").read_text(encoding="utf-8")
        self.assertIn("budget", quelle.lower(),
                      "crosscheck.py kennt die Budget-Achse nicht — ein Auseinanderlaufen der "
                      "Schranken wäre für den Kreuzvergleich unsichtbar")
        self.assertIn("LAUF11-L4", quelle,
                      "der negative Vektor trägt keine Kennung — dann ist beim nächsten Lesen "
                      "nicht erkennbar, welche Klasse er offenhält")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
