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
from _lastdeckel import KOSTEN_JE_ELEMENT, gedeckelt  # noqa: E402 — LAUF11-L3, eigene Testlast gedeckelt

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
        # DIE MENGE, nicht nur die Werte (LAUF12-L1 F1/F2, zwei P0): `signatures` und `witnesses`
        # setzt Python auf Pfaden durch, die dieser Binary AUCH faehrt (DSSE-Umschlag, Trust Pack) —
        # und er kannte sie nicht. Ein Vergleich, der nur ueber die Achsen laeuft, die Rust nennt,
        # kann eine fehlende Achse nicht sehen; deshalb wird hier die Menge festgehalten.
        gemeinsam = {"input_bytes", "json_nodes", "json_depth", "string_len", "signatures", "witnesses"}
        self.assertEqual(
            set(rust), gemeinsam,
            f"der Binary setzt nicht genau die Achsen der gemeinsamen Pfade durch — fehlt: "
            f"{sorted(gemeinsam - set(rust))}, zu viel: {sorted(set(rust) - gemeinsam)}")

    def test_zu_viele_signaturen_werden_von_BEIDEN_abgewiesen(self):
        """LAUF12-L1 F1 (P0, ausgefuehrt): ein gueltig signiertes Ziel plus 512 Muell-Eintraege in
        `signatures` — Python fail-closed (601 > 512), Rust verifizierte mit exit 0."""
        from proofbundle.budget import DEFAULT_BUDGET
        env, pub = self._signiertes_ziel()
        env["signatures"] = list(env["signatures"]) + [{"sig": "AA=="}] * gedeckelt(DEFAULT_BUDGET.signatures, bytes_je_element=KOSTEN_JE_ELEMENT["signatures"])
        py_ok, py_grund = self._python_urteil(env, pub)
        rc, rust_aus = self._rust_urteil(env, pub)
        self.assertFalse(py_ok, "Vorbedingung verfehlt: Python nimmt das Ziel mit 513 Signaturen an")
        self.assertNotEqual(rc, 0, f"Rust verifiziert ein Ziel mit {len(env['signatures'])} Signaturen, "
                                   f"das Python abweist ({py_grund}) — Rust: {rust_aus!r}")
        self.assertIn("signatures", rust_aus.lower(), f"Rust weist ab, aber nicht an der Achse: {rust_aus!r}")

    def test_genau_die_schranke_bleibt_in_beiden_erlaubt(self):
        """Gegenrichtung: genau 512 Signaturen sind erlaubt — ein Fix, der die Schranke um eins
        verschiebt, faellt hier. Die Zusatzeintraege sind Muell; Python urteilt dann 'nicht
        verifiziert' (False, keine Budget-Abweisung), Rust muss dasselbe sagen."""
        from proofbundle.budget import DEFAULT_BUDGET
        env, pub = self._signiertes_ziel()
        env["signatures"] = list(env["signatures"]) + [{"sig": "AA=="}] * (gedeckelt(DEFAULT_BUDGET.signatures, bytes_je_element=KOSTEN_JE_ELEMENT["signatures"]) - 1)
        self.assertEqual(len(env["signatures"]), DEFAULT_BUDGET.signatures)
        py_ok, py_grund = self._python_urteil(env, pub)
        self.assertNotIn("budget", py_grund.lower(), f"Python weist genau die Schranke ab: {py_grund}")
        rc, rust_aus = self._rust_urteil(env, pub)
        self.assertNotIn("budget", rust_aus.lower(), f"Rust weist genau die Schranke ab: {rust_aus!r}")

    def test_zu_viele_zeugen_werden_von_BEIDEN_abgewiesen(self):
        """LAUF12-L1 F2 (P0, ausgefuehrt): ein Trust Pack mit 257 root-keyIds (Limit 256) — Python
        structure_ok=false, Rust `root_threshold_met=true`."""
        from datetime import datetime, timedelta, timezone
        from proofbundle import dsse
        from proofbundle.budget import DEFAULT_BUDGET
        from proofbundle.emit import generate_signer
        import hashlib
        from proofbundle.trust_pack import (INTOTO_STATEMENT_PAYLOAD_TYPE, STATEMENT_TYPE,
                                            TRUST_PACK_PREDICATE_TYPE, _rfc8785_bytes, verify_trust_pack)
        n = gedeckelt(DEFAULT_BUDGET.witnesses, bytes_je_element=KOSTEN_JE_ELEMENT["witnesses"]) + 1
        # 257 VERSCHIEDENE Schluessel: die einzige Abweichung vom gueltigen Pack ist die Zahl. Signiert
        # wird ohne `sign_trust_pack`, denn der Python-Signierer weist das Pack selbst ab (Budget +
        # Sybil) — ein Vektor, den die Referenz nicht erzeugen kann, muss von Hand gebaut werden.
        signer = [generate_signer() for _ in range(n)]
        pubs = {f"w{i}": base64.b64encode(s.public_key().public_bytes_raw()).decode() for i, s in enumerate(signer)}
        exp = (datetime.now(timezone.utc) + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
        pred = {"schemaVersion": "0.1.0", "trustPackId": "tp-witnesses-l1", "version": 1,
                "expires": exp, "prevVersionDigest": None,
                "roles": {"root": {"keyIds": list(pubs), "threshold": 2}},
                "keys": {kid: {"publicKey": pk} for kid, pk in pubs.items()},
                "nonClaims": ["budget vector: more root keyIds than the witnesses budget admits"]}
        # Auch `build_trust_pack_statement` validiert und wirft — das Statement entsteht hier in
        # derselben Form von Hand (Subjekt = sha256 des kanonischen Praedikats).
        statement = {"_type": STATEMENT_TYPE,
                     "subject": [{"name": "trust-pack:tp-witnesses-l1:v1",
                                  "digest": {"sha256": hashlib.sha256(_rfc8785_bytes(pred)).hexdigest()}}],
                     "predicateType": TRUST_PACK_PREDICATE_TYPE, "predicate": pred}
        body = _rfc8785_bytes(statement)
        msg = dsse.pae(INTOTO_STATEMENT_PAYLOAD_TYPE, body)
        env = {"payload": base64.b64encode(body).decode("ascii"), "payloadType": INTOTO_STATEMENT_PAYLOAD_TYPE,
               "signatures": [{"keyid": f"w{i}", "sig": base64.b64encode(signer[i].sign(msg)).decode("ascii")}
                              for i in (0, 1)]}
        try:
            py = verify_trust_pack(env)
            py_ok = bool(py.get("root_threshold_met")) and bool(py.get("structure_ok", True))
        except Exception:  # noqa: BLE001 — eine typisierte Abweisung ist ein Urteil
            py_ok = False
        self.assertFalse(py_ok, f"Vorbedingung verfehlt: Python nimmt {n} root-keyIds an")
        with tempfile.TemporaryDirectory() as d:
            fp = Path(d) / "tp.json"
            fp.write_text(json.dumps(env), encoding="utf-8")
            p = subprocess.run([str(self.rust), "verify-trust-pack-threshold", str(fp)],  # noqa: S603
                               capture_output=True, text=True, timeout=120)
        aus = (p.stdout + p.stderr).strip()
        self.assertNotEqual(p.returncode, 0, f"Rust meldet root_threshold_met bei {n} Zeugen: {aus!r}")
        self.assertIn("witnesses", aus.lower(), f"Rust weist ab, aber nicht an der Achse: {aus!r}")

    def test_genau_die_zeugenschranke_bleibt_in_beiden_erlaubt(self):
        """POSITIVKONTROLLE (Gegenlesung un_turbov1, Lauf 13, Stelle 1): ohne sie unterschiede der
        Zeugen-Test nicht 'Budget-Abweisung' von 'Struktur-Abweisung' — ein Binary, das das
        handgebaute Statement aus einem ANDEREN Grund abweist, bestuende ihn. Genau 256 verschiedene
        Zeugen, threshold 2, zwei Signaturen: beide Seiten verifizieren. Gemessen: die Bauform von
        Hand ist payload- und signaturidentisch mit `sign_trust_pack`."""
        from proofbundle.budget import DEFAULT_BUDGET
        from proofbundle.emit import generate_signer
        from proofbundle.trust_pack import sign_trust_pack, verify_trust_pack
        from datetime import datetime, timedelta, timezone
        n = gedeckelt(DEFAULT_BUDGET.witnesses, bytes_je_element=KOSTEN_JE_ELEMENT["witnesses"])
        signer = [generate_signer() for _ in range(n)]
        pubs = {f"w{i}": base64.b64encode(s.public_key().public_bytes_raw()).decode() for i, s in enumerate(signer)}
        exp = (datetime.now(timezone.utc) + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
        pred = {"schemaVersion": "0.1.0", "trustPackId": "tp-witnesses-kontrolle", "version": 1,
                "expires": exp, "prevVersionDigest": None,
                "roles": {"root": {"keyIds": list(pubs), "threshold": 2}},
                "keys": {kid: {"publicKey": pk} for kid, pk in pubs.items()},
                "nonClaims": ["positive control: exactly the witnesses budget"]}
        env = sign_trust_pack(pred, {"w0": signer[0], "w1": signer[1]})
        py = verify_trust_pack(env)
        self.assertTrue(py.get("ok") and py.get("structure_ok") and py.get("root_threshold_met"),
                        f"Python weist genau die Schranke ab: {py.get('errors')}")
        with tempfile.TemporaryDirectory() as d:
            fp = Path(d) / "tp.json"
            fp.write_text(json.dumps(env), encoding="utf-8")
            p = subprocess.run([str(self.rust), "verify-trust-pack-threshold", str(fp)],  # noqa: S603
                               capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, f"Rust weist genau die Schranke ab: {(p.stdout + p.stderr).strip()!r}")
        self.assertIn("root_threshold_met=true", p.stdout)

    def test_ein_einsames_surrogat_wird_von_BEIDEN_abgewiesen(self):
        """Gegenlesung un_turbov1 (Lauf 13, Stelle 6; P1 der L1-Klasse, ausgefuehrt): `"\\ud800"` —
        Python `json` nahm es als EIN Zeichen, `verify_envelope` verifizierte einen Umschlag mit
        `keyid = "\\ud800"`, Rust `verify-dsse` meldete exit 2 (serde_json: unexpected end of hex
        escape). Dieselbe Datei, zwei Urteile. Jetzt weisen beide ab — und ein GUELTIGES Paar
        (`\\ud83d\\ude00`, ein Codepoint) nehmen beide an."""
        from proofbundle._strict_json import loads_strict
        from proofbundle.dsse import verify_envelope
        from proofbundle.errors import ProofBundleError
        faelle = ((b'{"a":"\\ud800"}', False), (b'{"\\udfff":1}', False), (b'{"a":"\\ud83d\\ude00"}', True))
        for roh, erlaubt in faelle:
            try:
                loads_strict(roh)
                py_ok = True
            except ProofBundleError:
                py_ok = False
            with tempfile.TemporaryDirectory() as d:
                fp = Path(d) / "s.json"
                fp.write_bytes(roh)
                p = subprocess.run([str(self.rust), "strict-parse", str(fp)],  # noqa: S603
                                   capture_output=True, text=True, timeout=120)
            with self.subTest(roh=roh):
                self.assertEqual(py_ok, erlaubt, f"Python: {roh!r}")
                self.assertEqual(p.returncode == 0, erlaubt, f"Rust: {roh!r} -> {(p.stdout + p.stderr).strip()!r}")
        # Der Verifikationspfad selbst, nicht nur der Parser: ein sonst gueltiger Umschlag.
        env, pub = self._signiertes_ziel()
        env["signatures"][0]["keyid"] = "\ud800"
        with self.assertRaises(ProofBundleError, msg="Python verifiziert einen Umschlag mit einsamem Surrogat"):
            verify_envelope(env, base64.b64decode(pub))
        with tempfile.TemporaryDirectory() as d:
            fp = Path(d) / "env.json"
            fp.write_text(json.dumps(env), encoding="utf-8")   # json.dumps schreibt \ud800 als Escape
            p = subprocess.run([str(self.rust), "verify-dsse", str(fp), pub],  # noqa: S603
                               capture_output=True, text=True, timeout=120)
        self.assertNotEqual(p.returncode, 0, "Rust verifiziert einen Umschlag mit einsamem Surrogat")

    def test_string_len_zaehlt_in_beiden_zeichen_nicht_bytes(self):
        """LAUF12-L1 F3 (P1, ausgefuehrt): Python misst `string_len` in Codepoints (`len(str)`),
        Rust mass Bytes (`s.len()`). Ein Feld aus 600.000 `é` (1,2 MB, 600.000 Zeichen) liegt unter
        der Schranke und wurde von Rust abgewiesen; dieselbe Datei, zwei Urteile. Beide Richtungen:
        unter der Schranke nehmen BEIDE an, darueber weisen BEIDE ab."""
        from proofbundle._strict_json import loads_strict
        from proofbundle.budget import DEFAULT_BUDGET
        knapp = gedeckelt(DEFAULT_BUDGET.string_len, bytes_je_element=2) - 1
        drueber = DEFAULT_BUDGET.string_len + 1
        for n, erlaubt in ((knapp, True), (drueber, False)):
            roh = json.dumps({"a": "\u00e9" * n}, ensure_ascii=False).encode("utf-8")
            try:
                loads_strict(roh)
                py_ok = True
            except Exception:  # noqa: BLE001
                py_ok = False
            with tempfile.TemporaryDirectory() as d:
                fp = Path(d) / "s.json"
                fp.write_bytes(roh)
                p = subprocess.run([str(self.rust), "strict-parse", str(fp)],  # noqa: S603
                                   capture_output=True, text=True, timeout=120)
            with self.subTest(codepoints=n, bytes=len(roh)):
                self.assertEqual(py_ok, erlaubt, f"Python-Vorbedingung verfehlt bei {n} Zeichen")
                self.assertEqual(p.returncode == 0, erlaubt,
                                 f"Rust urteilt anders als Python bei {n} Zeichen / {len(roh)} Bytes: "
                                 f"exit {p.returncode} {(p.stdout + p.stderr).strip()!r}")

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

    @classmethod
    def setUpClass(cls):
        cls.rust = _binary()
        if cls.rust is None:
            raise unittest.SkipTest("NOT MEASURABLE: tools/pb_verify_rs fehlt oder cargo ist nicht da")

    def test_eine_policy_mit_tippfehler_wird_von_BEIDEN_verweigert(self):
        """Lauf 13 (Linse L4, F1, ausgefuehrt; Owner 11.09.: in denselben Kopf vor Lauf 14): `relatoins`
        statt `relations` — Python load_policy exit 2, Rust ignorierte die Policy und verifizierte mit
        exit 0. Beide muessen verweigern; ein fehlendes Pflichtfeld (policy_id) ebenso."""
        import contextlib
        import io
        from proofbundle.cli import main as cli
        fall = REPO / "conformance" / "relation" / "statement-supersedes-verified-blocked"
        pub = (fall / "pub.b64").read_text(encoding="utf-8").strip()
        basis = json.loads((fall / "policy.json").read_text(encoding="utf-8"))
        typo = dict(basis)
        typo["relatoins"] = typo.pop("relations")
        ohne_id = {k: v for k, v in basis.items() if k != "policy_id"}
        for name, pol in (("tippfehler", typo), ("ohne_policy_id", ohne_id)):
            with tempfile.TemporaryDirectory() as d:
                pp = Path(d) / "policy.json"
                pp.write_text(json.dumps(pol), encoding="utf-8")
                argv = ["relation-statement", "verify", str(fall / "receipt.json"), "--pub", pub, "--json",
                        "--with-related", str(fall / "related_t.json"), "--related-pub", pub, "--policy", str(pp)]
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    py_rc = cli(argv)
                p = subprocess.run([str(self.rust), "verify-relation-statement", str(fall / "receipt.json"), pub,  # noqa: S603
                                    "--with-related", str(fall / "related_t.json"), "--related-pub", pub, "--policy", str(pp)],
                                   capture_output=True, text=True, timeout=120)
            with self.subTest(fall=name):
                self.assertEqual(py_rc, 2, f"Python nimmt die Policy ({name}) an")
                self.assertEqual(p.returncode, 2, f"Rust: exit {p.returncode} {(p.stdout + p.stderr).strip()!r} — die Policy ({name}) wurde nicht verweigert")
                self.assertIn("bad --policy", p.stderr)

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
        for achse in ("signatures", "witnesses"):
            self.assertIn(f"budget axis ({achse})", quelle,
                          f"crosscheck.py traegt keinen Negativvektor fuer die {achse}-Achse — die "
                          "Regression von Lauf 12 waere fuer den Kreuzvergleich wieder unsichtbar")


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
