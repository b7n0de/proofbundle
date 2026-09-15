"""ADR 0008 Entscheidungspunkt 2 als EIGENSCHAFT, nicht als vier Beispiele.

Die ADR sagt: *"The gate stops grepping prose and verifies the attestation. A documentation edit
cannot produce a signature, so P1, P2 and P3 fall out of the change rather than being patched one
regex at a time."* Das ist eine Aussage ueber eine KLASSE — jeden denkbaren Text — und sie ist
heute an vier EINZELFAELLEN festgeschrieben (P1 bis P4 in
``tests/test_pre_tag_gate_eigenschaften.py``). Vier Beispiele sind keine Klasse.

WAS DIESE DATEI ANDERS MACHT. Der Korpus wird aus der Prosa-Mechanik ABGELEITET, die im Tor noch
liegt: ``_AUDIT_MARKERS`` (das Vokabular) und ``_ATTESTATION`` (die kanonische Zeile). Jeder
Korpuseintrag wird zuerst gegen ``_positive_audit_marker`` bzw. ``attests_version`` geprueft — er
ist also nachweislich ein Text, den die alte Mechanik als Attestierung GELESEN haette — und danach
gegen ``evaluate()`` gehalten. Die Zusicherung lautet:

    Jeder Text, den die Prosa-Mechanik als positive Attestierung akzeptiert, erteilt dem Tor
    trotzdem KEINE Freigabe, solange kein gueltiges Receipt den Baum bindet.

WARUM DIE ABLEITUNG UND NICHT EINE LISTE. Waechst das Vokabular um ein Wort, waechst der Korpus
mit. ``test_jede_vokabelalternative_hat_eine_probe`` wird ROT, sobald jemand eine Alternative
hinzufuegt, ohne eine Probe zu hinterlegen — eine Liste haette an dieser Stelle geschwiegen, und
genau das Schweigen ist der Fehlermodus, gegen den die ADR ueberhaupt geschrieben wurde.

WARUM DIE PROSA-MECHANIK UEBERHAUPT NOCH DA IST, gemessen 2026-09-15: ``evaluate()`` bezieht sein
Urteil ausschliesslich aus dem Receipt; ``_positive_audit_marker`` wird dort nur noch fuer das Feld
``changelog_records_audit`` aufgerufen, das ausdruecklich ``changelog_is_presentational`` traegt.
``attests_version``, ``attesting_records_for``, ``audit_records_for`` und ``audit_artifact_for``
haben im lebenden Baum ausser Tests KEINEN Aufrufer mehr. Die Flaeche ist also entwaffnet, aber
NICHT verschwunden — die ADR-Folgezeile *"The blocklist-of-negations disappears as a security
surface"* ist damit noch nicht eingeloest. Diese Datei loescht sie nicht (die bestehenden Tests
pinnen ihr Verhalten), sie sichert das ab, worauf es ankommt: dass ein Wiederanschluss auffaellt.

POSITIVKONTROLLE ist Pflicht. Ohne sie bestuende diese Datei auch gegen ein Tor, das NIE erteilt,
und wuerde ein kaputtes Tor als sicher ausweisen.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest

_REPO = pathlib.Path(__file__).resolve().parents[1]
_GATE_PFAD = _REPO / "scripts" / "pre_tag_audit_gate.py"
_VERSION = "9.9.9"
_TOKEN = "999"


def _tor():
    import sys  # noqa: PLC0415
    s = str(_REPO / "scripts")
    if s not in sys.path:
        sys.path.insert(0, s)
    spec = importlib.util.spec_from_file_location("_pretag_kein_prosa", _GATE_PFAD)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _vokabelalternativen(muster: str) -> list[str]:
    """Die Alternativen der Vokabelliste, so wie sie im Muster stehen — Quelle des Korpus."""
    return [a for a in muster.split("|") if a.strip()]


# Je Alternative eine Probe, die sie AUSLOEST. Kommt eine Alternative dazu und hier keine Probe,
# wird test_jede_vokabelalternative_hat_eine_probe rot.
_PROBEN: dict[str, str] = {
    r"\b\d+\s*-?\s*lens(es)?\b": "The 6-lens pass ran for this release and every lens reported.\n",
    r"\badversarial\b": "The adversarial audit ran for this release and reported clean.\n",
    r"\bmaster[- ]prompt\b": "The master-prompt procedure was executed in full for this release.\n",
    r"\blinsen\b": "Die sechs Linsen sind gefahren und haben berichtet.\n",
}


@unittest.skipUnless(_GATE_PFAD.is_file(), "pre_tag_audit_gate.py nicht vorhanden")
class KeinProsaErteiltDasTor(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.gate = _tor()

    # ---- der Korpus bindet an die Mechanik, nicht an eine Liste ----

    def test_jede_vokabelalternative_hat_eine_probe(self) -> None:
        """Waechst das Vokabular, waechst der Korpus — oder dieser Test wird rot.

        Eine Liste von Beispielen haette hier geschwiegen. Genau dieses Schweigen ist der
        Fehlermodus, gegen den ADR 0008 geschrieben wurde.
        """
        alternativen = _vokabelalternativen(self.gate._AUDIT_MARKERS.pattern)
        fehlend = [a for a in alternativen if a not in _PROBEN]
        self.assertEqual(
            fehlend, [],
            "die Vokabelliste des Tors hat Alternativen ohne Probe im Korpus — je eine Probe in "
            f"_PROBEN eintragen: {fehlend}")

    def test_jede_probe_wird_von_der_alten_mechanik_akzeptiert(self) -> None:
        """Die Gueltigkeit des Korpus selbst, gemessen statt angenommen.

        Eine Probe, die die Prosa-Mechanik gar nicht akzeptiert, wuerde unten gruen durchlaufen und
        NICHTS belegen — dieselbe Leerform wie ein Anti-Fall, der nicht fallen kann.
        """
        for muster, probe in _PROBEN.items():
            with self.subTest(alternative=muster):
                self.assertTrue(
                    self.gate._positive_audit_marker(probe),
                    f"die Probe loest die Alternative {muster!r} nicht aus, sie belegt also nichts")

    def test_die_kanonische_zeile_attestiert_die_version_noch_immer(self) -> None:
        """Auch die staerkste Prosa-Form des alten Tors bleibt Prosa. Ohne diese Messung waere der
        Fall unten ein Test gegen einen Text, den die Mechanik ohnehin ablehnt."""
        zeile = f"pre-tag-adversarial-audit: RUN | version={_VERSION}\n"
        self.assertTrue(self.gate.attests_version(zeile, _VERSION))

    # ---- die Eigenschaft ----

    def _baum_ohne_receipt(self, **dateien: str) -> pathlib.Path:
        d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        (d / "audit_artifacts" / _TOKEN).mkdir(parents=True)
        for name, inhalt in dateien.items():
            # .md IST PFLICHT, nicht Kosmetik: das Tor scannt ``*.md`` (audit_records_for,
            # attesting_records_for). Die erste Fassung schrieb ``RECORD`` ohne Endung — der
            # Fangnachweis lief damit GRUEN, obwohl ein eingepflanzter Prosa-Pfad im Tor lag, weil
            # die Dateien nie gelesen wurden. Gemessen 2026-09-15: RC=0 mit Defekt.
            self.assertTrue(name.endswith(".md"), f"Korpusdatei ohne .md wird nie gelesen: {name}")
            (d / "audit_artifacts" / _TOKEN / name).write_text(inhalt, encoding="utf-8")
        return d

    def test_kein_text_des_korpus_erteilt_ohne_receipt(self) -> None:
        """DIE ZUSICHERUNG. Jeder Text, den die alte Mechanik gelesen haette, erteilt nichts."""
        korpus = dict(_PROBEN)
        korpus["kanonische_zeile"] = f"pre-tag-adversarial-audit: RUN | version={_VERSION}\n"
        korpus["bericht_ueber_die_methodik"] = (
            "This report describes the adversarial six-lens methodology used elsewhere.\n")
        korpus["alles_zusammen"] = "\n".join(_PROBEN.values()) + korpus["kanonische_zeile"]
        for name, text in korpus.items():
            with self.subTest(form=name):
                baum = self._baum_ohne_receipt(**{"RECORD.md": text})
                erg = self.gate.evaluate(baum, _VERSION)
                self.assertFalse(
                    erg["ok"],
                    f"Prosa der Form {name!r} hat eine Freigabe erteilt — ADR 0008 Punkt 2 gebrochen")

    def test_auch_der_changelog_abschnitt_erteilt_nichts(self) -> None:
        """Der zweite Prosa-Ort des alten Tors. Er ist im Ergebnis sichtbar und muss folgenlos sein."""
        d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        (d / "audit_artifacts" / _TOKEN).mkdir(parents=True)
        (d / "CHANGELOG.md").write_text(
            f"## [{_VERSION}]\n\nThe adversarial audit ran for this release.\n", encoding="utf-8")
        erg = self.gate.evaluate(d, _VERSION)
        self.assertFalse(erg["ok"], "ein CHANGELOG-Abschnitt hat eine Freigabe erteilt")
        self.assertTrue(erg.get("changelog_is_presentational"),
                        "das Ergebnis weist den CHANGELOG nicht mehr als presentational aus")

    # ---- Positivkontrolle: das Tor erteilt sehr wohl, wenn ein Receipt bindet ----

    def _signierter_baum(self) -> tuple[pathlib.Path, str]:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: PLC0415
        import sys  # noqa: PLC0415
        s = str(_REPO / "scripts")
        if s not in sys.path:
            sys.path.insert(0, s)
        from pre_tag_receipt_lib import RECEIPT_SCHEMA, canonical_bytes, subject_tree_digest  # noqa: PLC0415

        d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        priv = Ed25519PrivateKey.generate()
        pub = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
        (d / "audit_artifacts" / _TOKEN).mkdir(parents=True)
        (d / "audit_artifacts" / "pre_tag_trusted_pubkeys.txt").write_text(pub + "\n", encoding="utf-8")
        (d / "pyproject.toml").write_text(f'[project]\nversion = "{_VERSION}"\n', encoding="utf-8")
        (d / "src").mkdir()
        (d / "src" / "marker.txt").write_text("x\n", encoding="utf-8")
        for befehl in (["init", "-q"], ["config", "user.email", "t@example.invalid"],
                       ["config", "user.name", "t"], ["add", "-A"],
                       ["-c", "commit.gpgsign=false", "commit", "-q", "-m", "t"]):
            subprocess.run(["git", "-C", str(d), *befehl], check=True, capture_output=True, timeout=30)
        tree = subject_tree_digest(d)
        gate_src = hashlib.sha256(_GATE_PFAD.read_bytes()).hexdigest()
        r = {"schema": RECEIPT_SCHEMA, "version": _VERSION, "subject_tree_digest": tree,
             "gate_source_digest": gate_src,
             "audit_command": "pytest -q", "audit_exit_code": 0,
             "audit_output_digest": "c" * 64, "runner_identity": "test",
             "produced_at": "2026-09-15T10:00:00Z"}
        r["signature"] = base64.b64encode(priv.sign(canonical_bytes(r))).decode()
        r["signer_pubkey"] = pub
        (d / "audit_artifacts" / _TOKEN / "receipt.json").write_text(
            json.dumps(r), encoding="utf-8")
        return d, tree

    def test_positivkontrolle_ein_gueltiges_receipt_erteilt(self) -> None:
        """OHNE DIESE MESSUNG belegt diese Datei nichts.

        Ein Tor, das jede Eingabe ablehnt, bestuende jede Zusicherung oben und waere dabei kaputt.
        Genau diese Verwechslung — 'nichts erteilt' mit 'sicher' — ist die Gegenrichtung des
        Fehlers, den ADR 0008 beschreibt.
        """
        baum, _ = self._signierter_baum()
        erg = self.gate.evaluate(baum, _VERSION)
        self.assertTrue(
            erg["ok"],
            f"ein gueltiges, baumgebundenes Receipt erteilt nicht — das Tor lehnt alles ab: {erg}")

    def test_prosa_neben_einem_gueltigen_receipt_aendert_nichts(self) -> None:
        """Die Gegenrichtung: Prosa erteilt nicht, sie ENTZIEHT aber auch nicht.

        Ein Tor, das bei jeder Prosa im Ordner ablehnt, waere ebenfalls an die Prosa gebunden — nur
        mit umgekehrtem Vorzeichen. Die ADR verlangt, dass Prosa den Verdikt in KEINE Richtung
        bewegt.
        """
        baum, _ = self._signierter_baum()
        (baum / "audit_artifacts" / _TOKEN / "NOTIZ.md").write_text(
            "an adversarial six-lens pass remains outstanding for this release\n", encoding="utf-8")
        erg = self.gate.evaluate(baum, _VERSION)
        self.assertTrue(
            erg["ok"],
            "eine verneinende Prosa-Zeile hat ein gueltiges Receipt entwertet — Prosa bewegt den "
            f"Verdikt damit doch, nur in der anderen Richtung: {erg}")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
