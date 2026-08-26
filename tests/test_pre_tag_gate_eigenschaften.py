"""Was ein Vor-Tag-Tor koennen MUSS — als Eigenschaften, nicht als Muster.

WARUM ES DIESE DATEI GIBT. Am 2026-08-16 wurde das Tor durch eine **Doku-Bearbeitung** erfuellt:
ein Mess-Bericht in `audit_artifacts/380/` zitierte zwei Saetze woertlich, die das Tor als
Attestierung liest, und die gesamte Suite meldete daraufhin `2120 passed` mit gruenem Release-Tor —
fuer ein Release ohne jeden Audit-Eintrag. Aufgefallen ist es nur, weil ein die ganze Runde
erwarteter roter Test ploetzlich fehlte.

Die Reaktion darauf ist NICHT ein weiteres Wort in einer Verneinungsliste. Diese Liste ist eine
Sperrliste ueber einem offenen Alphabet (CWE-184), und jede Runde findet den naechsten Satz, der
nicht darauf steht. Die Reaktion ist, aufzuschreiben, WAS ein Tor koennen muss, und zwar so, dass
die Aussage die Implementierung ueberlebt: PR #139 baut das Tor gerade um, und diese Datei prueft
weder seine Regexe noch seine Datenstrukturen, sondern sein VERHALTEN an fuenf Wegwerf-Baeumen.

DER STAND IST GEMESSEN, NICHT VERMUTET (2026-08-16, gegen das Tor auf release/v3.8.0):

    P5 KONTROLLE  leere Akte erteilt nicht          haelt
    P4 wahrhaftiger Eintrag erteilt                 haelt
    P1 Datei UEBER den Audit erteilt nicht          VERLETZT -> haelt seit #139
    P2 Eintrag fuer eine ANDERE Version             VERLETZT -> haelt seit #139
    P3 "nichts gelaufen" erteilt nicht              VERLETZT -> haelt seit #139

Die drei verletzten trugen `expectedFailure` — und der Mechanismus hat GENAU SO gefeuert, wie er
sollte. Mit dem Merge von PR #139 (2026-08-17) halten P1, P2 und P3, und unittest meldete drei
**Unexpected success**, also einen FEHLSCHLAG. Das zwang zum Entfernen der Markierungen; sie sind
entfernt, die drei Eigenschaften sind ab hier normale Zusicherungen.

Warum das hier stehen bleibt statt weggeraeumt zu werden: es ist der Beleg, dass die Bauform
funktioniert. Ein `skip` haette geschwiegen, als die Arbeit getan war, und aus "bekannt offen" waere
unbemerkt "unbekannt" geworden. Ein Pin auf eine LUECKE muss rot werden, wenn die Luecke sich
schliesst — sonst haelt er einen Zustand fest, nachdem er aufgehoert hat zu gelten.

KEINE ZWEITE MESSSTELLE: geprueft wird gegen den ECHTEN `evaluate()` des Tors, nie gegen eine
nachgebaute Kopie seiner Logik. Zwei Kopien derselben Regel sind die naechste Drift.
"""
from __future__ import annotations

import importlib.util
import pathlib
import shutil
import tempfile
import unittest

_REPO = pathlib.Path(__file__).resolve().parents[1]
_GATE = _REPO / "scripts" / "pre_tag_audit_gate.py"
_VERSION = "3.8.0"
_TOKEN = "380"

# Eine Zeile, die das Tor als Attestierung LESEN SOLL — die Form, die PR #139 einfuehrt.
_WAHRHAFTIG = "pre-tag-adversarial-audit: RUN | version=3.8.0\n"


def _tor():
    spec = importlib.util.spec_from_file_location("_pretag_eigenschaften", _GATE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


@unittest.skipUnless(_GATE.is_file(), "pre_tag_audit_gate.py nicht vorhanden")
class WasEinVorTagTorKoennenMuss(unittest.TestCase):

    def _baum(self, **dateien: str) -> pathlib.Path:
        """Ein Wegwerf-Baum mit genau diesen Dateien in der versionsgebundenen Akte."""
        d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        (d / "audit_artifacts" / _TOKEN).mkdir(parents=True)
        for name, inhalt in dateien.items():
            (d / "audit_artifacts" / _TOKEN / name.replace("__", ".")).write_text(
                inhalt, encoding="utf-8")
        return d

    def _erteilt(self, baum: pathlib.Path) -> bool:
        return bool(_tor().evaluate(baum, _VERSION)["ok"])

    # ---- die beiden Eigenschaften, die HEUTE halten. Ein Umbau darf sie nicht brechen. ----

    def test_P5_kontrolle_leere_akte_erteilt_nicht(self) -> None:
        """Die Gegenprobe des Messaufbaus. Ohne sie saehe ein Tor, das NIE erteilt, makellos aus."""
        self.assertFalse(self._erteilt(self._baum()),
                         "eine leere Akte erteilt die Freigabe — dann misst nichts hier etwas")

    def test_P4_eine_prosa_zeile_erteilt_keinen_pass_mehr(self) -> None:
        """makellose-500 F6: die kanonische Prosa-Zeile war forgeable (P6 des Gegenlesers) und ist jetzt
        presentational. Der Verdikt kommt aus einem signierten, tree-gebundenen Receipt. Die
        Gegenrichtung — dass das Tor nicht ALLES ablehnt — ist die Positiv-Kontrolle in
        tests/test_pre_tag_receipt_gate.py (ein gueltiger Receipt verifiziert)."""
        self.assertFalse(self._erteilt(self._baum(RECORD__md=_WAHRHAFTIG)),
                         "eine Prosa-Zeile hat weiterhin einen PASS erteilt (F6 nicht geschlossen)")

    # ---- die drei gemessenen Luecken. Werden sie gruen, meldet unittest UNEXPECTED SUCCESS. ----

    def test_P1_eine_datei_ueber_den_audit_erteilt_nicht(self) -> None:
        """Ein Bericht UEBER einen Audit ist kein Bericht VON einem Audit.

        Genau dieser Fall ist am 2026-08-16 eingetreten und war live gruen. Das Tor scannt jede
        `*.md` der Akte auf ein Markerwort; ein Mess-Bericht, ein Index, ein Befund — alle liegen
        dort und alle tragen das Vokabular, ueber das sie schreiben.
        """
        bericht = ("This report describes the adversarial six-lens methodology used elsewhere.\n")
        self.assertFalse(self._erteilt(self._baum(MESSUNG__md=bericht)),
                         "ein Bericht ueber die Methodik attestiert das Release")

    def test_P2_ein_eintrag_fuer_eine_andere_version_erteilt_nicht(self) -> None:
        """Ein Eintrag, der ausdruecklich eine ANDERE Version attestiert, attestiert diese nicht.

        Heute ist der Ordnername der einzige Anker: ein aus 3.7.0 kopierter Eintrag erteilt die
        Freigabe fuer 3.8.0, weil er im richtigen Ordner liegt. Die Version gehoert IN die
        attestierende Zeile.
        """
        fremd = "The adversarial audit ran and passed for version 3.7.0.\n"
        self.assertFalse(self._erteilt(self._baum(RECORD__md=fremd)),
                         "ein Eintrag fuer 3.7.0 attestiert 3.8.0")

    def test_P3_ein_satz_der_das_gegenteil_sagt_erteilt_nicht(self) -> None:
        """Ein Satz, der in klaren Worten sagt, es sei nichts gelaufen, darf nichts attestieren.

        Die Verneinungsliste faengt die meisten Formen — von zwoelf schmucklosen Verneinungen
        blieben zwei. Ihre Form steht hier absichtlich nur beschrieben, nicht zitiert: eine verneint
        ueber Ausstehen, die andere ueber Urheberschaft. Der Wortlaut ist in einer Datei, die in der
        Akte liegt, genau der Vektor — das ist am 2026-08-16 passiert und der Grund, dass diese
        Datei existiert. Der hier benutzte Satz ist deshalb eine DRITTE Form derselben Klasse.
        """
        verneinend = "an adversarial six-lens pass remains outstanding for this release\n"
        self.assertFalse(self._erteilt(self._baum(RECORD__md=verneinend)),
                         "ein Satz, der das Ausstehen benennt, attestiert das Release")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
