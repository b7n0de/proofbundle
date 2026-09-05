"""Jede Klassenkennung im Ledger bezeichnet genau eine Klasse — der Riegel gegen den Namenskonflikt.

WOHER DIESER TEST KOMMT. Der Probe-Merge der vier Nachbesserungs-Lanes auf den Mergekopf brach am
2026-09-06 in ``audit_artifacts/klassen_ledger.md`` ab. Die Ursache war kein Anhaenge-Konflikt,
sondern ein NAMENSKONFLIKT: die framing2- und die matrix2-Lane hatten unabhaengig voneinander
``KLASSE-C-2026-0905`` vergeben, einmal fuer "Eine Zusicherung verkleinert ihre eigene Positivmenge"
und einmal fuer "Selbstbeglaubigung". Die naheliegende Aufloesung — beide Bloecke behalten, Marken
entfernen — haette zwei verschiedene Klassen unter einer Ueberschrift in den Ledger gestellt.

WARUM DAS MEHR IST ALS UNORDNUNG. Der Ledger ist append-only, und der Sinn davon ist, dass eine
Kennung FUER IMMER dasselbe bezeichnet: spaetere Belege, Commits und Berichte verweisen auf sie.
Zwei Klassen unter einem Namen machen jeden solchen Verweis zweideutig, rueckwirkend und ohne dass
irgendwo etwas rot wuerde. Ein append-only Ledger, der zwei Dinge gleich nennt, hat genau die
Eigenschaft verloren, wegen der er append-only ist.

DIE KLASSE, NICHT DIE INSTANZ. Die Kennung wird aus einem Buchstaben und dem Datum gebildet, und
keine Lane sieht, welchen Buchstaben eine andere am selben Tag schon genommen hat. Parallel
arbeitende Lanes kollidieren deshalb SYSTEMATISCH — es war kein Zufall, sondern die absehbare Folge
der Vergabeform. Die Instanz ist aufgeloest (matrix2 nahm E), aber ohne diesen Test faellt die
naechste Kollision wieder erst beim Merge auf, oder gar nicht.

WAS ER MISST, und was ausdruecklich nicht: er prueft die EINDEUTIGKEIT der Kennungen, nicht ihre
Reihenfolge und nicht ihre Vollstaendigkeit. Ein Ledger darf Luecken haben (eine Lane, die B nahm
und verworfen wurde, hinterlaesst eine) — was er nicht darf, ist denselben Namen zweimal tragen.
"""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
LEDGER = REPO / "audit_artifacts" / "klassen_ledger.md"

#: Eine Ledger-Ueberschrift: ``## KLASSE-<Buchstabe>-<JJJJ>-<MMTT> — <Titel>``
_UEBERSCHRIFT = re.compile(r"^## (KLASSE-[A-Z]+-\d{4}-\d{4})\s*(?:—|-)\s*(.+)$", re.M)


def kennungen(text: str) -> list[tuple[str, str]]:
    """``[(kennung, titel), …]`` in Dateireihenfolge."""
    return [(m.group(1), m.group(2).strip()) for m in _UEBERSCHRIFT.finditer(text)]


@pytest.fixture(scope="module")
def ledger_text() -> str:
    if not LEDGER.is_file():
        pytest.skip("audit_artifacts/klassen_ledger.md liegt hier nicht — der Ordner ist aus dem "
                    "sdist gepruned (MANIFEST.in), dieser Test ist Repo-Kontext")
    return LEDGER.read_text(encoding="utf-8")


def test_jede_kennung_bezeichnet_genau_eine_klasse(ledger_text):
    """DER RIEGEL. Doppelt vergeben heisst: irgendwo verweist etwas auf zwei verschiedene Dinge."""
    paare = kennungen(ledger_text)
    assert paare, "der Ledger traegt keine einzige Kennung — dann misst dieser Test nichts"
    zaehler = Counter(k for k, _ in paare)
    doppelt = {k: n for k, n in zaehler.items() if n > 1}
    if doppelt:
        titel = {k: [t for kk, t in paare if kk == k] for k in doppelt}
        raise AssertionError(
            "Kennung(en) mehrfach vergeben: "
            + "; ".join(f"{k} ({n}x): {titel[k]}" for k, n in doppelt.items())
            + ". Ein append-only Ledger, in dem eine Kennung zwei Klassen bezeichnet, macht jeden "
              "spaeteren Verweis zweideutig — vergib der juengeren Klasse den naechsten freien "
              "Buchstaben und schreib die Umbenennung als Kommentar dazu, damit sie nicht wie eine "
              "stille Korrektur aussieht.")


def test_jede_kennung_traegt_einen_titel(ledger_text):
    """Eine Kennung ohne Titel ist ein Platzhalter, kein Ledger-Eintrag — und ein Platzhalter, den
    jemand spaeter fuellt, ist genau die Stelle, an der zwei Lanes wieder kollidieren."""
    for k, t in kennungen(ledger_text):
        assert len(t) >= 10, f"{k} hat keinen tragfaehigen Titel: {t!r}"


def test_der_riegel_faengt_eine_gepflanzte_dublette(ledger_text):
    """META-TEST. Ohne ihn koennte der Riegel oben gruen sein, weil sein Muster nichts findet —
    etwa nach einer Formatumstellung der Ueberschriften. Hier wird eine Dublette in einer KOPIE des
    echten Textes gepflanzt und verlangt, dass die Auswertung sie sieht."""
    paare = kennungen(ledger_text)
    assert paare, "Vorbedingung: der echte Ledger traegt Kennungen"
    erste = paare[0][0]
    gepflanzt = ledger_text + f"\n\n## {erste} — eine zweite Klasse unter demselben Namen\n\nText.\n"
    zaehler = Counter(k for k, _ in kennungen(gepflanzt))
    assert zaehler[erste] == 2, (
        "die gepflanzte Dublette wurde nicht gesehen — das Muster der Ueberschriftenerkennung passt "
        "nicht mehr zum Ledger-Format, und der Riegel oben ist damit Zierde")


def test_das_muster_erkennt_beide_bindestricharten():
    """Der Ledger benutzt den Gedankenstrich; ein spaeterer Eintrag koennte den einfachen nehmen.
    Ein Riegel, der an der Strichart scheitert, sieht die Dublette daneben nicht."""
    for strich in ("—", "-"):
        text = f"## KLASSE-Z-2026-0906 {strich} Ein Titel mit genug Zeichen\n"
        assert kennungen(text) == [("KLASSE-Z-2026-0906", "Ein Titel mit genug Zeichen")], strich


class TestGegenDenEchtenVorfall:
    """Der staerkste Nachweis: der Riegel wird gegen den TATSAECHLICHEN historischen Zustand
    gefahren, nicht gegen ein erfundenes Beispiel.

    Am 2026-09-06 trugen `fix/deepgate600/framing2` und der damalige matrix2-Stand
    ``44d2ae48`` beide ``KLASSE-C-2026-0905``. Waere der Merge-Konflikt stumpf aufgeloest worden,
    stuenden zwei Klassen unter diesem Namen im Ledger. Dieser Test stellt genau das nach — aus den
    echten Commits, nicht aus einer Nachbildung — und verlangt, dass die Auswertung es sieht.

    Er ist bewusst an feste Commit-Kennungen gebunden: er misst einen VORFALL, und ein Vorfall
    aendert sich nicht mehr. Sind die Commits eines Tages nicht mehr erreichbar (aufgeraeumtes
    Wegwerf-Repo), skippt er ehrlich, statt eine Aussage zu behaupten, die er nicht mehr messen kann.
    """

    MERGEKOPF = "48159022f52c297cefa82f769bee72dd34d8e576"
    MATRIX2_VOR_UMBENENNUNG = "44d2ae485953928a519b98310dfcf74b54de0f56"

    @staticmethod
    def _blob(ref: str) -> str | None:
        import subprocess
        r = subprocess.run(["git", "-C", str(REPO), "show", f"{ref}:audit_artifacts/klassen_ledger.md"],
                           capture_output=True, text=True, timeout=15)
        return r.stdout if r.returncode == 0 else None

    def _zusammen(self, links: str, rechts_ref: str) -> str | None:
        """Die stumpfe Aufloesung: alles aus ``links`` plus die Kennungen, die ``rechts`` neu bringt."""
        rechts = self._blob(rechts_ref)
        basis = self._blob(self.MERGEKOPF)
        if rechts is None or basis is None:
            return None
        schon = {k for k, _ in kennungen(basis)}
        neu = [(k, t) for k, t in kennungen(rechts) if k not in schon]
        return links + "\n" + "\n".join(f"## {k} — {t}" for k, t in neu)

    def test_der_riegel_haette_den_vorfall_gefangen(self):
        from collections import Counter as _C
        f = self._blob("fix/deepgate600/framing2")
        if f is None:
            pytest.skip("fix/deepgate600/framing2 ist hier nicht erreichbar")
        text = self._zusammen(f, self.MATRIX2_VOR_UMBENENNUNG)
        if text is None:
            pytest.skip("der historische matrix2-Stand ist hier nicht erreichbar")
        z = _C(k for k, _ in kennungen(text))
        assert z.get("KLASSE-C-2026-0905", 0) == 2, (
            "die historische Dublette wurde NICHT gesehen — dann faengt der Riegel den Vorfall "
            f"nicht, gegen den er gebaut ist. Gezaehlt: {dict(z)}")

    def test_und_nach_der_umbenennung_ist_er_still(self):
        """Die Gegenrichtung: ein Riegel, der auch den reparierten Zustand rot faerbt, haette nichts
        gemessen, sondern nur zugemacht."""
        from collections import Counter as _C
        f = self._blob("fix/deepgate600/framing2")
        if f is None:
            pytest.skip("fix/deepgate600/framing2 ist hier nicht erreichbar")
        text = self._zusammen(f, "fix/deepgate600/matrix2")
        if text is None:
            pytest.skip("der heutige matrix2-Stand ist hier nicht erreichbar")
        z = _C(k for k, _ in kennungen(text))
        doppelt = {k: n for k, n in z.items() if n > 1}
        assert not doppelt, f"nach der Umbenennung stehen immer noch Dubletten: {doppelt}"
