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
keine Lane sieht, welchen Buchstaben eine andere schon genommen hat. Parallel arbeitende Lanes
kollidieren deshalb SYSTEMATISCH — es war kein Zufall, sondern die absehbare Folge der Vergabeform.

DIE ZWEITE FASSUNG, 2026-09-06, und warum es sie braucht. Die erste Fassung zaehlte die VOLLE
Kennung, Buchstabe UND Datum. Sie fing den Vorfall, gegen den sie gebaut war (zweimal
``KLASSE-C-2026-0905``), und liess den naechsten durch: beim Merge von matrix2 auf den
Integrationskopf trafen ``KLASSE-D-2026-0906`` (framing2) und ``KLASSE-D-2026-0905`` (matrix2)
aufeinander — zwei verschiedene Klassen, beide ``D``, als Zeichenketten verschieden. Der Riegel war
still, und ``test_und_nach_der_umbenennung_ist_er_still`` bescheinigte diesem Zustand sogar
ausdruecklich, sauber zu sein: ein gruener Test, der den Defekt zertifiziert.

Der ordnende Schluessel ist der BUCHSTABE, nicht die volle Kennung. Der Beweis steht in der eigenen
Historie: als ``C`` kollidierte, wurde matrix2 zu ``E`` umbenannt — nicht zu ``C`` mit einem anderen
Datum. Haette das Datum unterschieden, waere die Umbenennung unnoetig gewesen. Das Datum ist
Beiwerk; Berichte, Commits und Belege verweisen mit „Klasse D".

Deshalb prueft dieser Test die Eindeutigkeit jetzt auf dem Buchstaben, und der Gate-Meta-Test
pflanzt eine Dublette mit ABWEICHENDEM Datum — genau der Fall, den die erste Fassung nicht sah.

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


def buchstabe(kennung: str) -> str:
    """``KLASSE-D-2026-0906`` -> ``D``. Der Teil, der die Identitaet traegt.

    Das Datum unterscheidet NICHT: zwei Lanes, die an verschiedenen Tagen denselben Buchstaben
    vergeben, haben dieselbe Kollision wie zwei am selben Tag — nur faellt sie einem Zeichenketten-
    vergleich nicht auf. Genau daran ging die erste Fassung dieses Tests vorbei.
    """
    return kennung.split("-")[1]


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
    zaehler = Counter(buchstabe(k) for k, _ in paare)
    doppelt = {b: n for b, n in zaehler.items() if n > 1}
    if doppelt:
        titel = {b: [f"{k} ({t})" for k, t in paare if buchstabe(k) == b] for b in doppelt}
        raise AssertionError(
            "Buchstabe(n) mehrfach vergeben: "
            + "; ".join(f"{b} ({n}x): {titel[b]}" for b, n in doppelt.items())
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


def test_der_riegel_sieht_eine_dublette_mit_ABWEICHENDEM_datum(ledger_text):
    """DER META-TEST GEGEN DIE ERSTE FASSUNG. Sie zaehlte die volle Kennung und war deshalb blind,
    sobald zwei Lanes denselben Buchstaben an verschiedenen Tagen vergaben. Hier wird genau das
    gepflanzt: derselbe Buchstabe, anderes Datum. Sieht die Auswertung es nicht, ist der Riegel
    wieder die Fassung, die den zweiten Vorfall durchgelassen hat."""
    paare = kennungen(ledger_text)
    assert paare, "Vorbedingung: der echte Ledger traegt Kennungen"
    erster_buchstabe = buchstabe(paare[0][0])
    gepflanzt = (ledger_text
                 + f"\n\n## KLASSE-{erster_buchstabe}-1999-0101 — dieselbe Klasse, anderes Datum\n\nText.\n")
    z = Counter(buchstabe(k) for k, _ in kennungen(gepflanzt))
    assert z[erster_buchstabe] >= 2, (
        f"die Dublette mit abweichendem Datum wurde nicht gesehen — der Riegel zaehlt wieder die "
        f"volle Kennung statt des Buchstabens. Gezaehlt: {dict(z)}")
    # Gegenrichtung: ein FREIER Buchstabe darf nicht als Dublette gelten, sonst waere der Riegel
    # nur eine Verweigerung.
    frei = next(c for c in "ZYXWVU" if c not in {buchstabe(k) for k, _ in paare})
    harmlos = ledger_text + f"\n\n## KLASSE-{frei}-1999-0101 — eine echte neue Klasse\n\nText.\n"
    z2 = Counter(buchstabe(k) for k, _ in kennungen(harmlos))
    assert z2[frei] == 1, f"ein freier Buchstabe wurde als Dublette gezaehlt: {dict(z2)}"


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

    MATRIX2_VOR_UMBENENNUNG_D = "c41d3e3b83fbb59a3397d53f193ba7760e3b65e0"
    FRAMING2_MIT_D = "cb9fcf0397d154f538a2d527afdc0cef93eee6c5"

    def test_und_den_zweiten_vorfall_mit_verschiedenen_datumsangaben(self):
        """DER ZWEITE VORFALL, und der Grund fuer die zweite Fassung. framing2 (`cb9fcf0`) trug
        ``KLASSE-D-2026-0906``, matrix2 (`c41d3e3`) unabhaengig ``KLASSE-D-2026-0905`` fuer eine
        andere Klasse. Auf der vollen Kennung sind das zwei verschiedene Zeichenketten — die erste
        Fassung dieses Tests war hier still. Auf dem Buchstaben ist es dieselbe Kollision wie bei C."""
        from collections import Counter as _C
        f = self._blob(self.FRAMING2_MIT_D)
        if f is None:
            pytest.skip(f"{self.FRAMING2_MIT_D[:7]} ist hier nicht erreichbar")
        text = self._zusammen(f, self.MATRIX2_VOR_UMBENENNUNG_D)
        if text is None:
            pytest.skip("der historische matrix2-Stand ist hier nicht erreichbar")
        z = _C(buchstabe(k) for k, _ in kennungen(text))
        assert z.get("D", 0) == 2, (
            "die zweite Kollision wurde NICHT gesehen — dann zaehlt der Riegel wieder die volle "
            f"Kennung statt des Buchstabens. Gezaehlt: {dict(z)}")

    def test_und_der_reparierte_ledger_im_baum_ist_still(self, ledger_text):
        """Die Gegenrichtung: ein Riegel, der auch den reparierten Zustand rot faerbt, haette nichts
        gemessen, sondern nur zugemacht.

        Gemessen wird der Ledger IM BAUM, nicht mehr eine nachgebaute Verschmelzung zweier Zweige.
        Das ist der Zustand, der wirklich ausgeliefert wird, und nach der Aufloesung des Merges der
        einzige, ueber den eine Aussage etwas wert ist."""
        from collections import Counter as _C
        z = _C(buchstabe(k) for k, _ in kennungen(ledger_text))
        assert z, "Vorbedingung: der Ledger im Baum traegt Kennungen"
        doppelt = {b: n for b, n in z.items() if n > 1}
        assert not doppelt, f"im Ledger des Baums stehen Dubletten: {doppelt}"
