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

DRITTE FASSUNG, wenige Minuten spaeter, nach einem Fund der Gegenlesung — und der Fund trifft
etwas Grundsaetzlicheres als die zwei davor. Die zweite Fassung erkannte eine Ueberschrift nur in
GENAU einer Form: zwei Rautenzeichen, Grossbuchstaben, Gedankenstrich oder Bindestrich, kein
fuehrendes Leerzeichen. Ein zweiter Eintrag mit einem EN-DASH (U+2013 `–` statt U+2014 `—`) oder
mit `###` war fuer den Riegel schlicht nicht vorhanden — und was nicht vorhanden ist, kollidiert
mit nichts. Zwei echte Klassen unter `D` ergaben PASS, empirisch nachgebaut.

Die Klasse dahinter heisst NICHT ERKANNT IST NICHT ABWESEND, und sie ist die teuerste Bauform
eines jeden Musters: ein Riegel, der seinen Gegenstand nach einer engen Form sucht, meldet bei
jeder Abweichung Ruhe statt Alarm. Die Antwort ist deshalb nicht eine weitere Form in der Regex —
die naechste Schreibweise faende sie wieder nicht. Die Antwort ist ein ZWEITES, ABSICHTLICH WEITES
Muster: was wie eine Klassenueberschrift AUSSIEHT, muss von der strengen Form auch erfasst werden.
Jede Zeile, die das weite Muster trifft und das strenge verfehlt, ist ein Befund mit Namen —
nicht eine Leerstelle. Der Ledger darf dann keine Zeile mehr enthalten, die der Riegel uebersieht,
ohne dass er das sagt.

Was diese Fassung ausdruecklich NICHT tut: die Schreibweise vereinheitlichen oder tolerieren. Eine
Ueberschrift in abweichender Form faellt weiterhin durch — sie faellt nur nicht mehr STILL.

WAS BEWUSST NICHT GEBAUT WURDE, und warum es hier steht statt in einem Kopf. Die zweite Fassung
hatte einen Test, der zwei ZWEIGE verglich (`framing2` plus den damaligen `matrix2`-Stand) und
damit eine FRUEHWARNUNG war: er haette die Kollision gesehen, solange sie noch in zwei getrennten
Zweigen schlummerte, vor dem Merge. Dieser Test ist durch einen ersetzt, der den Ledger IM BAUM
misst. Das ist eine echte Einbusse, und sie wurde in Kauf genommen:

Die Fruehwarnung zu verallgemeinern hiesse, dass der Test die MENGE DER VORHANDENEN ZWEIGE liest.
Damit haenge sein Ergebnis an Laufzeitzustand ausserhalb des Prueflings — dasselbe Zustandsbild wie
`N13` im Restrisiko-Register, wo ein Knoten rot oder gruen wird, je nachdem was neben ihm auf der
Maschine liegt. Ein Riegel gegen stille Kollisionen, der selbst nichtdeterministisch wird, tauscht
ein bekanntes Problem gegen ein schlechteres.

Geblieben ist die Kreuz-Zweig-PRUEFUNG in `TestGegenDenEchtenVorfall`: sie baut dieselbe
Verschmelzung nach, aber gegen FESTE Commit-Kennungen. Ein Vorfall aendert sich nicht mehr, eine
Zweigmenge schon. Was fehlt, ist damit nur die Warnung fuer KUENFTIGE, noch nicht gemergte Zweige —
und die faengt der Merge selbst, weil dort seit dieser Runde der weite Detektor mitlaeuft.

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

#: Eine Ledger-Ueberschrift, STRENG: ``## KLASSE-<Buchstabe>-<JJJJ>-<MMTT> — <Titel>``
_UEBERSCHRIFT = re.compile(r"^## (KLASSE-[A-Z]+-\d{4}-\d{4})\s*(?:—|-)\s*(.+)$", re.M)

#: Und dasselbe ABSICHTLICH WEIT: alles, was wie eine Klassenueberschrift aussieht. Beliebig viele
#: Rautenzeichen, fuehrender Weissraum, Gross- oder Kleinschreibung, jede Strichart (Em-Dash,
#: En-Dash, Bindestrich, Geviert-, Halbgeviertstrich), Titel optional. Dieses Muster ist NICHT der
#: Vertrag — es ist der Detektor fuer Zeilen, die der Vertrag uebersehen wuerde.
_UEBERSCHRIFT_WEIT = re.compile(r"^[ \t]*#{1,6}[ \t]*(KLASSE[-_][A-Za-z]+[-_]\d{2,4}[-_]\d{2,4})",
                                re.M | re.IGNORECASE)


def fast_ueberschriften(text: str) -> list[str]:
    """Zeilen, die wie eine Klassenueberschrift AUSSEHEN — streng oder nicht."""
    return [m.group(0).strip() for m in _UEBERSCHRIFT_WEIT.finditer(text)]


def uebersehene_ueberschriften(text: str) -> list[str]:
    """Was das weite Muster sieht und das strenge nicht. Jede davon ist ein Befund.

    Der Vergleich laeuft ueber die ZEILENNUMMER, nicht ueber die Kennung: zwei Eintraege
    koennen dieselbe Kennung tragen (genau der Fall, den dieser Test sucht), und ein
    Mengenvergleich ueber Kennungen wuerde den zweiten wieder verschlucken.
    """
    streng = {text[:m.start()].count("\n") for m in _UEBERSCHRIFT.finditer(text)}
    aus = []
    for m in _UEBERSCHRIFT_WEIT.finditer(text):
        if text[:m.start()].count("\n") not in streng:
            aus.append(m.group(0).strip())
    return aus


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


def test_keine_ueberschrift_entgeht_dem_strengen_muster(ledger_text):
    """DER RIEGEL GEGEN 'NICHT ERKANNT IST NICHT ABWESEND'.

    Ohne ihn ist die Eindeutigkeitspruefung daneben nur so gut wie ihre Schreibweise: ein
    Eintrag mit En-Dash oder `###` faellt aus der Erkennung, kollidiert mit nichts und laesst
    den Riegel gruen. Hier wird verlangt, dass die WEITE und die STRENGE Sicht dieselbe Menge
    von Zeilen sehen. Weichen sie ab, ist die abweichende Zeile benannt — sie verschwindet nicht.
    """
    uebersehen = uebersehene_ueberschriften(ledger_text)
    assert not uebersehen, (
        "Diese Zeile(n) sehen aus wie eine Klassenueberschrift, werden vom strengen Muster aber "
        "NICHT erfasst — und was nicht erfasst wird, kollidiert mit nichts:\n  "
        + "\n  ".join(uebersehen)
        + "\nSchreib sie in der kanonischen Form `## KLASSE-<Buchstabe>-<JJJJ>-<MMTT> — <Titel>` "
          "(zwei Rautenzeichen, Grossbuchstaben, Gedankenstrich).")


def test_der_weite_detektor_sieht_die_abweichenden_formen(ledger_text):
    """META-TEST zum Riegel darueber. Ein Detektor, der die Abweichung nicht sieht, macht den
    Riegel zur Zierde. Hier werden die vier gemessenen Umgehungsformen gepflanzt und verlangt,
    dass jede einzeln auffaellt."""
    formen = {
        "En-Dash statt Gedankenstrich": "## KLASSE-Q-2026-0906 – Ein Titel mit genug Zeichen",
        "drei Rautenzeichen":           "### KLASSE-Q-2026-0906 — Ein Titel mit genug Zeichen",
        "fuehrendes Leerzeichen":       "  ## KLASSE-Q-2026-0906 — Ein Titel mit genug Zeichen",
        "Kleinschreibung":              "## KLASSE-q-2026-0906 — Ein Titel mit genug Zeichen",
    }
    for name, zeile in formen.items():
        gepflanzt = ledger_text + "\n\n" + zeile + "\n\nText.\n"
        uebersehen = uebersehene_ueberschriften(gepflanzt)
        assert uebersehen, f"die Form '{name}' wurde NICHT als uebersehene Ueberschrift erkannt"
        assert any("KLASSE" in u.upper() for u in uebersehen), (name, uebersehen)
    # Gegenrichtung: die KANONISCHE Form darf nicht als uebersehen gelten, sonst waere der
    # Detektor eine Dauerbeschwerde und niemand laese ihn mehr.
    kanonisch = ledger_text + "\n\n## KLASSE-Q-2026-0906 — Ein Titel mit genug Zeichen\n\nText.\n"
    assert not uebersehene_ueberschriften(kanonisch), (
        "die kanonische Form wurde als uebersehen gemeldet — der Detektor schlaegt immer an")


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
    belegt = {buchstabe(k) for k, _ in paare}
    frei = next((c for c in "ZYXWVUTSRQPONMLKJIHGFEDCBA" if c not in belegt), None)
    assert frei is not None, (
        "kein freier Buchstabe mehr im Alphabet — dann ist die Gegenrichtung dieses Meta-Tests "
        "nicht mehr messbar, und das ist selbst ein Befund am Vergabeschema, kein Testfehler. "
        f"Belegt: {sorted(belegt)}")
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
