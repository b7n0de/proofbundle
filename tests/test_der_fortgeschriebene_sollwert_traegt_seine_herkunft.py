"""Ein selbstgesetzter Sollwert muss seine HERKUNFT mitführen — nachrechenbar, nicht erzählt.

LINSE 3, 13.09.2026, ausführbar belegt: ``gemessen_an.sha256`` in
``RESTRISIKO_600_OBJEKTKLASSEN.json`` lässt sich ohne jede Freigabe auf den aktuellen Ist-Wert
von ``RESTRISIKO_600.md`` ziehen — danach sind ``test_ausgangsdigest_wird_verglichen`` UND
``test_der_sollwert_wird_nicht_aus_dem_register_abgeleitet`` beide grün. Der zweite schützt nur
gegen Selbstbezug **im Testcode** (er prüft per Substring, dass der Sollwert aus der
Objektklassen-Datei kommt), nicht gegen eine Umschreibung des Datenfeldes. Per grep verifiziert:
kein anderer Test im Baum liest ``gemessen_an``, ``_warum_fortgeschrieben`` oder
``_vorheriger_stand``.

**Die Absicherung war damit rein prozedural** — und in derselben Nacht habe ich den Sollwert
selbst fortgeschrieben (38e56bf6… → 16b856b2…). Genau dann, wenn man eine Regel selbst anwendet,
gehört sie in einen Träger: eine Prozedur, die nur der bindet, der sie kennt, bindet niemanden.

WAS DIESER TEST KANN, und die Grenze steht hier statt in einer Fußnote: er kann nicht wissen, ob
die Fortschreibung GEWOLLT war. Er verlangt zwei Dinge, die eine erfundene Fortschreibung nicht
liefern kann, ohne dass es auffällt:

  1. Eine Fortschreibung nennt ihren VORGÄNGER und einen Grund.
  2. Der genannte Vorgänger ist ein Digest, den die Datei in ihrer eigenen Geschichte WIRKLICH
     einmal trug. Ein erfundener Vorgänger fällt hier durch — und das ist der Unterschied zu
     einem Feld, in das man schreiben kann, was man will.
"""
from __future__ import annotations

import json
import importlib.util
import pathlib

import pytest

# DER ERZEUGER LIEGT IN scripts/, WEIL IHN AUCH PRODUKTIONSCODE RUFT: die Frage "liegt die
# Historie hier ueberhaupt vor" stellt sich audit_candidate_matrix.py genauso. Zwei Werkzeuge
# fuer dieselbe Frage driften (OA-714de2fcdd), also gibt es nur eines.
# DIE PFADFORM, NICHT DER BLANKE NAME — und das ist ein Fund des eigenen Riegels von heute
# frueh: `scripts/` wird NICHT ausgeliefert (MANIFEST.in kennt kein `graft scripts`, gemessen an
# SOURCES.txt). Ein blanker `from b7_historie import ...` auf Modulebene braeche im entpackten
# sdist das SAMMELN und mit ihm die ganze Suite. Die Pfadform nennt ein Verzeichnis, und `conftest`
# macht daraus ein ehrliches SKIP statt eines Abbruchs.
_HIST_PFAD = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "b7_historie.py"
_HIST_SPEC = importlib.util.spec_from_file_location("b7_historie", _HIST_PFAD)
_HIST = importlib.util.module_from_spec(_HIST_SPEC)
_HIST_SPEC.loader.exec_module(_HIST)
digest_in_historie = _HIST.digest_in_historie
letzte_abweichende_fassung = _HIST.letzte_abweichende_fassung

REPO = pathlib.Path(__file__).resolve().parents[1]
OBJEKTKLASSEN = REPO / "RESTRISIKO_600_OBJEKTKLASSEN.json"
QUELLE_REL = "RESTRISIKO_600.md"


def _gemessen_an() -> dict:
    if not OBJEKTKLASSEN.is_file():
        pytest.skip(f"{OBJEKTKLASSEN.name} liegt hier nicht")
    return json.loads(OBJEKTKLASSEN.read_text(encoding="utf-8")).get("gemessen_an") or {}


def test_eine_fortschreibung_nennt_vorgaenger_und_grund():
    g = _gemessen_an()
    assert g.get("sha256"), "gemessen_an trägt keinen sha256"
    vor = g.get("_vorheriger_stand")
    if vor is None:
        # Erstmessung: zulässig, aber dann darf auch keine Fortschreibungs-Begründung dastehen.
        assert not g.get("_warum_fortgeschrieben"), (
            "eine Fortschreibungs-Begründung ohne `_vorheriger_stand` behauptet eine Historie, "
            "die das Feld nicht trägt")
        return
    assert vor.get("sha256"), "`_vorheriger_stand` ohne sha256 ist keine Herkunft"
    assert g.get("_warum_fortgeschrieben"), (
        "der Sollwert wurde fortgeschrieben, ohne den Grund zu nennen — wer einen Prüfpunkt "
        "selbst verschiebt, schuldet die Begründung an derselben Stelle")
    assert vor["sha256"] != g["sha256"], "Vorgänger und aktueller Stand sind identisch"


def test_die_kette_ist_lueckenlos_und_ohne_wiederholung():
    """Kontinuität und Wiederholung — OHNE git prüfbar, und das ist der Punkt.

    RE-GATE, LINSE 3, 13.09.2026, drei Umgehungen ausgeführt gemessen:

      1. Ein Vorgänger, den es WIRKLICH gab, aber der nie der Sollwert war (z.B. der
         Ur-Digest der Datei) — der alte Vertrag prüfte nur „kommt irgendwo in der Historie
         vor", nie „stand er unmittelbar davor IN DIESEM FELD". GRÜN.
      2. Zweistufig: erst Stufe 1 fälschen, dann eine ehrlich aussehende Stufe 2 darauf —
         beide einzeln GRÜN, die erfundene Abstammung wird stillschweigend absorbiert.
      3. Ohne ``.git`` (sdist, Docker, nachgelagerte CI) mit einem FREI ERFUNDENEN Vorgänger:
         ``1 passed, 1 skipped``, RC=0. Der einzige Test, der echt von erfunden trennt, lief
         gar nicht — **ein Skip liest sich wie Bestehen**.

    Und viertens, ohne Messung entscheidbar: **sha256 trägt keine Richtung.** Ein byte-genauer
    Rückfall auf einen älteren echten Stand ist von einem Fortschritt nicht zu unterscheiden,
    solange beide in der Historie vorkommen.

    Die Kette in den DATEN beantwortet 1, 2 und 4 ohne git: der genannte Vorgänger muss das
    letzte Glied sein, und der aktuelle Wert darf in der Kette nicht schon einmal vorkommen.
    """
    g = _gemessen_an()
    kette = g.get("_kette")
    vor = g.get("_vorheriger_stand")
    if vor is None:
        assert not kette, "eine Kette ohne Fortschreibung behauptet eine Geschichte, die es nicht gibt"
        return
    assert isinstance(kette, list) and kette, (
        "es gibt eine Fortschreibung, aber keine Kette `_kette` — dann ist die Herkunft nur "
        "erzählt und ohne git gar nicht prüfbar")

    digests = [k.get("sha256") for k in kette]
    assert all(digests), "ein Kettenglied ohne sha256 ist kein Glied"
    assert digests[-1] == vor.get("sha256"), (
        f"der genannte Vorgänger {str(vor.get('sha256'))[:16]}… ist NICHT das letzte Glied der "
        f"Kette ({str(digests[-1])[:16]}…). Ein Vorgänger, der irgendwo in der Historie vorkommt, "
        f"aber nie der Sollwert war, ist keine Herkunft.")
    assert len(set(digests)) == len(digests), (
        f"die Kette wiederholt ein Glied: {digests}. Eine Wiederholung ist ein Rückfall, der sich "
        f"als Fortschritt ausgibt.")
    # RÜCKFALL: verboten — AUSSER er ist erklärt. Re-Gate Iteration 3, Linse 2, Achse D:
    # die erste Fassung lehnte auch einen OFFEN DOKUMENTIERTEN, legitimen Rückbau hart ab. Der
    # einzige Ausweg wäre gewesen, den Digest künstlich zu verändern — also genau das zu tun,
    # wogegen die Kette gebaut ist. Ein Riegel, der einen ehrlichen Vorgang unmöglich macht,
    # wird beim ersten Zeitdruck abgeschaltet; dann ist auch der unehrliche Fall wieder frei.
    # Deshalb: möglich, aber SICHTBAR. Wer zurückbaut, sagt worauf und warum.
    if g.get("sha256") in digests:
        rb = g.get("_rueckbau")
        assert isinstance(rb, dict), (
            f"der aktuelle Sollwert {str(g.get('sha256'))[:16]}… steht schon in der Kette — ein "
            f"byte-genauer Rückfall. sha256 trägt keine Richtung, die Kette muss sie tragen. "
            f"Ein GEWOLLTER Rückbau ist zulässig, aber er gehört deklariert: Feld `_rueckbau` "
            f"mit `auf` und `grund`.")
        assert rb.get("auf") == g.get("sha256"), (
            f"`_rueckbau.auf` ({str(rb.get('auf'))[:16]}…) nennt nicht den Wert, auf den "
            f"tatsächlich zurückgebaut wurde ({str(g.get('sha256'))[:16]}…)")
        grund = (rb.get("grund") or "").strip()
        assert len(grund) >= 25 and grund != "NOT EXPLAINED", (
            f"`_rueckbau.grund` ist kein Satz ({grund!r}). Derselbe Boden wie bei den "
            f"Begründungen der Gegenrechnung: er schließt Platzhalter aus, er beweist nichts.")


def test_die_kette_setzt_die_COMMITTETE_kette_fort():
    """Unmittelbarkeit statt Mitgliedschaft — die Lücke, die Iteration 3 fand.

    RE-GATE ITERATION 3, LINSE 2, ausgeführt gemessen: ein Vorgänger, den es WIRKLICH gab, der
    aber drei Fortschreibungen alt ist statt der unmittelbare, lief **3 passed, RC=0, vollständig
    grün**. Grund: der git-Test prüft nur MITGLIEDSCHAFT in der Historie von
    ``RESTRISIKO_600.md`` — nie, ob der genannte Wert unmittelbar davor im FELD stand. Und per
    grep verifiziert: nirgends wurde ``_kette`` gegen die zuvor COMMITTETE Fassung dieser JSON
    selbst gehalten.

    Dieser Test schließt genau das. Er liest die committete Vorfassung der Objektklassen-Datei
    und verlangt zweierlei:

      1. **Append-only.** Die committete Kette ist ein PRÄFIX der jetzigen — Glieder werden
         angehängt, nie umgeschrieben, nie umsortiert.
      2. **Unmittelbarkeit.** Der committete ``gemessen_an.sha256`` ist das LETZTE Glied der
         jetzigen Kette. Wer fortschreibt, hängt genau den Wert an, der vorher galt — nicht
         irgendeinen aus der Historie.

    EHRLICHE GRENZE, und sie bleibt: ohne git ist beides nicht prüfbar. Der Skip nennt deshalb
    ausdrücklich, WELCHE Eigenschaft dann ungeprüft bleibt, statt nur zu schweigen — ein Skip,
    der seinen blinden Fleck benennt, ist etwas anderes als einer, der wie Bestehen aussieht.
    """
    import json as _json

    g = _gemessen_an()
    kette = g.get("_kette")
    if not kette:
        pytest.skip("keine Kette — dann gibt es auch keine Fortsetzung zu prüfen")
    if not (REPO / ".git").exists():
        pytest.skip(
            "UNGEPRÜFT OHNE GIT: ob die Kette die committete Vorfassung FORTSETZT und ob der "
            "genannte Vorgänger der UNMITTELBARE war, ist ohne Historie nicht entscheidbar. "
            "Die Konsistenz der Kette in sich wurde geprüft, ihre Echtheit nicht.")

    # GEGEN DIE LETZTE ABWEICHENDE FASSUNG, NICHT GEGEN HEAD (Codex r3999796582).
    #
    # Die Vorgaengerfassung las den Arbeitsbaum und verglich ihn gegen `git show HEAD:` DERSELBEN
    # Datei. In einem sauberen Checkout — und das ist jeder CI-Lauf — sind beide byte-gleich. Die
    # Zusicherung "die Kette setzt die committete fort" verglich damit die Kette mit sich selbst
    # und war trivial wahr. Ein Umschreiben oder Kuerzen der Kette blieb gruen, sobald es committet
    # war, und genau das ist der Fall, gegen den dieser Test steht.
    #
    # Gefragt ist die UNMITTELBARE Vorfassung, und die ist die letzte in der Historie, die sich
    # vom heutigen Inhalt UNTERSCHEIDET. Das haelt beide Lagen richtig: im dirty Worktree ist das
    # HEAD, im sauberen Checkout die Fassung davor. Der Skip-Text dieser Funktion behauptet diese
    # Eigenschaft seit jeher — jetzt misst sie sie auch.
    # DREI ZUSTAENDE, NICHT ZWEI (Codex 4000088153). Die Vorgaengerfassung deutete jedes
    # Nicht-Finden als Erstaufnahme. Im flachen Klon ist das falsch: es gibt eine Vorfassung, sie
    # ist nur nicht abrufbar. "nicht gefunden" und "nicht nachsehbar" duerfen nicht dasselbe Wort
    # tragen — der Erzeuger trennt sie, dieser Fall nennt den Grund, den er bekommt.
    zustand, vor_commit, vor_bytes, grund = letzte_abweichende_fassung(
        REPO, OBJEKTKLASSEN.name, OBJEKTKLASSEN.read_bytes())
    if zustand == "NICHT MESSBAR":
        pytest.skip(f"UNGEPRUEFT: {grund}. Ob die Kette die committete Vorfassung FORTSETZT, ist "
                    f"hier nicht entscheidbar. Das ist ausdruecklich KEIN Bestehen.")
    if zustand == "ERSTAUFNAHME":
        pytest.skip("keine abweichende Vorfassung in der Historie — Erstaufnahme, es gibt nichts "
                    "fortzusetzen. Das ist ausdruecklich KEIN Bestehen der Fortsetzungspruefung.")
    alt = (_json.loads(vor_bytes.decode("utf-8")).get("gemessen_an") or {})
    alt_kette = alt.get("_kette") or []

    assert kette[:len(alt_kette)] == alt_kette, (
        f"die Kette setzt die Vorfassung aus {vor_commit[:12]} NICHT fort: dort "
        f"{[k.get('sha256','')[:12] for k in alt_kette]}, "
        f"jetzt {[k.get('sha256','')[:12] for k in kette]}. Glieder werden ANGEHÄNGT, nie "
        f"umgeschrieben — sonst ist die Kette eine Erzählung mit Rückwirkung.")

    if alt.get("sha256") and alt["sha256"] != g.get("sha256"):
        assert kette[-1].get("sha256") == alt["sha256"], (
            f"der Sollwert wurde fortgeschrieben, aber das letzte Kettenglied "
            f"({str(kette[-1].get('sha256'))[:16]}…) ist NICHT der Wert, der zuletzt committet "
            f"war ({alt['sha256'][:16]}…). Ein Vorgänger aus der Historie ist nicht dasselbe wie "
            f"DER Vorgänger.")


def test_der_genannte_vorgaenger_stand_wirklich_einmal_in_der_datei():
    """Der Teil, den man nicht erzählen kann: der Vorgänger muss in der Historie vorkommen."""
    g = _gemessen_an()
    vor = g.get("_vorheriger_stand")
    if not vor:
        pytest.skip("keine Fortschreibung vermerkt — nichts nachzurechnen")
    if not (REPO / ".git").exists():
        pytest.skip("kein git-Baum (sdist) — die Historie ist hier nicht lesbar")

    # HIER SASS DAS FALSCHE ROT (Codex 4000088153). Die Vorgaengerfassung lief los, sobald `.git`
    # dastand, und deutete jedes Nicht-Finden als erfundene Herkunft. Gemessen in einem Klon mit
    # Tiefe 1 — und so checkt die Pflichtmatrix aus — meldete sie "eine Herkunft, die es nie gab"
    # ueber eine Herkunft, die es gibt. Ein Riegel, der in seiner eigenen Pflichtumgebung falsch
    # anschlaegt, wird abgeschaltet, und dann ist auch der echte Fall wieder frei.
    zustand, grund = digest_in_historie(REPO, QUELLE_REL, vor["sha256"])
    if zustand == "NICHT MESSBAR":
        pytest.skip(f"UNGEPRUEFT: {grund}. Ob der genannte Vorgaenger wirklich einmal in der Datei "
                    f"stand, ist hier nicht entscheidbar — das ist KEIN Bestehen.")
    assert zustand == "GEFUNDEN", (
        f"der als `_vorheriger_stand` genannte Digest {vor['sha256'][:16]}… gehört zu KEINER "
        f"Fassung von {QUELLE_REL} in der Historie dieses Baums ({grund}). Eine Herkunft, die es "
        f"nie gab, ist keine Herkunft — sie ist die Behauptung einer.")
