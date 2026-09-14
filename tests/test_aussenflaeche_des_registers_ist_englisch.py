"""Die Aussenflaeche des signierten Registers traegt keine deutsche Prosa — und der Pruefer
liefert seine REICHWEITE mit, nicht nur ein Urteil.

WARUM ES IHN GIBT. Regel R13 der Gegenlesung (``REVIEW_extern_registerform_61_20260911.md``,
Abschnitt 6) verlangt: „Bekannte deutsche Fachwoerter in Titel, Kurzbegruendung und erzeugte
Notizen einsetzen. Sprachpruefung muss rot werden." Gemessen am 2026-09-12: im ganzen Baum gab es
keinen Sprachpruefer — 0 Dateien fuer `sprachpruef`, `englisch`, `english_only`, `nur_englisch`,
`lang=`, `locale`. Der einzige Waechter, der dieselbe Flaeche liest
(``scripts/claims_hygiene_check.py``), prueft UEBERBEHAUPTUNGEN: ein eingepflanzter deutscher
Satz lief mit `0 violations` durch, eine eingepflanzte Ueberbehauptung wurde mit Zeile und
Wendung gefangen. Der Waechter funktioniert — er misst etwas anderes.

DIE REICHWEITE IST HIER SCHMAL, UND ZWAR ABSICHTLICH. Gemessen: das signierte Register hat GENAU
EIN Freitextfeld (``note``), 20 Notizen, 8114 Zeichen; ``id``, ``severity`` und ``status`` sind
geschlossene Wertemengen, dort ist Sprache keine Frage. Ob auch ``RESTRISIKO_600.md``, ``docs/``
und die README dazugehoeren sollen, ist eine offene Owner-Entscheidung — dieser Test entscheidet
sie NICHT, er deckt das Minimum und sagt in seiner eigenen Ausgabe, was er abgedeckt hat.

DIE WORTGRENZE IST DER GANZE TRICK, und sie hat mich beim ersten Versuch erwischt. Mit
``(?<![0-9a-zA-Z])`` traf ``nicht`` in ``test_gate_meta_koexistenz_im_selben_job_reicht_nicht_mehr``
— ein BEZEICHNER, keine Prosa. Unterstriche gehoeren nicht zu ``[0-9a-zA-Z]``, also ist ``_nicht_``
fuer diese Grenze ein eigenstaendiges Wort. Mit ``(?<![0-9a-zA-Z_])`` sind es null Treffer, und
die strengere Grenze faengt echte Prosa weiter (fuenf Treffer in der Probe). Gemessen: 8 von 20
Notizen tragen snake_case-Bezeichner — ohne diese Grenze laege dort die ganze Fehlalarm-Flaeche.
Dieselbe Grenzenfrage hat am 06.09. die Bahn-Zuordnung falsch geroutet und am 12.09. den
Office-Root-Riegel (``\\b`` gegen ``(?![-\\w])``).

DIE EHRLICHE GRENZE, und die Gegenlesung schreibt sie selbst vor: „Sprach- und Namenspruefungen
koennen bekannte Verstoesse zuverlaessig fangen, aber nicht jede unbekannte deutsche Wendung …
Deshalb die automatisierte Reichweite benennen und die redaktionelle Pruefung neuer oeffentlicher
Freitexte erhalten. 'Sprachreinheit vollstaendig bewiesen' waere eine Ueberbehauptung."
Darum steht unten ein Test, der die Reichweite AUSGIBT, und keiner, der Vollstaendigkeit behauptet.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
REGISTER = REPO / "audit_artifacts" / "findings_register_361.json"

#: Haeufige deutsche FUNKTIONSWOERTER. Bewusst keine Fachwoerter und keine Namen: Funktionswoerter
#: kommen in jeder deutschen Prosa vor und fast nie in englischer. Die Liste ist klein und steht
#: hier im Test — wo eine groessere Liste gefuehrt wuerde, ist eine offene Entscheidung.
_DEUTSCHE_FUNKTIONSWOERTER = (
    "aber", "auch", "damit", "dass", "der", "die", "das", "denn", "durch", "eine", "einen",
    "einer", "fuer", "ist", "sind", "kein", "keine", "nicht", "noch", "oder", "schon", "sondern",
    "ueber", "und", "weil", "werden", "wird", "wurde", "wurden",
)
#: DIE GRENZE SCHLIESST DEN UNTERSTRICH EIN. Ohne ihn ist `_nicht_` in einem Bezeichner ein Wort.
_MUSTER = re.compile(
    r"(?<![0-9a-zA-Z_])(" + "|".join(_DEUTSCHE_FUNKTIONSWOERTER) + r")(?![0-9a-zA-Z_])", re.I)
#: Code in Backticks ist Zitat, keine Prosa — dieselbe Unterscheidung wie im Office-Root-Riegel.
_CODESPANNE = re.compile(r"`[^`]*`")


def _notizen() -> list[str]:
    if not REGISTER.is_file():
        pytest.skip("audit_artifacts/findings_register_361.json liegt hier nicht")
    d = json.loads(REGISTER.read_text(encoding="utf-8"))
    return [str(f.get("note", "")) for f in d.get("findings", [])]


def _ohne_code(text: str) -> str:
    return _CODESPANNE.sub(" ", text)


def test_die_notizen_des_signierten_registers_tragen_keine_deutsche_prosa():
    notizen = _notizen()
    assert notizen, "keine Notizen gelesen — der Test misst dann nichts"
    treffer = []
    for i, t in enumerate(notizen):
        for m in _MUSTER.finditer(_ohne_code(t)):
            a, b = max(0, m.start() - 60), min(len(t), m.end() + 60)
            treffer.append(f"note[{i}] {m.group(1)!r} in …{t[a:b]}…")
    assert not treffer, (
        f"{len(treffer)} deutsche(s) Funktionswort(e) in den Notizen des SIGNIERTEN Registers — "
        f"das ist Aussenflaeche:\n  " + "\n  ".join(treffer[:5]) +
        "\nEntweder umformulieren, oder — wenn es ein zitierter Bezeichner ist — in Backticks "
        "setzen; Code in Backticks wird als Zitat behandelt und nicht geprueft.")


def test_der_pruefer_faengt_eine_eingepflanzte_deutsche_wendung():
    """Ohne diesen Fall waere ein gruenes Urteil auch mit kaputtem Muster vereinbar."""
    probe = "Die Vollstaendigkeitspruefung wird nicht durchgefuehrt, weil das Artefakt fehlt."
    gefunden = _MUSTER.findall(_ohne_code(probe))
    assert len(gefunden) >= 4, f"die Probe muss klar auffallen, gefunden: {gefunden}"


def test_ein_bezeichner_mit_deutscher_silbe_ist_KEIN_fund():
    """Die Gegenrichtung, und sie ist der Grund fuer die Unterstrich-Grenze.

    GEMESSEN am echten Register: genau EIN Scheintreffer entstand ohne diese Grenze, und zwar
    `nicht` in `test_gate_meta_koexistenz_im_selben_job_reicht_nicht_mehr`.
    """
    bezeichner = "test_gate_meta_koexistenz_im_selben_job_reicht_nicht_mehr"
    assert not _MUSTER.findall(bezeichner), (
        "ein snake_case-Bezeichner darf nicht als deutsche Prosa zaehlen — sonst misst der "
        "Pruefer Namen statt Sprache")
    assert not _MUSTER.findall("das_ergebnis_erreicht_die_flaeche_nicht")
    # Und ein zitierter Bezeichner in Backticks ebenfalls nicht:
    assert not _MUSTER.findall(_ohne_code("siehe `reicht nicht mehr` im Testnamen"))


def test_die_reichweite_wird_ausgegeben_nicht_behauptet(capsys):
    """Die Gegenlesung verlangt: die automatisierte Reichweite BENENNEN.

    Ein Pruefer, der nur ein Urteil liefert, laedt dazu ein, es fuer Vollstaendigkeit zu halten.
    Dieser Test misst und druckt, WORUEBER geurteilt wurde — und behauptet nichts darueber
    hinaus.
    """
    notizen = _notizen()
    zeichen = sum(len(t) for t in notizen)
    print(f"REICHWEITE: {len(notizen)} Notizen des signierten Registers, {zeichen} Zeichen, "
          f"{len(_DEUTSCHE_FUNKTIONSWOERTER)} Funktionswoerter, Code in Backticks ausgenommen.")
    print("NICHT GEPRUEFT: RESTRISIKO_600.md, docs/, README, Commit-Texte — und jede deutsche "
          "Wendung, die aus keinem dieser Funktionswoerter besteht. Sprachreinheit ist damit "
          "NICHT bewiesen, nur die benannte Menge ist gemessen.")
    assert len(notizen) > 0 and zeichen > 0
