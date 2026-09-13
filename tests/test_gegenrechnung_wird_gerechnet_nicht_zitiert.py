"""Der Traeger muss die Gegenrechnung fuehren, die zu SEINEM Bestand gehoert.

DER AUFTRAG. ``20260912T1317Z`` verlangt woertlich: "gegen die Fremdzaehlung rechnen,
gleich/fehlt/zu viel je Kennung." Das Inventar fuehrt dafuer ``cross_count``.

DER DEFEKT, gemessen 2026-09-13 — und er sass NICHT in den Daten. Die Eingabe
``RESTRISIKO_600_OBJEKTKLASSEN.json`` traegt ZWEI richtige Zahlen nebeneinander:

    gegenrechnung_gegen_die_sollliste        140 gleich, 0 fehlt, 2 zu viel
                                             richtig fuer den Stand vom 12.09. 13:16Z
    ...gegen_den_heutigen_bestand            140 gleich, 0 fehlt, 5 zu viel
                                             richtig fuer heute, mit Grund je Kennung

``gen_findings_register`` reichte den OBEREN durch. Der Traeger und BEIDE Ansichten
veroeffentlichten damit "2 extra", waehrend die aktuelle Zahl eine Ebene tiefer in
derselben Datei stand. Nicht die Daten waren veraltet — der Leser griff in das falsche
Fach, und niemand merkte es, weil beide Zahlen fuer sich stimmen.

EHRLICHKEITSMARKE ZU DIESEM TEST: seine erste Fassung behauptete im Docstring, "niemand
hat nachgerechnet". Das war falsch — jemand hatte, und hatte das Ergebnis als
``gegen_den_heutigen_bestand`` abgelegt, samt Vertrag
(``test_die_gegenrechnung_gegen_die_fremdzaehlung_ist_in_sich_stimmig``). Die Korrektur
steht hier, weil ein Test, der seinen Anlass falsch erzaehlt, die naechste Leserin in
dieselbe Fehldeutung fuehrt.

DIE PROBE, die den Fehlgriff zeigt, ist eine Addition: eine Kennung des Registers ist in
der Fremdzaehlung enthalten oder nicht, ein drittes Fach gibt es nicht. 140 + 2 = 142,
das Register traegt 145.

WARUM DIESER TEST OHNE DIE FREMDDATEI AUSKOMMT. Die Sollliste liegt im Repository
``2bedone``. Ein Test, der sie oeffnet, ist auf einem fremden Checkout nicht lauffaehig
und wuerde dort still uebersprungen — eine Luecke derselben Art. Er prueft deshalb die
ARITHMETIK des Blocks gegen die eigene Population und die EINIGKEIT der beiden Leser.
"""
from __future__ import annotations

import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
V2 = REPO / "audit_artifacts/600/findings_register_v2.json"


def _traeger() -> dict:
    if not V2.is_file():
        pytest.skip(f"kein v2-Traeger unter {V2.relative_to(REPO)}")
    return json.loads(V2.read_text(encoding="utf-8"))


def test_gegenrechnung_geht_auf():
    """gleich + zu_viel == die Zahl der getragenen Kennungen. Kein drittes Fach."""
    doc = _traeger()
    inv = doc["inventory"]
    cc = inv.get("cross_count")
    assert cc, "das Inventar fuehrt keinen cross_count — der Auftrag 1317Z verlangt ihn"

    getragen = inv["identifiers_in_this_register"]
    gleich, zu_viel, fehlt = cc.get("gleich"), cc.get("zu_viel"), cc.get("fehlt")
    for name, wert in (("gleich", gleich), ("zu_viel", zu_viel), ("fehlt", fehlt)):
        assert isinstance(wert, int), f"cross_count.{name} ist keine Zahl: {wert!r}"

    assert gleich + zu_viel == getragen, (
        f"die Gegenrechnung geht nicht auf: gleich {gleich} + zu viel {zu_viel} = "
        f"{gleich + zu_viel}, aber das Register traegt {getragen} Kennungen. "
        f"Differenz {getragen - gleich - zu_viel}. Eine Kennung ist entweder in der "
        f"Fremdzaehlung oder nicht — ein drittes Fach gibt es nicht. Der Block ist also "
        f"aelter als die Population, die er beschreibt.")


def test_jede_zu_viel_kennung_ist_einzeln_benannt_und_begruendet():
    """Wer 'zu viel' sagt, nennt WELCHE — und je Kennung, warum das kein Fund ist.

    Die frueher in der Ansicht fest verdrahtete Sammelbegruendung "named boundaries, not
    findings" stimmt fuer G1/G2 (``zaehlt_als_fund=false``) und haette S121-S123, die
    ``zaehlt_als_fund=true`` tragen, zu Grenzen erklaert.
    """
    doc = _traeger()
    cc = doc["inventory"].get("cross_count") or {}
    assert not cc.get("state"), f"die Gegenrechnung ist {cc.get('state')}: {cc.get('reason')}"
    welche = cc.get("zu_viel_welche") or []
    assert len(welche) == cc.get("zu_viel"), (
        f"zu_viel ist {cc.get('zu_viel')}, aufgezaehlt sind {len(welche)}: {welche}")

    gruende = cc.get("warum_zu_viel_je_kennung") or {}
    ohne = [k for k in welche if not gruende.get(k) or gruende[k] == "NOT EXPLAINED"]
    assert not ohne, (
        f"diese 'zu viel'-Kennungen tragen keine eigene Begruendung: {ohne}. Eine "
        f"Sammelbegruendung, die nur einen Teil der Liste nennt, deckt den Rest "
        f"stillschweigend mit ab.")


def test_der_zweite_leser_traegt_immer_einen_DEKLARIERTEN_zustand():
    """Ein fehlender Prüfer muss SICHTBAR fehlen — nie einfach nicht da sein.

    LINSE 2, 13.09.2026, ausführbar belegt: die erste Fassung trug bei fehlendem
    ``gegen_den_heutigen_bestand`` ein ``uebereinstimmung: None``, ``pruefe_v2`` prüfte auf
    ``is False``, und BEIDE Ansichten meldeten "145 equal, 0 missing, 0 extra" — ohne ein Wort
    darüber, dass der zweite Leser nie lief. Die Abwesenheit einer Prüfung sah aus wie ihr
    Bestehen.

    UND DER SCHÄRFERE TEIL, der diesen Test selbst betrifft: die frühere Fassung dieses
    Vertrags rief in genau diesem Zustand ``pytest.skip`` auf. Die Suite meldete dann
    "2 passed, 1 skipped" — von einem echt doppelt geprüften Lauf nicht zu unterscheiden.
    **Ein Skip darf keinen Ausfall verdecken.** Deshalb gibt es hier kein ``skip`` mehr: der
    Zustand wird VERLANGT, und ``FEHLT`` ist ein zulässiger, aber sichtbarer Wert.
    """
    doc = _traeger()
    cc = doc["inventory"].get("cross_count") or {}
    assert not cc.get("state"), f"die Gegenrechnung ist {cc.get('state')}: {cc.get('reason')}"
    zl = cc.get("zweiter_leser")
    assert isinstance(zl, dict) and zl.get("zustand") in {"EINIG", "UNEINIG", "FEHLT"}, (
        f"der zweite Leser trägt keinen deklarierten Zustand: {zl!r}. Ein Prüfer, der fehlt, "
        f"muss sichtbar fehlen — sonst liest sich seine Abwesenheit wie sein Bestehen.")
    assert zl["zustand"] != "UNEINIG", (
        f"gerechnet und handgezählt sind sich uneinig in {zl.get('abweichende_felder')}")
    if zl["zustand"] == "FEHLT":
        assert zl.get("grund"), "FEHLT ohne Grund ist eine Lücke, kein Zustand"


def test_die_begruendungen_bestehen_den_boden_DES_MODULS():
    """Der Test fragt das MODUL, statt die Regel nachzubauen.

    DEFEKT AN DIESEM TEST SELBST, gefunden 13.09.2026 beim dritten Umbau des Bodens: die erste
    Fassung hatte die Bedingung (``len(t) < 25 or len(t.split()) < 4``) hier WORTGLEICH
    nachgebaut. Zwei Fassungen derselben Regel an zwei Orten driften — und sie taten es sofort:
    der Boden im Modul verlor die Wortzahl (sie blockte einen chinesischen Satz und das
    hauseigene Bindestrich-Format), der Test hätte sie weiter verlangt. Ein Vertrag, der seinen
    Gegenstand NACHBAUT statt ihn zu BEFRAGEN, prüft am Ende sich selbst.

    Owner-Anker ``OA-714de2fcdd`` sagt dasselbe eine Ebene höher: *„kein zweiter Erzeuger, zwei
    Werkzeuge für dieselbe Frage driften."* Das gilt für Prüfer genauso.
    """
    import importlib.util

    doc = _traeger()
    spec = importlib.util.spec_from_file_location("gen_reg", REPO / "scripts/gen_findings_register.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)

    fehler = [f for f in m.pruefe_v2(doc, REPO) if f.startswith("[GR-")]
    assert not fehler, (
        "der Boden des Moduls beanstandet die Begründungen des erzeugten Trägers:\n  "
        + "\n  ".join(fehler))


def test_der_boden_faengt_platzhalter_und_laesst_echte_begruendungen_durch():
    """Fangkraft und Gegenrichtung an EINEM Ort — beides gemessen, nichts behauptet.

    Die Fälle stammen aus zwei Iterationen des Gates: Iteration 1 (Linse 1) widerlegte die
    Anwesenheits-Prüfung mit sechs Platzhaltern, Iteration 2 widerlegte den Ersatz in BEIDE
    Richtungen — er ließ Füllwörter durch und blockte ``'S121 postdates 2026-09-12T13:16Z'``,
    einen chinesischen Satz und das hauseigene durchgekoppelte Format.

    EHRLICHE GRENZE, als Fall geführt statt als Fußnote: Lorem ipsum besteht den Boden, und das
    ist Absicht. Ob eine Begründung WAHR ist, ist aus ihrem Text nicht entscheidbar; noch eine
    Formregel wäre derselbe Fehler eine Ebene tiefer.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("gen_reg2", REPO / "scripts/gen_findings_register.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)

    def beanstandet(grund: str) -> bool:
        ok = {"gegenrechnung_gegen_die_sollliste": {
            "sollliste_kennungen": ["A1"],
            "gegen_den_heutigen_bestand": {
                "gleich": 1, "fehlt": 0, "zu_viel": 1, "zu_viel_welche": ["G1"],
                "zu_viel_welche_grund": {"G1": grund}}}}
        cc = m._gegenrechnung(ok, [{"id": "A1"}, {"id": "G1"}])
        d = {"inventory": {"identifiers_in_this_register": 2, "identifiers_total": 2,
                           "identifiers_without_evidence": [], "coverage_gaps": [],
                           "cross_count": cc}, "records": []}
        # ORAKEL GENAU GENUG, sonst misst es die falsche Ursache. Gemessen 13.09.2026:
        # der Filter lautete `"Gegenrechnung:" in f` und fing, seit `pruefe_v2` die
        # Gegenrechnung NEU ABLEITET, auch die Abweichungsmeldung dieser Neuableitung mit —
        # denn eine synthetische Sonde weicht naturgemäß von den echten Daten ab. Der Test
        # meldete daraufhin „diese ECHTEN Begründungen werden zu Unrecht geblockt", obwohl
        # der Boden sie durchließ. Ein zu grobes Orakel meldet nicht nichts, es meldet das
        # FALSCHE — und schickt die Leserin in die falsche Richtung.
        return any(f.startswith("[GR-BEGRUENDUNG]") for f in m.pruefe_v2(d, REPO))

    muss_fangen = {
        "leer": "", "Lueckenwort": "NOT EXPLAINED", "Platzhalter": "TODO", "kurz": "n/a",
        "ein Token wiederholt": "G1 G1 G1 G1 G1 G1 G1 G1 G1 G1 G1 G1",
    }
    durchgerutscht = [k for k, v in muss_fangen.items() if not beanstandet(v)]
    assert not durchgerutscht, f"diese Platzhalter bestehen den Boden: {durchgerutscht}"

    muss_durchlassen = {
        "knapp mit Datum": "S121 postdates 2026-09-12T13:16Z",
        "ohne Leerzeichen (zh)": "此标识符在外部计数之后才被添加因此不可能出现在其中",
        "durchgekoppelt": "Nachtragsaufnahme-am-20260912T2215Z-nach-Sollliste",
        "Haus-Wortlaut": "benannte Grenze, kein Fund — die Fremdzaehlung kennt das Praefix G nicht",
    }
    geblockt = [k for k, v in muss_durchlassen.items() if beanstandet(v)]
    assert not geblockt, (
        f"diese ECHTEN Begründungen werden zu Unrecht geblockt: {geblockt}. Ein Riegel, der "
        f"Gesundes blockt, wird beim ersten Zeitdruck abgeschaltet.")
