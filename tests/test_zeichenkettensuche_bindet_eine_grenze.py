"""DIE KLASSE, nicht die drei Instanzen: eine Zeichenketten-Suche entscheidet ueber eine Groesse,
die eine GRENZE meint.

HERKUNFT (deep gate Lauf 5 gegen den 6.0.0-Kandidaten, 2026-09-07). Zwei Linsen fanden unabhaengig
denselben Fehlermodus an voellig verschiedenen Flaechen:

  * Linse 2, `pre_tag_receipt_lib._RECEIPT_MUSTER`: `.search()` auf die ganze `ls-tree`-Zeile ohne
    Anker am Pfadanfang. Jede Datei irgendwo im Baum mit passendem Pfad-ENDE fiel aus der
    Signaturbindung. Ausgefuehrt: Digest byteidentisch, Tor weiter `verified`.
  * Linse 5, `mutation_check._rote_aus_text`: `re.search(r"(\\d+) failed", blob)` nahm den ERSTEN
    Treffer im gesamten stdout. pytest kippt bei Fehlschlag den Testkoerper samt Docstring VOR die
    Bilanz. Ausgefuehrt: gepflanzter Defekt hob die wahre Roete 1->2, Parser meldete beide Male 0.

DER GEMEINSAME KERN, und er ist keine Code-Form: eine Suche ohne Anker beantwortet die Frage
"kommt dieser Text irgendwo vor?", waehrend die Stelle die Frage "liegt hier die GRENZE?" stellt.
Pfadgrenze, Bilanzzeile, Hunk-Kopf, TOML-Sektion — dieselbe verletzte Annahme.

DER SWEEP, der daraus folgte (2026-09-07): 50 `.search()`-Stellen in `scripts/` und `src/`
gesichtet. Nicht getroffen sind die, wo "irgendwo im Text" die GEWOLLTE Semantik ist (ein
Steuerzeichen irgendwo in einer signierten Notiz IST ein Fund) und die, die ihren Anker schon
tragen (`pre_tag_audit_gate` sucht je ABSATZ, `audit_candidate_matrix` schneidet am `(?:^|\\s)#`).
Getroffen und gefixt sind die vier Faelle, die diese Datei bindet.

Warum die Faelle HIER stehen und nicht je bei ihrer Instanz: ein Fix an vier Stellen ohne
gemeinsames Orakel ist vier Instanz-Fixes. Kommt die Klasse an einer FUENFTEN Flaeche wieder,
gehoert der Fall in diese Datei — nicht in eine neue.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]


def _skript(name: str):
    spec = importlib.util.spec_from_file_location(f"_grenze_{name}", REPO / "scripts" / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


# ── Instanz 3: die gesammelte Testzahl des Manifest-Tors ─────────────────────────────────────────

def test_die_sammelzahl_kommt_aus_der_bilanz_und_nicht_aus_dem_diagnosetext():
    """Dieselbe Klasse wie Linse 5, zweite Flaeche: `test_manifest_gate` entscheidet ueber die
    Bodenpruefung der Testmenge und las die Zahl mit `re.search` aus dem ganzen stdout."""
    m = _skript("test_manifest_gate")
    blob = (
        "==================================== ERRORS ====================================\n"
        '    """Doku eines Tests: 9999 tests collected in 1.00s, 7 errors"""\n'
        "E   ImportError: kaputt\n"
        "3840 tests collected, 2 errors in 12.34s\n")
    treffer = m._letzter_treffer(m._COLLECTED_RE, blob)
    assert treffer and int(treffer.group(1)) == 3840, (
        f"Die Sammelzahl kommt aus dem Diagnosetext statt aus der Bilanz: "
        f"{treffer.group(1) if treffer else None}. Eine Zahl aus einem Docstring entschiede dann "
        f"ueber den Boden, unter den die Testmenge nicht fallen darf.")
    fehler = m._letzter_treffer(m._ERROR_RE, blob)
    assert fehler and int(fehler.group(1)) == 2, "auch die Fehlerzahl gehoert in die Bilanz"


def test_ANTI_PARITAET_ohne_stoertext_bleibt_die_zahl_dieselbe():
    """Die Kontrolle: der Anker darf den Normalfall nicht verschieben."""
    m = _skript("test_manifest_gate")
    treffer = m._letzter_treffer(m._COLLECTED_RE, "3840 tests collected in 12.34s\n")
    assert treffer and int(treffer.group(1)) == 3840
    assert m._letzter_treffer(m._COLLECTED_RE, "nichts dergleichen") is None, (
        "ein Text ohne Bilanz muss None geben — sonst erfindet der Anker eine Zahl")


# ── Geprueft und KEIN Fund: der Hunk-Kopf des Signatur-Waechters ────────────────────────────────
#
# `mutant_signature_guard:103` sah aus wie die Klasse: `re.search(r"\+(\d+)", raw)` auf den
# Hunk-Kopf, dessen Ende einen Kontextausschnitt aus dem Quelltext traegt (`@@ -1,2 +3,4 @@
# def f(x=+999)`). Ein Anker wurde gebaut, ein Fangnachweis dazu geschrieben — und der Fangnachweis
# blieb OHNE den Anker gruen. Der Grund ist die Form selbst: `+neu` steht immer VOR dem
# Kontextausschnitt, die Struktur traegt den richtigen Treffer also ohne Zutun des Musters.
#
# Der Anker ist deshalb wieder entfernt. Das steht hier, weil ein zurueckgenommener Fund genauso
# zum Sweep gehoert wie ein bestaetigter: haette der Fall den Anker behalten, waere er gruen
# geblieben, egal was der Code tut, und haette eine gepruefte Flaeche vorgetaeuscht.

# ── Instanz 5 (latent): die Release-Version ohne Sektionsgrenze ──────────────────────────────────
#
# MEHRERE Skripte lesen die Version aus `pyproject.toml`, alle mit derselben Form
# `re.search(r'(?m)^\s*version\s*=\s*["\']...')`. `(?m)^` verankert an den ZEILENanfang, nicht an
# die SEKTION. TOML kennt aber Sektionen, und `version` ist ein Feld VON `[project]` — in
# `[build-system]`, `[tool.poetry]` oder jedem anderen Tisch darueber stuende ein anderer Wert
# gleichberechtigt am Zeilenanfang, und ALLE naehmen ihn.
#
# DIE LISTE HIESS "SECHS" UND TRUG VIER, und die fuenfte reale Instanz fehlte ganz (Linse C der
# Verify-Lane, 2026-09-07): `audit_candidate_matrix._version_aus_pyproject` liest mit demselben
# Muster und weist das Ergebnis der MODULGLOBALEN `VERSION_UNDER_TEST` zu — eine
# release-entscheidende Groesse, die der Klassen-Fix nicht erfasste. Die Ausnahme im Kopf-Docstring
# nannte diese Datei sogar, aber wegen einer ANDEREN, wirklich verankerten Stelle in ihr.
# Vierte Instanz der Kennzahl-Klasse an einem Tag, diesmal im Test, der die Klasse binden soll.
#
# DESHALB WIRD DIE MENGE JETZT GEMESSEN STATT GETIPPT: `test_die_liste_der_versionsleser_ist_
# VOLLSTAENDIG` sweept `scripts/*.py` nach dem Muster und verlangt, dass jede Fundstelle hier
# steht. Eine Liste, die niemand gegen die Wirklichkeit haelt, wird still zu kurz.
#
# HEUTE NICHT WIRKEND, gemessen: `pyproject.toml` traegt genau eine Zeile, die das Muster trifft
# (Zeile 7, in `[project]`), und `[build-system]` darueber hat kein `version`-Feld. Der Fall unten
# bindet deshalb die EIGENSCHAFT (alle Leser sind sich einig) und zeigt die Bruchstelle, statt
# sechs Implementierungen am Vorabend eines Tags umzubauen. Das ist die ehrliche Grenze dieses
# Sweeps und steht hier, damit sie nicht als erledigt gilt: der Umbau auf sektionsbewusstes Lesen
# ist ein eigener, ruhiger Zug.

#: (Skript, Funktion, nimmt_repo_argument). Die dritte Stelle ist noetig, weil
#: `audit_candidate_matrix._version_aus_pyproject` sein Repo aus einer Modulkonstante nimmt statt
#: als Argument — eine Form, die genau deshalb leicht uebersehen wird.
_VERSIONSLESER = (
    ("check_version_and_changelog", "_pyproject_version", True),
    ("pre_tag_audit_gate", "pyproject_version", True),
    ("findings_register", "_pyproject_version", True),
    ("sign_readiness_artifact", "pyproject_version", True),
    ("audit_candidate_matrix", "_version_aus_pyproject", False),
)

#: Das Muster, das die Klasse ausmacht: `version` am ZEILENanfang statt in seiner TOML-Sektion.
_VERSIONSMUSTER = re.compile(r'\(\?m\)\^\\s\*version\\s\*=')


def test_alle_versionsleser_sind_sich_ueber_DIESES_repo_einig():
    """Die Zusicherung: alle Wege zu einer Groesse muessen eine Antwort geben.

    Die Zahl steht nicht mehr im Satz. Sie stand hier als "sechs", waehrend die Liste vier trug —
    und niemand las beides nebeneinander (Linse C, 2026-09-07).
    """
    werte = {}
    for skript, funktion, nimmt_repo in _VERSIONSLESER:
        m = _skript(skript)
        werte[skript] = getattr(m, funktion)(REPO) if nimmt_repo else getattr(m, funktion)()
    assert len(set(werte.values())) == 1, (
        f"Die Versionsleser widersprechen sich: {werte}. Eine Freigabe, deren Version davon "
        f"abhaengt, welches Skript sie liest, bindet nichts.")
    assert werte["pre_tag_audit_gate"], "kein Leser lieferte eine Version — dann prueft dieser Fall nichts"


def test_die_bruchstelle_ist_die_SEKTIONSGRENZE_und_sie_ist_gezeigt(tmp_path):
    """Der Nachweis, dass die Einigkeit oben eine Eigenschaft DIESER Datei ist und nicht der Muster.

    Eine zweite `version`-Zeile in einem Tisch VOR `[project]` ist gueltiges TOML und veraendert die
    Release-Version nicht. Die Muster nehmen sie trotzdem. Dieser Fall haelt fest, DASS das so ist —
    er verlangt den Umbau nicht, er verhindert, dass die Luecke vergessen wird.
    """
    echt = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    manipuliert = '[build-system]\nversion = "0.0.1-nicht-die-release-version"\n\n' + echt
    (tmp_path / "pyproject.toml").write_text(manipuliert, encoding="utf-8")
    muster = re.compile(r'(?m)^\s*version\s*=\s*["\']([^"\']+)["\']')
    treffer = muster.search(manipuliert)
    assert treffer and treffer.group(1) == "0.0.1-nicht-die-release-version", (
        "Das Muster nimmt NICHT die erste passende Zeile — dann ist die hier dokumentierte "
        "Bruchstelle keine, und dieser Kommentar gehoert korrigiert statt konserviert.")
    # und die echte Datei traegt genau EINE solche Zeile — das ist der Grund, warum es heute haelt
    assert len(muster.findall(echt)) == 1, (
        f"pyproject.toml traegt {len(muster.findall(echt))} Zeilen, die das Muster treffen. Damit "
        f"ist die latente Luecke WIRKEND geworden und der Umbau auf sektionsbewusstes Lesen ist "
        f"faellig — er ist kein Aufschub mehr, sondern ein Defekt.")


def test_die_liste_der_versionsleser_ist_VOLLSTAENDIG():
    """DER KLASSEN-FIX ZUR LISTE SELBST: die Menge wird gemessen, nicht getippt.

    GEFUNDEN VON LINSE C (Verify-Lane, 2026-09-07): der Kommentar sprach von SECHS Skripten, die
    Liste trug VIER, und eine fuenfte reale Instanz stand ungenannt in
    `audit_candidate_matrix._version_aus_pyproject` — mit einer Ausschlussbegruendung im
    Kopf-Docstring, die sich auf eine ANDERE Stelle derselben Datei bezog. Eine Aufzaehlung neben
    einer Menge, die sich bewegt, wird still zu kurz; genau das ist die Klasse, die diese Datei
    bindet, und sie hatte sie an sich selbst.

    Dieser Fall sweept `scripts/*.py` nach dem zeilenverankerten Versionsmuster und verlangt, dass
    jede Fundstelle in `_VERSIONSLESER` gefuehrt ist. Findet jemand einen sechsten Leser und traegt
    ihn nicht ein, faellt dieser Fall — nicht erst der naechste Release.
    """
    gefunden = set()
    for pfad in sorted((REPO / "scripts").glob("*.py")):
        if _VERSIONSMUSTER.search(pfad.read_text(encoding="utf-8", errors="replace")):
            gefunden.add(pfad.stem)
    assert gefunden, (
        "der Sweep findet KEINE Stelle mit dem Versionsmuster — dann prueft dieser Fall nichts, "
        "statt still zu bestehen (das Muster selbst ist dann kaputt)")
    gefuehrt = {name for name, _f, _r in _VERSIONSLESER}
    fehlend = gefunden - gefuehrt
    assert not fehlend, (
        f"Diese Skripte lesen die Version mit dem zeilenverankerten Muster, stehen aber NICHT in "
        f"_VERSIONSLESER: {sorted(fehlend)}. Damit sagt die Zusicherung ueber sie nichts — und die "
        f"Liste behauptet eine Deckung, die sie nicht hat. Eintragen oder mit Begruendung "
        f"ausnehmen, aber nicht uebersehen.")


def test_ANTI_PARITAET_der_vollstaendigkeits_sweep_wuerde_einen_fehlenden_leser_melden(tmp_path):
    """DIE KONTROLLE. Ohne sie bestuende der Fall oben auch bei einem Sweep, der nie etwas findet."""
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "ein_neuer_leser.py").write_text(
        'import re\nm = re.search(r\'(?m)^\\s*version\\s*=\\s*["\']([^"\']+)["\']\', "")\n',
        encoding="utf-8")
    gefunden = {p.stem for p in sorted((tmp_path / "scripts").glob("*.py"))
                if _VERSIONSMUSTER.search(p.read_text(encoding="utf-8"))}
    assert gefunden == {"ein_neuer_leser"}, (
        f"Die Sweep-Logik faengt einen eingepflanzten neuen Leser NICHT (gefunden: {gefunden}) — "
        f"dann bestuende der Fall oben nur, weil nichts zu finden war.")
    assert not (gefunden & {name for name, _f, _r in _VERSIONSLESER}), (
        "der eingepflanzte Name kollidiert mit einem echten Eintrag — der Fall misst dann etwas anderes")
