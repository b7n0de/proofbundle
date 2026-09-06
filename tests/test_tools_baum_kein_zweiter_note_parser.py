"""Punkt 6, Review Runde 2 (Framing, 2026-09-05): eine STRUKTURELLE Sicherung statt eines einmaligen
Inventars. Ein Inventar altert (der naechste Commit unter ``tools/`` macht es falsch, ohne dass irgendwer
es merkt); ein Test, der bei jedem Lauf neu scannt, nicht.

WAS GEPRUEFT WIRD. ``checkpoint._split_signed_note`` traegt seit L1-600-NOTE-FRAMING-01 den EINEN
gemeinsamen Vertrag fuer C2SP-Notenrahmung in Python. Review Runde 1 verlangte, dass JEDE vorhandene
Rust- (oder sonstige Zweitsprachen-) Entsprechung denselben Vertrag traegt ODER nach vollstaendigem
Inventar NICHT betroffen ist. Runde 2 fand: das Paket lieferte dafuer nur eine BERICHTETE Suche und
einen Ausschnitt von ``main.rs`` — nicht reproduzierbar, nicht der GANZE ``tools``-Baum.

DIESER TEST scannt bei JEDEM Lauf den GANZEN ``tools``-Baum (jede Datei, jede Sprache — nicht nur
``*.rs``, damit ein kuenftiger Go-/JS-/C-Port genauso auffiele) nach den Markern, an denen sich eine
C2SP-Notenrahmung ausnahmslos zu erkennen gibt (``c2sp``, ``tlog-proof``/``tlog-checkpoint``,
``sumdb/note``, ``signed-note``, ``note.Open``/``note::open``). Jeder Treffer ausserhalb der ALLOWLIST
unten macht den Test ROT: kommt ein Note-Parser dazu, faellt er auf, ohne dass irgendwer daran denken
muss, ein Inventar nachzuziehen.

DIE ALLOWLIST ist selbst eine bewusste Entscheidung, keine Ausnahme ohne Begruendung: jede Zeile nennt
die Datei UND warum sie kein zweiter, konkurrierender Note-Parser ist. Die Gegenprobe unten
(``MetaSicherungFaengtEinenGepflanztenNoteParser``) pflanzt einen erfundenen Note-Parser in einen
temporaeren Baum und verlangt, dass der Scanner ihn NICHT uebersieht — sonst waere die Sicherung Zierde.

ZWEITE SCHICHT: DIE BAUFORM, NICHT DIE BENENNUNG (Gegenlesung 2026-09-05, Linse 2 von 6).
Die erste Fassung erkannte einen Note-Parser ausschliesslich an einer festen Sechs-Wort-Vokabelliste.
Die Gegenlesung fuhr den Pflanzversuch selbst und fand die Luecke: ein Rust-Parser mit GENAU derselben
C2SP-Rahmung, aber neutral benannt (``split_body_and_trailer`` statt ``split_signed_note``, keine
Herkunftskommentare), traegt keine der sechs Vokabeln — und blieb gruen. Alle drei damaligen
Meta-Pflanzungen trugen eine Vokabel WOERTLICH, der Test prueft also nur den Fall, den sein Autor im
Kopf hatte. Genau das ist der Fehlermodus, den die Auflage verhindern wollte: rot werden soll er beim
Hinzukommen EINES NOTE-PARSERS, nicht beim Hinzukommen eines Note-Parsers mit passendem Wortschatz.

Deshalb sucht der Scanner jetzt ZUSAETZLICH die BAUFORM: ein Doppelumbruch-Literal als Trenner UND ein
Em-Dash-Literal in DERSELBEN Datei. Beide Merkmale einzeln waeren wertlos (``\n\n`` steht in jedem
zweiten Stringliteral, das Em-Dash ist hier Kommentartrenner) — ihre KONJUNKTION ist die Rahmung, denn
so und nicht anders sieht eine C2SP-Note aus: Text, Leerzeile, Signaturzeilen mit ``— `` davor. Gemessen
am 2026-09-05 gegen den echten ``tools``-Baum: NULL zusaetzliche Treffer, also keine Falschalarme; gegen
den neutral benannten Parser der Gegenlesung: gefunden. Die Vokabelliste bleibt daneben stehen, sie
faengt den beschrifteten Fall frueher und nennt ihn beim Namen."""
from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TOOLS = REPO / "tools"

# Ausnahmslos die Marker, an denen sich EINE C2SP-Signed-Note/Checkpoint/tlog-proof-Rahmung in JEDER
# Sprache zu erkennen gibt — bewusst NICHT das blosse Wort "checkpoint" (zu generisch, ML-Checkpoints
# etc. waeren falsche Treffer) und NICHT das blosse EM-DASH-Zeichen "—" (dieses Repo nutzt es als
# Kommentartrenner in praktisch jeder Datei — ein Treffer darauf allein waere reine Zierde, kein Signal).
_NOTE_PARSER_MARKER = re.compile(
    r"c2sp|tlog[_-]?proof|tlog[_-]?checkpoint|sumdb[/\\]note|signed[_-]?note|note\.open|note::open",
    re.IGNORECASE,
)

# DIE BAUFORM. Kein Wortschatz, sondern die Form, in der eine C2SP-Note nun einmal gerahmt ist:
# Text, Leerzeile, Signaturzeilen mit EM-DASH davor. Ein Parser dafuer muss BEIDES im Quelltext
# tragen — den Doppelumbruch als Trenner und das Em-Dash als Zeilenmarke. Einzeln sagt keines von
# beiden etwas (siehe Modul-Docstring), zusammen sind sie die Rahmung.
_STRUKTUR_DOPPELUMBRUCH = re.compile(r"\\n\\n")
_STRUKTUR_EMDASH = re.compile(
    "\u2014"                       # das Zeichen selbst
    r"|\\u\{?2014\}?"              # Rust \u{2014}, Go/JS \u2014
    r"|\\xe2\\x80\\x94"             # C/Python-Bytefolge
    r"|U\+2014",                    # Prosa-Schreibweise in einem Kommentar
    re.IGNORECASE,
)
_STRUKTUR_MARKE = "BAUFORM:doppelumbruch+emdash"

_SKIP_DIRS = {".git", "target", "__pycache__", "node_modules", ".venv", "gocache", "gopath"}


def scan_for_note_parser_markers(root: Path) -> dict:
    """{relativer Pfad (posix) -> [gefundene Marker-Strings]} fuer jede Textdatei unter ``root``, deren
    Inhalt einen der Marker traegt. Binaerdateien (ein ``UnicodeDecodeError``) werden uebersprungen —
    ein Note-Parser ist immer Quelltext, nie ein kompiliertes Artefakt."""
    hits: dict = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        found = sorted(set(_NOTE_PARSER_MARKER.findall(text)))
        # zweite Schicht: die BAUFORM, unabhaengig von jeder Benennung (siehe Modul-Docstring)
        if _STRUKTUR_DOPPELUMBRUCH.search(text) and _STRUKTUR_EMDASH.search(text):
            found = sorted(set(found) | {_STRUKTUR_MARKE})
        if found:
            hits[path.relative_to(root).as_posix()] = found
    return hits


# Jede Zeile: Datei -> warum sie kein zweiter, konkurrierender Note-Parser ist. Alle drei gehoeren zu
# tools/go_note_differential/, dem in DIESER Lane (Punkt 2) gebauten, bereits geprueften ORAKEL, das die
# ECHTE Referenzimplementierung (golang.org/x/mod/sumdb/note.Open) aufruft — es IMPLEMENTIERT keine
# eigene Rahmung, es ruft die fremde Referenz auf und vergleicht ihr Urteil mit proofbundle.
_ALLOWLIST_BEGRUENDUNG = {
    "go_note_differential/main.go":
        "ruft golang.org/x/mod/sumdb/note.Open auf (vendorte Fremdabhaengigkeit, note.NewVerifier/"
        "note.Open/note.VerifierList) — keine eigene Rahmungslogik, reines Orakel-Treibprogramm.",
    "go_note_differential/README.md":
        "Dokumentation des Orakels, beschreibt note.Open als REFERENZ — kein Code, keine Rahmung.",
    "go_note_differential/treiber.py":
        "Python-Treiber, baut cases.json und ruft `go run .` (main.go) auf — reicht Bytes durch, "
        "parst selbst keine C2SP-Note.",
}
ALLOWLIST = frozenset((TOOLS / rel).resolve().relative_to(TOOLS.resolve()).as_posix()
                      for rel in _ALLOWLIST_BEGRUENDUNG)


class KeinZweiterNoteParserImToolsBaum(unittest.TestCase):
    """Der eigentliche Riegel: jeder Treffer im ECHTEN ``tools``-Baum muss auf der begruendeten
    Allowlist stehen — Gleichheit, nicht nur Teilmenge, damit auch eine ENTFERNTE Allowlist-Datei
    auffaellt (die Allowlist selbst darf nicht veralten)."""

    def test_jeder_marker_treffer_ist_die_begruendete_allowlist_nicht_mehr_nicht_weniger(self):
        hits = scan_for_note_parser_markers(TOOLS)
        gefunden = frozenset(hits)
        unerwartet = gefunden - ALLOWLIST
        fehlend = ALLOWLIST - gefunden
        self.assertEqual(
            unerwartet, frozenset(),
            f"neue Datei(en) mit Note-Parser-Markern ausserhalb der Allowlist: {sorted(unerwartet)} "
            f"(Marker je Datei: { {k: hits[k] for k in unerwartet} }) — pruefen, ob hier ein zweiter "
            "Note-Parser entsteht; wenn nein, mit Begruendung in _ALLOWLIST_BEGRUENDUNG aufnehmen, "
            "wenn ja, denselben Vertrag wie checkpoint._split_signed_note dort verdrahten")
        self.assertEqual(
            fehlend, frozenset(),
            f"Allowlist-Eintrag ohne Treffer mehr: {sorted(fehlend)} — die Datei wurde entfernt oder "
            "geaendert; die Allowlist muss nachgezogen werden, sonst deckt sie nichts mehr")

    def test_allowlist_ist_nicht_leer_und_jeder_eintrag_hat_eine_begruendung(self):
        # Anti-Tautologie eine Ebene hoeher: eine LEERE Allowlist wuerde den Test oben ebenfalls bestehen
        # lassen, ohne dass er je einen echten Treffer verarbeitet haette.
        self.assertGreater(len(ALLOWLIST), 0)
        for rel in ALLOWLIST:
            self.assertTrue(_ALLOWLIST_BEGRUENDUNG.get(rel), f"{rel} ohne Begruendung in _ALLOWLIST_BEGRUENDUNG")


class MetaSicherungFaengtEinenGepflanztenNoteParser(unittest.TestCase):
    """ANTITAUTOLOGIE: der Scanner MUSS einen erfundenen Note-Parser in einem isolierten Baum finden —
    sonst waere die Sicherung oben nur deshalb gruen, weil sie nie etwas gesehen hat."""

    def test_gepflanzter_go_note_parser_wird_gefunden(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "fremd").mkdir()
            (root / "fremd" / "parser.go").write_text(
                'package main\n// verarbeitet ein "tlog-checkpoint" mit EM-DASH-Signaturzeilen\n',
                encoding="utf-8")
            hits = scan_for_note_parser_markers(root)
            self.assertIn("fremd/parser.go", hits)
            self.assertIn("tlog-checkpoint", hits["fremd/parser.go"])

    def test_gepflanzter_sumdb_note_import_wird_gefunden(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "x.rs").write_text('// port of golang.org/x/mod/sumdb/note, signed-note style\n',
                                       encoding="utf-8")
            hits = scan_for_note_parser_markers(root)
            self.assertIn("x.rs", hits)
            self.assertTrue({"sumdb/note", "signed-note"} & set(hits["x.rs"]))

    def test_unverwandte_datei_bleibt_unauffaellig(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "harmlos.py").write_text(
                "def add(a, b):\n    return a + b\n# ein normaler Kommentar — mit Em-Dash, ohne Bezug\n",
                encoding="utf-8")
            hits = scan_for_note_parser_markers(root)
            self.assertEqual(hits, {}, "eine unverwandte Datei loeste einen Treffer aus — der Scanner "
                                      "ist zu weit gefasst")

    def test_binaerdatei_wird_uebersprungen_nicht_roh_gescheitert(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "blob.bin").write_bytes(bytes(range(256)))
            hits = scan_for_note_parser_markers(root)   # darf NICHT mit UnicodeDecodeError crashen
            self.assertEqual(hits, {})

    # DER FALL, DEN DIE VOKABELLISTE DURCHLIESS. Wortwoertlich die Datei, mit der die Gegenlesung am
    # 2026-09-05 die erste Fassung widerlegt hat: dieselbe Rahmung, neutral benannt, keine Vokabel.
    # Sie steht hier als FIXTURE und nicht nur im Bericht, damit die Empfindlichkeit beim naechsten
    # Umbau nicht still verlorengeht — ein extern einmal gefuehrter Nachweis schuetzt den naechsten
    # Commit nicht.
    NEUTRAL_BENANNTER_PARSER = (
        "pub fn split_body_and_trailer(input: &str) -> Option<(&str, &str)> {\n"
        '    let idx = input.rfind("\\n\\n")?;\n'
        "    let (body, rest) = input.split_at(idx);\n"
        "    if rest[2..].lines().all(|l| l.starts_with('\\u{2014} ')) "
        "{ Some((body, &rest[2..])) } else { None }\n"
        "}\n"
    )

    def test_neutral_benannter_note_parser_wird_trotzdem_gefunden(self):
        """Die Auflage sagt: rot beim Hinzukommen EINES Note-Parsers — nicht eines mit passendem
        Wortschatz. Dieser Parser traegt keine der sechs Vokabeln und muss dennoch auffallen."""
        self.assertEqual(
            sorted(set(_NOTE_PARSER_MARKER.findall(self.NEUTRAL_BENANNTER_PARSER))), [],
            "Vorbedingung dieses Tests: der Parser darf KEINE Vokabel tragen, sonst prueft er die "
            "Bauform-Schicht gar nicht")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "getarnt").mkdir()
            (root / "getarnt" / "parser.rs").write_text(self.NEUTRAL_BENANNTER_PARSER, encoding="utf-8")
            hits = scan_for_note_parser_markers(root)
            self.assertIn("getarnt/parser.rs", hits,
                          "ein neutral benannter Note-Parser blieb unentdeckt — die Sicherung faengt "
                          "nur den beschrifteten Fall (Gegenlesung 2026-09-05, Linse 2)")
            self.assertIn(_STRUKTUR_MARKE, hits["getarnt/parser.rs"])

    def test_die_bauform_allein_reicht_nicht_je_merkmal_fuer_sich(self):
        """Gegenrichtung: NUR ein Em-Dash (dieses Repo nutzt es als Kommentartrenner) oder NUR ein
        Doppelumbruch-Literal darf keinen Treffer erzeugen. Sonst waere die neue Schicht ein
        Falschalarm-Generator und wuerde die Allowlist aufblaehen, bis niemand mehr hinsieht."""
        faelle = {
            "nur_emdash.py": "# ein Kommentar \u2014 mit Em-Dash, ohne jede Rahmung\ndef f():\n    return 1\n",
            "nur_doppelumbruch.py": 'text = "a\\n\\nb"\n',
            "harmlos.go": "package main\n\nfunc add(a, b int) int { return a + b }\n",
        }
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for name, inhalt in faelle.items():
                (root / name).write_text(inhalt, encoding="utf-8")
            self.assertEqual(scan_for_note_parser_markers(root), {},
                             "ein einzelnes Merkmal loeste einen Treffer aus — die Bauform ist die "
                             "KONJUNKTION beider, nicht eines davon")

    def test_die_bauform_erzeugt_im_echten_baum_keinen_zusaetzlichen_treffer(self):
        """Gemessen am 2026-09-05: die neue Schicht findet im echten tools-Baum NICHTS, was die
        Vokabelliste nicht schon fand. Waechst hier je ein Treffer, ist das ein echter Befund und
        keine Justierschraube — die Allowlist wird dann mit Begruendung erweitert, nicht die Regel
        aufgeweicht."""
        hits = scan_for_note_parser_markers(TOOLS)
        nur_bauform = sorted(k for k, v in hits.items() if v == [_STRUKTUR_MARKE])
        self.assertEqual(nur_bauform, [],
                         f"neue Datei(en), die NUR ueber die Bauform auffallen: {nur_bauform} — pruefen, "
                         "ob dort eine zweite Notenrahmung entsteht")

    def test_allowlist_datei_selbst_waere_ohne_begruendung_ein_treffer(self):
        # Zeigt, dass die reale Allowlist keine leere Menge maskiert: dieselbe Marker-Regex trifft
        # tatsaechlich auf go_note_differential/main.go zu — die Begruendung deckt einen ECHTEN Treffer.
        hits = scan_for_note_parser_markers(TOOLS)
        self.assertIn("go_note_differential/main.go", hits)


if __name__ == "__main__":
    unittest.main()
