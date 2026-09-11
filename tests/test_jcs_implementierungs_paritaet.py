"""Die beiden ausgelieferten JCS-Implementierungen muessen UEBEREINSTIMMEN, nicht nur fail-closed sein.

DEEP GATE, Lauf 10 am Kopf `1b2adc2`, Fund `L1-JCS-IMPL-SPLIT-01`, P1, von drei Juroren bestaetigt:
`tools/pb_verify_rs` kanonisiert ueber `serde_jcs 0.1`, Python ueber `rfc8785`. Dieselbe signierte
Datei bekam entgegengesetzte Verdikte — **in beide Richtungen**, 5 von 23 geprueften Werten.

WARUM DAS EINE RELEASE-AUSSAGE TRIFFT: `tools/pb_verify_rs/src/main.rs:1-7` erklaert woertlich, die
Aufgabe des zweiten Verifizierers sei, mit dem Python-Verifizierer UEBEREINZUSTIMMEN. Genau diese
Unabhaengigkeitsbehauptung verwandelt die Matrix-Zeile C8.2 in ein Release-Signal. Eine Seite, die
die korrekte Schreibweise der anderen abweist, hat die Zusage bereits gebrochen — auch wenn beide
Seiten je fuer sich fail-closed sind.

DIE ZWEITE HAELFTE DES FUNDES, und sie ist der Grund fuer DIESE Datei: das bisherige Differential
(`tools/pb_verify_rs/crosscheck.py`) zieht seine Faelle aus `conformance/manifest.json` — den
SELBST-DEKLARIERTEN Vektoren des Artefakts. `all_agree=true` ist damit eine Aussage ueber den
KORPUS, nicht ueber die Implementierungen. Ein Korpus, der nur enthaelt, was man ohnehin schon fuer
richtig haelt, kann eine Abweichung nicht finden, die niemand erwartet hat.

DAS ORAKEL BRAUCHT KEINEN NEUEN RUST-UNTERBEFEHL. Der `content-root` IST das
Kanonisierungs-Orakel: er ist der SHA-256 ueber die kanonischen Bytes (ADR 0002,
`canonical.statement_content_root`). Stimmen die Wurzeln fuer denselben Wert ueberein, stimmen die
kanonischen Bytes ueberein; weichen sie ab, kanonisieren die beiden Implementierungen verschieden.
Das ist eine ZWEISEITIGE Gleichheit und kein Fail-closed-Vergleich.

EHRLICHE GRENZE: ohne gebauten Rust-Verifizierer ist die Frage hier nicht beantwortbar, und der Fall
SKIPPT mit ausgeschriebenem Grund. Ein Skip ist keine Zusicherung — die CI baut den Verifizierer
(`ci.yml`, Schritt „Build the independent Rust second-verifier") vor dem Differential.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

import pytest

from proofbundle.canonical import statement_content_root

REPO = Path(__file__).resolve().parents[1]
BIN = REPO / "tools" / "pb_verify_rs" / "target" / "release" / "pb_verify_rs"


def _rust_content_root(v) -> tuple[str | None, str]:
    """Die Rust-Wurzel fuer einen Wert. Gibt (hex|None, grund) zurueck — wirft nie."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
        # ensure_ascii=False ist Absicht: die Nicht-BMP-Achse verlangt ECHTE Zeichen. Mit
        # \u-Fluchten in der Datei misst der Fall die Fluchtschreibweise statt der Sortierung, und
        # genau die Sortierung ist der Gegenstand.
        json.dump(v, fh, ensure_ascii=False)
        pfad = fh.name
    try:
        p = subprocess.run([str(BIN), "content-root", pfad],
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"{type(exc).__name__}: {exc}"
    finally:
        Path(pfad).unlink(missing_ok=True)
    if p.returncode != 0:
        return None, f"rc={p.returncode}: {(p.stderr or p.stdout or '').strip()[:160]}"
    return (p.stdout or "").strip(), "gemessen"


def _python_content_root(v) -> tuple[str | None, str]:
    try:
        return statement_content_root(v).hex(), "gemessen"
    except Exception as exc:                      # noqa: BLE001 — eine Ablehnung IST ein Ergebnis
        return None, f"{type(exc).__name__}: {str(exc)[:160]}"


def _korpus() -> list[tuple[str, object]]:
    """Der GENERIERTE Korpus, entlang der Achsen, die der Fund benennt.

    Kein Fixture-Verzeichnis: die Faelle entstehen aus der Struktur des Wertebereichs, nicht aus
    einer Liste dessen, was schon einmal aufgefallen ist.
    """
    faelle: list[tuple[str, object]] = []

    # ACHSE 1 — Schluesselsortierung nach UTF-16-Code-Units (RFC 8785 Abschnitt 3.2.3).
    # Ein Nicht-BMP-Zeichen ist in UTF-16 ein SURROGATPAAR, dessen erste Einheit
    # (U+D800..U+DBFF) KLEINER ist als jedes BMP-Zeichen ab U+E000. Nach Code-POINTS ist die
    # Ordnung genau umgekehrt. Hier trennt sich eine code-unit-korrekte von einer
    # code-point-Sortierung — und das ist die Achse, auf der der Fund liegt.
    for i, hoch in enumerate(("\U0001F600", "\U00010000", "\U0010FFFF")):
        for tief in ("", "￿", "�"):
            faelle.append((f"schluessel_nichtbmp_vs_bmp_{i}_{ord(tief):04x}",
                           {hoch: 1, tief: 2}))

    # ACHSE 2 — Ganzzahlbereich. I-JSON begrenzt exakt darstellbare Ganzzahlen auf 2^53; darueber
    # muss eine Implementierung ABWEISEN statt zu emittieren, und beide muessen dasselbe tun.
    for n in (2**53 - 1, 2**53, 2**53 + 1, -(2**53), 2**63 - 1, 2**63, -(2**63)):
        faelle.append((f"ganzzahl_{n}", {"n": n}))

    # ACHSE 3 — Zahlschreibweisen, die denselben Wert tragen.
    for name, wert in (("float_eins", 1.0), ("float_hundert", 1e2), ("float_minusnull", -0.0),
                       ("float_klein", 1e-7), ("float_gross", 1e21)):
        faelle.append((name, {"x": wert}))

    # ACHSE 4 — Fluchtschreibweisen und Steuerzeichen, in WERTEN und in SCHLUESSELN. Als Escapes
    # geschrieben, nicht als Literale: eine Quelldatei mit rohen Steuerzeichen ist beim Lesen und
    # beim Weiterreichen eine eigene Fehlerquelle.
    for name, s in (("nul", "\x00"), ("tab", "\t"), ("quote", '"'),
                    ("backslash", "\\"), ("del", "\x7f"),
                    ("lineseparator", "\u2028")):
        faelle.append((f"wert_escape_{name}", {"s": s}))
        faelle.append((f"schluessel_escape_{name}", {s: 1}))

    # ACHSE 5 — verschachtelt, damit die Sortierung nicht nur auf der obersten Ebene gemessen wird.
    faelle.append(("verschachtelt_nichtbmp",
                   {"a": {"\U0001F600": 1, "": 2},
                    "b": [{"￿": 3, "\U00010000": 4}]}))
    return faelle


@pytest.mark.skipif(not BIN.is_file(),
                    reason=(f"der zweite Verifizierer ist nicht gebaut ({BIN}); ohne ihn ist die "
                            "Uebereinstimmung NICHT MESSBAR — das ist keine Zusicherung. In CI "
                            "baut ihn der Schritt vor dem Differential."))
def test_beide_implementierungen_kanonisieren_gleich():
    """DIE ZUSICHERUNG: fuer JEDEN Wert des Korpus ist die Wurzel beider Seiten dieselbe.

    Ein abweichender Wert ist ein FEHLSCHLAG, unabhaengig davon, welche Seite RFC-konform ist — die
    Zusage des Repos ist Uebereinstimmung, nicht 'jede Seite fuer sich plausibel'.
    """
    korpus = [(n, v) for n, v in _korpus() if not n.startswith("ganzzahl_")]
    assert korpus, "der Generator lieferte keinen einzigen Fall — dann prueft dieser Knoten nichts"

    # DIE GANZZAHL-ACHSE IST HIER AUSGENOMMEN, und zwar benannt statt still. Sie ist am
    # 10.09.2026 gemessen OFFEN und liegt als Owner-Karte `jcs-integer-domain-600` vor: vier
    # verschiedene Werte jenseits 2^63 ergeben in Rust DIESELBE content-root, weil serde_json sie
    # als f64 parst. Der Fall wird eine Ebene tiefer geprueft, in
    # `test_die_ganzzahl_achse_stimmt_ueberein` — dort mit xfail(strict), damit die Behebung
    # AUFFAELLT statt still gruen zu werden.
    #
    # Ein stiller Filter waere hier der Fehler des Tages: er sieht aus wie eine gruene Achse.

    abweichungen = []
    for name, v in korpus:
        py, py_grund = _python_content_root(v)
        rs, rs_grund = _rust_content_root(v)
        if py == rs:
            continue
        abweichungen.append(
            f"{name}: python={py or py_grund} · rust={rs or rs_grund} · "
            f"wert={json.dumps(v, ensure_ascii=False)[:90]}")

    assert not abweichungen, (
        f"{len(abweichungen)} von {len(korpus)} generierten Werten kanonisieren VERSCHIEDEN:\n  "
        + "\n  ".join(abweichungen[:12])
        + ("\n  …" if len(abweichungen) > 12 else "")
        + "\n\nDie beiden ausgelieferten Verifizierer stimmen nicht ueberein. Solange das gilt, ist "
          "`all_agree` aus dem bestehenden Differential eine Aussage ueber den Korpus, nicht ueber "
          "die Implementierungen (deep gate Lauf 10, L1-JCS-IMPL-SPLIT-01, P1).")


def test_META_der_generator_deckt_die_benannten_achsen_ab():
    """Ohne diesen Fall koennte der Generator stillschweigend schrumpfen und der Knoten bliebe gruen.

    Ein Differential, dessen Korpus unbemerkt zusammenfaellt, ist genau der Fehlermodus, gegen den
    diese Datei gebaut wurde — nur eine Ebene hoeher. Er braucht kein Rust und laeuft ueberall.
    """
    namen = [n for n, _ in _korpus()]
    for achse in ("schluessel_nichtbmp_vs_bmp", "ganzzahl_", "float_",
                  "wert_escape_", "schluessel_escape_", "verschachtelt_"):
        assert any(n.startswith(achse) for n in namen), f"Achse {achse!r} fehlt im Generator"
    assert len(namen) >= 30, (
        f"der Generator liefert nur {len(namen)} Faelle — zu wenig fuer eine Flaeche")
    assert len(namen) == len(set(namen)), "doppelte Fallnamen — dann verdeckt ein Fall den anderen"


@pytest.mark.skipif(not BIN.is_file(), reason=f"der zweite Verifizierer ist nicht gebaut ({BIN})")
# DAS `xfail(strict=True)` IST HIER ENTFERNT, UND DAS IST DER VOLLZUG, NICHT DAS AUFRAEUMEN.
#
# Es stand hier, solange die Karte `jcs-integer-domain-600` offen war: Python wies Ganzzahlen
# jenseits [-(2^53)+1, 2^53-1] mit IntegerDomainError ab, Rust emittierte sie — und serde_json
# parste Werte jenseits i64/u64 als f64, sodass 9223372036854775807, ...808, ...809 und
# 9223372036854776000 DIESELBE content-root ergaben. Der content-root traegt die Signaturen;
# das war eine Kollision, keine Strenge-Frage.
#
# GEMESSEN 11.09.2026, bevor der Dekorator fiel: mit ihm meldete der Lauf `1 failed, 3 passed`
# — das FAILED war ein XPASS(strict), also genau das Erfolgssignal, das der Docstring unten
# ankuendigt. Der Fix in tools/pb_verify_rs liegt vor; die Achse divergiert nicht mehr.
# Owner-Anordnung OA-8da988f0bc, Option A (11.09.2026 06:55:09Z): "Fix committen, xfail strict
# entfernen". Ab jetzt ist dieser Fall ein gewoehnlicher Regressionstest: faellt die Paritaet
# je wieder, faellt er rot und nicht gruen.
def test_die_ganzzahl_achse_stimmt_ueberein():
    """Der Fall, der rot sein MUSS, solange die Karte offen ist — und der auffaellt, wenn sie faellt.

    `xfail(strict=True)` ist hier die ganze Aussage: wird die Divergenz behoben, meldet pytest
    XPASS und der Lauf faellt. Ein `skip` waere die stille Variante gewesen, und eine Luecke, die
    nach ihrer Behebung weiter uebersprungen wird, merkt niemand.
    """
    ganzzahlen = [(n, v) for n, v in _korpus() if n.startswith("ganzzahl_")]
    assert ganzzahlen, ("der Generator fuehrt keine Ganzzahl-Faelle mehr — dann ist der Filter im "
                        "Test darueber unbemerkt wirkungslos geworden")
    abweichungen = [n for n, v in ganzzahlen
                    if _python_content_root(v)[0] != _rust_content_root(v)[0]]
    assert not abweichungen, (
        f"{len(abweichungen)} von {len(ganzzahlen)} Ganzzahl-Faellen divergieren: {abweichungen}")


def test_META_die_ausgenommene_achse_ist_nicht_leer():
    """Ohne diesen Fall koennte `ganzzahl_` aus dem Generator verschwinden und beide Tests
    blieben gruen — der eine, weil er nichts mehr filtert, der andere, weil er nichts mehr
    findet. Er braucht kein Rust und laeuft ueberall."""
    namen = [n for n, _ in _korpus()]
    ganzzahl = [n for n in namen if n.startswith("ganzzahl_")]
    assert len(ganzzahl) >= 5, f"nur {len(ganzzahl)} Ganzzahl-Faelle im Generator: {ganzzahl}"
    assert len(namen) - len(ganzzahl) >= 20, "die uebrigen Achsen sind zu duenn geworden"
