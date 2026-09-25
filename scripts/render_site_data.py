#!/usr/bin/env python3
"""render_site_data — site-data.json aus gemessenen Quellen im Repository und nichts sonst.

OWNER-AUFTRAG Z193, QITEM-PROOFBUNDLE-SITE-DATA-ERZEUGER-KENNZAHLEN-UND-PROOF-LOG-01, woertlich:
„Jeder Wert traegt Quelle und Messzeit. Ein Wert, den der Erzeuger nicht messen kann, steht als
nicht_messbar mit Grund, nie als 0 und nie als letzter bekannter Wert." Und: „Die Seite zeigt
Kennzahlen und einen Proof log, beides darf nie getippt sein."

═══ DER WIDERSPRUCH IM AUFTRAG, UND WIE ER HIER AUFGELOEST IST ═══

Der Auftrag verlangt zweierlei, das sich ausschliesst, solange „Messzeit" die LAUFZEIT meint:

    „Jeder Wert traegt Quelle und Messzeit."
    „Die Datei ist byte-stabil bei unveraenderten Quellen."

Eine Laufzeit in jedem Feld macht die Datei bei JEDEM Lauf anders, auch wenn sich keine Quelle
bewegt hat. Dann ist „byte-stabil" nicht erfuellbar, und ein Vertragstest darauf koennte nie gruen
werden.

AUFGELOEST SO: die Messzeit eines Wertes ist die Zeit des GEMESSENEN, nicht die des Laufs.

    aus einer Datei      der Commit, der sie zuletzt geaendert hat (Autorzeit, UTC)
    aus einem Tag        das Datum des Tags
    aus dem Netz         die Laufzeit, denn eine fremde Antwort hat keine andere Zeit

Damit ist alles aus dem Baum byte-stabil, und genau die Felder aus dem Netz sind es nicht — das
steht im Kopf der Datei als `stabil: false` mit Begruendung, statt als stille Ausnahme. Der
Vertragstest prueft die Stabilitaet ueber die BAUM-Felder und ueber nichts sonst; wer sie ueber
alles pruefte, haette einen Test, der bei jedem zweiten Lauf rot ist und darum abgeschaltet wird.

═══ WAS VOR DEM BAU GEMESSEN WURDE, weil drei Angaben des Auftrags so nicht zutreffen ═══

  checks     Der Auftrag nennt „3, aus der Liste der Verifier-Pruefungen im Code, nicht als
             Konstante". Ein echter Verify-Lauf an einem Konformanz-Buendel liefert ZWEI
             (`ed25519-signature`, `merkle-inclusion`). Die Zahl haengt am BUENDEL, nicht am Code:
             ein Buendel ohne Anker traegt keine Anker-Pruefung. Deshalb steht hier keine Zahl,
             sondern die gemessene Liste MIT dem Buendel, an dem sie gemessen wurde.
  interop    `docs/interop_status.json` existiert nicht. Eine gepflegte Liste ist Wissen, das
             jemand pflegt, keine Messung. Fehlt sie, steht `nicht_messbar` mit Grund.
  tests      4544 ist `def test_` ueber `tests/`, also OHNE parametrisierte Faelle und ohne
             Trennung von Modul- und Klassenmethoden. Die Zaehlregel steht IM Feld, sonst ist die
             Zahl bedeutungslos und ein spaeterer Lauf mit `--collect-only` nennt eine andere,
             ohne dass sich etwas geaendert hat.

═══ WAS DIESE DATEI NICHT TUT ═══

Sie schreibt keinen Schluessel und kein Token. Sie raet nichts. Sie traegt keinen letzten bekannten
Wert weiter — ein veralteter Wert ohne Kennzeichnung ist schlimmer als eine Luecke, weil er
gelesen wird wie eine Messung.

Aufruf:
    python3 scripts/render_site_data.py [--aus docs/site/site-data.json] [--kein-netz] [--json]

Exit: 0 geschrieben · 2 NICHT MESSBAR (keine Quelle lesbar, nichts geschrieben)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

#: Die Buendel, an denen die Verifier-Pruefungen gemessen werden. MIT Pfad im Ergebnis, damit die
#: Zahl nachpruefbar ist — eine Zahl ohne ihren Gegenstand ist die Konstante, die der Auftrag
#: ausschliesst, nur mit einem Umweg.
_MESS_BUENDEL = (
    "conformance/envelope_profile/r4-positive-control-issuer-is-the-signing-key/bundle.json",
)

#: Die Zaehlregel steht als DATEN neben der Zahl, nicht in einem Kommentar. Ein Leser, der 4544
#: sieht, muss wissen, was gezaehlt wurde.
_TEST_ZAEHLREGEL = (
    "Dateien: *.py direkt unter tests/. Funktionen: Zeilen, die auf 'def test_' passen, also EINE "
    "je Funktion — parametrisierte Faelle zaehlen als eins, Klassenmethoden werden nicht getrennt "
    "gezaehlt. Ein Lauf mit `pytest --collect-only` nennt eine andere Zahl, ohne dass sich etwas "
    "geaendert hat."
)


def _jetzt() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _git(*args: str, baum: Path | None = None) -> tuple[str, str]:
    """(stdout, lage). `lage` ist 'gemessen' oder ein NICHT-MESSBAR-Satz."""
    try:
        r = subprocess.run(["git", "-C", str(baum or REPO), *args],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return "", f"NICHT MESSBAR: {type(exc).__name__}: {exc}"
    if r.returncode != 0:
        return "", f"NICHT MESSBAR: git {' '.join(args)} rc={r.returncode}: {r.stderr.strip()[:120]}"
    return r.stdout.strip(), "gemessen"


def _stand_der_datei(rel: str) -> str | None:
    """Die Zeit des Commits, der diese Datei zuletzt geaendert hat — nicht die Laufzeit.

    `None`, wenn die Datei in keinem Commit steht. Das ist eine Aussage und kein Platzhalter: eine
    ungetrackte Datei hat keine Quellzeit, die ein Leser nachpruefen koennte.
    """
    aus, lage = _git("log", "-1", "--format=%aI", "--", rel)
    if lage != "gemessen" or not aus:
        return None
    return aus


def _feld(wert, *, quelle: str, stand: str | None, stabil: bool = True, **rest) -> dict:
    """Ein gemessener Wert mit Quelle und Messzeit."""
    d = {"wert": wert, "quelle": quelle, "gemessen_am": stand, "stabil": stabil}
    d.update(rest)
    return d


def _luecke(*, quelle: str, grund: str, **rest) -> dict:
    """NICHT MESSBAR mit Grund. Ausdruecklich KEIN 0, KEINE leere Liste, KEIN alter Wert.

    Der Auftrag nennt genau diese drei Ersatzformen und verbietet sie. Sie haben eine gemeinsame
    Eigenschaft: sie lesen sich wie eine Messung. Eine Luecke, die wie ein Wert aussieht, ist
    teurer als eine, die man sieht.
    """
    d = {"nicht_messbar": True, "grund": grund, "quelle": quelle, "gemessen_am": None,
         "stabil": True}
    d.update(rest)
    return d


# ── version, release_date, release_commit ───────────────────────────────────────────────────────
def version_und_release() -> dict:
    """Version aus pyproject, Datum und Commit aus dem Tag dieser Version."""
    p = REPO / "pyproject.toml"
    if not p.is_file():
        return {"version": _luecke(quelle="pyproject.toml", grund="pyproject.toml fehlt"),
                "release_date": _luecke(quelle="git tag", grund="ohne Version kein Tag"),
                "release_commit": _luecke(quelle="git tag", grund="ohne Version kein Tag")}
    m = re.search(r'^version\s*=\s*"([^"]+)"', p.read_text(encoding="utf-8"), re.M)
    if not m:
        return {"version": _luecke(quelle="pyproject.toml",
                                   grund="pyproject.toml traegt keine version-Zeile"),
                "release_date": _luecke(quelle="git tag", grund="ohne Version kein Tag"),
                "release_commit": _luecke(quelle="git tag", grund="ohne Version kein Tag")}
    v = m.group(1)
    stand = _stand_der_datei("pyproject.toml")
    aus = {"version": _feld(v, quelle="pyproject.toml:version", stand=stand)}

    tag = f"v{v}"
    datum, lage = _git("tag", "--list", tag, "--format=%(creatordate:iso-strict)")
    kopf, lage2 = _git("rev-list", "-n", "1", tag)
    if lage != "gemessen" or not datum:
        aus["release_date"] = _luecke(quelle=f"git tag {tag}",
                                      grund=f"kein Tag {tag} in diesem Baum — die Version in "
                                            "pyproject ist noch nicht veroeffentlicht")
        aus["release_commit"] = _luecke(quelle=f"git tag {tag}", grund=f"kein Tag {tag}")
        return aus
    aus["release_date"] = _feld(datum, quelle=f"git tag {tag}", stand=datum)
    aus["release_commit"] = (_feld(kopf, quelle=f"git rev-list -n1 {tag}", stand=datum)
                             if lage2 == "gemessen" and kopf else
                             _luecke(quelle=f"git rev-list -n1 {tag}", grund=lage2))
    return aus


# ── checks ──────────────────────────────────────────────────────────────────────────────────────
def verifier_pruefungen() -> dict:
    """Die Pruefungen eines ECHTEN Verify-Laufs, mit dem Buendel, an dem sie gemessen wurden.

    KEINE ZAHL OHNE IHREN GEGENSTAND. Der Auftrag sagt „nicht als Konstante"; eine Zahl, die aus
    einem Lauf kommt, dessen Gegenstand nicht dabeisteht, ist von einer Konstante nicht zu
    unterscheiden. Gemessen 25.09.2026 sind es an einem Envelope-Buendel ZWEI und nicht drei — ein
    Buendel ohne Ankerschicht traegt keine Anker-Pruefung.
    """
    ergebnisse = []
    for rel in _MESS_BUENDEL:
        p = REPO / rel
        if not p.is_file():
            ergebnisse.append({"buendel": rel, "nicht_messbar": True,
                               "grund": "Buendel fehlt in diesem Baum"})
            continue
        lage, namen = _verify(p)
        if namen is None:
            ergebnisse.append({"buendel": rel, "nicht_messbar": True, "grund": lage})
            continue
        ergebnisse.append({"buendel": rel, "anzahl": len(namen), "pruefungen": namen,
                           "stand": _stand_der_datei(rel)})
    messbar = [e for e in ergebnisse if "anzahl" in e]
    if not messbar:
        return _luecke(quelle="proofbundle verify ueber " + ", ".join(_MESS_BUENDEL),
                       grund="kein Messbuendel lieferte ein Ergebnis", laeufe=ergebnisse)
    return _feld(messbar[0]["anzahl"],
                 quelle=f"proofbundle verify {messbar[0]['buendel']}",
                 stand=messbar[0]["stand"], pruefungen=messbar[0]["pruefungen"],
                 laeufe=ergebnisse,
                 anmerkung=("die Zahl haengt am Buendel und nicht am Code; ein Buendel ohne "
                            "Ankerschicht traegt keine Anker-Pruefung"))


def _verify(pfad: Path) -> tuple[str, list[str] | None]:
    """(Lage, Pruefnamen). `None` heisst: nicht gemessen, und die Lage sagt warum.

    DER EINSTIEG IST `proofbundle.cli.main` UND NICHT `python -m proofbundle` — gemessen am
    25.09.2026: das Paket hat kein `__main__`, und der Modulaufruf endet mit „No module named
    proofbundle.__main__". Ein Erzeuger, der den falschen Einstieg nimmt, meldet fuer jedes Buendel
    NICHT MESSBAR und sieht dabei sorgfaeltig aus.
    """
    code = (
        "import json,sys; sys.path.insert(0,'src');"
        "from proofbundle import cli; sys.argv=['proofbundle','verify',%r,'--json'];"
        "\ntry: cli.main()\nexcept SystemExit: pass" % str(pfad)
    )
    try:
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                           timeout=180, cwd=str(REPO))
    except (OSError, subprocess.SubprocessError) as exc:
        return f"NICHT MESSBAR: {type(exc).__name__}: {exc}", None
    i = r.stdout.find("{")
    if i < 0:
        return (f"NICHT MESSBAR: verify gab kein JSON zurueck (rc={r.returncode}): "
                f"{(r.stderr or r.stdout).strip()[:140]}"), None
    try:
        d = json.loads(r.stdout[i:])
    except ValueError as exc:
        return f"NICHT MESSBAR: verify-Ausgabe ist kein JSON: {exc}", None
    # `checks` traegt `name`, `matrix` traegt `check` — zwei Formen derselben Liste, gemessen
    # 25.09.2026. Gelesen wird die Quelle, nicht die Darstellung.
    namen = [c.get("name") for c in (d.get("checks") or []) if c.get("name")]
    if not namen:
        namen = [c.get("check") for c in (d.get("matrix") or []) if c.get("check")]
    if not namen:
        return "NICHT MESSBAR: die verify-Ausgabe traegt keine Pruefnamen", None
    return "gemessen", namen


# ── tests ───────────────────────────────────────────────────────────────────────────────────────
def testflaeche() -> dict:
    d = REPO / "tests"
    if not d.is_dir():
        return {"tests_files": _luecke(quelle="tests/", grund="tests/ fehlt"),
                "tests_functions": _luecke(quelle="tests/", grund="tests/ fehlt")}
    dateien = sorted(p for p in d.glob("*.py"))
    n = 0
    for p in dateien:
        try:
            n += len(re.findall(r"^\s*def test_", p.read_text(encoding="utf-8"), re.M))
        except OSError:
            continue
    stand = _stand_der_datei("tests")
    return {"tests_files": _feld(len(dateien), quelle="tests/*.py", stand=stand,
                                 zaehlregel=_TEST_ZAEHLREGEL),
            "tests_functions": _feld(n, quelle="tests/*.py", stand=stand,
                                     zaehlregel=_TEST_ZAEHLREGEL)}


# ── interop ─────────────────────────────────────────────────────────────────────────────────────
def interop() -> dict:
    rel = "docs/interop_status.json"
    p = REPO / rel
    if not p.is_file():
        return _luecke(quelle=rel,
                       grund=("die gepflegte Liste fehlt in diesem Baum. Ihr Inhalt ist Wissen, "
                              "das jemand pflegt, und keine Messung — der Erzeuger kann sie lesen "
                              "und ihr Fehlen melden, ihren Inhalt nicht erfinden"))
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return _luecke(quelle=rel, grund=f"unlesbar: {type(exc).__name__}: {exc}")
    zeilen = d if isinstance(d, list) else (d.get("zeilen") or d.get("entries") or [])
    fehlend = [i for i, z in enumerate(zeilen)
               if not (isinstance(z, dict) and z.get("stand") and z.get("beleg") and z.get("datum"))]
    return _feld(zeilen, quelle=rel, stand=_stand_der_datei(rel),
                 ohne_pflichtfelder=fehlend,
                 anmerkung=("der Auftrag verlangt je Zeile Stand, Beleg und Datum; Zeilen ohne "
                            "diese drei stehen in ohne_pflichtfelder und sind nicht stillschweigend "
                            "ergaenzt"))


# ── proof_log ───────────────────────────────────────────────────────────────────────────────────
def _quittung_pruefen(d: dict) -> dict:
    """Eine Pre-Tag-Quittung mit IHREM Pruefer, nicht mit dem Buendel-Verifier.

    ERSTER ENTWURF SCHRIEB `failed` FUER ALLE VIER, und das waere ein Fehlalarm ueber die eigenen
    Release-Quittungen auf einer oeffentlichen Seite gewesen. Gemessen 25.09.2026: eine Pre-Tag-
    Quittung traegt `schema: b7n0de.pre_tag_audit_receipt.v1` mit `audit_command`,
    `audit_exit_code`, `signature`, `signer_pubkey`, `subject_tree_digest` — sie ist KEIN
    proofbundle-Buendel. `proofbundle verify` darauf liefert keine Pruefnamen, und mein Code las das
    als Fehlschlag.

    DREI ZUSTAENDE, NIE ZWEI: `passed` · `failed` · `nicht_pruefbar` mit Grund. `failed` heisst
    „geprueft und durchgefallen"; es fuer eine Artefaktart zu schreiben, die man mit dem falschen
    Werkzeug angefasst hat, ist eine Anschuldigung ohne Messung.

    WAS HIER GEPRUEFT WIRD und was ausdruecklich nicht: Signatur durch einen VERTRAUTEN Schluessel,
    Versionsbindung, und `audit_exit_code == 0`. NICHT geprueft wird die Bindung an den Baum — dafuer
    braeuchte es den Baum AM TAG, nicht den heutigen, und eine historische Quittung gegen den
    heutigen Baum zu halten muesste fehlschlagen, weil der Baum weitergelaufen ist. Das steht als
    `baumbindung: nicht_gepruefbar_ohne_auscheckung_am_tag` im Ergebnis, statt stillschweigend zu
    fehlen.
    """
    if not isinstance(d, dict) or d.get("schema") != "b7n0de.pre_tag_audit_receipt.v1":
        return {"zustand": "nicht_pruefbar",
                "grund": (f"unbekannte Artefaktart {(d or {}).get('schema')!r} — fuer sie ist hier "
                          "kein Pruefer erklaert, und ein Urteil ohne Pruefer waere geraten")}
    try:
        sys.path.insert(0, str(REPO / "src"))
        sys.path.insert(0, str(REPO / "scripts"))
        import importlib.util as _u  # noqa: PLC0415
        s = _u.spec_from_file_location("_ptl", REPO / "scripts" / "pre_tag_receipt_lib.py")
        lib = _u.module_from_spec(s)
        s.loader.exec_module(lib)
        from proofbundle._wire_b64 import decode_b64  # noqa: PLC0415
        from proofbundle.signature import verify_ed25519  # noqa: PLC0415
    except Exception as exc:  # noqa: BLE001 — ein nicht ladbarer Pruefer ist NICHT MESSBAR
        return {"zustand": "nicht_pruefbar",
                "grund": f"der Pruefer ist nicht ladbar: {type(exc).__name__}: {exc}"}

    try:
        vertraut = lib.load_trusted_pubkeys(REPO)
    except Exception as exc:  # noqa: BLE001
        return {"zustand": "nicht_pruefbar",
                "grund": f"die Liste der vertrauten Schluessel ist nicht lesbar: {exc}"}

    pub = d.get("signer_pubkey")
    if pub not in (vertraut or []):
        return {"zustand": "failed",
                "grund": "der signierende Schluessel steht nicht in "
                         "audit_artifacts/pre_tag_trusted_pubkeys.txt",
                "baumbindung": "nicht_gepruefbar_ohne_auscheckung_am_tag"}
    try:
        # DIE REIHENFOLGE IST (pubkey, signature, message) UND NICHT (pubkey, message, signature).
        # Erster Entwurf hatte die letzten zwei vertauscht. Der Aufruf gelang, gab einen bool
        # zurueck, und der bool war falsch: ALLE VIER echten Release-Quittungen meldeten „die
        # ed25519-Signatur haelt nicht", und das waere als Anschuldigung auf eine oeffentliche Seite
        # gegangen. Gemessen 25.09.2026; die richtige Reihenfolge steht in
        # pre_tag_receipt_lib.verify_receipt, Zeile ~282.
        ok = verify_ed25519(decode_b64(pub), decode_b64(d.get("signature")),
                            lib.canonical_bytes(d))
    except Exception as exc:  # noqa: BLE001
        return {"zustand": "nicht_pruefbar",
                "grund": f"die Signatur ist nicht auswertbar: {type(exc).__name__}: {exc}"}
    if not ok:
        return {"zustand": "failed", "grund": "die ed25519-Signatur haelt nicht",
                "baumbindung": "nicht_gepruefbar_ohne_auscheckung_am_tag"}
    if d.get("audit_exit_code") != 0:
        return {"zustand": "failed",
                "grund": f"audit_exit_code ist {d.get('audit_exit_code')!r} und nicht 0 — die "
                         "Quittung bezeugt einen FEHLGESCHLAGENEN Lauf",
                "baumbindung": "nicht_gepruefbar_ohne_auscheckung_am_tag"}
    return {"zustand": "passed",
            "geprueft": ["signatur_durch_vertrauten_schluessel", "audit_exit_code_0"],
            "baumbindung": "nicht_gepruefbar_ohne_auscheckung_am_tag",
            "baumbindung_grund": ("verify_receipt verlangt den erwarteten Baum-Digest; eine "
                                  "historische Quittung gegen den HEUTIGEN Baum zu halten muesste "
                                  "fehlschlagen, weil der Baum weitergelaufen ist")}


def proof_log(*, verifizieren: bool = True) -> dict:
    """Je Release die Pre-Tag-Quittung, ihr sha256, der Nachrechenbefehl und ein ECHTER Pruefer.

    DER ERZEUGER PRUEFT SELBST, und ein Fehlschlag steht als `failed` MIT Grund. Eine Quittung, die
    im Proof log steht, ohne dass jemand sie gefahren hat, ist eine Behauptung ueber eine Pruefung.
    Aber `failed` wird nur geschrieben, wenn wirklich geprueft wurde — sonst `nicht_pruefbar`.
    """
    eintraege = []
    for p in sorted((REPO / "audit_artifacts").glob("*/pre_tag_receipt_*.json")):
        rel = str(p.relative_to(REPO))
        try:
            rohe = p.read_bytes()
            inhalt = json.loads(rohe)
        except (OSError, ValueError) as exc:
            eintraege.append({"quittung": rel, "nicht_messbar": True, "grund": str(exc)[:140]})
            continue
        e = {
            "quittung": rel,
            "version": inhalt.get("version"),
            "sha256": hashlib.sha256(rohe).hexdigest(),
            "nachrechnen": f"sha256sum {rel}",
            "gemessen_am": _stand_der_datei(rel),
        }
        e["verify"] = (_quittung_pruefen(inhalt) if verifizieren else
                       {"zustand": "nicht_gefahren", "grund": "--kein-verify gesetzt"})
        eintraege.append(e)
    if not eintraege:
        return _luecke(quelle="audit_artifacts/*/pre_tag_receipt_*.json",
                       grund="keine Pre-Tag-Quittung in diesem Baum")
    return _feld(eintraege, quelle="audit_artifacts/*/pre_tag_receipt_*.json",
                 stand=max((e.get("gemessen_am") or "") for e in eintraege) or None)


# ── audit_state / audit_link ────────────────────────────────────────────────────────────────────
def audit_stand(version_wert) -> dict:
    d = REPO / "audit_artifacts"
    if not d.is_dir():
        return {"audit_state": _luecke(quelle="audit_artifacts/", grund="audit_artifacts/ fehlt"),
                "audit_link": _luecke(quelle="audit_artifacts/", grund="audit_artifacts/ fehlt")}
    stufen = sorted(p.name for p in d.iterdir() if p.is_dir() and p.name.isdigit())
    erwartet = None
    if isinstance(version_wert, str):
        teile = version_wert.split(".")
        if len(teile) >= 2 and all(t.isdigit() for t in teile[:2]):
            erwartet = f"{teile[0]}{teile[1]}0"
    stand = _stand_der_datei("audit_artifacts")
    if erwartet and erwartet not in stufen:
        return {"audit_state": _luecke(
                    quelle="audit_artifacts/", stufen=stufen,
                    grund=(f"fuer Version {version_wert} waere Stufe {erwartet} zu erwarten; sie "
                           f"liegt nicht. Vorhanden sind {', '.join(stufen)}")),
                "audit_link": _luecke(quelle="audit_artifacts/",
                                      grund=f"ohne Stufe {erwartet} kein Link")}
    stufe = erwartet or (stufen[-1] if stufen else None)
    if stufe is None:
        return {"audit_state": _luecke(quelle="audit_artifacts/", grund="keine Stufe vorhanden"),
                "audit_link": _luecke(quelle="audit_artifacts/", grund="keine Stufe vorhanden")}
    return {"audit_state": _feld(stufe, quelle="audit_artifacts/", stand=stand, stufen=stufen),
            "audit_link": _feld(f"audit_artifacts/{stufe}/", quelle="audit_artifacts/",
                                stand=stand)}


# ── scorecard ───────────────────────────────────────────────────────────────────────────────────
def scorecard(*, netz: bool = True) -> dict:
    ziel = "https://api.scorecard.dev/projects/github.com/b7n0de/proofbundle"
    if not netz:
        return _luecke(quelle=ziel, grund="--kein-netz gesetzt, also nicht gefragt", stabil=False)
    try:
        r = subprocess.run(["curl", "-sS", "--max-time", "25", ziel],
                           capture_output=True, text=True, timeout=40)
    except (OSError, subprocess.SubprocessError) as exc:
        return _luecke(quelle=ziel, grund=f"{type(exc).__name__}: {exc}", stabil=False)
    if r.returncode != 0:
        return _luecke(quelle=ziel, grund=f"curl rc={r.returncode}: {r.stderr.strip()[:140]}",
                       stabil=False)
    try:
        d = json.loads(r.stdout or "null")
    except ValueError as exc:
        return _luecke(quelle=ziel, grund=f"Antwort ist kein JSON: {exc}", stabil=False)
    if not isinstance(d, dict):
        return _luecke(quelle=ziel, grund=f"Antwort ist {type(d).__name__}, erwartet ein Objekt",
                       stabil=False)
    pruefungen = d.get("checks") or []
    # ALLE Werte, nicht die Gesamtnote. Der Auftrag sagt „alle 18 Werte"; wie viele es WIRKLICH
    # sind, sagt die Antwort und nicht der Auftrag — deshalb steht die gemessene Zahl daneben.
    return _feld({"score": d.get("score"),
                  "checks": [{"name": c.get("name"), "score": c.get("score"),
                              "reason": c.get("reason")} for c in pruefungen]},
                 quelle=ziel, stand=_jetzt(), stabil=False,
                 anzahl_pruefungen=len(pruefungen),
                 anmerkung=("aus dem Netz, deshalb nicht byte-stabil: eine fremde Antwort hat "
                            "keine Quellzeit im Baum, ihre Messzeit ist die Laufzeit"))


def baue(*, netz: bool = True, verify: bool = True) -> dict:
    vr = version_und_release()
    aus = {
        "schema": "b7n0de.proofbundle_site_data.v1",
        "erzeugt_von": "scripts/render_site_data.py",
        "erzeugt_am": _jetzt(),
        # DIE ERKLAERUNG DARF NICHT WIE EIN FELD AUSSEHEN. Erster Entwurf nannte die Schluessel
        # `messzeit`, `stabil` und `nicht_messbar` — dieselben Namen wie die Datenfelder. Die
        # Schleife, die die Luecken zaehlt, hielt den Erklaerungsblock darum fuer ein gemessenes
        # Feld ohne Grund und brach mit KeyError ab. Gemessen 25.09.2026 am ersten Lauf.
        #
        # Behoben an der KOLLISION und nicht am Einzelfall: die Schluessel heissen jetzt
        # `..._bedeutet`, also kann kein Leser und keine Schleife sie mit einem Wert verwechseln.
        # Ein Sonderfall in der Schleife haette dieselbe Klasse beim naechsten Erklaerungsblock
        # wieder erzeugt.
        "lesart": {
            "messzeit_bedeutet": ("die Zeit des GEMESSENEN, nicht die des Laufs: bei einer Datei der "
                         "Commit, der sie zuletzt geaendert hat, bei einem Tag sein Datum, beim "
                         "Netz die Laufzeit"),
            "stabil_bedeutet": ("true heisst: der Wert aendert sich nur, wenn seine Quelle sich aendert. "
                       "Felder mit false kommen aus dem Netz und machen die Datei bei jedem Lauf "
                       "anders — der Vertragstest prueft die Stabilitaet ueber die Baum-Felder"),
            "nicht_messbar_bedeutet": ("ein Wert, den der Erzeuger nicht messen kann, steht als "
                              "nicht_messbar mit Grund. Nie 0, nie eine leere Liste, nie ein "
                              "letzter bekannter Wert"),
        },
        **vr,
        **audit_stand(vr["version"].get("wert")),
        "checks": verifier_pruefungen(),
        **testflaeche(),
        "interop": interop(),
        "proof_log": proof_log(verifizieren=verify),
        "scorecard": scorecard(netz=netz),
    }
    return aus


def baum_felder(d: dict) -> dict:
    """Nur die Felder, die aus dem Baum kommen — der Gegenstand der Stabilitaetszusage."""
    return {k: v for k, v in d.items()
            if isinstance(v, dict) and v.get("stabil") is True}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--aus", type=Path, default=REPO / "docs" / "site" / "site-data.json")
    ap.add_argument("--kein-netz", action="store_true",
                    help="die Netzquellen nicht fragen; sie stehen dann als nicht_messbar mit "
                         "genau diesem Grund")
    ap.add_argument("--kein-verify", action="store_true",
                    help="die Quittungen nicht selbst nachrechnen; ihr Zustand ist dann "
                         "nicht_gefahren und ausdruecklich nicht passed")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    d = baue(netz=not a.kein_netz, verify=not a.kein_verify)
    luecken = [k for k, v in d.items() if isinstance(v, dict) and v.get("nicht_messbar")]
    if len(luecken) == len([k for k, v in d.items() if isinstance(v, dict) and "stabil" in v]):
        print("NICHT MESSBAR: keine einzige Quelle lesbar — nichts geschrieben", file=sys.stderr)
        return 2

    a.aus.parent.mkdir(parents=True, exist_ok=True)
    tmp = a.aus.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    tmp.replace(a.aus)

    if a.json:
        print(json.dumps(d, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"geschrieben: {a.aus.relative_to(REPO) if a.aus.is_relative_to(REPO) else a.aus}")
        print(f"  Felder: {len([k for k, v in d.items() if isinstance(v, dict) and 'stabil' in v])} "
              f"· nicht messbar: {len(luecken)}")
        for k in luecken:
            print(f"  ! {k}: {d[k]['grund'][:110]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
