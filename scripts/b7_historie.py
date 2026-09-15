"""Ob die HISTORIE hier vorliegt, wird GEMESSEN — nicht aus der Existenz von `.git` geschlossen.

FUND, Codex 4000088153 (P1). Die Herkunfts-Zusicherungen fragten `(REPO / ".git").exists()` und
liefen danach los, als waere die Geschichte damit da. In einem flachen Klon ist `.git` da und
`git log` antwortet — nur eben mit genau einem Commit. Der als Vorgaenger genannte Digest ist dann
nicht zu finden, und der Fall meldete "eine Herkunft, die es nie gab". Das ist ein FALSCHES ROT:
die Herkunft gibt es, die Historie ist abgeschnitten. Gemessen in `git clone --depth 1`:
1 failed. Die Pflichtmatrix in `.github/workflows/ci.yml` checkt ohne Tiefenangabe aus, also flach.

DIE KLASSE: eine Zusicherung, die eine VORBEDINGUNG aus einem Stellvertreter schliesst, statt sie
zu messen. `.git` ist der Stellvertreter, "die Historie reicht zurueck" die Eigenschaft. Beide
fallen fast immer zusammen — ausser im flachen Klon, und der ist der Normalfall in CI.

DREI ZUSTAENDE, NICHT ZWEI, und darin liegt der Fix. "nicht gefunden" und "nicht nachsehbar"
duerfen nicht dasselbe Wort tragen: das erste ist ein Fund, das zweite ein blinder Fleck. Ein
blinder Fleck, der seinen Grund nennt, ist etwas anderes als ein Bestehen — und etwas anderes als
ein Fehler.

EIN ERZEUGER, NICHT ZWEI. Zwei Dateien brauchen dieselbe Auskunft; sie steht deshalb hier und
wird dort importiert. Zwei Werkzeuge fuer dieselbe Frage driften.
"""
from __future__ import annotations

import hashlib
import pathlib
import subprocess

#: Warum als Konstante: der Text steht in Skip-Gruenden UND in den Faengen, die ihn pruefen.
ABGESCHNITTEN = "die Historie ist hier abgeschnitten (flacher Klon)"

#: EIN NICHT LESBARER BLOB IST KEIN ANDERER INHALT (Jury Linse 3, 13.09.2026). In einem partial
#: clone (`--filter=blob:none`) liefert `git log` die GANZE Liste der Commits, aber `git show`
#: scheitert auf jedem Blob, der noch nicht nachgeladen ist — und ohne erreichbaren Ursprung
#: dauerhaft. GEMESSEN: drei Commits sichtbar, `git show <aeltester>:<datei>` mit RC 128
#: ("bad object"). Die Vorgaengerfassung uebersprang das still und meldete danach NICHT GEFUNDEN —
#: also genau das falsche ROT, gegen das diese Datei gebaut ist, nur ueber einen dritten
#: Stellvertreter. Partial clones sind ein empfohlenes Standardmuster fuer grosse Repositorien.
_UNLESBAR = ("{n} Fassung(en) dieser Datei sind hier nicht LESBAR (partial clone, entfernte oder "
             "beschaedigte Objekte) — die Liste der Commits ist vollstaendig, ihr Inhalt nicht")


def _git(repo, *args, text: bool = True):
    return subprocess.run(["git", "-C", str(repo), *args],
                          capture_output=True, text=text, timeout=60)


def historie_abgeschnitten(repo) -> str | None:
    """Grund, warum die Historie hier UNVOLLSTAENDIG ist — oder None, wenn sie vollstaendig ist.

    None heisst: von hier aus ist die ganze Geschichte lesbar. Ein Grund heisst: sie ist es nicht,
    und der Grund sagt warum. Der Aufrufer entscheidet, ob er dann ueberspringt oder urteilt.
    """
    if not (repo / ".git").exists():
        return "kein git-Baum (sdist, entpacktes Paket)"

    # ZWEITE RUNDE AN DIESER FUNKTION, und sie fiel in ihre EIGENE Klasse. Die erste Fassung
    # fragte `git rev-parse --is-shallow-repository`. Das prueft nur, ob die Datei
    # `$GIT_DIR/shallow` EXISTIERT — nicht, ob sie die erreichbare Historie tatsaechlich
    # beschneidet. GEMESSEN 13.09.2026 in einem vollen Klon: `: > .git/shallow` (null Bytes)
    # kippt die Antwort auf "true", waehrend `git log -- RESTRISIKO_600.md` unveraendert alle 87
    # Commits liefert. Damit wurde aus einem ECHTEN roten Fund ein Skip — eine Datei, kein Commit,
    # keine Spur in der Historie. Der Stellvertreter war nicht mehr `.git`, sondern
    # `.git/shallow`; die Klasse war dieselbe.
    #
    # GEMESSEN WIRD JETZT DIE EIGENSCHAFT: endet die SICHTBARE Historie an einer Pfropfstelle
    # oder an einer echten Wurzel? Zwei Schritte, beide notwendig:
    #   1. die Grenzen aus `shallow` werden VALIDIERT — nur Eintraege, die git als Commit
    #      aufloest, zaehlen. Muell und Leere sind keine Grenze.
    #   2. eine Grenze wirkt nur, wenn die sichtbare Historie AN IHR endet: die wurzellosen
    #      Commits von HEAD muessen eine der Grenzen treffen.
    # Ein untergeschobener ECHTER Vorfahre faellt damit ebenfalls auf — git behandelt ihn als
    # Wurzel, und genau das misst Schritt 2.
    # `--git-common-dir`, NICHT `--git-dir` (Jury Linse 3). In einem worktree zeigt `--git-dir` auf
    # `.git/worktrees/<name>`, und dort liegt keine `shallow`-Datei — die steht im GEMEINSAMEN
    # Verzeichnis. Wer am falschen Ort nachsieht, findet nichts und nennt einen abgeschnittenen
    # Baum vollstaendig. Derselbe Befehl beantwortet beide Lagen.
    gd = _git(repo, "rev-parse", "--git-common-dir")
    if gd.returncode != 0:
        gd = _git(repo, "rev-parse", "--git-dir")
    if gd.returncode != 0:
        return f"die Vollstaendigkeit der Historie ist NICHT MESSBAR (git: {gd.stderr.strip()[:60]})"
    gdp = pathlib.Path(gd.stdout.strip())
    datei = gdp / "shallow" if gdp.is_absolute() else repo / gdp / "shallow"
    if not datei.exists():
        return None
    grenzen = set()
    for zeile in datei.read_text(encoding="utf-8", errors="replace").split():
        if _git(repo, "cat-file", "-e", f"{zeile}^{{commit}}").returncode == 0:
            grenzen.add(zeile)
    if not grenzen:
        return None          # eine Marke ohne aufloesbare Grenze beschneidet nichts
    wurzeln = _git(repo, "rev-list", "--max-parents=0", "HEAD")
    if wurzeln.returncode != 0:
        return f"die Vollstaendigkeit der Historie ist NICHT MESSBAR ({wurzeln.stderr.strip()[:60]})"
    return ABGESCHNITTEN if (set(wurzeln.stdout.split()) & grenzen) else None


def letzte_abweichende_fassung(repo, datei_rel: str, jetzt_bytes: bytes):
    """Die letzte Fassung der Datei, die sich vom heutigen Inhalt UNTERSCHEIDET.

    Gibt `(zustand, commit, bytes, grund)` zurueck, Zustand aus:

      GEFUNDEN      — commit und bytes tragen die Vorfassung
      ERSTAUFNAHME  — die Historie ist vollstaendig und enthaelt keine abweichende Fassung
      NICHT MESSBAR — hier ist nicht nachsehbar, ob es eine gibt; `grund` sagt warum
    """
    grund = historie_abgeschnitten(repo)
    jetzt = hashlib.sha256(jetzt_bytes).hexdigest()
    log = _git(repo, "log", "--format=%H", "--", datei_rel)
    if log.returncode != 0:
        return "NICHT MESSBAR", None, None, f"git log fehlgeschlagen ({log.stderr.strip()[:80]})"
    unlesbar = 0
    for commit in log.stdout.split():
        b = _git(repo, "show", f"{commit}:{datei_rel}", text=False)
        if b.returncode != 0:
            unlesbar += 1
            continue
        if hashlib.sha256(b.stdout).hexdigest() != jetzt:
            return "GEFUNDEN", commit, b.stdout, ""
    # NICHTS GEFUNDEN — und erst JETZT entscheidet die Vollstaendigkeit, was das heisst.
    if grund:
        return "NICHT MESSBAR", None, None, grund
    if unlesbar:
        return "NICHT MESSBAR", None, None, _UNLESBAR.format(n=unlesbar)
    return "ERSTAUFNAHME", None, None, "keine abweichende Fassung in der vollstaendigen Historie"


def digest_in_historie(repo, datei_rel: str, digest: str):
    """Trug die Datei diesen Digest jemals? `(zustand, grund)`.

      GEFUNDEN      — ja, in mindestens einer Fassung
      NICHT GEFUNDEN — nein, und die Historie ist vollstaendig; das ist ein FUND
      NICHT MESSBAR — hier nicht entscheidbar; `grund` sagt warum
    """
    grund = historie_abgeschnitten(repo)
    log = _git(repo, "log", "--format=%H", "--", datei_rel)
    if log.returncode != 0:
        return "NICHT MESSBAR", f"git log fehlgeschlagen ({log.stderr.strip()[:80]})"
    unlesbar = 0
    for commit in log.stdout.split():
        b = _git(repo, "show", f"{commit}:{datei_rel}", text=False)
        if b.returncode != 0:
            unlesbar += 1
            continue
        if hashlib.sha256(b.stdout).hexdigest() == digest:
            return "GEFUNDEN", ""
    if grund:
        return "NICHT MESSBAR", grund
    if unlesbar:
        return "NICHT MESSBAR", _UNLESBAR.format(n=unlesbar)
    return "NICHT GEFUNDEN", "die vollstaendige Historie kennt diesen Digest nicht"
