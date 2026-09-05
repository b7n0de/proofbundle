"""Kein Skript im sdist liest einen privaten Schluessel (Owner-Auflage 2026-09-06, Karte OA-8b1a31cc4f).

DIE ANORDNUNG, woertlich: "MANIFEST.in ersetzt graft scripts durch eine ausdrueckliche Liste, kein
Signierskript und kein Schluessel-lesender Weg im sdist, ein Test misst die sdist-Dateiliste und wird
rot, wenn ein Skript mit Ed25519PrivateKey oder privkey-file hineingeraet."

WARUM DIE DATEILISTE UND NICHT MANIFEST.in. Wer die Regeln nachbaut, prueft seine Nachbildung. Was
ausgeliefert wird, entscheidet setuptools aus MANIFEST.in, den Paketdaten und seinen eigenen
Vorgaben — die einzige ehrliche Frage ist deshalb: was liegt am Ende IM Archiv.

WARUM PER AST UND NICHT PER TEXTSUCHE. ``scripts/sign_readiness_artifact.py`` erklaert in seinem
Docstring ausfuehrlich, dass es ``--privkey-file`` NICHT mehr gibt — eine Textsuche findet dort also
genau das Wort, dessen Abwesenheit der Docstring beschreibt, und wuerde die Datei verbannen, die den
Fix TRAEGT. Dieselbe Lehre wie bei C8 (``or True``): ein Riegel, der Text zaehlt statt Struktur zu
lesen, misst die Erzaehlung statt des Codes.

GEPRUEFT WIRD ein LESENDER Zugriff: ``Ed25519PrivateKey`` als Aufruf oder Attributzugriff
(``from_private_bytes``, ``generate`` zaehlt NICHT — ein ephemerer Testschluessel, der nie die Datei
verlaesst, ist kein Signierweg und wird von der Gate-Mechanik gebraucht), und eine
``--privkey``-Flagge als STRING-LITERAL im Code, nicht im Docstring.
"""
from __future__ import annotations

import ast
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

#: Ein Aufruf, der einen VORHANDENEN privaten Schluessel laedt. ``generate()`` steht bewusst NICHT
#: hier: es erzeugt einen wegwerfbaren Testschluessel, verlaesst den Prozess nie und ist die Form,
#: in der ``type_confusion_gate`` und ``gate_qualification_harness`` ihre Vektoren bauen.
_LADENDE_ATTRIBUTE = {"from_private_bytes"}
_PRIVATKLASSE = "Ed25519PrivateKey"


def schluessel_lesende_stellen(quelltext: str) -> list[str]:
    """Die Codestellen, die einen privaten Schluessel LADEN — per AST, nie aus Prosa."""
    try:
        baum = ast.parse(quelltext)
    except SyntaxError:                                       # pragma: no cover
        return ["<nicht parsebar>"]
    fund: list[str] = []
    for k in ast.walk(baum):
        if isinstance(k, ast.Attribute) and k.attr in _LADENDE_ATTRIBUTE:
            fund.append(f"{k.attr} (Zeile {k.lineno})")
        # eine --privkey-Flagge als echtes String-Literal im Code (argparse), nicht im Docstring
        if isinstance(k, ast.Constant) and isinstance(k.value, str) and k.value.startswith("--privkey"):
            fund.append(f"{k.value!r} (Zeile {k.lineno})")
        # Direktkonstruktion mit Schluesselmaterial: Ed25519PrivateKey(<argument>)
        if (isinstance(k, ast.Call) and isinstance(k.func, ast.Name)
                and k.func.id == _PRIVATKLASSE and k.args):
            fund.append(f"{_PRIVATKLASSE}(...) (Zeile {k.lineno})")
    return sorted(set(fund))


@pytest.fixture(scope="module")
def sdist_dateien():
    """Die ECHTE Dateiliste eines frisch gebauten sdist, plus der Inhalt seiner Skripte.

    ZWEI FALLEN, beide gemessen am 2026-09-06, beide hier vermieden.

    ERSTENS DER CACHE. setuptools schreibt beim Bauen ein ``*.egg-info/SOURCES.txt`` und LIEST es
    beim naechsten Bau wieder — eine Datei, die MANIFEST.in inzwischen ausschliesst, kommt dadurch
    trotzdem mit. Genau so gemessen: im Lane-Baum enthielt der sdist 30 Skripte einschliesslich der
    beiden ausgeschlossenen, im frischen Baum 28 ohne sie. Wer im Arbeitsbaum baut, misst also den
    Cache und nicht die Regel. Deshalb wird hier in eine KOPIE des getrackten Standes gebaut, in der
    kein ``egg-info`` liegt — dieselbe Isolation, die ``mutation_check.py`` fuer seine Mutanten
    schon zieht. Fuer den Release ist das kein Testdetail: ein Release-Bau in einem Baum mit altem
    ``egg-info`` liefert ausgeschlossene Dateien aus, ohne dass jemand etwas falsch gemacht haette.

    ZWEITENS DAS FRONTEND. ``python -m build`` ist hier nicht ueberall vorhanden, und mit
    ``--no-isolation`` scheitert es an Bauabhaengigkeiten, die in einem Pruef-venv fehlen duerfen.
    Der Bau laeuft deshalb ueber die PEP-517-Schnittstelle des Backends selbst
    (``setuptools.build_meta.build_sdist``) — dieselbe Funktion, die jedes Frontend ruft, nur ohne
    das Frontend.
    """
    if not (REPO / ".git").exists():
        pytest.skip("kein git-Checkout — der sdist-Bau braucht die getrackte Dateimenge")
    arbeit = Path(tempfile.mkdtemp(prefix="sdist_riegel_"))
    try:
        baum = arbeit / "baum"
        r = subprocess.run(["git", "-C", str(REPO), "ls-files", "-z"],
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            pytest.skip(f"git ls-files scheitert hier: {r.stderr.strip()}")
        for rel in [x for x in r.stdout.split("\0") if x]:
            quelle = REPO / rel
            if not quelle.is_file():
                continue
            ziel = baum / rel
            ziel.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(quelle, ziel)
        assert not list(baum.rglob("*.egg-info")), (
            "der Probebaum traegt ein egg-info — dann misst dieser Test den setuptools-Cache "
            "statt MANIFEST.in")
        raus = arbeit / "dist"
        raus.mkdir()
        code = ("import sys, setuptools.build_meta as bm; "
                "sys.stdout.write(bm.build_sdist(sys.argv[1]))")
        b = subprocess.run([sys.executable, "-c", code, str(raus)], cwd=str(baum),
                           capture_output=True, text=True, timeout=900)
        archive = sorted(raus.glob("*.tar.gz"))
        if b.returncode != 0 or not archive:
            pytest.skip(f"sdist-Bau hier nicht moeglich (exit {b.returncode}): "
                        f"{(b.stderr or b.stdout)[-300:]}")
        with tarfile.open(archive[-1]) as tf:
            namen = tf.getnames()
            skripte = {}
            for n in namen:
                teile = n.split("/", 1)
                if len(teile) == 2 and teile[1].startswith("scripts/") and n.endswith(".py"):
                    f = tf.extractfile(n)
                    if f is not None:
                        skripte[teile[1]] = f.read().decode("utf-8", errors="replace")
        yield {"namen": namen, "skripte": skripte}
    finally:
        shutil.rmtree(arbeit, ignore_errors=True)


class TestKeinSignierwerkzeugImSdist:
    def test_der_sdist_enthaelt_ueberhaupt_skripte(self, sdist_dateien):
        """Anti-Tautologie: waeren gar keine Skripte drin, bestuende der Riegel unten leer — und der
        sdist waere zugleich kaputt, weil die ausgelieferten Tests ihre Werkzeuge brauchen."""
        assert sdist_dateien["skripte"], "der sdist enthaelt kein einziges Skript — dann pruefen die " \
                                         "ausgelieferten Tests ihre Werkzeuge gegen nichts"

    def test_kein_ausgeliefertes_skript_liest_einen_privaten_schluessel(self, sdist_dateien):
        """DER RIEGEL. Jede Fundstelle ist eine Datei, die im Archiv liegt — nicht eine, die
        MANIFEST.in zu listen scheint."""
        treffer = {name: st for name, quelle in sdist_dateien["skripte"].items()
                   if (st := schluessel_lesende_stellen(quelle))}
        assert not treffer, (
            "im sdist liegen Skripte mit einem schluessel-lesenden Codepfad: "
            + "; ".join(f"{n} -> {', '.join(s)}" for n, s in sorted(treffer.items()))
            + ". Entweder die Datei aus der Liste in MANIFEST.in nehmen, oder den Codepfad "
              "entfernen — ein ausgeliefertes Werkzeug, das einen privaten Schluessel laden kann, "
              "liefert die Faehigkeit zur Selbstbeglaubigung mit aus, ob sie jemand ruft oder nicht")

    def test_die_beiden_benannten_skripte_sind_nicht_im_archiv(self, sdist_dateien):
        """Namentlich, damit ein kuenftiges `graft scripts` nicht unbemerkt zurueckkommt."""
        for n in ("scripts/pre_tag_receipt.py", "scripts/gen_findings_register.py"):
            assert n not in sdist_dateien["skripte"], (
                f"{n} liegt wieder im sdist — es traegt den Inline-Signierweg (Owner-Entscheid "
                "2026-09-06: der Modus bleibt im Repo als Owner-Signierweg am Mac, aber er wird "
                "nicht ausgeliefert)")


class TestDerRiegelMisstWirklich:
    """Zweiseitig: faengt der Prueferkern den Defekt, und laesst er die Prosa in Ruhe?"""

    def test_ein_gepflanzter_ladender_zugriff_wird_gefunden(self):
        gepflanzt = ("from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey\n"
                     "def sign(p):\n"
                     "    k = Ed25519PrivateKey.from_private_bytes(open(p, 'rb').read())\n"
                     "    return k.sign(b'x')\n")
        assert schluessel_lesende_stellen(gepflanzt), "ein ladender Zugriff blieb unentdeckt"

    def test_eine_gepflanzte_privkey_flagge_wird_gefunden(self):
        gepflanzt = "import argparse\np = argparse.ArgumentParser()\np.add_argument('--privkey-file')\n"
        assert schluessel_lesende_stellen(gepflanzt), "eine --privkey-Flagge blieb unentdeckt"

    def test_ein_ephemerer_testschluessel_ist_kein_fund(self):
        """``generate()`` erzeugt einen wegwerfbaren Schluessel; genau so bauen
        ``type_confusion_gate`` und ``gate_qualification_harness`` ihre Vektoren. Waere das ein Fund,
        muesste die Gate-Mechanik aus dem sdist — und mit ihr die Tests, die sie pruefen."""
        harmlos = ("from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey\n"
                   "def vektor():\n"
                   "    return Ed25519PrivateKey.generate().public_key().public_bytes_raw()\n")
        assert schluessel_lesende_stellen(harmlos) == [], "ein ephemerer Testschluessel zaehlte als Fund"

    def test_prosa_ueber_einen_entfernten_weg_ist_kein_fund(self):
        """Der Grund fuer den AST. ``sign_readiness_artifact.py`` beschreibt in seinem Docstring,
        dass es ``--privkey-file`` nicht mehr gibt. Eine Textsuche verbannte ausgerechnet die Datei,
        die den Fix traegt."""
        prosa = ('"""Ein frueherer Stand akzeptierte --privkey-file und signierte selbst. Es gibt\n'
                 'keinen Codepfad mehr, der einen privaten Schluessel liest."""\n'
                 "def emit():\n    return b''\n")
        assert schluessel_lesende_stellen(prosa) == [], "eine Docstring-Erwaehnung zaehlte als Fund"

    def test_das_echte_signierwerkzeug_ist_sauber(self):
        """Der Beleg fuer die Entscheidung, ``sign_readiness_artifact.py`` im sdist zu LASSEN: es
        traegt gemessen keinen ladenden Zugriff. Kommt je einer dazu, faellt dieser Test zuerst."""
        q = (REPO / "scripts" / "sign_readiness_artifact.py")
        if not q.is_file():
            pytest.skip("das Skript liegt hier nicht (sdist ohne Repo-Kontext)")
        assert schluessel_lesende_stellen(q.read_text(encoding="utf-8")) == []


#: Was ABSICHTLICH nicht ausgeliefert wird, je mit dem Grund. Eine Ausschlussmenge ohne Grund ist
#: eine Liste, auf die man alles schiebt, was gerade rot ist.
AUSGESCHLOSSEN = {
    # Auflage C9 / Owner-Entscheid 2026-09-06: beide tragen einen schluessel-LESENDEN Codepfad.
    "pre_tag_receipt.py": "liest Ed25519PrivateKey ueber --privkey-file (Owner-Signierweg am Mac)",
    "gen_findings_register.py": "liest denselben Weg aus Umgebung oder Datei",
    # Kein sdist-Verbraucher: der git-Hook des Checkouts und der CI-Kanal, beides gibt es dort nicht.
    "install_git_hooks.sh": "Verbraucher sind der Checkout-Hook und CI, nicht das Paket",
}


def test_jede_datei_unter_scripts_ist_in_manifest_entschieden():
    """Die Liste darf nicht altern. Jede Datei unter ``scripts/`` steht entweder in MANIFEST.in oder
    in der begruendeten Ausschlussmenge — eine neue Datei muss ENTSCHIEDEN werden, statt durch ein
    ``graft`` mitzurutschen. Genau das war der Grund, das ``graft`` zu ersetzen.

    NICHT NUR ``*.py``, und das ist die Nachbesserung vom 06.09.2026. Die erste Fassung dieses
    Riegels globte ``*.py`` — und maass damit genau die Haelfte, die ohnehin niemand vergisst. Der
    Probe-Merge der vier Lanes fuhr die Vollsuite und wurde rot; beim Nachmessen fielen FUENF
    Nicht-Python-Dateien auf, die das ersetzte ``graft scripts`` ausgeliefert hatte und die neue
    Liste nicht: ``rust_parity_registry.json`` (gelesen von ``scripts/rust_parity_gate.py:58``),
    ``mutation_shard_weights.json`` (``scripts/mutation_check.py:626``), ``demo.sh`` und
    ``demo_tamper.sh`` (gerufen vom AUSGELIEFERTEN Makefile, Ziele ``demo`` und ``demo-tamper``)
    und ``install_git_hooks.sh``. Vier davon sind jetzt drin, die fuenfte steht mit Grund draussen.

    DIE KLASSE, damit sie nicht nur hier geschlossen ist: wer ein Verzeichnis-``graft`` durch eine
    Liste ersetzt, uebernimmt die Entscheidung fuer JEDE Datei darin — nicht fuer jede Datei der
    Sprache, an die er gerade denkt. Ein Skript ohne seine Datendatei ist kein Skript, und die
    Abwesenheit faellt nicht auf, weil nichts sie meldet: der Ordner ist ja da.
    """
    manifest = REPO / "MANIFEST.in"
    if not manifest.is_file() or not (REPO / "scripts").is_dir():
        pytest.skip("kein Repo-Kontext")
    gelistet = {z.split("include scripts/", 1)[1].strip()
                for z in manifest.read_text(encoding="utf-8").splitlines()
                if z.startswith("include scripts/")}
    ausgeschlossen = set(AUSGESCHLOSSEN)
    vorhanden = {p.name for p in (REPO / "scripts").iterdir() if p.is_file()}
    unentschieden = sorted(vorhanden - gelistet - ausgeschlossen)
    assert not unentschieden, (
        f"neue Datei(en) unter scripts/, die MANIFEST.in nicht entscheidet: {unentschieden} — "
        "aufnehmen (include scripts/<datei>) oder mit Begruendung ausschliessen")
    verschwunden = sorted(gelistet - vorhanden)
    assert not verschwunden, (
        f"MANIFEST.in listet Skripte, die es nicht mehr gibt: {verschwunden} — eine Liste, die auf "
        "Verschwundenes zeigt, deckt nichts mehr")


class TestInlineSperre:
    """Die zweite Auflage: der Inline-Signierweg bleibt, aber nicht auf dem Bau- und Pruefhost.

    Er BLEIBT, weil er der Weg ist, auf dem der Owner an seiner eigenen Maschine unterschreibt; ihn
    zu entfernen hiesse, den Signierweg abzuschaffen statt ihn einzugrenzen. Er ist GESPERRT, wo der
    messende Agent laeuft — ein Werkzeug, das dort einen privaten Schluessel laden KANN, liefert die
    Faehigkeit zur Selbstbeglaubigung mit, unabhaengig davon, ob sie je gerufen wird.
    """

    @staticmethod
    def _modul():
        import importlib.util
        q = REPO / "scripts" / "pre_tag_receipt.py"
        if not q.is_file():
            pytest.skip("scripts/pre_tag_receipt.py liegt hier nicht (sdist ohne Repo-Kontext) — "
                        "genau das ist der Sinn des Packaging-Ausschlusses")
        spec = importlib.util.spec_from_file_location("_ptr_sperre", str(q))
        m = importlib.util.module_from_spec(spec)
        sys.modules["_ptr_sperre"] = m
        spec.loader.exec_module(m)
        return m

    def test_ohne_freigabe_verweigert_der_inline_weg(self, monkeypatch):
        m = self._modul()
        for n in m._BAUHOST_MERKMALE:
            monkeypatch.delenv(n, raising=False)
        monkeypatch.delenv(m.INLINE_FREIGABE_ENV, raising=False)
        with pytest.raises(SystemExit) as exc:
            m._inline_erlaubt_oder_stop()
        assert m.INLINE_FREIGABE_ENV in str(exc.value)
        assert "--emit-payload" in str(exc.value), "die Absage muss den Weg nennen, der funktioniert"

    def test_mit_freigabe_laeuft_er(self, monkeypatch):
        """Gegenrichtung: eine Sperre, die immer sperrt, hat den Weg abgeschafft statt eingegrenzt."""
        m = self._modul()
        for n in m._BAUHOST_MERKMALE:
            monkeypatch.delenv(n, raising=False)
        monkeypatch.setenv(m.INLINE_FREIGABE_ENV, "1")
        m._inline_erlaubt_oder_stop()          # darf NICHT werfen

    @pytest.mark.parametrize("marke", ["CI", "GITHUB_ACTIONS"])
    def test_auf_einem_bauhost_verweigert_er_auch_mit_freigabe(self, monkeypatch, marke):
        """Die Freigabe ist die Erlaubnis eines Menschen an seiner eigenen Maschine, kein Schalter
        fuer eine Pipeline — deshalb schlaegt das Bauhost-Merkmal sie."""
        m = self._modul()
        for n in m._BAUHOST_MERKMALE:
            monkeypatch.delenv(n, raising=False)
        monkeypatch.setenv(m.INLINE_FREIGABE_ENV, "1")
        monkeypatch.setenv(marke, "true")
        with pytest.raises(SystemExit) as exc:
            m._inline_erlaubt_oder_stop()
        assert "build host" in str(exc.value)

    def test_die_sperre_steht_vor_dem_schluessel_nicht_dahinter(self):
        """Eine Sperre hinter dem Lesen des Schluessels waere Zierde: der Schluessel waere dann
        schon im Speicher. Gemessen am Quelltext: der Aufruf steht VOR ``_need(... privkey-file)``
        und damit vor jedem Lesen."""
        q = (REPO / "scripts" / "pre_tag_receipt.py")
        if not q.is_file():
            pytest.skip("kein Repo-Kontext")
        quelle = q.read_text(encoding="utf-8")
        i_sperre = quelle.index("_inline_erlaubt_oder_stop()\n    _need")
        i_lesen = quelle.index("args.privkey_file.read_text")
        assert i_sperre < i_lesen, "die Sperre steht hinter dem Lesen des Schluessels"


# ---------------------------------------------------------------------------------------------
# DIE KLASSE HINTER DEM FUND VOM 06.09.2026, als Riegel statt als vier Einzelzeilen im MANIFEST.


def _geschwisterdateien_die_ein_skript_zusammensetzt(quelle: str, namen: set[str]) -> set[str]:
    """Welche Dateien unter ``scripts/`` setzt dieses Modul als PFAD zusammen?

    GEMESSEN WIRD DIE KOMPOSITION, NICHT DIE ERWAEHNUNG, und der Unterschied ist hier belegbar:
    ``scripts/audit_candidate_matrix.py:1570`` nennt ``scripts/rust_parity_registry.json`` in einem
    Meldungstext — das ist Prosa ueber eine Datei, kein Zugriff auf sie. ``rust_parity_gate.py:58``
    schreibt dagegen ``REPO / "scripts" / "rust_parity_registry.json"``, und das IST einer. Ein
    Detektor, der beides gleich behandelt, meldet Bedarf, wo keiner ist — und wer ihm zweimal
    umsonst geglaubt hat, glaubt ihm beim dritten Mal nicht mehr.

    Erkannt wird deshalb nur ein ``/``-Ausdruck (``ast.BinOp`` mit ``ast.Div``), in dessen Aesten
    eine Zeichenkette steht, die eine wirklich existierende Datei unter ``scripts/`` benennt.
    """
    treffer: set[str] = set()
    try:
        baum = ast.parse(quelle)
    except SyntaxError:
        return treffer
    for k in ast.walk(baum):
        if not isinstance(k, ast.BinOp) or not isinstance(k.op, ast.Div):
            continue
        for teil in ast.walk(k):
            if isinstance(teil, ast.Constant) and isinstance(teil.value, str):
                name = teil.value.rsplit("/", 1)[-1]
                if name in namen:
                    treffer.add(name)
    return treffer


def test_ein_ausgeliefertes_skript_bekommt_seine_datendateien_mit():
    """Ein Skript ohne seine Datendatei ist kein Skript.

    DER GEMESSENE FALL: ``graft scripts`` lieferte den ganzen Ordner aus. Als die Owner-Auflage ihn
    durch eine Liste ersetzte, blieben ``rust_parity_gate.py`` und ``mutation_check.py`` drin,
    ihre Registry und ihre Gewichtsdatei aber draussen. Nichts wurde rot: der Ordner war ja da, die
    Skripte waren da, und ihre Dateien fehlen erst zur Laufzeit beim Anwender.
    """
    manifest = REPO / "MANIFEST.in"
    if not manifest.is_file() or not (REPO / "scripts").is_dir():
        pytest.skip("kein Repo-Kontext")
    gelistet = {z.split("include scripts/", 1)[1].strip()
                for z in manifest.read_text(encoding="utf-8").splitlines()
                if z.startswith("include scripts/")}
    namen = {p.name for p in (REPO / "scripts").iterdir() if p.is_file()}
    fehlend: dict[str, set[str]] = {}
    for skript in sorted(gelistet):
        p = REPO / "scripts" / skript
        if p.suffix != ".py" or not p.is_file():
            continue
        gebraucht = _geschwisterdateien_die_ein_skript_zusammensetzt(
            p.read_text(encoding="utf-8", errors="replace"), namen)
        fehlt = {g for g in gebraucht if g not in gelistet and g != skript}
        if fehlt:
            fehlend[skript] = fehlt
    assert not fehlend, (
        f"ausgelieferte Skripte setzen Pfade auf Dateien zusammen, die das sdist nicht traegt: "
        f"{ {k: sorted(v) for k, v in fehlend.items()} } — aufnehmen oder den Zugriff entfernen")


def test_meta_der_detektor_unterscheidet_zusammensetzung_von_erwaehnung():
    """Beide Richtungen. Ohne die zweite Haelfte waere ein Detektor, der ALLES meldet, ebenso
    gruen — und die Aussage oben waere wertlos, weil sie dann immer Bedarf faende."""
    namen = {"registry.json"}
    zusammengesetzt = 'from pathlib import Path\nP = Path(__file__).parent / "registry.json"\n'
    erwaehnt = 'MSG = "siehe scripts/registry.json fuer den Grund"\n'
    assert _geschwisterdateien_die_ein_skript_zusammensetzt(zusammengesetzt, namen) == {"registry.json"}, \
        "eine echte Pfad-Zusammensetzung wird nicht gesehen — der Riegel ist blind"
    assert _geschwisterdateien_die_ein_skript_zusammensetzt(erwaehnt, namen) == set(), \
        "eine blosse Erwaehnung gilt als Zugriff — der Riegel meldet Bedarf, wo keiner ist"


def test_meta_eine_entfernte_datendatei_wird_wirklich_gefunden():
    """Pflanzen und fangen am ECHTEN Zustand: nimmt man die Registry aus der Liste, muss der
    Riegel oben ihren Leser melden. Faellt er dann nicht, misst er nichts."""
    manifest = REPO / "MANIFEST.in"
    if not manifest.is_file() or not (REPO / "scripts").is_dir():
        pytest.skip("kein Repo-Kontext")
    gelistet = {z.split("include scripts/", 1)[1].strip()
                for z in manifest.read_text(encoding="utf-8").splitlines()
                if z.startswith("include scripts/")}
    assert "rust_parity_registry.json" in gelistet, (
        "die Vorbedingung dieses Meta-Tests ist weg: die Registry steht nicht mehr in der Liste")
    ohne = gelistet - {"rust_parity_registry.json"}
    namen = {p.name for p in (REPO / "scripts").iterdir() if p.is_file()}
    leser = REPO / "scripts" / "rust_parity_gate.py"
    gebraucht = _geschwisterdateien_die_ein_skript_zusammensetzt(
        leser.read_text(encoding="utf-8", errors="replace"), namen)
    assert "rust_parity_registry.json" in gebraucht - ohne, (
        "der gepflanzte Verlust wird nicht gefunden — der Riegel oben ist eine Zusicherung ohne Wirkung")
