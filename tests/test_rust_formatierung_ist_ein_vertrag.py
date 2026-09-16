"""Die gepinnte Rust-Toolchain als VERTRAG: beide Waechter, ihre Form und ihr Lauf.

WARUM ES DIESE DATEI GIBT. Am 2026-09-15 war `cargo fmt --check` im Rust-Baum rot: 36 Treffer
unter der gepinnten Toolchain. Der Fix lief ueber PR 211 und landete als `8d20eec`, und die
Messung dazu war ehrlich — nur eben NICHT belegbar. Der Abschluss-Beleg dieses Hauses verlangt
einen Fangnachweis in Form eines pytest-Knotens, und fuer eine cargo-Messung gab es keinen. Der
Antrag wurde mit `abgewiesen` zurueckgewiesen, und die Lehre stand danach im Fehlerbuch statt im
Baum: eine Messung, fuer die es keinen Knoten gibt, kann man nicht zusagen.

DIE FORM WIRD AUS DEM GEPARSTEN YAML GELESEN, NICHT AUS DEM TEXT, und das ist der Kern der
zweiten Fassung. Die erste suchte Teilzeichenketten im Rohtext von `ci.yml`. Eine ausfuehrende
Gegenlesung am 2026-09-16 fand daran vier Wege, die Zusage zu erfuellen, ohne sie zu halten:
ein blosser KOMMENTAR `# working-directory: tools/pb_verify_rs` genuegte dem Verzeichnis-Check;
ein angehaengtes `|| true` neutralisierte den Ausgangswert, waehrend `-D warnings` noch dastand;
und `text.index(zeile)` fand immer das ERSTE Vorkommen einer Zeile, sodass ein harmloser
Koeder-Job weiter oben seine Konformitaet an den echten, kaputten Schritt weiter unten vererbte.
Alle vier verschwinden, wenn man Schritte als OBJEKTE liest statt als Zeilen.

DIE VERSION WIRD AUF GLEICHHEIT GEPRUEFT, nicht auf Teilzeichenkette. `"1.95.0" in
"rustc 1.95.0-ROGUE-FORK …"` ist wahr, und dieselbe Gegenlesung hat genau das vorgefuehrt.

DER LAUF MUSS IM CI AUCH WIRKLICH STATTFINDEN. Die erste Fassung lief nur, wenn
`tools/pb_verify_rs/target` existierte — und gemessen baut KEIN Job, der diese Datei mit pytest
faehrt, den Rust-Baum. Die Trefferquote in der echten Pipeline war null, und ein Fall, der nie
misst, sieht aus wie Sorgfalt. Der Job `rust-parity` baut den Baum und faehrt diese Datei
seitdem ausdruecklich mit; der Fall darunter pinnt genau das.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
RUST = REPO / "tools" / "pb_verify_rs"
PIN = RUST / "rust-toolchain.toml"
CI = REPO / ".github" / "workflows" / "ci.yml"

#: `channel = "1.95.0"` — bewusst eine Regex und kein tomllib: das Paket wird auch auf 3.10
#: getestet, und dort gibt es tomllib nicht.
_KANAL = re.compile(r'^\s*channel\s*=\s*"([^"]+)"\s*$', re.M)
#: `rustc 1.95.0 (59807616e 2026-04-14)` — die Version als EIGENES Feld, nicht als Teilstring.
_RUSTC = re.compile(r"^rustc\s+(\S+)")
#: `components = ["rustfmt", "clippy"]` — das FELD, nicht der Dateitext. Der Kopf der Pinnung
#: nennt beide Werkzeuge in einem Kommentar; ein `"clippy" in text` ist deshalb auch dann wahr,
#: wenn die Liste es nicht mehr enthaelt. Genau so ueberlebte der erste Anlauf dieses Falls den
#: gepflanzten Defekt — dieselbe Klasse, gegen die diese ganze zweite Fassung antritt, im Fix
#: gegen sie selbst.
_COMPONENTS = re.compile(r"^\s*components\s*=\s*\[([^\]]*)\]", re.M)
#: Was einen Ausgangswert verschluckt. `cmd || true`, `cmd || :`, `cmd ; true`, `set +e`.
_VERSCHLUCKT = re.compile(r"\|\|\s*(true|:)\s*$|;\s*true\s*$|\bset\s+\+e\b", re.M)


def _gepinnter_kanal() -> str:
    if not PIN.is_file():
        pytest.skip(f"{PIN} liegt hier nicht")
    m = _KANAL.search(PIN.read_text(encoding="utf-8"))
    if not m:
        pytest.fail(f"{PIN} nennt keinen `channel` — ohne ihn ist die Messung nicht gepinnt")
    return m.group(1)


def _lauf(*befehl: str, cwd: Path = RUST) -> subprocess.CompletedProcess:
    return subprocess.run(befehl, cwd=str(cwd), capture_output=True, text=True)


def _schritte_mit(befehlsteil: str) -> list[tuple[str, dict, dict, dict]]:
    """Alle Schritte, deren `run` den Befehlsteil enthaelt, als (job_id, job, step, workflow).

    ALS OBJEKTE, NICHT ALS ZEILEN. Ein Schritt ist ein Woerterbuch mit `run`, `working-directory`
    und seinem Job; ein Kommentar ist im geparsten Baum gar nicht mehr da, und zwei textgleiche
    Zeilen in zwei Jobs sind zwei verschiedene Objekte. Genau daran scheiterte die erste Fassung.
    """
    yaml = pytest.importorskip("yaml", reason="PyYAML fehlt — die Form von ci.yml ist NICHT MESSBAR")
    if not CI.is_file():
        pytest.skip(".github/workflows/ci.yml liegt hier nicht")
    wf = yaml.safe_load(CI.read_text(encoding="utf-8")) or {}
    aus = []
    for job_id, job in (wf.get("jobs") or {}).items():
        for step in (job or {}).get("steps") or []:
            if isinstance(step, dict) and befehlsteil in str(step.get("run") or ""):
                aus.append((job_id, job or {}, step, wf))
    return aus


def _arbeitsverzeichnis(step: dict, job: dict, wf: dict) -> str | None:
    """Das WIRKSAME Arbeitsverzeichnis eines Schritts, in der Rangfolge von GitHub Actions."""
    for ebene in (step, job, wf):
        wd = ebene.get("working-directory")
        if wd:
            return str(wd)
        vor = ((ebene.get("defaults") or {}).get("run") or {}).get("working-directory")
        if vor:
            return str(vor)
    return None


def _laeuft_im_verzeichnis_der_pinnung(step: dict, job: dict, wf: dict) -> bool:
    """Landet dieser Schritt in `tools/pb_verify_rs`? rustup waehlt danach die Toolchain."""
    wd = _arbeitsverzeichnis(step, job, wf)
    if wd and wd.strip().strip("./") == "tools/pb_verify_rs":
        return True
    return bool(re.search(r"cd\s+tools/pb_verify_rs\s*&&", str(step.get("run") or "")))


def test_die_toolchain_ist_auf_eine_exakte_version_gepinnt_und_nennt_beide_werkzeuge():
    """Ein Kanal wie `stable` ist keine Pinnung, sondern eine bewegliche Flaeche.

    UND DIE KOMPONENTEN GEHOEREN DAZU: nennt die Datei `clippy` nicht, installiert ein frischer
    Runner es gar nicht erst, und der clippy-Schritt braeche — waehrend lokal alles gruen bliebe,
    weil die Komponente dort laengst liegt. Ein Mutant, der `clippy` aus der Liste nahm, ueberlebte
    die erste Fassung."""
    kanal = _gepinnter_kanal()
    assert re.fullmatch(r"\d+\.\d+\.\d+", kanal), (
        f"channel = {kanal!r} ist kein exakter Stand. rustfmt und clippy urteilen "
        "versionsabhaengig; ein beweglicher Kanal laesst denselben Quelltext morgen anders "
        "aussehen, und genau dieser Drift hat den Gate schon einmal rot gefaerbt.")
    m = _COMPONENTS.search(PIN.read_text(encoding="utf-8"))
    assert m, f"{PIN} nennt kein `components`-Feld"
    genannt = {w.strip().strip('\'"') for w in m.group(1).split(",") if w.strip()}
    for werkzeug in ("rustfmt", "clippy"):
        assert werkzeug in genannt, (
            f"die Pinnung fuehrt {werkzeug!r} nicht in `components` (gelesen: {sorted(genannt)}) — "
            "ein frischer Runner installiert es dann nicht, und sein Schritt bricht aus einem "
            "Grund, den diese Datei zu verhindern behauptet")


@pytest.mark.parametrize("befehl,flagge", [("cargo fmt", "--check"), ("cargo clippy", "-D warnings")])
def test_jeder_waechter_laeuft_im_verzeichnis_der_pinnung_und_haelt_seinen_ausgang(befehl, flagge):
    """Die Form, aus dem GEPARSTEN Workflow. Drei Zusagen je Schritt.

    (1) Er landet in `tools/pb_verify_rs`, denn rustup waehlt die Toolchain nach dem
    Arbeitsverzeichnis — ueber `working-directory` auf Schritt-, Job- oder Workflow-Ebene oder
    ueber ein `cd … &&`. (2) Er traegt seine Flagge: `--check` prueft statt zu formatieren,
    `-D warnings` macht aus einer Warnung einen Fehler. (3) Sein Ausgangswert wird nicht
    verschluckt — ein angehaengtes `|| true` macht beide anderen Zusagen zur Deko."""
    schritte = _schritte_mit(befehl)
    assert schritte, f"kein Schritt im CI fuehrt `{befehl}` aus"
    for job_id, job, step, wf in schritte:
        wo = f"job {job_id!r}, Schritt {step.get('name') or step.get('run')!r}"
        assert _laeuft_im_verzeichnis_der_pinnung(step, job, wf), (
            f"{wo} landet nicht in tools/pb_verify_rs. rustup waehlt die Toolchain nach dem "
            "Arbeitsverzeichnis; ohne das misst der Schritt unter einer beliebigen Version, und "
            "gruen oder rot waere Zufall.")
        run = str(step.get("run") or "")
        assert flagge in run, f"{wo} traegt {flagge!r} nicht: {run!r}"
        assert not _VERSCHLUCKT.search(run), (
            f"{wo} verschluckt seinen Ausgangswert ({run!r}). Mit `|| true` am Ende ist "
            f"{flagge!r} eine Meinung, keine Zusage.")


def test_der_rust_job_faehrt_diese_datei_mit():
    """DER FALL, DER DIESE DATEI UEBERHAUPT WIRKSAM MACHT.

    Der Lauf-Fall unten braucht einen gebauten Rust-Baum. Gemessen 2026-09-16: KEIN Job, der
    pytest auf diese Datei faehrt, baut ihn — `test` und `coverage` bauen kein Rust, `rust-parity`
    und `audit-candidate-matrix` fahren kein pytest. Die Trefferquote in der echten Pipeline war
    damit NULL, und ein Fall, der nie misst, sieht aus wie Sorgfalt. Gefunden von einer
    ausfuehrenden Gegenlesung, nicht beim Lesen.

    Der Job `rust-parity` baut den Baum ohnehin; seitdem faehrt er diese Datei ausdruecklich mit,
    und dieser Fall haelt das fest."""
    yaml = pytest.importorskip("yaml", reason="PyYAML fehlt — die Form von ci.yml ist NICHT MESSBAR")
    if not CI.is_file():
        pytest.skip(".github/workflows/ci.yml liegt hier nicht")
    wf = yaml.safe_load(CI.read_text(encoding="utf-8")) or {}
    meine_datei = Path(__file__).name
    baut, faehrt = set(), set()
    for job_id, job in (wf.get("jobs") or {}).items():
        for step in (job or {}).get("steps") or []:
            run = str((step or {}).get("run") or "")
            if "cargo build" in run:
                baut.add(job_id)
            if meine_datei in run:
                faehrt.add(job_id)
    gemeinsam = baut & faehrt
    assert gemeinsam, (
        f"kein Job baut den Rust-Baum UND faehrt {meine_datei}: baut {sorted(baut)}, "
        f"faehrt {sorted(faehrt)}. Ohne Schnittmenge ueberspringt sich der Lauf-Fall in der "
        "ganzen Pipeline und misst nie etwas.")


def _gepinnte_flaeche_oder_skip(kanal: str) -> str:
    """Laeuft hier die gepinnte Toolchain? Sonst ein SKIP, das sagt WARUM nicht gemessen wurde."""
    if not RUST.is_dir():
        pytest.skip("tools/pb_verify_rs liegt hier nicht (Paketlauf statt Checkout)")
    if shutil.which("cargo") is None:
        pytest.skip("NICHT GEMESSEN: kein `cargo` im PATH — das ist kein bestandener Lauf")
    # EINE UMLENKUNG DES WERKZEUGS IST KEINE GEPINNTE FLAECHE. `RUSTFMT` bindet ein fremdes
    # Programm ein, waehrend `rustc --version` weiter die Pinnung meldet; eine Gegenlesung hat
    # damit einen ECHTEN Formatfehler an diesem Fall vorbeigebracht.
    for var in ("RUSTFMT", "RUSTC", "CARGO"):
        if os.environ.get(var):
            pytest.skip(f"NICHT GEMESSEN: ${var} lenkt das Werkzeug um ({os.environ[var]!r}) — "
                        "was dann laeuft, ist nicht die gepinnte Toolchain")
    rustc = _lauf("rustc", "--version")
    if rustc.returncode != 0:
        pytest.skip(f"NICHT GEMESSEN: `rustc --version` endete mit {rustc.returncode} — "
                    f"{(rustc.stderr or rustc.stdout).strip()[:160]}")
    m = _RUSTC.match(rustc.stdout.strip())
    gemessen = m.group(1) if m else rustc.stdout.strip()
    # GLEICHHEIT, NICHT TEILZEICHENKETTE: `"1.95.0" in "rustc 1.95.0-ROGUE-FORK …"` ist wahr.
    if gemessen != kanal:
        pytest.skip(f"NICHT GEMESSEN auf der gepinnten Flaeche: die Pinnung nennt {kanal}, hier "
                    f"laeuft {gemessen!r}")
    return rustc.stdout.strip()


def test_der_rust_baum_ist_unter_der_gepinnten_toolchain_formatiert():
    """DER EIGENTLICHE KNOTEN fuer die Formatierung. Er misst, was der CI-Schritt misst."""
    toolchain = _gepinnte_flaeche_oder_skip(_gepinnter_kanal())
    ver = _lauf("cargo", "fmt", "--version")
    komponente = ver.stdout.strip() if ver.returncode == 0 else "(rustfmt-Version nicht messbar)"
    r = _lauf("cargo", "fmt", "--check")
    assert r.returncode == 0, (
        f"`cargo fmt --check` unter {toolchain} / {komponente} endete mit {r.returncode}. Das ist "
        f"derselbe Befehl, den der CI-Schritt faehrt.\n--- stdout ---\n{r.stdout[:4000]}\n"
        f"--- stderr ---\n{r.stderr[:1000]}")


def test_der_linter_ist_gruen_wo_der_baum_schon_steht():
    """Der Linter-Lauf. Er zieht KEINE Vollkompilierung in die Suite.

    Gemessen: 3,5 s auf einem gebauten Baum, Minuten auf einem kalten. Er laeuft deshalb nur, wo
    der Baum steht — und dass das im CI wirklich der Fall ist, haelt
    `test_der_rust_job_faehrt_diese_datei_mit` fest."""
    toolchain = _gepinnte_flaeche_oder_skip(_gepinnter_kanal())
    if not (RUST / "target").is_dir():
        pytest.skip("NICHT GEMESSEN: der Rust-Baum ist hier nicht gebaut — eine Vollkompilierung "
                    "gehoert nicht in diese Suite, sie laeuft im Rust-Job")
    r = _lauf("cargo", "clippy", "--all-targets", "--", "-D", "warnings")
    assert r.returncode == 0, (
        f"`cargo clippy --all-targets -- -D warnings` unter {toolchain} endete mit "
        f"{r.returncode}. Das ist derselbe Befehl, den der CI-Schritt faehrt.\n"
        f"--- stderr ---\n{r.stderr[-4000:]}")
