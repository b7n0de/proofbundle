"""Die gepinnte Rust-Formatierung als VERTRAG, nicht nur als CI-Schritt.

WARUM ES DIESE DATEI GIBT. Am 2026-09-15 war `cargo fmt --check` im Rust-Baum rot: 36 Treffer
unter der gepinnten Toolchain. Der Fix lief ueber PR 211 und landete als `8d20eec`, und die
Messung dazu war ehrlich — nur eben NICHT belegbar. Der Abschluss-Beleg dieses Hauses verlangt
einen Fangnachweis in Form eines pytest-Knotens, und fuer eine cargo-Messung gab es keinen. Der
Antrag wurde mit `abgewiesen` zurueckgewiesen, und die Lehre stand danach im Fehlerbuch statt im
Baum: eine Messung, fuer die es keinen Knoten gibt, kann man nicht zusagen.

Dieser Fall ist der Knoten. Er misst dasselbe, was der CI-Schritt misst, im selben Verzeichnis und
damit unter derselben Toolchain-Datei.

DIE FLAECHE WIRD MITGEMESSEN, nicht angenommen. `rustfmt` ist versionsabhaengig: derselbe Quelltext
ergibt unter zwei Versionen zwei verschiedene Urteile, und genau dieser Drift hat den Gate am
2026-07-18 rot gefaerbt (siehe den Kopf von `tools/pb_verify_rs/rust-toolchain.toml`). Ein gruenes
`cargo fmt --check` aus einer FREMDEN Version sagt darum nichts ueber CI. Der Fall vergleicht die
gemessene Version mit der gepinnten und faellt lieber in ein ehrliches SKIP als in ein Gruen, das
eine andere Flaeche beschreibt.

`cargo clippy` steht seit dem 2026-09-16 daneben, in einer eigenen Klasse mit eigener
Laufzeitentscheidung. Gemessen wurde vorher, was es kostet: 3,5 s auf einem GEBAUTEN Baum, Minuten
auf einem kalten. Der Fall laeuft deshalb nur, wenn der Baum schon gebaut ist, und sagt sonst
warum nicht — ein Vertrag, der eine Vollkompilierung in die Testsuite zieht, wird abgeschaltet und
schuetzt danach nichts mehr.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
RUST = REPO / "tools" / "pb_verify_rs"
PIN = RUST / "rust-toolchain.toml"

#: `channel = "1.95.0"` — bewusst eine Regex und kein tomllib: das Paket wird auch auf 3.10
#: getestet, und dort gibt es tomllib nicht. Eine Abhaengigkeit fuer eine Zeile waere zu teuer.
_KANAL = re.compile(r'^\s*channel\s*=\s*"([^"]+)"\s*$', re.M)


def _gepinnter_kanal() -> str:
    if not PIN.is_file():
        pytest.skip(f"{PIN.relative_to(REPO) if PIN.is_relative_to(REPO) else PIN} liegt hier nicht")
    m = _KANAL.search(PIN.read_text(encoding="utf-8"))
    if not m:
        pytest.fail(f"{PIN} nennt keinen `channel` — ohne ihn ist die Messung nicht gepinnt")
    return m.group(1)


def _lauf(*befehl: str, cwd: Path = RUST) -> subprocess.CompletedProcess:
    return subprocess.run(befehl, cwd=str(cwd), capture_output=True, text=True)


def test_die_toolchain_ist_auf_eine_exakte_version_gepinnt():
    """Ein Kanal wie `stable` ist keine Pinnung, sondern eine bewegliche Flaeche.

    Dieser Fall braucht KEIN cargo und laeuft deshalb in jedem Checkout. Er ist der Grund, aus dem
    der Fall darunter ueberhaupt etwas ueber CI aussagen kann."""
    kanal = _gepinnter_kanal()
    assert re.fullmatch(r"\d+\.\d+\.\d+", kanal), (
        f"channel = {kanal!r} ist kein exakter Stand. rustfmt urteilt versionsabhaengig; ein "
        "beweglicher Kanal laesst denselben Quelltext morgen anders aussehen, und genau dieser "
        "Drift hat den Gate schon einmal rot gefaerbt.")
    inhalt = PIN.read_text(encoding="utf-8")
    assert "rustfmt" in inhalt, "die Pinnung nennt rustfmt nicht als Komponente"


def test_der_ci_schritt_misst_im_verzeichnis_der_pinnung():
    """Die Pinnung wirkt ueber das VERZEICHNIS, nicht ueber ein Flag.

    `rust-toolchain.toml` gilt fuer den Baum, in dem es liegt. Liefe der CI-Schritt aus der
    Repo-Wurzel, griffe die Pinnung nicht, und der Schritt maesse unter irgendeiner Version —
    gruen oder rot waere dann Zufall. Der Fall bindet den Schritt an das Verzeichnis, damit
    Vertrag und Gate nicht auseinanderlaufen."""
    ci = REPO / ".github" / "workflows" / "ci.yml"
    if not ci.is_file():
        pytest.skip(".github/workflows/ci.yml liegt hier nicht")
    text = ci.read_text(encoding="utf-8")
    zeilen = [z.strip() for z in text.splitlines() if "cargo fmt" in z]
    assert zeilen, "kein Schritt im CI fuehrt `cargo fmt` aus"
    # DER PFADNAME IM BEFEHL REICHT NICHT, und das hat ein gepflanzter Defekt gezeigt: die erste
    # Fassung suchte nur die Zeichenkette `tools/pb_verify_rs`, und
    # `cargo fmt --check --manifest-path tools/pb_verify_rs/Cargo.toml` enthaelt sie — laeuft aber
    # in der Repo-Wurzel. rustup waehlt die Toolchain nach dem ARBEITSVERZEICHNIS, nicht nach dem
    # Manifest, also haette dieser Schritt unter irgendeiner Version gemessen. Gepruefft wird
    # deshalb der Wechsel selbst, in den beiden Formen, die GitHub Actions dafuer kennt.
    verzeichniswechsel = re.compile(r"cd\s+tools/pb_verify_rs\s*&&")
    for z in zeilen:
        wechsel = bool(verzeichniswechsel.search(z))
        # Die zweite Form: `working-directory: tools/pb_verify_rs` im selben Schritt. Ein Schritt
        # reicht vom `- name:` bis zum naechsten; gesucht wird im Block, nicht in der Zeile.
        if not wechsel:
            i = text.index(z)
            anfang = text.rfind("\n      - ", 0, i)
            ende = text.find("\n      - ", i)
            block = text[anfang if anfang >= 0 else 0: ende if ende >= 0 else len(text)]
            wechsel = "working-directory: tools/pb_verify_rs" in block
        assert wechsel, (
            f"der fmt-Schritt wechselt nicht in das Verzeichnis der Pinnung: {z!r}. rustup waehlt "
            "die Toolchain nach dem Arbeitsverzeichnis; ohne den Wechsel misst der Schritt unter "
            "einer beliebigen Version, und gruen oder rot waere Zufall.")
        assert "--check" in z, f"der fmt-Schritt formatiert, statt zu pruefen: {z!r}"


def test_der_rust_baum_ist_unter_der_gepinnten_toolchain_formatiert():
    """DER EIGENTLICHE KNOTEN. Er misst, was der CI-Schritt misst.

    Drei Zustaende statt zwei: gruen, rot, oder ein SKIP, das sagt WARUM nicht gemessen wurde.
    Ein SKIP ist hier kein bestandener Lauf, und die Meldung sagt das auch."""
    kanal = _gepinnter_kanal()
    if not RUST.is_dir():
        pytest.skip("tools/pb_verify_rs liegt hier nicht (Paketlauf statt Checkout)")
    if shutil.which("cargo") is None:
        pytest.skip("NICHT GEMESSEN: kein `cargo` im PATH — das ist kein bestandener fmt-Lauf")

    # DAS RICHTIGE FELD, und der erste Entwurf nahm das falsche. `cargo fmt --version` meldet die
    # Version der KOMPONENTE rustfmt (`rustfmt 1.9.0-stable (…)`), nicht die der Toolchain; ein
    # Vergleich mit `1.95.0` aus der Pinnung schlug darum IMMER fehl, auch auf der richtigen
    # Maschine. Der Fall haette nie gemessen und dabei ehrlich ausgesehen. Die Toolchain-Version
    # steht in `rustc --version`, und sie wird HIER gemessen, im Verzeichnis der Pinnung.
    rustc = _lauf("rustc", "--version")
    if rustc.returncode != 0:
        pytest.skip(f"NICHT GEMESSEN: `rustc --version` endete mit {rustc.returncode} — "
                    f"{(rustc.stderr or rustc.stdout).strip()[:160]}")
    toolchain = rustc.stdout.strip()
    if kanal not in toolchain:
        pytest.skip(
            f"NICHT GEMESSEN auf der gepinnten Flaeche: die Pinnung nennt {kanal}, hier laeuft "
            f"{toolchain!r}. Ein gruenes Urteil aus einer anderen Toolchain sagt nichts ueber CI "
            "— rustfmt urteilt versionsabhaengig.")
    ver = _lauf("cargo", "fmt", "--version")
    komponente = ver.stdout.strip() if ver.returncode == 0 else "(rustfmt-Version nicht messbar)"

    r = _lauf("cargo", "fmt", "--check")
    assert r.returncode == 0, (
        f"`cargo fmt --check` unter {toolchain} / {komponente} endete mit {r.returncode}. Das ist "
        f"derselbe Befehl, den der CI-Schritt faehrt.\n--- stdout ---\n{r.stdout[:4000]}\n"
        f"--- stderr ---\n{r.stderr[:1000]}")

# --- der zweite Waechter an derselben Pinnung: `cargo clippy -D warnings` ---------------------
#
# Er gehoert aus demselben Grund gebunden wie die Formatierung: clippy urteilt
# versionsabhaengig, und ein `-D warnings` unter einer anderen Version ist eine andere Zusage.
# Der Unterschied ist die LAUFZEIT — gemessen 3,5 s auf einem gebauten Baum, Minuten auf einem
# kalten. Deshalb ZWEI Faelle statt einem: die Form des CI-Schritts wird IMMER geprueft, der Lauf
# selbst nur dort, wo der Baum schon steht.


def _schritt_wechselt_ins_verzeichnis(text: str, zeile: str) -> bool:
    """Wechselt der Schritt, zu dem diese Zeile gehoert, in das Verzeichnis der Pinnung?

    Beide Formen, die GitHub Actions dafuer kennt: `cd <verzeichnis> &&` in der Zeile, oder
    `working-directory:` irgendwo im selben Schritt. Ein Pfadname IM Befehl reicht nicht — siehe
    die Begruendung bei `test_der_ci_schritt_misst_im_verzeichnis_der_pinnung`.
    """
    if re.search(r"cd\s+tools/pb_verify_rs\s*&&", zeile):
        return True
    i = text.index(zeile)
    anfang = text.rfind("\n      - ", 0, i)
    ende = text.find("\n      - ", i)
    block = text[anfang if anfang >= 0 else 0: ende if ende >= 0 else len(text)]
    return "working-directory: tools/pb_verify_rs" in block


def test_der_ci_schritt_des_linters_verweigert_warnungen_im_verzeichnis_der_pinnung():
    """Die Form, und die kostet nichts.

    `-D warnings` macht aus einer Warnung einen Fehler; ohne das Flag ist der Schritt eine
    Meinung, keine Zusage. Und ohne den Verzeichniswechsel urteilt eine beliebige clippy-Version
    darueber."""
    ci = REPO / ".github" / "workflows" / "ci.yml"
    if not ci.is_file():
        pytest.skip(".github/workflows/ci.yml liegt hier nicht")
    text = ci.read_text(encoding="utf-8")
    zeilen = [z.strip() for z in text.splitlines() if "cargo clippy" in z]
    assert zeilen, "kein Schritt im CI fuehrt `cargo clippy` aus"
    for z in zeilen:
        assert _schritt_wechselt_ins_verzeichnis(text, z), (
            f"der clippy-Schritt wechselt nicht in das Verzeichnis der Pinnung: {z!r}. rustup "
            "waehlt die Toolchain nach dem Arbeitsverzeichnis.")
        assert "-D warnings" in z, (
            f"der clippy-Schritt macht aus Warnungen keine Fehler: {z!r}. Ohne `-D warnings` ist "
            "er eine Meinung, keine Zusage.")


def test_der_linter_ist_gruen_wo_der_baum_schon_steht():
    """Der Lauf selbst, und er zieht KEINE Vollkompilierung in die Suite.

    Laeuft nur auf einem bereits gebauten Baum; sonst ein SKIP, das die fehlende Vorbedingung
    benennt. Ein Vertrag, der jede Suite um Minuten verlaengert, wird abgeschaltet, und ein
    abgeschalteter Vertrag schuetzt nichts."""
    kanal = _gepinnter_kanal()
    if not RUST.is_dir():
        pytest.skip("tools/pb_verify_rs liegt hier nicht (Paketlauf statt Checkout)")
    if shutil.which("cargo") is None:
        pytest.skip("NICHT GEMESSEN: kein `cargo` im PATH — das ist kein bestandener Lauf")
    if not (RUST / "target").is_dir():
        pytest.skip("NICHT GEMESSEN: der Rust-Baum ist hier nicht gebaut — eine Vollkompilierung "
                    "gehoert nicht in diese Suite, sie laeuft im Rust-Job")
    rustc = _lauf("rustc", "--version")
    if rustc.returncode != 0 or kanal not in rustc.stdout:
        pytest.skip(f"NICHT GEMESSEN auf der gepinnten Flaeche: die Pinnung nennt {kanal}, hier "
                    f"laeuft {rustc.stdout.strip()!r}")
    r = _lauf("cargo", "clippy", "--all-targets", "--", "-D", "warnings")
    assert r.returncode == 0, (
        f"`cargo clippy --all-targets -- -D warnings` unter {rustc.stdout.strip()} endete mit "
        f"{r.returncode}. Das ist derselbe Befehl, den der CI-Schritt faehrt.\n"
        f"--- stderr ---\n{r.stderr[-4000:]}")
