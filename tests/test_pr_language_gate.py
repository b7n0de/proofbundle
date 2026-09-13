"""Contract for the pr-language-gate, R3 of the standard, in both directions.

R3 verbatim: "Fangnachweis beide Richtungen, ein deutscher Titel rot, ein englischer Titel mit
englischem Zitat eines deutschen Satzes gruen, ein gemischter Text rot."

Beyond R3 this file pins the exemption that was MEASURED into existence. On 2026-09-13 a naive
marker scan called pull request 189 German because its English body contains `NICHT MESSBAR`, a
typed state of this house. The briefing that ordered the work listed 189 as English, and the
briefing was right. Without the exemption this gate would turn red on precisely the texts that are
most careful about declaring what they did not measure.
"""
from __future__ import annotations

import importlib.util
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("plg", REPO / "scripts" / "pr_language_gate.py")
plg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(plg)


# ── R3, the three ordered cases ─────────────────────────────────────────────────────────────────

def test_r3_ein_deutscher_titel_ist_rot():
    erg = plg.pruefe("feat(riegel): der Paketbau bricht ab, wenn Schluesselmaterial mitgeht", "")
    assert not erg["sauber"], "a German title must be red"
    assert "title" in erg["befunde"]


def test_r3_ein_englischer_text_mit_zitiertem_deutschen_satz_ist_gruen():
    """The quote is marked as a quote. That is what makes it a quote and not prose."""
    text = (
        "The guard refuses the build when key material would ship.\n\n"
        "> Der Paketbau bricht ab, wenn Schluesselmaterial im sdist liegt.\n\n"
        "The sentence above is the original wording of the order, kept verbatim.\n"
    )
    erg = plg.pruefe("feat(guard): the package build fails closed on key material", text)
    assert erg["sauber"], f"a quoted German sentence must stay green: {erg['befunde']}"


def test_r3_ein_gemischter_text_ist_rot():
    text = ("The guard refuses the build. Der Riegel bricht den Bau ab, wenn "
            "Schluesselmaterial mitgeht, und das ist der ganze Punkt.\n")
    erg = plg.pruefe("feat(guard): the package build fails closed", text)
    assert not erg["sauber"], "mixed prose must be red"
    assert "body" in erg["befunde"]


# ── Die gemessene Ausnahme, und ihre Gegenrichtung ──────────────────────────────────────────────

def test_ein_typisierter_hauszustand_macht_englisch_nicht_deutsch():
    """DER FUND VOM 13.09.2026 an PR 189, als ausfuehrbarer Fall."""
    text = ("Seven cells fall on NICHT MESSBAR because the mapping tables say NO COUNTERPART "
            "there, and the receipt stays PARTIAL_GATE_NO_WITHSTANDS until a lens runs.\n")
    erg = plg.pruefe("docs(interop): the frozen fixture and its honest limit", text)
    assert erg["sauber"], f"typed house states are not German prose: {erg['befunde']}"


def test_der_hauszustand_ist_kein_freibrief_fuer_den_rest_des_satzes():
    """Die Gegenrichtung. Sonst waere die Ausnahme ein Loch, durch das jeder Satz passt."""
    text = "The value is NICHT MESSBAR und der Grund dafuer wird hier nicht genannt.\n"
    erg = plg.pruefe("docs: a limit", text)
    assert not erg["sauber"], (
        "the exemption removed the typed state but must leave the surrounding prose scannable")


def test_ohne_die_ausnahme_waere_der_englische_text_rot():
    """RUECKNAHME-PROBE: sie belegt, dass die Ausnahme ueberhaupt noetig ist.

    Ohne sie meldet dieselbe Markerliste auf demselben englischen Text einen Treffer. Fehlt diese
    Probe, koennte die Ausnahme spurlos entfernt werden und der Fall darueber bliebe gruen, weil
    er auch ohne sie gruen waere.
    """
    text = "Seven cells fall on NICHT MESSBAR because the mapping tables say NO COUNTERPART there."
    roh = plg.MARKER.findall(text)
    assert roh, "die Rohliste findet hier nichts — dann belegt die Ausnahme nichts"
    assert plg.treffer(text) == [], "mit Ausnahme muss derselbe Text sauber sein"


# ── Zitatformen, alle drei, weil eine davon reicht um die Regel zu umgehen ───────────────────────

def test_alle_drei_zitatformen_schuetzen():
    satz = "Der Riegel bricht den Bau ab, wenn das nicht stimmt."
    for form, text in (
        ("blockquote", f"English prose here.\n\n> {satz}\n"),
        ("inline", f"English prose here, quoting `{satz}` verbatim.\n"),
        ("fenced", f"English prose here.\n\n```\n{satz}\n```\n"),
    ):
        erg = plg.pruefe("docs: a title in English", text)
        assert erg["sauber"], f"{form}: a marked quote must stay green: {erg['befunde']}"


def test_dieselben_worte_ohne_zitatform_sind_rot():
    """Gegenrichtung zu allen drei Formen auf einmal."""
    satz = "Der Riegel bricht den Bau ab, wenn das nicht stimmt."
    erg = plg.pruefe("docs: a title in English", f"English prose here. {satz}\n")
    assert not erg["sauber"], "unmarked German prose must be red"


def test_commit_nachrichten_werden_mitgeprueft():
    erg = plg.pruefe("feat: an English title", "An English body.",
                     ["feat: an English commit", "fix: der zweite Commit ist deutsch"])
    assert not erg["sauber"]
    assert any(k.startswith("commit") for k in erg["befunde"]), erg["befunde"]
