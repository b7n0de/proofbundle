"""Contract for the pr-language-gate, R3 of the standard, in both directions.

R3, in English: a catch proof in both directions, a German title red, an English title with an
English quotation of a German sentence green, a mixed text red.

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

def test_r3_a_german_title_is_red():
    erg = plg.pruefe("feat(riegel): der Paketbau bricht ab, wenn Schluesselmaterial mitgeht", "")
    assert not erg["sauber"], "a German title must be red"
    assert "title" in erg["befunde"]


def test_r3_an_english_text_with_a_quoted_german_sentence_is_green():
    """The quote is marked as a quote. That is what makes it a quote and not prose."""
    text = (
        "The guard refuses the build when key material would ship.\n\n"
        "> Der Paketbau bricht ab, wenn Schluesselmaterial im sdist liegt.\n\n"
        "The sentence above is the original wording of the order, kept verbatim.\n"
    )
    erg = plg.pruefe("feat(guard): the package build fails closed on key material", text)
    assert erg["sauber"], f"a quoted German sentence must stay green: {erg['befunde']}"


def test_r3_a_mixed_text_is_red():
    text = ("The guard refuses the build. Der Riegel bricht den Bau ab, wenn "
            "Schluesselmaterial mitgeht, und das ist der ganze Punkt.\n")
    erg = plg.pruefe("feat(guard): the package build fails closed", text)
    assert not erg["sauber"], "mixed prose must be red"
    assert "body" in erg["befunde"]


# ── The measured exemption, and its other direction ─────────────────────────────────────────────

def test_a_typed_house_state_does_not_make_english_german():
    """THE FINDING OF 2026-09-13 on PR 189, as an executable case."""
    text = ("Seven cells fall on NICHT MESSBAR because the mapping tables say NO COUNTERPART "
            "there, and the receipt stays PARTIAL_GATE_NO_WITHSTANDS until a lens runs.\n")
    erg = plg.pruefe("docs(interop): the frozen fixture and its honest limit", text)
    assert erg["sauber"], f"typed house states are not German prose: {erg['befunde']}"


def test_the_house_state_is_no_licence_for_the_rest_of_the_sentence():
    """The other direction. Otherwise the exemption would be a hole any sentence passes through."""
    text = "The value is NICHT MESSBAR und der Grund dafuer wird hier nicht genannt.\n"
    erg = plg.pruefe("docs: a limit", text)
    assert not erg["sauber"], (
        "the exemption removed the typed state but must leave the surrounding prose scannable")


def test_without_the_exemption_the_english_text_would_be_red():
    """RETRACTION PROBE: it shows that the exemption is needed at all.

    Without it the same marker list reports a hit on the same English text. Without this probe the
    exemption could be removed without a trace and the case above would stay green, because it would
    be green without it as well.
    """
    text = "Seven cells fall on NICHT MESSBAR because the mapping tables say NO COUNTERPART there."
    raw = plg.MARKER.findall(text)
    assert raw, "the raw list finds nothing here, so the exemption proves nothing"
    assert plg.treffer(text) == [], "with the exemption the same text must be clean"


# ── Quote forms, all three, because one of them is enough to get around the rule ────────────────

def test_all_three_quote_forms_protect():
    sentence = "Der Riegel bricht den Bau ab, wenn das nicht stimmt."
    for form, text in (
        ("blockquote", f"English prose here.\n\n> {sentence}\n"),
        ("inline", f"English prose here, quoting `{sentence}` verbatim.\n"),
        ("fenced", f"English prose here.\n\n```\n{sentence}\n```\n"),
    ):
        erg = plg.pruefe("docs: a title in English", text)
        assert erg["sauber"], f"{form}: a marked quote must stay green: {erg['befunde']}"


def test_the_same_words_without_a_quote_form_are_red():
    """The other direction to all three forms at once."""
    sentence = "Der Riegel bricht den Bau ab, wenn das nicht stimmt."
    erg = plg.pruefe("docs: a title in English", f"English prose here. {sentence}\n")
    assert not erg["sauber"], "unmarked German prose must be red"


# ── The measured false red of 2026-10-17, and the threshold that closes it ──────────────────────

#: Lines as they stand in commit messages and bodies of open pull requests 278, 279 and 299. With a
#: single list word enough, each of them made its pull request red, because of the acronym DER.
DER_ZEILEN = (
    "certificate is not DER X.509, is malformed; an unprotected x5c",
    "The SubjectPublicKeyInfo is now read as DER first. EC on P-256 or P-384 is built from",
    "fix(cli): the statement key check reads the DER shape and builds no key",
    "opens with an OID, and a BIT STRING) with the reader's own DER element",
)


def test_an_english_acronym_alone_does_not_make_a_line_german():
    for zeile in DER_ZEILEN:
        erg = plg.pruefe("docs: an English title", zeile)
        assert erg["sauber"], f"{zeile!r}: {erg['befunde']}"
        assert plg.MARKER.findall(zeile), "the raw list must hit DER here, or this case proves nothing"


def test_two_list_words_on_one_line_are_red():
    erg = plg.pruefe("docs: an English title", "The guard stays green, und das ist ein Fehler.\n")
    assert not erg["sauber"], "two list words on one line are German prose"


def test_an_umlaut_alone_is_red():
    erg = plg.pruefe("fix: Prüfung angepasst", "")
    assert not erg["sauber"], "R1 counts an umlaut on its own"


def test_the_historical_titles_keep_their_verdict():
    """The old and new titles of pull requests 200 and 201, read from their rename events."""
    for alt in ("feat(riegel): der Paketbau bricht ab, wenn Schluesselmaterial im sdist oder wheel liegt",
                "chore(identitaet): .mailmap statt Umschrift, einheitliche Anzeige ohne einen Commit anzufassen"):
        assert not plg.pruefe(alt, "")["sauber"], alt
    for neu in ("feat(guard): the package build fails closed when key material would ship in the sdist or wheel",
                "chore(identity): map by address to one identity, no real name in the file"):
        assert plg.pruefe(neu, "")["sauber"], neu


def test_the_threshold_is_the_one_of_the_new_lines_gate():
    """One number for one question. Read from the other tool's source, not imported, because that
    tool measures a git tree when it is imported."""
    import ast
    quelle = (REPO / "scripts" / "neue_zeilen_sind_englisch.py").read_text(encoding="utf-8")
    werte = [k.value.value for k in ast.walk(ast.parse(quelle))
             if isinstance(k, ast.Assign) and any(getattr(z, "id", None) == "SCHWELLE" for z in k.targets)]
    assert werte == [plg.SCHWELLE], werte


def test_the_word_list_holds_r1_and_the_shared_list():
    from tests import _deutsche_prosa as DP
    assert set(plg._STOPWOERTER) <= set(plg._WOERTER)
    assert set(DP.FUNKTIONSWOERTER) <= set(plg._WOERTER)


def test_commit_messages_are_checked_too():
    erg = plg.pruefe("feat: an English title", "An English body.",
                     ["feat: an English commit", "fix: der zweite Commit ist deutsch"])
    assert not erg["sauber"]
    assert any(k.startswith("commit") for k in erg["befunde"]), erg["befunde"]
