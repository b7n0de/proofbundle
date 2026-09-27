"""What six review lenses broke in the register producer on 2026-09-20, kept as executable cases.

The lenses ran against the head that introduced the 610 line and the third find form. Each case
below reproduces one of their counter-examples and asserts the repair. They are written from the
counter-example inwards, not from the fix outwards: every one of them was RED before its repair.

WHAT IS NOT CLAIMED. These are the defects that were found, not the defects that exist. Two of the
lens findings are carried as named limits instead of as cases, and they are named in the module
that carries them: a heading of the form `## Open questions, all resolved` still reads as open,
and a promise denied in a wording other than the short negation list still reads as a promise.
Deciding whether prose asserts or denies is not a job a pattern finishes.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]


def _erzeuger():
    s = importlib.util.spec_from_file_location(
        "_gen_under_test", REPO / "scripts" / "gen_findings_register.py")
    m = importlib.util.module_from_spec(s)
    sys.modules["_gen_under_test"] = m
    s.loader.exec_module(m)
    return m


ZUSAGE = "Register entry `{}`, target 6.2.0."


def test_ein_absatz_mit_CRLF_verschluckt_nicht_die_ganze_datei():
    """Lens 1, target 2. Measured: with CRLF the literal two-newline search never fires, and one
    identifier received the WHOLE 371 KB source document as its evidence, accepted by the checker
    because a whole file is a range inside the file."""
    g = _erzeuger()
    text = ("Head.\r\n\r\nSome paragraph before.\r\n\r\n"
            + ZUSAGE.format("AAA-BBBBBBB-01") + "\r\n\r\nTail after it.\r\n")
    von, bis, art = g.schneide_beleg(text, "AAA-BBBBBBB-01", {"AAA-BBBBBBB-01"})
    stueck = text.encode()[von:bis].decode()
    assert art == "prosa_zusage"
    assert "Some paragraph before" not in stueck, stueck
    assert "Tail after it" not in stueck, stueck


def test_eine_zeile_aus_leerzeichen_trennt_zwei_absaetze():
    """Lens 1, target 4. A separator line carrying spaces let two paragraphs merge, so one
    finding's evidence swallowed its neighbour's sentence."""
    g = _erzeuger()
    text = ("Head.\n\nNeighbour sentence that must stay out.\n   \n"
            + ZUSAGE.format("CCC-DDDDDDD-01") + "\n\nTail.\n")
    von, bis, _ = g.schneide_beleg(text, "CCC-DDDDDDD-01", {"CCC-DDDDDDD-01"})
    assert "Neighbour sentence" not in text.encode()[von:bis].decode()


def test_eine_verneinte_zusage_ist_keine():
    """Lens 1, target 3. `there is no Register entry X` produced a record whose title was the
    sentence denying it."""
    g = _erzeuger()
    text = ("Head.\n\nThis is closed, so there is no Register entry `EEE-FFFFFFF-01` for it.\n\n")
    assert g.schneide_beleg(text, "EEE-FFFFFFF-01", {"EEE-FFFFFFF-01"}) is None


def test_eine_kennung_die_aus_dem_belegverzeichnis_ausbricht_wird_abgewiesen(tmp_path):
    """Lens 2, target 4, the sharpest of the round. An entry whose identifier is a traversal path
    produced a record the checker accepted with zero errors, and the evidence write landed outside
    the repository."""
    g = _erzeuger()
    quelle = tmp_path / "RESTRISIKO_PROBE.md"
    kennung = "../../../../tmp/ausbruch"
    quelle.write_text(f"## {kennung}\n\nSomething.\n", encoding="utf-8")
    ok = tmp_path / "PROBE_OBJEKTKLASSEN.json"
    ok.write_text(json.dumps({"gemessen_an": {"datei": "RESTRISIKO_PROBE.md",
                                              "sha256": "0" * 64, "utc": "2026-09-20T00:00:00Z"},
                              "eintraege": [{"kennung": kennung, "klasse": "x",
                                             "zaehlt_als_fund": True}]}),
                  encoding="utf-8")
    g.RESTRISIKO_REL, g.OBJEKTKLASSEN_REL = "RESTRISIKO_PROBE.md", "PROBE_OBJEKTKLASSEN.json"
    with pytest.raises(SystemExit) as e:
        g.baue_v2(tmp_path, "2026-09-20T00:00:00Z")
    # BOUND TO THE REFUSED VALUE, not to the wording of the refusal. The first version asserted the
    # German word `Kennung`; translating that message into English broke a case whose subject had
    # not changed by a byte. A refusal names the value it refuses, in any language, and that is the
    # property worth holding.
    assert kennung in str(e.value), e.value


def test_eine_kennung_die_eine_andere_als_praefix_hat_verliert_ihren_eintrag_NICHT(tmp_path):
    """Fourth review round, thread 4057469367. Identifier identity, not character containment.

    With `N1` and `N10` both declared, the paragraph promising `N10` contains the characters of
    `N1`, so the foreign-identifier check saw `N1` inside it, refused the paragraph and dropped
    `N10` into `identifiers_without_evidence` although its promise was found. Measured at the
    previous head, the produced carrier lost a valid entry; this case builds that exact tree.
    """
    g = _erzeuger()
    quelle = tmp_path / "RESTRISIKO_PROBE.md"
    quelle.write_text(
        "## Open — the probe\n\n"
        "Register entry `N10`, target 6.2.0.\n\n"
        "## N1 · a heading of its own\n\nSomething about N1.\n",
        encoding="utf-8")
    ok = tmp_path / "PROBE_OBJEKTKLASSEN.json"
    ok.write_text(json.dumps({
        "gemessen_an": {"datei": "RESTRISIKO_PROBE.md", "sha256": "0" * 64,
                        "utc": "2026-09-20T00:00:00Z"},
        "eintraege": [{"kennung": "N1", "klasse": "x", "zaehlt_als_fund": True},
                      {"kennung": "N10", "klasse": "x", "zaehlt_als_fund": True}]}),
        encoding="utf-8")
    g.RESTRISIKO_REL, g.OBJEKTKLASSEN_REL = "RESTRISIKO_PROBE.md", "PROBE_OBJEKTKLASSEN.json"
    doc = g.baue_v2(tmp_path, "2026-09-20T00:00:00Z")
    getragen = {r["id"] for r in doc["records"]}
    assert "N10" in getragen, (
        f"the entry whose identifier has another as a prefix was dropped: carried {sorted(getragen)}, "
        f"without evidence {doc['inventory']['identifiers_without_evidence']}")
    assert "N1" in getragen, f"the shorter identifier lost its own entry: {sorted(getragen)}"


def test_die_grenze_kennt_dasselbe_alphabet_wie_die_formregel(tmp_path):
    """Sixth review round, thread 4057493355. The repair for a second list made a third one.

    The boundary class was typed out beside the form rule and left the dot out, so with `N1` and
    `N1.foo` both declared the dot counted as a boundary, `N1` was found inside `N1.foo`, and the
    longer entry was dropped from the carrier exactly as before. Measured here at the data path,
    and the constant is now shared rather than repeated.
    """
    g = _erzeuger()
    (tmp_path / "RESTRISIKO_PROBE.md").write_text(
        "## Open — the probe\n\n"
        "Register entry `N1.foo`, target 6.2.0.\n\n"
        "## N1 · a heading of its own\n\nSomething about N1.\n",
        encoding="utf-8")
    (tmp_path / "PROBE_OBJEKTKLASSEN.json").write_text(json.dumps({
        "gemessen_an": {"datei": "RESTRISIKO_PROBE.md", "sha256": "0" * 64,
                        "utc": "2026-09-20T00:00:00Z"},
        "eintraege": [{"kennung": "N1", "klasse": "x", "zaehlt_als_fund": True},
                      {"kennung": "N1.foo", "klasse": "x", "zaehlt_als_fund": True}]}),
        encoding="utf-8")
    g.RESTRISIKO_REL, g.OBJEKTKLASSEN_REL = "RESTRISIKO_PROBE.md", "PROBE_OBJEKTKLASSEN.json"
    doc = g.baue_v2(tmp_path, "2026-09-20T00:00:00Z")
    getragen = {r["id"] for r in doc["records"]}
    assert "N1.foo" in getragen, (
        f"an identifier the form rule admits was split by a boundary that does not know it: "
        f"carried {sorted(getragen)}, without evidence "
        f"{doc['inventory']['identifiers_without_evidence']}")

    # AND THE CONSTANT IS THE ONE THE FORM RULE USES, not a second list that happens to agree.
    assert all(z in g._KENNUNG_ZEICHEN for z in "._-"), g._KENNUNG_ZEICHEN
    assert g._kennung_form().match("N1.foo"), "the form rule no longer admits what the case assumes"


def test_eine_geaenderte_DEKLARATION_bewegt_den_ERZEUGER_nicht_nur_den_vertrag(tmp_path):
    """Class sweep of this branch. The declared rule must drive the producer, not describe it.

    The carrier declares `maxLength`, `keep`, `cut`, `ellipsis` and `columnFallbackIndex`, and the
    language contract executes that declaration against the produced titles. But the producer used
    to hard-wire all of them, so a declared bound was a description of the code rather than its
    rule: changing it moved the contract alone, and the contract could then only report that the
    two disagreed, never which side was meant.

    Measured in both directions. Against the producer as it stood before this case, the declared
    bound below is ignored and the title keeps its full length; against the producer that reads
    its rule, the title follows the declaration.
    """
    g = _erzeuger()
    # THE PROBE IS MEASURED, NOT GUESSED. Its first sentence is 156 characters: past the bound
    # declared below, and short of the 200 the producer used to hard-wire. Only a promise in that
    # window separates the two producers. The first version of this case used a 34-character
    # sentence, where neither bound bites, and passed against BOTH — a case that cannot go red is
    # not a catch proof, it is a decoration.
    (tmp_path / "RESTRISIKO_PROBE.md").write_text(
        "## Open — the probe\n\n"
        "Register entry `N1`, a promise written out at deliberate length so the first sentence "
        "passes sixty characters while staying below two hundred, target 6-2-0. A second "
        "sentence follows.\n",
        encoding="utf-8")
    (tmp_path / "PROBE_OBJEKTKLASSEN.json").write_text(json.dumps({
        "gemessen_an": {"datei": "RESTRISIKO_PROBE.md", "sha256": "0" * 64,
                        "utc": "2026-09-20T00:00:00Z"},
        "eintraege": [{"kennung": "N1", "klasse": "x", "zaehlt_als_fund": True}]}),
        encoding="utf-8")
    g.RESTRISIKO_REL, g.OBJEKTKLASSEN_REL = "RESTRISIKO_PROBE.md", "PROBE_OBJEKTKLASSEN.json"

    # THE DECLARATION IS CHANGED, nothing else. If the producer reads it, the output moves.
    form = "prosa_zusage"
    vorher = dict(g.NORMALISIERUNG_JE_FUNDART[form])
    try:
        g.NORMALISIERUNG_JE_FUNDART[form] = {**vorher, "maxLength": 60}
        doc = g.baue_v2(tmp_path, "2026-09-20T00:00:00Z")
    finally:
        g.NORMALISIERUNG_JE_FUNDART[form] = vorher

    titel = [r["title"] for r in doc["records"] if r["id"] == "N1"]
    assert titel, f"the probe entry was not carried: {[r['id'] for r in doc['records']]}"
    assert len(titel[0]) <= 62, (
        "the producer ignored the declared bound, so the declaration describes the code instead "
        f"of ruling it: declared 60, produced {len(titel[0])} characters — {titel[0]!r}")

    # AND THE PROBE REALLY REACHES PAST THE BOUND, so a green here means the rule bit rather
    # than that there was nothing to cut.
    assert len(titel[0]) > 40, f"the probe never reached the bound, so nothing was measured: {titel[0]!r}"


def test_eine_ueberschrift_gehoert_der_LAENGEREN_kennung_nicht_ihrem_praefix():
    """Seventh review round, thread 4057515923. The heading boundary knows the alphabet.

    Measured at `8626ed7`: `schneide_beleg("## N1.foo — open…", "N1")` and the same call for
    `N1.foo` BOTH returned the byte range (0, 45), so two records were backed by one heading and
    `N1` was handed the title `.foo — open`. The form rule admits `N1.foo`, but the boundary in
    `schneide_beleg` and the sibling in `_kopf_muster` each carried `(?![0-9A-Za-z])`, an alphabet
    of their own that does not contain the dot.

    This is the class of the previous round at two more sites. Round six unified the form rule and
    the foreign-identifier boundary and treated the class as closed; it had five readers, not two.
    """
    g = _erzeuger()
    text = "## N1.foo — open\n\nOnly the longer finding.\n"
    bek = {"N1", "N1.foo"}
    kurz, lang = g.schneide_beleg(text, "N1", bek), g.schneide_beleg(text, "N1.foo", bek)
    assert lang is not None, "the declared identifier lost its own heading"
    assert kurz != lang, (
        f"a heading was recorded as evidence for a prefix of the identifier it names: "
        f"N1 -> {kurz}, N1.foo -> {lang}")
    assert kurz is None, f"N1 has no heading in this text, but one was cut for it: {kurz}"


def test_eine_kennung_die_kein_text_ist_endet_in_einem_URTEIL_nicht_in_einem_traceback(tmp_path):
    """Seventh review round, thread 4057515935. The type boundary comes before the collecting.

    Measured at `8626ed7`: an entry with `"kennung": ["N1"]` raised `TypeError: unhashable type:
    'list'` in the set comprehension that collected the identifiers, so the `isinstance` refusal
    three lines further down never ran. A validation placed after a step that can already fail is
    not a boundary. The generator must end in its typed verdict for every malformed shape.
    """
    g = _erzeuger()
    (tmp_path / "RESTRISIKO_PROBE.md").write_text(
        "## Open — the probe\n\nRegister entry `N1`, target 6.2.0.\n", encoding="utf-8")
    (tmp_path / "PROBE_OBJEKTKLASSEN.json").write_text(json.dumps({
        "gemessen_an": {"datei": "RESTRISIKO_PROBE.md", "sha256": "0" * 64,
                        "utc": "2026-09-20T00:00:00Z"},
        "eintraege": [{"kennung": ["N1"], "klasse": "x", "zaehlt_als_fund": True}]}),
        encoding="utf-8")
    g.RESTRISIKO_REL, g.OBJEKTKLASSEN_REL = "RESTRISIKO_PROBE.md", "PROBE_OBJEKTKLASSEN.json"
    with pytest.raises(SystemExit) as e:
        g.baue_v2(tmp_path, "2026-09-20T00:00:00Z")
    assert "['N1']" in str(e.value), (
        f"the refusal does not name the value it refused: {str(e.value)[:160]}")


def test_eine_unbekannte_fundart_wird_ABGELEHNT_nicht_stillschweigend_zur_ueberschrift():
    """Own sweep, measured while making the producer read its declared rule.

    Two wrong answers were measured on this one line, one before the change and one introduced by
    it. Before, an unknown find form fell through to the heading branch and got a title from a
    rule nobody had declared for it, which is an unmeasured case turned into a passing one. After
    reading the declaration it became `KeyError`, which is the traceback-instead-of-verdict shape
    that the same review round reported one function away.

    The third option is the one that belongs here, and this case binds it so neither of the other
    two can come back.
    """
    g = _erzeuger()
    with pytest.raises(SystemExit) as e:
        g._titel("## N1 something\n", "N1", "gibt_es_nicht", None)
    assert "gibt_es_nicht" in str(e.value), (
        f"the refusal does not name the form it refused: {str(e.value)[:160]}")

    # AND A DECLARED FORM STILL PASSES, so the refusal is not a refusal of everything.
    assert g._titel("## N1 something\n", "N1", "ueberschrift", None) == "something"


def test_ein_beleg_verschlingt_die_NACHBARFUNDSTELLE_nicht(tmp_path):
    """Eighth review round, thread 4057515793. Lowercase identifiers, and my own blind spot.

    Measured at `4cccefb`: `schneide_beleg("## n1 ...\\n\\n### n2 ...", "n1")` returned the WHOLE
    text, so the evidence for one finding contained another. Both `n1` and `n2` are admitted by
    `_kennung_form`; the heading reader captured only `[A-Z]\\d+`, so neither the identifier-shaped
    terminator nor the generic one (which only sees headings of the same level or shallower)
    ended the range.

    I HAD MEASURED THIS AREA ONE ROUND EARLIER AND MISSED IT. Three shapes, all with capital
    identifiers, all showing no difference, and I reported "no effect". Three cases that share
    the property under test are one case run three times. This one varies the property.
    """
    g = _erzeuger()
    text = "## n1 — first\n\nfirst body\n\n### n2 — second\n\nsecond body\n"
    r = g.schneide_beleg(text, "n1", {"n1", "n2"})
    assert r is not None, "the lowercase identifier lost its own heading"
    stueck = text.encode()[r[0]:r[1]].decode()
    assert "n2" not in stueck, (
        f"the evidence for n1 swallowed the neighbouring finding: {r} of {len(text.encode())} "
        f"bytes, cut = {stueck!r}")

    # AND A PROSE HEADING DOES NOT OPEN A RECORD, which is why the declared set is passed at all.
    prosa = "## n1 — first\n\nfirst body\n\n### Notes on the above\n\nstill about n1\n"
    r2 = g.schneide_beleg(prosa, "n1", {"n1"})
    assert "still about n1" in prosa.encode()[r2[0]:r2[1]].decode(), (
        f"a prose heading cut the evidence short: {r2}")


def test_eine_quelle_ausserhalb_des_baumes_wird_ABGELEHNT(tmp_path):
    """Eighth review round, thread 4057515786, P1. Evidence has to stay inside the tree.

    Measured at `4cccefb`: an entry with `"quelle": "../outside.md"` and a matching heading in
    that sibling file produced a record titled from bytes OUTSIDE the measured tree, recorded
    `../outside.md` as its provenance, and the writer copied the slice into the repository. A
    carrier built that way cannot be rechecked from a clean checkout, which is the one thing it
    exists to allow.
    """
    g = _erzeuger()
    (tmp_path / "outside.md").write_text("## N1 a finding from outside\n\nExternal body.\n",
                                         encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "RESTRISIKO_PROBE.md").write_text(
        "## Open — x\n\nRegister entry `N9`, target 6.2.0.\n", encoding="utf-8")
    (repo / "PROBE_OBJEKTKLASSEN.json").write_text(json.dumps({
        "gemessen_an": {"datei": "RESTRISIKO_PROBE.md", "sha256": "0" * 64,
                        "utc": "2026-09-20T00:00:00Z"},
        "eintraege": [{"kennung": "N1", "quelle": "../outside.md", "klasse": "x",
                       "zaehlt_als_fund": True}]}), encoding="utf-8")
    g.RESTRISIKO_REL, g.OBJEKTKLASSEN_REL = "RESTRISIKO_PROBE.md", "PROBE_OBJEKTKLASSEN.json"
    with pytest.raises(SystemExit) as e:
        g.baue_v2(repo, "2026-09-20T00:00:00Z")
    assert "outside" in str(e.value), (
        f"the refusal does not say what it refused: {str(e.value)[:160]}")


def test_eine_quelle_die_kein_text_ist_endet_in_einem_URTEIL(tmp_path):
    """Eighth review round, thread 4057515789. The source field is the sibling of the identifier.

    Measured at `4cccefb`: `"quelle": ["R.md"]` raised `TypeError: unhashable type: 'list'`, a
    mapping the same class, an integer one line further on at `repo / rel`, and none of them
    reached the typed refusal beside it because that catches only `OSError`. The identifier field
    had been repaired one round earlier; its sibling had not.
    """
    g = _erzeuger()
    for kaputt in (["RESTRISIKO_PROBE.md"], 7, {"a": 1}):
        (tmp_path / "RESTRISIKO_PROBE.md").write_text(
            "## Open — x\n\nRegister entry `N9`, target 6.2.0.\n", encoding="utf-8")
        (tmp_path / "PROBE_OBJEKTKLASSEN.json").write_text(json.dumps({
            "gemessen_an": {"datei": "RESTRISIKO_PROBE.md", "sha256": "0" * 64,
                            "utc": "2026-09-20T00:00:00Z"},
            "eintraege": [{"kennung": "N1", "quelle": kaputt, "klasse": "x",
                           "zaehlt_als_fund": True}]}), encoding="utf-8")
        g.RESTRISIKO_REL, g.OBJEKTKLASSEN_REL = ("RESTRISIKO_PROBE.md",
                                                 "PROBE_OBJEKTKLASSEN.json")
        with pytest.raises(SystemExit) as e:
            g.baue_v2(tmp_path, "2026-09-20T00:00:00Z")
        assert "not a path" in str(e.value), (
            f"the source {kaputt!r} did not reach the typed refusal: {str(e.value)[:140]}")


def test_JEDES_deklarierte_feld_der_titelregel_bewegt_den_erzeuger():
    """Eighth review round, thread 4057515784. Three of seven fields obeyed is not the rule.

    The previous round made the producer read `maxLength`, `cut` and `ellipsis` from the
    declaration and left `sourceUnit`, `strip`, `flattenWhitespace` and `takeFirstSentence`
    hard-wired. Measured at `4cccefb`: setting `takeFirstSentence` to false still produced a
    first-sentence title, and the carrier then shipped that title beside a declaration saying
    otherwise, with the checker reporting nothing.
    """
    g = _erzeuger()
    form = "prosa_zusage"
    vor = dict(g.NORMALISIERUNG_JE_FUNDART[form])
    lang = ("Register entry `N1`, first sentence here. And a clearly separate second sentence "
            "that must appear when the rule says not to take only the first.")
    try:
        g.NORMALISIERUNG_JE_FUNDART[form] = {**vor, "takeFirstSentence": False}
        ohne = g._titel(lang, "N1", form, None)
        g.NORMALISIERUNG_JE_FUNDART[form] = {**vor, "takeFirstSentence": True}
        mit = g._titel(lang, "N1", form, None)
    finally:
        g.NORMALISIERUNG_JE_FUNDART[form] = vor
    assert ohne != mit, (
        f"the declared field does not move the producer, so the declaration describes it rather "
        f"than ruling it: both gave {mit!r}")
    assert "separate second" in ohne, f"with the field off the rest was still dropped: {ohne!r}"


def test_ohne_die_deklarierten_kennungen_wird_NICHT_geraten():
    """The cross-reading's axis, and it caught a regression my own repair had introduced.

    Asked what else my cases held constant, the cross-reading named exactly the case I had not
    built: the identifier under search is `N1` and the text carries a PROSE subheading whose
    first word fits the widened alphabet. Measured on the first repair of `schneide_beleg`: the
    evidence ended at (0, 35) where it had been (0, 74), so the finding lost the rest of its own
    section. The reported defect and this regression are the two directions of one question, and
    a shape can answer neither.

    So the declared set is required. A caller without one is told, because a plausible wrong
    answer is worse here than a refusal: the carrier it feeds is the thing a reader rechecks.
    """
    g = _erzeuger()
    text = "## N1 — the finding\n\nfirst body\n\n### Notes on the above\n\nstill about N1\n"
    r = g.schneide_beleg(text, "N1", {"N1"})
    assert "still about N1" in text.encode()[r[0]:r[1]].decode(), (
        f"a prose subheading cut the evidence short: {r}")

    with pytest.raises(SystemExit) as e:
        g.schneide_beleg(text, "N1")
    assert "declared identifiers" in str(e.value), (
        f"the refusal does not say what is missing: {str(e.value)[:140]}")


def test_die_grenze_endet_das_WORT_nicht_nur_die_ascii_klasse():
    """The cross-reading's second axis. The general form of the dot defect.

    The boundary asked whether the next character was outside the ASCII identifier alphabet, and
    a letter of another script is outside it. Measured: `## N1\u00e4 a heading` was cut as evidence
    for `N1`, although the heading names a token that `_kennung_form` does not admit at all. The
    dot of round six and this are the same defect one character class apart, so the repair is the
    general one: the boundary asks whether the WORD ends, in any script.

    MEASURED OVER THE SHIPPED SHEETS BEFORE WIDENING IT, because a boundary is exactly the place
    where a careless widening eats real evidence: what follows a complete identifier in a heading
    is a space (123 times) or a comma (9 times). Both stay outside `\\w`, and both are checked
    here so a later narrowing cannot take them away silently.
    """
    g = _erzeuger()
    # Nothing that can CONTINUE a word may end the identifier.
    for text, k in (("## N1\u00e4 a heading\n\nBody.\n", "N1"),
                    ("## N1.foo open\n\nOnly the longer.\n", "N1"),
                    ("## S11 title\n\nBody.\n", "S1")):
        assert g.schneide_beleg(text, k, {k}) is None, (
            f"{k!r} was given evidence from a heading that names another token: {text!r}")

    # AND THE SEPARATORS THE SHIPPED SHEETS ACTUALLY USE still separate.
    for text, k in (("## S22, Nachtrag\n\nBody.\n", "S22"),
                    ("## G1 \u00b7 Titel\n\nBody.\n", "G1")):
        assert g.schneide_beleg(text, k, {k}) is not None, (
            f"a separator the sheets use stopped working: {text!r}")


def test_eine_fehlende_quelle_endet_in_einem_urteil_nicht_in_einem_traceback(tmp_path):
    """Lens 2, target 3. A missing per-entry source raised a raw FileNotFoundError, so the run had
    no NOT MEASURABLE path at all."""
    g = _erzeuger()
    (tmp_path / "RESTRISIKO_PROBE.md").write_text("## K1\n\nSomething.\n", encoding="utf-8")
    ok = tmp_path / "PROBE_OBJEKTKLASSEN.json"
    ok.write_text(json.dumps({"gemessen_an": {"datei": "RESTRISIKO_PROBE.md",
                                              "sha256": "0" * 64, "utc": "2026-09-20T00:00:00Z"},
                              "eintraege": [{"kennung": "K1", "klasse": "x",
                                             "zaehlt_als_fund": True,
                                             "quelle": "GIBT_ES_NICHT.md"}]}),
                  encoding="utf-8")
    g.RESTRISIKO_REL, g.OBJEKTKLASSEN_REL = "RESTRISIKO_PROBE.md", "PROBE_OBJEKTKLASSEN.json"
    with pytest.raises(SystemExit) as e:
        g.baue_v2(tmp_path, "2026-09-20T00:00:00Z")
    # Same class as the case above, swept in the same pass rather than left to break next time the
    # message is touched: the verdict names the unreadable source and the entry that asked for it.
    assert "GIBT_ES_NICHT.md" in str(e.value) and "K1" in str(e.value), e.value


def test_zwei_datensaetze_unter_derselben_kennung_fallen_auf():
    """Lens 2, target 2. The sum check stayed arithmetically true while the register carried two
    contradictory records under one identifier."""
    g = _erzeuger()
    doc = {"records": [{"id": "K1", "kind": None, "kind_state": "NOT MEASURED",
                        "kind_reason": "x", "severity": {"value": None, "state": "NOT MEASURED",
                                                         "reason": "x"},
                        "status": {"value": None, "state": "NOT MEASURED", "reason": "x"},
                        "evidence": []} for _ in range(2)],
           "inventory": {"source_documents": [], "identifiers_total": 2,
                         "identifiers_in_this_register": 2, "identifiers_without_evidence": [],
                         "coverage_gaps": [], "cross_count": {}},
           "assessment_cutoff": "2026-09-20", "generated_at": "2026-09-20T00:00:00Z",
           "signature": {"state": "UNSIGNED", "reason": "x", "consequence_for_the_reader": "x"}}
    fehler = g.pruefe_v2(doc, REPO)
    assert any("dieselbe Kennung" in f for f in fehler), fehler


def test_eine_zwischenueberschrift_verdeckt_die_offene_sektion_nicht():
    """Lens 3, target 2. A deeper heading between the finding and its `## Open` section made a real
    open finding fall to NOT MEASURED, and with it out of the known-issues view."""
    g = _erzeuger()
    text = ("## Open — the outer section\n\n### A detail heading\n\n"
            + ZUSAGE.format("GGG-HHHHHHH-01") + "\n")
    stelle = text.index("Register entry")
    assert g._status_aus_abschnitt(text, len(text[:stelle].encode())) == "open"


def test_ein_absatz_der_eine_FREMDE_kennung_nennt_belegt_nicht_diesen_fund(tmp_path):
    """Lens 1, target 1. The refusal counted promises, not mentions, so a paragraph discussing one
    finding by name while promising an entry for another absorbed the foreign text."""
    g = _erzeuger()
    quelle = tmp_path / "RESTRISIKO_PROBE.md"
    quelle.write_text(
        "Head.\n\nThis is related to FREMD-KENNUNG-01, discussed elsewhere. "
        + ZUSAGE.format("IIII-JJJJJJ-01") + "\n\n## FREMD-KENNUNG-01\n\nIts own section.\n",
        encoding="utf-8")
    ok = tmp_path / "PROBE_OBJEKTKLASSEN.json"
    ok.write_text(json.dumps(
        {"gemessen_an": {"datei": "RESTRISIKO_PROBE.md",
                         "sha256": __import__("hashlib").sha256(quelle.read_bytes()).hexdigest(),
                         "utc": "2026-09-20T00:00:00Z"},
         "eintraege": [{"kennung": "IIII-JJJJJJ-01", "klasse": "x", "zaehlt_als_fund": True},
                       {"kennung": "FREMD-KENNUNG-01", "klasse": "x", "zaehlt_als_fund": True}]}),
        encoding="utf-8")
    g.RESTRISIKO_REL, g.OBJEKTKLASSEN_REL = "RESTRISIKO_PROBE.md", "PROBE_OBJEKTKLASSEN.json"
    doc = g.baue_v2(tmp_path, "2026-09-20T00:00:00Z")
    assert "IIII-JJJJJJ-01" in doc["inventory"]["identifiers_without_evidence"]


def test_KONTROLLE_die_gesunde_zusage_geht_weiter_durch():
    """A guard that refuses everything measures nothing. The ordinary form must still be cut."""
    g = _erzeuger()
    text = "Head.\n\n" + ZUSAGE.format("KKK-LLLLLLL-01") + "\n\nTail.\n"
    t = g.schneide_beleg(text, "KKK-LLLLLLL-01", {"KKK-LLLLLLL-01"})
    assert t is not None and t[2] == "prosa_zusage"
    von, bis, _ = t
    assert text.encode()[von:bis].decode().strip() == ZUSAGE.format("KKK-LLLLLLL-01")


def _probe_baum(tmp_path, eintraege, blatt="## Open — x\n\nRegister entry `N9`, target 6.2.0.\n"):
    """A minimal tree with the two files the producer reads. Returns the repo path."""
    (tmp_path / "RESTRISIKO_PROBE.md").write_text(blatt, encoding="utf-8")
    (tmp_path / "PROBE_OBJEKTKLASSEN.json").write_text(json.dumps({
        "gemessen_an": {"datei": "RESTRISIKO_PROBE.md", "sha256": "0" * 64,
                        "utc": "2026-09-20T00:00:00Z"},
        "eintraege": eintraege}), encoding="utf-8")
    return tmp_path


def test_eine_ABSOLUTE_quelle_im_baum_wird_ABGELEHNT(tmp_path):
    """Ninth review round, thread 4057824359, P2. The NEIGHBOUR of the round-eight P1.

    That P1 asked whether a source lies inside the tree, and the repair answered it by RESOLVING
    the path. Measured at `55811a2`: an entry whose `quelle` is the ABSOLUTE path of an in-tree
    file passes that check, because its resolved target is under the root — and the absolute
    spelling is then published verbatim in `evidence[].source_path` and in
    `inventory.source_documents`. Relocate the clean checkout and the carrier is unverifiable,
    while a stale file at the old absolute location is still the one consulted.

    Containment was checked; portable provenance was not, and provenance is what this artefact is
    for.
    """
    g = _erzeuger()
    repo = _probe_baum(tmp_path, [])
    absolut = str((repo / "RESTRISIKO_PROBE.md").resolve())
    (repo / "PROBE_OBJEKTKLASSEN.json").write_text(json.dumps({
        "gemessen_an": {"datei": "RESTRISIKO_PROBE.md", "sha256": "0" * 64,
                        "utc": "2026-09-20T00:00:00Z"},
        "eintraege": [{"kennung": "N9", "quelle": absolut, "klasse": "x",
                       "zaehlt_als_fund": True}]}), encoding="utf-8")
    g.RESTRISIKO_REL, g.OBJEKTKLASSEN_REL = "RESTRISIKO_PROBE.md", "PROBE_OBJEKTKLASSEN.json"
    with pytest.raises(SystemExit) as e:
        g.baue_v2(repo, "2026-09-20T00:00:00Z")
    assert "absolute" in str(e.value).lower(), (
        f"an absolute in-tree source was not refused as one: {str(e.value)[:180]}")


def test_zwei_schreibweisen_EINER_quelle_sind_EIN_inventareintrag(tmp_path):
    """Ninth review round, the second half of the same class — measured, not anticipated.

    Measured at `55811a2`: with `R.md` on one entry and `./R.md` on another, the two spellings
    became two `_quellen` keys, so `inventory.source_documents` listed the SAME file twice, each
    row claiming one of the two identifiers. The inventory then reports two sources where the tree
    has one, and neither row carries the true count.

    The recorded key is the canonical repository-relative path of the file that was actually
    opened, so a spelling in the data cannot split one source into two.
    """
    g = _erzeuger()
    blatt = "## N1 — open, one\n\nbody one\n\n## N2 — open, two\n\nbody two\n"
    repo = _probe_baum(tmp_path, [
        {"kennung": "N1", "quelle": "RESTRISIKO_PROBE.md", "klasse": "x", "zaehlt_als_fund": True},
        {"kennung": "N2", "quelle": "./RESTRISIKO_PROBE.md", "klasse": "x",
         "zaehlt_als_fund": True}], blatt=blatt)
    g.RESTRISIKO_REL, g.OBJEKTKLASSEN_REL = "RESTRISIKO_PROBE.md", "PROBE_OBJEKTKLASSEN.json"
    doc = g.baue_v2(repo, "2026-09-20T00:00:00Z")
    blaetter = [q for q in doc["inventory"]["source_documents"]
                if q["path"].endswith("RESTRISIKO_PROBE.md")]
    assert len(blaetter) == 1, (
        f"one file, two rows in the inventory: {[q['path'] for q in blaetter]}")
    assert blaetter[0]["identifiers"] == 2, (
        f"the single row does not carry both identifiers: {blaetter[0]}")
    assert all(not pathlib.PurePosixPath(r["evidence"][0]["source_path"]).is_absolute()
               and r["evidence"][0]["source_path"] == "RESTRISIKO_PROBE.md"
               for r in doc["records"]), (
        "a record kept the spelling from the data instead of the canonical key: "
        f"{[r['evidence'][0]['source_path'] for r in doc['records']]}")


def test_ein_deklarierter_WERT_ausserhalb_seiner_domaene_wird_ABGELEHNT():
    """Ninth review round, thread 4057824361, P2. Truthiness is not a domain.

    The round-seven repair made an unknown find FORM a typed refusal and made `_titel` execute all
    seven declared FIELDS — and then trusted every field's VALUE. Measured at `55811a2`:

      ellipsis="mystery"            every derived title stays byte-identical, nothing reports it
      flattenWhitespace="mystery"   the same, and `takeFirstSentence` shares the surface
      keep="mystery"                WORSE: it does not do nothing, it selects the OTHER branch —
                                    a 250 character title was cut to its LAST 200 while the
                                    carrier published `keep: prefix`

    Each value is measured on its own, because a loop over one field would have proven one field.
    """
    g = _erzeuger()
    orig = dict(g.NORMALISIERUNG_JE_FUNDART["prosa_zusage"])
    faelle = [("ellipsis", "mystery"), ("flattenWhitespace", "mystery"),
              ("takeFirstSentence", "mystery"), ("keep", "mystery"), ("cut", "mystery"),
              ("sourceUnit", "something else"), ("maxLength", 0), ("maxLength", "200"),
              ("strip", ["noSuchStep"])]
    try:
        for feld, wert in faelle:
            g.NORMALISIERUNG_JE_FUNDART["prosa_zusage"] = {**orig, feld: wert}
            with pytest.raises(SystemExit) as e:
                g._titel("Register entry `X`, target 6.2.0. A second sentence.", "X",
                         "prosa_zusage")
            assert feld in str(e.value), (
                f"{feld}={wert!r} was refused without naming the field: {str(e.value)[:160]}")
    finally:
        g.NORMALISIERUNG_JE_FUNDART["prosa_zusage"] = orig


def test_eine_REGEL_wird_geprueft_auch_wenn_KEIN_titel_sie_erreicht(tmp_path):
    """Ninth review round. A declaration no title exercises would otherwise ship unchecked.

    `_kuerzen` returns early for a title shorter than `maxLength`, so on a corpus of short titles
    a wrong `keep`, `cut` or `ellipsis` is reachable by no title at all. The rules are therefore
    judged as DECLARATIONS, once, before the first one is applied — and a form that no record of
    this run uses is judged too, because a carrier that publishes a rule for a form it never
    applied publishes a rule for nothing.
    """
    g = _erzeuger()
    orig = dict(g.NORMALISIERUNG_JE_FUNDART["tabelle_spalte1"])
    repo = _probe_baum(tmp_path, [{"kennung": "N9", "quelle": "RESTRISIKO_PROBE.md",
                                   "klasse": "x", "zaehlt_als_fund": True}])
    g.RESTRISIKO_REL, g.OBJEKTKLASSEN_REL = "RESTRISIKO_PROBE.md", "PROBE_OBJEKTKLASSEN.json"
    try:
        gesund = g.baue_v2(repo, "2026-09-20T00:00:00Z")
        fundarten = {r["evidence"][0]["fundart"] for r in gesund["records"]}
        assert "tabelle_spalte1" not in fundarten, (
            "the probe corpus was meant to use no table row; it uses one, so this case would "
            f"prove nothing: {fundarten}")
        assert all(len(r["title"]) < orig["maxLength"] for r in gesund["records"]), (
            "the probe titles reach maxLength, so an early return would not hide the rule")
        g.NORMALISIERUNG_JE_FUNDART["tabelle_spalte1"] = {**orig, "keep": "mystery"}
        with pytest.raises(SystemExit) as e:
            g.baue_v2(repo, "2026-09-20T00:00:00Z")
        assert "tabelle_spalte1" in str(e.value) and "keep" in str(e.value), (
            f"the unused rule was not judged: {str(e.value)[:180]}")
    finally:
        g.NORMALISIERUNG_JE_FUNDART["tabelle_spalte1"] = orig


def test_ein_deklariertes_feld_das_NIEMAND_ausfuehrt_wird_ABGELEHNT():
    """Ninth review round, the other direction of the round-seven finding.

    There the declaration carried seven fields and the producer executed three, so the carrier
    shipped a rule it did not follow. The reverse — a field the declaration carries and nothing
    here reads — has the same shape: it reads like a promise and changes nothing. Both directions
    are closed by naming the admissible set and refusing everything outside it.
    """
    g = _erzeuger()
    orig = dict(g.NORMALISIERUNG_JE_FUNDART["prosa_zusage"])
    try:
        g.NORMALISIERUNG_JE_FUNDART["prosa_zusage"] = {**orig, "wrapAt": 80}
        with pytest.raises(SystemExit) as e:
            g.pruefe_titelregeln()
        assert "wrapAt" in str(e.value), (
            f"an undeclared field was accepted or refused anonymously: {str(e.value)[:160]}")
        # A field that belongs to ANOTHER form is refused where it does not belong — the same
        # question, asked about a field that does exist.
        g.NORMALISIERUNG_JE_FUNDART["prosa_zusage"] = {**orig, "columnFallbackIndex": 1}
        with pytest.raises(SystemExit) as e:
            g.pruefe_titelregeln()
        assert "columnFallbackIndex" in str(e.value), (
            f"a table field on the prose rule was accepted: {str(e.value)[:160]}")
    finally:
        g.NORMALISIERUNG_JE_FUNDART["prosa_zusage"] = orig
