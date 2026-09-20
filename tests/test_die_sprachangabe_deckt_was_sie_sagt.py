"""Die Sprachangabe des Traegers deckt, was sie sagt — Zitate behalten ihre Sprache und stehen dabei.

HERKUNFT, Codex r3999621601. Der Traeger fuehrte `language: en` und trug deutsche Prosa. Wer ein
Dokument nach seiner Sprachangabe auswaehlt oder darstellt, bekam etwas materiell anderes, als die
Angabe sagt.

UEBERSETZEN WAR HIER KEINE OPTION, und das ist der Kern des Fixes. Gemessen stammen 79 Titel und
33 Klassenbegruendungen WORTWOERTLICH aus `RESTRISIKO_600.md`, einer deutschen Quelle, und die
Belegdateien sind byte-gepinnt: `pruefe_v2` rechnet ihren Digest gegen genau diese Bytes. Eine
Uebersetzung waere eine Faelschung der Evidenz. Ein Zitat behaelt seine Sprache; das ist keine
Schwaeche des Dokuments, sondern die Bedingung dafuer, dass es nachrechenbar bleibt.

Deshalb wurde die ANGABE wahr gemacht statt der Inhalt passend. `language` beschreibt die ERZEUGTE
Prosa, und die ist durchgaengig englisch. Was zitiert ist, steht in `language_scope` mit seiner
eigenen Sprache, seiner Quelle und dem Grund.

EINE ZWEITE RUNDE AM EIGENEN ZUSATZ: das Feld `severity.source_reason` kam heute dazu und trug
deutschen Text — derselbe Fund an der Ergaenzung, die eine Runde vorher entstanden war. Was der
Erzeuger selbst schreibt, folgt der Angabe; was er zitiert, steht im Geltungsbereich.

EHRLICHE GRENZE: gemessen wird ueber eine benannte Menge deutscher Funktionswoerter. Ein deutscher
Satz ohne eines davon faellt durch. Das ist eine Untergrenze der Messung, keine Zusicherung.
"""
from __future__ import annotations

import fnmatch
import json
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]

#: EVERY carrier, not the one that existed when this was written.
#:
#: MEASURED 2026-09-20 by a lens: this file opened a hard wired
#: `audit_artifacts/600/findings_register_v2.json`. When a second line (610) arrived the contract
#: did not see it, and it would have caught two findings there at once, a quotation source
#: pointing at the wrong file and a language statement that is wrong for the quoted titles. A
#: gate whose reach hangs on a file path loses it at the next neighbour.
def _traeger_liste() -> list[pathlib.Path]:
    return sorted(REPO.glob("audit_artifacts/*/findings_register_v2.json"))


TRAEGER = REPO / "audit_artifacts" / "600" / "findings_register_v2.json"

#: Deutsche Funktionswoerter. Benannt, damit die Grenze der Messung sichtbar ist.
_DEUTSCH = re.compile(
    r"\b(die|der|das|und|nicht|wird|liegt|keine|eine|ist|werden|steht|waere|kein|fuer|auch)\b")


def _doc(pfad: pathlib.Path | None = None):
    p = pfad or TRAEGER
    if not p.is_file():
        pytest.skip(f"NICHT MESSBAR: {p} fehlt")
    return json.loads(p.read_text(encoding="utf-8"))


def _traeger_param():
    """The carriers as parameters. Empty means NOT MEASURABLE, not passed."""
    liste = _traeger_liste()
    if not liste:
        pytest.skip("NICHT MESSBAR: kein Traeger im Baum")
    return liste


traeger = pytest.mark.parametrize(
    "traegerpfad", _traeger_liste() or [TRAEGER],
    ids=lambda x: pathlib.Path(x).parent.name)


def _alle_strings(doc) -> list[tuple[str, str]]:
    """Jede Zeichenkette des Traegers mit ihrem Pfad. EIN Sammler fuer beide Fragen."""
    raus: list[tuple[str, str]] = []

    def geh(o, pfad=""):
        if isinstance(o, dict):
            for k, v in o.items():
                geh(v, f"{pfad}.{k}")
        elif isinstance(o, list):
            for v in o:
                geh(v, f"{pfad}[]")
        elif isinstance(o, str):
            raus.append((pfad, o))
    geh(doc)
    return raus


def _deutsche_felder(doc) -> dict:
    raus: dict[str, int] = {}
    for pfad, wert in _alle_strings(doc):
        if _DEUTSCH.search(wert):
            raus[pfad] = raus.get(pfad, 0) + 1
    return raus


def _gruppen(doc) -> list:
    """Die Zitatgruppen, je Quelle eine. Die alte Ein-Quellen-Form ist ausdruecklich KEIN Treffer."""
    q = (doc.get("language_scope") or {}).get("quoted_from_source")
    assert isinstance(q, list), (
        f"`quoted_from_source` ist keine Liste von Gruppen ({type(q).__name__}). Die erste Fassung "
        f"nannte EINE Quelle fuer Felder aus ZWEI Dateien — eine Herkunftsangabe, die auf die "
        f"falsche Datei zeigt, ist nicht nachrechenbar.")
    return q


def _quellwerte(repo: pathlib.Path, quelle: str):
    """Die zitierbaren Bytes einer Quelle. JSON wird GEPARST, nicht als Rohtext gelesen.

    WARUM GEPARST: die erste Fassung dieser Messung verglich geparste Zeichenketten gegen den
    ROHTEXT der JSON — jeder Wert mit einem Anfuehrungszeichen darin scheiterte an der
    Maskierung und galt faelschlich als erzeugt. An der Eigenschaft messen, nicht an der
    Schreibweise; das galt hier fuer das Messwerkzeug selbst.
    """
    p = repo / quelle
    if not p.is_file():
        return None
    roh = p.read_text(encoding="utf-8")
    if not quelle.endswith(".json"):
        return roh
    werte: set[str] = set()

    def sammle(x):
        if isinstance(x, str):
            werte.add(x.strip())
        elif isinstance(x, dict):
            for v in x.values():
                sammle(v)
        elif isinstance(x, list):
            for v in x:
                sammle(v)
    sammle(json.loads(roh))
    return werte


def _flach(s: str) -> str:
    """Whitespace collapsed. A line break belongs to the wrapping, not to the quotation."""
    return " ".join(s.split())


def _steht_drin(wert: str, vorrat) -> bool:
    """Is `wert` in the source, even where the source wraps it across lines?

    MEASURED 2026-09-20, the first time this contract pointed at the 610 carrier: all five titles
    of the find form `prosa_zusage` failed. The cause is not a forgery but the wrapping. `_titel`
    pulls the first sentence of a paragraph onto one line and Markdown wraps paragraphs, so the
    title is byte verbatim in no source and word verbatim in exactly one.
    """
    # A SHORTENED TITLE IS A VERBATIM PREFIX, and it says so with its ellipsis. The producer cuts
    # long titles at a word boundary and appends " …"; demanding the whole value in the source
    # would make the shortening itself the finding. Measured at
    # COMMIT-PATTERN-DOMAIN-NOT-AT-VERIFY-BOUNDARY-01, 199 Zeichen, mit Auslassungszeichen.
    kandidaten = {wert.strip(), _flach(wert)}
    ohne = _flach(wert).removesuffix("…").strip()
    if ohne != _flach(wert):
        kandidaten.add(ohne)
    if isinstance(vorrat, set):
        flach = {_flach(x) for x in vorrat}
        return any(k in vorrat or k in flach or any(k in f for f in flach) for k in kandidaten)
    flach = _flach(vorrat)
    return any(k in vorrat or k in flach for k in kandidaten)


def nicht_woertlich(doc, repo: pathlib.Path) -> list[str]:
    """Welche als ZITAT deklarierten Werte stehen NICHT woertlich in ihrer genannten Quelle?"""
    raus = []
    # A VALUE HOLDS WHEN IT IS IN ANY OF THE SOURCES THAT COVER ITS FIELD.
    #
    # The first version demanded it in EVERY named source. That was right while exactly one group
    # existed per field. Since a line cuts from TWO risk sheets, the scope names two sources for
    # `records[].title`, and the old condition would have looked for every title in the other
    # sheet. The EXACT binding per record is checked by
    # `test_jeder_titel_steht_in_der_quelle_SEINES_datensatzes`, where the data carries it, at
    # `evidence[].source_path`.
    vorraete: dict[str, object] = {}
    for g in _gruppen(doc):
        quelle = g.get("source") or ""
        v = _quellwerte(repo, quelle)
        if v is None:
            raus.append(f"{quelle}: die genannte Quelle fehlt")
            continue
        vorraete[quelle] = v
    for pfad, wert in _alle_strings(doc):
        if "language_scope" in pfad or not wert.strip():
            continue
        # ONE PREDICATE PER QUESTION, and the stronger one wins.
        #
        # Codex named this in the same round that found the substring hole: this check and the
        # per-record one went through the SAME helper, so fixing one and leaving the other would
        # have left a second, weaker answer to the same question standing — and a weaker check
        # that can report green still looks like coverage. A title is bound by the derivation of
        # its OWN evidence, which is sharper than containment in a group's source, so it is
        # answered there and the findings are folded back in below.
        if pfad.lstrip(".") == "records[].title":
            continue
        deckend = [g.get("source") or "" for g in _gruppen(doc)
                   if any(fnmatch.fnmatch(pfad.lstrip("."), m) for m in (g.get("fields") or []))]
        if not deckend:
            continue
        if not any(_steht_drin(wert, vorraete[q]) for q in deckend if q in vorraete):
            raus.append(f"{pfad} steht in keiner der genannten Quellen {deckend}: {wert[:70]!r}")
    raus.extend(titel_ohne_ableitung(doc, repo))
    return raus


@traeger
def test_der_traeger_nennt_einen_geltungsbereich(traegerpfad):
    """[ZAEHLT] Eine Angabe ohne Geltungsbereich verschweigt ihre Ausnahme."""
    ls = _doc(traegerpfad).get("language_scope")
    assert ls, "der Traeger fuehrt keinen language_scope"
    assert ls.get("generated_prose"), "die Sprache der erzeugten Prosa ist nicht genannt"
    gruppen = _gruppen(_doc(traegerpfad))
    assert gruppen, "der Geltungsbereich nennt keine einzige Zitatgruppe"
    for g in gruppen:
        for feld in ("language", "source", "fields", "why"):
            assert g.get(feld), f"eine Zitatgruppe nennt {feld!r} nicht: {g}"


@traeger
def test_jedes_deutsche_feld_liegt_im_geltungsbereich(traegerpfad):
    """[ZAEHLT] Der Fund selbst, ueber den ganzen Traeger."""
    doc = _doc(traegerpfad)
    muster = [m for g in _gruppen(doc) for m in (g.get("fields") or [])]
    offen = [p for p in _deutsche_felder(doc)
             if "language_scope" not in p
             and not any(fnmatch.fnmatch(p.lstrip("."), m) for m in muster)]
    assert not offen, (
        f"{len(offen)} Feld(er) tragen deutsche Prosa ausserhalb des deklarierten "
        f"Geltungsbereichs: {sorted(offen)}")


@traeger
def test_die_zitierte_quelle_existiert_und_ist_die_gepinnte(traegerpfad):
    """[ZAEHLT] Ein Geltungsbereich, der auf eine Datei zeigt, die es nicht gibt, deckt nichts."""
    doc = _doc(traegerpfad)
    genannt = {s["path"] for s in doc["inventory"]["source_documents"]}
    for g in _gruppen(doc):
        assert (REPO / g["source"]).is_file(), f"die genannte Quelle fehlt: {g['source']!r}"
        assert g["source"] in genannt, (
            f"die zitierte Quelle {g['source']!r} steht nicht im Inventar — dann ist ihr Digest "
            f"nicht gebunden, und das Zitat nicht nachrechenbar")


@traeger
def test_die_erzeugten_gruende_sind_in_der_deklarierten_sprache(traegerpfad):
    """[ZAEHLT] Was der Erzeuger selbst schreibt, folgt der Angabe."""
    doc = _doc(traegerpfad)
    fehler = []
    for r in doc["records"]:
        for f in ("kind_reason", "class_reason", "last_measured_reason"):
            if r.get(f) and _DEUTSCH.search(r[f]):
                fehler.append(f"{r['id']}.{f}")
        sev = r.get("severity") or {}
        for f in ("reason", "source_reason", "source_state"):
            if sev.get(f) and _DEUTSCH.search(str(sev[f])):
                fehler.append(f"{r['id']}.severity.{f}")
    assert not fehler, f"{len(fehler)} erzeugte Begruendungen tragen deutsche Prosa: {fehler[:6]}"


def test_ANTI_die_zitate_wurden_NICHT_uebersetzt():
    """[ZAEHLT] Measured on the 600 carrier, and that carrier is NAMED here rather than assumed.

    The number 20 speaks about a sheet whose headings are German. The 610 carrier quotes an
    English sheet, where the same bound would demand German text that does not belong there. A
    bound that does not name its object goes astray at the next neighbour.
    """
    """[ZAEHLT] Gegenrichtung, und sie ist die wichtigere.

    Wer die Titel uebersetzte, um die Sprachangabe zu retten, faelschte die Evidenz: die Belege
    sind byte-gepinnt und ihr Digest wird gegen genau diese Bytes gerechnet. Dieser Fall haelt
    fest, dass die Zitate ihre Sprache BEHALTEN.
    """
    doc = _doc(TRAEGER)
    deutsch_in_titeln = sum(1 for r in doc["records"] if _DEUTSCH.search(r.get("title") or ""))
    assert deutsch_in_titeln >= 20, (
        f"nur {deutsch_in_titeln} Titel tragen noch deutsche Prosa — wurden die Zitate uebersetzt? "
        f"Dann stimmen die Belegdigests nicht mehr mit der Quelle ueberein")


def test_die_grenze_der_messung_steht_im_text():
    """[ZAEHLT] Eine Wortliste ist eine Untergrenze, und das gehoert hingeschrieben."""
    q = pathlib.Path(__file__).read_text(encoding="utf-8")
    assert "EHRLICHE GRENZE" in q
    assert "Untergrenze der Messung" in q


# ── DIE DEKLARATION WIRD NACHGERECHNET, NICHT GEGLAUBT ────────────────────────────────────
#
# ZWEITE RUNDE AN DER EIGENEN ARBEIT, selbst gefunden am 13.09.2026. Der Geltungsbereich der
# ersten Fassung fuehrte `inventory.assurance_checks[].prose_rationale_note` als ZITAT — das Feld
# ist aber selbst geschrieben. Damit deckte die Ausnahme etwas, das gar nicht zitiert ist, und
# genau das ist die Klasse, gegen die dieser Traeger gebaut wurde: eine Angabe, die mehr behauptet,
# als sie traegt. Ein Geltungsbereich, den niemand nachrechnet, ist eine zweite Erzaehlung neben
# der ersten.

@traeger
def test_jedes_als_zitat_deklarierte_feld_steht_woertlich_in_seiner_quelle(traegerpfad):
    """[ZAEHLT] Der Fund an der eigenen Ausnahme: deklariert ist nicht dasselbe wie zitiert."""
    offen = nicht_woertlich(_doc(traegerpfad), REPO)
    assert not offen, (
        f"{len(offen)} als Zitat deklarierte Wert(e) stehen nicht woertlich in ihrer genannten "
        f"Quelle — dann ist die Ausnahme eine Behauptung: {offen[:4]}")


def test_FANG_ein_deklariertes_aber_ERZEUGTES_feld_faellt_auf():
    """[ZAEHLT] Gegenrichtung rot: genau die Lage, die in der ersten Fassung gruen war."""
    import copy  # noqa: PLC0415
    doc = copy.deepcopy(_doc(TRAEGER))
    gruppen = _gruppen(doc)
    assert gruppen, "keine Gruppe zu erweitern"
    # Ein Feld, dessen Wert der Erzeuger selbst schreibt, in den Geltungsbereich schmuggeln.
    gruppen[0].setdefault("fields", []).append("inventory.assurance_checks[].prose_rationale_note")
    for a in doc["inventory"]["assurance_checks"]:
        a["prose_rationale_note"] = "die Zusicherung haelt, und dieser Satz steht in keiner Quelle"
    offen = nicht_woertlich(doc, REPO)
    assert any("prose_rationale_note" in x for x in offen), (
        f"ein erzeugtes Feld wurde als Zitat deklariert und faellt NICHT auf: {offen[:3]}")


@traeger
def test_ANTI_der_echte_traeger_bleibt_ohne_befund(traegerpfad):
    """[ZAEHLT] Ein Riegel, der alles meldet, misst nichts."""
    assert nicht_woertlich(_doc(traegerpfad), REPO) == []


#: THE TITLE COLUMNS, by NAME. Kept here rather than imported from the producer: a checker that
#: imports the thing it checks re-runs it instead of measuring it.
_TITELSPALTEN = ("Finding", "In one line", "What it is", "Title")


def _tabellenkopf(text: str, byte_von: int) -> list[str]:
    """The column names of the table a row sits in, searched upwards from the find site."""
    vor = text.encode()[:byte_von].decode("utf-8", errors="ignore")
    for zeile in reversed(vor.splitlines()):
        z = zeile.strip()
        if z.startswith("|") and "Id" in z:
            return [t.strip() for t in z.strip("|").split("|")]
        if z.startswith("#"):
            break
    return []


def _ableiten(stueck: str, kennung: str, fundart: str, kopf: list[str]) -> str:
    """The title the declared rule of THIS find form produces from THESE evidence bytes.

    Written out here from the declared rules rather than imported from `gen_findings_register`.
    HONEST LIMIT, and it is the whole reach of this case: two implementations of the same rule
    catch a title that DETACHED from its evidence, and they catch the two drifting apart. They do
    NOT catch a rule that is wrong in both places — that question is answered by reading the
    declaration, not by running it.
    """
    zeilen = stueck.splitlines()
    erste = zeilen[0] if zeilen else ""
    if fundart == "prosa_zusage":
        flach = " ".join(x.strip() for x in zeilen).strip()
        teile = re.split(r"(?<=[.!?])\s+", flach)
        satz = teile[0] if teile else flach
        if len(satz) <= 200:
            return satz
        gekuerzt = satz[:200].rsplit(" ", 1)[0]
        return (gekuerzt or satz[:200]) + " …"
    if fundart == "tabelle_spalte1":
        spalten = [t.strip() for t in erste.strip().strip("|").split("|")]
        for name in _TITELSPALTEN:
            if kopf and name in kopf:
                i = kopf.index(name)
                if i < len(spalten):
                    return spalten[i][:200]
        return (spalten[1] if len(spalten) > 1 else "")[:200]
    k = re.sub(rf"^#+\s*{re.escape(kennung)}\s*", "", erste).strip()
    return re.sub(r"^[·\-—,:]\s*", "", k)[:200]


def titel_ohne_ableitung(doc, repo: pathlib.Path) -> list[str]:
    """Which titles are NOT what the declared rule makes of their own evidence bytes?

    THE ONE PREDICATE both the real case and the catch proof use. A catch proof that carries its
    own copy proves something about the copy.
    """
    raus: list[str] = []
    roh: dict[str, bytes] = {}
    for r in doc.get("records") or []:
        b = (r.get("evidence") or [{}])[0]
        rel, br, fundart = b.get("source_path"), b.get("byte_range"), b.get("fundart")
        if not rel or not isinstance(br, list) or len(br) != 2 or not fundart:
            raus.append(f"{r.get('id')}: the record names no source, byte range or find form")
            continue
        if rel not in roh:
            p = repo / rel
            if not p.is_file():
                raus.append(f"{r.get('id')}: the named source {rel!r} is missing")
                continue
            roh[rel] = p.read_bytes()
        quelle = roh[rel]
        von, bis = br
        if not (0 <= von < bis <= len(quelle)):
            raus.append(f"{r.get('id')}: the byte range {br} does not lie in {rel}")
            continue
        kopf = (_tabellenkopf(quelle.decode("utf-8", "ignore"), von)
                if fundart == "tabelle_spalte1" else [])
        soll = _ableiten(quelle[von:bis].decode("utf-8", "ignore"), r.get("id") or "", fundart,
                         kopf)
        if soll != (r.get("title") or ""):
            raus.append(f"{r.get('id')} [{fundart}]: the carrier says {str(r.get('title'))[:50]!r}, "
                        f"the rule of its find form makes {soll[:50]!r}")
    return raus


@traeger
def test_jeder_titel_ist_die_ableitung_seiner_eigenen_belegbytes(traegerpfad):
    """[ZAEHLT] The binding, and it replaces a check that measured neighbourhood.

    Found by a review round on 2026-09-20 at commit 191b9d8f. The binding before this one asked
    whether the title is a SUBSTRING of the flattened source, so replacing a title with the two
    words `Register entry` — which stand in the sheet — left both this case and the group check
    green. Substring membership stood in for the declared derivation, and a title could therefore
    detach from the evidence that is supposed to carry it.
    """
    offen = titel_ohne_ableitung(_doc(traegerpfad), REPO)
    assert not offen, (
        f"{len(offen)} title(s) are not what the declared rule makes of their own evidence — "
        f"then the provenance is a claim, not a derivation: {offen[:4]}")


def test_FANG_ein_vom_beleg_abgeloester_titel_faellt_auf():
    """[ZAEHLT] The counter-example of the review round, run against the LIVING predicate."""
    import copy  # noqa: PLC0415
    doc = copy.deepcopy(_doc(TRAEGER))
    assert doc.get("records"), "no record to detach"
    assert titel_ohne_ableitung(doc, REPO) == [], (
        "the unmutated carrier already reports a finding — then the case below proves nothing")
    doc["records"][0]["title"] = "Register entry"
    offen = titel_ohne_ableitung(doc, REPO)
    assert any(doc["records"][0]["id"] in x for x in offen), (
        f"a title replaced by a phrase that merely STANDS in the source is not reported: {offen[:3]}")


@traeger
def test_jede_benutzte_fundart_traegt_eine_deklarierte_regel(traegerpfad):
    """[ZAEHLT] Not one more and not one fewer — both directions, because both mislead.

    A rule for a form that produced nothing here is a rule for nothing; a form that produced
    titles and carries no rule leaves exactly those titles undeclared while the block looks whole.
    """
    doc = _doc(traegerpfad)
    benutzt = {(r.get("evidence") or [{}])[0].get("fundart") for r in doc.get("records") or []}
    benutzt.discard(None)
    erklaert = set((doc.get("language_scope") or {}).get("title_derivation") or {})
    assert benutzt == erklaert, (
        f"the find forms used and the rules declared do not match: used {sorted(benutzt)}, "
        f"declared {sorted(erklaert)}")
    for form, regel in ((doc.get("language_scope") or {}).get("title_derivation") or {}).items():
        assert regel and len(regel) > 40, f"the rule of {form!r} is not a rule: {regel!r}"


@traeger
def test_die_deklarierte_regel_sagt_was_die_daten_zeigen(traegerpfad):
    """[ZAEHLT] The declaration is held against the VALUES, not against its own wording.

    The case that failed to catch the wrong declaration asked whether the sentence contains the
    words `wrap` and `cut`. It did, and it was still wrong for 145 of 150 values. What is
    checkable without believing the prose: a title marked with a trailing ellipsis can only come
    from a form whose rule says it ellipsises, and a title sitting exactly on the length bound
    without one can only come from a form whose rule says the cut is hard.
    """
    doc = _doc(traegerpfad)
    regeln = (doc.get("language_scope") or {}).get("title_derivation") or {}
    fehler = []
    for r in doc.get("records") or []:
        titel = r.get("title") or ""
        form = (r.get("evidence") or [{}])[0].get("fundart")
        regel = (regeln.get(form) or "").lower()
        if titel.endswith("…") and "ellipsis" not in regel:
            fehler.append(f"{r.get('id')}: the title ends in an ellipsis, the rule of {form!r} "
                          f"does not mention one")
        if len(titel) == 200 and not titel.endswith("…") and "hard" not in regel:
            fehler.append(f"{r.get('id')}: the title sits exactly on 200 characters without an "
                          f"ellipsis, the rule of {form!r} does not call the cut hard")
    assert not fehler, f"{len(fehler)} title(s) contradict the rule declared for their form: {fehler[:4]}"


@traeger
def test_eine_gruppe_die_titel_deckt_verweist_auf_die_regeln_je_fundart(traegerpfad):
    """[ZAEHLT] A tolerance that is not declared is a tolerance nobody can check.

    Found by a review round on 2026-09-20. The titles of this carrier are not byte identical to
    any source line. The first answer was to make the CHECKER tolerant, which is the wrong way
    round; the second declared ONE rule for all of them, and that rule was wrong for 145 of 150
    values because the derivation differs per find form. So the group no longer restates a rule —
    it names WHERE the rule of a record stands, and the record carries its find form.
    """
    doc = _doc(traegerpfad)
    ohne = []
    for g in _gruppen(doc):
        if "records[].title" not in (g.get("fields") or []):
            continue
        regel = g.get("normalisation") or ""
        if not regel:
            ohne.append(f"{g.get('source')}: no normalisation named")
        elif not ("title_derivation" in regel and "fundart" in regel):
            ohne.append(f"{g.get('source')}: the sentence does not say where the rule of a record "
                        f"stands: {regel[:70]!r}")
    assert not ohne, (
        "a group covering titles does not point at the rules per find form — then a reader cannot "
        f"tell which of them applies to a record: {ohne}")
