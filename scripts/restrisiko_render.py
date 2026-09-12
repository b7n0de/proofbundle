#!/usr/bin/env python3
"""Validate the findings register and render its outward surfaces — or refuse entirely.

Built to the external review of 2026-09-11 (sha256 59a14a7c), which is binding for the
register form. Its section 6 lists the rules a generator must ENFORCE; each one is a
`pruefung_*` function below and each has a planted-defect case in
`tests/test_restrisiko_render.py`.

Three design decisions that are not obvious, so they are stated rather than inferred:

  Nothing partial is ever published. Validation runs to completion, the surfaces are built
  in memory, and only a fully valid set is written. A half-renewed output set is worse than
  none: it looks current.

  Security and quality never share a status field. `vex_statements` carries native OpenVEX
  for security findings; `quality_assessments` carries OUR documented extension for quality
  ones. A wrong documentation figure does not become a vulnerability by being labelled
  `affected`, and calling our extension a standard would be the same overclaim one level up.

  Three words for three gaps (owner decision 2026-09-11). NOT_MEASURED is a missing
  measurement. NOT_MEASURABLE CLAIMS a limit and must carry its reason — the generator
  refuses one without. NOT_APPLICABLE is outside the scope under test. None is an all-clear.

Offline by construction: no module that opens a socket is imported, and a test asserts it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
EXIT_OK, EXIT_REFUSED, EXIT_IDENTIFIER = 0, 1, 2

PROFIL = "proofbundle.findings_register.v2"
ID_HEADING = re.compile(r"^#{2,4}\s+(?:↳\s*)?\**\s*([A-Z]\d+[a-z]?)\b", re.M)
ID_ROW = re.compile(r"^\|\s*([A-Z]\d+[a-z]?)\s*\|", re.M)
GAP_WORDS = {"NOT_MEASURED", "NOT_MEASURABLE", "NOT_APPLICABLE"}
ROLLEN = {"historical_record", "measurement", "catch_proof", "decision"}
# German technical terms that must not reach a generated English surface. Deliberately
# short and explicit: the review says a language check catches KNOWN violations and cannot
# prove purity, so the reach is named rather than overclaimed.
DEUTSCHE_FACHWOERTER = ("riegel", "fangnachweis", "gemessen", "belegt", "pruefer",
                        "zeugen", "quittung", "nachweis", "abschluss", "vorher", "nachher")


def identifiers_in_prose(text: str) -> set[str]:
    return set(ID_HEADING.findall(text)) | set(ID_ROW.findall(text))


# Areas the identifier check and the language check do NOT judge — each with its ground and the
# decision that granted it. Owner order 20260911T2233Z, decision one, item three, and its
# prohibition: "no silent exception in the identifier check, every exempt path stands with its
# reason in the configuration".
#
# Why this list exists at all, stated because the honest version is less flattering than the
# claim it replaces: two outward texts already SAID the archive was "an explicitly stated exempt
# area, stated with its reason in the generator's configuration". The generator had no such
# configuration. The archive was out of scope by accident of architecture — the checks only ever
# saw the generated text and never walked a tree — which is the definition of a silent exception,
# not the opposite of one. An exemption that nothing consults is decoration; this one is read on
# every run, and every area it actually takes effect on is printed with this reason.
AUSGENOMMENE_BEREICHE = (
    {
        "path": "audit_artifacts/600/restrisiko",
        "reason": "archive of byte-identical excerpts from the published 6.0.0 record. It carries "
                  "the older vocabulary and internal identifiers ON PURPOSE: the owner decision "
                  "binds it byte-for-byte, so judging it could only ever demand a change that the "
                  "same decision forbids. The generated English surface stands beside it and "
                  "points at it; it contains none of its bytes.",
        "decision": "owner order 20260911T2233Z, decision one, item three",
    },
)


def pruefung_ausnahmen(bereiche=AUSGENOMMENE_BEREICHE) -> list[str]:
    """The exemption list judged by the same standard it grants: no area without a ground.

    A configuration entry is only worth more than a sentence in a README if something refuses a
    bad one. An area without a reason, or one whose path could swallow the tree, would turn the
    list from a declaration into a way out.
    """
    f = []
    for b in bereiche:
        pfad = (b.get("path") or "").strip()
        if not pfad:
            f.append("exempt area without a path")
        elif pfad.startswith("/") or ".." in Path(pfad).parts:
            f.append(f"exempt area is absolute or escapes upwards: {pfad!r}")
        elif pfad in (".", ""):
            f.append("exempt area covers the whole tree — that is not an exception, that is an end")
        if not (b.get("reason") or "").strip():
            f.append(f"exempt area {pfad!r} without a reason — the order forbids a silent exception")
        if not (b.get("decision") or "").strip():
            f.append(f"exempt area {pfad!r} names no decision that granted it")
    return f


def ausgenommen_durch(p: Path, wurzel: Path, bereiche=AUSGENOMMENE_BEREICHE) -> dict | None:
    """The declared area covering this path, or None. Compared on resolved paths, not on text.

    A string prefix would let `…/restrisiko_other` inherit the exemption of `…/restrisiko`, and a
    symlink would let anything inherit it. `is_relative_to` on resolved paths asks the question
    that matters: does this file LIE in the area.
    """
    try:
        ziel = p.resolve()
    except OSError:
        return None
    for b in bereiche:
        bereich = (wurzel / b["path"]).resolve()
        if ziel == bereich or ziel.is_relative_to(bereich):
            return b
    return None


# Which files count as a text the checks may judge. Named rather than guessed: a binary read as
# UTF-8 either raises or produces noise, and noise in a checker produces findings about itself.
TEXT_ENDUNGEN = {".md", ".txt", ".json", ".rst", ".html", ".csv", ".yaml", ".yml"}


def sammle_neue_texte(ziele, wurzel: Path,
                      bereiche=AUSGENOMMENE_BEREICHE) -> tuple[list[Path], list[tuple[Path, dict]]]:
    """Split the named new texts into (judged, exempted-with-its-area).

    The second list is the point. A checker that simply skipped the archive would be indistinguish-
    able from one that never looked — and that is exactly the state this replaces.
    """
    geprueft: list[Path] = []
    ausgenommen: list[tuple[Path, dict]] = []
    for ziel in ziele:
        kandidaten = ([ziel] if ziel.is_file()
                      else sorted(q for q in ziel.rglob("*")
                                  if q.is_file() and q.suffix.lower() in TEXT_ENDUNGEN))
        for k in kandidaten:
            b = ausgenommen_durch(k, wurzel, bereiche)
            (ausgenommen.append((k, b)) if b else geprueft.append(k))
    return geprueft, ausgenommen


# An evidence file larger than this is refused rather than read. Named because a bound
# nobody can see is a bound nobody can check.
MAX_BELEG_BYTES = 64 * 1024 * 1024


def sha256_of(p: Path) -> str:
    """Hash in chunks, with a size bound and a regular-file check.

    `read_bytes()` on a FIFO blocks until a writer appears, and on a multi-gigabyte file it
    loads the whole thing into memory — in both cases the validator stops producing a
    verdict, which is worse than producing a wrong one. Both were named by a foreign-family
    lens; neither had occurred.
    """
    st = p.stat()
    if not p.is_file():
        raise ValueError(f"not a regular file: {p}")
    if st.st_size > MAX_BELEG_BYTES:
        raise ValueError(f"evidence larger than {MAX_BELEG_BYTES} bytes: {p} ({st.st_size})")
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _normalise(s: str) -> str:
    """Fold case and strip accents. `Mueller` and `Müller` are one name to a reader."""
    z = unicodedata.normalize("NFKD", s)
    return "".join(c for c in z if not unicodedata.combining(c)).casefold()


# ---------------------------------------------------------------- rules (review, sec. 6)

def pruefung_profil(reg: dict) -> list[str]:
    """Strict profile: unknown status, unknown reason, missing mandatory field → refuse."""
    f = []
    if reg.get("schema") != PROFIL:
        return [f"not a {PROFIL} document: {reg.get('schema')!r}"]
    for k in ("profile_version", "document_id", "register_revision", "publisher",
              "language", "issued", "release_subject", "assessment_cutoff",
              "inventory", "policy_refs", "entries"):
        if k not in reg:
            f.append(f"document: mandatory field missing: {k}")
    if reg.get("language") != "en":
        f.append("document: generated surfaces are English; language must be 'en'")
    if not reg.get("policy_refs"):
        f.append("document: policy_refs must name the rules this register judges by")
    gesehen: dict[str, int] = {}
    # Presence AND type. This function is the gate for every later rule (`if not fehler`),
    # so a wrong type slipping through here does not produce a verdict further down — it
    # produces an AttributeError. A validator that crashes has not judged.
    TYPEN = {"id": str, "record_revision": int, "title": str, "record_role": str,
             "kind": str, "severity": str, "funnel": dict, "remediation": dict,
             "evidence": list}
    for e in reg.get("entries", []):
        if not isinstance(e, dict):
            f.append(f"entries: an entry is {type(e).__name__}, not an object")
            continue
        for k, typ in TYPEN.items():
            if k not in e:
                f.append(f"{e.get('id', '?')}: mandatory field missing: {k}")
            elif not isinstance(e[k], typ) or (typ is int and isinstance(e[k], bool)):
                f.append(f"{e.get('id', '?')}: field {k} is {type(e[k]).__name__}, "
                         f"expected {typ.__name__}")
        for k, typ in (("vex_statements", list), ("quality_assessments", list),
                       ("related_records", list), ("measurement_state", dict)):
            if k in e and not isinstance(e[k], typ):
                f.append(f"{e.get('id', '?')}: field {k} is {type(e[k]).__name__}, "
                         f"expected {typ.__name__}")
        gesehen[e.get("id", "?")] = gesehen.get(e.get("id", "?"), 0) + 1
        if e.get("severity") not in ("P0", "P1", "P2", "P3"):
            f.append(f"{e.get('id')}: severity {e.get('severity')!r} is outside the house rule")
        if e.get("record_role") not in ("finding", "limitation", "assessment_update"):
            f.append(f"{e.get('id')}: record_role {e.get('record_role')!r} unknown")
        ms = e.get("measurement_state")
        if ms:
            if ms.get("state") not in GAP_WORDS:
                f.append(f"{e.get('id')}: measurement_state {ms.get('state')!r} is not one of the three words")
            if ms.get("state") == "NOT_MEASURABLE" and not (ms.get("reason") or "").strip():
                f.append(f"{e.get('id')}: NOT_MEASURABLE without a reason — a claimed limit "
                         "without its ground is a forgotten measurement wearing a verdict")
    for i, n in gesehen.items():
        if n > 1:
            f.append(f"{i}: appears {n} times — duplicate identifier")
    return f


def pruefung_semantik(reg: dict) -> list[str]:
    """Security and quality assessments must not be interchanged."""
    f = []
    for e in reg.get("entries", []):
        i, kind = e.get("id"), e.get("kind")
        vex, qual = e.get("vex_statements") or [], e.get("quality_assessments") or []
        if kind == "security" and qual:
            f.append(f"{i}: a security finding carries quality_assessments")
        if kind == "quality" and vex:
            f.append(f"{i}: a quality finding is exported as an OpenVEX statement — "
                     "a wrong figure does not become a vulnerability by being labelled")
        if kind == "quality" and not qual:
            f.append(f"{i}: quality finding without a quality assessment")
        if kind == "security" and not vex:
            f.append(f"{i}: security finding without a VEX statement")
        VEX_STATUS = {"not_affected", "affected", "fixed", "under_investigation"}
        for s in vex:
            # The whole set, not two special cases. Asking "is it one of the two I check?"
            # binds the FORM; asking "is it a valid status?" binds the property — and an
            # unknown status was silently accepted before a foreign-family lens named it.
            if s.get("status") not in VEX_STATUS:
                f.append(f"{i}: OpenVEX status {s.get('status')!r} is not one of "
                         f"{sorted(VEX_STATUS)}")
            if s.get("justification") and s.get("justification") not in {
                    "component_not_present", "vulnerable_code_not_present",
                    "vulnerable_code_not_in_execute_path",
                    "vulnerable_code_cannot_be_controlled_by_adversary",
                    "inline_mitigations_already_exist"}:
                f.append(f"{i}: OpenVEX justification {s.get('justification')!r} unknown")
            if s.get("status") == "affected" and not (s.get("action_statement") or "").strip():
                f.append(f"{i}: OpenVEX `affected` requires an action_statement")
            if s.get("status") == "not_affected" and not (
                    s.get("justification") or s.get("impact_statement")):
                f.append(f"{i}: OpenVEX `not_affected` requires a justification or impact_statement")
    return f


def pruefung_abhilfe(reg: dict) -> list[str]:
    """`vendor_fix` needs a published correction. A target release is not a fix."""
    f = []
    for e in reg.get("entries", []):
        r = e.get("remediation") or {}
        i = e.get("id")
        if r.get("category") == "vendor_fix" and not (r.get("fix_reference") or "").strip():
            f.append(f"{i}: vendor_fix without fix_reference — a planned fix is not a fix")
        if r.get("category") == "no_fix_planned" and not (r.get("details") or "").strip():
            f.append(f"{i}: no_fix_planned needs an explicit reason, it is not a default")
        if r.get("planning_state") not in ("planned", "deferred", "undecided", None):
            f.append(f"{i}: planning_state {r.get('planning_state')!r} unknown")
        if r.get("category") == "deferred":
            f.append(f"{i}: `deferred` is a planning state, never a remediation category")
        # a fix for a later version must not be reported as fixed for the subject under test
        for qa in e.get("quality_assessments") or []:
            if qa.get("quality_status") == "fixed" and (r.get("target_version") and
                                                        not (r.get("fix_reference") or "")):
                f.append(f"{i}: reported `fixed` while the remediation only names a target version")
    return f


def pruefung_trichter(reg: dict) -> list[str]:
    """`reaches_user: null` is a real value. Unknown must not be turned into false."""
    f = []
    for e in reg.get("entries", []):
        fu = e.get("funnel") or {}
        i = e.get("id")
        if fu.get("reaches_user") not in (True, False, None):
            f.append(f"{i}: reaches_user must be true, false or null")
        if fu.get("verdict") not in ("blocks_release", "does_not_block_release", "unresolved"):
            f.append(f"{i}: funnel verdict {fu.get('verdict')!r} unknown")
        codes = fu.get("reason_codes") or []
        if not codes:
            f.append(f"{i}: funnel without a reason code")
        if "insufficient_evidence" in codes and fu.get("verdict") != "unresolved":
            f.append(f"{i}: insufficient_evidence stays UNRESOLVED — it is not an all-clear")
        if not (fu.get("rationale") or "").strip():
            f.append(f"{i}: funnel without a rationale")
    return f


def pruefung_belege(reg: dict, wurzel: Path) -> list[str]:
    """Evidence must exist, be local, match its digest, and carry an honest role."""
    f = []
    for e in reg.get("entries", []):
        i = e.get("id")
        belege = e.get("evidence") or []
        if not belege:
            f.append(f"{i}: no evidence at all")
            continue
        rollen = set()
        for b in belege:
            p_rel = b.get("path", "")
            rollen.add(b.get("role"))
            if b.get("role") not in ROLLEN:
                f.append(f"{i}: evidence role {b.get('role')!r} unknown")
            if p_rel.startswith("/") or ".." in Path(p_rel).parts:
                f.append(f"{i}: evidence path escapes the evidence root: {p_rel}")
                continue
            p = wurzel / p_rel
            try:
                aufgeloest = p.resolve()
            except OSError as exc:
                f.append(f"{i}: evidence path unresolvable ({type(exc).__name__}): {p_rel}")
                continue
            if not aufgeloest.is_relative_to(wurzel.resolve()):
                f.append(f"{i}: evidence resolves outside the root (symlink?): {p_rel}")
                continue
            if not p.is_file():
                f.append(f"{i}: evidence file missing: {p_rel}")
                continue
            if p.stat().st_size == 0:
                f.append(f"{i}: evidence file is empty: {p_rel}")
                continue
            ist = sha256_of(p)
            if b.get("sha256") != ist:
                f.append(f"{i}: evidence digest differs for {p_rel} "
                         f"(recorded {str(b.get('sha256'))[:12]}…, measured {ist[:12]}…)")
        # a historical report is not a catch-proof the generator ran
        if rollen == {"historical_record"}:
            f.append(f"{i}: only historical_record evidence — a historical report is not a "
                     "catch-proof and cannot stand alone as measurement")
    return f


def pruefung_inventar(reg: dict, wurzel: Path) -> list[str]:
    """Coverage is bounded to a NAMED source state, and a gap may not be waved away."""
    f = []
    inv = reg.get("inventory") or {}
    if not inv.get("sources"):
        return ["inventory: no sources named — completeness would be unbounded"]
    for s in inv["sources"]:
        pfad = s.get("path", "")
        # sources may name a tree state (`file@ref`) that is not a local file
        lokal = wurzel / pfad.split("@")[0]
        if "@" not in pfad and lokal.is_file():
            ist = sha256_of(lokal)
            if s.get("sha256") != ist:
                f.append(f"inventory: source digest differs for {pfad}")
    reihen = inv.get("series_counts") or {}
    if reihen and sum(reihen.values()) != inv.get("source_identifiers_total"):
        f.append(f"inventory: series counts sum to {sum(reihen.values())} but total says "
                 f"{inv.get('source_identifiers_total')}")
    # A count without a named source is a number about an unknown file. The sum rule above cannot
    # substitute for this: it compares two declared numbers with each other, so it holds for any
    # pair that adds up and says nothing about the tree either of them came from. Measured on this
    # register: the counts describe the tag state, the coverage run reads the branch state, and
    # both were right about different files.
    if reihen:
        quelle = (inv.get("series_counts_source") or "").strip()
        pfade = {q.get("path") for q in (inv.get("sources") or [])}
        if not quelle:
            f.append("inventory: series_counts without series_counts_source — a count belongs to "
                     "the tree it was taken in, and this one names none")
        elif quelle not in pfade:
            f.append(f"inventory: series_counts_source {quelle!r} is not one of the declared "
                     f"sources {sorted(x for x in pfade if x)}")
    for g in inv.get("coverage_gaps") or []:
        if g.get("state") not in GAP_WORDS:
            f.append(f"inventory: gap state {g.get('state')!r} is not one of the three words")
        if len((g.get("note") or "")) < 20:
            f.append(f"inventory: gap {g.get('identifiers')!r} claims a state without a reason")
        if g.get("state") == "NOT_APPLICABLE" and "sha256" not in str(g.get("note", "")).lower() \
                and not any(q.get("path") for q in inv["sources"]):
            f.append(f"inventory: gap {g.get('identifiers')!r} declared resolved without naming "
                     "the source that resolves it")
    return f


def pruefung_beziehungen(reg: dict) -> list[str]:
    """Relations must point somewhere, and never at themselves."""
    f = []
    ids = {e.get("id") for e in reg.get("entries", [])}
    for e in reg.get("entries", []):
        i = e.get("id")
        if e.get("record_revision", 0) < 1:
            f.append(f"{i}: record_revision must start at 1")
        for r in e.get("related_records") or []:
            ziel = r.get("target")
            if ziel == i:
                f.append(f"{i}: relates to itself — a cycle, not a relation")
            elif ziel not in ids and not (r.get("target_sha256") or r.get("target_revision")):
                f.append(f"{i}: relation target {ziel!r} is neither in this register nor "
                         "pinned by revision or digest")

    # Cycles of ANY length, not only self-loops.
    #
    # The first version checked `ziel == i` and called that the cycle rule. A
    # foreign-family lens named the gap with one input: A -> B -> A passes both conditions
    # and walks straight through. A cycle of length 2 is a cycle, not a special case, and
    # "a cycle of length 1" is the FORM of the rule where "the graph has a cycle" is its
    # property. So: a real walk over the whole graph.
    kanten: dict[str, list[str]] = {}
    for e in reg.get("entries", []):
        kanten[e.get("id")] = [r.get("target") for r in (e.get("related_records") or [])
                               if r.get("target") in ids]
    WEISS, GRAU, SCHWARZ = 0, 1, 2
    farbe = {k: WEISS for k in kanten}

    def wandere(knoten: str, pfad: list[str]) -> None:
        farbe[knoten] = GRAU
        for nachbar in kanten.get(knoten, []):
            if farbe.get(nachbar) == GRAU:          # back edge: the cycle closes here
                ring = pfad[pfad.index(nachbar):] + [nachbar] if nachbar in pfad else \
                       [nachbar, knoten, nachbar]
                f.append(f"relation cycle: {' -> '.join(ring)}")
            elif farbe.get(nachbar) == WEISS:
                wandere(nachbar, pfad + [nachbar])
        farbe[knoten] = SCHWARZ

    for k in list(kanten):
        if farbe[k] == WEISS:
            wandere(k, [k])
    return f


def pruefung_sprache(text: str) -> list[str]:
    """Known German technical terms on a generated English surface. Reach is limited."""
    flach = _normalise(text)
    return [f"German technical term on an English surface: {w!r}"
            for w in DEUTSCHE_FACHWOERTER if re.search(rf"\b{w}\b", flach)]


def pruefung_deckung(reg: dict, prosa_dateien: list[Path]) -> list[str]:
    """No identifier may live only in the prose — including subordinate ones.

    And: the prose actually read must be a source state the inventory NAMES. Measured 12.09.2026
    on this very register, which is why the rule exists rather than being imagined. The inventory
    declares three sources; two of them are the same file name at two states:

        RESTRISIKO_600.md@v6.0.0            R7 S107 N21 A4 + 4 subordinate = 143 identifiers
        RESTRISIKO_600.md@arbeit/601-nachzug R7 S104 N21 A4 + 4 subordinate = 140

    `series_counts` totals 139 main identifiers — the TAG state. The coverage run reads the file
    in the working tree, which is the BRANCH state. Both numbers are right; they belong to
    different trees, and nothing said which one was being counted. `pruefung_inventar` cannot
    catch this: it skips every `@`-pinned source, so the digests it does not check are exactly the
    ones that distinguish the two states, and its own rule compares the series sum against the
    declared total — arithmetic that is true of any pair of numbers that add up.

    So the file that is actually read is hashed and matched against the declared sources. An
    unnamed state is refused, with both digests printed: a coverage figure measured against a tree
    nobody named is a figure about an unknown file.
    """
    traeger = {e.get("id") for e in reg.get("entries", [])}
    unter = set()
    for liste in (reg.get("inventory", {}).get("subordinate_identifiers") or {}).values():
        unter.update(liste)
    bekannt = {q.get("sha256"): q.get("path") for q in (reg.get("inventory", {}).get("sources") or [])}
    f = []
    for d in prosa_dateien:
        if not d.is_file():
            f.append(f"prose file named for coverage does not exist: {d}")
            continue
        ist = sha256_of(d)
        if bekannt and ist not in bekannt:
            f.append(f"{d.name}: coverage was measured against a source state the inventory does "
                     f"not name (measured {ist[:12]}…; declared: "
                     f"{', '.join(f'{v} {str(k)[:12]}…' for k, v in bekannt.items())})")
        nur = identifiers_in_prose(d.read_text(encoding="utf-8")) - traeger - unter
        f += [f"{d.name}: {x} appears in the prose with no carrier entry" for x in sorted(nur)]
    return f


def check_identifiers(text: str, list_path: Path | None) -> tuple[list[str], str]:
    """The word list is read from OUTSIDE the repository — a list inside it is refused."""
    if list_path is None:
        return [], "NOT_MEASURED — no identifier list given"
    aufgeloest = list_path.resolve()
    if aufgeloest.is_relative_to(REPO):
        raise SystemExit(
            f"the identifier list lies INSIDE the repository ({aufgeloest}).\n"
            "Refusing: a list of names that must not ship cannot itself ship.")
    if not aufgeloest.is_file():
        return [], f"NOT_MEASURED — list not found at {aufgeloest}"
    worte = [z.strip() for z in aufgeloest.read_text(encoding="utf-8").splitlines()
             if z.strip() and not z.lstrip().startswith("#")]
    flach = _normalise(text)
    treffer = []
    for w in worte:
        n = _normalise(w)
        if len(n) > 2 and n in flach:
            zeile = flach[:flach.index(n)].count("\n") + 1
            treffer.append(f"an entry of the list (length {len(w)}) occurs "
                           f"{flach.count(n)}x, first at line {zeile}")
    return treffer, f"checked against {len(worte)} entries"


# ---------------------------------------------------------------------------- rendering

def render_uebersicht(reg: dict) -> str:
    """The first page: a reading task, not a line count. Target under 600 words."""
    e = reg["entries"]
    offen = [x for x in e if any(q.get("quality_status") == "open"
                                 for q in x.get("quality_assessments") or [])
             or any(v.get("status") == "affected" for v in x.get("vex_statements") or [])]
    ungeklaert = [x for x in e if (x.get("funnel") or {}).get("verdict") == "unresolved"]
    blockend = [x for x in e if (x.get("funnel") or {}).get("verdict") == "blocks_release"]
    inv = reg["inventory"]
    z = [f"# Known issues — {reg['release_subject']['product']} "
         f"{reg['release_subject']['version']}", "",
         f"**Assessment cutoff {reg['assessment_cutoff']} · register revision "
         f"{reg['register_revision']} · profile {reg['profile_version']}**", "",
         "GENERATED from the signed register. Do not edit.", "",
         "## What this covers, and what it does not", "",
         f"The source record carries **{inv['source_identifiers_total']} main identifiers**; this "
         f"register holds **{len(e)}** of them as structured entries. That is the honest coverage "
         "figure, not a claim about the tree — and the count below speaks only about findings "
         "already made, at the cutoff above.", ""]
    if inv.get("coverage_gaps"):
        z += ["Known coverage gaps, stated rather than closed:", ""]
        for g in inv["coverage_gaps"]:
            z.append(f"* **{g['identifiers']}** — `{g['state']}`. {g['note']}")
        z.append("")
    z += ["## What needs a decision", "",
          f"**{len(blockend)} blocking · {len(offen)} open · {len(ungeklaert)} unresolved.**", ""]
    if blockend or ungeklaert:
        for x in blockend + ungeklaert:
            z.append(f"* **{x['id']}** ({x['severity']}) — {x['title']}")
    else:
        z.append("Nothing here blocks the release. Every open entry is an accepted, named risk "
                 "with a target; none of them changes a verification verdict.")
    z += ["", "## Every entry, in one line each", "",
          "| Id | Sev | Role | Status | Reaches user | Remediation | Title |",
          "|---|---|---|---|---|---|---|"]
    for x in e:
        st = ((x.get("quality_assessments") or [{}])[0].get("quality_status")
              or (x.get("vex_statements") or [{}])[0].get("status") or "—")
        ru = {True: "yes", False: "no", None: "unknown"}[(x.get("funnel") or {}).get("reaches_user")]
        r = x["remediation"]
        z.append(f"| {x['id']} | {x['severity']} | {x['record_role']} | {st} | {ru} | "
                 f"{r['category']}/{r.get('planning_state') or '—'} | {x['title']} |")
    z += ["", "The full assessment of each entry, with its evidence paths and digests, is in "
          "`audit_artifacts/findings_register_610.json`. That file is the source; this page is "
          "a rendering of it.", ""]
    return "\n".join(z)


def render_voll(reg: dict) -> str:
    z = [f"# Residual risk, {reg['release_subject']['product']} "
         f"{reg['release_subject']['version']} — full register", "",
         "GENERATED from the signed register. Do not edit.", "",
         "> Judged by: " + ", ".join(
             f"{r['name']} {r['version']} (`{r['sha256'][:12]}…`)" for r in reg["policy_refs"]),
         ""]
    for e in reg["entries"]:
        fu, r = e["funnel"], e["remediation"]
        z += [f"## {e['id']} — {e['title']}", "",
              f"**Role** {e['record_role']} · **Kind** {e['kind']} · **Severity** {e['severity']}"
              + ("  (historical grade, not re-assessed)" if e.get("severity_is_historical") else ""),
              f"**Origin** {e.get('origin') or 'NOT_MEASURED'}",
              f"**Class** `{e.get('class_id') or 'NOT_MEASURED'}`", ""]
        for q in e.get("quality_assessments") or []:
            z += [f"**Quality assessment** `{q['quality_status']}` / `{q['reason_code']}` "
                  f"— about: {q['subject']}", "", q["rationale"], ""]
        for v in e.get("vex_statements") or []:
            z += [f"**Security assessment (OpenVEX)** `{v['status']}`"
                  + (f" / `{v['justification']}`" if v.get("justification") else ""), "",
                  v.get("action_statement") or v.get("impact_statement") or "", ""]
        ru = {True: "yes", False: "no", None: "unknown"}[fu["reaches_user"]]
        z += [f"**Funnel** reaches user: {ru} · verdict: `{fu['verdict']}` · "
              f"{', '.join(f'`{c}`' for c in fu['reason_codes'])}", "", fu["rationale"], "",
              f"**Remediation** `{r['category']}` / `{r.get('planning_state') or 'none'}`"
              + (f" · target {r['target_version']}" if r.get("target_version") else "")
              + (f" · fix: {r['fix_reference']}" if r.get("fix_reference") else ""), ""]
        if r.get("details"):
            z += [r["details"], ""]
        if e.get("measurement_state"):
            m = e["measurement_state"]
            z += [f"**Measurement** `{m['state']}`"
                  + (f" — {m['reason']}" if m.get("reason") else ""), ""]
        z += ["**Evidence**", ""]
        for b in e["evidence"]:
            z.append(f"* `{b['path']}` — {b['role']}, sha256 `{b['sha256'][:16]}…`")
        z += ["", f"*first seen {e.get('first_seen') or 'NOT_MEASURED'} · "
              f"last measured {e.get('last_measured') or 'NOT_MEASURED'} · "
              f"revision {e['record_revision']}*", ""]
    return "\n".join(z)


def render_openvex(reg: dict) -> dict:
    """ONE document with several statements per release edition — not one per finding.

    A projection, never a second source: it carries no signature of its own and points at
    the register's stable document id and revision.
    """
    statements = []
    for e in reg["entries"]:
        for v in e.get("vex_statements") or []:
            statements.append({**v, "_register_entry": e["id"]})
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"{reg['document_id']}/openvex",
        "author": reg["publisher"],
        "timestamp": reg["issued"],
        "version": reg["register_revision"],
        "statements": statements,
        "_projection_of": {"document_id": reg["document_id"],
                           "register_revision": reg["register_revision"]},
    }


# --------------------------------------------------------------------------------- main

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--register", type=Path, required=True)
    p.add_argument("--out-summary", type=Path)
    p.add_argument("--out-full", type=Path)
    p.add_argument("--out-openvex", type=Path)
    p.add_argument("--evidence-root", type=Path, default=REPO)
    p.add_argument("--identifier-list", type=Path)
    p.add_argument("--also-cover", type=Path, nargs="*", default=[])
    p.add_argument("--also-check", type=Path, nargs="*", default=[],
                   help="new texts the identifier and language checks judge as well (files or "
                        "directories). Declared exempt areas are skipped AND named with their "
                        "reason — owner order 20260911T2233Z, decision one, item three")
    p.add_argument("--check-only", action="store_true")
    p.add_argument("--refresh-evidence-digests", action="store_true",
                   help="re-measure evidence digests and rewrite the register. DELIBERATELY a "
                        "separate, explicit act: a generator that silently refreshes digests "
                        "turns the binding into decoration — it would always agree with itself")
    a = p.parse_args(argv)

    try:
        reg = json.loads(a.register.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"REFUSED — register is not valid JSON: {exc}", file=sys.stderr)
        return EXIT_REFUSED

    if a.refresh_evidence_digests:
        geaendert = []
        for e in reg.get("entries", []):
            for b in e.get("evidence", []):
                datei = a.evidence_root / b.get("path", "")
                if not datei.is_file():
                    print(f"  {e.get('id')}: cannot refresh, file missing: {b.get('path')}",
                          file=sys.stderr)
                    continue
                ist = sha256_of(datei)
                if b.get("sha256") != ist:
                    geaendert.append(f"{e.get('id')} {b['path']}: "
                                     f"{str(b.get('sha256'))[:12]}… -> {ist[:12]}…")
                    b["sha256"] = ist
        a.register.write_text(json.dumps(reg, indent=2, ensure_ascii=False) + "\n",
                              encoding="utf-8")
        if geaendert:
            print(f"refreshed {len(geaendert)} evidence digest(s) — each one means the evidence "
                  f"CHANGED, and that is a fact about the evidence, not about this tool:")
            for g in geaendert:
                print(f"  {g}")
        else:
            print("no evidence digest changed")
        return EXIT_OK

    fehler: list[str] = []
    # The exemption list is judged BEFORE it exempts anything. An area without a ground would
    # otherwise be a way out that only the next reader discovers.
    fehler += pruefung_ausnahmen()
    fehler += pruefung_profil(reg)
    if not fehler:                       # later rules assume the shape holds
        fehler += pruefung_semantik(reg)
        fehler += pruefung_abhilfe(reg)
        fehler += pruefung_trichter(reg)
        fehler += pruefung_belege(reg, a.evidence_root)
        fehler += pruefung_inventar(reg, a.evidence_root)
        fehler += pruefung_beziehungen(reg)
        fehler += pruefung_deckung(reg, list(a.also_cover))
    if fehler:
        print(f"REFUSED — {len(fehler)} rule violation(s), nothing was written:", file=sys.stderr)
        for f in fehler:
            print(f"  {f}", file=sys.stderr)
        return EXIT_REFUSED

    # build everything in memory; publish only a complete, valid set
    flaechen: list[tuple[Path, str]] = []
    if a.out_summary:
        flaechen.append((a.out_summary, render_uebersicht(reg)))
    if a.out_full:
        flaechen.append((a.out_full, render_voll(reg)))
    openvex_text = None
    if a.out_openvex:
        openvex_text = json.dumps(render_openvex(reg), indent=2) + "\n"

    sprachfehler = []
    for _, text in flaechen:
        sprachfehler += pruefung_sprache(text)
    if sprachfehler:
        print("REFUSED — generated English surface carries German terms:", file=sys.stderr)
        for s in sorted(set(sprachfehler)):
            print(f"  {s}", file=sys.stderr)
        return EXIT_REFUSED

    # New texts, judged by the same two checks as the generated surfaces — and the archive is
    # skipped by the DECLARED area, out loud. Owner order 20260911T2233Z, decision one, item three:
    # "they know the archive path as an exempt area, explicitly and with a ground, not as a silent
    # exception." Printing it is what makes the difference between the two.
    neue_texte, uebergangen = sammle_neue_texte(list(a.also_check), a.evidence_root)
    for datei, bereich in uebergangen:
        print(f"EXEMPT AREA — not judged: {datei}\n"
              f"    area:   {bereich['path']}\n"
              f"    ground: {bereich['reason']}\n"
              f"    by:     {bereich['decision']}")
    neuer_text = ""
    for datei in neue_texte:
        try:
            inhalt = datei.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            print(f"REFUSED — named for checking but unreadable as text: {datei} "
                  f"({type(exc).__name__})", file=sys.stderr)
            return EXIT_REFUSED
        neu_sprache = pruefung_sprache(inhalt)
        if neu_sprache:
            print(f"REFUSED — {datei} carries terms an outward text must not:", file=sys.stderr)
            for sf in sorted(set(neu_sprache)):
                print(f"  {sf}", file=sys.stderr)
            return EXIT_REFUSED
        neuer_text += "\n" + inhalt
    if neue_texte:
        print(f"checked {len(neue_texte)} new text(s); {len(uebergangen)} file(s) in a declared "
              f"exempt area")

    zusammen = "\n".join(t for _, t in flaechen) + (openvex_text or "") + neuer_text
    treffer, lage = check_identifiers(zusammen, a.identifier_list)
    if treffer:
        print(f"IDENTIFIER CHECK FAILED ({lage}) — nothing was written:", file=sys.stderr)
        for t in treffer:
            print(f"  {t}", file=sys.stderr)
        print("The words themselves are not printed; look at the named lines.", file=sys.stderr)
        return EXIT_IDENTIFIER

    if a.check_only:
        print(f"OK — {len(reg['entries'])} entries pass every rule. "
              f"Identifier check: {lage}. Nothing written (--check-only).")
        return EXIT_OK
    for ziel, text in flaechen:
        ziel.write_text(text, encoding="utf-8")
        print(f"wrote {ziel} ({len(text.split())} words)")
    if openvex_text is not None:
        a.out_openvex.write_text(openvex_text, encoding="utf-8")
        n = len(render_openvex(reg)["statements"])
        print(f"wrote {a.out_openvex} — ONE document, {n} statement(s), a projection not a source")
    print(f"identifier check: {lage}")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
