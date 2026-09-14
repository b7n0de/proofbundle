#!/usr/bin/env python3
"""Ceremony: build the structured findings register — and let SOMEBODY ELSE sign it.

WHAT THIS FILE IS FOR. The register is the SINGLE STRUCTURED SOURCE for "how many open P0/P1"
(RT-10 / PB-2026-0718-14). It replaced a lexical "0 open P0/P1" substring scan of a stale .md that
granted a FALSE PASS in ``audit_candidate_matrix`` C12.2 while current open P0/P1 existed. It
carries, per finding, STRUCTURED fields (id, severity, status, superseded_by) plus an ed25519
signature over the canonical (RFC-8785 / JCS) bytes of the register WITHOUT its signature block.

NO PRIVATE KEY IS READ OR CREATED IN THIS FILE (Teil F, 2026-09-06). This is the same fix that
``scripts/sign_readiness_artifact.py`` received under Auflage C9, applied to the neighbour that
still carried the defect — closing a class at one surface while its twin keeps it is how a
capability moves one file over instead of going away.

  Until 2026-09-06 this script called ``_load_or_create_key()``: it read
  ``audit_artifacts/.findings_register_key.ed25519`` or, if that file was absent, GENERATED a fresh
  private key and wrote it to disk — and then signed, in the same process that had just built the
  body. That is self-certification: a signature means "an independent party attests this" only when
  the party holding the key is not the party that shaped what gets signed. It had a second, quieter
  failure mode: run from a tree without the key file, it silently minted a NEW key, so the register
  was validly signed and rejected by the trust anchor, and the message said nothing about why.

  The owner's signing policy (card OA-e10ba2ba39, 2026-09-06) is explicit: the anchor key signs
  "the three readiness artefacts AND THE REGISTER BODY … the private half stays with the owner on
  the Mac, nothing of it on the farmer". So the build host emits, the owner signs, the build host
  assembles — and ``scripts/findings_register.py`` verifies against the ANCHOR, not against a
  second pin of its own.

TWO MODES, the same signed body in both:

  emit      --emit-payload P --context-out C: write the canonical bytes to P and the body to C.
            The key holder signs P out of band; the build host then assembles.
  assemble  --assemble --context-in C --sig-file S --signer-pubkey B --out A: wrap body +
            signature. Self-checks the signature and REFUSES on a mismatch, so a bad pair never
            reaches disk.

Usage:
  python scripts/gen_findings_register.py --emit-payload /tmp/reg.bin --context-out /tmp/reg.json
  # ... the owner signs /tmp/reg.bin on the Mac, producing sig.b64 ...
  python scripts/gen_findings_register.py --assemble --context-in /tmp/reg.json \\
      --sig-file sig.b64 --signer-pubkey <base64 pubkey> --out audit_artifacts/findings_register_361.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from proofbundle import canonical  # noqa: E402

REGISTER_REL = "audit_artifacts/findings_register_361.json"

# ── REGISTERFORM 6.1 (v2), Owner-Entscheid OA-714de2fcdd vom 2026-09-12 ────────────────────
#
# "1A, zusammen mit 3C als Grundlage … die v2-Form wird auf scripts/gen_findings_register.py
#  gebaut und nicht daneben, die vorhandene Mechanik bleibt … Ausdrueckliches Verbot, kein
#  zweiter Erzeuger, zwei Werkzeuge fuer dieselbe Frage driften."
#
# Deshalb steht die v2-Form HIER und nicht in einer neuen Datei. Die v1-Mechanik darunter
# bleibt unberuehrt: derselbe emit/assemble-Weg, dieselbe JCS-Kanonisierung, derselbe
# Grundsatz, dass der private Schluessel am Mac bleibt.

RESTRISIKO_REL = "RESTRISIKO_600.md"
OBJEKTKLASSEN_REL = "RESTRISIKO_600_OBJEKTKLASSEN.json"
EVIDENZ_REL = "audit_artifacts/600/register_evidence"
V2_REL = "audit_artifacts/600/findings_register_v2.json"
ANSICHTEN_REL = "audit_artifacts/600/views"

LUECKENWOERTER = {"NOT MEASURED", "NOT MEASURABLE", "NOT APPLICABLE"}
VEX_STATUS = {"affected", "not_affected", "fixed", "under_investigation"}
QUAL_STATUS = {"open", "fixed", "not_a_defect", "under_investigation"}
ABHILFE = {"none_available", "vendor_fix", "workaround", "no_fix_planned"}
PLANUNG = {"planned", "deferred", "undecided", None}
BELEGROLLE = {"historical_record", "measurement", "catch_proof", "decision"}

_KENNUNG_KOPF = None  # lazy, siehe _kopf_muster()


def _kopf_muster():
    global _KENNUNG_KOPF
    if _KENNUNG_KOPF is None:
        import re  # noqa: PLC0415
        _KENNUNG_KOPF = re.compile(r"^(#{2,4}) ([A-Z]\d+)(?![0-9A-Za-z])", re.M)
    return _KENNUNG_KOPF


def schneide_beleg(text: str, kennung: str):
    """Der byte-genaue Bereich der Fundstelle EINER Kennung. -> (von, bis, fundart) | None.

    DREI FASSUNGEN, und die ersten beiden waren falsch — beide nur durch Messen gefunden:

      1. Die erste nahm die ERSTE gefundene Ueberschriftenebene. Fuer S102 traf sie den
         Sammelkopf "## S102 bis S114" und schnitt 24160 B mit DREIZEHN Kennungen darin.
         Ein Beleg, der dreizehn Funde enthaelt, belegt keinen.
      2. Die zweite nahm die engste Ebene, endete aber erst an der naechsten Ueberschrift
         GLEICHER oder hoeherer Ebene — und schnitt damit den Nachtrag einer FREMDEN
         Kennung mit: "### S22, Nachtrag" liegt innerhalb von "## S24", "### Z2" in
         "## S58". Vier Belege trugen so einen fremden Fund. Gemessen ueber alle 142.
      3. Diese endet an der naechsten Ueberschrift, die eine ANDERE Kennung eroeffnet,
         auch wenn die tiefer liegt. Ergebnis ueber alle 142: null Ueberlappungen,
         Median 1627 B, groesster Schnitt 7750 B.

    Zwei Fundarten, wie RESTRISIKO_600_OBJEKTKLASSEN.json sie deklariert: Ueberschrift
    (S/R/G/Z) und Tabellenzeile mit der Kennung in Spalte 1 (N/A).
    """
    import re  # noqa: PLC0415
    # VIERTE FASSUNG, Fund der Fremdfamilie (Codex r3999820860, 13.09.2026). Die dritte suchte von
    # der TIEFSTEN Ebene aufwaerts (4, 3, 2) und nahm damit bei neun Kennungen einen spaeteren
    # `### <K>, Nachtrag` statt der HAUPTSTELLE `## <K>`. Gemessen an der erzeugten Belegdatei:
    # `audit_artifacts/600/register_evidence/S35.md`, 3755 B und committet, trug AUSSCHLIESSLICH
    # den ersten Nachtrag; die Hauptstelle fehlte vollstaendig, der zweite Nachtrag ebenso.
    #
    # Der Selbsttest der Funktion mass "keine Ueberlappung", nie "richtiger Abschnitt" — deshalb
    # rutschte der Fehler durch zwei vorherige Haertungen hindurch. Eine Eigenschaft, die niemand
    # prueft, haelt nur zufaellig.
    #
    # GESUCHT WIRD JETZT VON DER FLACHSTEN EBENE ABWAERTS, weil die Hauptstelle die flachste ist.
    # AUSNAHME, und sie ist GEMESSEN statt vermutet: eine Ueberschrift, die eine SPANNE eroeffnet
    # (`## S102 bis S114`), gehoert mehreren Kennungen und darf nicht der Beleg EINER sein — dort
    # ist die tiefere Ebene die richtige, und das ist die dokumentierte Absicht der zweiten
    # Fassung. Ueber alle 132 Ueberschriften des Bestands gemessen: NEUN Kennungen haben mehrere
    # Ueberschriften, GENAU EINE davon eroeffnet eine Spanne.
    #
    # Die Spannenform ist eng gefasst, `bis`/`to` plus Kennung. Eine erste, weitere Fassung nahm
    # auch einen Gedankenstrich vor einer Kennung und hielt damit S21, S24, S49 und Z5
    # faelschlich fuer Sammelkoepfe — dort steht nach dem Strich nur der erste Satz.
    for ebene in (2, 3, 4):
        m = re.search(rf"^({'#' * ebene}) {re.escape(kennung)}(?![0-9A-Za-z])", text, re.M)
        if not m:
            continue
        zeilenende = text.find("\n", m.end())
        rest = text[m.end():zeilenende if zeilenende != -1 else len(text)]
        if re.match(r"^\s*(?:bis|to)\s+[A-Z]\d+\b", rest):
            continue                      # Sammelkopf einer Spanne, die tiefere Ebene gilt
        ende = len(text)
        for n in _kopf_muster().finditer(text, m.end()):
            if len(n.group(1)) <= ebene or n.group(2) != kennung:
                ende = n.start()
                break
        tiefer = re.search(rf"^#{{2,{ebene}}} ", text[m.end():], re.M)
        if tiefer:
            ende = min(ende, m.end() + tiefer.start())
        return (len(text[:m.start()].encode()), len(text[:ende].encode()), "ueberschrift")
    m = re.search(rf"^\|\s*{re.escape(kennung)}\s*\|", text, re.M)
    if m:
        ze = text.find("\n", m.start())
        ze = len(text) if ze == -1 else ze
        return (len(text[:m.start()].encode()), len(text[:ze].encode()), "tabelle_spalte1")
    return None


#: Die Fassung, ueber die dieses Register spricht. Sie MUSS der ausliefernden Identitaet
#: entsprechen — `findings_register._version_binding_error` weist alles andere fail-closed ab, und
#: genau daran fiel C12.2 am 2026-09-06: ein gueltig signiertes Register auf `3.6.1` entschied ueber
#: 6.0.0. Wer diese Zahl aendert, aendert auch FINDINGS; ein Register mit neuer Version und alten
#: Funden waere dieselbe Luege eine Ebene tiefer.
VERSION = "6.0.0"

#: DER EHRLICHE STAND DER 6.0.0-FUNDE, abgeleitet aus `RESTRISIKO_600.md` (N1..N15) — nicht aus
#: dem Gedaechtnis und nicht aus der 3.6.1-Liste, die hier vorher stand.
#:
#: SCHWEREGRAD NACH WIRKUNG, nicht nach Wunsch. Der Gate liest {P0, P1} als freigabeentscheidend;
#: einen Fund niedriger einzustufen, damit das Tor gruen wird, waere genau der falsche PASS, gegen
#: den dieses Register gebaut ist. Massgeblich ist die Spalte „Wirkung" des Restrisiko-Registers,
#: Wort fuer Wort. Zwei Eintraege bleiben ausdruecklich OFFEN (N14, N15) — beide mit
#: Owner-Entscheidung und beide ohne Wirkung auf einen Nutzer des Pakets.
FINDINGS = [
    {"id": "N1", "severity": "P3", "status": "closed",
     "note": "flip oracle of the A5 corpus test read one field; fixed to require ok (bc95dd6). The "
             "wider class — narrow-scope comparison oracles — is not swept repo-wide"},
    {"id": "N2", "severity": "P3", "status": "closed",
     "note": "corpus input key serialised the whole params; fixed to the keys the runner reads, "
             "meta test both ways (bc95dd6)"},
    {"id": "N3", "severity": "P2", "status": "closed",
     "note": "the Receipt: line of a published disclosure block is the file hash, not "
             "receipt_digest(); documented in 6.0.0 rather than changed, because two published "
             "receipts carry it. Can mislead a reader who copies the line into priorDigest"},
    {"id": "N4", "severity": "P3", "status": "closed",
     "note": "POLICY_NOT_EVALUATED and AGENT_REVIEW_LEGACY_V01 moved from reason_codes to "
             "advisory_codes; no released build carried either code before 6.0.0"},
    {"id": "N5", "severity": "P2", "status": "closed",
     "note": "agent-review/v0.2 emits only selfDeclared assurance; a witness outside the agent "
             "workspace is not provided — documented honest limit"},
    {"id": "N6", "severity": "P3", "status": "closed",
     "note": "the time block of a policy file is evaluated only when present; the shipped standard "
             "policy carries none (time_policy_decision: null)"},
    {"id": "N7", "severity": "P3", "status": "closed",
     "note": "the skipped set of the PR-185 full run was not enumerated; the freeze audit run "
             "(pytest -rs) enumerates it and the receipt README lists it"},
    {"id": "N8", "severity": "P3", "status": "closed",
     "note": "C12.1 reports not-applicable on a pull request and absent on main until the signed "
             "6.0.0 receipt exists — the gate at work, not a defect"},
    {"id": "N9", "severity": "P3", "status": "closed",
     "note": "the relative CHANGELOG.md link in the new README section was dead in the sdist; "
             "fixed to an absolute URL (72c21e7)"},
    {"id": "N10", "severity": "P3", "status": "closed",
     "note": "CAP-1 coverage (feat/cap1-abdeckung, target 6.1.0) is not part of 6.0.0 by decision; "
             "the branch is not in the frozen tree"},
    {"id": "N11", "severity": "P2", "status": "closed",
     "note": "the canonical full mutation run was started on 658ed063 before this file existed; "
             "the byte-identity of src/, tests/ and scripts/ against the frozen head is measured "
             "and recorded, or the run is repeated"},
    {"id": "N12", "severity": "P2", "status": "closed",
     "note": "the learned-class ledger replay cannot finish inside the 240 s default window its "
             "runner carries (182 nodes measured 479 s); measured to completion under a wide "
             "window it reports pass. A property of the release-side replay runner, not of shipped "
             "code"},
    {"id": "N13", "severity": "P2", "status": "closed",
     "note": "the replay set contains at least one node whose result depends on runtime state "
             "OUTSIDE the tree under test (tests/test_warte_riegel.py in the 2bedone repository); "
             "recorded because it can decide this package's gate verdict"},
    # ── DIE ZWEI, DIE OFFEN BLEIBEN, und sie stehen als offen da, weil sie es sind ─────────────
    {"id": "N14", "severity": "P2", "status": "open",
     "note": "CLASS: a signing path in the shipped tree. sign_readiness_artifact.py is CLOSED (no "
             "code path loads a private key, measured by AST); pre_tag_receipt.py is DEFUSED, not "
             "closed — excluded from the sdist file by file and refusing to run inline without "
             "PB_INLINE_SIGNING=1, never on an automated build host. The CLASS — a build host that "
             "can reach a private key at all — is carried to 6.1 with the separate signing "
             "principal, so this entry stays OPEN until then. Owner decision 2026-09-06, card "
             "OA-8b1a31cc4f"},
    {"id": "N15", "severity": "P2", "status": "open",
     "note": "the wheel of 6.0.0 is bit-reproducible in both directions and also built from the "
             "shipped sdist; the sdist is not. Cause measured to the byte: the sdist path of "
             "setuptools 84.0.0 does not honour SOURCE_DATE_EPOCH, so each archive carries a pax "
             "header with the wall clock. The CONTENT of both builds is identical. Owner decision "
             "2026-09-06: 6.0.0 ships with this sdist and the non-reproducibility is named rather "
             "than played down; the build-backend change is a 6.1 item"},
    # ── DIE DREI FUNDE DES ADVERSARIAL DEEP GATE, LAUF 5 (2026-09-06) ──────────────────────────
    #
    # SCHWEREGRAD IST HIER NICHT GEWAEHLT, SONDERN UEBERNOMMEN. Alle drei tragen P2, weil die
    # dreikoepfige Jury des Laufs sie so bewertet hat — nicht, weil P2 das Tor gruen laesst. Der
    # Unterschied ist wichtig genug, ihn hinzuschreiben: der Kommentar oben warnt genau davor,
    # einen Fund herunterzustufen, damit C12.2 durchgeht, und wer diese Zeilen liest, soll die
    # Herkunft der Zahl pruefen koennen statt sie glauben zu muessen. Verdikt des Laufs:
    # FIX_FIRST. Fuer 6.0.0 wird KEIN WITHSTANDS_DEEPGATE behauptet.
    #
    # Alle drei stehen OFFEN. Owner-Entscheid OA-b4489d0204 vom 2026-09-06: sie bleiben fuer
    # 6.0.0 unter der Halte-Schwelle und werden im Sammelrelease geschlossen.
    {"id": "N16", "severity": "P2", "status": "open",
     "note": "deep gate run 5, L6-02: action/action.yml:35-36 interpolates ${{ inputs.version }} "
             "and ${{ inputs.extras }} directly into a run: shell body, while lines 43-44 route "
             "inputs.command through env: and say why. A class fix applied to one of three inputs "
             "of one file and never swept to its siblings. NOT introduced by this release: the "
             "file is byte-identical to the one at the public v1.0.0 tag (sha256 91cfcdc4…, a "
             "single commit ever touched it, that tag is an ancestor of this candidate). Measured "
             "reach: INTEGRATIONS.md points at action@v1.0.0, that tag is FIXED, and no moving "
             "major ref v1 exists — so a fix on main does NOT reach the documented users; a new "
             "action ref is outward-facing and needs its own owner GO. Owner decision "
             "OA-b4489d0204: first item after the tag, not pulled forward, because "
             "action/action.yml lies inside the frozen tree"},
    {"id": "N17", "severity": "P2", "status": "open",
     "note": "deep gate run 5, L5-G8-01: scripts/rust_parity_gate.py:124 swallows an unparseable "
             "or unreadable source file (except (SyntaxError, OSError): continue), and "
             "registry_integrity_ok derives its verdict as ok = not (untracked or orphaned or "
             "stale) — an assertion from ABSENT complaint over the resulting population. The "
             "consumers c8_1_registry_integrity and c8_3_pending_documented are RELEASE-DECIDING "
             "(measured: neither is in _INFORMATIVE_CHECKS, audit_candidate_matrix.py:84). "
             "MEASURED LIMIT on this candidate: the population is COMPLETE — 68 of 68 .py under "
             "src/ parse and are readable — so no verdict of this release rests on a narrowed "
             "set; the finding is the CAPABILITY of a false pass, not its occurrence. The same "
             "class is already closed in the neighbour (type_confusion_gate.py:487-499, which "
             "names rust_parity_gate.py:124 verbatim as the defect site), and the docstring of "
             "the defective function itself lists FOUR narrowings of this class lifted on "
             "2026-08-26; this branch survived that sweep and carries no test (no occurrence of "
             "SyntaxError or OSError in tests/test_rust_parity_gate.py). Owner decision "
             "OA-b4489d0204: below the hold threshold for 6.0.0, closed in the collection release "
             "following the pattern the neighbour already carries, with a catch-proof"},
    {"id": "N18", "severity": "P2", "status": "open",
     "note": "deep gate run 5, L6-01: pip install <sdist> && pytest WITHOUT the [test] extras is "
             "RED, not skipped, while the shipped pyproject.toml promises a bare [eval] install "
             "'degrades to clean skips'. Measured: 1 failed, 3075 passed, 482 skipped; the red "
             "node is tests/test_ausfuehrung_aus_quelltext_l5_g7_04.py::"
             "test_gate_meta_koexistenz_im_selben_job_reicht_nicht_mehr, which reaches PyYAML "
             "INDIRECTLY through scripts/audit_candidate_matrix.py:1395 and therefore does not "
             "carry the module's own @_braucht_yaml guard — the guard sits where the import is "
             "VISIBLE, not where the dependency IS. Introduced by this candidate's own commit "
             "1311498. Additionally measured: the CI step whose own comment claims to pin exactly "
             "this property (published-artifact-gate.yml:83-84, 'Stops the invariant from "
             "drifting false again') installs [test] into the same venv at line 86 before the "
             "suite starts at line 92 — the bare path is exercised NOWHERE; and the guard built "
             "for the earlier instance of this class (L6-F1-SDIST-PYYAML, 2026-08-25) is scaled "
             "to a single file (tests/test_sdist_selftest_optional_deps.py:35), while the "
             "regression landed in its sibling. Owner decision OA-b4489d0204, Auflage 4: own "
             "register entry and named in the release note; in the collection release the promise "
             "is either honoured or reworded in pyproject.toml"},
    # ── DIE MESSGRENZEN DER STUFE-6-EVIDENZ, Owner-Auflage vom 2026-09-06 ──────────────────────
    {"id": "N19", "severity": "P3", "status": "open",
     "note": "the mutation gate collects its test population with unittest discover and therefore "
             "measures a SUBSET: measured on this candidate, unittest discover runs 2537 tests "
             "while pytest collects 3702, and 59 of 252 test files carry only pytest functions and "
             "are invisible to that collector. Every stage-6 statement of this release is bounded "
             "by that subset: SURVIVED means 'no unittest-visible test catches this'. Of the 100 "
             "operators, 91 were killed, 7 survived only because the gate cannot see the test that "
             "kills them (each proven by running pytest against the MEASURED covering file), 1 is "
             "not measurable (N20), 1 is a documented equivalent expected to survive — and ZERO "
             "are real gaps. Sibling scope figures of this release: the learned-class ledger "
             "replay ran 94 of 182 classes (the other 88 carry no evidence in either direction), "
             "the Python/Rust parity gate saw 68 of 68 source files. Closing action after the tag: "
             "move the gate to a collector that sees every test, with a catch-proof"},
    {"id": "N20", "severity": "P3", "status": "open",
     "note": "one mutation operator is NOT MEASURABLE rather than killed or survived: 'budget: "
             "data_digests-Schranke praktisch entfernt' removes the very resource ceiling under "
             "test, and the mutated run reached 116519388 kB RSS (111 GiB, 88.3 % of memory, 1 GiB "
             "free) before it was stopped deliberately rather than left to the OOM killer, whose "
             "choice of victim would not have been the same process. An earlier attempt ended at "
             "signal 9. Neither outcome is a test verdict — what stopped the run was the kernel, "
             "not an assertion — so it is counted in neither sort. This is evidence that the "
             "ceiling the operator removes does its job, not a defect of the candidate"},
    # N21 FEHLTE HIER BIS 2026-09-08, und die Luecke war strukturell unsichtbar: C12.2 zaehlt
    # OFFENE P0/P1 im signierten Register, und eine FEHLENDE Zeile kann dort nicht offen sein. Das
    # Restrisiko-Register fuehrte N1..N21, dieses hier N1..N20, und audit_artifacts/600/README.md
    # zaehlte ausdruecklich „R1-R7 and N1-N21" — drei Dokumente, zwei Zahlen, kein Vergleich. Der
    # Riegel dagegen ist jetzt tests/test_register_population_gegen_restrisiko.py: er VERGLEICHT
    # die beiden Populationen, statt die eine aus der anderen abzuleiten. Owner-GO 08.09.2026.
    {"id": "N21", "severity": "P3", "status": "open",
     "note": "the release-deciding check C12.2 flips PASS to FAIL on 2027-09-07 BY DESIGN, and this "
             "line exists so that a gate which turns red on a calendar date is written down BEFORE "
             "it does, not explained afterwards. The closing-round fix makes an expired anchor key "
             "authorise nothing NOW, and the sole key carries not_after=2027-09-06; an empty "
             "authorised set is FAIL, not DATA_BLOCKED (only an unreadable anchor is the latter). "
             "From that day the audit matrix goes red until the key is rotated. Intended behaviour "
             "of a validity window, not a defect of the candidate. Closing action: rotate the key "
             "before 2027-09-06, or accept the red"},
]


# ── DER v2-TRAEGER: aus gemessenen Groessen, nicht aus dem Gedaechtnis ─────────────────────

def _tabellenkopf(text: str, byte_von: int) -> list[str]:
    """Die Spaltennamen der Tabelle, in der eine Zeile steht — nach oben gesucht.

    GEMESSEN: die Quelle fuehrt DREI Tabellenformate, nicht eines.
        | Id | Finding | Class | Funnel verdict |              (N-Funde)
        | Id | In one line | Closed where |                    (Nachtragsliste)
        | Id | Severity | Assurance touched | What it is | State |   (A-Funde)
    Die erste Fassung nahm blind Spalte 2 und gab A1 den Titel "P2" — das ist dort die
    SCHWERE. Wer eine Spalte nach Position liest statt nach Namen, liest irgendwann die
    falsche.
    """
    vor = text.encode()[:byte_von].decode("utf-8", errors="ignore")
    for zeile in reversed(vor.splitlines()):
        z = zeile.strip()
        if z.startswith("|") and "Id" in z:
            return [t.strip() for t in z.strip("|").split("|")]
        if z.startswith("#"):
            break
    return []


#: Spaltennamen, die den Titel eines Fundes tragen — nach Namen, nicht nach Position.
_TITELSPALTEN = ("Finding", "In one line", "What it is", "Title")


def _titel(stueck: str, kennung: str, fundart: str, kopf: list[str] | None = None) -> str:
    """Der Titel EINER Fundstelle, aus ihren eigenen Bytes."""
    import re  # noqa: PLC0415
    zeilen = stueck.splitlines()
    erste = zeilen[0] if zeilen else ""
    if fundart == "tabelle_spalte1":
        spalten = [t.strip() for t in erste.strip().strip("|").split("|")]
        if kopf:
            for name in _TITELSPALTEN:
                if name in kopf:
                    i = kopf.index(name)
                    if i < len(spalten):
                        return spalten[i][:200]
        return (spalten[1] if len(spalten) > 1 else "")[:200]
    k = re.sub(rf"^#+\s*{re.escape(kennung)}\s*", "", erste).strip()
    return re.sub(r"^[·\-—,:]\s*", "", k)[:200]


def _severity_aus_tabelle(stueck: str, kopf: list[str]) -> str | None:
    """Eine Schwere, die in der Tabelle STEHT — messbar, nicht geraten."""
    import re  # noqa: PLC0415
    if not kopf or "Severity" not in kopf:
        return None
    spalten = [t.strip() for t in stueck.splitlines()[0].strip().strip("|").split("|")]
    i = kopf.index("Severity")
    if i < len(spalten) and re.fullmatch(r"P[0-3]", spalten[i]):
        return spalten[i]
    return None


def _severity(kennung: str, aus_tabelle: str | None = None) -> dict:
    """Schwere nur, wo sie STEHT: im signierten v1-Register oder in der Severity-Spalte der
    Quelle. Sonst eine Luecke MIT Grund — nie eine geratene Einstufung, denn der Gate liest
    {P0,P1} als freigabeentscheidend, und ein herabgestufter Fund waere genau der falsche
    PASS, gegen den dieses Register gebaut ist."""
    for f in FINDINGS:
        if f["id"] == kennung:
            # DAS ETIKETT SAGTE "signiert" UND LAS DEN SPEICHER (Codex r3999796578). FINDINGS ist
            # eine Python-Liste in DIESER Datei; eine Aenderung daran aendert die veroeffentlichte
            # Schwere, und das Ergebnis wies sich als signierte Evidenz aus. Der Weg ist derselbe
            # geblieben, die AUSSAGE darueber ist jetzt wahr: die Liste wird genannt, wie sie ist,
            # und ob sie mit dem signierten Register uebereinstimmt, prueft
            # tests/test_register_gegen_erzeuger.py als eigene Zusicherung — nicht dieses Etikett.
            # ERZEUGTE PROSA, ALSO IN DER DEKLARIERTEN SPRACHE. Dieses Feld ist heute
            # hinzugekommen und trug deutschen Text — derselbe Fund eine Runde spaeter am eigenen
            # Zusatz. Was der Erzeuger selbst schreibt, folgt `language`; was er zitiert, behaelt
            # seine Sprache und steht im `language_scope`.
            return {"value": f["severity"],
                    "source": "FINDINGS in scripts/gen_findings_register.py",
                    "source_state": "NOT CHECKED AGAINST THE SIGNED ARTIFACT",
                    "source_reason": ("the list lives in the producer, not in the signed register; "
                                      "their agreement is a separate assurance and not a property "
                                      "of this field")}
    if aus_tabelle:
        return {"value": aus_tabelle, "source": f"severity column in {RESTRISIKO_REL}"}
    return {"value": None, "state": "NOT MEASURED",
            "reason": ("this identifier appears neither in the signed v1 register nor in a "
                       "table with a severity column; setting a severity here would be a "
                       "rating without evidence")}


def _bewertungsgrenze(ok: dict):
    """Der Tag, bis zu dem der Bestand GEMESSEN ist — aus der Quelle, nie aus der Uhr des Laufs.

    Drei Zustaende. Ein lesbares Kalenderdatum; sonst ein Lueckenwort MIT Grund. Ein Platzhalter
    wie `2026-09-13T0?:??Z` zaehlt ausdruecklich als lesbar, soweit sein DATUMSteil es ist — die
    Stunde fehlt dort, der Tag nicht, und der Tag ist die Groesse, um die es hier geht.
    """
    import datetime as _dt  # noqa: PLC0415
    import re  # noqa: PLC0415
    roh = str(((ok.get("gemessen_an") or {}).get("utc")) or "")
    m = re.match(r"(\d{4}-\d{2}-\d{2})", roh)
    if m:
        # DIE ZIFFERNFORM IST NICHT DAS DATUM (Codex 4000140173). Der Ausdruck oben prueft vier
        # Ziffern, zwei Ziffern, zwei Ziffern — mehr nicht. GEMESSEN: `gemessen_an.utc` auf
        # "2026-99-99T00:00:00Z" gesetzt und neu gebaut endet mit 0, meldet gruen und schreibt
        # `assessment_cutoff: "2026-99-99"`; `pruefe_v2` findet null Fehler, weil es dort nur
        # gegen eine nichtleere Zeichenkette prueft. Monat 99, Tag 99 — eine Bewertungsgrenze,
        # die es im Kalender nicht gibt, wurde als erfolgreich geprueft veroeffentlicht.
        #
        # GEPRUEFT WIRD MIT DEM KALENDER, nicht mit einem zweiten Ausdruck: `date.fromisoformat`
        # kennt Schaltjahre und Monatslaengen, ein Regex kennt sie nie. Ein unmoegliches Datum ist
        # danach NICHT MESSBAR mit Grund — nicht etwa die Uhr dieses Laufs, denn die wuerde den
        # gemessenen Stand vordatieren.
        try:
            _dt.date.fromisoformat(m.group(1))
        except ValueError:
            return {"state": "NOT MEASURED",
                    "value": None,
                    "reason": (f"`gemessen_an.utc` starts with {m.group(1)!r}, which has the shape "
                               f"of a date but is not one in the calendar; the assessment boundary "
                               f"is NOT derived from the time of this run, because that would "
                               f"predate the measured state")}
        return m.group(1)
    return {"state": "NOT MEASURED",
            "reason": ("the object class file carries no readable calendar date under "
                       "`gemessen_an.utc`; the assessment boundary is NOT derived from the time "
                       "of this run, because that would predate the measured state")}


def _status_aus_tabelle(stueck: str, kopf: list) -> str | None:
    """Ein Zustand, der in der Tabelle STEHT. Spalte nach NAMEN, nicht nach Position."""
    if not kopf or "State" not in kopf:
        return None
    spalten = [x.strip() for x in stueck.splitlines()[0].strip().strip("|").split("|")]
    i = kopf.index("State")
    return spalten[i][:80] if i < len(spalten) and spalten[i] else None


#: DER ZUSTAND STEHT AUCH IN DER UEBERSCHRIFT (Codex 4000140162). Die Quelle fuehrt ihre Funde in
#: ZWEI Gestalten: als Tabellenzeile mit Zustandsspalte und als Ueberschrift, deren Text den
#: Zustand nach einem Gedankenstrich nennt ("… — open, reproduced …", "… — CLOSED, and …").
#: Gelesen wurde nur die erste. GEMESSEN ueber die Quelle: 50 Ueberschriften tragen eine Kennung,
#: 12 nennen darin `open`, 5 `closed`, 33 nennen nichts. Die 17 mit Zustand kamen als NOT MEASURED
#: heraus und fielen damit aus `known_issues.md` — S5 steht in der Quelle ausdruecklich offen und
#: fehlte in der Ansicht der offenen Punkte.
#:
#: ENG GEFASST, UND DIE GRENZE IST GEMESSEN: erkannt wird das Zustandswort NACH einem
#: Gedankenstrich, also die Hausform der Ueberschrift. Das trifft 15 der 17. Die zwei uebrigen
#: (S1, S11) tragen "CLOSED" mitten im Satz; sie bleiben NOT MEASURED, weil ein Muster, das jedes
#: `open` irgendwo im Titel als Zustand liest, aus "opened the file" einen Fund macht. Lieber eine
#: benannte Luecke als ein geratener Zustand — die zwei sind als eigener Posten vermerkt.
#: `re` wird in dieser Datei bewusst LOKAL importiert; das Muster wird deshalb im Aufruf gebaut
#: und nicht auf Modulebene. Es steht hier als Zeichenkette, damit die Form lesbar bleibt.
_ZUSTAND_IN_UEBERSCHRIFT = r"[—–-]{1,2}\s*\**(open|closed)\b"


def _status_aus_ueberschrift(stueck: str, kennung: str) -> str | None:
    """Das Zustandswort aus der Ueberschrift DIESER Kennung — oder None."""
    import re  # noqa: PLC0415
    muster = re.compile(_ZUSTAND_IN_UEBERSCHRIFT, re.I)
    for zeile in stueck.splitlines():
        z = zeile.strip()
        if not z.startswith("#") or kennung not in z:
            continue
        m = muster.search(z)
        if m:
            return m.group(1).lower()
    return None


def _status(kennung: str, aus_tabelle: str | None = None,
            aus_ueberschrift: str | None = None) -> dict:
    """Der Zustand eines Fundes, GELESEN statt geraten.

    Codex r3999621596: `_offen` fiel fuer jede Kennung, die nicht in FINDINGS steht, auf
    `bool(severity) and record_role == "finding"` zurueck und las den Zustand der Quelle NIE.
    Gemessen trat das ein: A4 steht in der Quelltabelle ausdruecklich als `closed` und erschien in
    der erzeugten Ansicht `known_issues.md` als offener P1. Ein Zustand, der aus Schwere und Rolle
    GERATEN wird, ist keine Auskunft ueber den Fund, sondern ueber die Form seines Datensatzes.

    Drei Zustaende, nie zwei: aus der Liste des Erzeugers, aus der Zustandsspalte der Quelle, oder
    NOT MEASURED mit Grund.
    """
    for f in FINDINGS:
        if f["id"] == kennung:
            return {"value": f["status"],
                    "source": "FINDINGS in scripts/gen_findings_register.py"}
    if aus_tabelle:
        return {"value": "closed" if aus_tabelle.lower().startswith("closed") else "open",
                "source": f"state column in {RESTRISIKO_REL}", "wortlaut": aus_tabelle}
    if aus_ueberschrift:
        return {"value": aus_ueberschrift,
                "source": f"state word in the heading in {RESTRISIKO_REL}"}
    return {"value": None, "state": "NOT MEASURED",
            "reason": ("this identifier appears neither in the producer list, nor in a table with "
                       "a state column, nor in a heading that names its state after a dash; "
                       "setting a state here would be a guess")}


def baue_v2(repo, generated_at: str, revision: int = 0) -> dict:
    """Der Traeger der Registerform 6.1 aus drei gemessenen Quellen.

    MIGRATION NACH 1A (Owner-Entscheid OA-3c501b246f/OA-714de2fcdd): echte Artefakte
    wandern, der Rest traegt NOT MEASURED MIT GRUND. Was hier steht, ist entweder aus der
    Quelle geschnitten, aus dem signierten v1-Register uebernommen oder als Luecke benannt.
    Nichts wird erfunden, damit eine Spalte voll aussieht.
    """
    import hashlib
    import json as _json  # noqa: PLC0415
    quelle = repo / RESTRISIKO_REL
    roh = quelle.read_bytes()
    text = roh.decode("utf-8")
    qd = hashlib.sha256(roh).hexdigest()
    ok = _json.loads((repo / OBJEKTKLASSEN_REL).read_text(encoding="utf-8"))

    # DIE DEKLARIERTE AUSNAHME, EINMAL GELESEN. Nur wer hier steht — mit Grund UND Beleg, das
    # verlangt tests/test_objektklassen_gegen_das_register.py — gilt als "gemessen, nichts
    # vorgefunden" und damit als KEIN Defekt. Alles andere bleibt ein Defekt, auch wenn es aus
    # Zaehlgruenden nicht zur Fundsumme beitraegt.
    _aus = (ok.get("ausnahmen_von_der_klasse") or {}).get("messung_ohne_fund") or {}
    _belege = _aus.get("beleg") or {}
    _OHNE_FUND = {kx: (_belege.get(kx) or _aus.get("warum") or "declared without a reason")
                  for kx in (_aus.get("kennungen") or [])}

    records, ohne_fundstelle = [], []
    for e in ok["eintraege"]:
        k = e["kennung"]
        t = schneide_beleg(text, k)
        if t is None:
            ohne_fundstelle.append(k)
            continue
        von, bis, fundart = t
        stueck = roh[von:bis]
        kopf = _tabellenkopf(text, von) if fundart == "tabelle_spalte1" else []
        records.append({
            "id": k,
            "record_revision": revision,
            "record_role": "finding" if e.get("zaehlt_als_fund") else "boundary",
            # ZWEI GRUENDE, EIN FELD — und deshalb ein zweites (Codex 4000176743).
            #
            # `record_role: boundary` heisst nur `zaehlt_als_fund: false`, und das beantwortet eine
            # ZAEHLFRAGE: traegt der Eintrag zur Fundsumme bei? Es beantwortet NICHT die Frage, ob
            # ein Defekt vorliegt. GEMESSEN am Bestand tragen ACHT Grenzen den Zustand offen, und
            # sie zerfallen in zwei Mengen:
            #   N21 ist in der Objektklassen-Datei als `messung_ohne_fund` DEKLARIERT — die Quelle
            #       sagt ausdruecklich, dass nichts vorliegt. Das gehoert nicht unter die offenen
            #       Punkte.
            #   R1 bis R7 sind `nachgemessene_fassung_einer_runde`: sie zaehlen nicht mit, weil man
            #       sonst DIESELBE Runde mehrfach zaehlte — aber die Defekte sind offen und echt
            #       ("contradicts the shipped code", "raises a raw exception", "three numbers are
            #       wrong").
            #
            # Die naheliegende Abhilfe — Grenzen aus der Ansicht nehmen — haette daher SIEBEN echte
            # offene Funde versteckt. Entschieden wird deshalb an der DEKLARIERTEN Ausnahme, nicht
            # an der Rolle: nur wer im Block `messung_ohne_fund` steht, mit Grund und Beleg, ist
            # kein Defekt. Der Vertrag zu diesem Block verlangt beides seit heute frueh.
            # EIN FELD, EINE HERKUNFT — und das war beim ersten Anlauf nicht so. Der Riegel
            # `test_die_sprachangabe_deckt_was_sie_sagt.py` wies ihn zurueck: dasselbe Feld trug
            # bei 142 Saetzen eine ERZEUGTE englische Begruendung und bei drei ein deutsches
            # ZITAT. Eine Herkunftsangabe, die fuer ein Feld gilt, muss fuer ALLE seine Werte
            # gelten. Das Zitat heisst deshalb `beleg` und steht nur da, wo es eines gibt; der
            # verneinte Fall traegt gar keine Prosa, denn "nichts deklariert" braucht keinen Satz.
            "not_a_defect": ({"value": True,
                              "source": "declared exception `messung_ohne_fund` in "
                                        "RESTRISIKO_600_OBJEKTKLASSEN.json",
                              "beleg": _OHNE_FUND.get(k)}
                             if k in _OHNE_FUND else {"value": False}),
            # ART NICHT GERATEN. Die Objektklassen unterscheiden nach HERKUNFT
            # (S/N/A/R/Z/G), nicht nach security/quality: `fund_sicherheit_und_korrektheit`
            # mischt beides, `fund_nachtrag` sagt ueber die Art nichts. Die erste Fassung
            # leitete `kind` daraus ab und machte N16 — eine Shell-Injection — zu `quality`.
            # Nach 1A wandert, was gemessen ist; der Rest traegt NOT MEASURED mit Grund.
            "kind": None,
            "kind_state": "NOT MEASURED",
            # DIE SPRACHE DES TRAEGERS IST DIE, DIE ER DEKLARIERT (Codex r3999621601). Er fuehrt
            # `language: en` und trug hier deutsche Prosa. Gemessen waren es sechs Feldarten;
            # eine davon rendert in zwei der drei Ansichten, fuenf in keiner — aber der Traeger
            # selbst wird gelesen, also zaehlt jede. Wer ein Dokument nach seiner Sprachangabe
            # auswaehlt, bekam etwas anderes, als die Angabe sagt.
            "kind_reason": ("the object classes separate by origin, not by kind; no source "
                            "carries a security or quality assignment, and it is decided per "
                            "finding rather than derived"),
            "title": _titel(stueck.decode("utf-8"), k, fundart, kopf),
            "class_id": None,
            "class_state": "NOT MEASURED",
            "class_reason": "the source carries no class identifiers",
            "objektklasse": e.get("klasse"),
            "objektklasse_begruendung": e.get("warum_diese_klasse"),
            "severity": _severity(k, _severity_aus_tabelle(stueck.decode("utf-8"), kopf)
                                  if fundart == "tabelle_spalte1" else None),
            "status": _status(k,
                              _status_aus_tabelle(stueck.decode("utf-8"), kopf)
                              if fundart == "tabelle_spalte1" else None,
                              _status_aus_ueberschrift(stueck.decode("utf-8"), k)),
            "evidence": [{
                "path": f"{EVIDENZ_REL}/{k}.md",
                "sha256": hashlib.sha256(stueck).hexdigest(),
                "role": "historical_record",
                "source_path": RESTRISIKO_REL,
                "source_sha256": qd,
                "byte_range": [von, bis],
                "fundart": fundart,
            }],
            "last_measured": None,
            "last_measured_state": "NOT MEASURED",
            "last_measured_reason": ("the source names the day it was produced, not the time "
                                     "each finding was last measured"),
        })

    luecken = []
    for name, g in (ok.get("luecken_in_der_nummernfolge") or {}).items():
        if name.startswith("_") or not isinstance(g, dict):
            continue
        luecken.append({"range": name.replace("_bis_", " bis "), "count": g.get("anzahl"),
                        "state": g.get("marke"), "reason": g.get("grund")})

    return {
        "schema": "proofbundle.findings_register.v2",
        "profile_version": "0.1",
        "document_id": f"urn:b7n0de:findings-register:{VERSION.replace('.', '')}",
        "register_revision": revision,
        "issuer": "b7n0de",
        # DIE SPRACHANGABE WAR EINE HALBE WAHRHEIT (Codex r3999621601). Der Traeger fuehrte
        # `language: en` und trug deutsche Prosa; wer ein Dokument nach dieser Angabe auswaehlt,
        # bekam etwas anderes, als sie sagt.
        #
        # UEBERSETZEN IST HIER KEINE OPTION, und das ist der Kern. Gemessen stammen 79 Titel und
        # 33 Klassenbegruendungen WORTWOERTLICH aus `RESTRISIKO_600.md`, einer deutschen Quelle,
        # und die Belegdateien sind byte-gepinnt: `pruefe_v2` rechnet ihren Digest gegen genau
        # diese Bytes. Eine Uebersetzung waere eine Faelschung der Evidenz. Ein Zitat behaelt seine
        # Sprache; das ist keine Schwaeche des Dokuments, sondern die Bedingung dafuer, dass es
        # nachrechenbar bleibt.
        #
        # Deshalb wird die Angabe WAHR gemacht statt der Inhalt passend: `language` beschreibt die
        # ERZEUGTE Prosa dieses Traegers, und die ist jetzt durchgaengig englisch. Was zitiert ist,
        # steht daneben mit seiner eigenen Sprache und seiner Quelle. Eine Angabe, die ihren
        # Geltungsbereich nennt, sagt mehr als eine, die ihn verschweigt.
        "language": "en",
        "language_scope": {
            "generated_prose": "en",
            # JE QUELLE EIN EINTRAG, und das ist eine Korrektur an der ersten Fassung dieses
            # Blocks. Sie nannte EINE Quelle fuer Felder aus ZWEI Dateien — gemessen kommen 145
            # Titel aus dem Quellregister und 153 weitere Zeichenketten aus der
            # Objektklassen-Datei. Eine Herkunftsangabe, die auf die falsche Datei zeigt, ist
            # nicht nachrechenbar, und nachrechenbar ist der ganze Zweck dieses Blocks.
            # `tests/test_die_sprachangabe_deckt_was_sie_sagt.py` rechnet ihn jetzt nach: jedes
            # als zitiert deklarierte Feld MUSS in seiner genannten Quelle woertlich vorkommen.
            "quoted_from_source": [
                {"language": "de", "source": RESTRISIKO_REL,
                 "fields": ["records[].title"],
                 "why": ("headings cut verbatim out of the source register; the evidence files "
                         "are byte pinned and digest checked, so translating them would falsify "
                         "the evidence they exist to reproduce")},
                {"language": "de", "source": "RESTRISIKO_600_OBJEKTKLASSEN.json",
                 "fields": ["records[].objektklasse_begruendung",
                            "records[].not_a_defect.beleg",
                            "inventory.coverage_gaps[].reason",
                            "inventory.cross_count._auflage",
                            "inventory.cross_count.warum_zu_viel_je_kennung.*"],
                 "why": ("reasons carried over verbatim from the object class file, which is "
                         "itself digest bound to the source register")},
            ],
        },
        "issued_at": generated_at[:10],
        "generated_at": generated_at,
        "release_subject": {"name": "proofbundle", "version": VERSION, "tag": f"v{VERSION}"},
        # DIE BEWERTUNGSGRENZE IST KEINE EIGENSCHAFT DES ERZEUGUNGSLAUFS (Codex r4000054881).
        # Sie stand auf `generated_at`, also auf dem Zeitpunkt, an dem dieser Befehl lief. Gemessen:
        # `baue_v2(..., "2099-01-01T00:00:00Z")` meldet null Fehler und laesst beide Ansichten eine
        # Bewertungsgrenze von 2099 behaupten, obwohl kein Eintrag in 2099 nachgemessen wurde. Ein
        # spaeteres Neuerzeugen haette die oeffentliche Grenze allein durch das Datum vorgerueckt.
        #
        # Sie kommt jetzt aus dem Stand, ueber den das Register spricht: dem Messzeitpunkt der
        # Quelle, wie die Objektklassen-Datei ihn fuehrt. Laesst er sich nicht lesen, steht NOT
        # MEASURED mit Grund — nie ein Rueckfall auf die Uhr des Laufs, denn das war der Fehler.
        "assessment_cutoff": _bewertungsgrenze(ok),
        "inventory": {
            "source_documents": [{"path": RESTRISIKO_REL, "sha256": qd,
                                  "identifiers": len(ok["eintraege"])},
                                 {"path": OBJEKTKLASSEN_REL,
                                  "sha256": hashlib.sha256(
                                      (repo / OBJEKTKLASSEN_REL).read_bytes()).hexdigest(),
                                  "identifiers": len(ok["eintraege"])}],
            "identifiers_total": len(ok["eintraege"]),
            "identifiers_in_this_register": len(records),
            "identifiers_without_evidence": ohne_fundstelle,
            "coverage_gaps": luecken,
            "cross_count": _gegenrechnung(ok, records, repo),
            "assurance_checks": _zusicherungen(text, records),
        },
        "records": records,
        # NICHT ANWENDBAR WAR DAS FALSCHE WORT (Codex 3999796576). Es liest sich wie "eine Signatur
        # ist hier ohne Bedeutung", und genau das Gegenteil stimmt: dieser Traeger IST fuer den
        # Signierweg gebaut, er ist nur noch nicht durch ihn gegangen. GEMESSEN: der `--v2`-Lauf
        # schreibt Traeger und Ansichten und endet mit 0, ohne `emit` oder `assemble` je zu rufen.
        # Ein Leser konnte den Aussteller damit nicht pruefen und las im selben Feld, das sei
        # bauartbedingt so.
        #
        # DER ZUSTAND HEISST JETZT, WAS ER IST, und er sagt beides: was FEHLT und was es BRAEUCHTE.
        # Signieren selbst bleibt eine Owner-Tuer — der private Schluesselteil liegt beim Owner, und
        # diese Sitzung hat ihn nicht. Was in ihrer Macht steht, ist die ehrliche Auskunft.
        "signature": {"state": "UNSIGNED",
                      "reason": ("this carrier has NOT been through the signing path; it was "
                                 "written by the generator alone, so the issuer named above is "
                                 "asserted by the document and not attested by anyone"),
                      "what_would_change_it": ("running the emit and assemble path over the "
                                               "canonical bytes of this body, with the private "
                                               "half of the key that stays with the owner"),
                      "consequence_for_the_reader": ("treat this as an unauthenticated record; a "
                                                     "coordinated change of register and evidence "
                                                     "cannot be detected from the document alone")},
    }


def _zusicherungen(text: str, records: list) -> list:
    """Die Zusicherungen der Quelle gegen ihre eigenen Daten gerechnet.

    WOZU. Die Prosa sagt ueber der A-Tabelle: "None of them changes the assurance
    0 open P0/P1: that count speaks about P0 and P1, and EVERY ENTRY HERE IS P2 OR P3."
    Gemessen an derselben Tabelle: A4 traegt P1. Die Zusicherung STIMMT — der einzige P1
    der ganzen Quelle ist `closed` —, aber ihre BEGRUENDUNG ist von der eigenen Tabelle
    drei Zeilen darunter widerlegt. Wuerde A4 je wieder geoeffnet, bliebe der Satz stehen
    und waere dann doppelt falsch: die Begruendung schon heute, die Zusicherung dann auch.

    Deshalb wird die Zusicherung hier GERECHNET statt zitiert, mit der Prosa-Begruendung
    als eigenem Feld daneben.
    """
    import re  # noqa: PLC0415
    # UEBER DIE DATENSAETZE, NICHT UEBER EINEN REGEX AUF DEN ROHTEXT (Codex r3999820857).
    #
    # Die alte Fassung suchte `| <Kennung> | P0/P1 | … |` — also ausschliesslich Zeilen der
    # A-Tabelle, weil nur dort die Schwere in Spalte zwei steht. Gemessen sind das 1 von 145
    # Datensaetzen; alle Funde in UEBERSCHRIFTENFORM (S, R, Z, G) und alle Eintraege aus der Liste
    # des Erzeugers waren strukturell unsichtbar. Ein offener P0 oder P1 aus diesen Mengen haette
    # `holds` nicht beruehrt, und die Zusicherung "0 open P0/P1" haette weiter gehalten.
    #
    # Der Fund nennt das eine Faehigkeit; gemessen am heutigen Bestand tritt sie NICHT ein, denn
    # kein Eintrag ausserhalb der A-Tabelle traegt heute P0 oder P1. Das ist genau der Unterschied
    # zwischen einem falschen Bestehen und der MOEGLICHKEIT eines falschen Bestehens, und beides
    # gehoert benannt.
    #
    # Gerechnet wird jetzt ueber die Datensaetze, die Schwere UND Zustand je aus einer benannten
    # Quelle tragen. Damit zaehlt dieselbe Menge, ueber die das Register spricht.
    hoch = []
    for r in records:
        sev = (r.get("severity") or {}).get("value")
        if sev not in ("P0", "P1"):
            continue
        st = r.get("status") or {}
        hoch.append({"id": r["id"], "severity": sev,
                     "state": st.get("value") or st.get("state") or "NOT MEASURED",
                     "state_source": st.get("source") or st.get("reason", "")[:60]})
    # EIN UNBEKANNTER ZUSTAND IST NICHT "GESCHLOSSEN". Die alte Fassung fragte, ob der Zustandstext
    # mit "closed" beginnt — was jeden nicht gemessenen Zustand stillschweigend als offen zaehlte
    # und umgekehrt jede fremde Schreibweise als offen. Hier zaehlt nur, was ausdruecklich zu ist.
    offen = [h for h in hoch if h["state"] != "closed"]
    anmerkung = None
    if re.search(r"every entry here is P2 or P3", text) and hoch:
        # ERZEUGTE PROSA, ALSO IN DER DEKLARIERTEN SPRACHE — und dieses Feld war der eine
        # Rueckstand der Sprachrunde. Es stand als ZITAT deklariert, war aber selbst geschrieben;
        # eine Deklaration, die mehr behauptet, als sie traegt, ist genau die Klasse, gegen die
        # der Sprachblock gebaut wurde. Gemessen: 153 der 154 deutschen Zeichenketten sind
        # woertliche Zitate, diese eine nicht.
        anmerkung = ("the prose above the severity table justifies '0 open P0/P1' with "
                     "'every entry here is P2 or P3'. Measured against that same table: "
                     + ", ".join(f"{h['id']} carries {h['severity']}" for h in hoch)
                     + ". The assurance holds because that entry is closed, not for the reason "
                       "the sentence gives. A sentence that justifies a true statement with a "
                       "false premise survives the change that makes it false.")
    # DIE UEBERSPRUNGENEN GEHOEREN IN DIE ZUSICHERUNG (Codex 4000140168).
    #
    # Die Schleife oben ueberspringt jeden Datensatz, dessen Schwere NICHT P0 oder P1 ist — und
    # damit auch jeden, dessen Schwere GAR NICHT GEMESSEN ist. Beides sah gleich aus. GEMESSEN am
    # Bestand: 120 von 145 Datensaetzen tragen in Schwere UND Zustand NICHT MESSBAR, waehrend die
    # Zusicherung ueber die verbleibende Handvoll rechnete und `holds: true` meldete. Eine Aussage
    # ueber "0 offene P0/P1" spricht aber ueber die GANZE Menge, nicht ueber die Teilmenge, die
    # sich einstufen liess.
    #
    # NICHT EINGESTUFT IST WEDER HOCH NOCH NIEDRIG. Wer die Ungemessenen als "nicht P0/P1"
    # verbucht, hat sie stillschweigend freigesprochen; wer sie als offen zaehlt, erfindet Funde.
    # Der dritte Zustand ist der ehrliche: die Zusicherung ist UNBESTIMMT, und die Zahl der
    # Ungemessenen steht daneben. `holds` traegt dann None — kein `true`, das mehr behauptet, als
    # die Datenlage hergibt, und kein `false`, das einen Fund erfindet.
    ohne_einstufung = [r["id"] for r in records
                       if (r.get("severity") or {}).get("value") is None]
    bestimmbar = not ohne_einstufung
    grundgesamtheit = {
        "records_gesamt": len(records),
        "mit_schwere": len(records) - len(ohne_einstufung),
        "ohne_schwere": len(ohne_einstufung),
        "ohne_schwere_beispiele": ohne_einstufung[:8],
    }
    return [{
        "claim": "0 open P0/P1",
        "computed": {"p0_p1_total": len(hoch), "p0_p1_open": len(offen),
                     "entries": hoch, "open_entries": [h["id"] for h in offen],
                     "population": grundgesamtheit},
        "holds": (not offen) if bestimmbar else None,
        "holds_state": "MEASURED" if bestimmbar else "INDETERMINATE",
        "holds_reason": None if bestimmbar else (
            f"{len(ohne_einstufung)} of {len(records)} records carry no measured severity, so they "
            f"can be shown to be neither P0/P1 nor anything else; a claim about the whole "
            f"population cannot be established from the {len(records) - len(ohne_einstufung)} that "
            f"could be classified"),
        "prose_rationale_state": "REFUTED" if anmerkung else "NOT MEASURED",
        "prose_rationale_note": anmerkung,
    }]


def _gegenrechnung(ok: dict, records: list, repo=None) -> dict:
    """Die Fremdzaehlung GERECHNET — und gegen die Handzaehlung derselben Datei gehalten.

    DER DEFEKT, gemessen 2026-09-13. ``RESTRISIKO_600_OBJEKTKLASSEN.json`` traegt ZWEI
    richtige Zahlen: den historischen Stand der Fremdzaehlung (140 gleich, 0 fehlt, 2 zu
    viel — richtig fuer den 12.09. 13:16Z) und darunter ``gegen_den_heutigen_bestand``
    (140/0/5, richtig fuer heute, mit Begruendung je Kennung). Dieser Erzeuger reichte den
    OBEREN durch:

        "cross_count": ok.get("gegenrechnung_gegen_die_sollliste")

    Damit veroeffentlichten der Traeger und BEIDE Ansichten "2 extra", waehrend die
    aktuelle Zahl eine Ebene tiefer in derselben Datei stand. Nicht die Daten waren
    veraltet — der Leser griff in das falsche Fach. Die Probe, die es zeigt, ist eine
    Addition: 140 + 2 = 142, das Register traegt 145.

    ZWEITER TEIL DESSELBEN DEFEKTS, in der Ansicht: an die Liste war fest verdrahtet
    "named boundaries, not findings". Fuer G1/G2 stimmt das (zaehlt_als_fund = false);
    S121-S123 tragen zaehlt_als_fund = TRUE. Waere nur die Zahl korrigiert worden, haette
    der Satz drei FUNDE zu Grenzen erklaert. Eine Begruendung, die an einer variablen
    Liste klebt, wird irgendwann fuer etwas ausgesprochen, das sie nicht meint.

    DIE BAUART. Gerechnet wird aus der Kennungsliste der Fremdzaehlung, die die Eingabe
    mitfuehrt (``sollliste_kennungen``, gebunden ueber den bereits gefuehrten sha256).
    Die handgefuehrte Zahl ``gegen_den_heutigen_bestand`` bleibt stehen und wird NICHT
    ersetzt, sondern als ZWEITER LESER derselben Quelle dagegen gehalten: stimmen beide
    nicht ueberein, ist das Ergebnis ROT. Zwei Ableitungen mit verschiedener
    Fehlergeometrie sind billiger als eine Zahl, der man glauben muss — und das ist
    dieselbe Methode, die diesen Defekt gefunden hat.

    FAIL-CLOSED: fehlt die Kennungsliste, gibt es keine gerechnete Zahl, sondern
    NOT MEASURED mit Grund — nie ein stiller Rueckfall auf das historische Fach.
    """
    ein = ok.get("gegenrechnung_gegen_die_sollliste") or {}
    hand = ein.get("gegen_den_heutigen_bestand") or {}
    kopf = {
        "_auflage": ein.get("_auflage"),
        "quelle": ein.get("quelle"),
        "sha256_der_sollliste": ein.get("sha256_der_sollliste"),
        "stand_der_fremdzaehlung": ein.get("stand_der_fremdzaehlung"),
        "historisch": {k: ein.get(k) for k in ("gemessen_utc", "gleich", "fehlt", "zu_viel",
                                               "zu_viel_welche")},
    }
    soll = ein.get("sollliste_kennungen")
    if not isinstance(soll, list) or not soll:
        return {**kopf, "state": "NOT MEASURED",
                "reason": ("die Eingabe fuehrt keine Liste `sollliste_kennungen`; ohne sie "
                           "laesst sich gegen die Fremdzaehlung nicht RECHNEN, und der "
                           "historische Block waere ein Zitat aus einem frueheren Stand")}
    # LINSE 1, Nebenfund 13.09.2026: `sorted()` ueber eine Menge mit unvergleichbaren Typen
    # (None neben str, int neben str) warf einen ROHEN TypeError — und zwar in `baue_v2`, also
    # VOR `pruefe_v2`. Ein Riegel, der mit einem Traceback endet statt mit einem Urteil, hat
    # keinen NOT-MEASURED-Pfad; er hat gar keinen. Eine Kennung ist eine Zeichenkette, und was
    # keine ist, wird BENANNT statt stillschweigend zu einer gemacht.
    fremd = [x for x in soll if not isinstance(x, str)] + \
            [r.get("id") for r in records if not isinstance(r.get("id"), str)]
    if fremd:
        return {**kopf, "state": "NOT MEASURED",
                "reason": (f"{len(fremd)} Kennung(en) sind keine Zeichenketten "
                           f"({[type(x).__name__ for x in fremd[:4]]}); eine Gegenrechnung ueber "
                           f"gemischte Typen ist keine Messung, sondern ein Zufall der Sortierung")}
    # DER DIGEST DER SOLLLISTE WURDE DURCHGEREICHT, NIE GEPRUEFT (Codex r3999944593). Der Block
    # nennt `quelle` und `sha256_der_sollliste` nebeneinander, und beides las sich wie eine
    # gepruefte Herkunft. Gemessen: die Funktion oeffnet keine Datei. Wer die eingebettete Liste
    # aendert und den Digest stehen laesst, bekommt eine gruene Herkunftsaussage ueber Bytes, die
    # niemand gesehen hat.
    #
    # EHRLICH IST HIER DREI ZUSTAENDE, nicht zwei. Die genannte Quelle liegt in einem ANDEREN
    # Repository (globe/staging/incoming/… des Hauses), von hier aus also nicht erreichbar. Eine
    # Pruefung, die nicht stattfinden kann, darf nicht wie eine bestandene aussehen: liegt die
    # Datei vor, wird gerechnet; liegt sie nicht vor, steht NICHT MESSBAR mit Grund; weicht sie ab,
    # ist es ein Fehler.
    import hashlib as _h  # noqa: PLC0415
    _quelle = ein.get("quelle")
    _soll_digest = ein.get("sha256_der_sollliste")
    _p = (repo / _quelle) if (repo is not None and _quelle) else None
    if not _soll_digest:
        herkunft = {"zustand": "NICHT MESSBAR",
                    "grund": "the input block names no sha256 for the tally list"}
    elif _p is None or not _p.is_file():
        herkunft = {"zustand": "NICHT MESSBAR", "quelle": _quelle, "erwartet": _soll_digest,
                    "grund": ("the named source is not reachable from this repository; the "
                              "digest is therefore NOT presented as verified but passed on as "
                              "unverified")}
    else:
        _ist = _h.sha256(_p.read_bytes()).hexdigest()
        herkunft = ({"zustand": "GEPRUEFT", "quelle": _quelle, "sha256": _ist}
                    if _ist == _soll_digest else
                    {"zustand": "ABWEICHEND", "quelle": _quelle,
                     "erwartet": _soll_digest, "gemessen": _ist,
                     "grund": "the named source carries different bytes than the block claims"})
    soll_ids, reg_ids = set(soll), {r["id"] for r in records}
    zu_viel, fehlt = sorted(reg_ids - soll_ids), sorted(soll_ids - reg_ids)
    gruende = hand.get("zu_viel_welche_grund") or {}
    gerechnet = {
        "gerechnet_aus": {"sollliste": len(soll_ids), "register": len(reg_ids)},
        "gleich": len(soll_ids & reg_ids),
        "fehlt": len(fehlt), "fehlt_welche": fehlt,
        "zu_viel": len(zu_viel), "zu_viel_welche": zu_viel,
        "warum_zu_viel_je_kennung": {k: gruende.get(k) or "NOT EXPLAINED" for k in zu_viel},
    }
    # ZWEITER LESER: die handgefuehrte Zahl derselben Datei, gegen die gerechnete gehalten.
    abweichung = None
    if hand:
        anders = [f for f in ("gleich", "fehlt", "zu_viel")
                  if hand.get(f) != gerechnet[f]]
        wl = set(hand.get("zu_viel_welche") or [])
        if wl != set(zu_viel):
            anders.append("zu_viel_welche")
        abweichung = anders or None
    # DER ZWEITE LESER IST EIN ZUSTAND, KEIN None. Linse 2 hat am 13.09.2026 gezeigt, warum:
    # fehlte `gegen_den_heutigen_bestand`, stand hier `uebereinstimmung: None`, `pruefe_v2` prueft
    # auf `is False` — und BEIDE Ansichten meldeten "145 equal, 0 missing, 0 extra", ohne mit
    # einem Wort zu sagen, dass der zweite Leser nie lief. Die Abwesenheit einer Pruefung sah
    # aus wie ihr Bestehen. Genau die Klasse, gegen die dieses Feld gebaut ist.
    if not hand:
        zweiter = {"zustand": "FEHLT",
                   "grund": ("die Eingabe fuehrt keinen Block `gegen_den_heutigen_bestand`; diese "
                             "Zahl hat damit nur EINEN Leser und ist nicht gegengerechnet")}
    elif abweichung:
        zweiter = {"zustand": "UNEINIG", "abweichende_felder": abweichung,
                   "grund": "gerechnet und handgezaehlt sagen Verschiedenes"}
    else:
        zweiter = {"zustand": "EINIG", "abweichende_felder": None}
    return {**kopf, **gerechnet, "zweiter_leser": zweiter, "herkunft_der_sollliste": herkunft}


def pruefe_belege_auf_platte(doc, repo) -> list[str]:
    """Die Datei unter `path` oeffnen und gegen `sha256` halten. Leer heisst gruen.

    WARUM ES DIESE FUNKTION GIBT, gemessen 13.09.2026 beim Nachmessen von Feld 5 des
    Zitatpakets G1 (Auftrag `20260912T1242Z`): `pruefe_v2` rechnete den Digest gegen
    `quelle[von:bis]` und OEFFNETE DIE DATEI NIE, die der Traeger unter `path` nennt. Ein
    geloeschter oder veraenderter Beleg blieb gruen. Und weil `schreibe_v2` der Datei einen
    Herkunftskopf voranstellte, stimmte `sha256sum <path>` bei KEINEM der 145 Belege mit
    dem Feld daneben — 145 von 145 gemessen. Der Owner-Auftrag verlangt das Gegenteil:
    "Der Digest muss nach der Veroeffentlichung mit 6.1 von jedem nachrechenbar sein, ohne
    dass wir ihm erklaeren muessen, was wir gehasht haben."

    Deshalb traegt die Belegdatei jetzt GENAU die Bytes ihres Bereichs und nichts sonst.
    Die Herkunft steht im Traeger — in `source_path`, `source_sha256`, `byte_range` und
    `fundart` —, wo sie ohnehin schon stand. Zwei Traeger derselben Angabe driften; einer,
    der sich nachrechnen laesst, tut es nicht.
    """
    import hashlib  # noqa: PLC0415
    fehler = []
    for r in doc["records"]:
        for b in r.get("evidence", []):
            p = repo / b["path"]
            if not p.is_file():
                fehler.append(f"{r['id']}, Belegdatei fehlt: {b['path']}")
                continue
            ist = hashlib.sha256(p.read_bytes()).hexdigest()
            if ist != b["sha256"]:
                fehler.append(
                    f"{r['id']}, Belegdatei traegt einen anderen Digest als das Feld: "
                    f"Feld {b['sha256'][:12]}, Datei {ist[:12]}")
    return fehler


def _signatur_lage(doc) -> tuple[str, str]:
    """Der EINE Ausgang fuer die Frage, ob dieser Traeger echt ist.

    ANWESENHEIT IST KEINE PRUEFUNG, und genau das stand hier (Codex r4001142831, P2, am Kopf
    fc2bdc57 nachgestellt). `pruefe_v2` verlangte bei vorhandenem `sig_b64` nur, dass `alg` und
    `public_key_b64` DA sind, und `_signaturzeile` schrieb daraufhin "Signed, ed25519.".
    Gemessen: mit dem Block {"alg": "ed25519", "public_key_b64": "not base64",
    "sig_b64": "not a signature"} meldete der Pruefer NULL Fehler und die Ansicht nannte den
    Traeger signiert. Eine Faelschung aenderte kein einziges Urteil.

    Warum ein gemeinsamer Ausgang und nicht zwei Pruefungen. Pruefer und Ansicht beantworteten
    dieselbe Frage getrennt, und nur einer von beiden wurde spaeter geschaerft — das ist dieselbe
    Klasse eine Ebene hoeher. Wer hier etwas aendert, aendert es fuer beide.

    FAIL-CLOSED bei fehlender Bibliothek. Ohne `cryptography` ist die Signatur NICHT PRUEFBAR,
    und das ist ein Fehler, kein Bestehen. Ein Pruefer, der bei fehlendem Werkzeug gruen meldet,
    behauptet das Gegenteil dessen, was er gemessen hat.

    Rueckgabe: (zustand, detail). zustand ist FEHLT, UNSIGNED, VERIFIZIERT, GEBROCHEN oder
    NICHT_PRUEFBAR.
    """
    import binascii  # noqa: PLC0415
    s = doc.get("signature")
    if not isinstance(s, dict) or not s:
        return "FEHLT", "der Traeger sagt ueber seine Echtheit gar nichts"
    if not s.get("sig_b64"):
        return "UNSIGNED", str(s.get("state") or "UNKNOWN")
    if not (s.get("alg") and s.get("public_key_b64")):
        return "NICHT_PRUEFBAR", ("eine Signatur ohne Verfahren oder oeffentlichen Schluessel "
                                  "ist nicht pruefbar")
    if s.get("alg") != "ed25519":
        return "NICHT_PRUEFBAR", f"unbekanntes Verfahren: {s.get('alg')!r}"
    try:
        from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
            Ed25519PublicKey)
        from proofbundle._wire_b64 import decode_b64  # noqa: PLC0415
    except ImportError as e:
        return "NICHT_PRUEFBAR", (f"die Signaturbibliothek fehlt ({e.name}) — NICHT GEMESSEN, "
                                  f"und nicht gemessen ist keine Freigabe")
    try:
        pub = Ed25519PublicKey.from_public_bytes(decode_b64(s["public_key_b64"]))
        roh = decode_b64(s["sig_b64"])
    except (binascii.Error, ValueError) as e:
        return "GEBROCHEN", f"Signatur oder Schluessel ist kein kanonisches base64 ({e})"
    try:
        pub.verify(roh, canonical_bytes(doc))
    except InvalidSignature:
        return "GEBROCHEN", "die Signatur haelt ueber den kanonischen Rumpf nicht"
    return "VERIFIZIERT", str(s.get("alg"))


def pruefe_v2(doc, repo) -> list[str]:
    """STABILE CODES statt Prosa fuer die Gegenrechnungs-Meldungen (`[GR-...]`).

    Gemessen 13.09.2026 an einem eigenen Fehler: der Vertrag filterte mit
    `"tragfaehige Begruendung" in f` — einem Satzfragment. Beim naechsten Umbau aenderte sich
    der Satz, der Filter traf nichts mehr, und der Test meldete daraufhin „alle Platzhalter
    bestehen den Boden", obwohl der Boden sie fing. **Ein Orakel, das an Prosa haengt, misst die
    Schreibweise seines Gegenstands statt dessen Verhalten** — dieselbe Klasse, gegen die dieses
    Modul in derselben Nacht mehrfach umgebaut wurde. Wer die Meldungstexte aendert, darf die
    Codes NICHT aendern; sie sind der Vertrag, der Satz ist die Erklaerung.

    Die Regeln, die der Erzeuger erzwingt. Leer heisst, die Ausgabe darf entstehen.

    Uebernommen aus dem Strukturbeispiel vom 11.09. und um die Belegbindung erweitert: ein
    Beleg zaehlt nur, wenn seine Bytes noch die der Quelle sind — ein Byte genuegt.

    NACHTRAG 13.09.2026, gemessen: der Bytebereich wurde NIE auf Plausibilitaet geprueft,
    und Python schneidet klaglos. `roh[500:400]` und `roh[10_000_000:10_000_001]` ergeben
    beide `b''`, dessen sha256 die feste Konstante e3b0c442… ist — beides gemessen, beides
    ging durch diesen Pruefer OHNE Fehler. Ein Eintrag konnte damit einen Beleg fuehren,
    der NULL Bytes der Quelle traegt, und dabei den Digest korrekt fuehren. Gefunden von
    der Gegenlese-Linse vom 12.09., nachgemessen bevor er angenommen wurde. Im heutigen
    Bestand kommt er NICHT vor (145 von 145 Bereiche sind gesund) — das ist die FAEHIGKEIT
    eines falschen Bestehens, nicht sein Eintreten.
    """
    import hashlib  # noqa: PLC0415
    fehler = []
    for r in doc["records"]:
        kid = r["id"]
        if not r.get("evidence"):
            fehler.append(f"{kid}, kein Beleg")
        for b in r.get("evidence", []):
            if b.get("role") not in BELEGROLLE:
                fehler.append(f"{kid}, Belegrolle unbekannt: {b.get('role')!r}")
            q = repo / b["source_path"]
            if not q.is_file():
                fehler.append(f"{kid}, Quelle fehlt: {b['source_path']}")
                continue
            roh = q.read_bytes()
            if hashlib.sha256(roh).hexdigest() != b["source_sha256"]:
                fehler.append(f"{kid}, die Quelle hat sich seit dem Schnitt geaendert")
                continue
            br = b.get("byte_range")
            if (not isinstance(br, list) or len(br) != 2
                    or not all(isinstance(x, int) for x in br)):
                fehler.append(f"{kid}, Bytebereich ist kein Paar ganzer Zahlen: {br!r}")
                continue
            von, bis = br
            if not (0 <= von < bis <= len(roh)):
                fehler.append(
                    f"{kid}, Bytebereich unmoeglich: [{von}, {bis}] in einer Quelle von "
                    f"{len(roh)} B — ein leerer oder umgedrehter Schnitt ist kein Beleg")
                continue
            if hashlib.sha256(roh[von:bis]).hexdigest() != b["sha256"]:
                fehler.append(f"{kid}, Beleg veraendert — der Bytebereich traegt andere Bytes")
        if r["kind"] is None:
            if r.get("kind_state") not in LUECKENWOERTER:
                fehler.append(f"{kid}, Art fehlt ohne Lueckenwort")
            elif not r.get("kind_reason"):
                fehler.append(f"{kid}, Lueckenwort bei der Art ohne Grund")
        elif r["kind"] not in {"security", "quality"}:
            fehler.append(f"{kid}, Art unbekannt: {r['kind']!r}")
        if r["kind"] == "quality" and r.get("vex_statements"):
            fehler.append(f"{kid}, Qualitaetsfund mit VEX-Aussage")
        sev = r.get("severity") or {}
        if sev.get("value") is None and sev.get("state") not in LUECKENWOERTER:
            fehler.append(f"{kid}, Schwere fehlt ohne Lueckenwort")
        if sev.get("state") in LUECKENWOERTER and not sev.get("reason"):
            fehler.append(f"{kid}, Lueckenwort ohne Grund bei der Schwere")
        for feld in ("class_state", "last_measured_state"):
            if r.get(feld) and r[feld] not in LUECKENWOERTER:
                fehler.append(f"{kid}, {feld} ist kein Lueckenwort: {r[feld]!r}")
    inv = doc["inventory"]
    # DIE QUELL-DIGESTS DES INVENTARS WURDEN NIE NACHGERECHNET (Codex r3999918378, P1). Die
    # Belegeintraege tragen je einen `source_sha256`, und DER wird geprueft — aber
    # `inventory.source_documents[]` fuehrt eine ZWEITE Digestangabe ueber dieselben Dateien, und
    # sie stand in keiner Pruefung. Gemessen am Kopf d6b24ef war genau das eingetreten: der Traeger
    # nannte fuer RESTRISIKO_600_OBJEKTKLASSEN.json einen Digest, den die Datei nicht mehr trug,
    # und `pruefe_v2` meldete null Fehler. Zwei Angaben ueber dieselbe Sache, von denen nur eine
    # geprueft wird, driften — und die ungeprueftere ist die, die ein Leser zuerst sieht.
    # DIE INNERE HERKUNFTSANGABE WURDE NIE GEPRUEFT (Codex r4000054882). Der Erzeuger hasht die
    # Objektklassen-Datei als GANZES und uebernimmt ihre Aussage ueber die Bytes von
    # RESTRISIKO_600.md ungeprueft. Gemessen: 64 Nullen in `gemessen_an.sha256`, und der Lauf endet
    # mit 0 und meldet gruen — ein in sich widerspruechlicher Herkunftspfad mit gutem Urteil.
    # Eine Herkunft, die auf eine zweite Herkunft zeigt, ist erst geprueft, wenn beide es sind.
    try:
        _ok_h = json.loads((repo / OBJEKTKLASSEN_REL).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        fehler.append(f"Herkunft: {OBJEKTKLASSEN_REL} nicht lesbar ({type(e).__name__})")
        _ok_h = None
    if isinstance(_ok_h, dict):
        # KEINE AUSSAGE IST NICHT DASSELBE WIE EINE FALSCHE AUSSAGE, und die erste Fassung dieses
        # Riegels hat beides verwechselt. Sie verlangte den Block unbedingt und brach damit zwei
        # Vertraege, die einen MINIMALEN Wegwerf-Baum bauen, um eine ganz andere Eigenschaft zu
        # messen — deren Objektklassen-Datei fuehrt zu Recht nur `eintraege`. Die zwei roten Tests
        # hatten recht.
        #
        # Gefragt ist hier die WIDERSPRUCHSFREIHEIT einer vorhandenen Herkunftsangabe. Fehlt sie
        # ganz, gibt es nichts zu widerlegen. Dass der ECHTE Bestand sie fuehrt, ist eine eigene
        # Zusicherung und steht in tests/test_die_quellangaben_des_traegers_werden_nachgerechnet.py;
        # so kann sie weder hier still verschwinden noch dort unbemerkt falsch werden.
        _ga = _ok_h.get("gemessen_an")
        _d, _s = (_ga or {}).get("datei"), (_ga or {}).get("sha256")
        if _ga is None:
            pass                          # keine Herkunftsangabe, also keine widerspruechliche
        elif not _d or not _s:
            fehler.append("Herkunft: `gemessen_an` steht da, nennt aber keine Datei oder keinen "
                          "Digest — eine halbe Angabe ist nicht pruefbar")
        else:
            _p = repo / _d
            if not _p.is_file():
                fehler.append(f"Herkunft: `gemessen_an.datei` fehlt: {_d!r}")
            else:
                _ist = hashlib.sha256(_p.read_bytes()).hexdigest()
                if _ist != _s:
                    fehler.append(
                        f"Herkunft: {_d} traegt {_ist[:12]}, `gemessen_an.sha256` nennt "
                        f"{str(_s)[:12]} — die Objektklassen-Datei widerspricht sich ueber ihre "
                        f"eigene Quelle")
    # DIE ZEITMARKE WURDE NIE GEPRUEFT (Codex r3999621598). Gemessen: `--generated-at x` endet mit
    # 0 und meldet gruen, und der Traeger fuehrt danach `issued_at`, `generated_at` und
    # `assessment_cutoff` je als "x". Auch `2026-13-45T99:99:99Z` kommt durch — Monat 13, Tag 45,
    # Stunde 99. Eine strukturell ungueltige Registerform wird damit als erfolgreich geprueft
    # veroeffentlicht.
    #
    # GEPRUEFT WIRD MIT DEM VORHANDENEN PRUEFER, NICHT MIT EINEM ZWEITEN. `findings_register.py`
    # traegt `_freshness_error` seit Langem: Form, Zukunft und Alter in einer Funktion, mit dem
    # stabilen Code REGISTER_STALE. Ihn hier nachzubauen waere ein zweiter Erzeuger fuer dieselbe
    # Frage — genau die Klasse, die dieses Haus ausdruecklich verbietet, und ich bin ihr in dieser
    # Sitzung schon einmal aufgesessen. Deshalb importiert statt getippt.
    try:
        import importlib.util as _iu  # noqa: PLC0415
        _s = _iu.spec_from_file_location("_fr_frische", REPO / "scripts" / "findings_register.py")
        _fr = _iu.module_from_spec(_s)
        _s.loader.exec_module(_fr)
        _zeitfehler = _fr._freshness_error({"generated_at": doc.get("generated_at")})
    except Exception as e:  # noqa: BLE001 — ohne Pruefer kein Urteil, und das ist keine Freigabe
        _zeitfehler = (f"die Zeitmarke ist NICHT PRUEFBAR ({type(e).__name__}: {e}) — "
                       f"scripts/findings_register.py traegt den Pruefer, er ist hier nicht ladbar")
    if _zeitfehler:
        fehler.append(f"Zeitmarke: {_zeitfehler}")
    # DIE ECHTHEITSAUSKUNFT GEHT INS URTEIL EIN (Codex 3999796576). Ein Block, der nur
    # dasteht, ist eine Notiz; gefordert ist ein BEKANNTER Zustand mit Grund, und wenn eine
    # Signatur behauptet wird, muessen ihre Teile auch da sein.
    _sig = doc.get("signature")
    _zustand, _detail = _signatur_lage(doc)
    if _zustand == "FEHLT":
        fehler.append(f"Signatur: {_detail}")
    elif _zustand == "NICHT_PRUEFBAR":
        fehler.append(f"Signatur: {_detail}")
    elif _zustand == "GEBROCHEN":
        fehler.append(f"Signatur: sie ist da und sie haelt nicht — {_detail}")
    elif _zustand == "VERIFIZIERT":
        pass
    else:
        if _sig.get("state") not in ("UNSIGNED", *LUECKENWOERTER):
            fehler.append(f"Signatur: unbekannter Zustand ({_sig.get('state')!r})")
        if not _sig.get("reason"):
            fehler.append("Signatur: ein Zustand ohne Grund ist eine leere Marke")
        if _sig.get("state") == "UNSIGNED" and not _sig.get("consequence_for_the_reader"):
            fehler.append("Signatur: UNSIGNED ohne die Folge fuer den Leser — wer die Einschraenkung "
                          "nicht nennt, veroeffentlicht sie auch nicht")
    _bg = doc.get("assessment_cutoff")
    if isinstance(_bg, dict):
        if _bg.get("state") not in LUECKENWOERTER or not _bg.get("reason"):
            fehler.append("Bewertungsgrenze: Lueckenwort ohne Grund")
    elif not isinstance(_bg, str) or not _bg:
        fehler.append(f"Bewertungsgrenze: weder Datum noch Lueckenwort ({_bg!r})")
    else:
        # NICHTLEER IST KEIN DATUM (Codex 4000140173). Bis hierher genuegte eine nichtleere
        # Zeichenkette, und damit kam "2026-99-99" durch den Pruefer wie durch den Erzeuger.
        # Der Erzeuger prueft jetzt am Kalender; dieser Riegel tut es AUCH, denn er urteilt ueber
        # einen fertigen Traeger, der nicht aus diesem Erzeuger stammen muss.
        import datetime as _dt2  # noqa: PLC0415
        try:
            _dt2.date.fromisoformat(_bg)
        except ValueError:
            fehler.append(f"Bewertungsgrenze: {_bg!r} hat die Form eines Datums, ist aber keines "
                          f"im Kalender")
    for q in inv.get("source_documents") or []:
        p = repo / q.get("path", "")
        if not p.is_file():
            fehler.append(f"Inventar: Quelle fehlt: {q.get('path')!r}")
            continue
        ist = hashlib.sha256(p.read_bytes()).hexdigest()
        if ist != q.get("sha256"):
            fehler.append(
                f"Inventar: {q.get('path')} traegt {ist[:12]}, der Traeger nennt "
                f"{str(q.get('sha256'))[:12]} — der Traeger ist nicht neu erzeugt worden")
    if inv["identifiers_in_this_register"] + len(inv["identifiers_without_evidence"]) \
            != inv["identifiers_total"]:
        fehler.append("Inventar: getragen + ohne Beleg != gesamt")
    for g in inv["coverage_gaps"]:
        if g["state"] not in LUECKENWOERTER:
            fehler.append(f"Luecke {g['range']}: Zustand ist kein Lueckenwort")
        if not g.get("reason"):
            fehler.append(f"Luecke {g['range']}: ohne Grund")
    # Die Gegenrechnung muss AUFGEHEN. Eine Kennung ist in der Fremdzaehlung oder nicht —
    # ein drittes Fach gibt es nicht, und die Summe ist der billigste Riegel dagegen, dass
    # eine gerechnete Zahl wieder zu einer zitierten wird.
    cc = inv.get("cross_count") or {}
    if cc.get("state") in LUECKENWOERTER:
        if not cc.get("reason"):
            fehler.append("[GR-LUECKENWORT] Lueckenwort ohne Grund")
    elif cc:
        g, z = cc.get("gleich"), cc.get("zu_viel")
        if not isinstance(g, int) or not isinstance(z, int):
            fehler.append(f"[GR-ARITHMETIK] gleich/zu_viel sind keine Zahlen ({g!r}/{z!r})")
        elif g + z != inv["identifiers_in_this_register"]:
            fehler.append(
                f"[GR-ARITHMETIK] geht nicht auf: gleich {g} + zu viel {z} = {g + z}, "
                f"das Register traegt {inv['identifiers_in_this_register']}")
        # ZWEI ITERATIONEN AN DIESER EINEN PRUEFUNG, und die zweite ist die lehrreichere.
        #
        # Iteration 1 (Linse 1, Z5): `if not v or v == "NOT EXPLAINED"` liess ' ', '-', 'TODO',
        # 'n/a', 'x' und 'siehe oben' durch — es pruefte Anwesenheit, nicht Inhalt.
        #
        # Iteration 2 (Re-Gate, Linse 1): mein ERSATZ — Laenge >=25 UND Wortzahl >=4 — ist in
        # BEIDEN Richtungen falsifiziert, beides ausgefuehrt gemessen:
        #   falsch NEGATIV: 'aaaa bbbb cccc dddd eeee ffff', 'G1 G1 G1 …', Lorem ipsum und ein
        #     wortwoertlich aus diesem Docstring kopierter Satz bestehen alle.
        #   falsch POSITIV: 'S121 postdates 2026-09-12T13:16Z' (3 Woerter), ein vollstaendiger
        #     chinesischer Satz (str.split() zaehlt EIN Wort) und das im Haus uebliche
        #     durchgekoppelte Format 'Nachtragsaufnahme-am-…' werden zu Unrecht geblockt.
        # Die Wortzahl faellt deshalb ERSATZLOS: sie hat gemessenen Schaden und keinen gemessenen
        # Nutzen — jeder der vier sinnfreien Faelle hat Woerter im Ueberfluss.
        #
        # DIE GRENZE, und sie wird hier nicht mehr verhandelt: ob eine Begruendung WAHR ist, ist
        # aus ihrem Text nicht entscheidbar. Lorem ipsum und ein kopierter Satz bleiben ungefangen,
        # und das ist KEIN Versehen, sondern die ehrliche Reichweite. Noch eine Formregel
        # draufzusetzen waere derselbe Fehler eine Ebene tiefer — genau die Klasse, wegen der
        # dieses Modul in derselben Nacht dreimal umgebaut wurde.
        #
        # Was die Pruefung WIRKLICH leistet, und nur das behauptet sie:
        #   1. kein Platzhalter (leer, Lueckenwort, zu kurz — Zeichen, nicht Woerter),
        #   2. nicht die Kennung selbst,
        #   3. nicht EIN Token, das sich wiederholt.
        #
        # ITERATION 3, und sie kam von den EIGENEN DATEN, nicht von einer Linse: ich hatte hier
        # zusaetzlich verlangt, dass keine zwei Kennungen dieselbe Begruendung tragen ("Kopieren
        # ist mechanisch entscheidbar"). Gegen den LIVE-Bestand gemessen fiel die Regel sofort:
        # G1 und G2 tragen byte-identische Begruendungen — und zwar zu Recht, denn sie haben
        # denselben Grund ("G-Kennungen sind keine Funde, die Fremdzaehlung kennt das Praefix G
        # nicht"). Eine geteilte Begruendung ist von einer kopierten NICHT unterscheidbar; die
        # Regel war also nie eine Messung, sondern eine Annahme ueber die Daten. Sie ist ersatzlos
        # weg. Dritte Fassung dieser einen Pruefung, und jede der ersten beiden hat etwas
        # Gesundes geblockt oder etwas Krankes durchgelassen — deshalb steht die Reichweite
        # jetzt ausdruecklich im Text statt in der Hoffnung.
        gruende = cc.get("warum_zu_viel_je_kennung") or {}
        ohne = []
        for k, v in gruende.items():
            t = (v or "").strip() if isinstance(v, str) else ""
            marken = []
            if not t or t == "NOT EXPLAINED":
                marken.append("leer/Lueckenwort")
            elif len(t) < 25:
                marken.append(f"zu kurz ({len(t)} Zeichen)")
            if t and t == k:
                marken.append("ist die Kennung selbst")
            wort = t.split()
            if wort and len(set(wort)) == 1 and len(wort) > 2:
                marken.append("EIN Token, wiederholt")
            if marken:
                ohne.append(f"{k}: {', '.join(marken)}")
        if ohne:
            fehler.append(
                f"[GR-BEGRUENDUNG] {ohne} — der Boden schliesst Platzhalter, Selbstbezug und "
                f"Wiederholungen aus; ob die Begruendung STIMMT, prueft er ausdruecklich NICHT")
        # RE-GATE, LINSE 2, FALL 6 — der schwerste Fund dieser Runde, und er ist strukturell:
        # dieser Pruefer las den Traeger und prueft seine FORM, nie seine HERLEITUNG. Gemessen,
        # ausgefuehrt: ein von Hand gefaelschter `cross_count` (gleich=100, zu_viel=45 mit 45
        # ERFUNDENEN Kennungen, `zweiter_leser: EINIG`; echt waren 140/5) bestand `pruefe_v2` mit
        # NULL Fehlern — und der zugehoerige Vertrag lief gruen mit, weil er denselben
        # gespeicherten Wert laedt, den er pruefen soll. Ein Pruefer, der das Artefakt liest,
        # das er beglaubigen soll, beglaubigt eine Faelschung genauso bereitwillig wie das Echte.
        #
        # Zweiter Fund derselben Runde (Fall 4b): verglichen wurden `gleich`, `fehlt`, `zu_viel`
        # und `zu_viel_welche` — `fehlt_welche` NIE (ein einziger Codetreffer, seine eigene
        # Erzeugung). Die Zahl konnte stimmen und die benannte Kennung falsch sein.
        #
        # BEIDE schliesst dieselbe Massnahme: NEU ABLEITEN und Feld fuer Feld vergleichen, statt
        # dem Traeger zu glauben. Was neu abgeleitet werden kann, wird nicht geglaubt.
        #
        # WAS DIESE MASSNAHME NICHT LEISTET, ausgefuehrt gemessen im Re-Gate Iteration 3, Linse 1:
        # sie leitet aus einer Datei ab, die im SELBEN Repo liegt wie der Traeger. Wer beide
        # konsistent faelscht — drei erfundene Kennungen im Traeger UND den Eingabeblock mit
        # derselben Funktion sauber nachgerechnet — kommt mit NULL Fehlern durch. Nur die HALB
        # gefaelschte Fassung wurde gefangen ([GR-ZWEITER-LESER] UNEINIG).
        #
        # Das Urteil der Linse, woertlich uebernommen, weil es stimmt: die Neuableitung ist ein
        # ANKER gegen unbeabsichtigtes Driften (Veralten, halbe Bearbeitung) und eine ZEREMONIE
        # gegen einen Angreifer, der den ganzen Baum kontrolliert. Ein echter Anker muesste aus
        # einer UNABHAENGIGEN Quelle stammen — signiert, versioniert oder von aussen gehalten.
        # Das ist hier NICHT gebaut, und der Unterschied gehoert an diese Stelle statt in einen
        # Bericht, den beim Aendern niemand liest.
        #
        # KOSTEN, gemessen statt gefuerchtet: der zweite Aufruf kostet rund 0,025 ms, etwa
        # 0,004 % der Gesamtlaufzeit von `schreibe_v2`. Ueber 95 % gehen an `schneide_beleg`.
        try:
            import json as _j  # noqa: PLC0415
            _ok = _j.loads((repo / OBJEKTKLASSEN_REL).read_text(encoding="utf-8"))
            # RE-GATE ITERATION 3, LINSE 1, ACHSE C: ein syntaktisch gueltiges JSON mit falschem
            # Toplevel (`[]`) liess `_ok.get(...)` mit AttributeError platzen — die entkam der
            # Klausel darunter, und `pruefe_v2` endete mit einem TRACEBACK statt mit einem Urteil.
            # DIESELBE KLASSE HATTE ICH IN ITERATION 2 GESCHLOSSEN — in `_gegenrechnung`, nicht
            # hier. Eine Klasse an EINEM Ort zu schliessen heisst nicht, sie geschlossen zu haben;
            # der zweite Ort war der, der die Datei selbst laedt.
            if not isinstance(_ok, dict):
                raise TypeError(f"Toplevel ist {type(_ok).__name__}, erwartet ein Objekt")
            _neu = _gegenrechnung(_ok, doc["records"], repo)
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            fehler.append(f"[GR-NEUABLEITUNG] nicht neu ableitbar ({type(e).__name__}: {e}) — "
                          f"ohne Neuableitung ist der Block eine Behauptung")
            _neu = None
        if _neu is not None:
            _abw = [f for f in ("gleich", "fehlt", "zu_viel", "fehlt_welche", "zu_viel_welche",
                                "warum_zu_viel_je_kennung", "state")
                    if cc.get(f) != _neu.get(f)]
            if _abw:
                fehler.append(
                    f"[GR-NEUABLEITUNG] der Traeger weicht ab in {_abw} — "
                    f"Traeger sagt gleich={cc.get('gleich')} zu_viel={cc.get('zu_viel')}, neu "
                    f"abgeleitet gleich={_neu.get('gleich')} zu_viel={_neu.get('zu_viel')}. Ein "
                    f"gespeicherter Block, der sich nicht nachrechnen laesst, ist eine Behauptung")
            _zl_neu = (_neu.get("zweiter_leser") or {}).get("zustand")
            if (cc.get("zweiter_leser") or {}).get("zustand") != _zl_neu:
                fehler.append(
                    f"[GR-ZWEITER-LESER] der Traeger meldet den zweiten Leser als "
                    f"{(cc.get('zweiter_leser') or {}).get('zustand')!r}, neu abgeleitet ist er "
                    f"{_zl_neu!r} — ein Etikett ohne Ableitungspfad")

        zl = cc.get("zweiter_leser") or {}
        if zl.get("zustand") == "UNEINIG":
            fehler.append(
                f"[GR-ZWEITER-LESER] gerechnet und handgezaehlt sind sich uneinig in "
                f"{zl.get('abweichende_felder')} — zwei Leser derselben Quelle, und "
                f"solange sie sich widersprechen, gilt keine der beiden Zahlen")
        if zl.get("zustand") not in ("EINIG", "UNEINIG", "FEHLT"):
            fehler.append(f"[GR-ZWEITER-LESER] der zweite Leser traegt keinen Zustand ({zl!r})")
        # Linse 2, zweiter Fund: fehlte `warum_zu_viel_je_kennung` GANZ (statt leer), gab
        # pruefe_v2 null Fehler und beide Ansichten liessen die Begruendungszeilen still weg.
        # Eine fehlende Liste ist keine leere Liste, sie ist eine unbeantwortete Frage.
        if cc.get("zu_viel") and cc.get("warum_zu_viel_je_kennung") is None:
            fehler.append(
                f"Gegenrechnung: {cc['zu_viel']} ueberzaehlige Kennungen, aber das Feld "
                f"`warum_zu_viel_je_kennung` fehlt GANZ — keine leere Antwort, sondern keine")
        # EIN GESCHRIEBENER WIDERSPRUCH IST KEINE ERLEDIGTE PRUEFUNG (Codex 4000140176).
        #
        # GEMESSEN am 13.09.2026: liegen an der genannten Sollliste andere Bytes, schreibt dieser
        # Block sauber `zustand: ABWEICHEND` in den Traeger — und `schreibe_v2` endet trotzdem mit
        # 0, meldet "gruen", schreibt Traeger UND Ansichten, und `pruefe_v2` gibt null Fehler
        # zurueck. Die Herkunft war damit nachweislich gebrochen und die Veroeffentlichung trotzdem
        # erfolgreich. Ein Zustand, der nur SERIALISIERT wird, ohne in das Urteil einzugehen, ist
        # eine Notiz, kein Riegel.
        #
        # DIE DREI ZUSTAENDE BLEIBEN DREI, und nur EINER ist ein Fehler: GEPRUEFT ist gut,
        # NICHT MESSBAR ist ein deklarierter blinder Fleck MIT Grund (die Quelle liegt in einem
        # anderen Repository und ist von hier aus nicht erreichbar), ABWEICHEND dagegen heisst:
        # die Quelle IST da und sagt etwas anderes. Genau dieser eine Fall bricht.
        h = cc.get("herkunft_der_sollliste") or {}
        hz = h.get("zustand")
        if hz == "ABWEICHEND":
            fehler.append(
                f"[GR-HERKUNFT] die genannte Sollliste {h.get('quelle')!r} ist erreichbar und "
                f"traegt ANDERE Bytes als der Block behauptet (erwartet "
                f"{str(h.get('erwartet'))[:12]}…, gemessen {str(h.get('gemessen'))[:12]}…) — eine "
                f"gebrochene Herkunft faehrt nicht als Randnotiz in einer erfolgreichen "
                f"Veroeffentlichung mit")
        elif hz not in ("GEPRUEFT", "NICHT MESSBAR"):
            fehler.append(f"[GR-HERKUNFT] die Herkunft der Sollliste traegt keinen bekannten "
                          f"Zustand ({hz!r})")
        elif hz == "NICHT MESSBAR" and not h.get("grund"):
            fehler.append("[GR-HERKUNFT] NICHT MESSBAR ohne Grund ist eine leere Marke")
    return fehler


# ── DIE ANSICHTEN: erzeugt, nie von Hand geschrieben ───────────────────────────────────────

def _offen(r) -> bool:
    """Offen heisst: eine Quelle sagt es. Ein unbekannter Zustand ist NICHT offen und nicht zu.

    Die alte Fassung riet fuer jede Kennung ausserhalb von FINDINGS aus Schwere und Rolle. Gemessen
    machte sie A4, in der Quelle ausdruecklich `closed`, zu einem offenen P1 in der Ansicht.
    """
    # EINE DEKLARIERTE NICHT-ABWEICHUNG IST KEIN OFFENER PUNKT (Codex 4000176743). Der Zustand
    # sagt, ob die HANDLUNG offen ist; ob ueberhaupt ein Defekt vorliegt, sagt die deklarierte
    # Ausnahme. Beides zu vermengen fuehrt in die eine oder die andere Richtung in die Irre.
    if ((r.get("not_a_defect") or {}).get("value")):
        return False
    st = r.get("status") or {}
    if st.get("value") in ("open", "closed"):
        return st["value"] == "open"
    return False


def _grenze_als_text(bg) -> str:
    """Die Bewertungsgrenze fuer eine Ansicht — ein Lueckenwort wird ANGEZEIGT, nicht verschwiegen.

    Die erste Fassung reichte den Wert ungeprueft an die Ansichten weiter und liess sie mit einem
    AttributeError platzen, sobald er das Lueckenwort war. Gefunden von zwei bestehenden Vertraegen,
    die einen minimalen Baum ohne Herkunftsangabe bauen. Ein Lueckenwort, das eine Ansicht zum
    Absturz bringt, ist schlechter als eine falsche Zahl: es macht den ehrlichen Zustand
    unbenutzbar und draengt zurueck zur Uhr des Laufs.
    """
    if isinstance(bg, dict):
        return f"{bg.get('state', 'NOT MEASURED')} ({bg.get('reason', '')[:120]})"
    return str(bg)


def _signaturzeile(doc) -> str:
    """Eine Zeile ueber die Echtheit — in BEIDEN Ansichten, aus EINER Quelle.

    Ein Leser, der nur die Ansicht sieht, konnte bisher nicht wissen, dass der Traeger
    unsigniert ist. Eine Herkunftsangabe, die nur im Rohdokument steht, erreicht ihn nicht.
    """
    s = doc.get("signature") or {}
    lage, detail = _signatur_lage(doc)
    if lage == "VERIFIZIERT":
        return f"Signed and verified against the canonical body, {detail}."
    if lage == "GEBROCHEN":
        return ("A signature is present and it does NOT verify against the canonical body. "
                "Treat this carrier as unauthenticated.")
    if lage == "NICHT_PRUEFBAR":
        return (f"A signature is present but it could not be checked here ({detail}). "
                f"Not checked is not verified.")
    zustand = s.get("state") or "UNKNOWN"
    grund = s.get("reason") or "no reason given"
    folge = s.get("consequence_for_the_reader")
    return f"Signature, {zustand} — {grund}." + (f" {folge[0].upper()}{folge[1:]}." if folge else "")


def ansicht_uebersicht(doc) -> str:
    sub, inv = doc["release_subject"], doc["inventory"]
    z = [f"# Known remainders, {sub['name']} {sub['version']}", "",
         f"Tag {sub['tag']}, assessment cutoff {_grenze_als_text(doc['assessment_cutoff'])}, "
         f"register revision {doc['register_revision']}.",
         f"Coverage, {inv['identifiers_in_this_register']} of {inv['identifiers_total']} "
         f"identifiers carried in this register.",
         _signaturzeile(doc), ""]
    for g in inv["coverage_gaps"]:
        z.append(f"Known gap, {g['range']}, {g['count']} identifiers, {g['state']}, {g['reason']}")
    cc = inv.get("cross_count") or {}
    if cc.get("state"):
        z += ["", f"Cross-count against the independent tally: {cc['state']} — {cc.get('reason')}"]
    elif cc:
        z += ["", f"Cross-count against the independent tally, computed: {cc.get('gleich')} equal, "
                  f"{cc.get('fehlt')} missing, {cc.get('zu_viel')} extra."]
        # JE KENNUNG, nicht als Sammelsatz. Der frueher hier fest verdrahtete Zusatz
        # "named boundaries, not findings" war fuer G1/G2 richtig und haette S121-S123,
        # die zaehlt_als_fund=true tragen, als Grenzen ausgewiesen.
        for k, warum in (cc.get("warum_zu_viel_je_kennung") or {}).items():
            z.append(f"  extra `{k}`: {warum}")
        zl = cc.get("zweiter_leser") or {}
        if zl.get("zustand") == "EINIG":
            z.append("  Second reader (hand tally in the same file): agrees.")
        else:
            z.append(f"  Second reader: **{zl.get('zustand', 'UNKNOWN')}** — "
                     f"{zl.get('grund') or zl.get('abweichende_felder')}")
    for a in inv.get("assurance_checks") or []:
        _m = ("holds" if a.get("holds") else
              "INDETERMINATE" if a.get("holds") is None else "DOES NOT HOLD")
        z += ["", f"Assurance `{a['claim']}`: **{_m}**, "
                  f"computed — {a['computed']['p0_p1_total']} P0/P1 in the source, "
                  f"{a['computed']['p0_p1_open']} open."]
        if a.get("prose_rationale_state") == "REFUTED":
            z.append("  The prose rationale in the source is REFUTED by the source's own table; "
                     "the claim is carried here because it is COMPUTED, not quoted.")
    z += ["", "## All records", "",
          "| Id | Role | Class | Severity | Evidence | Bytes |", "|---|---|---|---|---|---|"]
    for r in doc["records"]:
        sev = r["severity"].get("value") or r["severity"].get("state")
        b = r["evidence"][0]
        z.append(f"| {r['id']} | {r['record_role']} | {r.get('objektklasse','')} | {sev} "
                 f"| {b['path']} | {b['byte_range'][0]}..{b['byte_range'][1]} |")
    z += ["", f"Generated from {V2_REL}. Do not edit by hand.", ""]
    return "\n".join(z)


def ansicht_known_issues(doc) -> str:
    z = [f"### Known issues, {doc['release_subject']['version']}", ""]
    for r in doc["records"]:
        if not _offen(r):
            continue
        sev = r["severity"].get("value") or r["severity"].get("state")
        z.append(f"* {r['id']} ({sev}), {r['title'][:160]}")
    z += ["", "Generated from the findings register. The register carries the rest.", ""]
    return "\n".join(z)


def ansicht_html(doc) -> str:
    import html as _h  # noqa: PLC0415
    sub, inv = doc["release_subject"], doc["inventory"]
    zeilen = []
    for r in doc["records"]:
        sev = r["severity"].get("value") or r["severity"].get("state")
        b = r["evidence"][0]
        klasse = "gap" if sev and sev.startswith("NOT") else "val"
        zeilen.append(
            f"<tr><td class=id>{_h.escape(r['id'])}</td>"
            f"<td>{_h.escape(r['record_role'])}</td>"
            f"<td>{_h.escape(str(r.get('objektklasse') or ''))}</td>"
            f"<td class={klasse}>{_h.escape(str(sev))}</td>"
            f"<td class=t>{_h.escape(r['title'][:150])}</td>"
            f"<td class=n>{b['byte_range'][0]}..{b['byte_range'][1]}</td></tr>")
    luecken = "".join(
        f"<li><b>{_h.escape(g['range'])}</b> ({g['count']}) — <span class=gap>{_h.escape(g['state'])}</span>: "
        f"{_h.escape(g['reason'][:300])}</li>" for g in inv["coverage_gaps"])
    # DIE GEGENRECHNUNG STAND IN DIESER ANSICHT GAR NICHT — gemessen 13.09.2026. Die
    # Markdown-Ansicht fuehrte sie, die HTML-Ansicht nicht, und der Owner liest die HTML.
    # Eine Auflage, die nur in der Ansicht erfuellt ist, die niemand oeffnet, ist offen.
    cc = inv.get("cross_count") or {}
    if cc.get("state"):
        kreuz = (f"<h2>Cross-count</h2><p class=warn>{_h.escape(cc['state'])} — "
                 f"{_h.escape(str(cc.get('reason') or ''))}</p>")
    elif cc:
        je = "".join(
            f"<li><b>{_h.escape(k)}</b> — {_h.escape(str(v))}</li>"
            for k, v in (cc.get("warum_zu_viel_je_kennung") or {}).items())
        kreuz = (f"<h2>Cross-count against the independent tally</h2>"
                 f"<p>Computed from {cc.get('gerechnet_aus', {}).get('sollliste')} tallied "
                 f"identifiers against {cc.get('gerechnet_aus', {}).get('register')} carried: "
                 f"<b>{cc.get('gleich')}</b> equal, <b>{cc.get('fehlt')}</b> missing, "
                 f"<b>{cc.get('zu_viel')}</b> extra.</p>"
                 + (f"<ul>{je}</ul>" if je else ""))
        zl = cc.get("zweiter_leser") or {}
        if zl.get("zustand") == "EINIG":
            kreuz += "<p>Second reader (hand tally in the same file): <b>agrees</b>.</p>"
        else:
            kreuz += (f"<p class=warn>Second reader: <b>{_h.escape(str(zl.get('zustand','UNKNOWN')))}"
                      f"</b> — {_h.escape(str(zl.get('grund') or zl.get('abweichende_felder')))}</p>")
    else:
        kreuz = ""
    zus = ""
    for a in inv.get("assurance_checks") or []:
        marke = ("holds" if a.get("holds") else
                 "INDETERMINATE" if a.get("holds") is None else "DOES NOT HOLD")
        zus += (f"<p>Assurance <code>{_h.escape(a['claim'])}</code>: <b>{marke}</b>, computed — "
                f"{a['computed']['p0_p1_total']} P0/P1 in the source, {a['computed']['p0_p1_open']} open.</p>")
        if a.get("prose_rationale_note"):
            zus += f"<p class=warn>{_h.escape(a['prose_rationale_note'])}</p>"
    return f"""<!doctype html><meta charset=utf-8>
<title>Findings register {_h.escape(sub['name'])} {_h.escape(sub['version'])}</title>
<style>
 body{{font:14px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:72rem;padding:0 1rem;color:#111}}
 h1{{font-size:1.4rem;margin:0 0 .3rem}} .sub{{color:#666;margin:0 0 1.5rem}}
 table{{border-collapse:collapse;width:100%;font-size:13px}}
 th,td{{border-bottom:1px solid #e5e5e5;padding:.4rem .5rem;text-align:left;vertical-align:top}}
 th{{background:#fafafa;position:sticky;top:0}} .id{{font-family:ui-monospace,monospace;white-space:nowrap}}
 .n{{font-family:ui-monospace,monospace;color:#666;white-space:nowrap}} .t{{max-width:40rem}}
 .gap{{color:#8a6d00;background:#fff8e1;padding:0 .3rem;border-radius:3px;white-space:nowrap}}
 .val{{font-weight:600}} .warn{{background:#fff4f4;border-left:3px solid #c33;padding:.6rem .8rem}}
 ul{{padding-left:1.2rem}} code{{background:#f4f4f4;padding:0 .25rem;border-radius:3px}}
</style>
<h1>Known remainders — {_h.escape(sub['name'])} {_h.escape(sub['version'])}</h1>
<p class=sub>Tag {_h.escape(sub['tag'])} · cutoff {_h.escape(_grenze_als_text(doc['assessment_cutoff']))} ·
 revision {doc['register_revision']} ·
 {inv['identifiers_in_this_register']} of {inv['identifiers_total']} identifiers carried</p>
<p class=warn>{_h.escape(_signaturzeile(doc))}</p>
{zus}
<h2>Known gaps</h2><ul>{luecken}</ul>
{kreuz}
<h2>All records</h2>
<table><thead><tr><th>Id<th>Role<th>Class<th>Severity<th>Title<th>Bytes</tr></thead>
<tbody>{''.join(zeilen)}</tbody></table>
<p class=sub>Generated from {_h.escape(V2_REL)}. Do not edit by hand.</p>
"""


def schreibe_v2(repo, generated_at: str, revision: int = 0) -> dict:
    """Prueft erst, schreibt dann. Bei einem Verstoss KEINE Teilausgabe."""
    import json as _json  # noqa: PLC0415
    doc = baue_v2(repo, generated_at, revision)
    fehler = pruefe_v2(doc, repo)
    if fehler:
        for f in fehler:
            print("ROT,", f)
        raise SystemExit(f"Erzeugung abgebrochen, {len(fehler)} Verstoesse, keine Teilausgabe")

    roh = (repo / RESTRISIKO_REL).read_bytes()
    ev = repo / EVIDENZ_REL
    ev.mkdir(parents=True, exist_ok=True)
    for r in doc["records"]:
        b = r["evidence"][0]
        von, bis = b["byte_range"]
        # GENAU die Bytes des Bereichs, nichts davor, nichts dahinter. Der fruehere
        # Herkunftskopf machte `sha256sum <path>` bei allen 145 Belegen unbrauchbar.
        (ev / f"{r['id']}.md").write_bytes(roh[von:bis])

    # ERST GEGENRECHNEN, DANN DEN TRAEGER SCHREIBEN. Faellt das hier, entsteht kein
    # Traeger, der auf Dateien zeigt, die etwas anderes tragen als er behauptet.
    auf_platte = pruefe_belege_auf_platte(doc, repo)
    if auf_platte:
        for f in auf_platte:
            print("ROT,", f)
        raise SystemExit(
            f"Erzeugung abgebrochen, {len(auf_platte)} Belege auf Platte weichen ab, "
            f"kein Traeger geschrieben")

    (repo / V2_REL).parent.mkdir(parents=True, exist_ok=True)
    (repo / V2_REL).write_text(_json.dumps(doc, indent=2, ensure_ascii=False) + "\n",
                               encoding="utf-8")
    an = repo / ANSICHTEN_REL
    an.mkdir(parents=True, exist_ok=True)
    (an / "uebersicht.md").write_text(ansicht_uebersicht(doc), encoding="utf-8")
    (an / "known_issues.md").write_text(ansicht_known_issues(doc), encoding="utf-8")
    (an / "uebersicht.html").write_text(ansicht_html(doc), encoding="utf-8")
    print(f"gruen, {len(doc['records'])} Eintraege")
    print(f"  Traeger   -> {V2_REL}")
    print(f"  Belege    -> {EVIDENZ_REL}/ ({len(doc['records'])} Dateien)")
    print(f"  Ansichten -> {ANSICHTEN_REL}/ (uebersicht.md, known_issues.md, uebersicht.html)")
    return doc


def build_register(generated_at: str) -> dict:
    return {
        "schema": "proofbundle.findings_register.v1",
        "version": VERSION,
        "generated_at": generated_at,
        "findings": FINDINGS,
    }


def canonical_bytes(body: dict) -> bytes:
    """The exact bytes signed and verified: RFC-8785 over the body WITHOUT the signature wrapper."""
    return canonical.canonicalize_statement({k: v for k, v in body.items() if k != "signature"})


def assemble(body: dict, sig_b64: str, signer_pubkey_b64: str) -> dict:
    """Wrap an externally produced signature. REFUSES on a mismatch — fail-closed, so a bad
    signature/body pair never becomes a register on disk."""
    import binascii  # noqa: PLC0415
    from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
        Ed25519PublicKey)
    from proofbundle._wire_b64 import decode_b64  # noqa: PLC0415
    # LAUF11-L2: strikt und kanonisch; unkanonisch wird abgewiesen, nicht geworfen.
    try:
        pub = Ed25519PublicKey.from_public_bytes(decode_b64(signer_pubkey_b64))
        roh_sig = decode_b64(sig_b64)
    except (binascii.Error, ValueError) as e:
        raise SystemExit(f"assemble: signature/pubkey field is not canonical base64 — refusing: {e}") from None
    try:
        pub.verify(roh_sig, canonical_bytes(body))
    except InvalidSignature:
        raise SystemExit("assemble: the signature does not verify over the canonical register body "
                         "— refusing") from None
    out = dict(body)
    out["signature"] = {"alg": "ed25519", "public_key_b64": signer_pubkey_b64, "sig_b64": sig_b64}
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--generated-at", default=None,
                   help="RFC-3339 UTC; default: measured now")
    p.add_argument("--emit-payload", type=Path, default=None,
                   help="keyless: write the canonical bytes here (needs --context-out)")
    p.add_argument("--context-out", type=Path, default=None)
    p.add_argument("--assemble", action="store_true")
    p.add_argument("--context-in", type=Path, default=None)
    p.add_argument("--sig-file", type=Path, default=None)
    p.add_argument("--signer-pubkey", default=None)
    p.add_argument("--out", type=Path, default=None)
    p.add_argument("--v2", action="store_true",
                   help="Registerform 6.1: Traeger, Belege und Ansichten erzeugen")
    p.add_argument("--revision", type=int, default=0)
    a = p.parse_args(argv)

    if a.v2:
        if a.generated_at is None:
            from datetime import datetime, timezone  # noqa: PLC0415
            a.generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        schreibe_v2(REPO, a.generated_at, a.revision)
        return 0

    if a.assemble:
        fehlt = [n for n in ("context_in", "sig_file", "signer_pubkey", "out")
                 if getattr(a, n, None) is None]
        if fehlt:
            raise SystemExit("assemble mode needs: "
                             + ", ".join("--" + n.replace("_", "-") for n in fehlt))
        body = json.loads(a.context_in.read_text(encoding="utf-8"))
        register = assemble(body, a.sig_file.read_text(encoding="utf-8").strip(),
                            a.signer_pubkey.strip())
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(json.dumps(register, indent=2, ensure_ascii=False) + "\n",
                         encoding="utf-8")
        print(f"assembled signed register -> {a.out} ({len(FINDINGS)} findings, version {VERSION})")
        return 0

    fehlt = [n for n in ("emit_payload", "context_out") if getattr(a, n, None) is None]
    if fehlt:
        raise SystemExit("emit mode needs: "
                         + ", ".join("--" + n.replace("_", "-") for n in fehlt))
    # DIE ZEITMARKE WIRD GEMESSEN, nicht fortgeschrieben. Die frueheren Fassungen trugen hier
    # `2026-07-18T00:00:00Z` als Vorgabewert, und dieses Datum stand danach in einem Register, das
    # ueber eine Fassung zwei Hauptversionen spaeter entschied. `findings_register` prueft die
    # Marke auf Form; sie soll auch stimmen.
    if a.generated_at is None:
        from datetime import datetime, timezone  # noqa: PLC0415
        a.generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = build_register(a.generated_at)
    a.emit_payload.parent.mkdir(parents=True, exist_ok=True)
    a.emit_payload.write_bytes(canonical_bytes(body))
    a.context_out.parent.mkdir(parents=True, exist_ok=True)
    a.context_out.write_text(json.dumps(body, indent=2, ensure_ascii=False) + "\n",
                             encoding="utf-8")
    print(f"emitted payload -> {a.emit_payload}  body -> {a.context_out} "
          f"({len(FINDINGS)} findings, version {VERSION}, generated_at {a.generated_at})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
