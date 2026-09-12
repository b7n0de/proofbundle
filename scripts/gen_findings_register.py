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
    for ebene in (4, 3, 2):
        m = re.search(rf"^({'#' * ebene}) {re.escape(kennung)}(?![0-9A-Za-z])", text, re.M)
        if not m:
            continue
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
            return {"value": f["severity"], "source": "findings_register v1, signiert"}
    if aus_tabelle:
        return {"value": aus_tabelle, "source": f"Severity-Spalte in {RESTRISIKO_REL}"}
    return {"value": None, "state": "NOT MEASURED",
            "reason": ("diese Kennung steht weder im signierten v1-Register noch in einer "
                       "Tabelle mit Severity-Spalte; eine Schwere hier zu setzen waere eine "
                       "Einstufung ohne Beleg")}


def baue_v2(repo, generated_at: str, revision: int = 0) -> dict:
    """Der Traeger der Registerform 6.1 aus drei gemessenen Quellen.

    MIGRATION NACH 1A (Owner-Entscheid OA-3c501b246f/OA-714de2fcdd): echte Artefakte
    wandern, der Rest traegt NOT MEASURED MIT GRUND. Was hier steht, ist entweder aus der
    Quelle geschnitten, aus dem signierten v1-Register uebernommen oder als Luecke benannt.
    Nichts wird erfunden, damit eine Spalte voll aussieht.
    """
    import hashlib, json as _json  # noqa: PLC0415
    quelle = repo / RESTRISIKO_REL
    roh = quelle.read_bytes()
    text = roh.decode("utf-8")
    qd = hashlib.sha256(roh).hexdigest()
    ok = _json.loads((repo / OBJEKTKLASSEN_REL).read_text(encoding="utf-8"))

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
            # ART NICHT GERATEN. Die Objektklassen unterscheiden nach HERKUNFT
            # (S/N/A/R/Z/G), nicht nach security/quality: `fund_sicherheit_und_korrektheit`
            # mischt beides, `fund_nachtrag` sagt ueber die Art nichts. Die erste Fassung
            # leitete `kind` daraus ab und machte N16 — eine Shell-Injection — zu `quality`.
            # Nach 1A wandert, was gemessen ist; der Rest traegt NOT MEASURED mit Grund.
            "kind": None,
            "kind_state": "NOT MEASURED",
            "kind_reason": ("die Objektklassen trennen nach Herkunft, nicht nach Art; eine "
                            "security/quality-Zuordnung liegt in keiner Quelle vor und wird "
                            "je Fund entschieden, nicht abgeleitet"),
            "title": _titel(stueck.decode("utf-8"), k, fundart, kopf),
            "class_id": None,
            "class_state": "NOT MEASURED",
            "class_reason": "Klassenkennungen liegen in der Quelle nicht vor",
            "objektklasse": e.get("klasse"),
            "objektklasse_begruendung": e.get("warum_diese_klasse"),
            "severity": _severity(k, _severity_aus_tabelle(stueck.decode("utf-8"), kopf)
                                  if fundart == "tabelle_spalte1" else None),
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
            "last_measured_reason": ("die Quelle nennt den Tag ihrer Erzeugung, nicht den "
                                     "Zeitpunkt der letzten Messung je Fund"),
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
        "language": "en",
        "issued_at": generated_at[:10],
        "generated_at": generated_at,
        "release_subject": {"name": "proofbundle", "version": VERSION, "tag": f"v{VERSION}"},
        "assessment_cutoff": generated_at[:10],
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
            "cross_count": ok.get("gegenrechnung_gegen_die_sollliste"),
            "assurance_checks": _zusicherungen(text, records),
        },
        "records": records,
        "signature": {"state": "NOT APPLICABLE",
                      "reason": ("dieser Traeger wird ueber den emit/assemble-Weg signiert; "
                                 "die private Schluesselhaelfte liegt am Mac")},
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
    hoch = []
    for m in re.finditer(r"^\|\s*([A-Z]\d+)\s*\|\s*(P[01])\s*\|([^\n]*)", text, re.M):
        zustand = [t.strip() for t in m.group(3).strip().strip("|").split("|")][-1]
        hoch.append({"id": m.group(1), "severity": m.group(2), "state": zustand[:60]})
    offen = [h for h in hoch if not h["state"].lower().startswith("closed")]
    anmerkung = None
    if re.search(r"every entry here is P2 or P3", text) and hoch:
        anmerkung = ("die Prosa ueber der Severity-Tabelle begruendet '0 open P0/P1' mit "
                     "'every entry here is P2 or P3'. Gemessen an derselben Tabelle: "
                     + ", ".join(f"{h['id']} traegt {h['severity']}" for h in hoch)
                     + ". Die Zusicherung haelt, weil dieser Eintrag geschlossen ist — nicht "
                       "aus dem Grund, den der Satz nennt. Ein Satz, der eine wahre Aussage "
                       "mit einer falschen Praemisse begruendet, ueberlebt die Aenderung, die "
                       "ihn falsch macht.")
    return [{
        "claim": "0 open P0/P1",
        "computed": {"p0_p1_total": len(hoch), "p0_p1_open": len(offen),
                     "entries": hoch, "open_entries": [h["id"] for h in offen]},
        "holds": not offen,
        "prose_rationale_state": "REFUTED" if anmerkung else "NOT MEASURED",
        "prose_rationale_note": anmerkung,
    }]


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


def pruefe_v2(doc, repo) -> list[str]:
    """Die Regeln, die der Erzeuger erzwingt. Leer heisst, die Ausgabe darf entstehen.

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
    if inv["identifiers_in_this_register"] + len(inv["identifiers_without_evidence"]) \
            != inv["identifiers_total"]:
        fehler.append("Inventar: getragen + ohne Beleg != gesamt")
    for g in inv["coverage_gaps"]:
        if g["state"] not in LUECKENWOERTER:
            fehler.append(f"Luecke {g['range']}: Zustand ist kein Lueckenwort")
        if not g.get("reason"):
            fehler.append(f"Luecke {g['range']}: ohne Grund")
    return fehler


# ── DIE ANSICHTEN: erzeugt, nie von Hand geschrieben ───────────────────────────────────────

def _offen(r) -> bool:
    sev = (r.get("severity") or {}).get("value")
    for f in FINDINGS:
        if f["id"] == r["id"]:
            return f["status"] == "open"
    return bool(sev) and r.get("record_role") == "finding"


def ansicht_uebersicht(doc) -> str:
    sub, inv = doc["release_subject"], doc["inventory"]
    z = [f"# Known remainders, {sub['name']} {sub['version']}", "",
         f"Tag {sub['tag']}, assessment cutoff {doc['assessment_cutoff']}, "
         f"register revision {doc['register_revision']}.",
         f"Coverage, {inv['identifiers_in_this_register']} of {inv['identifiers_total']} "
         f"identifiers carried in this register.", ""]
    for g in inv["coverage_gaps"]:
        z.append(f"Known gap, {g['range']}, {g['count']} identifiers, {g['state']}, {g['reason']}")
    cc = inv.get("cross_count") or {}
    if cc:
        z += ["", f"Cross-count against the independent tally: {cc.get('gleich')} equal, "
                  f"{cc.get('fehlt')} missing, {cc.get('zu_viel')} extra "
                  f"({', '.join(cc.get('zu_viel_welche') or [])} — named boundaries, not findings)."]
    for a in inv.get("assurance_checks") or []:
        z += ["", f"Assurance `{a['claim']}`: **{'holds' if a['holds'] else 'DOES NOT HOLD'}**, "
                  f"computed — {a['computed']['p0_p1_total']} P0/P1 in the source, "
                  f"{a['computed']['p0_p1_open']} open."]
        if a.get("prose_rationale_state") == "REFUTED":
            z.append(f"  The prose rationale in the source is REFUTED by the source's own table; "
                     f"the claim is carried here because it is COMPUTED, not quoted.")
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
    zus = ""
    for a in inv.get("assurance_checks") or []:
        marke = "holds" if a["holds"] else "DOES NOT HOLD"
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
<p class=sub>Tag {_h.escape(sub['tag'])} · cutoff {_h.escape(doc['assessment_cutoff'])} ·
 revision {doc['register_revision']} ·
 {inv['identifiers_in_this_register']} of {inv['identifiers_total']} identifiers carried</p>
{zus}
<h2>Known gaps</h2><ul>{luecken}</ul>
<h2>All records</h2>
<table><thead><tr><th>Id<th>Role<th>Class<th>Severity<th>Title<th>Bytes</tr></thead>
<tbody>{''.join(zeilen)}</tbody></table>
<p class=sub>Generated from {_h.escape(V2_REL)}. Do not edit by hand.</p>
"""


def schreibe_v2(repo, generated_at: str, revision: int = 0) -> dict:
    """Prueft erst, schreibt dann. Bei einem Verstoss KEINE Teilausgabe."""
    import hashlib, json as _json  # noqa: PLC0415
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
