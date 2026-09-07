#!/usr/bin/env python3
"""5.0.0 AUDIT-CANDIDATE matrix — the 33 machine-checkable acceptance checks (§9 minus external audit).

The audit-candidate status is TRUE only when every INTERNAL, machine-checkable acceptance criterion of
the Assurance-Extension §10 is green, leaving the single external human crypto/protocol audit as the one
remaining gate to stable. This gate makes that claim FALSIFIABLE: it runs one check per acceptance
obligation (33 in total, mapped to §9 criteria 1..12), orchestrating the already-built foundation gates
(F3 formal model, F4 type-confusion, F5 readiness pack, rust-parity, claims-hygiene, test-manifest,
fuzz-soak) rather than re-implementing them.

No-Fake verdict vocabulary (a DATA_BLOCKED is NOT a PASS):
  * PASS              — machine-verified green here.
  * PENDING_JUSTIFIED — honestly declared, not-yet-closed but not a blocker (e.g. an accepted Rust
                        PENDING gap documented in the readiness pack); never silently a PASS.
  * DATA_BLOCKED      — needs a toolchain/time this environment does not have (cargo binary, a real 24h
                        soak, an isolated build). Reported honestly as "not verified HERE", never green.
  * EXTERNAL_PENDING  — the single deliberately-open gate: the external human audit itself.
  * FAIL              — a real, machine-detected failure of an acceptance obligation.

Top-level verdict:
  * ``audit_candidate_ready`` is True iff 0 FAIL AND every check is PASS / PENDING_JUSTIFIED / the one
    EXTERNAL_PENDING — i.e. nothing is broken and nothing internal is un-closed without justification.
  * ``fully_verified_here`` is additionally True iff there are also 0 DATA_BLOCKED — i.e. the whole
    matrix was runnable in THIS environment (cargo + build tools + a recorded 24h soak present). The two
    are reported separately so a CI box without cargo reads honestly, never a fake green.

CLI:
  python scripts/audit_candidate_matrix.py [--json] [--strict]

Exit 0 iff ``audit_candidate_ready``; ``--strict`` additionally requires ``fully_verified_here``.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import functools
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for _sub in ("src", "scripts", "formal", "conformance"):
    _p = str(REPO / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)

PASS, PENDING, DATA_BLOCKED, EXTERNAL, FAIL = (
    "PASS", "PENDING_JUSTIFIED", "DATA_BLOCKED", "EXTERNAL_PENDING", "FAIL")
#: A release-ceremony obligation evaluated against an object it was never meant to bless.
#:
#: WHY THIS IS NOT ONE OF THE FOUR EXISTING STATES. PENDING means "not yet, but it will be here";
#: DATA_BLOCKED means "this environment cannot measure it"; EXTERNAL means "a human outside must
#: do it"; FAIL means "the obligation is BROKEN". None of them fits "the obligation does not apply
#: to this kind of object at all". Reusing one of them would have made a fifth meaning wear a
#: fourth name, and the reader could no longer tell which was meant.
#:
#: It is NOT readiness. A work branch is not audit-candidate-ready, and ``audit_candidate_ready``
#: keeps saying so. What changes is only whether this check calls the branch BROKEN.
NOT_APPLICABLE = "NOT_APPLICABLE_BEFORE_TAG"
_NON_FAIL = {PASS, PENDING, DATA_BLOCKED, EXTERNAL, NOT_APPLICABLE}

# F7 CLOSED (makellose-500 Phase 4, reviewer P8): these checks measure a keyword / a directory entry /
# non-emptiness, not a behaviour — 7 of them passed on pure lexical decoys incl. a NEGATED sentence. A
# presence proxy cannot GRANT release readiness, so they are INFORMATIVE (reported, never release-
# deciding). ``audit_candidate_ready`` is computed only over the release-deciding checks.
#
# C10.2 JOINED THIS SET Runde 2, Auflage C5 (2026-09-05) — A DOCUMENTED, VISIBLE DOWNGRADE, NOT A
# SILENT ONE. `c10_2_slot_filled` reads `docs/readiness_pack/index.json`, a HAND-MAINTAINED reviewer
# table with no candidate/producer/input-digest binding and no pinned-identity signature (its own
# self-receipt is explicitly ADVISORY — see `readiness_pack_manifest.py`). The review offered two
# ways to close this: rebuild it as candidate-bound signed pack evidence (every `delivers` entry
# checked for existence/digest/type/candidate-reference/role), or remove it from the release-
# deciding lines. Building a second signing subsystem for one slot, on top of the one this lane
# just hardened for C6.2/C6.3/C8.2, would be a second, differently-shaped trust mechanism shipped
# under time pressure — exactly the risk Auflage C6 warns against ("eine dokumentierte Ausnahme
# darf nicht still dieselbe Freigabestaerke behalten"). So: informative, and said so here, in the
# inventory (`EVIDENCE_ADMISSION_INVENTORY` below) and in the check's own docstring — never silent.
_INFORMATIVE_CHECKS = {"C1.2", "C1.3", "C9.2", "C10.2", "C10.3", "C10.4", "C10.5", "C11.3"}
_KNOWN_VERDICTS = {PASS, PENDING, DATA_BLOCKED, EXTERNAL, FAIL, NOT_APPLICABLE}
_EXTERNAL_CHECK_ID = "EXT.1"  # the ONE explicitly-external open audit

#: Human-readable names, first, with the id in parentheses behind them (owner directive
#: 04.09.2026: "was ist c12.1? das muessen wir umbenennen wenn das oefter kommt in
#: menschenlesbar"). The id stays as the stable identifier for tests and tables; the NAME is what
#: a person reads first. For every row other than C12.1 the name IS the existing plain title —
#: no new wording is invented, only the order changes.
_HUMAN_NAME = {"C12.1": "Pre-tag audit receipt"}


def _laeuft_auf_pull_request() -> bool:
    """Runs this evaluation against a pull request?

    FAIL-CLOSED BY CONSTRUCTION: only the literal string ``pull_request`` (and its ``_target``
    sibling) answers yes. A local run, an unset variable, a tag build, a push to main — anything
    else — is treated as NOT a pull request, and C12.1 stays sharp. The direction matters: an
    unknown environment must not be able to switch a release gate off.
    """
    return os.environ.get("GITHUB_EVENT_NAME", "") in ("pull_request", "pull_request_target")


def _version_aus_pyproject() -> str:
    """Die Version GELESEN, nicht getippt.

    Hier stand eine feste Zeichenkette, und am 04.09.2026 stand sie auf "5.1.0", waehrend das Paket
    5.1.0.post1 auslieferte. Das Skript meldete seine eigene Drift korrekt (`version_pin: drift`) —
    und niemand zog nach, weil ein fester Wert nichts erzwingt. Genau diese Klasse fing dieses
    Skript laut seinem eigenen Kopf schon einmal (Fund L6-01, schaler Pin); sie kam wieder, weil
    der Fund die INSTANZ traf und nicht die Bauform.

    DREI ZUSTAENDE, und der dritte ist ausdruecklich keine Freigabe: gelesen · Datei fehlt ·
    Datei da, aber ohne Versionszeile. Die letzten beiden liefern einen leeren String, und der
    Drift-Check darunter sagt dann NICHT "alles in Ordnung", sondern dass er nicht messen konnte.
    """
    import re as _re
    pp = REPO / "pyproject.toml"
    try:
        roh = pp.read_text(encoding="utf-8")
    except OSError:
        return ""
    m = _re.search(r'(?m)^\s*version\s*=\s*["\']([^"\']+)["\']', roh)
    return m.group(1) if m else ""


VERSION_UNDER_TEST = _version_aus_pyproject()


def _slot_schluessel(version: str) -> str:
    """Der Schluessel, unter dem die Bereitschafts-Evidenz dieser Version liegt.

    WARUM ES DIESE FUNKTION GIBT — ein Folgefehler, den erst eine Gegenlese-Linse fand, NICHT die
    Aenderung selbst. `release_evidence_slots` in docs/readiness_pack/index.json ist eine
    handgepflegte Tabelle mit EXAKTEN Schluesseln ("5.0.0", "5.1.0", ...). Solange
    `VERSION_UNDER_TEST` fest auf "5.1.0" stand, traf der Nachschlag immer. Seit sie GELESEN wird,
    heisst sie bei einem Post-Release "5.1.0.post1" — und der Nachschlag geht ins Leere.
    Gemessen 04.09.2026: `c10_2_slot_filled()` -> ('FAIL', "5.1.0.post1 slot status is None").

    WARUM DER RUECKFALL RICHTIG IST UND KEIN NACHGEBEN. Ein Post-Release aendert per PEP 440
    KEINEN Code — es korrigiert die Beschreibung. Die Bereitschafts-Evidenz der Basisversion gilt
    damit unveraendert weiter; einen zweiten Slot mit denselben Belegen anzulegen waere eine
    Kopie derselben Wahrheit an einem zweiten Ort, also genau die Klasse, die dieser Zweig
    schliesst.

    ENG GEHALTEN: NUR `.postN` faellt zurueck. Eine Vorabversion (`rc1`) und eine
    Entwicklungsfassung (`.devN`) tun es ausdruecklich NICHT — bei ihnen ist der Code ein anderer
    als bei der Freigabe, und ihre Evidenz von der Freigabe zu borgen waere eine Behauptung ueber
    ungemessenen Code. Sie fallen weiter durch, und das ist die richtige Antwort.
    """
    import re as _re
    m = _re.match(r"^([0-9]+\.[0-9]+\.[0-9]+)\.post[0-9]+$", version or "")
    return m.group(1) if m else version


def version_pin_binding(pinned: str) -> dict:
    """Is the pinned version still the version we SHIP? Three states, never two.

    FOUND BY THE PRE-TAG DEEP GATE on 2026-08-25 (finding L6-01, three lenses converged
    independently): this matrix pinned ``3.6.0``, evaluated ``release_evidence_slots["3.6.0"]``
    and ``pre_tag_audit_gate.evaluate(version="3.6.0")``, and reported
    ``audit_candidate_ready=True`` with exit 0 — while the shipping package was ``5.0.0``, two
    majors ahead. A release-readiness gate was attesting readiness from evidence about a
    different release, and nothing in the pipeline could notice.

    THE POINT IS NOT THE LITERAL. Editing ``3.6.0`` to ``5.0.0`` would make this instance green
    and recreate the class at the next version bump — the pin would go stale again, silently,
    and again nothing would notice. What is missing is the BINDING: a gate whose verdict is
    version-scoped must fail closed when its scope no longer matches the shipping identity.

    Three states:
      * ``bound``          — the pin equals the package version; this gate speaks about what ships.
      * ``drift``          — they differ; the verdict is about another release and cannot be read
                             as readiness for this one.
      * ``not_determinable`` — the package version could not be read here. Explicitly NOT a pass:
                             an unmeasurable binding is not a verified one.
    """
    try:
        import proofbundle
        shipping = str(getattr(proofbundle, "__version__", "") or "")
    except Exception as exc:                                    # noqa: BLE001
        return {"state": "not_determinable", "pinned": pinned, "shipping": None,
                "detail": f"package version unreadable: {type(exc).__name__}: {exc}"}
    if not shipping:
        return {"state": "not_determinable", "pinned": pinned, "shipping": None,
                "detail": "proofbundle.__version__ is empty"}
    if shipping == pinned:
        return {"state": "bound", "pinned": pinned, "shipping": shipping,
                "detail": f"pin matches the shipping package ({shipping})"}
    return {"state": "drift", "pinned": pinned, "shipping": shipping,
            "detail": (f"this matrix is scoped to {pinned} but the package ships {shipping} — "
                       f"its checks read {pinned} evidence slots and a {pinned} pre-tag audit "
                       f"record, so its verdict says nothing about {shipping}")}


def _read(rel: str, base: Path = REPO) -> str:
    p = base / rel
    return p.read_text(encoding="utf-8") if p.is_file() else ""


def _json_artifact(rel: str) -> dict | None:
    p = REPO / rel
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except ValueError:
        return None


# ─────────────────────────────────────────────────────────────────────────────────────────────
# EIN ZULASSUNGSPFAD FUER JEDE FREIGABEENTSCHEIDENDE EVIDENZ
# (Tiefen-Gate 2026-09-05, Fund L5-G7-02 P2 — Klasse A: PROVENIENZ UND KANDIDATENBINDUNG)
#
# WAS GEMESSEN WURDE, und es ist die ganze Begruendung. `c6_2_recorded_soak_clean` las
# `audit_artifacts/360/fuzz_soak_latest.json` und tat im Kern nur
# `a.get("untriaged_crash_count", 1) == 0 and a.get("false_accept_count", 1) == 0`. Der Reproducer
# des Gates erzeugte damit vier Bestehen aus Artefakten, die nichts belegen: das echte, auf 3.6.0
# lautende, unsignierte Artefakt entschied ueber 6.0.0 (90 Sekunden, Seed 7, 16 von 43 Parsern
# uebersprungen); ein JSON mit ZWEI Schluesseln ergab „recorded soak: None iters, 0 crash, 0
# false-accept"; ein Artefakt mit `ok=false` UND nichtleerer `untriaged_crashes`-Liste ergab dasselbe
# Gruen, weil nur die ZAEHLER gelesen wurden; und `c8_2_differential_agrees` sagte „Python==Rust on
# all" zu `{"all_agree": true}` ohne einen einzigen Vektor.
#
# DIE EIGENSCHAFT DER KLASSE A, ausfuehrbar formuliert. Eine Pruefung, die NICHT in
# `_INFORMATIVE_CHECKS` steht, darf ein Bestehen nur aus Evidenz bilden, die
#   (P-A1) eine ed25519-Signatur traegt, die ueber den KANONISCHEN Bytes des gesamten Rumpfes unter
#          einem EINGECHECKTEN Vertrauensanker verifiziert,
#   (P-A2) den exakten KANDIDATEN bindet — Commit UND Baumkennung UND die Digests von sdist und
#          wheel —, wobei die Baumkennung gegen den lebenden Baum nachgerechnet wird,
#   (P-A2b) die GATE-ZEILE des entscheidenden Deep-Gate-Laufs traegt, deren `head` an den
#          `candidate.commit` gebunden ist — damit die Baumaschine nicht ihre eigene Freigabe
#          beglaubigt (Release-Standard 6.0.0 vom 05.09.2026, Zeile 18),
#   (P-A3) ihr eigenes Schema, ihre Erzeuger- und Werkzeugversion, den Digest ihrer Eingabe, ihre
#          Zeit und ihre Signiererrolle nennt,
#   (P-A4) frisch ist (wohlgeformte Zeit, nicht in der Zukunft, nicht aelter als das erklaerte
#          Fenster),
#   (P-A5) Arbeitszaehler ungleich null traegt — ein signiertes „ok" mit Nullzaehlern ist kein Beleg,
#   (P-A6) ihre eigenen Erfolgs- und Fehlerfelder nicht widerlegt,
#   (P-A7) und deren AUSSAGE ausschliesslich aus den SIGNIERTEN Feldern abgeleitet wird.
#
# (P-A7) IST STRUKTURELL ERZWUNGEN, nicht nur zugesagt: bei `ART_VERIFIED` liefert der Helfer
# `signed_body` — den Rumpf OHNE den Signatur-Umschlag —, und nur daraus bilden die Zeilen ihren
# Satz. Ein Feld, das nicht mitsigniert wurde, existiert auf diesem Weg nicht. Der unverifizierte
# Rumpf steht unter `unverified` und darf ausschliesslich ABLEHNEN.
#
# WARUM DER INHALT VOR DER ATTESTIERUNG GEPRUEFT WIRD, und das ist Absicht: ungepruefter Inhalt darf
# nur ABLEHNEN, niemals ZUSPRECHEN. Ein Artefakt, das seiner eigenen Version widerspricht oder sein
# Scheitern protokolliert, ist auch unsigniert schon widerlegt.
#
# FAIL ODER DATA_BLOCKED, und die Grenze ist scharf (Auflage C2 des Gegenlesers): DATA_BLOCKED sagt
# ausschliesslich „diese UMGEBUNG kann es nicht messen" — kein git, kein Kanonisierer, kein PyYAML,
# keine Soak-Box, kein cargo, kein Build-Backend. Alles, was am ARTEFAKT liegt — fehlend, kaputt,
# unsigniert, fremd signiert, ungebunden, leer, sich selbst widersprechend — und auch ein Repo, das
# gar keinen Vertrauensanker eincheckt, ist ungueltige Evidenz und damit FAIL.
#
# EHRLICHE GRENZEN, aufgeschrieben statt geglaettet:
#   * Das Verzeichnis `360` in den Pfaden ist HISTORIE und keine Bindung. Die Bindung ist der
#     signierte `candidate`-Block.
#   * `candidate.sdist_sha256` / `candidate.wheel_sha256` werden hier NICHT nachgerechnet (das hiesse
#     zwei Distributionen bauen). Sie werden als vorhanden, wohlgeformt und MITSIGNIERT verlangt, so
#     dass ein Leser sie nachrechnen kann und ein Faelscher sie nicht unbemerkt aendern kann.
#   * Der Vertrauensanker dieses Repos ist derzeit LEER (nur Kommentare). Solange er leer ist,
#     kann KEIN Artefakt zugelassen werden — die betroffenen Zeilen sind rot, und das ist der wahre
#     Zustand, kein Werkzeugfehler.
# ─────────────────────────────────────────────────────────────────────────────────────────────

#: Eingecheckter Vertrauensanker fuer Freigabe-Evidenz (eine base64-Zeile je ed25519-Schluessel,
#: `#` ist Kommentar). Gelesen wird der COMMITTETE Blob, nie der Arbeitsbaum.
READINESS_TRUST_ANCHOR_REL = "audit_artifacts/readiness_trusted_pubkeys.txt"

#: Das Frische-Fenster. ZWEITRANGIG und ausdruecklich so: die eigentliche Frische ist die
#: Kandidatenbindung (`candidate.tree_digest` gegen den lebenden Baum). Das Fenster faengt den Fall,
#: in dem eine Evidenz zwar denselben Baum bindet, aber aus einer Umgebung stammt, die es so nicht
#: mehr gibt — der Baum-Digest bindet das Repo, nicht die Toolchain darum herum.
_EVIDENCE_MAX_AGE_DAYS = 180
#: Zulaessiger Uhrenversatz nach vorn. Eine Evidenz aus der Zukunft ist keine Evidenz.
_EVIDENCE_FUTURE_SKEW = timedelta(minutes=5)

_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
_HEX40 = re.compile(r"\A[0-9a-f]{40}\Z")
_RFC3339_Z = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z\Z")

#: Die Pflichtfelder der Kandidatenbindung, jedes mit seinem Formtest.
_CANDIDATE_FIELDS = (("commit", _HEX40), ("tree_digest", _HEX64),
                     ("sdist_sha256", _HEX64), ("wheel_sha256", _HEX64))

#: Die Pflichtfelder der GATE-ZEILE, uebernommen aus dem Verdikt des entscheidenden Deep-Gate-Laufs.
#: Form abgelesen am Lauf-4-Verdikt (`notes.gate_zeile`, 20 Felder); hier sind die verlangt, die die
#: Zeile zu einer BINDUNG machen: welche Gate-Fassung, welche Workflow-Datei mit welchem Digest,
#: welcher Modus, und welchen Kopf der Lauf beurteilt hat.
_GATE_LINE_FIELDS = (("gate_version", None), ("workflow_datei", None),
                     ("workflow_sha256", _HEX64), ("modus", None), ("head", _HEX40),
                     ("verdict", None))

#: Verdikte, die ein BESTEHEN bedeuten. Eine Allowlist und keine Sperrliste, weil ein unbekanntes
#: Verdikt anhalten muss statt durchzugehen — fail-closed heisst, dass der Zug am NICHT-Wissen
#: haengenbleibt, nicht nur am bekannten Nein.
#:
#: WARUM ES DIESES FELD GIBT (Gegenlesung 2026-09-07, Owner-Anordnung OA-638966a598, Option A).
#: Die Gate-Zeile trug zwanzig Felder und darunter KEIN Urteil. Gemessen am echten
#: `gate_result_600_lauf4b_FIX_FIRST.json`: dessen `verdict` ist "FIX_FIRST" und sein `release`
#: sagt woertlich "do not present ... as WITHSTANDS" — beides steht auf der obersten Ebene des
#: Laufergebnisses, und `notes.gate_zeile` uebernimmt es NICHT. Die Zeile band damit die HERKUNFT
#: des Laufs (welche Fassung, welcher Workflow, welcher Kopf) und nicht sein ERGEBNIS: ein Lauf,
#: der das Release ausdruecklich verbietet, lieferte eine Gate-Zeile, die die Pruefung vollstaendig
#: bestand. Der Erzeuger der Zeile muss das Verdikt jetzt mittragen; tut er es nicht, haelt der
#: Pruefer an, statt eine unvollstaendige Bindung durchzuwinken.
_GATE_VERDICTS_PASS = frozenset({"WITHSTANDS_DEEPGATE"})

#: Typisierte Ausgaenge. Typisiert und nicht Prosa, weil genau daran der Nachbarfund L5-G6-01 haengt:
#: ein Satz driftet, wenn ihn jemand umformuliert; ein Feld nicht.
ART_VERIFIED = "verified"
ART_ABSENT = "absent"
ART_MALFORMED = "malformed"
ART_SCHEMA_MISMATCH = "schema_mismatch"
ART_VERSION_UNBOUND = "version_unbound"
ART_CANDIDATE_UNBOUND = "candidate_unbound"
ART_GATE_LINE_UNBOUND = "gate_line_unbound"
ART_PROVENANCE_INCOMPLETE = "provenance_incomplete"
ART_STALE = "stale"
ART_VACUOUS = "vacuous"
ART_SELF_REPORTED_FAILURE = "self_reported_failure"
ART_UNSIGNED = "unsigned"
ART_NO_TRUST_ANCHOR = "no_trust_anchor"
ART_UNTRUSTED = "untrusted"
ART_UNMEASURABLE_HERE = "unmeasurable_here"

#: Der EINZIGE Zustand, der „diese Umgebung kann es nicht messen" heisst. Alles andere ist eine
#: Aussage ueber die Evidenz und damit FAIL (Auflage C2).
_ART_DATA_BLOCKED_STATES = {ART_UNMEASURABLE_HERE}


def _trust_anchor(repo: Path) -> tuple[dict, str]:
    """``(schluessel, zustand)`` mit ``zustand`` in ``{"ok", "empty", "unmeasurable"}``.

    DIE UNTERSCHEIDUNG IST DER PUNKT (Auflage C2): „kein git in dieser Umgebung" und „dieses Repo
    checkt keinen Anker ein" sahen in der ersten Fassung gleich aus (beide: leere Liste), und damit
    waere ein Umgebungsmangel als ungueltige Evidenz gemeldet worden oder umgekehrt.

    Gelesen wird der COMMITTETE Blob (``git show HEAD:…``), nicht der Arbeitsbaum — dieselbe
    Begruendung wie bei ``pre_tag_receipt_lib.load_trusted_pubkeys`` (Spur-2 Linse A, 2026-08-27):
    aus dem Arbeitsbaum koennte ein schmutziger Checkout einen Schluessel einlegen und sich selbst
    beglaubigen.
    """
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "show", f"HEAD:{READINESS_TRUST_ANCHOR_REL}"],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return [], "unmeasurable"
    if r.returncode != 0:
        stderr = (r.stderr or "").lower()
        # „existiert nicht in HEAD" ist eine Aussage ueber das REPO (leer); alles andere — kein
        # Repo, keine Referenz, kaputter Objektspeicher — ist eine ueber die UMGEBUNG. GEMESSEN
        # 2026-09-05 mit git, statt die Wortlaute zu raten:
        #   Pfad nicht im HEAD          -> "fatal: path '…' does not exist in 'HEAD'"
        #   auf Platte, aber ungetrackt -> "fatal: path '…' exists on disk, but not in 'HEAD'"
        #   gar kein Repo               -> "fatal: not a git repository (or any of the parent …)"
        #   Repo ohne Commit            -> "fatal: invalid object name 'HEAD'."
        # Die ersten beiden heissen „dieses Repo checkt keinen Anker ein", die letzten beiden
        # „hier ist nichts zu lesen".
        if "does not exist" in stderr or "exists on disk, but not in" in stderr:
            return {}, "empty"
        return {}, "unmeasurable"
    zuordnung = _anker_zeilen_lesen(r.stdout)
    return zuordnung, ("ok" if zuordnung else "empty")


#: Pflichtfelder je Ankerzeile (Auflage C3, zweite Haelfte, 2026-09-06). Vorher war der Anker eine
#: flache Liste roher base64-Schluessel: er sagte WER unterschreiben darf, aber nicht WOFUER und BIS
#: WANN. Damit war ``signer_role`` im Artefakt eine unbelegte Selbstauskunft — der Erzeuger schrieb
#: die Rolle hinein, gegen die er geprueft werden sollte. Eine Rolle, die der Geprueft selbst setzt,
#: ist keine Rolle.
_ANKER_FELDER = ("role", "not_after")

#: Die ZULAESSIGEN Rollen, und wofuer jede steht. Review Runde 3, Abschnitt 3, Punkt 3: eine Rolle
#: muss "einer vorab festgelegten Liste und den zulaessigen Artefaktschemata beziehungsweise
#: Check-IDs zugeordnet sein". Eine freie Zeichenkette als Rolle bindet nichts — sie sagt nur, dass
#: irgendwo dasselbe Wort noch einmal steht. Der Wert je Rolle ist die Menge der Check-IDs, fuer
#: die ein unter ihr signiertes Artefakt ueberhaupt in Frage kommt; ``None`` heisst ausdruecklich
#: "fuer alle" und ist bewusst NICHT vergeben, damit niemand versehentlich eine Generalvollmacht
#: einfuehrt.
#: DIE NAMEN SIND GEMESSEN, NICHT ERFUNDEN. Die erste Fassung dieser Liste trug drei ausgedachte
#: Rollen (`readiness-soak`, `readiness-parity`, `readiness-release`) — und liess damit die
#: einzige Rolle fallen, die dieses Repository wirklich benutzt. Gemessen im Testbaum: sechs
#: Stellen schreiben `role=release-runner`, keine schreibt etwas anderes. Eine Allowlist, die den
#: Bestand nicht kennt, ist kein Riegel, sondern ein Ausfall.
_ANKER_ROLLEN: dict[str, frozenset[str]] = {
    # OWNER-ENTSCHEID (Nachtrag 3, Teil A5, order_id
    # QITEM-PB-600-LAUF4-FIX-FIRST-VIER-LANES-NACHLAUF-LAUF5-01, Revision 4): fuer 6.0.0 gilt
    # derselbe Schluessel wie fuer 5.0.0, und seine Signierpolitik ist ausdruecklich eng — er
    # signiert die drei Bereitschaftsartefakte und den Registerkoerper, nichts sonst.
    # C12.2 GEHOERT DAZU, und dass es fehlte, war ein Widerspruch zum Satz drei Zeilen darueber.
    # Die Owner-Karte OA-e10ba2ba39 (2026-09-06T00:05:57Z) nennt die Signierpolitik woertlich:
    # „ausschliesslich Bereitschaftsartefakte C6.2, C6.3, C8.2 UND DEN REGISTERKOERPER". Die
    # Registerzeile heisst C12.2. Sie stand hier nicht, waehrend `scripts/findings_register.py`
    # gleichzeitig einen ZWEITEN, eigenen Schluessel pinnte, dessen private Haelfte auf dem
    # Bauhost lag — zwei Quellen fuer dieselbe Frage, die Verschiedenes sagten, und nichts verglich
    # sie. Gemessen und unabhaengig gegengelesen am 2026-09-06 (un-Nachpruefung TA3B, ACCEPT:
    # „Der Kommentar und der Rollenname versprechen Register-Signatur; die Implementierung liefert
    # sie nicht"). Seither gibt es nur noch DIESE Quelle: findings_register hat keinen eigenen Pin
    # mehr und bekommt die autorisierten Schluessel vom Aufrufer gereicht.
    "readiness_und_register_signierer_600": frozenset({"C6.2", "C6.3", "C8.2", "C12.2"}),
}


def _autorisierte_schluessel(repo: Path, check_id: str, *,
                             gemessen_am: str | None = None) -> tuple[set[str] | None, str]:
    """``(schluessel, grund)`` — wer darf fuer ``check_id`` unterschreiben?

    ``None`` heisst NICHT MESSBAR (kein git, kein lesbarer Anker) und ist beim Aufrufer
    fail-closed; ein LEERES Set heisst gemessen „niemand". Die Unterscheidung ist dieselbe wie
    ueberall in dieser Datei: eine unmessbare Sicherheitsrelation ist nie ihre Erfuellung.

    ``gemessen_am`` ist der Messzeitpunkt der Evidenz, gegen den ``not_after`` geprueft wird —
    ``produced_at`` bei den Bereitschaftsartefakten, ``generated_at`` beim Registerkoerper.
    NICHT gegen "jetzt": Evidenz von gestern wird nicht unzulaessig, bloss weil die Matrix heute
    laeuft. Das ist derselbe Vergleich, den ``_artifact_signature_ok`` fuer die Artefakte schon
    fuehrt.

    WARUM DIESER PARAMETER HINZUKAM (Owner-Karte OA-89f05b70cd, Option A, 2026-09-06). Diese
    Funktion las ``not_after`` und wertete es NIE aus — sie filterte allein ueber ``role``. Fuer
    C6.2/C6.3/C8.2 fiel das nicht auf, weil dort ``_artifact_signature_ok`` die Frist zusaetzlich
    selbst prueft. Fuer C12.2 gab es diese zweite Instanz nicht: gemessen mit
    ``not_after=2000-01-01`` blieb der Schluessel autorisiert und die Zeile meldete PASS. Der
    ausgelieferte Vertrauensanker sagt woertlich das Gegenteil („last day this key may produce
    evidence, compared against the artifact's produced_at"), und die Rolle
    ``readiness_und_register_signierer_600`` deckt laut Rollentabelle ausdruecklich auch C12.2.
    Ein Widerruf ueber das Absenken von ``not_after`` waere damit wirkungslos gewesen und haette
    wirksam ausgesehen — und genau das ist die Richtung, in der ein Fehler am teuersten ist.

    OHNE ``gemessen_am`` wird KEIN Schluessel autorisiert, und der Grund sagt warum. Die erste
    Fassung liess in diesem Fall ungefiltert durch und nannte das eine „benannte Grenze" — die
    Pflicht-Gegenlesung hat das als fail-open zurueckgewiesen, und sie hat recht: ein Aufrufer, der
    den Parameter vergisst oder aus einer aelteren Fassung stammt, bekaeme sonst abgelaufene
    Schluessel. Ein Sicherheitsfilter, dessen Vorgabe das Nichtfiltern ist, ist kein Filter.

    ZWEI FRISTEN, NICHT EINE, und der Grund steht in einer widerlegten eigenen Behauptung.
    Geprueft wird gegen den Messzeitpunkt der Evidenz UND gegen heute:

      * gegen ``gemessen_am``: Evidenz, die NACH dem Ablauf entstanden ist, ist unzulaessig. Das
        ist die Semantik, die der Anker beschreibt.
      * gegen HEUTE: ein widerrufener Schluessel darf die heutige Freigabe nicht autorisieren,
        egal wie alt die Evidenz ist. Widerruf heisst „diesem Schluessel nicht mehr glauben", nicht
        „ihm fuer kuenftige Evidenz nicht mehr glauben".

    WARUM DIE ZWEITE FRIST DAZUKAM. Die erste Fassung prueft nur gegen ``gemessen_am`` und trug
    dazu das Argument, das Lesen dieses Feldes aus dem noch ungepruefen Register sei sicher, weil es
    die erlaubte Menge nur VERKLEINERN koenne. Das ist falsch, und die Gegenlesung hat es
    ausfuehrbar widerlegt: mit ``not_after=2000-01-01`` und ehrlichem Messzeitpunkt sind null
    Schluessel autorisiert — mit einem auf 1999 zurueckdatierten ``generated_at`` ist es wieder
    einer. Die Signatur deckt ``generated_at`` mit ab, ein Halter eines widerrufenen Schluessels
    kann es also frei waehlen. Die Rueckdatierung VERGROESSERT die Menge gegenueber dem ehrlichen
    Zeitpunkt, und genau das ist der Vergleich, auf den es ankommt. Das Alterfenster im Register
    begrenzt die Rueckdatierung auf 180 Tage, es schliesst sie nicht — deshalb die zweite Frist.
    """
    from datetime import datetime, timezone                # noqa: PLC0415
    zuordnung, zustand = _trust_anchor(repo)
    if zustand == "unmeasurable":
        return None, "der Vertrauensanker ist hier nicht lesbar"
    passend = {pub for pub, feld in zuordnung.items()
               if check_id in _ANKER_ROLLEN.get(feld.get("role", ""), frozenset())}
    if gemessen_am is None:
        return set(), (f"kein Messzeitpunkt uebergeben — ohne ihn ist die Gueltigkeitsfrist nicht "
                       f"anwendbar, und ein nicht anwendbarer Sicherheitsfilter autorisiert "
                       f"niemanden (fail-closed; {len(passend)} Schluessel haetten die Rolle fuer "
                       f"{check_id})")
    # DATUMSVERGLEICH, KEIN ZEICHENVERGLEICH. Hier stand: "Zeichenvergleich der ersten zehn
    # Stellen: beide Formen sind ISO-8601-Praefixe" — eine unbelegte Annahme ueber feste Breite,
    # die die eigene Ankervalidierung nicht erzwang. Zwei Linsen der Pflicht-Gegenlesung haben sie
    # am 2026-09-06 unabhaengig widerlegt: `not_after=2026-9-6` parst mit `strptime` klaglos, und
    # `"2026-10-05" > "2026-9-6"` ist False, weil '1' < '9' an Stelle 5 steht. Ein ABGELAUFENER
    # Schluessel war damit im vierten Quartal autorisiert — ohne Rueckdatierung, mit voellig
    # ehrlicher Evidenz. Der Riegel sitzt jetzt an der Lesestelle (nur kanonisches `%Y-%m-%d`
    # ueberlebt) und hier wird mit `date`-Objekten verglichen, damit die Breitenannahme gar nicht
    # mehr existiert. Ein unlesbarer Messzeitpunkt autorisiert niemanden (fail-closed).
    tag_roh = str(gemessen_am)[:10]
    try:
        tag = datetime.strptime(tag_roh, "%Y-%m-%d").date()
    except ValueError:
        return set(), (f"Messzeitpunkt {gemessen_am!r} traegt kein lesbares Kalenderdatum "
                       f"(erwartet YYYY-MM-DD…) — ohne Datum ist die Frist nicht anwendbar, und ein "
                       f"nicht anwendbarer Sicherheitsfilter autorisiert niemanden (fail-closed)")
    heute_d = datetime.now(timezone.utc).date()
    heute = heute_d.strftime("%Y-%m-%d")
    erlaubt, abgelaufen = set(), []
    for pub in passend:
        frist_d = _frist_datum(zuordnung[pub])
        frist = str(zuordnung[pub].get("not_after", ""))
        if frist_d is None:
            # Kein geparstes Datum heisst: diese Zeile kam nicht durch `_anker_zeilen_lesen` (etwa
            # ein direkt gebautes Test-Mapping). Frueher stand hier `erlaubt.add(pub)` fuer eine
            # fehlende Frist — eine Autorisierung aus fehlender Information. Fail-closed.
            abgelaufen.append(f"{pub[:12]}…(ohne pruefbare Frist — nicht autorisiert)")
        elif tag > frist_d:
            abgelaufen.append(f"{pub[:12]}…(not_after={frist}, Evidenz von {tag_roh})")
        elif heute_d > frist_d:
            abgelaufen.append(f"{pub[:12]}…(not_after={frist}, heute {heute} — widerrufen)")
        else:
            erlaubt.add(pub)
    schwanz = f", {len(abgelaufen)} abgelaufen: {abgelaufen}" if abgelaufen else ""
    return erlaubt, (f"{len(erlaubt)} Schluessel im Anker autorisiert fuer {check_id} "
                     f"(Ankerzustand {zustand}, gemessen_am={tag_roh}, heute={heute}{schwanz})")

#: Base64 in kanonischer Form fuer genau 32 Bytes: 43 Zeichen aus dem Standardalphabet plus genau
#: ein Fuellzeichen. Die Laengenpruefung allein reicht nicht — ``b64decode`` mit ``validate=True``
#: faengt zusaetzlich Alphabetfremdes, und der Vergleich der Rueckkodierung faengt die nicht
#: kanonischen Varianten, bei denen die letzten Bits ungleich null sind.
_ANKER_B64 = re.compile(r"^[A-Za-z0-9+/]{43}=$")


def _anker_pubkey_ok(pub: str) -> bool:
    """Ist ``pub`` kanonisches Base64 ueber genau 32 Byte Ed25519-Material?

    DREI PRUEFUNGEN, und jede faengt etwas anderes: die Form (Alphabet und Laenge), die
    Dekodierbarkeit mit ``validate=True`` (Alphabetfremdes, das die Regex nicht sieht, etwa in einer
    laengeren Zeile) und die Kanonizitaet ueber die Rueckkodierung. Ohne die dritte waeren mehrere
    verschiedene Zeichenketten derselbe Schluessel — und ein Anker, in dem ein Schluessel unter zwei
    Namen steht, ist genau die Mehrdeutigkeit, die er ausschliessen soll.
    """
    if not _ANKER_B64.match(pub):
        return False
    try:
        roh = base64.b64decode(pub, validate=True)
    except (binascii.Error, ValueError):
        return False
    if len(roh) != 32:
        return False
    return base64.b64encode(roh).decode("ascii") == pub


def _anker_zeilen_lesen(roh: str) -> dict:
    """``{pubkey_b64: {"role": str, "not_after": str}}`` aus dem Ankertext.

    FORMAT, eine Zeile je Schluessel:  ``<base64> role=<rolle> not_after=<YYYY-MM-DD>``

    FAIL-CLOSED UND NICHT RUECKWAERTSKOMPATIBEL, mit Absicht. Eine nackte base64-Zeile ohne Rolle
    und Frist wird VERWORFEN, nicht als "Schluessel ohne Einschraenkung" gelesen — sonst waere das
    alte, schwaechere Format die stille Umgehung des neuen. Das kostet hier nichts: der Anker dieses
    Repositoriums ist heute leer (nur Kommentare, absichtlich, siehe die Datei selbst), es gibt also
    keinen Bestand, den eine strengere Lesart braeche. Genau deshalb ist jetzt der richtige
    Zeitpunkt, das Format festzulegen — spaeter waere jede Verschaerfung ein Bruch.

    Eine Zeile, die das Format verletzt, verschwindet still aus der Menge; der Aufrufer sieht
    dadurch WENIGER Schluessel, nie mehr. Das ist die sichere Richtung: eine unlesbare Zeile kann
    nichts autorisieren.
    """
    aus: dict = {}
    gesehen: set[str] = set()
    for zeile in roh.splitlines():
        z = zeile.strip()
        if not z or z.startswith("#"):
            continue
        teile = z.split()
        if len(teile) < 1 + len(_ANKER_FELDER):
            continue                      # nackte base64-Zeile: altes Format, nicht mehr gueltig
        pub, rest = teile[0], teile[1:]
        # SCHLUESSELMATERIAL (Runde 3, Punkt 3). Vorher wurde ``pub`` ungeprueft als Schluesselname
        # uebernommen: eine Zeile `nicht-base64 role=x not_after=y` legte einen "Schluessel" an, den
        # keine Signatur je treffen kann — harmlos im Ergebnis, aber der Anker behauptete damit
        # etwas ueber Material, das er nie angesehen hat.
        if not _anker_pubkey_ok(pub):
            continue
        felder: dict[str, str] = {}
        doppelt = False
        for stueck in rest:
            if "=" not in stueck:
                doppelt = True            # ein Feld ohne `=` ist kein Feld — die Zeile ist unklar
                break
            k, _, v = stueck.partition("=")
            k, v = k.strip(), v.strip()
            # DUBLETTEN UND UNBEKANNTES fallen, statt still zu ueberschreiben oder mitzufahren.
            # `role=a role=b` hatte vorher schlicht `b` ergeben — die Zeile sagt aber nicht, welche
            # Rolle gilt, und wer sie schreibt, hat sie auch nicht entschieden.
            if k in felder or k not in _ANKER_FELDER:
                doppelt = True
                break
            felder[k] = v
        if doppelt or not all(felder.get(f) for f in _ANKER_FELDER):
            continue                      # unvollstaendig oder mehrdeutig: keine halbe Autorisierung
        if felder["role"] not in _ANKER_ROLLEN:
            continue                      # unbekannte Rolle autorisiert nichts
        # FRIST ALS DATUM, nicht als Zeichenkette. `not_after=9999-99-99` sortierte vorher lexikalisch
        # hinter jedes echte Datum und haette damit nie abgelaufen — ein Ablaufdatum, das nicht
        # ablaufen kann, ist keins.
        #
        # ZWEITE HAELFTE DERSELBEN KLASSE, gefunden von der Pflicht-Gegenlesung am 2026-09-06 und
        # von zwei Linsen unabhaengig belegt. Die Pruefung oben schloss den EINEN Fall
        # (`9999-99-99`) und liess den Rest der Klasse offen: `strptime` ist tolerant und nimmt
        # `2026-9-6` klaglos an. Die Vergleiche weiter unten waren aber ZEICHENvergleiche auf
        # `[:10]`, und die setzen feste Breite voraus. GEMESSEN:
        #
        #     "2026-10-05" > "2026-9-6"   -> False   (weil '1' < '9' an Stelle 5)
        #     Kalender:      05.10. liegt NACH dem 06.09.
        #
        # Damit genuegte eine plausible, von der eigenen Validierung akzeptierte Schreibweise im
        # Anker, um einen ABGELAUFENEN Schluessel zu autorisieren — ohne jede Rueckdatierung, mit
        # voellig ehrlicher Evidenz, jedes Jahr im vierten Quartal. Beide Fristen fielen zusammen,
        # weil beide denselben Vergleich benutzten.
        #
        # Der Riegel sitzt jetzt an der LESESTELLE und nicht an den Vergleichen: hier wird die
        # Kanonizitaet erzwungen (nur nullgepolstertes `%Y-%m-%d` ueberlebt) UND das geparste Datum
        # abgelegt, damit kein Leser mehr in Versuchung kommt, Zeichen zu vergleichen. Eine
        # abweichende Schreibweise VERSCHWINDET wie jede andere Formverletzung — die sichere
        # Richtung, der Aufrufer sieht weniger Schluessel, nie mehr.
        try:
            _frist = datetime.strptime(felder["not_after"], "%Y-%m-%d").date()
        except ValueError:
            continue
        if _frist.strftime("%Y-%m-%d") != felder["not_after"]:
            continue                      # nicht kanonisch geschrieben (z.B. `2026-9-6`)
        # EIN SCHLUESSEL, EINE ZEILE. Zwei Zeilen fuer denselben Schluessel widersprechen sich
        # potenziell in Rolle oder Frist; die zweite ueberschrieb vorher still die erste. Beide
        # fallen, denn welche gelten soll, steht nirgends.
        if pub in gesehen:
            aus.pop(pub, None)
            continue
        gesehen.add(pub)
        aus[pub] = {f: felder[f] for f in _ANKER_FELDER}
    return aus


def _frist_datum(feld: dict) -> date | None:
    """Die Frist eines Ankereintrags als Kalenderdatum — oder ``None``, wenn sie das nicht hergibt.

    EINE QUELLE, STRENG GELESEN. Eine erste Fassung legte das geparste Datum als ZWEITES Feld
    (``not_after_date``) neben den String. Das war eine zweite Wahrheitsquelle, und sie ist sofort
    auseinandergelaufen: ein Test, der nur ``not_after`` ueberschrieb, hatte danach einen String,
    der 2000 sagte, und ein Datum, das 2027 sagte — die Pruefung las das Datum und liess einen
    "abgelaufenen" Schluessel durch. Zwei gekoppelte Felder, von denen ein Aufrufer nur eines setzt,
    sind kein Detail, sondern die naechste Instanz derselben Klasse. Deshalb wird hier bei JEDER
    Benutzung aus dem String geparst.

    STRENG heisst: nur die kanonische, nullgepolsterte Form ``YYYY-MM-DD``. `strptime` allein
    genuegt nicht — es nimmt ``2026-9-6`` an, und genau diese Schreibweise hat am 2026-09-06 in der
    Pflicht-Gegenlesung einen abgelaufenen Schluessel autorisiert, weil die Vergleiche damals
    ZEICHEN verglichen (``"2026-10-05" > "2026-9-6"`` ist False). Alles Unkanonische ergibt ``None``,
    und ``None`` autorisiert nichts.
    """
    roh = str(feld.get("not_after", ""))
    try:
        d = datetime.strptime(roh, "%Y-%m-%d").date()
    except ValueError:
        return None
    return d if d.strftime("%Y-%m-%d") == roh else None


def _anchor_last_touched_at_head(repo: Path, head_sha: str) -> tuple[bool | None, str]:
    """True iff the trust anchor file was last modified in EXACTLY the commit ``head_sha`` names.

    AUFLAGE C3 (Runde 2): „ein Schluessel, der im selben ungeschuetzten Baupfad eingefuehrt wird,
    darf keine Evidenz desselben Pfads autorisieren". `_trust_anchor` reads the anchor from the
    COMMITTED blob, which stops a dirty checkout from injecting a key — but it does NOT stop the
    SAME commit that introduces a new trusted key from also being the candidate that key goes on to
    authorise. A key pinned in an ANCESTOR commit is fine (that is the whole point of "eingecheckt");
    a key whose only committed history is the very commit it would authorise is not pre-registered
    at all, it is self-registered.

    DREI ZUSTAENDE, nicht zwei (Review Runde 3, Abschnitt 3, Punkt 4). Die erste Fassung gab bei
    einem Git-Fehler, fehlender Historie oder nicht aufloesbarem Pfad ``False`` zurueck — also
    dieselbe Antwort wie „nachweislich NICHT im Kandidatencommit geaendert". Das ist fail-open an
    genau der Stelle, die Selbstregistrierung verhindern soll: wo nichts messbar ist, sah der
    Aufrufer ein „alles in Ordnung". Der Gegenleser hat es benannt, und er hat recht — die
    Unmessbarkeit einer Sicherheitsrelation ist nie ihre Erfuellung.

    ``True``  – der Anker wurde zuletzt in genau diesem Commit geaendert (Selbstregistrierung)
    ``False`` – gemessen: zuletzt in einem ANDEREN Commit geaendert (der zulaessige Fall)
    ``None``  – hier nicht messbar; der Aufrufer macht daraus DATA_BLOCKED, nie ein Bestehen
    """
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "log", "-1", "--format=%H", "HEAD", "--",
             READINESS_TRUST_ANCHOR_REL],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"git is not usable here ({type(exc).__name__})"
    if r.returncode != 0:
        return None, f"git log failed here (exit {r.returncode})"
    if not r.stdout.strip():
        return None, (f"{READINESS_TRUST_ANCHOR_REL} has no commit history reachable from HEAD — "
                      "whether the key predates the candidate cannot be decided here")
    letzter = r.stdout.strip()
    if letzter == head_sha:
        return True, f"last modified in {letzter[:12]}…, the candidate commit itself"
    return False, f"last modified in {letzter[:12]}…, an earlier commit than the candidate"


def _live_tree_digest(repo: Path) -> tuple[str | None, str]:
    """``(digest, grund)`` des lebenden Baums — dieselbe Groesse, die ein Pre-Tag-Receipt bindet.

    RUFT ``sign_readiness_artifact.tree_digest`` AUF, statt sie ein zweites Mal zu implementieren
    (Auflage C3, Runde 2): ein Erzeuger und ein Tor, die getrennt entscheiden, was von der
    Baumkennung ausgeschlossen ist, koennten leise auseinanderlaufen, und keine Seite wuerde es
    bemerken — das genaue Gegenteil von "an das Artefakt binden". Vorher schloss diese Funktion den
    GANZEN Ordner ``audit_artifacts`` non-rekursiv aus; das versteckte auch den eingecheckten
    Vertrauensanker vor der Bindung. Jetzt: rekursiv, und nur die zwei namentlich bekannten
    mutablen Evidenzpfade sind ausgeschlossen (``sign_readiness_artifact.MUTABLE_EVIDENCE_RELS``).

    Schlaegt git fehl, ist das Ergebnis ``None`` und nicht der Digest der leeren Zeichenkette —
    sonst verglichen wir stillschweigend gegen nichts."""
    try:
        import sign_readiness_artifact as sra            # noqa: PLC0415
    except ImportError as exc:
        return None, f"sign_readiness_artifact is not importable here ({type(exc).__name__})"
    try:
        return sra.tree_digest(repo), "measured"
    except SystemExit as exc:
        return None, str(exc)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"git is not usable here ({type(exc).__name__})"


def _artifact_signature_ok(artifact: dict, trusted: dict, anchor_state: str, *,
                           repo: Path | None = None) -> tuple[str, str]:
    """``(zustand, grund)`` fuer die Attestierung EINES Artefakts.

    REIHENFOLGE MIT ABSICHT: erst alles, was OHNE Anker entscheidbar ist (Algorithmus, base64,
    Kanonisierung, die Mathematik der Signatur), dann die Zugehoerigkeit zum Anker. Sonst waere eine
    kaputt gerechnete Signatur in einem Baum ohne Anker nur „nicht messbar" statt widerlegt.

    ``repo`` ist optional NUR aus Rueckwaertskompatibilitaet zur Signatur; jeder produktive Aufrufer
    uebergibt ihn. Fehlt er (z.B. ein direkter Testaufruf ohne Baum), wird die Auflage-C3-Pruefung
    „Anker nicht im selben Commit wie der Kandidat eingefuehrt" uebersprungen statt zu raten — sie
    braucht einen echten Baum, um etwas zu messen.
    """
    import base64                                        # noqa: PLC0415
    sig = artifact.get("signature")
    if not isinstance(sig, dict):
        return ART_UNSIGNED, "the artifact carries no signature block"
    if sig.get("alg") != "ed25519":
        return ART_UNTRUSTED, f"unexpected signature alg {sig.get('alg')!r}"
    pub_b64 = sig.get("public_key_b64")
    if not isinstance(pub_b64, str) or not pub_b64:
        return ART_UNTRUSTED, "the signature block names no public key"
    try:
        pub = base64.b64decode(pub_b64, validate=True)
        raw_sig = base64.b64decode(sig.get("sig_b64", ""), validate=True)
    except (ValueError, TypeError) as exc:
        return ART_UNTRUSTED, f"signature fields are not valid base64: {exc}"
    body = {k: v for k, v in artifact.items() if k != "signature"}
    try:
        from proofbundle import canonical                # noqa: PLC0415
        from proofbundle.signature import verify_ed25519  # noqa: PLC0415
        msg = canonical.canonicalize_statement(body)
    except Exception as exc:                             # noqa: BLE001 — fehlender Kanonisierer = Umgebung
        return ART_UNMEASURABLE_HERE, (f"the artifact cannot be canonicalized in this environment "
                                       f"({type(exc).__name__}: {exc}) — not measurable is not verified")
    try:
        gueltig = verify_ed25519(pub, raw_sig, msg)
    except Exception as exc:                             # noqa: BLE001
        return ART_UNTRUSTED, f"signature check errored (fail-closed): {type(exc).__name__}: {exc}"
    if not gueltig:
        return ART_UNTRUSTED, "ed25519 signature does not verify over the canonical artifact bytes"
    if anchor_state == "unmeasurable":
        return ART_UNMEASURABLE_HERE, ("the committed trust anchor cannot be read in this environment "
                                       "(no usable git) — not measurable is not verified")
    if anchor_state == "empty" or not trusted:
        return ART_NO_TRUST_ANCHOR, (f"the signature verifies, but this repository commits no trusted "
                                     f"key at {READINESS_TRUST_ANCHOR_REL} — without an anchor no "
                                     f"signature can be attributed, so the evidence is not admissible")
    if pub_b64 not in trusted:
        return ART_UNTRUSTED, ("the signing key is not in the committed trusted set "
                               f"(signer={pub_b64[:12]}...)")

    # AUFLAGE C3, ZWEITE HAELFTE (2026-09-06). Die erste Haelfte — der Anker wird aus dem
    # committeten Blob gelesen und darf nicht im Kandidaten-Commit eingefuehrt worden sein — stand
    # schon. Was fehlte, war der Rest des Satzes: "samt Digest, ROLLE, GUELTIGKEITSZEIT und
    # Signierpolitik". ``signer_role`` wurde bis hier nur auf ANWESENHEIT geprueft, also auf ein
    # Feld, das der Erzeuger selbst schreibt — eine Rolle, die der Geprueft sich selbst gibt, ist
    # keine Rolle. Jetzt entscheidet der ANKER, wofuer ein Schluessel sprechen darf, und das
    # Artefakt muss dazu passen.
    # AUFLAGE C3, DRITTER TEIL (2026-09-06): das Artefakt muss den ANKERZUSTAND binden, unter dem es
    # entstand. Ohne diese Bindung sagt es nur, WER unterschrieben hat, nicht gegen welche
    # Vertrauensbasis das galt — und ein spaeter erweiterter Anker (ein Schluessel mehr, eine
    # gelockerte Rolle, eine verlaengerte Frist) waere an einem alten Artefakt nicht zu sehen.
    # Gelesen wird derselbe committete Blob, den `_trust_anchor` liest, und derselbe Digest, den
    # `sign_readiness_artifact.trust_anchor_digest` schreibt — EINE Funktion, importiert statt
    # nachgebaut, aus dem Grund, aus dem `_live_tree_digest` schon so gebaut ist.
    if repo is not None:
        gebunden = artifact.get("trust_anchor_digest")
        try:
            import sign_readiness_artifact as _sra       # noqa: PLC0415
            heute = _sra.trust_anchor_digest(repo)
        except ImportError:
            heute = None
        if heute is None:
            return ART_UNMEASURABLE_HERE, ("the trust anchor digest cannot be recomputed here "
                                           "(sign_readiness_artifact is not importable) — not "
                                           "measurable is not verified")
        if not isinstance(gebunden, str) or not gebunden:
            return ART_CANDIDATE_UNBOUND, (
                "the artifact carries no trust_anchor_digest — it names a signer but not the trust "
                "basis it was produced under, so a later-widened anchor would be invisible in it")
        if not heute:
            return ART_NO_TRUST_ANCHOR, ("the artifact binds a trust anchor, but this repository "
                                         f"commits none at {READINESS_TRUST_ANCHOR_REL}")
        if gebunden != heute:
            return ART_CANDIDATE_UNBOUND, (
                f"the artifact was produced under trust anchor {gebunden[:12]}… but the committed "
                f"anchor here is {heute[:12]}… — the trust basis changed since the measurement, so "
                "this evidence does not speak about the anchor in force now")

    erlaubt = trusted[pub_b64]
    rolle_im_artefakt = artifact.get("signer_role")
    if not isinstance(rolle_im_artefakt, str) or not rolle_im_artefakt:
        return ART_UNTRUSTED, ("the artifact names no signer_role, but the trust anchor binds this "
                               f"key to role {erlaubt['role']!r} — an unnamed role cannot match one")
    if rolle_im_artefakt != erlaubt["role"]:
        return ART_UNTRUSTED, (
            f"the artifact claims signer_role {rolle_im_artefakt!r}, but the committed anchor binds "
            f"this key to {erlaubt['role']!r} — the anchor decides what a key may speak for, not "
            "the artifact that wants to be admitted")

    # GUELTIGKEITSZEIT, gegen ZWEI Fristen. Die erste Fassung prueft nur gegen ``produced_at`` und
    # begruendete das so: "ein Artefakt, das gestern rechtmaessig entstand, wird nicht dadurch
    # ungueltig, dass heute jemand die Matrix faehrt". Der Satz ist richtig — und als alleinige
    # Pruefung reicht er nicht, weil ``produced_at`` VOM SIGNIERER SELBST gewaehlt und mitsigniert
    # wird. Wer die private Haelfte eines abgelaufenen Schluessels haelt, schreibt einen Zeitpunkt
    # innerhalb des Fensters hinein und ist wieder autorisiert. GEMESSEN 2026-09-06 an genau dieser
    # Stelle, mit einem Wegwerf-Schluesselpaar und not_after=2027-09-06, Pruefzeitpunkt 25 Tage nach
    # Ablauf: ehrliches produced_at -> untrusted, um 30 Tage zurueckdatiertes produced_at ->
    # verified. Der Korridor war genau so breit wie das Frischefenster (_EVIDENCE_MAX_AGE_DAYS),
    # also 180 Tage ab dem Tag nach Ablauf.
    #
    # DIESELBE KLASSE stand am selben Tag auf dem Registerpfad (``_autorisierte_schluessel``) und
    # wurde dort von der Pflicht-Gegenlesung widerlegt; Klasse
    # ``gueltigkeitsfenster_gegen_selbstbehaupteten_zeitpunkt`` im Berkeley-Klassenledger. Ein
    # selbstbehaupteter Zeitpunkt kann NICHT belegen, WANN signiert wurde — genau dafuer gibt es
    # vertrauenswuerdige Zeitstempel (RFC 3161); ohne einen solchen ist die einzige tragfaehige
    # Lesart, dass das Fenster auch JETZT offen sein muss.
    #
    # WAS DAS KOSTET, ehrlich: nach Ablauf eines Schluessels wird seine Evidenz hier unzulaessig,
    # auch die rechtmaessig entstandene. Das ist derselbe Handel wie bei Code-Signaturen ohne
    # Zeitstempel und hier bezahlbar, weil ``_freshness_error`` Evidenz ohnehin auf
    # _EVIDENCE_MAX_AGE_DAYS begrenzt: eine historische Nachpruefung alter Evidenz ist NICHT die
    # Aufgabe dieser Matrix, sie beurteilt einen Kandidaten mit frischer Messung. Wer nach Ablauf
    # weiter freigeben will, rollt den Schluessel — das ist die vorgesehene Bewegung.
    # ZWEITE WIDERLEGUNG DERSELBEN STELLE, 2026-09-06. Hier stand: "Beide Formen sind
    # ISO-8601-Praefixe; ein Zeichenvergleich der ersten zehn Stellen ordnet Kalendertage korrekt."
    # Die erste Haelfte ist eine Annahme, keine Zusicherung — die Ankervalidierung erzwang keine
    # feste Breite. Eine Linse der Pflicht-Gegenlesung hat daraus einen Bypass OHNE Rueckdatierung
    # gebaut: mit `not_after=2026-9-6` im Anker und einem voellig EHRLICHEN produced_at im vierten
    # Quartal ("2026-10-05" > "2026-9-6" ist False) lieferte diese Funktion `verified` fuer einen
    # abgelaufenen Schluessel. Jetzt gilt beides: die Lesestelle laesst nur kanonisches `%Y-%m-%d`
    # durch, und hier wird mit `date`-Objekten verglichen.
    #
    # ZEITZONE, ausgesprochen statt vorausgesetzt: `produced_at` MUSS RFC3339 mit literalem `Z`
    # sein. Der produktive Aufrufer erzwingt das schon ueber `_provenance_error`, aber diese
    # Funktion wird auch direkt gerufen (Tests, kuenftige Aufrufer) — und ein Offset wie `+09:00`
    # liesse `[:10]` das ORTS- statt des UTC-Kalendertags liefern, also eine falsche Sperre oder
    # eine falsche Freigabe je nach Vorzeichen. Deshalb wird die Form hier selbst geprueft, statt
    # sich auf einen Aufrufer zu verlassen, dessen Vorleistung nirgends als Vertrag stand.
    frist = erlaubt["not_after"]
    frist_d = _frist_datum(erlaubt)
    erzeugt = artifact.get("produced_at")
    if not isinstance(erzeugt, str) or not erzeugt:
        return ART_UNTRUSTED, ("the artifact names no produced_at, so its signing key's validity "
                               f"window (not_after={frist}) cannot be applied to it")
    if not _RFC3339_Z.match(erzeugt):
        return ART_UNTRUSTED, (
            f"produced_at={erzeugt!r} is not an RFC3339 UTC 'Z' timestamp — a local-offset form "
            "would make the calendar-day comparison against the key's window read the wrong day, "
            "so the window cannot be applied (fail-closed)")
    if frist_d is None:
        return ART_UNTRUSTED, (
            f"the anchor entry for this key carries no parsed not_after date (raw {frist!r}) — "
            "without one the validity window cannot be applied (fail-closed)")
    try:
        erzeugt_d = datetime.strptime(erzeugt[:10], "%Y-%m-%d").date()
    except ValueError:
        return ART_UNTRUSTED, (f"produced_at={erzeugt!r} carries no readable calendar date, so the "
                               f"key's validity window (not_after={frist}) cannot be applied")
    if erzeugt_d > frist_d:
        return ART_UNTRUSTED, (
            f"the artifact was produced at {erzeugt} but the anchor limits this key to "
            f"not_after={frist} — evidence signed after a key's window is not admissible")
    heute_d = datetime.now(timezone.utc).date()
    heute = heute_d.strftime("%Y-%m-%d")
    if heute_d > frist_d:
        return ART_UNTRUSTED, (
            f"the anchor limits this key to not_after={frist} and today is {heute} — the window is "
            f"closed NOW, so this key admits nothing, whatever produced_at={erzeugt} the artifact "
            "claims for itself. A produced_at is written by the same holder that signs, so it "
            "cannot establish WHEN the signature was made; without a trusted timestamp the only "
            "sound reading is that an expired key authorises nothing. Roll the key and re-sign")
    # AUFLAGE C3 (Runde 2): der Anker darf nicht im selben Commit eingefuehrt worden sein, den er
    # gerade autorisiert — sonst koennte derselbe ungeschuetzte Bauprincipal Schluessel und
    # Kandidat in einer Kette einfuehren. Nur geprueft, wenn ein Baum uebergeben wurde UND der
    # Kandidat selbst einen Commit nennt (die Kandidatenbindung prueft dessen Form/Ident separat);
    # ohne beides gibt es nichts, woran „derselbe Commit" gemessen werden koennte.
    if repo is not None:
        kandidat_commit = (artifact.get("candidate") or {}).get("commit")
        if isinstance(kandidat_commit, str) and _HEX40.fullmatch(kandidat_commit):
            selbst, hist_grund = _anchor_last_touched_at_head(repo, kandidat_commit)
            if selbst is None:
                # NICHT MESSBAR IST KEINE FREIGABE (Runde 3, Punkt 4). Vorher fiel dieser Fall mit
                # dem gemessenen Nicht-Selbstregistriert-Fall zusammen und liess durch.
                return ART_UNMEASURABLE_HERE, (
                    f"whether the trust anchor at {READINESS_TRUST_ANCHOR_REL} was pre-registered "
                    f"cannot be measured here: {hist_grund}")
            if selbst:
                return ART_UNTRUSTED, (
                    f"the trust anchor at {READINESS_TRUST_ANCHOR_REL} was last modified in "
                    f"commit {kandidat_commit[:12]}… — the SAME commit this artifact binds as its "
                    "candidate. A key introduced in the same unprotected build path it goes on to "
                    "authorise is self-registered, not pre-registered; pin it in an ancestor commit "
                    f"first ({hist_grund})")
    return ART_VERIFIED, "signed by a committed trusted key, signature verifies"


def _live_commit(repo: Path) -> tuple[str | None, str]:
    """``(commit, grund)`` — dasselbe ``git rev-parse HEAD``, das der Erzeuger bindet. ``None`` bei
    einem Git-Fehler, nie ein geratener Wert."""
    try:
        r = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                           capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"git is not usable here ({type(exc).__name__})"
    if r.returncode != 0:
        return None, f"git rev-parse HEAD failed here (exit {r.returncode})"
    return r.stdout.strip(), "measured"


#: Distributionsdateien, aus denen C2 tatsaechlich nachrechnet — die neueste je Endung, damit ein
#: liegen gebliebener alter Bau in `dist/` keinen frisch gebauten Kandidaten unbemerkt ueberdeckt.
def _dist_files(repo: Path, version: str | None = None) -> tuple[Path | None, Path | None, str]:
    """``(sdist, wheel, grund)`` — ueber IDENTITAET, nicht ueber den Zeitstempel.

    DIE ALTE FASSUNG NAHM DIE JUENGSTE DATEI (Review Runde 3, Abschnitt 3, Punkt 7). „Eine
    Distribution ist durch Name, Version und Digest bestimmt, nicht durch den juengsten
    Dateizeitstempel." Der Satz trifft genau: `mtime` ist ein Nebeneffekt des Dateisystems, keine
    Eigenschaft des Pakets. Ein `touch` auf ein altes Wheel, ein Rebuild in anderer Reihenfolge, ein
    kopiertes Archiv aus einem anderen Baum — jedes davon verschiebt die Kandidatenidentitaet, ohne
    dass irgendwo etwas Falsches steht. Und weil das Ergebnis danach gegen die signierten Digests
    geprueft wird, sah ein solcher Fehlgriff aus wie ein Digest-Konflikt und nicht wie das, was er
    ist: die falsche Datei angesehen.

    ZULAESSIG IST GENAU EIN VERSIONSPASSENDES PAAR. Gesucht werden Dateien, deren Name die Version
    des Kandidaten traegt (die Namenskonvention aus PEP 427/625: `proofbundle-<version>.tar.gz`,
    `proofbundle-<version>-*.whl`). Gibt es davon mehr als eine je Art, ist die Identitaet
    MEHRDEUTIG — und Mehrdeutigkeit wird gemeldet, nicht durch eine Sortierregel aufgeloest. Gibt
    es keine, fehlt der Bau. Beides ist eine Aussage ueber die UMGEBUNG und fuehrt beim Aufrufer zu
    DATA_BLOCKED, nie zu einem Bestehen.

    Aeltere Distributionen anderer Versionen im selben `dist` stoeren dadurch nicht mehr: sie
    tragen eine andere Version im Namen und kommen gar nicht erst in die Auswahl.
    """
    # DIE VERSION WIRD BEIM AUFRUF AUFGELOEST, nicht beim Definieren. Die erste Fassung schrieb
    # `version: str = VERSION_UNDER_TEST` in die Signatur — Python bindet einen Vorgabewert einmal,
    # zur Definitionszeit, und jede spaetere Aenderung des Modulwerts kam nie an. Gemessen: die
    # Testbaeume setzen `m.VERSION_UNDER_TEST` auf 9.9.9 und legen passende Distributionen ab; die
    # Auswahl suchte trotzdem nach 6.0.0 und meldete DATA_BLOCKED. Ein Wert, der zur Definitionszeit
    # einfriert, folgt dem Zustand nicht — dieselbe Klasse wie eine fest geschriebene Versionszahl,
    # gegen die `test_die_matrix_liest_dieselbe_zahl_statt_sie_zu_tippen` in diesem Repo schon steht.
    marke = (version if version is not None else VERSION_UNDER_TEST).strip()
    dist = repo / "dist"
    if not dist.is_dir():
        return None, None, "dist/ does not exist — nothing was built here"
    sdists = [q for q in sorted(dist.glob("*.tar.gz")) if f"-{marke}.tar.gz" in q.name]
    wheels = [q for q in sorted(dist.glob("*.whl")) if f"-{marke}-" in q.name]
    if len(sdists) > 1 or len(wheels) > 1:
        return None, None, (
            f"dist/ is ambiguous for version {marke}: "
            f"{[q.name for q in sdists]} / {[q.name for q in wheels]} — a candidate is identified by "
            "name, version and digest, not by the newest timestamp; build into a clean dist/")
    if not sdists or not wheels:
        vorhanden = sorted(q.name for q in dist.iterdir() if q.is_file())
        return None, None, (
            f"dist/ carries no version-{marke} sdist/wheel pair (present: {vorhanden or 'nothing'})")
    return sdists[0], wheels[0], f"exactly one version-{marke} pair: {sdists[0].name}, {wheels[0].name}"


def _evidenz_relation_erlaubt(repo: Path, gebunden: str, live: str) -> tuple[bool | None, str]:
    """``(erlaubt, grund)`` fuer einen HEAD, der VOM gebundenen Commit abweicht. ``None`` bei einem
    Git-Fehler — nie ein geratenes Urteil.

    Erlaubt ist genau der Fall, den ``MUTABLE_EVIDENCE_RELS`` zusagt: der Lauf hat seine eigene
    Ergebnisdatei committet, sonst nichts. Zwei Bedingungen, beide notwendig:

    1. ``gebunden`` ist ein Vorfahr von ``live`` (``git merge-base --is-ancestor``). Ein fremder
       Commit aus einem anderen Zweig faellt hier — er ist kein "spaeterer Evidenzcommit", er ist
       ein anderer Baustand.
    2. Die Pfadmenge von ``gebunden`` nach ``live`` liegt vollstaendig in
       ``sign_readiness_artifact.MUTABLE_EVIDENCE_RELS``. Ein Commit, der irgendetwas anderes
       anfasst — Quelltext, Vertrauensanker, Klassen-Ledger — faellt hier, auch wenn er ein
       Vorfahr-Nachfahr-Verhaeltnis hat.

    Die Richtung ist bewusst eng: das Tor laesst den dokumentierten Ablauf zu und sonst nichts. Es
    ist KEIN Freibrief fuer "HEAD ist irgendwie weiter" — genau das waere die Luecke, die die
    Gleichheitspruefung vermeiden wollte.
    """
    try:
        import sign_readiness_artifact as sra            # noqa: PLC0415
    except ImportError as exc:
        return None, f"sign_readiness_artifact is not importable here ({type(exc).__name__})"
    try:
        # ZUERST: EXISTIERT der gebundene Commit hier ueberhaupt? Diese Frage muss VOR merge-base
        # stehen, und ihre Antwort ist eine Aussage ueber die EVIDENZ, kein Umgebungsmangel.
        # ``merge-base --is-ancestor`` beantwortet sie namlich nicht: bei einem unbekannten Objekt
        # gibt es exit 128 zurueck, denselben Code wie bei einem kaputten Repo — und die erste
        # Fassung machte daraus ein "nicht messbar", also DATA_BLOCKED. Der Anti-Paritaets-Test
        # ``kandidat_falscher_commit`` (ein Kandidat, der 000000…  bindet) hat genau das gefangen:
        # ein Artefakt, das einen Commit nennt, den es hier nicht gibt, BINDET NICHTS — das ist FAIL.
        # DATA_BLOCKED heisst ausschliesslich "diese Umgebung kann nicht messen" (Auflage C2), und
        # ein erfundener Commit ist kein Umgebungsmangel, sondern ein Befund.
        # ZWEI Fehlerquellen, ZWEI Antworten. ``cat-file -e`` scheitert sowohl, wenn der Commit
        # fehlt (Befund), als auch, wenn hier gar kein Repository liegt (Umgebungsmangel) — beide
        # mit exit != 0. Wer sie zusammenwirft, hat den Fehler nur auf die andere Seite geschoben:
        # erst meldete ein erfundener Commit DATA_BLOCKED, dann meldete ein fehlendes Repo einen
        # Befund. Deshalb zuerst die Umgebungsfrage, dann die Evidenzfrage.
        repo_da = subprocess.run(["git", "-C", str(repo), "rev-parse", "--git-dir"],
                                 capture_output=True, text=True, timeout=10)
        if repo_da.returncode != 0:
            return None, "there is no git repository here to resolve the bound commit against"
        da = subprocess.run(["git", "-C", str(repo), "cat-file", "-e", f"{gebunden}^{{commit}}"],
                            capture_output=True, text=True, timeout=10)
        if da.returncode != 0:
            return False, "the bound commit does not exist in this repository at all"
        vorfahr = subprocess.run(
            ["git", "-C", str(repo), "merge-base", "--is-ancestor", gebunden, live],
            capture_output=True, text=True, timeout=10)
        if vorfahr.returncode not in (0, 1):
            return None, f"git merge-base failed here (exit {vorfahr.returncode})"
        if vorfahr.returncode == 1:
            return False, "the bound commit is not an ancestor of HEAD"
        geaendert = subprocess.run(
            ["git", "-C", str(repo), "diff", "--name-only", gebunden, live],
            capture_output=True, text=True, timeout=10)
        if geaendert.returncode != 0:
            return None, f"git diff --name-only failed here (exit {geaendert.returncode})"
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"git is not usable here ({type(exc).__name__})"
    pfade = {ln.strip() for ln in geaendert.stdout.splitlines() if ln.strip()}
    fremd = sorted(pfade - set(sra.MUTABLE_EVIDENCE_RELS))
    if fremd:
        return False, ("commits after the bound one touch paths outside the mutable evidence set: "
                       f"{', '.join(fremd[:5])}"
                       + (f" (and {len(fremd) - 5} more)" if len(fremd) > 5 else ""))
    return True, ("HEAD is a later evidence commit: an ancestor relation plus changes confined to "
                  f"{', '.join(sra.MUTABLE_EVIDENCE_RELS)}")


def _candidate_binding_error(body: dict, repo: Path,
                             version: str | None = None) -> tuple[str, str] | None:
    """``(zustand, grund)`` wenn die Kandidatenbindung fehlt/nicht passt, sonst ``None``.

    Auflage C1 des Gegenlesers: ein Vergleich der Zeichenkette „6.0.0" bindet KEINEN Kandidaten. Ein
    Release-Kandidat ist ein Baum plus zwei Distributionen; die Evidenz muss genau den benennen.
    """
    # DIE VERSION REIST MIT, statt aus dem Modul geholt zu werden. Sie steht beim Aufrufer schon
    # fest — er hat gerade geprueft, dass die Evidenz auf genau diese Version lautet —, und die
    # Distributionsauswahl braucht dieselbe. Sie stattdessen aus `VERSION_UNDER_TEST` zu lesen
    # hiesse, in einer Kette zwei Quellen fuer denselben Wert zu fuehren; gemessen fiel genau das
    # auf, als ein Test die Version als Argument uebergab und die Auswahl weiter die Modulzahl las.
    kandidat = body.get("candidate")
    if not isinstance(kandidat, dict):
        return ART_CANDIDATE_UNBOUND, "the artifact carries no `candidate` block"
    fehlend = []
    for feld, form in _CANDIDATE_FIELDS:
        wert = kandidat.get(feld)
        if not isinstance(wert, str) or not form.fullmatch(wert):
            fehlend.append(f"candidate.{feld}={wert!r}")
    if fehlend:
        return ART_CANDIDATE_UNBOUND, ("the candidate binding is incomplete or malformed: "
                                       f"{', '.join(fehlend)}")
    # AUFLAGE C1 (Runde 2), zweiter Anlauf. Ein formgueltiger, aber BELIEBIGER Commitstring darf
    # nicht genuegen — und die Auflage verlangt zweierlei: gegen den vorab festgelegten Quellcommit
    # pruefen UND "die erlaubte Relation fuer einen spaeteren Evidenzcommit ausdruecklich
    # modellieren". Die erste Fassung erledigte nur die erste Haelfte und ersetzte die Relation
    # durch exakte Gleichheit, mit der Begruendung, die Evidenzdatei werde nie committet.
    #
    # DIE GEGENLESUNG HAT DAS WIDERLEGT (2026-09-05, Linse 5 von 6, mit nachgebautem Ablauf):
    # ``sign_readiness_artifact.MUTABLE_EVIDENCE_RELS`` existiert genau dafuer, dass ein Lauf seine
    # EIGENE Ergebnisdatei committen kann, ohne die Bindung zu zerstoeren — deshalb schliesst
    # ``tree_digest`` diese zwei Pfade aus, und deshalb bleibt der Baumdigest ueber einen solchen
    # Commit hinweg gleich. Beide Pfade sind getrackt. Kandidat committen, Evidenz signieren,
    # Evidenz committen: der Baumdigest passt weiter, HEAD ist gewandert, und die Gleichheit oben
    # verwarf genau den Ablauf, den die Schwesterdatei zusagt. Ein Tor, das den eigenen
    # dokumentierten Weg verbietet, ist nicht streng, sondern falsch.
    #
    # DIE MODELLIERTE RELATION, in zwei Bedingungen, die zusammen gelten muessen:
    #   1. der gebundene Commit ist ein VORFAHR des heutigen HEAD (oder HEAD selbst) — ein fremder
    #      Commit aus einem anderen Zweig ist damit draussen, auch wenn er existiert;
    #   2. alles, was seither dazukam, liegt AUSSCHLIESSLICH in MUTABLE_EVIDENCE_RELS — ein Commit,
    #      der Quelltext, Anker, Ledger oder sonst irgendetwas anfasst, ist damit draussen.
    # Das ist dieselbe Trennung, die ``tree_digest`` auf der Baum-Achse schon zieht (was der Lauf
    # selbst erzeugt, bindet ihn nicht), nur auf die Commit-Achse gezogen — kein neuer Begriff.
    live_commit, commit_grund = _live_commit(repo)
    if live_commit is None:
        return ART_UNMEASURABLE_HERE, f"the candidate commit cannot be read here: {commit_grund}"
    if kandidat["commit"] != live_commit:
        erlaubt, rel_grund = _evidenz_relation_erlaubt(repo, kandidat["commit"], live_commit)
        if erlaubt is None:
            return ART_UNMEASURABLE_HERE, (
                f"the relation between the bound commit {kandidat['commit'][:12]}… and HEAD "
                f"{live_commit[:12]}… cannot be measured here: {rel_grund}")
        if not erlaubt:
            return ART_CANDIDATE_UNBOUND, (
                f"the artifact binds commit {kandidat['commit'][:12]}… and HEAD here is "
                f"{live_commit[:12]}… — that is only allowed for a later EVIDENCE commit "
                f"(an ancestor plus changes confined to the mutable evidence paths); {rel_grund}")
    live, grund = _live_tree_digest(repo)
    if live is None:
        return ART_UNMEASURABLE_HERE, f"the candidate tree digest cannot be recomputed here: {grund}"
    if kandidat["tree_digest"] != live:
        return ART_CANDIDATE_UNBOUND, (f"the artifact binds tree {kandidat['tree_digest'][:12]}… but "
                                       f"this tree is {live[:12]}… — evidence about another candidate "
                                       f"cannot decide this one")
    # AUFLAGE C2 (Runde 2): sdist/wheel-Digests werden aus den TATSAECHLICH gebauten Dateien
    # nachgerechnet, nicht als freie Eingabe geglaubt. Fehlen die gebauten Dateien, ist das eine
    # Aussage ueber die UMGEBUNG (kein frischer Bau vorhanden) — DATA_BLOCKED, nie ein Bestehen aus
    # unverifizierten Strings.
    sdist_p, wheel_p, dist_grund = _dist_files(repo, version)
    if sdist_p is None or wheel_p is None:
        return ART_UNMEASURABLE_HERE, (
            f"the candidate sdist/wheel digests cannot be recomputed here: {dist_grund} — build the "
            "candidate first (`python scripts/build_reproducible.py --outdir dist`); an "
            "un-recomputed digest is not evidence")
    live_sdist = hashlib.sha256(sdist_p.read_bytes()).hexdigest()
    live_wheel = hashlib.sha256(wheel_p.read_bytes()).hexdigest()
    if kandidat["sdist_sha256"] != live_sdist:
        return ART_CANDIDATE_UNBOUND, (
            f"the artifact claims sdist sha256 {kandidat['sdist_sha256'][:12]}… but the built "
            f"sdist here ({sdist_p.name}) is {live_sdist[:12]}… — a free digest string is not proof")
    if kandidat["wheel_sha256"] != live_wheel:
        return ART_CANDIDATE_UNBOUND, (
            f"the artifact claims wheel sha256 {kandidat['wheel_sha256'][:12]}… but the built "
            f"wheel here ({wheel_p.name}) is {live_wheel[:12]}… — a free digest string is not proof")
    return None


def _gate_line_error(body: dict) -> tuple[str, str] | None:
    """``(zustand, grund)`` wenn die GATE-ZEILE fehlt, unformig ist oder einen ANDEREN Lauf bezeugt.

    WARUM ES DIESES FELD GIBT (Release-Standard 6.0.0 vom 05.09.2026, Zeile 18, woertlich): „Damit die
    Baumaschine nicht ihre eigene Freigabe beglaubigt, traegt jedes signierte Artefakt Kandidatenbindung
    (Commit, sdist- und wheel-Digest, Werkzeugversion, Zeit) und die Gate-Zeile des Lauf-5-Verdikts als
    Feld. Der Verifier prueft die Bindung, nicht nur die Signatur."

    Ohne diese Zeile beglaubigt der Farmer sich selbst: er misst, er signiert, er released — und die
    Signatur sagt nur, dass ER es war, nicht dass ein Tor es durchgelassen hat. Die Gate-Zeile ist die
    fremde Instanz IM signierten Rumpf.

    DIE BINDUNG, die hier wirklich geprueft wird: ``gate_zeile.head`` muss der ``candidate.commit``
    sein. Ein Verdikt ueber einen anderen Kopf ist ein Verdikt ueber eine andere Sache; genau daran
    faellt die Gate-Zeile eines FREMDEN Laufs.

    UND DAS VERDIKT, seit 2026-09-07: die Zeile muss ihr eigenes Urteil tragen, und es muss ein
    Bestehen sein. Vorher band sie nur die HERKUNFT des Laufs — welche Gate-Fassung, welcher
    Workflow, welcher Kopf — und ein Lauf mit `verdict: FIX_FIRST` bestand die Pruefung vollstaendig.

    EHRLICHE GRENZE, aufgeschrieben statt geglaettet: eine gefaelschte Gate-Zeile fuer DENSELBEN Kopf
    ist hier nicht unterscheidbar, solange der ``workflow_sha256`` des entscheidenden Laufs nirgends
    gepinnt ist. Sobald das Verdikt von Lauf 5 existiert, ist das eine Zeile mehr (Vergleich gegen
    einen eingecheckten Erwartungswert, gelesen wie der Vertrauensanker aus dem committeten Baum).
    """
    zeile = body.get("gate_zeile")
    if not isinstance(zeile, dict):
        return ART_GATE_LINE_UNBOUND, ("the artifact carries no `gate_zeile` — nothing but its own "
                                       "signature vouches for it, and a build machine that signs its "
                                       "own release attests nothing")
    fehlend = []
    for feld, form in _GATE_LINE_FIELDS:
        wert = zeile.get(feld)
        if not isinstance(wert, str) or not wert.strip():
            fehlend.append(f"gate_zeile.{feld}={wert!r}")
        elif form is not None and not form.fullmatch(wert):
            fehlend.append(f"gate_zeile.{feld}={wert!r} (malformed)")
    if fehlend:
        return ART_GATE_LINE_UNBOUND, f"the gate line is incomplete or malformed: {', '.join(fehlend)}"
    if zeile["verdict"] not in _GATE_VERDICTS_PASS:
        return ART_GATE_LINE_UNBOUND, (
            f"the gate line reports verdict {zeile['verdict']!r}, which is not a pass "
            f"({sorted(_GATE_VERDICTS_PASS)}) — a run that did not withstand cannot release, and an "
            "unknown verdict stops the train rather than passing it")
    kandidat = body.get("candidate") or {}
    if zeile["head"] != kandidat.get("commit"):
        return ART_GATE_LINE_UNBOUND, (f"the gate line attests head {zeile['head'][:12]}… but the "
                                       f"artifact binds commit {str(kandidat.get('commit'))[:12]}… — "
                                       f"a verdict about another head cannot release this one")
    return None


def _provenance_error(body: dict) -> tuple[str, str] | None:
    """``(zustand, grund)`` wenn Erzeuger, Eingabe-Digest, Zeit oder Signiererrolle fehlen."""
    erzeuger = body.get("producer")
    fehlend = []
    if not isinstance(erzeuger, dict):
        fehlend.append("producer")
    else:
        for feld in ("tool", "tool_version"):
            wert = erzeuger.get(feld)
            if not isinstance(wert, str) or not wert.strip():
                fehlend.append(f"producer.{feld}={wert!r}")
    eingabe = body.get("input_digest")
    if not isinstance(eingabe, str) or not _HEX64.fullmatch(eingabe):
        fehlend.append(f"input_digest={eingabe!r}")
    rolle = body.get("signer_role")
    if not isinstance(rolle, str) or not rolle.strip():
        fehlend.append(f"signer_role={rolle!r}")
    zeit = body.get("produced_at")
    if not isinstance(zeit, str) or not _RFC3339_Z.match(zeit):
        fehlend.append(f"produced_at={zeit!r}")
    if fehlend:
        return ART_PROVENANCE_INCOMPLETE, ("the artifact does not state its own provenance: "
                                           f"{', '.join(fehlend)}")
    return None


def _freshness_error(body: dict, *, jetzt: datetime | None = None) -> tuple[str, str] | None:
    """``(zustand, grund)`` wenn die Evidenz aus der Zukunft oder aus dem Vorleben stammt."""
    zeit = body.get("produced_at")
    if not isinstance(zeit, str):
        return ART_PROVENANCE_INCOMPLETE, f"produced_at={zeit!r} is not a timestamp at all"
    form = "%Y-%m-%dT%H:%M:%S.%f%z" if "." in zeit else "%Y-%m-%dT%H:%M:%S%z"
    try:
        erzeugt = datetime.strptime(zeit.replace("Z", "+0000"), form)
    except ValueError as exc:
        return ART_PROVENANCE_INCOMPLETE, f"produced_at={zeit!r} is not a usable timestamp: {exc}"
    jetzt = jetzt or datetime.now(timezone.utc)
    if erzeugt > jetzt + _EVIDENCE_FUTURE_SKEW:
        return ART_STALE, f"produced_at={zeit} lies in the future — evidence cannot precede its run"
    if erzeugt < jetzt - timedelta(days=_EVIDENCE_MAX_AGE_DAYS):
        alter = (jetzt - erzeugt).days
        return ART_STALE, (f"produced_at={zeit} is {alter} days old, past the declared "
                           f"{_EVIDENCE_MAX_AGE_DAYS}-day evidence window")
    return None


def _signed_versioned_artifact(rel: str, version: str, *,
                               counters: dict[str, int] | tuple[str, ...] = (),
                               positive_numeric: tuple[str, ...] = (),
                               failure_fields: tuple[str, ...] = (),
                               consistency_pairs: tuple[tuple[str, str], ...] = (),
                               schema: str | None = None, ok_field: str | None = "ok",
                               repo: Path | None = None) -> dict:
    """Der EINE Zulassungspfad, ueber den jede freigabeentscheidende Pruefung ihre Evidenz holt.

    Gibt ``{"state", "detail", "signed_body", "unverified", "source_digest"}`` zurueck und wirft nie:
    eine feindliche Evidenz ist ein sauberes Urteil, kein Absturz. ``state == ART_VERIFIED`` ist die
    EINZIGE Antwort, aus der eine Pruefung ein Bestehen bilden darf, und dann steht der zugelassene
    Rumpf unter ``signed_body`` — ohne den Signatur-Umschlag, so dass ein nicht mitsignierten Feld
    auf diesem Weg gar nicht erst existiert (P-A7). ``_artifact_verdict`` uebersetzt alles andere.

    AUFLAGE C4 (Runde 2): jedes hier genannte Feld ist VERPFLICHTEND und TYPGENAU. Fehlt es oder
    hat es den falschen Typ, ist das ein Gestaendnis wie jeder andere Widerspruch — nicht ein Feld,
    das man ausliess und damit ungeprueft liess.

    * ``counters`` — Zaehlfelder: nichtnegative GANZZAHLEN (kein Float, keine Bool) mit einem
      ZEILENSPEZIFISCHEN Mindestwert. Als ``dict[name, mindestwert]`` uebergeben; ein reines
      Namens-Tupel (Rueckwaertskompatibilitaet) bedeutet Mindestwert 1 fuer jeden Namen — die alte
      "muss > 0 sein"-Regel. Fehlt ein Feld, hat den falschen Typ oder unterschreitet seinen
      Mindestwert, ist das ein Gestaendnis (P-A5): ein Lauf, der nichts (Nachweisbares) getan hat,
      kann nicht zeigen, dass nichts kaputt ist.
    * ``positive_numeric`` — Messfelder, die keine reinen Zaehler sind (z.B. eine Dauer in Sekunden)
      und darum Ganzzahl ODER Gleitkommazahl sein duerfen, aber ebenso VERPFLICHTEND vorhanden,
      typgenau und ``> 0`` sein muessen.
    * ``failure_fields`` — die eigenen Fehlerfelder. VERPFLICHTEND vorhanden; nichtleer/ungleich
      null = die Evidenz meldet ihr eigenes Scheitern, und das wird geehrt statt uebergangen (P-A6).
    * ``consistency_pairs`` — (Liste, Zaehler): beide VERPFLICHTEND und typgenau (Liste/Dict bzw.
      Ganzzahl); widersprechen sie einander, ist die Evidenz in sich widerlegt. Genau daran fiel D4:
      ``untriaged_crash_count=0`` neben nichtleerer ``untriaged_crashes``-Liste.
    * ``ok_field`` — das Selbsturteil. VERPFLICHTEND vorhanden (wenn nicht ``None``); steht es auf
      etwas anderem als ``True`` oder fehlt es, ist es ein Gestaendnis und keine Evidenz.
    """
    if not isinstance(counters, dict):
        counters = {feld: 1 for feld in counters}
    basis = Path(repo) if repo is not None else REPO
    p = basis / rel
    leer = {"signed_body": None, "unverified": None, "source_digest": None}
    if not p.is_file():
        return {"state": ART_ABSENT, "detail": f"{rel} is absent", **leer}
    try:
        roh = p.read_bytes()
    except OSError as exc:
        return {"state": ART_MALFORMED, "detail": f"{rel} is unreadable: {exc}", **leer}
    digest = "sha256:" + hashlib.sha256(roh).hexdigest()
    if not roh.strip():
        return {"state": ART_MALFORMED, "detail": f"{rel} is empty (zero bytes of content)",
                "signed_body": None, "unverified": None, "source_digest": digest}
    try:
        art = json.loads(roh.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        return {"state": ART_MALFORMED, "detail": f"{rel} is not valid JSON: {exc}",
                "signed_body": None, "unverified": None, "source_digest": digest}
    if not isinstance(art, dict):
        return {"state": ART_MALFORMED, "detail": f"{rel} is not a JSON object",
                "signed_body": None, "unverified": None, "source_digest": digest}
    rumpf = {k: v for k, v in art.items() if k != "signature"}
    umgebung = {"signed_body": None, "unverified": rumpf, "source_digest": digest}

    def _nein(zustand_grund):
        zustand, grund = zustand_grund
        return {"state": zustand, "detail": f"{rel}: {grund}", **umgebung}

    if schema is not None and rumpf.get("schema") != schema:
        return _nein((ART_SCHEMA_MISMATCH,
                      f"declares schema {rumpf.get('schema')!r}, expected {schema!r}"))
    gefunden = rumpf.get("version")
    if not isinstance(gefunden, str) or not gefunden:
        return _nein((ART_VERSION_UNBOUND,
                      f"carries no version field, so it cannot be shown to be about {version!r}"))
    if gefunden != version:
        return _nein((ART_VERSION_UNBOUND,
                      f"is scoped to {gefunden!r}, the version under test is {version!r} — evidence "
                      f"about another release cannot decide this one"))
    fehler = _candidate_binding_error(rumpf, basis, version)
    if fehler is not None:
        return _nein(fehler)
    fehler = _gate_line_error(rumpf)
    if fehler is not None:
        return _nein(fehler)
    fehler = _provenance_error(rumpf)
    if fehler is not None:
        return _nein(fehler)
    fehler = _freshness_error(rumpf)
    if fehler is not None:
        return _nein(fehler)
    ohne_arbeit = []
    for feld, mindest in counters.items():
        wert = rumpf.get(feld)
        if feld not in rumpf:
            ohne_arbeit.append(f"{feld} is missing (mandatory counter)")
        elif isinstance(wert, bool) or not isinstance(wert, int):
            ohne_arbeit.append(f"{feld}={wert!r} (must be a non-negative integer, not {type(wert).__name__})")
        elif wert < 0:
            ohne_arbeit.append(f"{feld}={wert!r} (must be non-negative)")
        elif wert < mindest:
            ohne_arbeit.append(f"{feld}={wert!r} (below the required minimum {mindest})")
    for feld in positive_numeric:
        wert = rumpf.get(feld)
        if feld not in rumpf:
            ohne_arbeit.append(f"{feld} is missing (mandatory)")
        elif isinstance(wert, bool) or not isinstance(wert, (int, float)) or wert <= 0:
            ohne_arbeit.append(f"{feld}={wert!r}")
    if ohne_arbeit:
        return _nein((ART_VACUOUS,
                      f"records no work ({', '.join(ohne_arbeit)}) — a signed 'ok' over zero/missing "
                      f"counters is not evidence"))
    gestaendnis = []
    if ok_field is not None:
        if ok_field not in rumpf:
            gestaendnis.append(f"{ok_field} is missing (mandatory)")
        elif rumpf.get(ok_field) is not True:
            gestaendnis.append(f"{ok_field}={rumpf.get(ok_field)!r}")
    for feld in failure_fields:
        if feld not in rumpf:
            gestaendnis.append(f"{feld} is missing (mandatory failure field)")
            continue
        wert = rumpf[feld]
        if isinstance(wert, bool):
            if wert:
                gestaendnis.append(f"{feld}=True")
        elif isinstance(wert, (int, float)):
            if wert != 0:
                gestaendnis.append(f"{feld}={wert!r}")
        elif isinstance(wert, (list, dict, str)):
            if len(wert) > 0:
                gestaendnis.append(f"{feld} carries {len(wert)} entr(y/ies)")
        else:
            gestaendnis.append(f"{feld}={wert!r} has an unexpected type {type(wert).__name__}")
    for liste, zaehler in consistency_pairs:
        w_l, w_z = rumpf.get(liste), rumpf.get(zaehler)
        if not isinstance(w_l, (list, dict)):
            gestaendnis.append(f"{liste}={w_l!r} is missing or not a list/dict (mandatory for the "
                               f"{liste}/{zaehler} consistency check)")
        elif not isinstance(w_z, int) or isinstance(w_z, bool):
            gestaendnis.append(f"{zaehler}={w_z!r} is missing or not an integer (mandatory for the "
                               f"{liste}/{zaehler} consistency check)")
        elif len(w_l) != w_z:
            gestaendnis.append(f"{liste} has {len(w_l)} entr(y/ies) but {zaehler}={w_z}")
    if gestaendnis:
        return _nein((ART_SELF_REPORTED_FAILURE, f"contradicts its own pass: {'; '.join(gestaendnis)}"))
    trusted, anker = _trust_anchor(basis)
    zustand, grund = _artifact_signature_ok(art, trusted, anker, repo=basis)
    if zustand != ART_VERIFIED:
        return _nein((zustand, grund))
    return {"state": ART_VERIFIED, "detail": f"{rel}: {grund}", "signed_body": rumpf,
            "unverified": rumpf, "source_digest": digest}


#: Die Abhilfe steht an jeder roten Zeile, weil ein Riegel ohne Weg daran vorbei nur aergert.
_ABHILFE_SIGNIEREN = ("Re-run the measurement for this candidate and sign it with "
                      "`scripts/sign_readiness_artifact.py`, then pin the signing key's public half "
                      f"in {READINESS_TRUST_ANCHOR_REL} in an owner-approved commit")


def _artifact_verdict(res: dict, *, absent: str = FAIL) -> tuple[str, str]:
    """Die EINE Uebersetzung Zustand -> Verdikt.

    Nur ``ART_UNMEASURABLE_HERE`` ist DATA_BLOCKED, denn nur er sagt etwas ueber die UMGEBUNG
    (Auflage C2). ``absent`` ist der einzige Freiheitsgrad, weil eine fehlende Datei je nach Pflicht
    „die Evidenz fehlt" (FAIL) oder „diese Umgebung erzeugt sie nicht" (DATA_BLOCKED) heisst — und
    welcher der beiden Faelle vorliegt, weiss nur die aufrufende Pflicht, die es dann MISST.
    """
    zustand, grund = res["state"], res["detail"]
    if zustand == ART_ABSENT:
        return absent, grund
    if zustand in _ART_DATA_BLOCKED_STATES:
        return DATA_BLOCKED, grund
    return FAIL, grund


# --- the 33 checks. Each returns (verdict, detail). Wrapped so one erroring check never crashes all. ---

def _ci_falsey_if(cond) -> bool:
    """True iff a GitHub Actions ``if:`` disables the job/step (literal false / 'false' / ${{ false }})."""
    if cond is False:
        return True
    if isinstance(cond, str):
        c = cond.strip().lower().replace("${{", "").replace("}}", "").strip()
        return c in ("false", "0")
    return False


def _ci_continues_on_error(node: dict) -> bool:
    """True iff a job/step declares ``continue-on-error: true`` (or the ``${{ true }}`` /
    ``'true'`` spellings GitHub Actions also accepts).

    AUFLAGE C7 (Runde 2): a job or step that continues on error cannot BLOCK the workflow no matter
    what its ``run:`` does — the same disabling effect as ``if: false``, just the other side of
    "ran but was ignored" instead of "did not run". ci.yml legitimately uses this on genuinely
    advisory jobs (``branch-base``, ``rust-parity``); what must never happen is the DECISIVE
    test/build/use step inheriting that shape and still being read as "declared and enabled"."""
    cond = node.get("continue-on-error")
    if cond is True:
        return True
    if isinstance(cond, str):
        c = cond.strip().lower().replace("${{", "").replace("}}", "").strip()
        return c in ("true", "1")
    return False


#: Flaggen, die aus einem `python -m build`/`-m pip` einen NICHT-ausfuehrenden Aufruf machen (nur
#: die Hilfe wird gedruckt, oder gefragt wird, ohne etwas zu tun) — Auflage C7 (Runde 2): ein Aufruf
#: mit einer dieser Flaggen deklariert KEINEN Bau, auch wenn das Modul ``build``/``pip`` heisst.
_NICHT_AUSFUEHREND = {"--help", "-h"}


def _is_real_test_invocation(argv: list[str]) -> bool:
    """True iff ``argv`` (one shell command, tokenised, leading ``VAR=value`` env assignments already
    stepped over) is a real, EXECUTING test-suite invocation. The command HEAD — the program actually
    run — must itself be a test runner: ``pytest`` / ``py.test`` / ``python -m pytest`` /
    ``python -m unittest`` / ``unittest discover``. It must NOT be a collect-only dry run
    (``--collect-only`` / ``--co``, which imports the tests but executes none).

    This is why the inspection commands that merely NAME pytest do NOT count: their head is
    ``which`` / ``command`` / ``pip`` / ``grep`` / ``find`` / ``ls`` / ``echo`` — not a runner — so
    ``which pytest``, ``command -v pytest``, ``pip show pytest``, ``grep -r pytest``,
    ``find -iname pytest.ini`` and ``ls pytest`` all return False here. ``make test`` and ``tox`` are
    deliberately NOT recognised (a documented known limitation — see AUDITOR_OPEN_POINTS.md); they run
    tests indirectly, and recognising them would need parsing the Makefile/tox config."""
    if not argv:
        return False
    head = argv[0].lower()
    rest = [a.lower() for a in argv[1:]]
    dry_run = "--collect-only" in rest or "--co" in rest
    if head in ("pytest", "py.test"):
        return not dry_run
    if re.fullmatch(r"python[0-9.]*", head):
        # a real ``python -m pytest`` / ``python -m unittest`` run; the module after -m is decisive.
        if "-m" in argv[1:]:
            mi = argv.index("-m", 1)
            mod = argv[mi + 1].lower() if mi + 1 < len(argv) else ""
            if mod == "pytest":
                return not dry_run
            if mod == "unittest":
                return True  # `python -m unittest [discover ...]` executes the suite
        return False
    if head == "unittest" and "discover" in rest:
        return True
    return False


def _ci_run_is_test(run: str) -> bool:
    """True iff a step's ``run:`` shell script actually EXECUTES the test suite. Comments are stripped
    and each ``;`` / ``&&`` / ``||`` / ``|``-separated command is judged in isolation by
    ``_is_real_test_invocation`` on its executed head (leading ``VAR=value`` env assignments stepped
    over), so ``echo x && pytest`` still counts the pytest half. A ``pytest`` named only inside a shell
    comment or an ``echo`` argument never runs; ``pip install pytest`` installs but does not run; and
    ``which pytest`` / ``pytest --collect-only`` do not execute the suite — none of them masquerade as
    a test step."""
    for raw in run.splitlines():
        # drop a shell comment (a '#' that starts a token) through end of line
        m = re.search(r"(?:^|\s)#", raw)
        line = raw[:m.start()] if m else raw
        # evaluate each shell command in isolation so `echo x && pytest` still counts the pytest half
        for cmd in re.split(r";|&&|\|\||\|", line):
            toks = cmd.strip().split()
            i = 0
            while i < len(toks) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", toks[i]):
                i += 1  # step over leading `PYTHONPATH=src` style env assignments
            argv = toks[i:]
            if not argv:
                continue
            if argv[0].lower() in ("echo", "printf", ":", "true", "false"):
                continue  # a printed argument is not an executing test command
            if "install" in cmd.lower():
                continue  # `pip install pytest` installs the runner, it does not run tests
            if _is_real_test_invocation(argv):
                return True
    return False


def _ci_workflow_facts(ci_text: str) -> tuple[bool, bool]:
    """Parse a CI workflow as YAML and return ``(named_ci, has_executing_test_step)``.

    named_ci — the parsed document's top-level ``name`` is 'CI' (a commented-out ``# name: CI`` does
    not count, because YAML parsing drops comments).
    has_executing_test_step — at least one NON-disabled, NON-continue-on-error job has a
    NON-disabled, NON-continue-on-error step whose ``run:`` executes the test suite (see
    ``_ci_run_is_test``). An ``if: false`` job or step is skipped, so a real pytest command inside a
    disabled job is correctly ignored. AUFLAGE C7 (Runde 2): so is ``continue-on-error: true`` — a
    step that cannot fail the build declares nothing decisive, however real its ``run:`` is."""
    import yaml  # noqa: PLC0415 — parse the workflow, never a file-wide substring scan
    try:
        doc = yaml.safe_load(ci_text)
    except yaml.YAMLError:
        return False, False
    if not isinstance(doc, dict):
        return False, False
    named_ci = str(doc.get("name", "")).strip().lower() == "ci"
    has_test = False
    jobs = doc.get("jobs")
    if isinstance(jobs, dict):
        for job in jobs.values():
            if not isinstance(job, dict) or _ci_falsey_if(job.get("if")) \
                    or _ci_continues_on_error(job):
                continue
            for step in job.get("steps") or []:
                if not isinstance(step, dict) or _ci_falsey_if(step.get("if")) \
                        or _ci_continues_on_error(step):
                    continue
                run = step.get("run")
                if isinstance(run, str) and _ci_run_is_test(run):
                    has_test = True
                    break
            if has_test:
                break
    return named_ci, has_test


#: Ein Pfad, der auf die Distribution zeigt (`dist/`, ein sdist, ein Rad).
_DIST_ARTIFACT = re.compile(r"dist/|\.tar\.gz|\.whl")
#: Programme, die eine GEBAUTE Distribution konsumieren (Basisname des ausgefuehrten Kopfes).
_DIST_CONSUMERS = {"pip", "pip3", "tar", "unzip", "twine"}
#: Koepfe, die selbst ein Distributionspaket bauen.
_DIST_BUILDER_HEADS = {"pyproject-build"}
#: Skripte dieses Repos, deren Aufruf ein Distributionspaket erzeugt.
_DIST_BUILDER_SCRIPTS = ("build_reproducible.py",)


def _pfad_norm(p: str) -> str:
    """Ein Ordnerpfad in Vergleichsform: ohne fuehrendes ``./``, ohne Schraegstrich am Ende."""
    q = p.strip().strip("'\"")
    while q.startswith("./"):
        q = q[2:]
    return q.rstrip("/") or "."


#: Die Flaggen, mit denen die bekannten Bauwege ihr Ausgabeverzeichnis nennen. Fehlt eine, gilt die
#: Voreinstellung ``dist`` — das ist die Konvention von ``python -m build`` und von
#: ``scripts/build_reproducible.py``, und sie zu raten waere hier falsch: sie ist dokumentiert.
_AUSGABE_FLAGGEN = ("--outdir", "-o", "--wheel-dir", "--sdist-dir")


def _ausgabeordner(argv: list[str]) -> str:
    """WOHIN baut dieses Kommando? Aus der Flagge, sonst die dokumentierte Voreinstellung."""
    for i, a in enumerate(argv):
        if a in _AUSGABE_FLAGGEN and i + 1 < len(argv):
            return _pfad_norm(argv[i + 1])
        for f in _AUSGABE_FLAGGEN:
            if a.startswith(f + "="):
                return _pfad_norm(a.split("=", 1)[1])
    return "dist"


def _artefakt_ordner(argv: list[str]) -> set[str]:
    """AUS WELCHEM Ordner nimmt dieses Kommando eine Distribution?

    Gesucht wird je Argument, ob es auf eine Distribution zeigt (``.tar.gz``, ``.whl`` oder ein
    Pfad unter einem Verzeichnis) — der ORDNERTEIL davon ist die Antwort. Ein Argument ohne
    Verzeichnisanteil (``proofbundle-6.0.0.whl`` im Arbeitsverzeichnis) ergibt ``.``.
    """
    aus: set[str] = set()
    for a in argv[1:]:
        roh = a.strip("'\"")
        if not (roh.endswith(".whl") or roh.endswith(".tar.gz") or "/" in roh):
            continue
        if not _DIST_ARTIFACT.search(roh):
            continue
        aus.add(_pfad_norm(roh.rsplit("/", 1)[0]) if "/" in roh else ".")
    return aus


def _run_touches_distribution(run: str) -> list[tuple[str, str]]:
    """Die Kommandos EINES ``run:``-Skripts als geordnete Liste ``(art, ordner)``.

    ART IST ``baut`` ODER ``benutzt``, ORDNER ist der Pfad, um den es geht — und die REIHENFOLGE
    bleibt erhalten. Das ist die Aenderung aus Review Runde 3, Abschnitt 3, Punkt 6: vorher gab
    diese Funktion zwei Wahrheitswerte zurueck, und der Aufrufer verknuepfte sie im selben Job mit
    UND. Damit genuegte „irgendein Buildbefehl neben irgendeinem Zugriff auf dist/" — ein Job, der
    zuerst ein altes Wheel installiert und spaeter in einen anderen Ordner baut, bestand. Gleich-
    zeitigkeit im selben Job ist keine Datenflussrelation.

    Das Alte steht weiter darunter:

    Dieselbe Zerlegung wie ``_ci_run_is_test``: Shell-Kommentare fallen weg, jedes durch ``;``/``&&``/
    ``||``/``|`` getrennte Kommando wird einzeln beurteilt, fuehrende ``VAR=wert``-Zuweisungen werden
    uebersprungen, und ``echo``/``printf`` zaehlen nie — ein gedrucktes Argument fuehrt nichts aus.

    EHRLICHE GRENZE, gleiche Form wie beim Nachbarn: die Erkennung ist eine Positivliste von Koepfen.
    ``make sdist`` oder ``tox -e build`` werden absichtlich NICHT erkannt (sie bauen indirekt; sie zu
    erkennen hiesse Makefile/tox-Konfiguration zu parsen). Das ist dieselbe dokumentierte Grenze, die
    ``_is_real_test_invocation`` fuer ``make test``/``tox`` traegt.
    """
    schritte: list[tuple[str, str]] = []
    for roh in run.splitlines():
        m = re.search(r"(?:^|\s)#", roh)
        zeile = roh[:m.start()] if m else roh
        for cmd in re.split(r";|&&|\|\||\|", zeile):
            toks = cmd.strip().split()
            i = 0
            while i < len(toks) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", toks[i]):
                i += 1
            argv = toks[i:]
            if not argv:
                continue
            kopf = argv[0].rsplit("/", 1)[-1].lower()
            if kopf in ("echo", "printf", ":", "true", "false"):
                continue
            rest = [a.lower() for a in argv[1:]]
            # AUFLAGE C7 (Runde 2): `python -m build --help` prints usage and builds nothing; it
            # must not count as a declared build just because the module is named `build`.
            hilfe_nur = bool(_NICHT_AUSFUEHREND & set(rest))
            if kopf in _DIST_BUILDER_HEADS and not hilfe_nur:
                schritte.append(("baut", _ausgabeordner(argv)))
            elif re.fullmatch(r"python[0-9.]*", kopf):
                if "-m" in argv[1:] and not hilfe_nur:
                    mi = argv.index("-m", 1)
                    mod = argv[mi + 1].lower() if mi + 1 < len(argv) else ""
                    if mod == "build":
                        schritte.append(("baut", _ausgabeordner(argv)))
                    elif mod == "pip" and _DIST_ARTIFACT.search(cmd):
                        for o in _artefakt_ordner(argv):
                            schritte.append(("benutzt", o))
                if any(a.endswith(_DIST_BUILDER_SCRIPTS) for a in rest) and not hilfe_nur:
                    schritte.append(("baut", _ausgabeordner(argv)))
            elif kopf in _DIST_CONSUMERS and _DIST_ARTIFACT.search(cmd) and not hilfe_nur:
                for o in _artefakt_ordner(argv):
                    schritte.append(("benutzt", o))
    return schritte


def _published_artifact_leg_facts(text: str) -> tuple[bool, bool]:
    """``(deklariert_bau, deklariert_benutzung)`` aus dem YAML-Dokument.

    LIEST DEKLARATION, NICHT AUSFUEHRUNG. Ein ``run:``-Skript ist Quelltext; dass es lief, steht
    nirgends darin. Der Aufrufer sagt deshalb „deklariert und eingeschaltet" und nicht „gelaufen"
    (Auflage C4).

    STRUKTURELL STATT LEXIKALISCH (Tiefen-Gate 2026-09-05, Fund L5-G7-04, P3). Hier stand
    ``"sdist" in pub.lower() or "published" in pub.lower() or "cleanroom" in pub.lower()`` — eine rohe
    Teilzeichenketten-Suche ueber die GANZE Datei. Gemessen: eine
    ``published-artifact-gate.yml`` mit ``name: nothing``, leeren ``jobs: {}`` und der einen
    Kommentarzeile „this file used to check the sdist; the leg was removed" ergab PASS. Ein Kommentar,
    der die ENTFERNUNG des Beins behauptet, erteilte also das Bestehen fuer sein Vorhandensein.

    YAML-Parsen loescht Kommentare, ``if: false`` schaltet Job und Schritt ab, und gezaehlt wird nur,
    was ein ``run:`` wirklich AUSFUEHRT — dieselbe Bauform, die ``_ci_workflow_facts`` fuer die
    Fliessband-Datei schon traegt.

    AUFLAGE C7 (Runde 2), ZWEI WEITERE HAERTUNGEN:

    * ``continue-on-error: true`` auf Job ODER Schritt zaehlt wie ``if: false`` NICHT — ein Schritt,
      der den Lauf nicht scheitern lassen kann, deklariert nichts Entscheidendes, egal wie real sein
      ``run:`` aussieht.
    * BAU und BENUTZUNG muessen im SELBEN Job stehen, nicht nur irgendwo in der Datei. Vorher wurden
      beide global ueber ALLE Jobs ODER-verknuepft: ein Job, der nur baut, und ein voellig
      unverbundener zweiter Job, der zufaellig ``pip install dist/...`` in einem anderen
      Zusammenhang ausfuehrt, haetten zusammen ``True, True`` ergeben — ohne dass ein einziger Job
      tatsaechlich den gebauten Artefakt benutzt (fehlender Artefaktfluss). Das reale
      ``hermetic-cleanroom``-Bein baut UND installiert im selben Job; diese Engführung bildet genau
      das ab und nichts Schwaecheres.
    """
    import yaml  # noqa: PLC0415 — parse the workflow, never a file-wide substring scan
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return False, False
    if not isinstance(doc, dict):
        return False, False
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        return False, False
    for job in jobs.values():
        if not isinstance(job, dict) or _ci_falsey_if(job.get("if")) or _ci_continues_on_error(job):
            continue
        # ALLE Kommandos des Jobs in AUSFUEHRUNGSREIHENFOLGE, ueber die Schritte hinweg. Der
        # Artefaktfluss ist eine Aussage ueber ein VORHER und ein NACHHER; eine Menge kennt keins.
        kette: list[tuple[str, str]] = []
        for step in job.get("steps") or []:
            if not isinstance(step, dict) or _ci_falsey_if(step.get("if")) \
                    or _ci_continues_on_error(step):
                continue
            run = step.get("run")
            if not isinstance(run, str):
                continue
            kette.extend(_run_touches_distribution(run))
        # DIE RELATION, und sie ist die ganze Auflage: es gibt einen Bau nach `P` und DANACH eine
        # Benutzung AUS `P`. Ein spaeterer Bau in einen anderen Ordner hilft nicht, eine fruehere
        # Installation aus `P` auch nicht — beides war vorher ein Bestehen.
        for i, (art_i, ordner_i) in enumerate(kette):
            if art_i != "baut":
                continue
            for art_j, ordner_j in kette[i + 1:]:
                if art_j == "benutzt" and ordner_j == ordner_i:
                    return True, True
    return False, False


def c1_1_two_ci_gates(repo: Path = REPO):
    """ZWEI GATE-KONFIGURATIONEN sind DEKLARIERT UND EINGESCHALTET — und genau das, nicht mehr.

    ─ DIE AUSSAGE ZUERST, dann die Pruefung (Auflage C4 des Gegenlesers) ────────────────────────
    Diese Zeile behauptet: in den committeten Workflow-Dateien steht je ein NICHT abgeschalteter Job
    mit einem NICHT abgeschalteten Schritt, dessen ``run:`` einen Testlauf beziehungsweise einen Bau
    UND eine Benutzung der Distribution DEKLARIERT. Sie behauptet ausdruecklich NICHT, dass diese
    Workflows fuer DIESEN Kandidaten gelaufen sind oder gruen waren.

    ─ WARUM DIE STAERKERE AUSSAGE HIER NICHT STEHT ──────────────────────────────────────────────
    „Der Testlauf hat stattgefunden" ist eine Aussage ueber eine AUSFUEHRUNG, und die kann kein
    Quelltext belegen. Dafuer braucht es einen kandidatsgebundenen Laufbeleg (Lauf-Kennung,
    Abschluss, Ergebnis, Digest der Workflow-Datei, Bindung an Commit und Baum), signiert vom
    Laeufer. Dieses Repo baut einen solchen Beleg fuer 6.0.0 NICHT. Die staerkere Aussage ist
    deshalb aus der freigabeentscheidenden Matrix HERAUSGENOMMEN statt unbelegt weitergefuehrt zu
    werden; kaeme der Laufbeleg, waere sein Fehlen DATA_BLOCKED und sein Widerspruch FAIL.

    ─ WAS HIER SASS: L5-G7-04 (P3), KLASSE B ───────────────────────────────────────────────────
    Das Bein fuer das veroeffentlichte Artefakt war
    ``"sdist" in pub.lower() or "published" in pub.lower() or "cleanroom" in pub.lower()`` — eine
    rohe Teilzeichenketten-Suche ueber die GANZE Datei. Gemessen: eine
    ``published-artifact-gate.yml`` mit ``name: nothing``, leeren ``jobs: {}`` und der Kommentarzeile
    „this file used to check the sdist; the leg was removed" ergab PASS. Ein Kommentar, der die
    ENTFERNUNG des Beins behauptet, erteilte das Bestehen fuer sein Vorhandensein.

    Das ist eine ANDERE Klasse als L5-G7-02 und wird getrennt gefuehrt: dort geht es um Provenienz
    und Kandidatenbindung ABGELEGTER Evidenz, hier um die Ableitung einer AUSFUEHRUNG aus
    QUELLTEXT. Ein Signaturanker haette diesen Fund nicht verhindert, und eine YAML-Analyse haette
    jenen nicht verhindert.
    """
    pub_text = _read(".github/workflows/published-artifact-gate.yml", repo)
    if not pub_text:
        return FAIL, "published-artifact-gate.yml missing"
    ci_text = _read(".github/workflows/ci.yml", repo)
    if not ci_text:
        return FAIL, "the second CI gate .github/workflows/ci.yml (repository/test gate) is missing"
    # BEIDE Beine werden YAML-geparst (nicht als Datei-Teilzeichenkette gelesen). Fehlt PyYAML hier,
    # ist das ehrlich DATA_BLOCKED und nie ein falsches Gruen — dieselbe Taxonomie wie C9.1. Der
    # Ausgang gilt fuer BEIDE Beine, seit auch das veroeffentlichte Bein strukturell prueft.
    try:
        baut, benutzt = _published_artifact_leg_facts(pub_text)
        named_ci, has_test_step = _ci_workflow_facts(ci_text)
    except ImportError:
        return DATA_BLOCKED, ("PyYAML not installed here — cannot YAML-parse ci.yml / "
                              "published-artifact-gate.yml to inspect the two gate configurations; "
                              "run in the dev/CI image")
    pub_d = hashlib.sha256(pub_text.encode("utf-8")).hexdigest()
    ci_d = hashlib.sha256(ci_text.encode("utf-8")).hexdigest()
    if not (baut and benutzt):
        return FAIL, ("published-artifact-gate.yml declares no enabled published-artifact leg "
                      f"(declares_build={baut}, declares_use_of_built_distribution={benutzt}) — a "
                      "comment, an echo or a disabled job that merely names sdist/cleanroom is not "
                      f"a declaration [workflow sha256 {pub_d[:12]}…]")
    if named_ci and has_test_step:
        return PASS, ("two CI gate CONFIGURATIONS are declared and enabled: ci.yml (name: CI + an "
                      "enabled run: step declaring a pytest/unittest invocation) + "
                      "published-artifact-gate.yml (one non-fault-tolerant job in which a build "
                      "writes to a directory and a LATER command in the same job consumes a "
                      "distribution from THAT directory — declared artifact flow, not mere "
                      "coexistence of a build and some access to dist/). This is configuration "
                      "presence, NOT evidence that either workflow ran for this candidate — that "
                      f"would need a signed, candidate-bound run record [ci.yml sha256 {ci_d[:12]}…, "
                      f"published-artifact-gate.yml sha256 {pub_d[:12]}…]")
    return FAIL, ("ci.yml is present but declares no enabled repository/test gate (needs `name: CI` "
                  "+ an enabled run: step naming pytest/unittest as the executed head, not only a "
                  f"comment/echo/disabled job) [workflow sha256 {ci_d[:12]}…]")


def c1_2_reproducible_normaliser():
    t = _read("scripts/build_reproducible.py")
    ok = "SOURCE_DATE_EPOCH" in t and ("tar" in t.lower())
    return (PASS, "deterministic sdist normaliser present (SOURCE_DATE_EPOCH + canonical tar)") if ok \
        else (FAIL, "build_reproducible.py missing SOURCE_DATE_EPOCH / tar normalisation")


def c1_3_release_sha_gate():
    t = _read(".github/workflows/release.yml")
    return (PASS, "release.yml carries a sha256 digest gate") if "sha256" in t.lower() \
        else (FAIL, "release.yml has no sha256 gate")


@functools.lru_cache(maxsize=1)
def _manifest_gate():
    import test_manifest_gate as tmg
    return tmg.evaluate()


def c2_1_no_collection_errors():
    r = _manifest_gate()
    return (PASS, f"pytest collected {r['collected']} tests, 0 collection errors") if r["errors"] == 0 \
        else (FAIL, f"{r['errors']} collection error(s) — a file silently dropped from the run")


def c2_2_no_missing_suites():
    r = _manifest_gate()
    return (PASS, f"collected {r['collected']} >= floor {r['min_collected_tests']}") \
        if r["collected"] >= r["min_collected_tests"] else (FAIL, "collected count below the locked floor")


def c3_1_manifest_floor():
    r = _manifest_gate()
    return (PASS, f"test manifest floor met (headroom {r['headroom_tests']})") if r["ok"] \
        else (FAIL, "; ".join(r["problems"]))


def c3_2_pytest_only():
    r = _manifest_gate()
    return (PASS, f"{r['pytest_only_modules']} pytest-only module(s) >= floor "
                  f"{r['min_pytest_only_modules']} (unittest-invisible class preserved)") \
        if r["pytest_only_modules"] >= r["min_pytest_only_modules"] \
        else (FAIL, "pytest-only coverage regressed")


def _type_confusion():
    import type_confusion_gate as tcg
    return tcg.evaluate()


def c4_1_never_raise():
    r = _type_confusion()
    return (PASS, f"{r['in_scope']} verifier(s) survive the {r['matrix_size']}-payload matrix, never-raise") \
        if r["never_raise_ok"] else (FAIL, f"{len(r['violations'])} raw-crash violation(s)")


def c4_2_no_needs_fixture():
    r = _type_confusion()
    return (PASS, "0 NEEDS_FIXTURE — every verifier is covered or honestly NON_JSON") \
        if r["needs_fixture"] == 0 else (PENDING, f"{r['needs_fixture']} NEEDS_FIXTURE (coverage owed)")


def c5_1_payloadtype_negatives():
    rc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
         "tests/test_trust_pack_payloadtype_negatives.py"],
        cwd=str(REPO), capture_output=True, text=True, env=_env())
    return (PASS, "trust-pack payloadType/predicateType confusion vectors all reject (never-raise)") \
        if rc.returncode == 0 else (FAIL, "payloadType negative vectors did not all pass")


def c6_1_soak_harness():
    return (PASS, "bounded fuzz-soak harness present") if (REPO / "scripts" / "fuzz_soak.py").is_file() \
        else (FAIL, "scripts/fuzz_soak.py missing")


#: Der Ablageort des aufgezeichneten Fuzz-Soak-Laufs. Das `360` darin ist HISTORIE, keine Bindung —
#: die Bindung ist das signierte `version`-Feld IM Artefakt (siehe `_signed_versioned_artifact`).
_SOAK_ARTIFACT_REL = "audit_artifacts/360/fuzz_soak_latest.json"
_SOAK_SCHEMA = "proofbundle.fuzz_soak.v1"
_VOLLER_SOAK_SEKUNDEN = 86400


def _soak_artifact():
    """Der aufgezeichnete Soak-Lauf, EINMAL gelesen und fuer beide Pflichten (C6.2/C6.3) derselbe."""
    return _signed_versioned_artifact(
        _SOAK_ARTIFACT_REL, VERSION_UNDER_TEST,
        schema=_SOAK_SCHEMA,
        # AUFLAGE C4 (Runde 2): `iterations`/`parsers_soaked` sind reine Zaehlfelder (Ganzzahl, > 0).
        # `elapsed_seconds` ist eine gemessene Dauer (`round(elapsed, 3)` in fuzz_soak.py — ein
        # Float) und gehoert deshalb zu `positive_numeric`, nicht zu den ganzzahligen `counters`.
        counters={"iterations": 1, "parsers_soaked": 1},
        positive_numeric=("elapsed_seconds",),
        failure_fields=("untriaged_crashes", "untriaged_crash_count",
                        "false_accepts", "false_accept_count"),
        consistency_pairs=(("untriaged_crashes", "untriaged_crash_count"),
                           ("false_accepts", "false_accept_count")))


def c6_2_recorded_soak_clean():
    """0 Abstuerze, 0 Falsch-Annahmen — aus ATTESTIERTER Evidenz, nicht aus zwei Zaehlern.

    HIER SASS L5-G7-02 (P2). Die Zeile war `a.get("untriaged_crash_count", 1) == 0 and
    a.get("false_accept_count", 1) == 0`, und sonst nichts: kein Schema, keine Signatur, keine
    Kandidatenbindung, kein Blick auf `ok`, `iterations` oder die Absturz-LISTE. Vier Bestehen
    entstanden daraus im Reproducer, jedes aus einem Artefakt, das nichts belegt.

    FEHLT DIE EVIDENZ, ist das FAIL und nicht DATA_BLOCKED: ein begrenzter Fuzz-Soak laeuft in
    Minuten und braucht keine Sonderumgebung — seine Abwesenheit ist eine Aussage ueber die Arbeit,
    nicht ueber die Maschine. Der 24-Stunden-Lauf ist der Fall, der eine Sonderumgebung braucht, und
    der steht in C6.3.
    """
    res = _soak_artifact()
    if res["state"] != ART_VERIFIED:
        verdikt, grund = _artifact_verdict(res, absent=FAIL)
        return verdikt, f"{grund}. {_ABHILFE_SIGNIEREN}"
    b = res["signed_body"]
    return PASS, (f"recorded soak (signed, candidate-bound, {VERSION_UNDER_TEST}): "
                  f"{b.get('iterations')} iterations over {b.get('parsers_soaked')} parser(s), "
                  f"0 crash, 0 false-accept [{res['source_digest']}]")


def c6_3_full_24h():
    """Der VOLLE 24-Stunden-Lauf. Auch diese Zeile darf ihr Ja nur aus attestierter Evidenz nehmen:
    `a.get("is_full_soak_24h")` war ein Bool in einer unsignierten Datei, also eine Selbstauskunft
    ohne Absender.

    DIE GRENZE, scharf gezogen (Auflage C2): eine UNGUELTIGE Evidenz ist FAIL wie ueberall. Nur zwei
    Faelle sind hier DATA_BLOCKED, und beide sind Aussagen ueber die Umgebung: es liegt GAR KEINE
    Aufzeichnung vor (diese Maschine ist keine Soak-Box), oder es liegt eine gueltige, aber KURZE
    vor (hier standen keine 24 Stunden zur Verfuegung).
    """
    res = _soak_artifact()
    if res["state"] != ART_VERIFIED:
        verdikt, grund = _artifact_verdict(res, absent=DATA_BLOCKED)
        return verdikt, f"{grund}. {_ABHILFE_SIGNIEREN}"
    b = res["signed_body"]
    el = b.get("elapsed_seconds", 0)
    if b.get("is_full_soak_24h") is True and isinstance(el, (int, float)) \
            and el >= _VOLLER_SOAK_SEKUNDEN:
        return PASS, f"a signed, candidate-bound full 24h soak artifact is present ({el}s)"
    return DATA_BLOCKED, (f"the attested soak ran {el}s (is_full_soak_24h="
                          f"{b.get('is_full_soak_24h')!r}), not the full {_VOLLER_SOAK_SEKUNDEN}s — "
                          "run `fuzz_soak.py --duration-seconds 86400` on a soak box (operational "
                          "artifact), then sign it with scripts/sign_readiness_artifact.py")


def _formal():
    # load formal/model.py by path (not `import model`, which a top-level `model` module could shadow)
    import importlib.util  # noqa: PLC0415
    spec = importlib.util.spec_from_file_location("proofbundle_formal_model", REPO / "formal" / "model.py")
    fm = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(fm)
    return fm.prove_all(bound=5)


def c7_1_formal_proven():
    r = _formal()
    return (PASS, f"formal model all non-reserved obligations proven (mode {r['prover_mode']})") \
        if r["all_proven"] else (FAIL, "a non-reserved formal obligation is not proven")


def c7_2_impl_crosscheck():
    r = _formal()
    return (PASS, "formal model grounded against the real implementation") \
        if r["implementation_crosscheck"]["ok"] else (FAIL, "implementation cross-check disagrees")


def c7_3_o7_reserved_honest():
    r = _formal()
    o7 = [o for o in r["obligations"] if o["id"] == "O7_PAYLOADTYPE_BINDING"]
    if not o7:
        return FAIL, "O7 payloadType obligation absent from the model"
    if o7[0]["status"] != "RESERVED":
        return FAIL, "O7 claims a status other than RESERVED (a fake proof would be a No-Fake violation)"
    return PASS, "O7 payloadType obligation present and HONESTLY reserved (code-enforced + vector-tested, no fake proof)"


def c7_4_reserved_slots_honest():
    r = _formal()
    reserved = {o["id"] for o in r["obligations"] if o["status"] == "RESERVED"}
    need = {"O5_TARGET_PIN_NOT_CRYPTO", "O6_RETRACTS_NEVER_RAISES", "O7_PAYLOADTYPE_BINDING"}
    return (PASS, "O5/O6/O7 declared reserved, no fabricated proofs") if need <= reserved \
        else (FAIL, f"expected reserved slots missing: {need - reserved}")


def _rust_parity():
    import rust_parity_gate as rpg
    return rpg.evaluate()


def c8_1_registry_integrity():
    r = _rust_parity()
    return (PASS, f"rust-parity registry integrity ok ({r['covered']} COVERED, {r['partial']} PARTIAL, "
                  f"{r['pending']} PENDING, 0 UNTRACKED/ORPHANED/STALE)") \
        if r["registry_integrity_ok"] else (FAIL, "registry integrity problem (untracked/orphaned/stale)")


_DIFFERENTIAL_ARTIFACT_REL = "audit_artifacts/360/rust_differential_matrix.json"
_DIFFERENTIAL_SCHEMA = "proofbundle.rust_relation_differential_matrix.v1"


def c8_2_differential_agrees():
    """Python == Rust — ueber ZEILEN, nicht ueber ein einzelnes Bool.

    NACHBAR DERSELBEN KLASSE, vom Gate reproduziert (D3): `{"all_agree": true}` — ein JSON mit EINEM
    Schluessel, ohne Schema, ohne Version, ohne Signatur und ohne einen einzigen Vektor — ergab
    „differential matrix: None vector(s), Python==Rust on all". Uebereinstimmung ueber der leeren
    Menge ist wahr und sagt nichts.
    """
    res = _signed_versioned_artifact(
        _DIFFERENTIAL_ARTIFACT_REL, VERSION_UNDER_TEST,
        schema=_DIFFERENTIAL_SCHEMA, counters=("total_relation_vectors",), ok_field=None)
    if res["state"] != ART_VERIFIED:
        # ABWESENHEIT WIRD GEMESSEN, NICHT ANGENOMMEN (Auflage C2). Ohne die Rust-Binaerdatei kann
        # diese Umgebung die Matrix nicht erzeugen — das ist DATA_BLOCKED. IST sie da und die Matrix
        # fehlt trotzdem, hat niemand sie gefahren, und das ist FAIL.
        blockiert = DATA_BLOCKED
        try:
            blockiert = DATA_BLOCKED if not _rust_parity().get("binary_available") else FAIL
        except Exception:                                # noqa: BLE001 — Gate kaputt = nicht messbar
            blockiert = DATA_BLOCKED
        verdikt, grund = _artifact_verdict(res, absent=blockiert)
        return verdikt, f"{grund}. {_ABHILFE_SIGNIEREN}"
    b = res["signed_body"]
    rows = b.get("rows")
    erwartet = b.get("total_relation_vectors")
    if not isinstance(rows, list) or not rows:
        return FAIL, (f"{_DIFFERENTIAL_ARTIFACT_REL} claims {erwartet} vector(s) but carries no rows "
                      "— an agreement over the empty set is vacuous")
    if len(rows) != erwartet:
        return FAIL, (f"{_DIFFERENTIAL_ARTIFACT_REL} claims {erwartet} vector(s) but carries "
                      f"{len(rows)} row(s) — the artifact contradicts its own population")
    uneins = [r.get("caseId") for r in rows
              if not isinstance(r, dict) or r.get("agree_python_rust") is not True]
    if uneins:
        return FAIL, (f"Python and Rust disagree on {len(uneins)} differential vector(s): "
                      f"{uneins[:5]}")
    if b.get("all_agree") is not True:
        return FAIL, (f"{_DIFFERENTIAL_ARTIFACT_REL} carries all_agree="
                      f"{b.get('all_agree')!r} while every row agrees — the artifact contradicts itself")
    return PASS, (f"differential matrix (signed, candidate-bound, {VERSION_UNDER_TEST}): "
                  f"{len(rows)} vector(s), Python==Rust on every row [{res['source_digest']}]")


def c8_3_pending_documented():
    """Jede PENDING-Flaeche nennt IHREN Grund — nicht: irgendwo steht das Wort „rust".

    NACHBAR DERSELBEN KLASSE (Sweep 2026-09-05). Hier stand
    ``documented = bool(doc) or "rust" in json.dumps(slot).lower()``. Beide Beine belegen nichts: das
    erste ist die blosse EXISTENZ einer Datei (57 undokumentierte Flaechen bestanden damit, solange
    die Datei nicht leer war), das zweite eine Teilzeichenketten-Suche ueber einen JSON-Abzug, in dem
    das Wort „rust" an jeder beliebigen Stelle stehen darf — bis hin zum eigenen Slot-Namen.

    STRUKTURELL STATT LEXIKALISCH: die Deklaration steht in der Registry, und dort traegt JEDER
    PENDING-Eintrag seinen eigenen, ausformulierten Grund. Ein Grund, der nur die Kennung wiederholt,
    ist keiner. Die Prosa-Datei bleibt Pflicht — sie ist die menschenlesbare Haelfte —, aber sie
    ersetzt die Deklaration nicht mehr.
    """
    r = _rust_parity()
    if r["pending"] == 0:
        return PASS, "no PENDING Rust surface to document"
    doc = _read("docs/readiness_pack/rust_parity_scope.md")
    if not doc.strip():
        return PENDING, (f"{r['pending']} PENDING Rust surface(s): "
                         "docs/readiness_pack/rust_parity_scope.md is absent or empty")
    ohne_grund = []
    for eintrag in r.get("items") or []:
        if not isinstance(eintrag, dict) or eintrag.get("status") != "PENDING":
            continue
        ref = eintrag.get("python_ref")
        grund = eintrag.get("notes")
        if not isinstance(grund, str) or not grund.strip() or grund.strip() == str(ref).strip():
            ohne_grund.append(ref)
    if ohne_grund:
        return PENDING, (f"{len(ohne_grund)} of {r['pending']} PENDING Rust surface(s) state no "
                         f"reason of their own in scripts/rust_parity_registry.json: "
                         f"{ohne_grund[:5]}")
    return PASS, (f"{r['pending']} PENDING Rust surface(s) honestly documented as deliberately not "
                  f"Rust-covered: the scope doc is present AND every PENDING registry entry states "
                  f"its own reason")


_REPRO_MEASUREMENT_SCHEMA = "proofbundle.reproducible_sdist_check.v1"


def c9_1_two_sdists_identical():
    """Zwei sdists byte-gleich — aus einem STRUKTURIERTEN Messergebnis, nicht aus der Standardausgabe.

    NACHBAR DERSELBEN KLASSE, im selben Durchgang gefegt (Auflage C2 des Gegenlesers). Hier stand
    `rc.returncode == 0 and ("reproducible ok" in out or "byte-identical" in out)` — eine
    freigabeentscheidende Aussage, abgeleitet aus zwei Teilzeichenketten der Standardausgabe. Wer den
    Satz umformuliert, aendert das Urteil; wer ihn zufaellig in einer Warnung unterbringt, erteilt es.
    Das Skript liefert jetzt `--check --json`, und gelesen werden die FELDER.

    DIESE ZEILE MISST SELBST, statt eine abgelegte Evidenz zuzulassen — die Kandidatenbindung ist
    darum trivial erfuellt: gebaut wird der Baum, der hier liegt. Was fehlte, war nicht die
    Provenienz, sondern die Strukturiertheit der Antwort.

    DIE GRENZE (Auflage C2): fehlt das Build-Backend, ist das eine Aussage ueber die UMGEBUNG
    (DATA_BLOCKED) — und sie wird STRUKTURELL festgestellt (`importlib.util.find_spec`), nicht aus
    einer Fehlermeldung gelesen. Unterscheiden sich die beiden Digests, ist das FAIL.
    """
    import importlib.util  # noqa: PLC0415
    t = _read("scripts/build_reproducible.py")
    if not t:
        return FAIL, "build_reproducible.py missing"
    if importlib.util.find_spec("build") is None:
        return DATA_BLOCKED, ("the `build` backend is not importable here — run in the release image "
                              "(the published-artifact-gate proves determinism in CI)")
    rc = subprocess.run([sys.executable, "scripts/build_reproducible.py", "--check", "--json"],
                        cwd=str(REPO), capture_output=True, text=True, env=_env(), timeout=600)
    try:
        mess = json.loads(rc.stdout.strip().splitlines()[-1]) if rc.stdout.strip() else None
    except (ValueError, IndexError):
        mess = None
    if not isinstance(mess, dict) or mess.get("schema") != _REPRO_MEASUREMENT_SCHEMA:
        return DATA_BLOCKED, (f"the determinism check produced no machine-readable measurement here "
                              f"(exit {rc.returncode}) — nothing was measured, so nothing is claimed")
    a, b = str(mess.get("sha256_a") or ""), str(mess.get("sha256_b") or "")
    if not (_HEX64.fullmatch(a) and _HEX64.fullmatch(b)):
        return DATA_BLOCKED, ("the determinism check reported no sdist digests — an empty comparison "
                              "is vacuous, not a pass")
    if mess.get("reproducible") is True and a == b and rc.returncode == 0:
        return PASS, (f"two sdist builds are byte-identical (sha256 {a[:12]}…, "
                      f"SOURCE_DATE_EPOCH {mess.get('epoch')})")
    if mess.get("reproducible") is False or a != b:
        return FAIL, f"two sdist builds are NOT byte-identical (A={a[:12]}… B={b[:12]}…)"
    return DATA_BLOCKED, (f"determinism not conclusively measured in this environment "
                          f"(exit {rc.returncode}); the published-artifact-gate proves it in CI")


def c9_2_slsa_reusable():
    t = _read(".github/workflows/reusable-build-attest.yml")
    return (PASS, "SLSA-L3-shape reusable attest workflow present (signing separated from build)") \
        if t and "attest" in t.lower() else (FAIL, "reusable-build-attest workflow missing")


def _readiness():
    import readiness_pack_gate as rp
    return rp.evaluate()


def c10_1_pack_ok():
    r = _readiness()
    return (PASS, f"readiness pack grounded ({r.get('conclusions')} conclusions, {r.get('release_slots')} slots)") \
        if r["ok"] else (FAIL, "; ".join(r["problems"]))


_PACK_INDEX_REL = "docs/readiness_pack/index.json"
_PACK_MANIFEST_REL = "docs/readiness_pack/MANIFEST.sha256"


def _readiness_index_manifest_binding(repo: Path) -> tuple[bool, str]:
    """Ist ``index.json`` vom Pack-Manifest GEDECKT und byte-gleich?

    Das Manifest ist erzeugt (``scripts/readiness_pack_manifest.py``), der Index handgepflegt. Wer
    einen Slot per Hand auf ``filled`` setzt, ohne das Manifest neu zu erzeugen, faellt hier auf.

    EHRLICHE GRENZE, aufgeschrieben statt geglaettet: das Selbst-Receipt des Packs ist ausdruecklich
    BERATEND (ephemerer Schluessel, siehe ``readiness_pack_manifest.py``). Das hier ist also
    Integritaet INNERHALB des Packs — Drift-Erkennung —, keine Attestierung durch eine gepinnte
    Identitaet. Es ist strikt mehr als das Wort „filled", und es ist ausdruecklich weniger als eine
    Signatur.
    """
    man = repo / _PACK_MANIFEST_REL
    idx = repo / _PACK_INDEX_REL
    if not idx.is_file():
        return False, f"{_PACK_INDEX_REL} is absent"
    if not man.is_file():
        return False, (f"{_PACK_MANIFEST_REL} is absent — the index is covered by nothing "
                       "(run scripts/readiness_pack_manifest.py --generate)")
    verzeichnet = None
    for zeile in man.read_text(encoding="utf-8").splitlines():
        teile = zeile.split(None, 1)
        if len(teile) == 2 and teile[1].strip() == "index.json":
            verzeichnet = teile[0].strip()
    if verzeichnet is None:
        return False, f"{_PACK_MANIFEST_REL} does not cover index.json"
    live = hashlib.sha256(idx.read_bytes()).hexdigest()
    if live != verzeichnet:
        return False, (f"{_PACK_INDEX_REL} drifted from the pack manifest "
                       f"(live {live[:12]}… vs manifested {verzeichnet[:12]}…) — a hand-edited slot "
                       "without a regenerated manifest is exactly this state")
    return True, "index.json is covered by the pack manifest and digest-equal"


def c10_2_slot_filled():
    """Der Bereitschafts-Slot dieser Version — GEDECKT und mit Inhalt, nicht nur mit dem Wort.

    SEIT RUNDE 2 (Auflage C5, 2026-09-05) INFORMATIV, NICHT MEHR FREIGABEENTSCHEIDEND — sichtbar in
    ``_INFORMATIVE_CHECKS`` und im Inventar ``EVIDENCE_ADMISSION_INVENTORY``, nicht still. Der
    Gegenleser bot zwei Wege: diese Zeile zu kandidatsgebundener signierter Pack-Evidenz ausbauen
    (jeder ``delivers``-Eintrag mit Existenz/Digest/Typ/Kandidatenbezug/Rolle geprueft), oder sie aus
    den entscheidenden Zeilen nehmen. Der erste Weg braeuchte eine ZWEITE Signierkette fuer einen
    einzelnen Slot, gebaut unter demselben Zeitdruck wie die gerade gehaertete erste — genau das
    Risiko, vor dem Auflage C6 warnt. Diese Zeile bleibt darum bestehen (sie ist immer noch strikt
    mehr als das Wort „filled"), zaehlt aber nicht mehr zur Freigabeentscheidung.

    NACHBAR DERSELBEN KLASSE (Sweep 2026-09-05). Die Zeile war
    ``slot.get("status") == "filled"``: ein handgetipptes Wort in einer handgepflegten Tabelle
    entschied ueber die Freigabe. Zwei Dinge fehlten — die BINDUNG des Index an das Pack-Manifest
    und die SUBSTANZ des Slots. Ein Slot, der „filled" sagt und keine gelieferte Evidenz nennt, ist
    dieselbe leere Zaehlermenge wie ein Soak-Lauf ueber null Iterationen.

    ERKLAERTE ABWEICHUNG VOM EINEN ZULASSUNGSPFAD, und sie ist hier aufgeschrieben statt verschwiegen
    (Auflage C2 des Gegenlesers verlangt, dass ALLE freigabeentscheidenden Leser ueber
    ``_signed_versioned_artifact`` gehen). Diese Zeile tut es NICHT, aus einem Formgrund:
    ``docs/readiness_pack/index.json`` ist kein Messartefakt eines Laeufers, sondern eine
    handgepflegte Reviewer-Tabelle. Sie traegt keinen Kandidaten, keinen Erzeuger und keinen
    Eingabe-Digest, und ihr etwas davon anzudichten waere eine Behauptung, keine Bindung. Das
    Selbst-Receipt des Packs ist ausdruecklich BERATEND (ephemerer Schluessel, siehe
    ``readiness_pack_manifest.py``), also gibt es HEUTE gar keine zurechenbare Attestierung fuer
    diese Flaeche. Was hier steht, ist deshalb bewusst weniger: Integritaet INNERHALB des Packs
    (Manifest-Digest) plus Substanz des Slots. Das ist strikt mehr als das Wort „filled" und strikt
    weniger als eine Signatur, und es bleibt ein offener Punkt, bis das Pack eine gepinnte Identitaet
    hat.
    """
    gebunden, bindung = _readiness_index_manifest_binding(REPO)
    if not gebunden:
        return FAIL, f"the {VERSION_UNDER_TEST} readiness slot cannot be trusted: {bindung}"
    idx = _json_artifact(_PACK_INDEX_REL) or {}
    schluessel = _slot_schluessel(VERSION_UNDER_TEST)
    slot = (idx.get("release_evidence_slots") or {}).get(schluessel) or {}
    if slot.get("status") != "filled":
        return FAIL, f"{VERSION_UNDER_TEST} slot status is {slot.get('status')!r}, expected filled"
    geliefert = [d for d in (slot.get("delivers") or [])
                 if isinstance(d, str) and d.strip()] if isinstance(slot.get("delivers"), list) else []
    if not geliefert:
        return FAIL, (f"the {VERSION_UNDER_TEST} slot says 'filled' but names no delivered evidence "
                      "(`delivers` absent or empty) — the word is not the evidence")
    return PASS, (f"{VERSION_UNDER_TEST} readiness slot (key {schluessel!r}) is filled and names "
                  f"{len(geliefert)} delivered item(s); {bindung}")


def c10_3_open_points():
    doc = _read("docs/readiness_pack/AUDITOR_OPEN_POINTS.md")
    return (PASS, "auditor open-points list present") if doc.strip() \
        else (FAIL, "docs/readiness_pack/AUDITOR_OPEN_POINTS.md missing")


def c10_4_manifest_self_receipt():
    man = REPO / "docs" / "readiness_pack" / "MANIFEST.sha256"
    if not man.is_file():
        return FAIL, "readiness pack SHA-256 manifest missing"
    receipt_dir = REPO / "docs" / "readiness_pack" / "proofbundle"
    has_receipt = receipt_dir.is_dir() and any(receipt_dir.iterdir())
    return (PASS, "SHA-256 manifest + proofbundle self-receipt present (advisory dogfood)") if has_receipt \
        else (PENDING, "SHA-256 manifest present; proofbundle self-receipt not generated (advisory)")


def c10_5_runbook():
    doc = _read("docs/readiness_pack/REPRODUCTION_RUNBOOK.md")
    return (PASS, "reproduction runbook present") if doc.strip() \
        else (FAIL, "docs/readiness_pack/REPRODUCTION_RUNBOOK.md missing")


def c11_1_claims_hygiene():
    rc = subprocess.run([sys.executable, "scripts/claims_hygiene_check.py"],
                        cwd=str(REPO), capture_output=True, text=True, env=_env())
    return (PASS, "claims-hygiene clean (no un-negated overclaim, extended audit-candidate list)") \
        if rc.returncode == 0 else (FAIL, "claims-hygiene found an overclaim")


def c11_2_beta_classifier():
    t = _read("pyproject.toml")
    if re.search(r"Development Status\s*::\s*5\s*-\s*Production/Stable", t):
        return FAIL, "pyproject declares Development Status 5 - Production/Stable (must stay 4 - Beta)"
    if re.search(r"Development Status\s*::\s*4\s*-\s*Beta", t):
        return PASS, "pyproject Development Status is 4 - Beta (status boundary held)"
    return PENDING, "no Development Status classifier found in pyproject (expected 4 - Beta)"


def c11_3_relation_experimental():
    t = _read("pyproject.toml") + _read("SPEC.md") + _read("docs/predicates/relation.md")
    return (PASS, "relation profile still marked EXPERIMENTAL") if "EXPERIMENTAL" in t \
        else (FAIL, "relation EXPERIMENTAL marker not found")


def c12_1_pretag_audit():
    """A signed pre-tag audit receipt must bind THIS tree, THIS version and THIS gate.

    WHY THIS IS RED ON A WORK BRANCH, AND WHY THAT IS CORRECT (Owner decision 2026-08-30, card
    OA-4a8daddb55). A receipt binds a `subject_tree_digest`. A work branch is not finished and will
    get at least one more commit when it merges, so a receipt issued against it attests a tree that
    is about to stop existing. Producing one anyway would be exactly the act this check was built to
    catch — it would REPRODUCE the finding instead of closing it. C12.1 is a RELEASE gate; the
    receipt belongs to the tree that actually gets tagged.

    So a red C12.1 on a branch is not unfinished work and not a tool defect. It is the check doing
    its job on an object it was not meant to bless. Measured the same day: the v5.0.0 receipt
    (`audit_artifacts/500/pre_tag_receipt_v5.0.0.json`) binds `4212087273dc…`, which IS the
    subject_tree_digest of the v5.0.0 tag, is signed by the pinned key, and this gate returns ok
    when run against that tree.

    HONEST LIMIT, recorded rather than smoothed over: the receipt's signed `audit_output_digest`
    resolves to no artifact that could be found, and nothing in this gate resolves it — the field is
    signed, which makes it tamper-evident and attributable, not checkable.
    """
    import pre_tag_audit_gate as pta
    r = pta.evaluate(REPO, version=VERSION_UNDER_TEST)
    if r["ok"]:
        return (PASS, f"pre-tag adversarial audit recorded for {VERSION_UNDER_TEST}")
    # AUF EINEM PULL REQUEST IST DIESE VERPFLICHTUNG NICHT ANWENDBAR, NICHT GEBROCHEN.
    #
    # Die Owner-Entscheidung vom 30.08. (Karte OA-4a8daddb55, im Docstring oben zitiert) sagt: ein
    # Receipt fuer einen Arbeitszweig zu erzeugen waere genau der Akt, den diese Pruefung faengt.
    # Daraus folgt aber, dass sie auf JEDEM PR rot ist — und eine Pruefung, die immer rot ist,
    # traegt keine Information und lehrt jeden Leser, Rot zu uebergehen. Unter dem oeffentlich auf
    # der SCITT-Liste verlinkten PR 178 sah ein Fremder ein rotes Kreuz an einem Beitrag, den wir
    # als sauber bezeichnen.
    #
    # DIE ENTSCHEIDUNG VOM 30.08. BLEIBT UNBERUEHRT: es wird weiterhin kein Receipt fuer Zweige
    # erzeugt. Es wird nur nicht mehr so getan, als koennte es eines geben.
    #
    # ENG GEHALTEN: nur der Fall „kein Receipt bindet diesen Baum" wird umgedeutet. Jeder ANDERE
    # Fehlschlag des Tors — eine kaputte Signatur, ein nicht vertrauenswuerdiger Schluessel, ein
    # unlesbares Receipt — bleibt FAIL, auch auf einem PR. Sonst waere aus einer Praezisierung
    # eine Abschaltung geworden.
    #
    # AM TYPISIERTEN FELD, NICHT AM PROSA-TEXT (Tiefen-Gate 2026-09-05, Fund L5-G6-01, P2). Hier stand
    # `"no valid pre-tag audit RECEIPT" in r["reason"]` — und genau dieser Satz steht im Tor-Grund SOWOHL
    # bei Abwesenheit ALS AUCH bei Ablehnung. Gemessen: ein fremder Signierer, eine manipulierte Signatur,
    # ein kopiertes 5.0.0-Receipt und eine unlesbare Datei wurden auf einem PR alle vier zu
    # NOT_APPLICABLE, und der ganze Lauf endete mit 0, obwohl ein bekannt schlechtes Artefakt im Baum lag.
    # Die Nachsicht gilt der ABWESENHEIT; sie vererbt sich nicht auf ein vorhandenes, geprueftes und
    # verworfenes Artefakt. `state` ist das Feld dafuer, und es driftet nicht, wenn jemand den Satz
    # umformuliert. Ein Tor ohne `state` (aeltere Fassung) faellt fail-closed auf FAIL zurueck.
    if _laeuft_auf_pull_request() and r.get("state") == "absent":
        return (NOT_APPLICABLE,
                "nicht anwendbar vor dem Tag: ein Receipt bindet einen BAUM, und der Baum eines "
                "Zweigs hoert beim Merge auf zu existieren (Owner-Entscheid 30.08., OA-4a8daddb55). "
                "Auf main und auf Tags bleibt diese Zeile scharf.")
    return (FAIL, r["reason"])


def c12_2_audit_pack_zero_p0p1(repo: Path = REPO):
    # RT-10 / PB-2026-0718-14 (was a proven FALSE-PASS): the '0 open P0/P1' obligation is carried by the
    # SIGNED, STRUCTURED findings register (audit_artifacts/findings_register_361.json), counted from
    # structured severity+status fields — NOT a lexical '0 open P0/P1' substring in a possibly-stale .md.
    # The old guard derived PASS from any non-negated '0 open P0/P1' line in a version-scoped record, with
    # NO freshness/supersession/signature/contradiction check, so a STALE record that still said '0 open'
    # granted PASS while current open P0/P1 existed (false_accept=true). The register replacement is
    # fail-closed: a valid ed25519 signature by the pinned key is required (unsigned/tampered/wrong-key =
    # FAIL); supersession is resolved current-wins; a contradiction is an ERROR; and absence / an empty
    # register is FAIL, not PASS (evaluated_count==0 -> FAIL, the assertion-by-absence guard). Every verdict
    # carries the RT-10 triple (population_size, evaluated_count, source_digest).
    #
    # DIE VERSIONSBINDUNG DES ARTEFAKTS, nicht nur die des Matrix-Pins (Tiefen-Gate 2026-09-05, Fund
    # L5-G6-02, P1). Diese Zeile entscheidet ueber die Freigabe, und sie las bis hierher ein signiertes
    # Register, das auf `3.6.1` lautet und am 18.07. erzeugt wurde — siebzehn Funde ueber eine Fassung
    # zwei Hauptversionen zurueck, als Aussage ueber die heutige. Ein Register mit `0.0.1` oder ganz
    # ohne Versionsfeld ging genauso durch. Die Signatur war immer gueltig; das war nie die Frage.
    # L6-01 hat diese Klasse fuer den PIN geschlossen — hier ist sie fuer das ARTEFAKT geschlossen.
    #
    # DIE VERTRAUENSBASIS KOMMT AUS DEM ANKER, nicht aus einem zweiten Pin (Teil F, 2026-09-06).
    # `findings_register` hielt bis hierher eine eigene Konstante mit einem Schluessel, dessen
    # private Haelfte auf dem Bauhost lag; der Anker dieses Repositoriums nannte einen anderen.
    # Welcher galt, entschied niemand — die zwei Quellen wurden nie verglichen. Jetzt reicht DIESE
    # Zeile die autorisierten Schluessel an, und zwar aus demselben Ankerleser, den auch C6.2,
    # C6.3 und C8.2 benutzen. Ist der Anker hier nicht lesbar, ist das DATA_BLOCKED und keine
    # Freigabe: eine unmessbare Vertrauensbasis ist nie eine erfuellte.
    # DER MESSZEITPUNKT KOMMT AUS DEM REGISTER SELBST, und zwar VOR jeder Pruefung (Owner-Karte
    # OA-89f05b70cd, 2026-09-06). Das sieht nach Zirkel aus und ist keiner: gelesen wird ein noch
    # ungeprueftes Feld, aber ausschliesslich, um die erlaubte Schluesselmenge zu VERKLEINERN. Diese
    # Richtung ist sicher — wer den Wert manipuliert, kann sich damit hoechstens selbst aussperren,
    # nie eine zusaetzliche Autorisierung erschleichen. Fehlt oder verrutscht das Feld, bleibt der
    # Tag leer und die Frist wird nicht angewandt; die Frischepruefung in `findings_register`
    # faengt denselben Fall eine Stufe spaeter fail-closed ab.
    #
    # DIE RUECKDATIERUNG IST DER GRUND FUER DIE ZWEITE HAELFTE. Wer einen widerrufenen Schluessel
    # haelt, koennte ein Register mit altem `generated_at` signieren und in das Fenster
    # zurueckreichen, in dem der Schluessel noch galt — die Signatur deckt das Feld ja mit ab. Was
    # das begrenzt, ist nicht diese Zeile, sondern das Alterfenster in `findings_register`. Die
    # zwei Pruefungen sind EIN Mechanismus, und deshalb sind sie zusammen gelandet.
    gemessen_am = None
    try:
        _vorab = json.loads((repo / "audit_artifacts" / "findings_register_361.json")
                            .read_text(encoding="utf-8"))
        if isinstance(_vorab, dict) and isinstance(_vorab.get("generated_at"), str):
            gemessen_am = _vorab["generated_at"]
    except (OSError, ValueError):
        gemessen_am = None
    erlaubt, anker_grund = _autorisierte_schluessel(repo, "C12.2", gemessen_am=gemessen_am)
    if erlaubt is None:
        return DATA_BLOCKED, (f"the trust basis for the findings register cannot be read here: "
                              f"{anker_grund}")
    import findings_register as fr
    r = fr.verify_and_count(repo, expected_version=VERSION_UNDER_TEST, authorised_pubkeys=erlaubt)
    triple = (f"population_size={r['population_size']} evaluated_count={r['evaluated_count']} "
              f"source_digest={r['source_digest']} version_bound={r.get('version_bound')} "
              f"register_version={r.get('register_version')!r} version_under_test={VERSION_UNDER_TEST!r} "
              f"anchor={anker_grund}")
    return (PASS if r["ok"] else FAIL), f"{r['reason']} [{triple}]"


def ext_1_external_audit():
    return EXTERNAL, ("the independent external human crypto/protocol audit — the SINGLE deliberately "
                      "open gate to stable; no internal instrument can substitute for it (No-Fake)")


CHECKS = [
    ("C1.1", 1, "two CI gate configurations declared + enabled (repo + published-artifact)",
     c1_1_two_ci_gates),
    ("C1.2", 1, "deterministic sdist normaliser", c1_2_reproducible_normaliser),
    ("C1.3", 1, "release sha256 digest gate", c1_3_release_sha_gate),
    ("C2.1", 2, "pytest cleanroom: 0 collection errors", c2_1_no_collection_errors),
    ("C2.2", 2, "no missing suites (floor met)", c2_2_no_missing_suites),
    ("C3.1", 3, "locked test manifest floor met", c3_1_manifest_floor),
    ("C3.2", 3, "pytest-only modules preserved", c3_2_pytest_only),
    ("C4.1", 4, "type-confusion matrix never-raise total", c4_1_never_raise),
    ("C4.2", 4, "no NEEDS_FIXTURE coverage gap", c4_2_no_needs_fixture),
    ("C5.1", 5, "trust-pack payloadType negatives green", c5_1_payloadtype_negatives),
    ("C6.1", 6, "fuzz-soak harness present", c6_1_soak_harness),
    ("C6.2", 6, "recorded soak: 0 crash, 0 false-accept", c6_2_recorded_soak_clean),
    ("C6.3", 6, "full 24h soak artifact", c6_3_full_24h),
    ("C7.1", 7, "formal model: non-reserved obligations proven", c7_1_formal_proven),
    ("C7.2", 7, "formal model grounded in implementation", c7_2_impl_crosscheck),
    ("C7.3", 7, "O7 payloadType obligation honestly reserved", c7_3_o7_reserved_honest),
    ("C7.4", 7, "reserved slots O5/O6/O7 honest (no fake proof)", c7_4_reserved_slots_honest),
    ("C8.1", 8, "rust-parity registry integrity", c8_1_registry_integrity),
    ("C8.2", 8, "Python<->Rust differential agrees", c8_2_differential_agrees),
    ("C8.3", 8, "PENDING Rust surface documented (no fake 100%)", c8_3_pending_documented),
    ("C9.1", 9, "two sdists byte-identical", c9_1_two_sdists_identical),
    ("C9.2", 9, "SLSA-L3 reusable attest workflow", c9_2_slsa_reusable),
    ("C10.1", 10, "readiness pack grounded", c10_1_pack_ok),
    ("C10.2", 10, f"{VERSION_UNDER_TEST} readiness slot filled", c10_2_slot_filled),
    ("C10.3", 10, "auditor open-points list", c10_3_open_points),
    ("C10.4", 10, "SHA-256 manifest + self-receipt", c10_4_manifest_self_receipt),
    ("C10.5", 10, "reproduction runbook", c10_5_runbook),
    ("C11.1", 11, "claims-hygiene (no stable/audited/prod-ready claim)", c11_1_claims_hygiene),
    ("C11.2", 11, "pyproject stays 4 - Beta", c11_2_beta_classifier),
    ("C11.3", 11, "relation still EXPERIMENTAL", c11_3_relation_experimental),
    ("C12.1", 12, "pre-tag adversarial audit recorded", c12_1_pretag_audit),
    ("C12.2", 12, "internal audit pack: 0 open P0/P1", c12_2_audit_pack_zero_p0p1),
    ("EXT.1", 0, "external human audit (the one remaining gate)", ext_1_external_audit),
]


# ─────────────────────────────────────────────────────────────────────────────────────────────
# AUFLAGE C6 (Runde 2, 2026-09-05): EXPLIZITE ZUORDNUNG statt Prosa-Beschreibung.
#
# Jede der sechs Zeilen, deren Bestehen unmittelbar von ABGELEGTER (nicht selbst gemessener)
# Evidenz abhaengt, mit ihrer behaupteten Eigenschaft, ihrer Evidenzart und der Funktion, die
# tatsaechlich zulaesst. Eine ausfuehrbare Struktur statt einer Tabelle in einem Kommentar, weil
# eine Tabelle in einem Kommentar von der Zulassungsfunktion abweichen kann, ohne dass irgendetwas
# rot wird — `tests/test_freigabe_evidenz_provenienz_l5_g7_02.py::
# test_das_inventar_stimmt_mit_checks_und_admission_fn_ueberein` prueft genau das.
#
# ``release_deciding`` MUSS mit der Mitgliedschaft in ``_INFORMATIVE_CHECKS`` uebereinstimmen — das
# ist die "eine dokumentierte Ausnahme darf nicht still dieselbe Freigabestaerke behalten"-Haelfte
# von C6: C10.2 ist HIER als ``False`` sichtbar, nicht nur in einem Mengen-Literal weiter oben.
EVIDENCE_ADMISSION_INVENTORY = (
    {"id": "C6.2", "property": "recorded fuzz-soak for this candidate: 0 untriaged crash, "
                                "0 false-accept",
     "evidence_kind": "signed_versioned_artifact", "admission_fn": "c6_2_recorded_soak_clean",
     "release_deciding": True},
    {"id": "C6.3", "property": "a full 24h soak artifact is present, attested and candidate-bound",
     "evidence_kind": "signed_versioned_artifact", "admission_fn": "c6_3_full_24h",
     "release_deciding": True},
    {"id": "C8.2", "property": "Python<->Rust differential agrees on every recorded vector, "
                                "population matches its own claim",
     "evidence_kind": "signed_versioned_artifact", "admission_fn": "c8_2_differential_agrees",
     "release_deciding": True},
    {"id": "C8.3", "property": "every PENDING Rust surface states its own documented reason "
                                "in the registry (not just a keyword in a prose file)",
     "evidence_kind": "structural_registry_read", "admission_fn": "c8_3_pending_documented",
     "release_deciding": True},
    {"id": "C9.1", "property": "two independently built sdists (this tree) are byte-identical",
     "evidence_kind": "self_measured_structured_result", "admission_fn": "c9_1_two_sdists_identical",
     "release_deciding": True},
    {"id": "C10.2", "property": "the version-under-test readiness slot is filled with named, "
                                 "manifest-covered delivered evidence",
     "evidence_kind": "index_manifest_binding (ADVISORY — the pack's own self-receipt uses an "
                       "ephemeral key, no pinned candidate-bound signer exists for this slot today)",
     "admission_fn": "c10_2_slot_filled",
     "release_deciding": False},
)


def _env() -> dict:
    import os
    e = dict(os.environ)
    src = str(REPO / "src")
    e["PYTHONPATH"] = src + (":" + e["PYTHONPATH"] if e.get("PYTHONPATH") else "")
    return e


def gate_ready_on_binding(ready_before: bool, binding_state: str) -> bool:
    """Der Versions-Pin senkt die Bereitschaft GENAU DANN, wenn er nicht gebunden ist.

    WARUM DAS EINE EIGENE FUNKTION IST (gemessen 02.09.2026). Die Regel stand als zwei Zeilen mitten
    in `evaluate()`, und die Anti-Paritaets-Probe konnte sie nur INDIREKT beobachten: sie verglich das
    Endergebnis mit der Bereitschaft davor. Solange die Bereitschaft davor ohnehin `False` ist -- und
    das ist sie auf jedem Baum, der nicht vollstaendig bereit ist -- sind beide Seiten `False`, die
    Gleichheit haelt, und ein eingepflanzter Dauer-`False`-Defekt kam mit `8 passed` durch. Gemessen,
    nicht vermutet: genau dieser Defekt lief gruen durch, bevor es diese Funktion gab.

    Als eigene Funktion ist die Regel ADRESSIERBAR: alle vier Kombinationen lassen sich hinschreiben,
    auch die eine, die den Defekt sichtbar macht (bereit davor UND gebunden ergibt bereit). Ein
    Riegel, der seine Bedingung nur beobachten kann, wenn die Welt gerade guenstig steht, ist auf
    jedem anderen Baum stumm.
    """
    return bool(ready_before) and binding_state == "bound"


def evaluate() -> dict:
    rows = []
    for cid, crit, title, fn in CHECKS:
        try:
            verdict, detail = fn()
        except Exception as exc:  # noqa: BLE001 - an erroring check is an honest FAIL, never a crash
            verdict, detail = FAIL, f"check raised {type(exc).__name__}: {exc}"
        rows.append({"id": cid, "criterion": crit, "title": title,
                     "verdict": verdict, "detail": detail})
    counts = {v: sum(1 for r in rows if r["verdict"] == v)
              for v in (PASS, PENDING, DATA_BLOCKED, EXTERNAL, FAIL, NOT_APPLICABLE)}
    # F2 + F7 CLOSED (makellose-500 Phase 4): audit_candidate_ready = every RELEASE-DECIDING check is
    # PASS, EXCEPT exactly the one explicitly-external open audit (EXT.1 == EXTERNAL_PENDING). An internal
    # PENDING_JUSTIFIED, an internal DATA_BLOCKED (a check that could NOT be measured here), an unknown
    # verdict, a FAIL, or an unbound version pin is NOT ready — honesty about not-having-measured is not
    # readiness. Informative (presence-only) checks are excluded from the verdict entirely. Fail-closed.
    unknown = [r for r in rows if r["verdict"] not in _KNOWN_VERDICTS]
    deciding = [r for r in rows if r["id"] not in _INFORMATIVE_CHECKS]
    # EIN NAME FUER DIE BEREITSCHAFT VOR DER PIN-BINDUNG, und er wird auch nach aussen gereicht.
    # Grund (gemessen 02.09.2026): die Anti-Paritaets-Probe dieser Datei bildete diese Groesse mit
    # `_NON_FAIL` NACH, und `_NON_FAIL` enthaelt DATA_BLOCKED, das hier ausdruecklich NICHT
    # bereitmacht. Beide Seiten stimmten nur ueberein, solange irgendeine Zeile FAILte; als ein
    # gueltiges Pre-Tag-Receipt die letzte FAIL-Zeile entfernte, klaffte die Nachbildung auf und der
    # Test beschuldigte den Pin, der bound und unbeteiligt war. Ein Pruefer, der die gepruefte
    # Bedingung NACHBAUT statt sie zu lesen, misst eine zweite Groesse mit demselben Namen.
    ready_before_binding = (counts[FAIL] == 0 and not unknown and all(
        r["verdict"] == PASS or (r["id"] == _EXTERNAL_CHECK_ID and r["verdict"] == EXTERNAL)
        for r in deciding))
    # THE BINDING GATES THE VERDICT, not just decorates it. A green matrix about another release
    # is not a green matrix about this one — and `ready` is the field a reader takes at face value.
    # `not_determinable` withholds readiness too: an unmeasurable binding is not a verified one,
    # and this gate's whole job is to be falsifiable.
    # THE PIN IS PASSED, NOT DEFAULTED. A default argument is bound once, when the function is
    # defined; the constant is then frozen into the signature and a later change to
    # VERSION_UNDER_TEST would no longer reach the check. Caught by this file's own anti-parity
    # test, which set the constant and watched the guard ignore it — a binding check that reads a
    # stale copy of the thing it binds is the same class of defect it exists to catch.
    binding = version_pin_binding(VERSION_UNDER_TEST)
    ready = gate_ready_on_binding(ready_before_binding, binding["state"])
    fully_here = ready and counts[DATA_BLOCKED] == 0
    # status_boundary is COMPUTED, never a static claim: it says "all internal deciding gates green" only
    # when that is actually true (reviewer F7 — the old static string claimed it unconditionally).
    not_pass_deciding = [r["id"] for r in deciding
                         if not (r["verdict"] == PASS or r["id"] == _EXTERNAL_CHECK_ID)]
    if ready:
        boundary = ("audit-candidate: all internal release-deciding gates PASS; the sole remaining gate "
                    "to stable is the independent external security audit. NOT stable, NOT audited, NOT "
                    "production-ready.")
    else:
        boundary = ("NOT audit-candidate-ready: internal release-deciding obligations are not all PASS "
                    f"(unmet: {not_pass_deciding or 'version-pin unbound'}). NOT stable, NOT audited, "
                    "NOT production-ready.")
    return {
        "schema": "proofbundle.audit_candidate_matrix.v1",
        "version_under_test": VERSION_UNDER_TEST,
        "version_pin": binding,
        "total_checks": len(rows),
        "release_deciding_count": len(deciding),
        "informative_count": len(rows) - len(deciding),
        "unknown_verdicts": [r["id"] for r in unknown],
        "unmet_deciding": not_pass_deciding,
        # Die Bereitschaft OHNE die Wirkung der Pin-Bindung. Wer pruefen will, ob die Bindung
        # das Verdikt gesenkt hat, vergleicht `audit_candidate_ready` hiermit — statt die
        # Bedingung ein zweites Mal nachzubauen.
        "ready_before_binding": ready_before_binding,
        "counts": counts,
        "audit_candidate_ready": ready,
        "fully_verified_here": fully_here,
        "status_boundary": boundary,
        "checks": rows,
    }


def _fmt(result: dict) -> str:
    c = result["counts"]
    pin = result.get("version_pin") or {}
    lines = []
    # The binding goes FIRST when it is not clean: a reader who stops after one line must not
    # walk away with a readiness impression that the line below would have withdrawn.
    if pin.get("state") == "drift":
        lines.append(f"[audit-candidate-matrix] VERSION PIN DRIFT — {pin.get('detail')}")
        lines.append("  audit_candidate_ready is withheld: this matrix does not speak about the "
                     "shipping version. Bind the pin (or scope the claim), do not just bump it.")
    elif pin.get("state") == "not_determinable":
        lines.append(f"[audit-candidate-matrix] VERSION PIN NOT DETERMINABLE — {pin.get('detail')}")
        lines.append("  audit_candidate_ready is withheld: an unmeasurable binding is not a "
                     "verified one.")
    lines += [
        f"[audit-candidate-matrix] {result['total_checks']} checks · "
        f"PASS {c[PASS]} · PENDING {c[PENDING]} · DATA_BLOCKED {c[DATA_BLOCKED]} · "
        f"EXTERNAL {c[EXTERNAL]} · NICHT ANWENDBAR {c[NOT_APPLICABLE]} · FAIL {c[FAIL]}",
        f"  audit_candidate_ready={result['audit_candidate_ready']} "
        f"fully_verified_here={result['fully_verified_here']}",
        f"  (ready = no internal obligation BROKEN; it does NOT mean all {result['total_checks']} are "
        f"green — {c[DATA_BLOCKED]} still need the release toolchain/24h soak (DATA_BLOCKED) and "
        f"{c[EXTERNAL]} is the external audit. Full green HERE needs fully_verified_here=True.)",
    ]
    for r in result["checks"]:
        mark = {PASS: "  ok ", PENDING: " pend", DATA_BLOCKED: " data",
                EXTERNAL: " ext ", FAIL: "FAIL ", NOT_APPLICABLE: " n.a."}[r["verdict"]]
        # NAME ZUERST, KUERZEL IN KLAMMERN. Das Kuerzel bleibt der stabile Bezeichner fuer Tests
        # und Tafeln; wer liest, soll aber nicht erst nachschlagen muessen, was C12.1 ist.
        name = _HUMAN_NAME.get(r["id"], r["title"])
        lines.append(f"  [{mark}] {name} ({r['id']}) (§{r['criterion']}): {r['detail']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--json", action="store_true")
    p.add_argument("--strict", action="store_true",
                   help="also require fully_verified_here (0 DATA_BLOCKED — a full toolchain env)")
    args = p.parse_args(argv)
    result = evaluate()
    print(json.dumps(result, indent=2, ensure_ascii=False) if args.json else _fmt(result))
    # DER AUSGANGSCODE SAGT „BLOCKIERT DIESE PRUEFUNG DIESES OBJEKT", NICHT „IST ES FERTIG".
    #
    # `audit_candidate_ready` bleibt unveraendert und sagt weiterhin die Wahrheit: ein Arbeitszweig
    # ist nicht release-bereit, und im JSON steht das auch so. Was sich aendert, ist allein, ob
    # dieser Lauf deswegen ROT wird. Haelt NUR eine nicht-anwendbare Zeile die Bereitschaft
    # zurueck, ist das keine Aussage ueber einen Defekt — und ein rotes Kreuz waere eine.
    #
    # FAIL bleibt FAIL, auch hier: sobald irgendeine Zeile wirklich gebrochen ist, oder die
    # Version-Pin-Bindung nicht steht, endet der Lauf rot wie bisher.
    if not result["audit_candidate_ready"]:
        _na = [r for r in result["checks"] if r["verdict"] == NOT_APPLICABLE]
        # WAS AUF EINEM PR KEIN MANGEL DES PR IST. `DATA_BLOCKED` steht hier neben
        # `NOT_APPLICABLE`, und zwar nicht aus Bequemlichkeit: der Workflow sagt es woertlich
        # ueber genau diesen Job — "a full run needs a soak box (24h) and the build backend, so
        # DATA_BLOCKED is expected in CI and must not fail the build (No-Fake)". Beides heisst
        # "hier nicht gemessen", keines heisst "gebrochen".
        #
        # FAIL, PENDING und ein unbekanntes Verdikt bleiben Maengel. Ein PENDING sagt "noch
        # nicht", und das ist eine Aussage ueber die Arbeit; die anderen beiden sind Aussagen
        # ueber die Umgebung und ueber den Gegenstand.
        _echte_maengel = [
            r for r in result["checks"]
            if r["id"] not in _INFORMATIVE_CHECKS
            and r["verdict"] not in (PASS, NOT_APPLICABLE, DATA_BLOCKED)
            and not (r["id"] == _EXTERNAL_CHECK_ID and r["verdict"] == EXTERNAL)
        ]
        _pin_ok = (result.get("version_pin") or {}).get("state") == "bound"
        if not (_na and not _echte_maengel and _pin_ok):
            return 1
    if args.strict and not result["fully_verified_here"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
