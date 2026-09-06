#!/usr/bin/env python3
"""RT-10 / PB-2026-0718-14: verify + count the SIGNED structured findings register (fail-closed).

The old audit_candidate_matrix C12.2 derived a PASS from a lexical "0 open P0/P1" line in a version-scoped
.md — with NO freshness, supersession, signature or contradiction check. A STALE record that still said
"0 open" granted a FALSE PASS while current open P0/P1 existed (false_accept=true). This module is the
structured, fail-closed replacement:

  * the count comes from STRUCTURED fields (severity + status), never a substring;
  * the register MUST carry a valid ed25519 signature over its canonical (RFC-8785) bytes by the PINNED
    public key — an unsigned / wrong-key / tampered register is FAIL, not PASS (self-attested root of trust);
  * supersession is resolved current-wins (a finding may be superseded_by a later id; the superseding entry
    decides), and a contradiction (the same id present twice with conflicting status in the effective set)
    is an ERROR, not silently resolved;
  * every result carries the RT-10 triple ``(population_size, evaluated_count, source_digest)`` and FAILs at
    ``evaluated_count == 0`` — an absent/empty register can never mask "0 open" (assertion-by-absence guard).

``verify_and_count(repo)`` returns a dict the gate consumes; it NEVER raises on a malformed/absent register
(fail-closed verdict instead), so a hostile register is a clean FAIL, not a crash.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
import unicodedata
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

REGISTER_REL = "audit_artifacts/findings_register_361.json"

# KEIN GEPINNTER SCHLUESSEL MEHR IN DIESER DATEI (Teil F, 2026-09-06).
#
# WAS HIER STAND UND WARUM ES FALSCH WAR. Bis hierher hielt dieses Modul eine eigene Konstante
# ``PINNED_PUBKEY_B64`` — einen Schluessel, dessen private Haelfte auf dem BAUHOST lag und der mit
# ``scripts/gen_findings_register.py`` im selben Prozess erzeugt und verwendet wurde, der das
# Register baute. Daneben fuehrt das Repositorium seit Teil A5 einen Owner-autorisierten
# Vertrauensanker (``audit_artifacts/readiness_trusted_pubkeys.txt``), und die Owner-Entscheidung
# dazu (Karte OA-e10ba2ba39, 2026-09-06) sagt woertlich: der Ankerschluessel signiert „ausschliesslich
# Bereitschaftsartefakte C6.2, C6.3, C8.2 und den Registerkoerper … Private Haelfte bleibt beim Owner
# am Mac, nichts davon auf dem Farmer."
#
# Zwei Quellen fuer dieselbe Frage „wer darf das Register beglaubigen" — und sie sagten
# Verschiedenes: der Anker nannte den Owner-Schluessel, die Konstante hier einen anderen. Gemessen
# am 2026-09-06 auf Kandidat a62d8cb liefen beide nebeneinander, ohne dass irgendetwas sie
# verglich. Deshalb gibt es hier keine zweite Quelle mehr: die autorisierten Schluessel REIST der
# Aufrufer an, und der Aufrufer ist das Tor, das den Anker ohnehin schon streng liest.
#
# ``authorised_pubkeys=None`` heisst NICHT „nimm irgendeinen" — es heisst „der Aufrufer hat nicht
# gebunden", und das ist fail-closed. Ein Register ohne benannte Autorisierung entscheidet nichts.
CODE_REGISTER_UNAUTHORISED_KEY = "REGISTER_UNAUTHORISED_KEY"

_GATING_SEVERITIES = {"P0", "P1"}
# 6-lens gate L5-01: severity is DENY-by-default (like status) — a string severity whose normalized form is
# not a KNOWN token is an anomaly, never silently non-gating. So an open P0 cannot hide behind an invisible
# zero-width (U+200B) or confusable/fullwidth severity char that renders as "P0" to a human reviewer.
_KNOWN_SEVERITIES = {"P0", "P1", "P2", "P3", "INFO"}


def _norm(s: str) -> str:
    """NFKC-normalize and strip Unicode whitespace + Cc/Cf (control/format, incl. the zero-width U+200B) so a
    severity/status cannot smuggle gating state past the {P0,P1} / 'closed' comparisons behind an invisible
    or confusable/fullwidth character (which str.strip() alone does not remove/normalize)."""
    nfkc = unicodedata.normalize("NFKC", s)
    return "".join(ch for ch in nfkc if unicodedata.category(ch) not in ("Cc", "Cf")).strip()


def _canonical_bytes(body: dict) -> bytes:
    from proofbundle import canonical  # noqa: PLC0415
    return canonical.canonicalize_statement(body)


def _signature_ok(register: dict, authorised_pubkeys: set[str] | None) -> tuple[bool, str]:
    sig = register.get("signature")
    if not isinstance(sig, dict):
        return False, "register carries no signature block"
    if sig.get("alg") != "ed25519":
        return False, f"unexpected signature alg {sig.get('alg')!r}"
    pub_b64 = sig.get("public_key_b64")
    # DIE AUTORISIERUNG KOMMT VON AUSSEN, und ihr Fehlen ist ein Nein. Ein leeres Set und None
    # bedeuten dasselbe Ergebnis (fail-closed), aber NICHT dasselbe: None heisst „nicht gebunden",
    # ein leeres Set heisst „gebunden, und der Anker autorisiert niemanden fuer diese Zeile". Beide
    # Gruende stehen ausgeschrieben, damit ein Leser sie unterscheiden kann.
    if authorised_pubkeys is None:
        return False, (f"{CODE_REGISTER_UNAUTHORISED_KEY}: the caller passed no authorised key set — "
                       "an unbound caller does not decide a release (fail-closed)")
    if not authorised_pubkeys:
        return False, (f"{CODE_REGISTER_UNAUTHORISED_KEY}: the trust anchor authorises no key for this "
                       "check — nobody may sign the register (fail-closed)")
    if not isinstance(pub_b64, str) or pub_b64 not in authorised_pubkeys:
        return False, (f"{CODE_REGISTER_UNAUTHORISED_KEY}: the register is signed by "
                       f"{str(pub_b64)[:16]}…, which the trust anchor does not authorise for this "
                       "check")
    try:
        pub = base64.b64decode(pub_b64)
        raw_sig = base64.b64decode(sig.get("sig_b64", ""))
    except (ValueError, TypeError) as exc:
        return False, f"signature fields are not valid base64: {exc}"
    body = {k: register[k] for k in register if k != "signature"}
    try:
        from proofbundle.signature import verify_ed25519  # noqa: PLC0415
        msg = _canonical_bytes(body)
    except Exception as exc:  # noqa: BLE001 - canonicalizer absence is a fail-closed verdict, never a crash
        return False, f"cannot canonicalize register for verification (fail-closed): {exc}"
    return (True, "signature valid") if verify_ed25519(pub, raw_sig, msg) \
        else (False, "signature does not verify under the pinned key")


def _resolve_current(findings: list) -> tuple[dict, list, list, set]:
    """current-wins with FAIL-CLOSED supersession (RT10-REG-01 fix). Returns
    (effective_by_id, contradictions, anomalies, legit_superseded).

    The prior version SILENTLY DROPPED a finding whenever it carried ANY ``superseded_by`` string — even a
    DANGLING link (target id absent), a SELF-supersession (superseded_by == own id) or a non-string id —
    which let a validly-signed register hide an open P0 behind a bogus supersession and still report 0 open
    (a fail-open the adversarial deep-gate reproduced). Now a finding is legitimately superseded ONLY by a PRESENT,
    DIFFERENT id; a dangling/self supersession, a non-string/empty id, or a non-dict entry is an ANOMALY that
    is NEVER dropped (the caller fails closed on any anomaly), so no finding can vanish from the count."""
    # ── THE ID SPACE IS NORMALISED ONCE, HERE (deep-gate finding L5-01, P0) ──────────────────
    #
    # _norm() (NFKC + Cc/Cf strip) ran over `severity` and `status` and NOT over `id` and
    # `superseded_by` — neighbouring fields in this very function, treated unequally. A validly
    # SIGNED register could therefore hide an open P0: give the P0 `superseded_by = "X​"` and
    # add a closed decoy with `id = "X​"`. Raw, the two strings differ, so the link looks like a
    # legitimate supersession to a present, DIFFERENT id and the P0 drops out of the count. To a
    # human reviewer both render as "X". The gate returned PASS.
    #
    # The fix is not to reject U+200B. A blocklist of invisible characters is the shape that failed
    # in the neighbouring finding L5-02: it can only name what someone already thought of. Identity
    # is decided on the SAME axis as everything else this function adjudicates.
    #
    # Normalised-id COLLISION is fail-closed, and which channel it takes depends on the statuses, so
    # that neither typed reason becomes decoration: differing statuses are a CONTRADICTION (the
    # existing channel keeps its meaning), identical ones an ANOMALY. Measured on the live register
    # 2026-08-08: 17 findings, ids unique raw AND normalised, none altered by normalisation — the
    # tightening blocks nothing that exists.
    _nid: dict[int, str] = {}          # index -> normalised id
    _raw_by_nid: dict[str, list[str]] = {}
    for idx, f in enumerate(findings):
        if isinstance(f, dict) and isinstance(f.get("id"), str) and f.get("id"):
            n = _norm(f["id"])
            _nid[idx] = n
            _raw_by_nid.setdefault(n, []).append(f["id"])
    ids_present = set(_raw_by_nid)
    effective: dict[str, dict] = {}
    contradictions: list[str] = []
    anomalies: list[str] = []
    legit_superseded: set[str] = set()
    sby_map: dict[str, str] = {}
    # KEINE Sammel-Menge fuer die Kollisionen. Die erste Fassung fuehrte hier ein `_kollision`-Set,
    # das befuellt und nie gelesen wurde — eine Variable, die wie ein Riegel aussieht und keiner ist.
    # Das ist die Form des Nachbarbefunds L1-03 ("die Klasse ist per Konstruktion geschlossen"), und
    # sie faellt bei einem Fix gegen genau diese Klasse doppelt auf. Die Kollision wirkt ueber die
    # beiden typisierten Kanaele darunter, und beide sind beim Aufrufer fail-closed.
    for n, rohe in _raw_by_nid.items():
        if len(rohe) < 2:
            continue
        stati = {(_norm(str(f.get("status", ""))).lower())
                 for i, f in enumerate(findings)
                 if isinstance(f, dict) and _nid.get(i) == n}
        if len(stati) > 1:
            contradictions.append(n)
        else:
            anomalies.append(f"{n}:normalised-id-collision={sorted(set(rohe))!r}")
    for idx, f in enumerate(findings):
        if not isinstance(f, dict):
            anomalies.append(f"index{idx}:non-dict-entry")
            continue
        fid_raw = f.get("id")
        if not isinstance(fid_raw, str) or not fid_raw:
            anomalies.append(f"index{idx}:bad-id={fid_raw!r}")
            continue
        # Ab hier IMMER die normalisierte Kennung. Ein leerer Rest nach der Normalisierung (eine
        # Kennung, die NUR aus unsichtbaren Zeichen besteht) ist selbst eine Anomalie — sonst
        # kollabierten mehrere solcher Kennungen still auf denselben leeren Schluessel.
        fid = _nid[idx]
        if not fid:
            anomalies.append(f"index{idx}:id-normalises-to-empty={fid_raw!r}")
            continue
        # RT10-REG severity/status TYPE-confusion fail-open (6-lens gate): a non-string severity (e.g. the
        # LIST ["P0"]) or status would slip past the {P0,P1}/"closed" comparisons below and HIDE an open P0
        # (str(["P0"]).upper() != "P0" -> not gating). Any non-string severity/status is an anomaly -> the
        # caller fails closed, so type-confusion can never mask an open finding.
        if not isinstance(f.get("severity"), str) or not isinstance(f.get("status"), str):
            anomalies.append(f"{fid}:non-string-severity-or-status="
                             f"{f.get('severity')!r}/{f.get('status')!r}")
            continue
        # 6-lens gate L5-01: severity DENY-by-default — a string severity whose NFKC/Cc/Cf-normalized form is
        # not a KNOWN token is an anomaly (fail-closed), so an open P0 cannot hide behind an invisible U+200B
        # or a confusable/fullwidth 'P0' that scores as non-gating while rendering as P0 to a reviewer.
        if _norm(f["severity"]).upper() not in _KNOWN_SEVERITIES:
            anomalies.append(f"{fid}:unknown-severity={f['severity']!r}")
            continue
        sby_raw = f.get("superseded_by")
        if isinstance(sby_raw, str) and sby_raw:
            # AUF DERSELBEN ACHSE vergleichen wie die Kennung: sonst ist "X" != "X<U+200B>" und ein
            # Selbstverweis liest sich als Verweis auf einen anderen, vorhandenen Eintrag.
            sby = _norm(sby_raw)
            if not sby or sby == fid or sby not in ids_present:
                anomalies.append(f"{fid}:dangling-or-self-supersede={sby_raw!r}")  # do NOT drop, fail-closed
            else:
                legit_superseded.add(fid)
                sby_map[fid] = sby
    # 6-lens gate L5-01: a supersession CYCLE (a ring A->B->A, or a longer loop) makes EVERY member point to
    # a present+different id, so all members drop as "legitimately superseded", accounted==population holds,
    # and open P0s hidden inside the ring are never counted (ok=True, 0 open — the exact fail-open this module
    # exists to close). A legit chain must TERMINATE at a present, non-superseded node; walk each chain with a
    # visited-set and treat any cycle as an anomaly -> fail-closed (no ring member stays legitimately dropped).
    for fid in list(legit_superseded):
        seen_chain: set[str] = set()
        cur = fid
        while cur in sby_map:
            if cur in seen_chain:
                anomalies.append(f"{fid}:supersession-cycle")
                legit_superseded.discard(fid)
                break
            seen_chain.add(cur)
            cur = sby_map[cur]
    for idx, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        fid = _nid.get(idx)      # normalisiert, wie ueberall sonst in dieser Funktion
        if not fid or fid in legit_superseded:
            continue
        if fid in effective and _norm(str(effective[fid].get("status", ""))).lower() \
                != _norm(str(f.get("status", ""))).lower():
            # Bereits oben ueber die Kollision erfasst; hier nicht doppelt melden.
            if fid not in contradictions:
                contradictions.append(fid)
        effective[fid] = f
    return effective, contradictions, anomalies, legit_superseded


_RFC3339_Z = __import__("re").compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z\Z")

CODE_REGISTER_VERSION_MISMATCH = "REGISTER_VERSION_MISMATCH"


def _version_binding_error(register: dict, expected_version: str | None) -> str | None:
    """The register's SIGNED version field must name the version under test (deep gate 2026-09-05,
    finding L5-G6-02, P1).

    THE CLASS, and it is the L6-01 lesson applied to the ARTEFACT rather than to the matrix pin: a
    version-scoped signed artefact that feeds a release-deciding check must bind its signed version to
    the shipping identity and fail closed on mismatch or absence. Measured on this tree: C12.2 reported
    PASS for 6.0.0 out of a register whose signed ``version`` says ``3.6.1`` and whose ``generated_at``
    is 2026-07-18 — seventeen findings about a release two majors back, deciding a release today. A
    register carrying ``0.0.1`` or no version field at all was accepted just the same, because nothing
    compared the two numbers. The signature was always valid; that was never the question.

    ``expected_version=None`` means the caller did NOT bind (library/inspection use). The verdict then
    carries ``version_bound: False`` so a reader can tell "bound and equal" from "never compared" —
    a gate that passes None is visibly unbound, not silently fine."""
    if expected_version is None:
        return None
    got = register.get("version")
    if not isinstance(got, str) or not got:
        return (f"{CODE_REGISTER_VERSION_MISMATCH}: the register carries no version field, so it cannot "
                f"be shown to be about {expected_version!r} (fail-closed)")
    if got != expected_version:
        return (f"{CODE_REGISTER_VERSION_MISMATCH}: the register is scoped to {got!r}, the version under "
                f"test is {expected_version!r} — findings about another release cannot decide this one")
    gen = register.get("generated_at")
    if not isinstance(gen, str) or not _RFC3339_Z.match(gen):
        return (f"{CODE_REGISTER_VERSION_MISMATCH}: the register carries no well-formed generated_at "
                f"(got {gen!r}) — freshness is not measurable, and not measurable is not fresh")
    return None


#: Wie alt ein Registerkoerper hoechstens sein darf, gemessen an seinem eigenen ``generated_at``.
#: DIESELBE ZAHL wie das Evidenzfenster der Bereitschaftsartefakte (audit_candidate_matrix
#: ``_EVIDENCE_MAX_AGE_DAYS``), und das ist kein Zufall: die zwei Pruefungen sind EIN Mechanismus.
#:
#: WARUM ES SIE UEBERHAUPT BRAUCHT (Owner-Karte OA-89f05b70cd, Auflage 1, 2026-09-06). Die
#: Gueltigkeitsfrist ``not_after`` eines Ankerschluessels wird gegen den MESSZEITPUNKT der Evidenz
#: verglichen, nicht gegen "jetzt" — sonst wuerde Evidenz von gestern unzulaessig, bloss weil die
#: Matrix heute laeuft. Genau daraus entsteht aber eine Rueckdatierungs-Luecke: wer einen
#: widerrufenen Schluessel haelt, koennte ein Register mit einem alten ``generated_at`` signieren und
#: damit in das Fenster zurueckreichen, in dem der Schluessel noch galt. Das Fenster hier begrenzt,
#: wie weit dieses Zurueckreichen ueberhaupt tragen kann. Ohne die Frische waere die Fristpruefung
#: eine Zusicherung, die nur teilweise gilt — und eine halb geltende Zusicherung ist die Klasse, die
#: dieses Repository durchgehend als Fehler behandelt.
_REGISTER_MAX_AGE_DAYS = 180
#: Uhren laufen auseinander; eine Minute Vorlauf ist kein Betrug, eine Stunde waere einer.
_REGISTER_FUTURE_SKEW_MINUTES = 5

CODE_REGISTER_STALE = "REGISTER_STALE"


def _freshness_error(register: dict, *, jetzt=None) -> str | None:
    """``None`` wenn der Registerkoerper frisch genug ist, sonst der Grund.

    Drei Zustaende, wie ueberall in dieser Datei: fehlend/unlesbar ist NICHT dasselbe wie alt, und
    beides ist nicht dasselbe wie frisch. Ein ``generated_at``, das gar nicht lesbar ist, faellt
    fail-closed — eine unmessbare Frische ist nie eine erfuellte."""
    from datetime import datetime, timedelta, timezone  # noqa: PLC0415
    zeit = register.get("generated_at")
    if not isinstance(zeit, str) or not zeit:
        return (f"{CODE_REGISTER_STALE}: the register names no generated_at, so its age cannot be "
                "measured — an unmeasurable freshness is never a satisfied one")
    form = "%Y-%m-%dT%H:%M:%S.%f%z" if "." in zeit else "%Y-%m-%dT%H:%M:%S%z"
    try:
        erzeugt = datetime.strptime(zeit.replace("Z", "+0000"), form)
    except ValueError as exc:
        return f"{CODE_REGISTER_STALE}: generated_at={zeit!r} is not a usable timestamp: {exc}"
    jetzt = jetzt or datetime.now(timezone.utc)
    if erzeugt > jetzt + timedelta(minutes=_REGISTER_FUTURE_SKEW_MINUTES):
        return (f"{CODE_REGISTER_STALE}: generated_at={zeit} lies in the future — a register cannot "
                "predate its own run")
    if erzeugt < jetzt - timedelta(days=_REGISTER_MAX_AGE_DAYS):
        alter = (jetzt - erzeugt).days
        return (f"{CODE_REGISTER_STALE}: generated_at={zeit} is {alter} days old, past the declared "
                f"{_REGISTER_MAX_AGE_DAYS}-day window")
    return None


def verify_and_count(repo: Path | str = REPO, expected_version: str | None = None,
                     authorised_pubkeys: set[str] | None = None) -> dict:
    """Fail-closed verify + count. Returns a verdict dict; never raises on a bad register.

    ``expected_version`` binds the register's SIGNED ``version`` field to the version under test
    (L5-G6-02). The release-deciding caller (audit_candidate_matrix C12.2) MUST pass it; a caller that
    passes None gets ``version_bound: False`` in the verdict and has, by that, declared it is not
    deciding a release."""
    repo = Path(repo)
    path = repo / REGISTER_REL
    triple = {"population_size": 0, "evaluated_count": 0, "source_digest": None,
              "version_bound": expected_version is not None}
    if not path.is_file():
        return {"ok": False, "reason": f"findings register missing at {REGISTER_REL} (RT-10: absence is FAIL, not PASS)",
                "open_ids": [], **triple}
    raw = path.read_bytes()
    source_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    try:
        register = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        return {"ok": False, "reason": f"register is not valid JSON (fail-closed): {exc}",
                "open_ids": [], **triple, "source_digest": source_digest}
    if not isinstance(register, dict) or register.get("schema") != "proofbundle.findings_register.v1":
        return {"ok": False, "reason": "register has the wrong schema (fail-closed)",
                "open_ids": [], **triple, "source_digest": source_digest}
    sig_ok, sig_detail = _signature_ok(register, authorised_pubkeys)
    if not sig_ok:
        return {"ok": False, "reason": f"register signature invalid: {sig_detail} (fail-closed)",
                "open_ids": [], **triple, "source_digest": source_digest}
    # AFTER the signature, BEFORE the count: the version binding decides whether these findings are
    # about the thing being released at all. A valid signature over the wrong scope is exactly the
    # shape this check exists for (L5-G6-02).
    version_err = _version_binding_error(register, expected_version)
    if version_err is not None:
        return {"ok": False, "reason": version_err, "open_ids": [], **triple,
                "register_version": register.get("version"), "source_digest": source_digest}
    # NACH der Versionsbindung, VOR der Zaehlung: ein Register, das ueber die richtige Fassung
    # spricht, aber aus dem Vorleben stammt, ist so wenig eine Aussage ueber heute wie eines ueber
    # die falsche Fassung. Siehe die Herleitung bei _REGISTER_MAX_AGE_DAYS — diese Pruefung ist die
    # zweite Haelfte der Fristpruefung, nicht ein zusaetzlicher Einfall.
    frische_err = _freshness_error(register)
    if frische_err is not None:
        return {"ok": False, "reason": frische_err, "open_ids": [], **triple,
                "register_version": register.get("version"), "source_digest": source_digest}
    findings = register.get("findings")
    if not isinstance(findings, list) or not findings:
        return {"ok": False, "reason": "register lists no findings (RT-10 evaluated_count==0 -> FAIL)",
                "open_ids": [], **triple, "source_digest": source_digest}
    effective, contradictions, anomalies, legit_superseded = _resolve_current(findings)
    population_size = len(findings)
    evaluated_count = len(effective)
    # RT10-REG-01 silent-drop guard: any anomaly (dangling/self supersession, non-string id, non-dict) is
    # FAIL-closed — a finding must never vanish from the count. Belt-and-suspenders: every finding is
    # accounted for (effective OR legitimately superseded), so population == accounted must hold.
    if anomalies:
        return {"ok": False, "reason": f"register has anomalous findings (silent-drop guard, fail-closed): {anomalies}",
                "open_ids": [], "population_size": population_size,
                "evaluated_count": evaluated_count, "source_digest": source_digest}
    accounted = evaluated_count + len(legit_superseded)
    if accounted != population_size:
        return {"ok": False, "reason": (f"population {population_size} != accounted {accounted} — a finding was "
                                        "silently excluded from the count (fail-closed)"),
                "open_ids": [], "population_size": population_size,
                "evaluated_count": evaluated_count, "source_digest": source_digest}
    if evaluated_count == 0:
        return {"ok": False, "reason": "no effective findings after supersession (RT-10 evaluated_count==0 -> FAIL)",
                "open_ids": [], "population_size": population_size, "evaluated_count": 0,
                "source_digest": source_digest}
    if contradictions:
        return {"ok": False, "reason": f"contradictory status for {contradictions} (ERROR, not silently resolved)",
                "open_ids": contradictions, "population_size": population_size,
                "evaluated_count": evaluated_count, "source_digest": source_digest}
    # No-Fake normalization: a finding counts as CLOSED only when its status is exactly 'closed' (case/space
    # folded); any other value (open/OPEN/partial/garbage) is treated as OPEN. Severity is upper-folded so a
    # lower-case 'p0' cannot slip past the {P0,P1} gate.
    open_p0p1 = sorted(fid for fid, f in effective.items()
                       if _norm(str(f.get("severity", ""))).upper() in _GATING_SEVERITIES
                       and _norm(str(f.get("status", ""))).lower() != "closed")
    ok = not open_p0p1
    reason = ("0 open P0/P1 from the signed structured register "
              f"({evaluated_count} findings evaluated, {source_digest})") if ok \
        else f"{len(open_p0p1)} open P0/P1 still present: {open_p0p1}"
    return {"ok": ok, "reason": reason, "open_ids": open_p0p1, "population_size": population_size,
            "evaluated_count": evaluated_count, "source_digest": source_digest,
            "version_bound": expected_version is not None,
            "register_version": register.get("version")}


def _pyproject_version(repo: Path) -> str | None:
    import re as _re
    try:
        roh = (repo / "pyproject.toml").read_text(encoding="utf-8")
    except OSError:
        return None
    m = _re.search(r'(?m)^\s*version\s*=\s*["\']([^"\']+)["\']', roh)
    return m.group(1) if m else None


def _autorisierte_schluessel_vom_tor(repo: Path, check_id: str = "C12.2") -> set[str] | None:
    """Die fuer ``check_id`` autorisierten Schluessel — aus DEM Anker-Leser des Tors, nicht aus einem zweiten.

    WARUM DER IMPORT HIER DRIN STEHT und nicht oben: ``audit_candidate_matrix`` importiert dieses
    Modul (``import findings_register as fr``). Ein Import in der Gegenrichtung auf Modulebene waere
    ein Zyklus. Die CLI ist der einzige Ort, der ihn braucht — sie wird von niemandem importiert —,
    und sie holt ihn erst, wenn sie laeuft. Der Bibliothekspfad bleibt damit azyklisch: wer
    ``verify_and_count`` aufruft, REICHT die Schluessel an, und das ist das Tor.

    Rueckgabe ``None`` heisst NICHT MESSBAR (die Matrix ist hier nicht importierbar, der Anker nicht
    lesbar) — der Aufrufer macht daraus fail-closed, nie ein Bestehen.
    """
    import sys as _sys  # noqa: PLC0415
    _sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        import audit_candidate_matrix as m  # noqa: PLC0415
    except Exception:                        # noqa: BLE001 - kein Importfehler darf hier ein Urteil faellen
        return None
    try:
        # `_trust_anchor` liefert (Schluessel, Zustand) und liest den COMMITTETEN Blob — nicht den
        # Arbeitsbaum. Genau diese Wahl ist der Grund, den Leser des Tors zu nehmen statt einen
        # eigenen: ein schmutziger Checkout koennte sonst einen Schluessel einlegen und sich selbst
        # beglaubigen. `zustand` != "ok" heisst NICHT MESSBAR beziehungsweise LEER, und beides ist
        # hier dasselbe Ergebnis wie ein leeres Set: niemand ist autorisiert.
        schluessel, zustand = m._trust_anchor(repo)
    except Exception:                        # noqa: BLE001
        return None
    if zustand == "unmeasurable":
        return None
    return {pub for pub, feld in schluessel.items()
            if check_id in m._ANKER_ROLLEN.get(feld.get("role", ""), frozenset())}


def main(argv=None) -> int:
    # Die CLI bindet gegen die ausgeliefernde Identitaet, sonst misst sie etwas anderes als das Tor —
    # und sie bindet gegen den ANKER, sonst misst sie eine andere Vertrauensbasis als das Tor.
    r = verify_and_count(REPO, expected_version=_pyproject_version(REPO),
                         authorised_pubkeys=_autorisierte_schluessel_vom_tor(REPO))
    print(json.dumps(r, indent=2, ensure_ascii=False))
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
