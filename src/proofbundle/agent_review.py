"""Agent Review predicate `agent-review/v0.1` — a signed SELF-DECLARATION, and it says so.

WHAT THIS IS FOR. A pull request or issue often says "an AI agent helped here, and it was reviewed".
Today a reader has to believe that sentence. This predicate lets a reader check, offline, that the
stated key signed exactly these bytes and that they have not changed since.

WHAT IT IS EMPHATICALLY NOT. It does not prove the named agent was really involved, that every review
run was captured, that a model was fresh or independent, or that the stated time is externally
witnessed. An external adversarial read of this design (31.08.2026) put the danger in one sentence:
a strong signature must not optically harden a weak self-report. Every design choice below follows
from that.

THREE LAYERS, KEPT APART (F01, F12, PBF01):

  declaration  — what the author or agent CLAIMS about the work
  observations — what a runner, platform or independent witness actually SAW
  policy       — what the relying party requires; NOT decided here

Collapsing them into one green status produces exactly the wrong effect. So every declared field
carries its own ``assurance``, and in v0.1 the only honest value is ``selfDeclared`` — the module
REFUSES the stronger values rather than letting a producer paint them on. Tier 2 (runner-observed)
and Tier 3 (independently witnessed) need a witness outside the agent's own workspace; that is a
separate product step and is deliberately NOT half-built here.

WHAT THAT REFUSAL IS AND IS NOT (external review, 31.08.2026). It is a SEMANTIC validator, not an
anti-forgery mechanism. Whoever controls the emitter bypasses it in a minute by building a DSSE
envelope by hand. It stops a careless producer from claiming a rung this version cannot support; it
does not stop a dishonest one from lying about the facts. The verifier re-checks the same condition,
so a receipt that reached a reader through some other path is still caught — but nothing here
authenticates the claim itself.

SUBJECT BINDING IS EXACT (F02, F03, F14). A PR number, a branch name or a URL points at something
that can still change. The subject therefore carries repository id, PR node id, headSha, baseSha, a
digest of the reviewed diff, and ``bodyCoreDigest`` — the digest of the human-visible body AFTER the
machine-managed disclosure block has been replaced by a fixed token. Without that replacement the
digest would have to cover bytes that contain its own value, which cannot be defined. Issues get
their own profile because they have no head sha, no merge base and no diff.

VALIDITY IS NOT CURRENCY (F04, F06). A receipt stays cryptographically valid after a force-push. It
then describes a state that is no longer the current one. Currency is a SEPARATE axis with its own
states, and this offline module can only ever reach ``CURRENTNESS_UNKNOWN`` — saying so is the point.
Time is likewise four different questions (declared, observed, signed, anchored), never one field.

Field names are lowerCamelCase (ITE-9). Like the rest of proofbundle this module is the enforced
validator; the JSON schema is docs.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any

from ._membership import is_member
from .errors import ProofBundleError

#: House convention is `b7n0de.com/proofbundle/predicates/<name>/v<major.minor>` — the external read
#: proposed a shorter path, but every sibling predicate here uses this one, and an inconsistent id is
#: a worse defect than a longer string. R2 of the envelope profile means this id is READ, not decoration.
AGENT_REVIEW_PREDICATE_TYPE = "https://b7n0de.com/proofbundle/predicates/agent-review/v0.1"
AGENT_REVIEW_SCHEMA_VERSION = "0.1.0"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
INTOTO_STATEMENT_PAYLOAD_TYPE = "application/vnd.in-toto+json"

#: The token that replaces the machine-managed disclosure block before `bodyCoreDigest` is taken.
#: It is part of the wire format: two implementations that pick different tokens compute different
#: digests over the same body, and the mismatch would look like tampering.
DISCLOSURE_BLOCK_TOKEN = "<!-- proofbundle:agent-review:disclosure -->"
DISCLOSURE_BEGIN = "<!-- proofbundle:agent-review:begin -->"
DISCLOSURE_END = "<!-- proofbundle:agent-review:end -->"

#: The token that replaces a receipt digest INSIDE the block before `disclosureCoreDigest` is taken.
#:
#: WHY ONLY THE DIGEST AND NOT THE WHOLE LINE. The block states, in prose a human actually reads,
#: how strong the claim is — "assurance selfDeclared, not independently witnessed". `bodyCoreDigest`
#: replaces the ENTIRE block by one token, which is exactly right for its job (an edit to the block
#: must not invalidate a receipt that was signed before the block existed) and exactly wrong as a
#: guarantee about the block's own content: a hand-edit from `selfDeclared` to
#: `independentlyWitnessed` moves nothing, and verification stays green while the visible text now
#: claims more than the signed object supports. `disclosureCoreDigest` closes that, and it can cover
#: everything EXCEPT the receipt digest itself, which cannot be inside its own preimage.
DISCLOSURE_SELFREF_TOKEN = "<selfref>"

#: The two self-referential shapes a rendered block can carry: the full digest, and the short link
#: label. Both are substituted; everything else in the block is hashed.
_SELFREF_FULL = re.compile(r"sha256:[0-9a-f]{64}")
_SELFREF_SHORT = re.compile(r"\[[0-9a-f]{12}\]\(")

_RFC3339_Z = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z\Z")
_SHA256_HEX = re.compile(r"\A[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"\A[0-9a-f]{40}\Z")
_SEMVER_0_1_X = re.compile(r"\A0\.1\.\d+\Z")

#: The assurance ladder. v0.1 ACCEPTS only the weakest rung — see `_ASSURANCE_ALLOWED_V0_1`.
_ASSURANCE_ALL = {"selfDeclared", "runnerObserved", "platformAttested", "independentlyWitnessed"}
_ASSURANCE_ALLOWED_V0_1 = {"selfDeclared"}

_SUBJECT_KINDS = {"githubPullRequest", "githubIssue"}
_COVERAGE_STATUS = {"COMPLETE", "PARTIAL", "UNKNOWN"}
_DISPOSITION = {"fixed", "dismissed", "deferred", "open"}
_SEVERITY = {"critical", "high", "medium", "low", "info"}

_DECLARATION_FIELDS = frozenset(
    ("authoring", "reviewRuns", "findings", "findingsTotal", "findingsRoot", "nonClaims"))
# v0.2 ERWEITERT diese Menge um `timeClaims`, statt sie in v0.1 zu lockern. Eine gemeinsame
# Konstante mit einem Zusatz-Parameter ist EINE Wahrheit mit einer Ausnahme; zwei kopierte Listen
# waeren zwei Wahrheiten, die auseinanderlaufen.
_DECLARATION_FIELDS_V02 = frozenset(("timeClaims",))


_REQUIRED_ALWAYS = ("schemaVersion", "reviewId", "subjectContext", "declaration",
                    "coverage", "times", "limitations")
_OPTIONAL = ("producer", "observations", "supersession", "planRef", "limitationCodes")
_ALLOWED_TOP = set(_REQUIRED_ALWAYS) | set(_OPTIONAL)

_PR_REQUIRED = ("kind", "forge", "repositoryId", "pullRequestNodeId", "headSha", "baseSha",
                "reviewedDiffDigest", "bodyCoreDigest")
_PR_ALLOWED = set(_PR_REQUIRED) | {"renderedDisclosureDigest", "humanRef", "disclosureCoreDigest"}
_ISSUE_REQUIRED = ("kind", "forge", "repositoryId", "issueNodeId", "bodyCoreDigest", "revisedAt")
_ISSUE_ALLOWED = set(_ISSUE_REQUIRED) | {"commentNodeId", "renderedDisclosureDigest", "humanRef", "disclosureCoreDigest"}

_TIME_FIELDS = ("declaredAt", "observedAt", "signedAt", "anchoredAt")


class AgentReviewError(ProofBundleError):
    """An agent-review predicate is malformed (fail-closed)."""


def _is_digest(obj: Any) -> bool:
    return isinstance(obj, dict) and isinstance(obj.get("sha256"), str) and bool(_SHA256_HEX.match(obj["sha256"]))


# ── bodyCoreDigest ──────────────────────────────────────────────────────────────────────────────
def body_core_bytes(body: str) -> bytes:
    """The exact UTF-8 bytes the digest is taken over: the body with the disclosure block replaced.

    FAIL-CLOSED ON AMBIGUITY (F03, P0 test 8). Zero blocks is the normal pre-disclosure case and is
    fine — the body is hashed as-is. TWO blocks, or a begin without an end, is NOT a body we can
    reduce to one canonical form, and guessing which block is 'the' one would let an attacker choose
    the digest. That raises instead of picking.
    """
    if not isinstance(body, str):
        raise AgentReviewError("body must be a string")
    n_begin, n_end = body.count(DISCLOSURE_BEGIN), body.count(DISCLOSURE_END)
    if n_begin != n_end:
        raise AgentReviewError(
            f"disclosure block markers are unbalanced ({n_begin} begin, {n_end} end) — the body has no "
            "single canonical core, fail-closed")
    if n_begin > 1:
        raise AgentReviewError(
            f"{n_begin} disclosure blocks found — a duplicated block has no single canonical core, "
            "fail-closed (an attacker who may add a second block could otherwise choose the digest)")
    if n_begin == 0:
        return body.encode("utf-8")
    start = body.index(DISCLOSURE_BEGIN)
    end = body.index(DISCLOSURE_END) + len(DISCLOSURE_END)
    if end <= start:
        raise AgentReviewError("disclosure end marker precedes its begin marker — fail-closed")
    return (body[:start] + DISCLOSURE_BLOCK_TOKEN + body[end:]).encode("utf-8")


def prepare_body_for_disclosure(body: str, *, anchor: str | None = None) -> str:
    """The body as it will look ONCE it carries a disclosure block — call this BEFORE emitting.

    THE ORDERING DEFECT THIS EXISTS TO PREVENT, found on 2026-08-31 while adding the first real
    disclosure line to a live pull request. `bodyCoreDigest` is stable when a block is CHANGED (the
    token replaces whatever is between the markers, so the content does not matter). It is NOT
    stable when the first block is INTRODUCED: a body without a block and the same body with an
    empty one differ by the token's own bytes. Measured: 8c482139… -> 87c6288a…

    The consequence is not academic. A receipt emitted over the pre-block body binds a body that
    stops existing the moment its own disclosure line is added — the receipt would be provably
    unrelated to the pull request it describes, and a reader recomputing the digest would rightly
    see a mismatch.

    So the order is: prepare the body, take the digest over THAT, emit, then render the real block
    into the prepared position. The last step cannot move the digest, because the block's content is
    replaced by the token either way — that is the whole reason the markers exist.

    `anchor` names a marker line to place the block AFTER (for example a section heading). Absent,
    the block goes at the end. A named anchor that is not found RAISES rather than silently falling
    back to the end: a block that lands somewhere else changes nothing about the digest, but it
    changes what a human reads, and quietly relocating it is how a disclosure ends up where nobody
    looks.
    """
    if not isinstance(body, str):
        raise AgentReviewError("body must be a string")
    if DISCLOSURE_BEGIN in body:
        raise AgentReviewError(
            "the body already carries a disclosure block — preparing it again would create a second "
            "one, and two blocks have no single canonical core (use render_disclosure_block to "
            "replace the existing one instead)")
    platzhalter = f"{DISCLOSURE_BEGIN}\n\n{DISCLOSURE_END}"
    if anchor is None:
        return body.rstrip("\n") + "\n\n" + platzhalter + "\n"
    if anchor not in body:
        raise AgentReviewError(
            f"anchor {anchor!r} not found in the body — refusing to place the disclosure block "
            "somewhere else, because a human reads the position even though the digest does not")
    i = body.index(anchor) + len(anchor)
    return body[:i] + "\n\n" + platzhalter + body[i:]


def replace_disclosure_block(body: str, block: str) -> str:
    """Swap the block for a rendered one. The core digest MUST survive this — that is the contract."""
    if body.count(DISCLOSURE_BEGIN) != 1 or body.count(DISCLOSURE_END) != 1:
        raise AgentReviewError("the body must carry exactly one disclosure block to replace")
    vorher = body_core_digest(body)
    start = body.index(DISCLOSURE_BEGIN)
    ende = body.index(DISCLOSURE_END) + len(DISCLOSURE_END)
    neu = body[:start] + block.strip("\n") + body[ende:]
    if body_core_digest(neu) != vorher:
        # Not reachable through the normal path; kept because a silent digest move here would
        # invalidate a receipt that was already signed, and that failure must be loud.
        raise AgentReviewError(
            "replacing the block moved the body core digest — the receipt would no longer bind this "
            "body (this means the replacement escaped the markers)")
    return neu


def body_core_digest(body: str) -> str:
    """sha256 hex over :func:`body_core_bytes`. Stable across re-renders of the block (P0 test 7)."""
    return hashlib.sha256(body_core_bytes(body)).hexdigest()


# ── disclosureCoreDigest ────────────────────────────────────────────────────────────────────────
def disclosure_core_bytes(body: str) -> bytes:
    """The bytes of the disclosure block itself, with only the receipt digest substituted.

    THE HOLE THIS CLOSES (P0.2 of the round-2 counter-reading, 2026-08-31). `bodyCoreDigest` binds
    everything AROUND the block and deliberately nothing inside it. That is the right contract for
    what it does — a receipt signed before the block existed must survive the block being rendered —
    but on its own it leaves the block unbound in both directions. Measured: changing the visible
    `assurance selfDeclared` to `independentlyWitnessed` leaves `bodyCoreDigest` byte-identical, the
    signature keeps verifying, and a reader is now told something the signed object does not say.

    RAISES when there is no block. A caller asking for the digest of a block that is not there is
    asking the wrong question, and returning the digest of the empty string would answer it with a
    number that looks like a fact.

    THE SUBSTITUTION IS THE NARROWEST ONE THAT TERMINATES. Only `sha256:<64 hex>` and the twelve-hex
    link label are replaced — those are the parts that would have to contain their own hash. The
    assurance rung, the finding counts, the limitations and the witnessed-or-not statement are all
    inside the preimage, which is the entire point.
    """
    if not isinstance(body, str):
        raise AgentReviewError("body must be a string")
    n_begin, n_end = body.count(DISCLOSURE_BEGIN), body.count(DISCLOSURE_END)
    if n_begin != n_end:
        raise AgentReviewError(
            f"disclosure block markers are unbalanced ({n_begin} begin, {n_end} end) — fail-closed")
    if n_begin > 1:
        raise AgentReviewError(
            f"{n_begin} disclosure blocks found — no single canonical block, fail-closed")
    if n_begin == 0:
        raise AgentReviewError(
            "the body carries no disclosure block — there is nothing to take a disclosure digest "
            "over, and answering with the digest of an empty string would look like a fact")
    start = body.index(DISCLOSURE_BEGIN) + len(DISCLOSURE_BEGIN)
    end = body.index(DISCLOSURE_END)
    if end < start:
        raise AgentReviewError("disclosure end marker precedes its begin marker — fail-closed")
    innen = body[start:end].strip("\n")
    innen = _SELFREF_FULL.sub(f"sha256:{DISCLOSURE_SELFREF_TOKEN}", innen)
    innen = _SELFREF_SHORT.sub(f"[{DISCLOSURE_SELFREF_TOKEN}](", innen)
    return innen.encode("utf-8")


def disclosure_core_digest(body: str) -> str:
    """sha256 hex over :func:`disclosure_core_bytes`."""
    return hashlib.sha256(disclosure_core_bytes(body)).hexdigest()


# ── findingsRoot ────────────────────────────────────────────────────────────────────────────────
def findings_root(findings: list[dict]) -> str:
    """A digest over the canonical findings list — removing one finding must change it (P0 test 11).

    Order-independent by construction: each finding is canonicalized on its own, the leaf digests are
    SORTED, and the root is taken over their concatenation. Two producers that list the same findings
    in a different order must not disagree, or the root would report tampering where there is none.
    """
    from . import canonical  # noqa: PLC0415
    leaves = []
    for f in findings:
        try:
            leaves.append(hashlib.sha256(canonical.canonicalize_statement(f)).hexdigest())
        except canonical.CanonicalizerUnavailable as exc:
            raise AgentReviewError(
                "findingsRoot needs the RFC 8785 (JCS) canonicalizer — install proofbundle[eval]") from exc
    return hashlib.sha256("".join(sorted(leaves)).encode("ascii")).hexdigest()


# ── Validation ──────────────────────────────────────────────────────────────────────────────────
def _mit_abschnitt(abschnitt: str, fehler: object, *, code_teil: str | None = None) -> str:
    """Stellt den Abschnittsnamen voran UND behaelt einen vorhandenen Reason Code.

    WARUM NICHT `f"{abschnitt}: {e}"`. Ein f-String auf einer `ShapeError` erzeugt ein nacktes
    `str` — der Code faellt lautlos weg, genau an der Stelle, an der er gebraucht wird. Gemessen
    am 01.09.2026: die Abnahme der Gegenlese nennt `String Declaration` ausdruecklich, und dieser
    Fall lief durch die Praefix-Zeile. Der Code wird dabei mit dem Abschnitt QUALIFIZIERT
    (`DECLARATION_SECTION_NOT_OBJECT`), damit zwei Abschnitte mit derselben Fehlerart
    unterscheidbar bleiben — sonst waere der Code weniger wert als der Satz.
    """
    text = f"{abschnitt}: {fehler}"
    code = getattr(fehler, "code", None)
    if not code:
        return text
    return _shape_err(f"{_code_segment(code_teil or abschnitt)}_{code}", text)


#: Only these characters may reach a reason code. Everything else is dropped rather than
#: transliterated, so a surprising input yields a SHORTER code, never a new one.
_CODE_ERLAUBT = re.compile(r"[^A-Z0-9_]+")


def _code_segment(roh: str) -> str:
    """Turn a caller-supplied section name into a STABLE code segment.

    WHY THIS EXISTS. ``_mit_abschnitt`` lifted its ``abschnitt`` argument straight into the code
    namespace. The obvious next repair — routing ``f"findings[{i}]: {e}"`` through it — would then
    have produced ``FINDINGS[7]_SECTION_NOT_OBJECT``: the ARRAY INDEX travelling into the code, so
    ``findings[0]`` and ``findings[7]`` would carry different codes for the same defect. That
    destroys the one property a reason code has, and it sat exactly on the path of the obvious fix.
    Measured by adversarial review on 2026-09-01 before it was written, not after.
    """
    return _CODE_ERLAUBT.sub("", roh.upper()).strip("_") or "UNBENANNT"


def validate_agent_review_predicate(predicate: Any, *, strict: bool = False,
                                    decl_zusatz: frozenset = frozenset()) -> list[str]:
    """Return fail-closed errors for an ``agent-review/v0.1`` predicate (empty = valid)."""
    errors: list[str] = []
    if not isinstance(predicate, dict):
        return ["predicate must be a JSON object"]

    for k in predicate:
        if k not in _ALLOWED_TOP:
            errors.append(f"unknown field {k!r} (additionalProperties:false)")
    for req in _REQUIRED_ALWAYS:
        if req not in predicate:
            errors.append(f"missing required field {req!r}")

    sv = predicate.get("schemaVersion")
    if "schemaVersion" in predicate and not (isinstance(sv, str) and _SEMVER_0_1_X.match(sv)):
        errors.append("schemaVersion must match 0.1.x")

    rid = predicate.get("reviewId")
    if "reviewId" in predicate and not (isinstance(rid, str) and rid):
        errors.append("reviewId must be a non-empty string")

    if "subjectContext" in predicate:
        errors.extend(_mit_abschnitt("subjectContext", e) for e in _validate_subject(predicate.get("subjectContext")))
    if "declaration" in predicate:
        errors.extend(_mit_abschnitt("declaration", e) for e in
                      _validate_declaration(predicate.get("declaration"), zusatz=decl_zusatz))
    if "coverage" in predicate:
        errors.extend(_mit_abschnitt("coverage", e) for e in _validate_coverage(predicate.get("coverage")))
    if "limitationCodes" in predicate:
        errors.extend(_validate_limitation_codes(predicate.get("limitationCodes")))
    if "times" in predicate:
        errors.extend(_mit_abschnitt("times", e) for e in _validate_times(predicate.get("times")))

    lim = predicate.get("limitations")
    if "limitations" in predicate and not (isinstance(lim, list) and lim
                                           and all(isinstance(x, str) and x for x in lim)):
        errors.append("limitations must be a non-empty array of strings — a receipt that states no "
                      "limit is claiming more than this predicate can carry")

    obs = predicate.get("observations")
    if "observations" in predicate:
        if not isinstance(obs, list):
            errors.append("observations must be an array")
        elif obs:
            # v0.1 CANNOT carry observations: there is no witness outside the agent's workspace yet,
            # so anything here would be the producer vouching for itself at a higher rung.
            errors.append("observations must be empty in v0.1 — a non-empty observation needs a "
                          "witness outside the producing agent, which this version does not have")

    sup = predicate.get("supersession")
    if "supersession" in predicate:
        errors.extend(_mit_abschnitt("supersession", e) for e in _validate_supersession(sup))

    if "planRef" in predicate and not _is_digest(predicate.get("planRef")):
        errors.append("planRef, when present, must be a sha256 digest object")

    # Die Luecke wird zwischen ZWEI Bloecken geprueft, deshalb hier und nicht in _validate_declaration.
    dec_ = predicate.get("declaration")
    cov_ = predicate.get("coverage")
    if isinstance(dec_, dict) and isinstance(cov_, dict):
        tot_, lst_ = dec_.get("findingsTotal"), dec_.get("findings")
        if (isinstance(tot_, int) and not isinstance(tot_, bool) and isinstance(lst_, list)
                and tot_ > len(lst_) and not cov_.get("knownGaps")):
            errors.append(
                f"findingsTotal {tot_} exceeds the {len(lst_)} findings listed, but coverage.knownGaps "
                "is empty — an unlisted finding must be named as a gap, never left as a silent "
                "difference between two numbers")

    pr = predicate.get("producer")
    if "producer" in predicate:
        if not isinstance(pr, dict):
            errors.append("producer must be an object")
        else:
            for k in pr:
                if k not in ("id", "keyId"):
                    errors.append(f"producer.{k} is not an allowed field")
                elif not isinstance(pr[k], str):
                    errors.append(f"producer.{k} must be a string")
    return errors


def _validate_subject(sc: Any) -> list[str]:
    errs: list[str] = []
    if not isinstance(sc, dict):
        return [_shape_err("SECTION_NOT_OBJECT", "must be an object")]
    kind = sc.get("kind")
    if not is_member(kind, _SUBJECT_KINDS):
        return [f"kind must be one of {sorted(_SUBJECT_KINDS)}"]
    required, allowed = ((_PR_REQUIRED, _PR_ALLOWED) if kind == "githubPullRequest"
                         else (_ISSUE_REQUIRED, _ISSUE_ALLOWED))
    for k in sc:
        if k not in allowed:
            errs.append(f"unknown field {k!r} for kind {kind!r}")
    for req in required:
        if req not in sc:
            errs.append(f"missing {req!r} (required for {kind})")
    if "forge" in sc and not (isinstance(sc["forge"], str) and sc["forge"]):
        errs.append("forge must be a non-empty string")
    for idf in ("repositoryId", "pullRequestNodeId", "issueNodeId", "commentNodeId"):
        if idf in sc and not (isinstance(sc[idf], str) and sc[idf]):
            errs.append(f"{idf} must be a non-empty string")
    for shaf in ("headSha", "baseSha"):
        if shaf in sc and not (isinstance(sc[shaf], str) and _GIT_SHA.match(sc[shaf])):
            errs.append(f"{shaf} must be a full 40-hex commit id (an abbreviated id is ambiguous)")
    for dgf in ("reviewedDiffDigest", "bodyCoreDigest", "renderedDisclosureDigest"):
        if dgf in sc and not (isinstance(sc[dgf], str) and _SHA256_HEX.match(sc[dgf])):
            errs.append(f"{dgf} must be a sha256 hex digest")
    if "revisedAt" in sc and not (isinstance(sc["revisedAt"], str) and _RFC3339_Z.match(sc["revisedAt"])):
        errs.append("revisedAt must be an RFC3339 UTC 'Z' timestamp")
    return errs


def _validate_declaration(dec: Any, *, zusatz: frozenset = frozenset()) -> list[str]:
    errs: list[str] = []
    if not isinstance(dec, dict):
        return [_shape_err("SECTION_NOT_OBJECT", "must be an object")]
    for k in dec:
        if k not in _DECLARATION_FIELDS | zusatz:
            errs.append(f"unknown field {k!r}")
    for req in ("authoring", "reviewRuns", "findings", "findingsTotal", "nonClaims"):
        if req not in dec:
            errs.append(f"missing {req!r}")

    for listf in ("authoring", "reviewRuns"):
        v = dec.get(listf)
        if listf in dec:
            if not isinstance(v, list):
                errs.append(f"{listf} must be an array")
            else:
                for i, item in enumerate(v):
                    # DER CODE UEBERLEBT (Gegenlesung 01.09.2026, Fund B3): diese Zeile war
                    # die f-String-Form, die `_mit_abschnitt` ausdruecklich als Fehler
                    # beschreibt — zwei Ebenen tiefer und deshalb uebersehen. Der
                    # Code-Teil traegt den Listennamen OHNE Index (`AUTHORING_ENTRY`),
                    # damit Eintrag 0 und Eintrag 7 denselben Defekt gleich benennen.
                    errs.extend(_mit_abschnitt(f"{listf}[{i}]", e,
                                               code_teil=f"{listf}_ENTRY")
                                for e in _validate_assured(item))

    fnd = dec.get("findings")
    if "findings" in dec:
        if not isinstance(fnd, list):
            errs.append("findings must be an array")
        else:
            seen: set[str] = set()
            for i, f in enumerate(fnd):
                errs.extend(_mit_abschnitt(f"findings[{i}]", e,
                                           code_teil="FINDINGS_ENTRY")
                            for e in _validate_finding(f))
                if isinstance(f, dict) and isinstance(f.get("id"), str):
                    if f["id"] in seen:
                        errs.append(f"findings[{i}]: duplicate id {f['id']!r}")
                    seen.add(f["id"])
    if "findingsRoot" in dec and not (isinstance(dec["findingsRoot"], str)
                                      and _SHA256_HEX.match(dec["findingsRoot"])):
        errs.append(_shape_err("FINDINGS_ROOT_MALFORMED",
                               "findingsRoot must be a sha256 hex digest"))
    # A PUBLISHED LIST WITHOUT ITS ROOT CANNOT BE CHECKED AT ALL (P1.2 of round-2 review).
    #
    # ``findingsRoot`` was optional, and the verifier only checks it ``elif isinstance(...,
    # str)`` — so a producer could simply omit it and the strongest binding in this predicate,
    # the one that catches a finding added or removed after signing, silently did not apply.
    # Test 11 passed the whole time: it plants a STALE root, and a stale root is present.
    #
    # MEASURED BEFORE ENFORCING, against every receipt we ourselves published (6 files under
    # ``receipts/agent_review/``): all six carry a root. Nothing already public breaks. The rule
    # is deliberately narrow — an EMPTY findings list needs no root, because there is nothing a
    # root could bind.
    if isinstance(dec.get("findings"), list) and dec["findings"] and "findingsRoot" not in dec:
        errs.append(_shape_err(
            "FINDINGS_ROOT_MISSING",
            "findingsRoot is required once findings are listed — without it nothing binds the "
            "published list, and a finding can be added or dropped after signing"))

    nc = dec.get("nonClaims")
    if "nonClaims" in dec and not (isinstance(nc, list) and nc and all(isinstance(x, str) and x for x in nc)):
        errs.append("nonClaims must be a non-empty array of strings (the No-Overclaim block is mandatory)")

    # LISTED IS NOT RECORDED, and the gap between them must be spoken.
    # Found in the first real use (31.08.2026): the reference pull request states "8 findings, 3
    # fixed, 5 dismissed" but publishes only the five dismissed ones individually. The three fixed
    # are not reconstructible from any published artifact. Listing five while the PR says eight is
    # not a lie, but a receipt that silently reports the smaller number lets an aggregate claim
    # disappear. So the aggregate gets its own field, it may never be SMALLER than the list, and a
    # shortfall without an explanation in coverage.knownGaps is rejected.
    # PFLICHT, nicht optional — und der Grund steht in einer Gegenlesung vom 31.08.2026, die den
    # Angriff ausgefuehrt hat: solange das Feld weggelassen werden durfte, lief die ganze
    # Luecken-Pflicht ins Leere. Ein Produzent listete einen von acht Funden, liess `findingsTotal`
    # weg, setzte `knownGaps` auf leer — und der Validator meldete NULL Fehler. Eine Pflicht, die
    # sich durch Weglassen eines Feldes abschalten laesst, ist keine.
    tot = dec.get("findingsTotal")
    if "findingsTotal" in dec:
        if not isinstance(tot, int) or isinstance(tot, bool) or tot < 0:
            errs.append("findingsTotal must be a non-negative integer")
        elif isinstance(fnd, list) and tot < len(fnd):
            errs.append(f"findingsTotal {tot} is smaller than the {len(fnd)} findings listed — the "
                        "aggregate cannot undercount its own list")
    return errs


def _validate_assured(item: Any) -> list[str]:
    """Every declared item names WHO says it and at WHAT assurance — F01, and v0.1 allows one rung."""
    errs: list[str] = []
    if not isinstance(item, dict):
        return [_shape_err("SECTION_NOT_OBJECT", "must be an object")]
    if "assurance" not in item:
        errs.append("missing 'assurance' — an unlabelled field silently reads as observed fact")
    else:
        a = item["assurance"]
        if not is_member(a, _ASSURANCE_ALL):
            errs.append(f"assurance must be one of {sorted(_ASSURANCE_ALL)}")
        elif not is_member(a, _ASSURANCE_ALLOWED_V0_1):
            errs.append(
                f"assurance {a!r} is not emittable in v0.1 — this version has no witness outside the "
                "producing agent, so only 'selfDeclared' is honest here (P0 test 1)")
    if "assertedBy" not in item:
        errs.append("missing 'assertedBy'")
    elif not (isinstance(item["assertedBy"], str) and item["assertedBy"]):
        errs.append("assertedBy must be a non-empty string")
    if "observedBy" in item and item["observedBy"] is not None and not isinstance(item["observedBy"], str):
        errs.append("observedBy must be a string or null")
    if "evidenceRef" in item and item["evidenceRef"] is not None and not _is_digest(item["evidenceRef"]):
        errs.append("evidenceRef must be a sha256 digest object or null")
    return errs


def _validate_finding(f: Any) -> list[str]:
    errs: list[str] = []
    if not isinstance(f, dict):
        return [_shape_err("SECTION_NOT_OBJECT", "must be an object")]
    for k in f:
        if k not in ("id", "severity", "title", "disposition", "fixCommit", "reason", "evidenceRef"):
            errs.append(f"unknown field {k!r}")
    for req in ("id", "severity", "title", "disposition"):
        if req not in f:
            errs.append(f"missing {req!r}")
    if "id" in f and not (isinstance(f["id"], str) and f["id"]):
        errs.append("id must be a non-empty string")
    if "severity" in f and not is_member(f.get("severity"), _SEVERITY):
        errs.append(f"severity must be one of {sorted(_SEVERITY)}")
    if "title" in f and not (isinstance(f["title"], str) and f["title"]):
        errs.append("title must be a non-empty string")
    if "disposition" in f and not is_member(f.get("disposition"), _DISPOSITION):
        errs.append(f"disposition must be one of {sorted(_DISPOSITION)}")
    # A closed finding owes an account of itself: fixed -> which change, dismissed -> why.
    if f.get("disposition") == "fixed" and not (isinstance(f.get("fixCommit"), str) and f.get("fixCommit")):
        errs.append("a finding marked 'fixed' must name its fixCommit")
    if f.get("disposition") == "dismissed" and not (isinstance(f.get("reason"), str) and f.get("reason")):
        errs.append("a finding marked 'dismissed' must carry a one-sentence reason")
    if "evidenceRef" in f and f["evidenceRef"] is not None and not _is_digest(f["evidenceRef"]):
        errs.append("evidenceRef must be a sha256 digest object or null")
    return errs


#: Die standardisierten Einschraenkungs-Codes (P0.4.6 der Gegenlesung Runde 2).
#:
#: WARUM CODES UND NICHT NUR FREITEXT. `limitations` ist eine Liste von Saetzen. Ein Satz ist fuer
#: einen Leser gut und fuer eine relying party wertlos: sie kann ihn nicht gegen eine Policy halten,
#: ohne ihn zu LESEN, und was sie nicht maschinell auswerten kann, wertet sie in der Praxis gar
#: nicht aus. Der Freitext bleibt — als Erlaeuterung, nicht als einzige Schutzschicht.
LIMITATION_CODES = frozenset((
    "IDENTITY_UNBOUND",          # kein gebundener Urheber
    "TIME_SELF_DECLARED",        # keine Zeit stammt von einem benannten Beobachter
    "CURRENTNESS_UNKNOWN",       # unbekannt, ob das Objekt seither bewegt wurde
    "COVERAGE_PARTIAL",          # die Abdeckung nennt selbst Luecken
    "NOT_QUALITY_ATTESTATION",   # sagt NICHTS ueber die Guete der Arbeit
))


def derive_limitation_codes(predicate: dict) -> list[str]:
    """Die Codes aus dem Predicate ABLEITEN statt sie tippen zu lassen.

    Ein von Hand gesetzter Code driftet vom Inhalt weg, ohne dass irgendein Digest sich bewegt —
    dieselbe Klasse wie die handgeschriebene Offenlegungszeile. Deshalb erzeugt diese Funktion sie,
    und ein Emitter, der sie benutzt, kann gar nicht erst etwas Falsches behaupten.

    `NOT_QUALITY_ATTESTATION` steht IMMER drin: kein agent-review-Receipt sagt jemals etwas ueber
    die Guete der geprueften Arbeit, und das ist keine Eigenschaft des Einzelfalls, sondern des
    Belegtyps.
    """
    codes = {"NOT_QUALITY_ATTESTATION"}
    if not isinstance(predicate, dict):
        return sorted(codes)
    dec = predicate.get("declaration")
    dec = dec if isinstance(dec, dict) else {}
    rungs = {i.get("assurance") for i in
             (dec.get("authoring") or []) + (dec.get("reviewRuns") or []) if isinstance(i, dict)}
    if not rungs or rungs <= {"selfDeclared"}:
        codes.add("IDENTITY_UNBOUND")
    beob = predicate.get("observations")
    if not (isinstance(beob, list) and beob):
        codes.add("TIME_SELF_DECLARED")
    cov = predicate.get("coverage")
    cov = cov if isinstance(cov, dict) else {}
    if cov.get("status") in ("PARTIAL", "UNKNOWN"):
        codes.add("COVERAGE_PARTIAL")
    # CURRENTNESS ist keine Eigenschaft des Predicates, sondern des Abrufzeitpunkts — es kann hier
    # nur UNKNOWN heissen, und das ist die ehrliche Angabe, nicht die faule.
    codes.add("CURRENTNESS_UNKNOWN")
    return sorted(codes)


def _validate_limitation_codes(v: Any) -> list[str]:
    if not isinstance(v, list):
        return [f"limitationCodes must be an array, got {type(v).__name__}"]
    errs = []
    for i, c in enumerate(v):
        if not isinstance(c, str):
            errs.append(f"limitationCodes[{i}] must be a string")
        elif not is_member(c, LIMITATION_CODES):
            errs.append(f"limitationCodes[{i}]: unknown code {c!r} — allowed: "
                        f"{sorted(LIMITATION_CODES)}")
    # `set(v)` WIRFT auf einer Liste, die ein dict enthaelt (unhashable). Der Typkonfusions-Fuzzer
    # hat genau diese Zeile getroffen — die harmlos aussehende, nicht den Mitgliedschaftstest
    # daneben, den ich vorher abgesichert hatte. Nur die Zeichenketten zaehlen; alles andere ist
    # oben schon als Befund vermerkt und braucht hier keine zweite Meldung.
    nur_str = [x for x in v if isinstance(x, str)]
    if len(set(nur_str)) != len(nur_str):
        errs.append("limitationCodes contains duplicates")
    return errs


def _validate_coverage(cov: Any) -> list[str]:
    errs: list[str] = []
    if not isinstance(cov, dict):
        return [_shape_err("SECTION_NOT_OBJECT", "must be an object")]
    for k in cov:
        if k not in ("status", "window", "sources", "observedRuns", "expectedRuns",
                     "knownGaps", "collectionMethod"):
            errs.append(f"unknown field {k!r}")
    if "status" not in cov:
        errs.append("missing 'status'")
    elif not is_member(cov.get("status"), _COVERAGE_STATUS):
        errs.append(f"status must be one of {sorted(_COVERAGE_STATUS)}")
    for listf in ("sources", "knownGaps"):
        if listf in cov and not (isinstance(cov[listf], list) and all(isinstance(x, str) for x in cov[listf])):
            errs.append(f"{listf} must be an array of strings")
    # EIN BOOLEAN IST IN PYTHON EIN int (P0.4.1). `isinstance(True, int)` ist wahr, also nahm die
    # erste Fassung `observedRuns: true` klaglos an — live gemessen. Der Reviewer hat genau das
    # vorgelegt, und es ist keine Spitzfindigkeit: `true` als Laufzahl wuerde spaeter in jeder
    # Rechnung als 1 auftreten und nie als der Unsinn, der es ist.
    for numf in ("observedRuns", "expectedRuns"):
        if numf in cov and cov[numf] is not None:
            v = cov[numf]
            if isinstance(v, bool) or not isinstance(v, int):
                errs.append(f"{numf} must be an integer or null, not {type(v).__name__} "
                            f"(a boolean is an int in Python and is rejected explicitly)")
            elif v < 0:
                errs.append(f"{numf} must not be negative, got {v} — a negative run count describes "
                            f"nothing that can have happened")
    # COMPLETE is a strong word. It needs a stated expectation that the observation actually met —
    # otherwise 'complete' means 'I saw everything I happened to see' (F07).
    if cov.get("status") == "COMPLETE":
        obs, exp = cov.get("observedRuns"), cov.get("expectedRuns")
        if not (isinstance(obs, int) and isinstance(exp, int)):
            errs.append("status COMPLETE requires integer observedRuns and expectedRuns — without a "
                        "stated expectation, 'complete' is unfalsifiable")
        elif obs < exp:
            errs.append(f"status COMPLETE but observedRuns {obs} < expectedRuns {exp}")
        # COMPLETE UEBER NULL LAEUFEN (P0.4.2). 0 von 0 erfuellt `obs >= exp` und war damit
        # gueltig — "vollstaendig" ueber eine leere Menge. Formal wahr, als Aussage wertlos, und
        # als Anzeige irrefuehrend: ein Leser sieht COMPLETE und schliesst auf gepruefte Laeufe.
        if isinstance(exp, int) and not isinstance(exp, bool) and exp == 0:
            errs.append("status COMPLETE with expectedRuns 0 — 'complete' over an empty expectation "
                        "says nothing; use UNKNOWN or NONE instead")
        if cov.get("knownGaps"):
            errs.append("status COMPLETE cannot list knownGaps")
        # COMPLETE MUSS SAGEN, WORUEBER (P0.4.3). Ohne Quellen, Fenster und Methode ist
        # "vollstaendig" gegen nichts pruefbar — dieselbe Klasse wie die fehlende Erwartung.
        fehlend = [f for f in ("sources", "window", "collectionMethod") if not cov.get(f)]
        if fehlend:
            errs.append(f"status COMPLETE requires {fehlend} — without them 'complete' names no "
                        f"universe it is complete over")
    # NACHBAR DERSELBEN KLASSE, im selben Durchgang geschlossen. COMPLETE musste seine Erwartung
    # nennen; PARTIAL musste gar nichts nennen und war damit genauso unwiderlegbar — "unvollstaendig,
    # aber ich sage nicht worin" ist keine Angabe. Wer eine Luecke behauptet, benennt sie.
    if cov.get("status") == "PARTIAL" and not cov.get("knownGaps"):
        errs.append("status PARTIAL requires a non-empty knownGaps — an incomplete coverage that "
                    "names no gap cannot be checked against anything")
    return errs


def _validate_times(t: Any) -> list[str]:
    errs: list[str] = []
    if not isinstance(t, dict):
        return [_shape_err("SECTION_NOT_OBJECT", "must be an object")]
    for k in t:
        if k not in _TIME_FIELDS:
            errs.append(f"unknown field {k!r}")
    if "declaredAt" not in t:
        errs.append("missing 'declaredAt'")
    for k in _TIME_FIELDS:
        v = t.get(k)
        if k in t and v is not None and not (isinstance(v, str) and _RFC3339_Z.match(v)):
            errs.append(f"{k} must be an RFC3339 UTC 'Z' timestamp or null")
    # anchoredAt asserts EXTERNAL time. This module cannot check an anchor, so it refuses the claim
    # rather than passing it through unmarked (F06, P0 test 17).
    if t.get("anchoredAt") is not None:
        errs.append("anchoredAt must be null in v0.1 — an external time claim needs anchor evidence "
                    "this predicate does not carry; set it only via a witnessed profile")
    return errs


def _validate_supersession(sup: Any) -> list[str]:
    errs: list[str] = []
    if not isinstance(sup, dict):
        return [_shape_err("SECTION_NOT_OBJECT", "must be an object")]
    for k in sup:
        if k not in ("supersedes", "corrects", "withdraws"):
            errs.append(f"unknown field {k!r}")
    for k in ("supersedes", "corrects", "withdraws"):
        v = sup.get(k)
        if k in sup:
            if not isinstance(v, list):
                errs.append(f"{k} must be an array")
            else:
                for i, rel in enumerate(v):
                    if not isinstance(rel, dict):
                        errs.append(f"{k}[{i}] must be an object")
                        continue
                    if not _is_digest(rel.get("priorDigest")):
                        errs.append(f"{k}[{i}].priorDigest must be a sha256 digest object")
                    if not (isinstance(rel.get("reason"), str) and rel.get("reason")):
                        errs.append(f"{k}[{i}].reason must be a non-empty string — a silent "
                                    "replacement is exactly what supersession exists to prevent")
    return errs


def _waere_fuer_dsse_ein_receipt(env: object) -> bool:
    """Wuerde die DSSE-Schicht das ueberhaupt als Receipt annehmen?

    Diese Weiche trennt zwei Dinge, die beide `receipt_digest` werfen lassen und trotzdem nichts
    miteinander zu tun haben:

    * ein ECHTES, kryptografisch gueltiges Receipt, dessen payload im urlsafe-Alphabet steht —
      `dsse` nimmt beide Alphabete (die Spec verlangt es), `receipt_digest` nur das Standard-
      Alphabet. Diese ASYMMETRIE war der am 01.09.2026 gemessene Defekt: so ein Receipt fiel
      lautlos aus der Kette. Das IST ein Verlust und muss gegen die Unversehrtheit zaehlen.
    * beliebiger Muell im Eingang (kein dict, keine payload-Zeichenkette, oder eine, die in KEINEM
      Alphabet dekodiert). Das ist gar kein Receipt. Wuerde es die Kette `integrity_ok=False`
      machen, koennte jeder Aufrufer sie mit einem sinnlosen Objekt als "kaputt" melden lassen —
      und der Resolver soll robust bleiben, nicht empfindlich.

    Die erste Fassung dieses Fixes machte genau diesen Fehler und fasste beides zusammen; gefangen
    hat es `test_ein_kaputter_umschlag_bringt_den_resolver_nicht_um`."""
    if not isinstance(env, dict) or not isinstance(env.get("payload"), str):
        return False
    for altchars in (None, b"-_"):
        try:
            base64.b64decode(env["payload"], altchars=altchars, validate=True)
            return True
        except (ValueError, TypeError):
            continue
    return False


def receipt_digest(envelope: dict) -> str:
    """Der sha256 ueber die kanonischen Bytes des Statements — die Groesse, die supersession bindet.

    ES IST AUSDRUECKLICH NICHT der Digest der DATEI. Eine Datei laesst sich neu einruecken, anders
    sortieren oder mit einem anderen Zeilenende speichern, ohne dass sich am signierten Objekt
    etwas aendert; ein Datei-Digest wuerde dann Faelschung melden, wo keine ist. Gebunden wird das
    Objekt, nicht seine Verpackung.
    """
    roh = envelope.get("payload")
    if not isinstance(roh, str):
        raise AgentReviewError("envelope carries no base64 payload")
    # validate=True ist hier NICHT kosmetisch: ohne es verwirft CPython stillschweigend jedes
    # Zeichen ausserhalb des Alphabets, und dann haette dasselbe Artefakt viele akzeptierte
    # Drahtformen — ein Angreifer koennte den Digest waehlen, indem er Muell einstreut.
    try:
        bytes_ = base64.b64decode(roh, validate=True)
    except (ValueError, TypeError) as exc:
        raise AgentReviewError(f"payload is not strict base64: {exc}") from exc
    return hashlib.sha256(bytes_).hexdigest()


def resolve_receipt_chain(envelopes: list[dict], *, verified: set[str] | None) -> dict:
    """Welches Receipt gilt JETZT, welche sind korrigiert, und ist die Kette vollstaendig.

    DREI AUSSAGEN, die oft verwechselt werden und hier getrennt bleiben (Supersessionstests 15
    bis 20):

    * `current` — worauf ein oeffentlicher Verweis zeigen SOLL. Genau eines, oder die Kette ist
      mehrdeutig und das wird gesagt statt geraten.
    * `corrected` — Vorgaenger, die weiterhin KRYPTOGRAFISCH GUELTIG sind und trotzdem nicht mehr
      der aktuelle Stand. Beides gilt gleichzeitig, und der Resolver behauptet nie das Gegenteil:
      ein korrigiertes Receipt wird nicht ungueltig, es wird ueberholt.
    * `integrity_ok` — ob jeder referenzierte Vorgaenger auch VORLIEGT. Verschwindet das alte
      Receipt, ist die Korrektur nicht mehr nachvollziehbar, und dann ist die Kette kaputt, auch
      wenn jedes einzelne Stueck fuer sich gueltig bleibt.

    `verified` IST PFLICHT und nimmt keinen Vorgabewert. Es enthaelt die Digests, die der Aufrufer
    selbst kryptografisch geprueft hat.

    WARUM PFLICHT, gemessen am 01.09.2026 durch eine Jury-Linse des Deep-Gates und mit einem
    gebauten Angriff bestaetigt: die erste Fassung liess JEDEN Umschlag der Menge einen anderen als
    korrigiert markieren. Ein Angreifer mit EIGENEM Schluessel legte einen Umschlag dazu, der den
    Digest unseres echten Belegs nannte — danach zeigte `current` auf SEIN Receipt, unseres stand
    unter `corrected`, und `integrity_ok` war True. Signaturpruefung an anderer Stelle half nicht:
    die Ordnung entstand VOR ihr und war bereits vergiftet.

    Ein Vorgabewert waere hier die falsche Freundlichkeit. Wer die Menge nicht nennt, bekommt kein
    stilles Vertrauen, sondern `None` — und dann darf KEIN Umschlag einen anderen korrigieren, alles
    bleibt Kandidat, und das Ergebnis ist laut mehrdeutig statt leise falsch.

    Der Resolver prueft KEINE Signaturen — das tut `verify_agent_review`. Er ordnet nur, und er
    sagt es hier, damit niemand `integrity_ok` fuer ein Krypto-Urteil haelt. Was er jetzt zusaetzlich
    tut: er ordnet nur nach dem, was der Aufrufer als geprueft BENANNT hat.
    """
    vorhanden: dict[str, dict] = {}
    korrigiert: dict[str, list[str]] = {}
    fehlend: list[str] = []
    # WAS DER VERIFIER ANNIMMT, MUSS DIE KETTE HALTEN KOENNEN — und wo sie es nicht kann, sagt sie
    # es, statt das Receipt lautlos fallen zu lassen.
    #
    # GEMESSEN (Tiefen-Gate 5.1.0, 01.09.2026, von zwei unabhaengigen Linsen und danach von Hand):
    # `dsse` akzeptiert BEIDE base64-Alphabete — die DSSE-Spec verlangt das, und der eigene
    # Docstring haelt es fest. `receipt_digest` akzeptiert nur das Standard-Alphabet und WIRFT,
    # und das ist ebenfalls richtig: ohne `validate=True` verwirft CPython stillschweigend jedes
    # fremde Zeichen, und ein Angreifer koennte sich den Digest durch eingestreuten Muell
    # aussuchen. BEIDE Entscheidungen sind fuer sich begruendet. Der Defekt war ihre ASYMMETRIE
    # plus ein stilles `continue`: ein kryptografisch gueltiges Receipt fiel aus der
    # Mitgliedschaftsmenge, und die Kette meldete trotzdem `integrity_ok=True`.
    # Live: url-safe Umschlag -> `crypto_ok=True`, `receipt_digest` wirft,
    # `resolve_receipt_chain([url])` -> `current=None`, `ambiguous=True`, `integrity_ok=True`.
    #
    # NICHT das Digest-Alphabet aufgeweicht (das waere die falsche Stelle und oeffnete genau die
    # Wahlfreiheit, gegen die `validate=True` steht). Stattdessen wird der Verlust BENANNT und
    # zaehlt gegen die Unversehrtheit — nicht messbar ist keine Freigabe.
    nicht_adressierbar: list[str] = []
    for env in envelopes:
        try:
            d = receipt_digest(env)
        except (AgentReviewError, ValueError) as exc:
            # NUR die gemessene Asymmetrie zaehlt als Verlust — nicht jeder Muell im Eingang.
            if _waere_fuer_dsse_ein_receipt(env):
                nicht_adressierbar.append(str(exc))
            continue
        vorhanden[d] = env

    ungeprueft_mit_anspruch: list[str] = []
    for d, env in vorhanden.items():
        try:
            st = json.loads(base64.b64decode(env["payload"], validate=True))
            sup = (st.get("predicate") or {}).get("supersession") or {}
        except (ValueError, KeyError, TypeError):
            continue
        if sup and (verified is None or d not in verified):
            # Ein Umschlag, den der Aufrufer nicht geprueft hat, darf die Ordnung nicht bestimmen.
            # Er wird nicht still ignoriert — sein Anspruch wird GEMELDET, sonst saehe ein
            # abgewehrter Uebernahmeversuch aus wie ein leerer Eingang.
            ungeprueft_mit_anspruch.append(d)
            continue
        for feld in ("corrects", "supersedes", "withdraws"):
            for rel in (sup.get(feld) or []):
                if not isinstance(rel, dict):
                    continue
                prior = (rel.get("priorDigest") or {}).get("sha256")
                if not isinstance(prior, str):
                    continue
                korrigiert.setdefault(prior, []).append(d)
                if prior not in vorhanden:
                    fehlend.append(prior)

    aktuell = [d for d in vorhanden if d not in korrigiert]
    return {"unverified_supersession_claims": sorted(ungeprueft_mit_anspruch),
            "current": aktuell[0] if len(aktuell) == 1 else None,
            "current_candidates": sorted(aktuell),
            "ambiguous": len(aktuell) != 1,
            "corrected": sorted(korrigiert),
            "corrected_by": {k: sorted(v) for k, v in korrigiert.items()},
            "missing_predecessors": sorted(set(fehlend)),
            # NICHT ADRESSIERBARE UMSCHLAEGE ZAEHLEN GEGEN DIE UNVERSEHRTHEIT. Sie sind keine
            # fehlenden Vorgaenger (die kennt `missing_predecessors`), sondern vorgelegte Belege,
            # die diese Kette nicht platzieren konnte — und solange auch nur einer davon
            # existiert, ist "die Kette ist vollstaendig" eine Behauptung ohne Grundlage.
            "unaddressable": sorted(nicht_adressierbar),
            "integrity_ok": not fehlend and not nicht_adressierbar,
            "note": ("this resolver orders receipts; it verifies no signatures — integrity_ok is "
                     "about the chain being complete, never about cryptographic validity")}


def require_valid_agent_review_predicate(predicate: Any, *, strict: bool = False) -> None:
    errs = validate_agent_review_predicate(predicate, strict=strict)
    if errs:
        raise AgentReviewError("invalid agent-review predicate: " + "; ".join(errs))


# ── Deterministic disclosure renderer (PBF03, PBF12, P0 tests 7 and 22) ─────────────────────────
#: The five lines a maintainer actually reads. They come from the SAME canonical predicate the
#: receipt is signed over, so the visible text and the signed object cannot drift apart without a
#: digest changing. Fixed order, fixed labels — two machines must produce identical bytes.
_HUMAN_LINE_ORDER = ("Involvement", "Review", "Findings", "Assurance", "Limits")


def render_disclosure_block(predicate: dict, *, receipt_digest: str | None = None) -> str:
    """The human-visible block, derived deterministically from the predicate.

    NEVER STRONGER THAN THE MACHINE STATUS (F17, P1 test 28). The `Assurance` line reports the
    weakest rung present, and the `Limits` line reproduces the predicate's own limitations verbatim.
    A reader who only skims the block must not come away with a stronger impression than a verifier
    would report.
    """
    require_valid_agent_review_predicate(predicate)
    dec = predicate["declaration"]
    cov = predicate["coverage"]
    runs = dec.get("reviewRuns") or []
    fnd = dec.get("findings") or []
    by_disp: dict[str, int] = {}
    for f in fnd:
        by_disp[f.get("disposition", "open")] = by_disp.get(f.get("disposition", "open"), 0) + 1
    rungs = {i.get("assurance") for i in (dec.get("authoring") or []) + runs}
    weakest = "selfDeclared"
    for rung in ("selfDeclared", "runnerObserved", "platformAttested", "independentlyWitnessed"):
        if rung in rungs:
            weakest = rung
            break
    authoring = ", ".join(sorted({str(a.get("assertedBy")) for a in (dec.get("authoring") or [])})) or "not stated"
    findings_txt = (", ".join(f"{n} {d}" for d, n in sorted(by_disp.items())) or "none recorded")
    total = dec.get("findingsTotal")
    listed_txt = (f"{len(fnd)} listed of {total} recorded" if isinstance(total, int) and total != len(fnd)
                  else f"{len(fnd)} total")
    lines = {
        "Involvement": authoring,
        "Review": f"{len(runs)} run(s), coverage {cov.get('status', 'UNKNOWN')}",
        "Findings": f"{listed_txt} ({findings_txt})",
        "Assurance": f"{weakest} — not independently witnessed",
        "Limits": "; ".join(predicate.get("limitations") or []),
    }
    body = "\n".join(f"- **{k}:** {lines[k]}" for k in _HUMAN_LINE_ORDER)
    tail = f"\n- **Receipt:** `sha256:{receipt_digest}`" if receipt_digest else ""
    return f"{DISCLOSURE_BEGIN}\n{body}{tail}\n{DISCLOSURE_END}"


def render_disclosure_line(predicate: dict, *, receipt_digest: str, receipt_url: str,
                           leaf_url: str | None = None, leaf_witnessed: bool = False,
                           pruefweg: str | None = None) -> str:
    """The COMPACT form: one line, derived from the same predicate the receipt is signed over.

    WHY DERIVED AND NOT HAND-WRITTEN. A hand-written disclosure line drifts from the receipt without
    any cryptographic error — the visible text and the signed object simply stop agreeing, and the
    signature keeps verifying. The five-line block and this one line therefore come from the same
    place; only the density differs.

    NEVER STRONGER THAN THE VERIFIER. The line names the weakest assurance rung present, and when a
    transparency-log leaf is referenced it states whether that leaf is WITNESSED yet. An entry can be
    in the tree, witnessed, and anchored, and those are three different facts — a line that says
    "notarised" while the witness round is still pending claims the second from the first.
    """
    require_valid_agent_review_predicate(predicate)
    dec = predicate["declaration"]
    rungs = {i.get("assurance") for i in (dec.get("authoring") or []) + (dec.get("reviewRuns") or [])}
    weakest = next((r for r in ("selfDeclared", "runnerObserved", "platformAttested",
                                "independentlyWitnessed") if r in rungs), "selfDeclared")
    fnd, total = dec.get("findings") or [], dec.get("findingsTotal")
    zahl = (f"{len(fnd)} listed of {total} recorded" if isinstance(total, int) and total != len(fnd)
            else f"{len(fnd)}")
    teile = [f"Agent review receipt: [{receipt_digest[:12]}]({receipt_url})",
             f"`sha256:{receipt_digest}`",
             f"{zahl} findings",
             f"assurance {weakest}, not independently witnessed"]
    if leaf_url:
        teile.append(f"[transparency log entry]({leaf_url})"
                     + ("" if leaf_witnessed else ", not yet in a witnessed checkpoint"))
    if pruefweg:
        # DER BEZUGSORT, und warum er nicht "pip install" heisst (Owner-Entscheid 31.08.2026).
        # Eine Zeile, die zum Nachrechnen auffordert, muss sagen WOMIT. Solange das
        # veroeffentlichte Release dieses Predicate nicht traegt, waere `pip install` eine
        # Anleitung, die beim Leser fehlschlaegt — und eine fehlschlagende Anleitung ist schlimmer
        # als keine, weil sie den Beleg als kaputt erscheinen laesst statt als noch nicht
        # ausgeliefert. Der Bezugsort wechselt auf den Paketnamen, sobald ein Release ihn traegt.
        teile.append(pruefweg)
    return "- " + " · ".join(teile)


# ── Emit / verify ───────────────────────────────────────────────────────────────────────────────
def _rfc8785_bytes(obj: Any) -> bytes:
    from . import canonical  # noqa: PLC0415
    try:
        return canonical.canonicalize_statement(obj)
    except canonical.CanonicalizerUnavailable as exc:
        raise AgentReviewError(
            "agent-review receipts need the RFC 8785 (JCS) canonicalizer — install proofbundle[eval]") from exc


def _rfc8785_available() -> bool:
    try:
        import rfc8785  # noqa: F401, PLC0415
        return True
    except Exception:
        return False


def _subject_name(predicate: dict) -> str:
    sc = predicate.get("subjectContext") or {}
    ref = sc.get("humanRef")
    if isinstance(ref, str) and ref:
        return ref
    kind = "github-pr" if sc.get("kind") == "githubPullRequest" else "github-issue"
    node = sc.get("pullRequestNodeId") or sc.get("issueNodeId") or ""
    return f"{kind}:{sc.get('repositoryId', '')}:{node}"


def _subject_digest(predicate: dict) -> str:
    """The digest that BINDS the receipt to the reviewed state.

    Not the whole predicate: the subject must identify the state that was reviewed, so that the same
    receipt copied onto another PR fails the subject check (P0 test 9). It is therefore taken over
    the subjectContext alone, which contains exactly the immutable identifiers.
    """
    return hashlib.sha256(_rfc8785_bytes(predicate["subjectContext"])).hexdigest()


def build_agent_review_statement(predicate: dict, *, subject_name: str | None = None,
                                 subject_sha256: str | None = None,
                                 v02: bool = False) -> dict:
    """Das Statement. `v02` waehlt den v0.2-predicateType UND den strengeren Validator.

    BEIDES ZUSAMMEN, NIE EINZELN. Ein v0.2-Typ mit v0.1-Validierung waere die schlimmste der drei
    Moeglichkeiten: der Leser sieht die staerkere Version im predicateType und bekommt die
    schwaechere Pruefung. Die Version steht deshalb nicht als freier Parameter da, sondern zieht
    ihren Validator mit.
    """
    if v02:
        errs = validate_agent_review_v02_predicate(predicate, strict=True)
        if errs:
            raise AgentReviewError("invalid agent-review/v0.2 predicate: " + "; ".join(errs))
    else:
        require_valid_agent_review_predicate(predicate)
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": subject_name or _subject_name(predicate),
                     "digest": {"sha256": subject_sha256 or _subject_digest(predicate)}}],
        "predicateType": AGENT_REVIEW_PREDICATE_TYPE_V02 if v02 else AGENT_REVIEW_PREDICATE_TYPE,
        "predicate": predicate,
    }


def emit_agent_review(predicate: dict, signer, *, subject_name: str | None = None,
                      subject_sha256: str | None = None, keyid: str | None = None,
                      strict: bool = True, v02: bool = False) -> dict:
    """Sign an agent-review statement. Uses the existing DSSE path — no new crypto."""
    from . import dsse  # noqa: PLC0415
    pruefer = validate_agent_review_v02_predicate if v02 else validate_agent_review_predicate
    errs = pruefer(predicate, strict=strict)
    if errs:
        raise AgentReviewError(
            f"invalid agent-review{'/v0.2' if v02 else ''} predicate: " + "; ".join(errs))
    statement = build_agent_review_statement(predicate, subject_name=subject_name,
                                             subject_sha256=subject_sha256, v02=v02)
    return dsse.sign_envelope(_rfc8785_bytes(statement), signer,
                              payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE, keyid=keyid)


def _pruefe_sichtbaren_block(r: dict, predicate: Any, observed_body: str | None) -> None:
    """Der sichtbare Block gegen das signierte Objekt (P0.2 der Gegenlesung Runde 2).

    DREI ZUSTAENDE, und der haeufigste ist der erste: ohne `observed_body` bleibt hier
    NOT_EVALUATED stehen, nie MATCH. Wer keinen Rumpf uebergibt, hat nicht nachgesehen, und
    "nicht nachgesehen" darf nicht aussehen wie "stimmt". Derselbe Schnitt wie bei
    `subject_expectation`, und aus demselben Grund.

    ABSENT_IN_RECEIPT ist ebenfalls kein Vorwurf: die sechs Receipts, die vor dieser Haertung
    ausgestellt wurden, tragen `disclosureCoreDigest` nicht, zwei davon sind veroeffentlicht und
    eines liegt in einem bezeugten Checkpoint. Das Feld in v0.1 zur Pflicht zu machen wuerde sie
    ungueltig machen — das ist eine Owner-Entscheidung, kein Fix.
    """
    # NOT_MEASURABLE BLOCKT AUF BEIDEN ACHSEN — und der Weg dorthin gehoert hierher, weil meine
    # erste Begruendung falsch war (01.09.2026, beim Nachbau von P0-Test 8).
    #
    # Zuerst blockte nur die BODY-Achse, mit dem Argument: `disclosure_core_digest` sei auch dann
    # nicht messbar, wenn der Rumpf noch gar keinen Block traegt, und das sei der normale Zustand
    # vor dem Rendern. Ein Mutationslauf hat das widerlegt — die Gegenmutation (auch die
    # Disclosure-Achse blocken lassen) machte NICHTS rot, also deckte kein Test das Argument.
    #
    # Nachgesehen: dieser "normale Zustand" landet gar nicht auf NOT_MEASURABLE. Traegt das
    # Receipt kein `disclosureCoreDigest`, ist das Ergebnis ABSENT_IN_RECEIPT und blockt zu Recht
    # nicht. NOT_MEASURABLE entsteht dort AUSSCHLIESSLICH, wenn das Receipt einen Disclosure-Digest
    # BEHAUPTET und der vorgelegte Rumpf keinen Block hat — und das ist kein Normalzustand, sondern
    # ein Widerspruch zwischen Beleg und Gegenstand. Beide Achsen blocken deshalb gleich.
    if observed_body is None:
        return
    ziel = (predicate or {}).get("subjectContext") if isinstance(predicate, dict) else None
    if not isinstance(ziel, dict):
        r["body_core_digest_match"] = "NOT_MEASURABLE"
        r["disclosure_core_digest_match"] = "NOT_MEASURABLE"
        return
    for feld, fn, key in (("bodyCoreDigest", body_core_digest, "body_core_digest_match"),
                          ("disclosureCoreDigest", disclosure_core_digest,
                           "disclosure_core_digest_match")):
        behauptet = ziel.get(feld)
        if not isinstance(behauptet, str):
            r[key] = "ABSENT_IN_RECEIPT"
            continue
        try:
            gemessen = fn(observed_body)
        except AgentReviewError as exc:
            r[key] = "NOT_MEASURABLE"
            r["warnings"].append(f"{feld}: not measurable over the supplied body ({exc})")
            continue
        if gemessen == behauptet:
            r[key] = "MATCH"
        else:
            r[key] = "MISMATCH"
            r["errors"].append(
                f"{feld} mismatch: the receipt binds {behauptet[:16]}... but the body in front of "
                f"you hashes to {gemessen[:16]}... — the visible text is not the text that was "
                f"signed")


def _zielbindung(r: dict, predicate: dict, statement: dict,
                 expected_subject_digest: str | None) -> None:
    """Setzt die ZWEI Achsen der Zielbindung — sie beantworten verschiedene Fragen.

    DER FUND (Gegenlese Runde 2, N04/P0.3, 31.08.2026): `subject_binding_ok` hiess wie eine
    Bindung an das angezeigte Objekt und war ohne extern gesetzte Erwartung nur eine
    Selbstkonsistenz-Pruefung — `derived` und `claimed` stammen BEIDE aus demselben signierten
    `subjectContext`, stimmen also ueberein, solange niemand das Statement von Hand baut. Wer ein
    gueltiges Receipt kopiert und behauptet, es gehoere zu einem anderen PR, aendert am Envelope
    nichts; er luegt daneben. Die Achse stand dabei auf `True`, und ein Verbraucher, der sie liest
    (`automation_summary` tut das), sah ein gruenes Bindungs-Signal fuer eine Bindung, die nicht
    geprueft wurde.

    ZWEI ACHSEN STATT EINER, weil zwei Fragen gestellt sind:

      internal_subject_consistency_ok  — passt der Statement-Digest zum signierten Kontext?
                                         Immer beantwortbar, immer nur INTERNE Konsistenz.
      expected_subject_match           — ist das der Kontext, den der Leser gerade ansieht?
                                         Nur beantwortbar mit unabhaengig erfassten Zielbytes.

    DREI ZUSTAENDE fuer die zweite Achse, nie zwei: `MATCH` · `MISMATCH` · `NOT_EVALUATED`. Der
    dritte ist ausdruecklich KEINE Freigabe — er sagt, dass niemand gefragt hat.

    `subject_binding_ok` BLEIBT als zusammengefuehrte Achse erhalten (Verbraucher lesen sie), aber
    sie ist ab jetzt NUR `True`, wenn beide Fragen positiv beantwortet sind. Ohne Zielkontext ist
    sie `None` — nicht `True` und nicht `False`, denn beides waere eine Aussage, die hier niemand
    treffen kann. Die Richtung ist einseitig: die Aenderung kann ein Ergebnis nur von gruen
    wegnehmen, nie hinzufuegen.

    EIN HELFER, ZWEI AUFRUFER. Die Bindungslogik stand bis hierher zweimal im Modul (v0.1 und
    v0.2). Zwei Kopien sind zwei Wahrheiten, die auseinanderlaufen — die Datei fuehrt dieselbe
    Begruendung schon fuer `_DECLARATION_FIELDS`. Ein Fix, der nur eine Kopie erreicht, ist genau
    der Fehlermodus, gegen den dieser Auftrag gebaut ist."""
    try:
        derived = _subject_digest(predicate)
        subj = (statement.get("subject") or [{}])[0]
        claimed = ((subj.get("digest") or {}).get("sha256") or "")
        intern = derived == claimed
        r["internal_subject_consistency_ok"] = intern
        if not intern:
            r["errors"].append(
                "subject digest does not match the signed subjectContext — this receipt does not "
                "bind the object it names")

        if expected_subject_digest is None:
            r["expected_subject_match"] = "NOT_EVALUATED"
            r["subject_binding_ok"] = False if not intern else None
            r["warnings"].append(
                "no expected_subject_digest was supplied: this run checked only that the receipt "
                "is internally consistent, NOT that it belongs to the object you are looking at. "
                "A valid receipt for a different pull request passes that check.")
            return

        r["subject_expectation"] = "checked"
        if derived != expected_subject_digest:
            r["expected_subject_match"] = "MISMATCH"
            r["subject_binding_ok"] = False
            r["errors"].append(
                f"subjectContext digest {derived[:16]}… is not the expected "
                f"{expected_subject_digest[:16]}… (receipt belongs to a different pull "
                "request or issue)")
            return
        r["expected_subject_match"] = "MATCH"
        r["subject_binding_ok"] = intern
    except (AgentReviewError, KeyError, TypeError, IndexError) as exc:
        r["internal_subject_consistency_ok"] = False
        r["expected_subject_match"] = "NOT_EVALUATED"
        r["subject_binding_ok"] = False
        r["errors"].append(f"subject binding not computable: {exc}")


def _empty_result() -> dict:
    return {"ok": None, "structure_ok": None, "crypto_ok": None, "predicate_type_ok": None,
            "statement_shape_ok": None, "reason_code": None, "reason_codes": [],
            "advisory_codes": [],
            "time_semantics": None, "observed_time_assurance": None,
            "subject_binding_ok": None, "subject_expectation": "not_supplied",
            "internal_subject_consistency_ok": None,
            "expected_subject_match": "NOT_EVALUATED",
            "internal_consistency_ok": None,
            "body_core_digest_match": "NOT_EVALUATED",
            "disclosure_core_digest_match": "NOT_EVALUATED",
            "findings_root_ok": None, "assurance_ok": None,
            "currentness": "CURRENTNESS_UNKNOWN", "automation": None,
            "warnings": [], "errors": []}


def _finalize_failclosed(r: dict) -> dict:
    """DIE DRITTE Automations-Flaeche — und bis zum 02.09.2026 die einzige ohne Nachkorrektur.

    Gemessen von einer adversarialen Linse: das Modul stellt an DREI Stellen eine
    `automation`-Flaeche her (`_verify_agent_review_inner`, `_verify_v02_inner` und hier), aber nur
    zwei riefen `_automation_darf_nicht_nachsichtiger_sein_als_ok`. Der strukturelle Waechter
    verlangte `count >= 2` — eine Schwelle, die die Zahl der Kopien von GESTERN einfriert und
    deshalb gruen meldete, waehrend genau der Fall eintrat, den sie verhindern soll.

    Heute nicht ausnutzbar (alle vier Aufrufstellen setzen vorher `structure_ok = False`, also
    blockt `STRUCTURE_NOT_OK` ohnehin) — aber eine fehlende zweite Verteidigungslinie an einer
    Stelle, die eine Zeile von einem echten Loch entfernt ist.
    """
    from .automation_verdict import automation_summary  # noqa: PLC0415
    r["ok"] = False
    r["automation"] = automation_summary(r, required_checks={
        "crypto": "crypto_ok", "structure": "structure_ok", "policy": None,
        "references": ["internal_subject_consistency_ok", "subject_binding_ok", "findings_root_ok", "assurance_ok"]})
    return r


INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")


class ShapeError(str):
    """A shape error that carries a STABLE machine-readable code alongside its human sentence.

    WHY A ``str`` SUBCLASS AND NOT A TUPLE. Both callers already do
    ``r["errors"].extend(shape_errs)`` and ``not shape_errs``; the result is serialised to JSON and
    read by people. A tuple would have broken every one of those. A ``str`` subclass keeps each of
    them working byte-for-byte while adding ``.code`` for machines — the reason code is an ADDITION
    to the evidence, never a replacement for the sentence.

    WHY CODES AT ALL (Gegenlese Runde 2, acceptance criterion for P0.1, 2026-08-31): *"Falsches
    ``_type``, String Subject, String Declaration, leere oder mehrfache Subjects und falsche
    Digestformen ergeben stabile Reason Codes."* Before this, ``verify_agent_review`` returned
    ``ok=False`` with a good sentence and an EMPTY ``reason_codes`` — a consumer could see THAT it
    failed but had nothing stable to branch on, and a reworded sentence would silently break any
    consumer that matched on the text.

    The code is deliberately part of the raising site, not derived from the message: a mapping from
    text to code is a change-detector on the wording, which is the defect one layer over.
    """

    code: str
    __slots__ = ("code",)

    def __new__(cls, code: str, message: str) -> "ShapeError":
        selbst = super().__new__(cls, message)
        selbst.code = code
        return selbst

    def __getnewargs__(self) -> tuple[str, str]:  # type: ignore[override]
        # THE OVERRIDE WIDENS ON PURPOSE, and mypy is right to say so: ``str`` promises
        # ``tuple[str]``, we return two. That is the whole point — ``__new__`` here takes
        # (code, message), so a one-element tuple cannot rebuild the object. The ignore is
        # narrow (this line, this rule) and documented rather than blanket: a bare
        # ``# type: ignore`` would also swallow the next, real error on this line.
        """Both arguments, so copy/deepcopy/pickle can rebuild this.

        WITHOUT THIS, THE REJECTION PATH THROWS — and only the rejection path. ``str`` supplies a
        one-argument ``__getnewargs__``; ``__new__`` here takes two, so ``copy.deepcopy(result)``
        raised ``TypeError: ShapeError.__new__() missing 1 required positional argument``. A valid
        receipt carries no ShapeError and copies fine, so every happy-path test stayed green while
        every consumer that logs, copies or hands off a REJECTED result broke. For a public
        library that is the worst possible distribution of a defect: invisible where it is tested,
        live where it is used.

        Measured by adversarial review on 2026-09-01, not by us.
        """
        return (self.code, str(self))


def _shape_err(code: str, message: str) -> ShapeError:
    return ShapeError(code, message)


#: DREI LAGEN, DIE EINE MELDUNG UNTERSCHEIDEN MUSS — und die Nennung des Typs gehoert nur in eine.
#:
#: GEMESSEN von einer adversarialen Linse am 02.09.2026: `digest` FEHLT und `digest = null` ergaben
#: beide "must be an object, got NoneType". Fuer den zweiten Fall stimmt das; fuer den ersten nennt
#: die Meldung den Typ eines Wertes, DEN ES NICHT GIBT. Dieselbe Kollaps-Klasse an drei weiteren
#: Stellen (`_type`, `subject`, `subject[0].name`). Das Modul fuehrt ABSENT sonst ueberall als
#: eigenen Zustand (`ABSENT_IN_RECEIPT` gegen `NOT_MEASURABLE`); die Formpruefung folgte der
#: eigenen Hausregel nicht.
#:
#: EINE Stelle, nicht fuenf: eine Regel, die an fuenf Orten wiederholt wird, driftet am sechsten.
def _feldlage(behaelter: object, schluessel: str) -> str:
    """`absent` (Schluessel fehlt) · `null` (da, aber None) · `vorhanden`.

    NICHT-MAPPINGS WERFEN, statt „absent" zu antworten. Gemessen von einer adversarialen Linse am
    02.09.2026: `_feldlage('nur ein String', 'k')` lieferte `'absent'` und
    `_feldlage(['a','b'], 'k')` ebenso — „der Schluessel fehlt" ist fuer einen Behaelter, der gar
    keine Schluessel haben KANN, die falsche der drei Antworten, und sie liest sich wie eine
    Messung. `int`/`None` warfen dagegen `TypeError`, also war das Verhalten zusaetzlich
    uneinheitlich. Alle vier heutigen Aufrufstellen garantieren ein `dict`; der Riegel steht fuer
    die fuenfte.
    """
    if not isinstance(behaelter, dict):
        raise TypeError(f"_feldlage erwartet ein dict, bekam {type(behaelter).__name__} — "
                        f"'absent' waere hier eine Antwort ueber einen Behaelter, der keine "
                        f"Schluessel haben kann")
    if schluessel not in behaelter:
        return "absent"
    return "null" if behaelter[schluessel] is None else "vorhanden"


def _lagen_satz(pfad: str, lage: str, wert: object, erwartet: str) -> str:
    """Ein Satz, der die LAGE beschreibt statt einen Typ zu erfinden."""
    if lage == "absent":
        return f"{pfad} is missing — it must be {erwartet}"
    if lage == "null":
        return f"{pfad} is null — it must be {erwartet}"
    if lage != "vorhanden":
        # DER HELFER VERTEIDIGT SEINE EIGENE INVARIANTE. Ohne diesen Zweig fiel jede unbekannte
        # Lage (`"abesnt"`, `"ABSENT"`, `""`, `None`) auf den Satz zurueck, der einen Typ fuer
        # einen moeglicherweise nicht existierenden Wert nennt — also genau in den Defekt, gegen
        # den er gebaut ist. Gemessen von einer adversarialen Linse am 02.09.2026; heute nicht
        # erreichbar, weil `_feldlage` nur drei Werte liefert, aber der Kommentar darueber warnt
        # selbst vor Drift „am sechsten Ort".
        raise ValueError(f"unbekannte Feldlage {lage!r} fuer {pfad} — erlaubt sind "
                         f"'absent', 'null', 'vorhanden'")
    return f"{pfad} must be {erwartet}, got {type(wert).__name__}"


def validate_statement_shape(statement: object, predicate: object) -> list[ShapeError]:
    """Type the whole in-toto Statement BEFORE any semantics are computed (P0.1, P0.3).

    WHY THIS EXISTS, measured on 2026-08-31 against our own r2 receipt. With a valid signature AND
    the correct expected subject digest, the verifier accepted a statement with a wrong ``_type``,
    with TWO subjects, and with a subject name pointing at a foreign repository — ``ok=True`` in all
    three cases. The subject array is the binding statement layer in the in-toto spec; leaving it
    unchecked means a signature authenticates bytes whose shape nobody agreed on.

    THE MEASUREMENT THAT NEARLY WENT WRONG, recorded because it is the reusable part: without an
    expected digest those same three mutations came back ``ok=False``, and that looked like the
    checks already existed. They did not. The red came from a different axis entirely — the missing
    target comparison. A verdict is not a reason; only reading the reason showed which was which.

    Returns a list of errors. Empty means the statement is shaped as this profile requires.
    """
    errs: list[ShapeError] = []
    if not isinstance(statement, dict):
        return [_shape_err("STATEMENT_NOT_OBJECT",
                           f"statement must be a JSON object, got {type(statement).__name__}")]

    t = statement.get("_type")
    if t != INTOTO_STATEMENT_TYPE:
        lage = _feldlage(statement, "_type")
        if lage == "absent":
            errs.append(_shape_err(
                "STATEMENT_TYPE_ABSENT",
                "_type is missing — the in-toto spec requires it, and a statement without one "
                "has no agreed shape at all (this is not the same as carrying the wrong one)"))
        else:
            errs.append(_shape_err(
                "STATEMENT_TYPE_MISMATCH",
                f"_type is {t!r}, expected {INTOTO_STATEMENT_TYPE!r} "
                "(the in-toto spec requires it; an unread _type is an unagreed shape)"))

    subj = statement.get("subject")
    if not isinstance(subj, list):
        lage = _feldlage(statement, "subject")
        errs.append(_shape_err(
            "SUBJECT_ABSENT_FIELD" if lage == "absent" else "SUBJECT_NOT_ARRAY",
            _lagen_satz("subject", lage, subj,
                        "an array (the subject array is the binding statement layer)")))
        return errs
    if len(subj) != 1:
        # ZWEI LAGEN, ZWEI CODES — dieselbe Klasse wie beim digest eine Ebene tiefer, und hier war
        # der Satz genauso aktiv falsch: fuer `got 0` gab er "more than one leaves it open which
        # object the receipt speaks about" aus. Null ist nicht mehr als eins. Ein Receipt ohne
        # Subjekt spricht ueber NICHTS; eines mit mehreren laesst offen, ueber WELCHES. Das sind
        # verschiedene Defekte mit verschiedenen Ursachen (kaputtes Statement gegen
        # Verwechslungsangriff), und ein Verbraucher muss sie trennen koennen.
        if not subj:
            errs.append(_shape_err(
                "SUBJECT_ABSENT",
                "the subject array is empty — the receipt binds no object at all, so there is "
                "nothing a verifier could hold the signature against"))
        else:
            errs.append(_shape_err(
                "SUBJECT_CARDINALITY",
                f"this profile binds exactly one subject, got {len(subj)} "
                "(more than one leaves it open which object the receipt speaks about)"))
        return errs
    s0 = subj[0]
    if not isinstance(s0, dict):
        errs.append(_shape_err(
            "SUBJECT_ENTRY_NOT_OBJECT",
            f"subject[0] must be an object, got {type(s0).__name__}"))
        return errs

    dig = s0.get("digest")
    if not isinstance(dig, dict):
        lage = _feldlage(s0, "digest")
        errs.append(_shape_err(
            "SUBJECT_DIGEST_ABSENT" if lage == "absent" else "SUBJECT_DIGEST_NOT_OBJECT",
            _lagen_satz("subject[0].digest", lage, dig,
                        "an object (it is what binds the receipt to the reviewed object)")))
    elif set(dig) != {"sha256"}:
        # DREI ZUSTAENDE, DREI CODES — und jeder Satz beschreibt seinen eigenen Fall.
        #
        # ZWEIMAL AN EINEM TAG DIESELBE KLASSE. Erst deckte EIN Code (`SUBJECT_DIGEST_ALGORITHMS`)
        # "gar kein Digest" und "zu viele" ab, mit einem Satz, der nur den zweiten Fall erklaerte —
        # gemessen gab er fuer `digest={}` woertlich "got [] (an extra algorithm ...)" aus. Der Fix
        # dagegen teilte in fehlend/ueberzaehlig — und liess dabei WIEDER einen Code ueber zwei
        # Zustaende stehen: `digest={}` und `digest={sha512}` bekamen beide "carries no sha256".
        # Das sind verschiedene Lagen, und die zweite ist die gefaehrlichere: dort ist das Subjekt
        # SEHR WOHL gebunden, nur an etwas, das dieser Verifier nicht liest. Gefunden von der
        # Pflicht-Gegenlesung, nicht von mir.
        #
        # Die Vorfassung deckte beides mit EINEM Code und EINEM Satz. Eine adversariale
        # Gegenlesung hat am 02.09.2026 die Ausgabe fuer `digest={}` gemessen:
        #
        #     subject[0].digest must carry exactly sha256, got []
        #     (an extra algorithm lets a producer choose which one a verifier reads)
        #
        # Es gibt keinen "extra algorithm". Ein Verbraucher konnte "Digest fehlt" nicht von
        # "Digest hat zu viele" unterscheiden, und der Satz erklaerte ihm den falschen Fall —
        # zwei entgegengesetzte Zustaende unter einem Namen.
        if not dig:
            errs.append(_shape_err(
                "SUBJECT_DIGEST_EMPTY",
                "subject[0].digest is an empty object — the subject is bound to nothing at all"))
        elif "sha256" not in dig:
            errs.append(_shape_err(
                "SUBJECT_DIGEST_SHA256_ABSENT",
                f"subject[0].digest carries {sorted(dig)} but no sha256 — the subject is bound "
                "by an algorithm this verifier does not read, which is not the same as being "
                "unbound: a producer can point the two at different objects"))
        else:
            errs.append(_shape_err(
                "SUBJECT_DIGEST_EXTRA_ALGORITHMS",
                f"subject[0].digest must carry exactly sha256, got {sorted(dig)} "
                "(an extra algorithm lets a producer choose which one a verifier reads)"))
    elif not (isinstance(dig["sha256"], str) and _HEX64.match(dig["sha256"])):
        errs.append(_shape_err(
            "SUBJECT_DIGEST_FORM",
            "subject[0].digest.sha256 must be 64 lowercase hex characters"))

    name = s0.get("name")
    if not (isinstance(name, str) and name):
        # VIER LAGEN, VIER ANTWORTEN. Die Vorfassung nannte alle `SUBJECT_NAME_EMPTY` — auch
        # `name = 42`, und 42 ist nicht leer, so wenig wie 0 mehr als 1 ist. Gemessen von einer
        # adversarialen Linse am 02.09.2026 als Befund C-3; dieselbe Funktion trennte fuer
        # `subject` und `digest` bereits, fuer `name` nicht.
        lage = _feldlage(s0, "name")
        if lage == "absent":
            errs.append(_shape_err(
                "SUBJECT_NAME_ABSENT",
                "subject[0].name is missing — it must be a non-empty string naming the object "
                "this receipt speaks about"))
        elif lage == "null":
            errs.append(_shape_err(
                "SUBJECT_NAME_NULL",
                "subject[0].name is null — it must be a non-empty string naming the object "
                "this receipt speaks about"))
        elif not isinstance(name, str):
            errs.append(_shape_err(
                "SUBJECT_NAME_NOT_STRING",
                f"subject[0].name must be a string, got {type(name).__name__} — a non-string "
                "name cannot be compared against the one derived from the signed subjectContext"))
        else:
            errs.append(_shape_err(
                "SUBJECT_NAME_EMPTY",
                "subject[0].name is the empty string — it must name the object this receipt "
                "speaks about"))
    elif isinstance(predicate, dict):
        # The name is DERIVED from the signed subjectContext. A name that disagrees with it points
        # the reader at a different object than the signature covers.
        # ZUERST: KANN ueberhaupt ein Name abgeleitet werden?
        #
        # `_subject_name` faellt auf `{}` zurueck (`predicate.get("subjectContext") or {}`) und
        # liefert dann `github-issue::` — einen Wert, den nichts im Receipt traegt. Gemessen von
        # einer adversarialen Linse am 02.09.2026 (Befund C-1): fehlte der `subjectContext` ganz,
        # meldete diese Stelle "the signed subjectContext derives 'github-issue::'", obwohl es
        # keinen gab; fehlte nur `kind`, sagte sie dem Leser, das signierte Objekt sei ein ISSUE,
        # waehrend nichts im Receipt das sagt. Vier Lagen unter einem Code, und fuer drei davon
        # ERFAND die Meldung ihren Vergleichswert.
        #
        # Ein abgeleiteter Name ist nur dann eine Aussage ueber das signierte Objekt, wenn der
        # subjectContext die Felder TRAEGT, aus denen er abgeleitet wird. Sonst ist die richtige
        # Antwort "hier laesst sich nichts vergleichen" — nicht ein erfundener Vergleich.
        sc = predicate.get("subjectContext") if isinstance(predicate, dict) else None
        _hat_ref = isinstance(sc, dict) and isinstance(sc.get("humanRef"), str) and sc["humanRef"]
        # `repositoryId` GEHOERT DAZU, und sein Fehlen war die naechste Auspraegung derselben Klasse.
        #
        # Die erste Fassung dieser Vorpruefung deckte VIER der FUENF Felder ab, aus denen
        # `_subject_name` ableitet. Eine adversariale Linse hat am 02.09.2026 gemessen, was das
        # kostet: fehlt `repositoryId`, meldet der Vergleich weiterhin „the signed subjectContext
        # derives 'github-pr::PR_kw1'" — byte-genau die Signatur des Defekts, den diese Aenderung
        # schliesst, nur ein Feld weiter. Bei `repositoryId: null` steht sogar ein Python-`None`
        # im erwarteten Namen.
        #
        # Das Kriterium ist mechanisch und wird von einem Test gehalten:
        # `felder(_subject_name) - felder(_ableitbar) == set()`. Wer `_subject_name` um ein Feld
        # erweitert, ohne es hier aufzunehmen, faellt dort.
        _ableitbar = bool(_hat_ref) or (
            isinstance(sc, dict) and sc.get("kind") in ("githubPullRequest", "githubIssue")
            and sc.get("repositoryId")
            and (sc.get("pullRequestNodeId") or sc.get("issueNodeId")))
        if not _ableitbar:
            errs.append(_shape_err(
                "SUBJECT_NAME_UNDERIVABLE",
                "subject[0].name cannot be checked: the predicate carries no subjectContext with "
                "a usable kind and node id, so there is nothing to derive an expected name from. "
                "This is NOT a disagreement about the name — it is a receipt that does not say "
                "what object it speaks about."))
        else:
            try:
                erwartet = _subject_name(predicate)
            except Exception:                                    # noqa: BLE001
                erwartet = None
            if erwartet is not None and name != erwartet:
                errs.append(_shape_err(
                    "SUBJECT_NAME_DISAGREES",
                    f"subject[0].name is {name!r} but the signed subjectContext derives "
                    f"{erwartet!r} — the visible name and the signed object disagree"))

    for k in statement:
        if k not in ("_type", "subject", "predicateType", "predicate"):
            errs.append(_shape_err(
                "UNKNOWN_STATEMENT_FIELD",
                f"unknown statement field {k!r} — this profile allows no extras"))
    return errs


# ── agent-review/v0.2 · Zeitaussagen nach Quelle und Assurance getrennt ────────────────────────
#
# WARUM ES DIESE VERSION GIBT (Owner-Entscheid 31.08.2026). Das `times`-Objekt von v0.1 mischt vier
# Aussagen VERSCHIEDENER AUTORITAET in einer flachen Struktur: eine vom Produzenten deklarierte
# Zeit, eine behauptete Beobachtungszeit, eine behauptete Signaturzeit und eine extern verankerte.
# Das widerspricht der eigenen Dreiteilung aus `declaration`, `observations` und `policy` — Zeiten
# muessen denselben Schichten folgen wie jede andere Aussage.
#
# DER KONKRETE ANLASS war messbar: drei Receipts desselben Tages trugen im selben Feld `observedAt`
# drei verschiedene Bedeutungen — die Reviewzeit (15:45Z), den Erzeugungszeitpunkt (19:59Z) und
# nichts (null). Kein Leser kann daraus ableiten, was gemeint war.
#
# WAS v0.2 AENDERT, in einem Satz: ein vom Agenten gesetzter Wert wird nicht dadurch BEOBACHTET,
# dass das Feld `observedAt` heisst. Beobachtung beginnt bei einem getrennt benannten Beobachter,
# externe Zeit bei ueberpruefbarer Ankerevidenz.
AGENT_REVIEW_PREDICATE_TYPE_V02 = "https://b7n0de.com/proofbundle/predicates/agent-review/v0.2"

_TIME_CLAIM_KINDS = {"reviewCompleted", "receiptCreated", "reviewStarted", "evidenceCollected"}
_TIME_ASSURANCE = {"selfDeclared", "runnerObserved", "platformAttested", "independentlyWitnessed"}
_V02_ASSURANCE_ALLOWED_FOR_CLAIMS = {"selfDeclared"}
# Die sieben Zustaende je Zeitachse. NOT_EVALUATED ist ausdruecklich KEINE Freigabe, CONFLICT
# ausdruecklich kein Fehler des Lesers — beides sind Befunde, die genannt und nicht geglaettet werden.
TIME_AXIS_STATES = ("ABSENT", "SELF_DECLARED", "RUNNER_OBSERVED", "PLATFORM_ATTESTED",
                    "EXTERNALLY_ANCHORED", "CONFLICT", "NOT_EVALUATED")


def validate_time_claim(tc: object) -> list[str]:
    """Eine fachliche Zeitaussage traegt IMMER ihre Quelle und ihre Assurance."""
    errs: list[str] = []
    if not isinstance(tc, dict):
        return [f"timeClaim must be an object, got {type(tc).__name__}"]
    for k in tc:
        if k not in ("kind", "value", "assertedBy", "assurance", "evidenceRef"):
            errs.append(f"unknown timeClaim field {k!r}")
    for req in ("kind", "value", "assertedBy", "assurance"):
        if req not in tc:
            errs.append(f"timeClaim is missing {req!r} — a time without a source is not a claim, "
                        "it is a number")
    if "kind" in tc and not is_member(tc.get("kind"), _TIME_CLAIM_KINDS):
        errs.append(f"timeClaim.kind must be one of {sorted(_TIME_CLAIM_KINDS)}")
    if "assurance" in tc and not is_member(tc.get("assurance"), _TIME_ASSURANCE):
        errs.append(f"timeClaim.assurance must be one of {sorted(_TIME_ASSURANCE)}")
    # DIE TRAGENDE REGEL: eine DEKLARIERTE Zeit kann nicht mehr als selbst deklariert sein. Wer
    # eine hoehere Sprosse behauptet, meint eine Beobachtung — und die gehoert in `observations`,
    # mit Beobachter-Identitaet und Beleg.
    if tc.get("assurance") in (_TIME_ASSURANCE - _V02_ASSURANCE_ALLOWED_FOR_CLAIMS):
        errs.append(f"timeClaim.assurance {tc.get('assurance')!r} claims more than a declaration "
                    "can carry — a time above selfDeclared belongs in observations, with a named "
                    "observer and its own evidence")
    if "value" in tc and not (isinstance(tc["value"], str) and tc["value"]):
        errs.append("timeClaim.value must be a non-empty string")
    if "assertedBy" in tc and not (isinstance(tc["assertedBy"], str) and tc["assertedBy"]):
        errs.append("timeClaim.assertedBy must be a non-empty string")
    if "evidenceRef" in tc and tc["evidenceRef"] is not None and not _is_digest(tc["evidenceRef"]):
        errs.append("timeClaim.evidenceRef must be a sha256 digest object or null")
    return errs


def validate_agent_review_v02_predicate(predicate: object, *, strict: bool = False) -> list[str]:
    """v0.2 zusaetzlich zu allem, was v0.1 schon verlangt.

    Der Kern in drei Saetzen: fachliche Zeiten stehen unter `declaration.timeClaims`. `observedAt`
    ist in einem reinen Tier-1-Predicate UNZULAESSIG — es ist einer getrennten Observation
    vorbehalten. Und eine Observation ohne benannten Beobachter ist keine.
    """
    errs = validate_agent_review_predicate(predicate, strict=strict,
                                          decl_zusatz=_DECLARATION_FIELDS_V02)
    if not isinstance(predicate, dict):
        return errs
    zeiten = predicate.get("times")
    if isinstance(zeiten, dict) and zeiten.get("observedAt") is not None:
        beob = predicate.get("observations")
        if not (isinstance(beob, list) and beob):
            errs.append(
                "v0.2: times.observedAt is set on a Tier 1 predicate — an observation time needs a "
                "separately named observer with its own evidence, not a producer-supplied value. "
                "Record the business time as declaration.timeClaims[kind=reviewCompleted] instead")
    # disclosureCoreDigest ist in v0.2 PFLICHT (P0.2 der Gegenlesung Runde 2).
    #
    # WARUM HIER UND NICHT IN v0.1. Sechs bereits ausgestellte v0.1-Receipts tragen das Feld nicht,
    # zwei davon sind veroeffentlicht und eines liegt in einem bezeugten Checkpoint. Es dort
    # nachtraeglich zu verlangen wuerde sie ungueltig machen — eine Schnittstelle brechen, statt
    # sie zu haerten. v0.2 ist noch nicht ausgestellt worden, hier kostet die Pflicht nichts und
    # traegt alles: ohne sie ist der sichtbare Block in einem v0.2-Receipt unverbindlich, und
    # genau das war der Befund.
    sc = predicate.get("subjectContext")
    if isinstance(sc, dict) and not isinstance(sc.get("disclosureCoreDigest"), str):
        errs.append(
            "v0.2: subjectContext.disclosureCoreDigest is required — without it the visible "
            "disclosure block is unbound, and an edit from 'selfDeclared' to "
            "'independentlyWitnessed' would leave every digest unchanged")

    # limitationCodes sind in v0.2 PFLICHT (P0.4.6) — aus demselben Grund wie
    # disclosureCoreDigest, und mit derselben Ruecksicht auf v0.1.
    if not isinstance(predicate.get("limitationCodes"), list):
        errs.append(
            "v0.2: limitationCodes is required — a free-text limitation cannot be held against a "
            "policy without being read, and what a relying party cannot evaluate it does not "
            "evaluate (use derive_limitation_codes)")

    dec = predicate.get("declaration")
    if isinstance(dec, dict) and "timeClaims" in dec:
        tcs = dec.get("timeClaims")
        if not isinstance(tcs, list):
            errs.append(f"declaration.timeClaims must be an array, got {type(tcs).__name__}")
        else:
            for i, tc in enumerate(tcs):
                errs.extend(f"timeClaims[{i}]: {e}" for e in validate_time_claim(tc))
    return errs


def _als_zeitpunkt(wert: object) -> float | None:
    """RFC 3339 zu einem vergleichbaren Zeitpunkt — oder None, wenn nicht bestimmbar.

    WARUM NICHT DIE ZEICHENKETTEN VERGLEICHEN (Jury-Linse 2, 01.09.2026). Ein lexikografischer
    Vergleich stimmt nur, solange alle Werte denselben Offset tragen. Konkret vorgelegt und
    nachgemessen: `2026-08-31T15:00:00+02:00` ist 13:00 UTC und liegt damit VOR
    `2026-08-31T14:00:00Z` — als Zeichenkette ist es groesser, und der Widerspruchs-Test
    schwieg.

    HEUTE NICHT AUSLOESBAR, und das ist genau der Grund, es JETZT zu reparieren: die Validierung
    verweigert nicht-leere `observations` noch vollstaendig, ein solcher Wert kommt also nicht
    durch. Er kommt durch, sobald Tier 2 die Beobachtungen oeffnet — und dann repariert das
    niemand mehr, weil dann alles andere dringend ist.

    None heisst NICHT BESTIMMBAR und nie "gleich": ein unparsbarer Wert darf keinen Widerspruch
    behaupten und ihn auch nicht ausschliessen.
    """
    if not isinstance(wert, str) or not wert:
        return None
    from datetime import datetime  # noqa: PLC0415
    roh = wert[:-1] + "+00:00" if wert.endswith("Z") else wert
    try:
        dt = datetime.fromisoformat(roh)
    except ValueError:
        return None
    if dt.tzinfo is None:
        # Ohne Zone ist der Zeitpunkt nicht bestimmt. Ihn als UTC zu lesen waere eine Annahme,
        # und eine Annahme ueber eine Zeit ist genau das, was dieses Modul nicht tut.
        return None
    return dt.timestamp()


def _zeitachsen(predicate: dict) -> dict:
    """Die getrennten Achsen. KEIN Gesamturteil ueber Zeit — das ist der ganze Punkt.

    Jede Achse sagt, WORAUS ihr Wert stammt, nicht ob er stimmt. Eine relying party entscheidet
    danach, welche Quelle ihrer Policy genuegt; der Verifier entscheidet das nicht fuer sie.
    """
    # EXPLIZITE VERENGUNG statt eines Ternaers: mypy kann `x if isinstance(x, dict) else {}` nicht
    # narrowen, weil `dict.get` Optional[Any] liefert. Ein type:ignore haette die Pruefung
    # stillgelegt statt sie zu erfuellen — und genau diese Stellen sind die, an denen heute rohe
    # AttributeError aus dem Verifier fielen.
    _d = predicate.get("declaration")
    dec: dict = _d if isinstance(_d, dict) else {}
    _t = dec.get("timeClaims")
    tcs: list = _t if isinstance(_t, list) else []
    _b = predicate.get("observations")
    beob: list = _b if isinstance(_b, list) else []
    _z = predicate.get("times")
    zeiten: dict = _z if isinstance(_z, dict) else {}

    fach = [tc for tc in tcs if isinstance(tc, dict) and tc.get("kind") == "reviewCompleted"]
    event = "ABSENT" if not fach else (
        "CONFLICT" if len({tc.get("value") for tc in fach}) > 1 else "SELF_DECLARED")

    obs = "ABSENT"
    mit_id: list = []
    if beob:
        mit_id = [b for b in beob if isinstance(b, dict)
                  and isinstance(b.get("observer"), dict) and b["observer"].get("id")]
        # Eine Beobachtung ohne benannten Beobachter hebt nichts an — sie bleibt Selbstauskunft
        # (Policytest 13). Eine Identitaet, die niemand nachschlagen kann, ist keine.
        obs = "RUNNER_OBSERVED" if mit_id else "SELF_DECLARED"
    elif zeiten.get("observedAt") is not None:
        obs = "SELF_DECLARED"

    # WIDERSPRUCH ZWISCHEN DEKLARIERTER EREIGNISZEIT UND BEOBACHTUNG (Policytest 14).
    #
    # Ein Zeuge kann nicht beobachten, was noch nicht geschehen ist. Liegt die Beobachtung eines
    # BENANNTEN Beobachters VOR der deklarierten Ereigniszeit, widersprechen sich beide Aussagen
    # unzulaessig — und dann ist der richtige Zustand CONFLICT, nicht "die staerkere gewinnt".
    # Eine Rangfolge waere hier der Fehler: sie wuerde einen kaputten Beleg in einen schwachen
    # verwandeln, und ein schwacher Beleg wird benutzt.
    if event == "SELF_DECLARED" and mit_id:
        ereignis = _als_zeitpunkt(
            next((tc.get("value") for tc in fach if isinstance(tc.get("value"), str)), None))
        beobachtet = [t for t in (_als_zeitpunkt(b.get("observedAt")) for b in mit_id)
                      if t is not None]
        if ereignis is not None and any(bo < ereignis for bo in beobachtet):
            event = "CONFLICT"
            obs = "CONFLICT"

    sig = "SELF_DECLARED" if zeiten.get("signedAt") else "ABSENT"
    # externalTime wird NIE aus einem Payloadfeld gesetzt. Ohne geprueften Anker heisst es
    # NOT_EVALUATED — nicht ABSENT, denn wir haben nicht nachgesehen, ob es einen gibt.
    ext = "NOT_EVALUATED"
    return {"event_time_status": event, "observation_time_status": obs,
            "signature_time_status": sig, "external_time_status": ext}


#: Was eine Policy verlangen kann, und welche ACHSE sie dafuer ansieht. Die Zuordnung ist der
#: eigentliche Inhalt der Policytests 9 bis 12: eine Frische-Policy fragt die EREIGNIS-Achse, eine
#: TTL-Policy die SIGNATUR-Achse. Wer sie verwechselt, laesst einen RFC-3161-Zeitstempel eine
#: fachliche Reviewzeit belegen — und das tut er nicht, er belegt nur, dass das Receipt existierte.
_POLICY_ACHSE = {"freshness": "event_time_status", "ttl": "signature_time_status",
                 "certificate_validity": "signature_time_status",
                 "currentness": "observation_time_status",
                 "existence": "external_time_status"}

#: Stufen, die eine Policy als BELEG gelten laesst. `SELF_DECLARED` steht bewusst NICHT darin:
#: eine Selbstauskunft ueber die eigene Zeit ist genau die Aussage, die eine Zeitpolicy pruefen
#: soll, und sie kann sich nicht selbst erfuellen.
_POLICY_GENUEGT = frozenset(("RUNNER_OBSERVED", "PLATFORM_ATTESTED", "EXTERNALLY_ANCHORED"))


def evaluate_time_policy(axes: dict, policy: dict) -> dict:
    """Die Entscheidung einer RELYING PARTY, nicht des Verifiers (Policytests 9 bis 14).

    WARUM SIE GETRENNT IST. Der Verifier meldet, WORAUS ein Zeitwert stammt; er entscheidet nicht,
    ob das jemandem genuegt. Diese Funktion entscheidet — aber nur, wenn ihr jemand eine BENANNTE
    Policy uebergibt. Ohne Policy gibt es keine Zeitfreigabe, und ein Verifier, der eine erfindet,
    nimmt dem Leser die Entscheidung ab, die ihm gehoert.

    DREI ERGEBNISSE, nie zwei: `accept` · `reject` · `insufficient_evidence`. Der dritte ist der
    haeufigste und der wichtigste — er heisst "die Achse traegt deine Anforderung nicht", nicht
    "das Receipt ist schlecht".

    CONFLICT wird IMMER zu `reject`, egal was die Policy verlangt: zwei einander widersprechende
    Zeitaussagen sind kein schwacher Beleg, sondern ein kaputter.
    """
    art = policy.get("kind") if isinstance(policy, dict) else None
    # EXPLIZITE VERENGUNG statt eines type:ignore — dieselbe Hausregel wie in `_zeitachsen`.
    # `is_member` schuetzt gegen unhashbare Eingaben, es verengt aber keinen Typ; der
    # isinstance-Test daneben tut beides sichtbar.
    if not isinstance(art, str) or not is_member(art, _POLICY_ACHSE):
        return {"decision": "insufficient_evidence", "policy_kind": art,
                "reason": f"unknown policy kind {art!r} — allowed: {sorted(_POLICY_ACHSE)}"}
    achse = _POLICY_ACHSE[art]
    zustand = axes.get(achse, "NOT_EVALUATED")
    if zustand == "CONFLICT":
        return {"decision": "reject", "policy_kind": art, "axis": achse, "axis_state": zustand,
                "reason": "the axis reports CONFLICT — two time statements contradict each other, "
                          "which is a broken claim, not a weak one"}
    if is_member(zustand, _POLICY_GENUEGT):
        return {"decision": "accept", "policy_kind": art, "axis": achse, "axis_state": zustand,
                "reason": f"{achse} is {zustand}, which comes from a named source outside the "
                          f"producer"}
    return {"decision": "insufficient_evidence", "policy_kind": art, "axis": achse,
            "axis_state": zustand,
            "reason": (f"{achse} is {zustand} — a producer's own statement about its own time "
                       f"cannot satisfy a {art} policy, because that is precisely the statement "
                       f"the policy exists to check")}


def apply_time_evidence(axes: dict, evidence: dict) -> dict:
    """Geprüfte externe Zeitevidenz auf die Achsen anwenden — und NUR auf die richtige.

    DIE GRENZE IST DER GANZE PUNKT (Policytests 11 und 12). Ein RFC-3161-Zeitstempel und ein
    OpenTimestamps-Beleg sagen beide dasselbe: dieses Byte-Objekt existierte vor diesem Zeitpunkt.
    Sie sagen NICHTS darueber, wann ein Mensch oder ein Agent den Review tatsaechlich durchgefuehrt
    hat. Deshalb heben sie die SIGNATUR- und EXISTENZ-Achse an und lassen die EREIGNIS-Achse
    unberuehrt — auch dann, wenn das im Einzelfall unbequem ist.

    `verified` MUSS ausdruecklich True sein. Eine mitgelieferte, ungepruefte Evidenz hebt nichts
    an; sonst waere die Anhebung eine Behauptung der Gegenseite.
    """
    aus = dict(axes)
    if not isinstance(evidence, dict) or evidence.get("verified") is not True:
        return aus
    art = evidence.get("kind")
    if art == "rfc3161":
        aus["signature_time_status"] = "PLATFORM_ATTESTED"
        aus["external_time_status"] = "EXTERNALLY_ANCHORED"
    elif art == "opentimestamps":
        # OTS belegt eine EXISTENZGRENZE, keine Signaturzeit eines benannten Dienstes.
        aus["external_time_status"] = "EXTERNALLY_ANCHORED"
    else:
        return aus
    return aus


# `_automation_darf_nicht_nachsichtiger_sein_als_ok` IST WEG — die Invariante lebt jetzt IN
# `automation_verdict.automation_summary`.
#
# Sie war ein separater Aufruf, den jede Flaeche selbst machen musste. Ein adversariales Tiefen-Gate
# hat am 02.09.2026 gemessen, was das kostet: eine vierte Flaeche mit `automation_verdict.
# automation_summary(...)` statt `automation_summary(...)` lieferte `ok=False, safe=True,
# blockers=[]` bei 89 gruenen Tests. Der Waechter dagegen pruefte die SCHREIBWEISE des Aufrufs.
#
# Der Klassen-Fix ist nicht ein besserer Waechter, sondern eine Stelle, an der man es nicht mehr
# vergessen KANN. Gemessen mit entfernten separaten Aufrufen: 0 Verstoesse bei 14 echten Aufrufstellen (hier stand '18' — das waren grep-Treffer inklusive drei Kommentarzeilen und einer def-Zeile; gemessen wurde ein VORKOMMEN statt einer EIGENSCHAFT).

def verify_agent_review(envelope: dict, public_key: bytes, *, strict: bool = False,
                        expected_subject_digest: str | None = None,
                        observed_body: str | None = None) -> dict:
    """Verify a DSSE-signed agent-review receipt — the PUBLIC surface, which never raises.

    THE GUARANTEE, and why it is a guarantee and not a nicety (measured 2026-08-31): a signed
    statement with ``subject`` or ``declaration`` in the wrong type left this function with a raw
    ``AttributeError`` instead of a typed fail-closed result. A verifier that crashes on malformed
    input is blind exactly where an attacker aims — the caller sees a stack trace, not ``ok=False``,
    and a pipeline that catches broadly cannot tell "invalid receipt" from "verifier broke".

    Anything unexpected becomes ``ok=False`` with the stable reason code ``internal_error``. That
    code is deliberately distinguishable from a normal rejection: it means the verifier itself hit
    something it did not model, which is a defect to report, not a verdict about the receipt.
    """
    try:
        return _verify_agent_review_inner(envelope, public_key, strict=strict,
                                          expected_subject_digest=expected_subject_digest,
                                          observed_body=observed_body)
    except Exception as exc:                                     # noqa: BLE001 — that is the point
        r = _empty_result()
        r["structure_ok"] = False
        r["errors"].append(f"internal_error: the verifier raised {type(exc).__name__} on this input "
                           f"— this is a defect in the verifier, not a verdict about the receipt")
        # EINE Quelle: der fatale Code steht in der Liste, `reason_code` ist die Ableitung daraus.
        # Zwei getrennt gepflegte Felder fuer dieselbe Groesse waeren die naechste Drift.
        r["reason_codes"].append("internal_error")
        r["reason_code"] = "internal_error"
        return _finalize_failclosed(r)


def _verify_agent_review_inner(envelope: dict, public_key: bytes, *, strict: bool = False,
                               expected_subject_digest: str | None = None,
                               observed_body: str | None = None) -> dict:
    """Separate axes, never one collapsed PASS (F12).

    ``currentness`` is ALWAYS ``CURRENTNESS_UNKNOWN`` here and that is not a defect: this verifier is
    offline, and whether the PR still looks like the reviewed state is a question only a live lookup
    or a trusted checkpoint can answer (F04). Reporting ``CURRENT`` from offline data would be the
    exact overclaim this predicate exists to avoid.
    """
    from . import dsse  # noqa: PLC0415
    from ._strict_json import loads_strict  # noqa: PLC0415
    from .budget import DEFAULT_BUDGET  # noqa: PLC0415
    r = _empty_result()
    try:
        r["crypto_ok"] = bool(dsse.verify_envelope(envelope, public_key,
                                                   payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE))
        if not r["crypto_ok"]:
            r["errors"].append("DSSE signature verification failed — payload is unauthenticated")
        body = dsse.load_payload(envelope)
        DEFAULT_BUDGET.check("input_bytes", len(body))
        statement = loads_strict(body.decode("utf-8"))
    except (ProofBundleError, ValueError, UnicodeDecodeError) as exc:
        r["structure_ok"] = False
        r["errors"].append(f"DSSE payload is not a well-formed in-toto Statement: {exc}")
        return _finalize_failclosed(r)

    ptype = statement.get("predicateType") if isinstance(statement, dict) else None
    r["predicate_type_ok"] = ptype == AGENT_REVIEW_PREDICATE_TYPE
    if not r["predicate_type_ok"]:
        if ptype == AGENT_REVIEW_PREDICATE_TYPE_V02:
            # KEIN RATEN UEBER VERSIONSGRENZEN (Owner-Entscheid 31.08.2026). Ein v0.1-Verifier
            # kennt die Zeitsemantik von v0.2 nicht; wuerde er sie nach v0.1-Regeln deuten, waere
            # eine Beobachtungszeit ploetzlich wieder eine Produzentenangabe. Ablehnen ist hier
            # die STAERKERE Antwort, nicht die bequemere.
            r["reason_codes"].append("UNKNOWN_PREDICATE_VERSION")
            r["errors"].append(
                "predicateType is agent-review/v0.2 — this is the v0.1 verifier and it refuses "
                "rather than guessing. Use verify_agent_review_v02; the two versions differ in "
                "what a time field MEANS, and a wrong guess would silently upgrade a declaration "
                "into an observation")
        else:
            r["errors"].append(
                f"predicateType is {ptype!r}, expected agent-review/v0.1 (confusion attack?)")

    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    # DIE TYPISIERUNG KOMMT VOR DER SEMANTIK (P0.1). Solange die Statement-Form nicht steht, ist
    # jede Achse darunter eine Rechnung auf Sand — und genau dort fielen die rohen AttributeError.
    shape_errs = validate_statement_shape(statement, predicate)
    r["errors"].extend(shape_errs)
    r["statement_shape_ok"] = not shape_errs
    # DIE CODES REISEN MIT (P0.1-Abnahme der Gegenlese Runde 2). Der Satz bleibt fuer
    # Menschen, der Code ist das, worauf eine Maschine sich verlassen darf: eine
    # umformulierte Fehlermeldung bricht sonst still jeden Verbraucher, der auf den Text
    # gematcht hat.
    #
    # DER VERTRAG ZWISCHEN DEN BEIDEN FELDERN, praezise (eine fruehere Fassung dieses
    # Kommentars sagte "`reason_code` ist die ABLEITUNG aus der Liste" — das war FALSCH und
    # eine adversariale Gegenlesung hat es am 01.09.2026 gemessen):
    #   `reason_codes`  traegt NUR FATALE Codes — Gruende, aus denen `ok` False wurde.
    #   `reason_code`   traegt den ERSTEN daraus, sonst None.
    #   `advisory_codes` traegt Hinweise, die den Ausgang NICHT bestimmen.
    #
    # DIE TRENNUNG IST AM 02.09.2026 ENTSTANDEN, weil eine adversariale Gegenlesung die Falle
    # gemessen hat, die die Vorfassung offen liess. Damals trug `reason_codes` ALLE Codes. Eine
    # fehlgeschlagene SIGNATURPRUEFUNG an einem Receipt mit `times.observedAt` kam so zurueck:
    #
    #     ok = False
    #     errors = ['DSSE signature verification failed — payload is unauthenticated']
    #     reason_code  = None
    #     reason_codes = ['LEGACY_SELF_DECLARED_OBSERVED_AT']
    #
    # Eine LEERE Liste sagt ehrlich "kein maschineller Grund". Eine Liste mit genau einem
    # Zeit-Hinweis laedt dazu ein, `reason_codes[0]` als Grund zu lesen — und der Grund war die
    # Signatur. Die Falle wurde fuer den SKALAR ausdruecklich geschlossen und fuer die LISTE offen
    # gelassen: ein Fix, der eine Haelfte schliesst. Jetzt kann ein Hinweis dort strukturell nicht
    # mehr stehen, statt dass ein Kommentar davor warnt.
    #
    # Ein informatorischer Code wird NIE zum `reason_code`. Ein GUELTIGES Receipt mit
    # `times.observedAt` hat ok=True, null Fehler, `reason_codes=[]`, `reason_code=None` und
    # `advisory_codes=[LEGACY_SELF_DECLARED_OBSERVED_AT]`.
    def _codes_sammeln(fehler) -> None:
        """Traegt die Codes einer Fehlerliste ein — EINE Stelle fuer beide Quellen."""
        for _e in fehler:
            _c = getattr(_e, "code", None)
            if _c and _c not in r["reason_codes"]:
                r["reason_codes"].append(_c)
        if r["reason_code"] is None and r["reason_codes"]:
            r["reason_code"] = r["reason_codes"][0]
    _codes_sammeln(shape_errs)
    struct_errs = validate_agent_review_predicate(predicate, strict=strict)
    r["errors"].extend(struct_errs)
    _codes_sammeln(struct_errs)

    canonical_ok = None
    if _rfc8785_available():
        try:
            canonical_ok = _rfc8785_bytes(statement) == body
        except Exception:
            canonical_ok = False
        if canonical_ok is False:
            r["errors"].append("payload is not RFC-8785 canonical (hash_binding fail-closed)")
    else:
        r["errors"].append(
            "RFC-8785 (JCS) canonicalizer unavailable — proofbundle requires rfc8785 (core dependency); "
            "hash_binding fail-closed, cannot verify canonicality")

    r["structure_ok"] = ((not struct_errs) and (not shape_errs)
                         and bool(r["predicate_type_ok"]) and canonical_ok is True)

    # Semantik NUR bei getypter Statement-Form: ein String in `subject` oder `declaration`
    # darf hier nicht mehr ankommen, sonst waere die Huelle oben die einzige Verteidigung.
    if isinstance(predicate, dict) and r["crypto_ok"] and not shape_errs:
        # Subject binding: the statement's subject digest must be the one derivable from the
        # signed subjectContext. A receipt copied onto another PR carries the old context and fails.
        # ZWEI ACHSEN, EIN HELFER — siehe `_zielbindung`. Bis zum 01.09.2026 stand die Logik
        # hier UND in v0.2, und die Achse hiess wie eine Bindung, war aber ohne Zielkontext eine
        # Selbstkonsistenz-Pruefung, die auf `True` stand.
        _zielbindung(r, predicate, statement, expected_subject_digest)

        # findingsRoot, when present, must actually cover the published list (P0 test 11).
        #
        # `or {}` FAENGT NUR FALSY, NICHT FALSCH GETYPT (gemessen 31.08.2026). Ein String im Feld
        # `declaration` ist wahrheitswertig, ueberlebt das `or` und laesst zwei Zeilen spaeter eine
        # rohe AttributeError fallen. Die Never-Raise-Huelle oben faengt sie — aber als
        # `internal_error`, und das ist die Meldung eines VERIFIER-Defekts, nicht ein Urteil ueber
        # das Receipt. Eine bekannte Eingabeklasse gehoert getypt, sonst verdeckt der Notausgang
        # genau die Faelle, fuer die er gebaut wurde.
        _dec_roh = predicate.get("declaration")
        dec_getypt = isinstance(_dec_roh, dict)
        dec: dict = _dec_roh if isinstance(_dec_roh, dict) else {}
        if not dec_getypt:
            r["errors"].append(
                f"declaration must be an object, got {type(_dec_roh).__name__} — findingsRoot "
                "and assurance cannot be evaluated, so both fail closed rather than staying unknown")
        if not dec_getypt:
            # BEIDE Achsen fail-closed, und die Folgebloecke werden UEBERSPRUNGEN. Mein erster
            # Entwurf setzte die Werte hier und liess die Bloecke laufen — sie ueberschrieben
            # beide zwei Zeilen spaeter, und `assurance_ok` stand wieder auf True. Ein Fix, der
            # danach verworfen wird, sieht im Quelltext richtig aus und wirkt nicht.
            r["findings_root_ok"] = False
            r["assurance_ok"] = False
        elif isinstance(dec.get("findingsRoot"), str):
            try:
                r["findings_root_ok"] = findings_root(dec.get("findings") or []) == dec["findingsRoot"]
                if not r["findings_root_ok"]:
                    r["errors"].append(
                        "findingsRoot does not cover the published findings list — a finding was added, "
                        "removed or altered after the root was taken")
            except AgentReviewError as exc:
                r["findings_root_ok"] = False
                r["errors"].append(f"findingsRoot not computable: {exc}")
        else:
            r["findings_root_ok"] = None

        # No rung above selfDeclared may appear in a v0.1 receipt, whatever the producer wrote.
        #
        # KEINE MENGE UEBER FREMDE DATEN, und der Grund ist nicht Stil (gemessen 31.08.2026, von
        # CI gefunden). Die erste Fassung baute `rungs` als set-Comprehension ueber Werte, die der
        # Produzent bestimmt. Ein unhashbarer Wert — eine Liste im Feld `assurance` — liess dort
        # eine ROHE TypeError aus einem Verify-Pfad fallen, der vertraglich immer ein typisiertes
        # Ergebnis liefert. Ausgefuehrt bestaetigt: `unhashable type: 'list'` statt ok=False.
        # Der Linter meldete nur den `in`-Test eine Zeile darunter; der schwerere Defekt war die
        # Menge selbst, und ohne den ausgefuehrten Gegenversuch haette ich nur den kleineren
        # gefixt und mich fuer fertig gehalten.
        rungs = [] if not dec_getypt else [
            i.get("assurance")
            for i in (dec.get("authoring") or []) + (dec.get("reviewRuns") or [])
            if isinstance(i, dict)]
        over = sorted({repr(x) for x in rungs
                       if x is not None and not is_member(x, _ASSURANCE_ALLOWED_V0_1)})
        if dec_getypt:
            r["assurance_ok"] = not over
        if over:
            r["errors"].append(
                f"assurance rung(s) {over} claimed in a v0.1 receipt — this version has no witness "
                "outside the producing agent; a valid signature does not raise a self-report")

    # ── v0.1 IST SEMANTISCH EINGEFROREN (Owner-Entscheid 31.08.2026) ───────────────────────────
    #
    # Die urspruengliche Forderung lautete "observedAt in Tier 1 verbieten". Umgesetzt haette sie
    # ein bereits VEROEFFENTLICHTES Receipt ungueltig gemacht, dessen observedAt eine Owner-Anordnung
    # desselben Tages ausdruecklich verlangt hatte. Der Entscheid nimmt weder das eine noch das
    # andere: v0.1 behaelt seine Semantik, v0.2 traegt die Trennung. Ein rueckwirkendes Verbot waere
    # ein Versionsbruch — und die Regel "nur Receipts nach Datum X ablehnen" waere besonders
    # schwach, weil der Verifier dann ausgerechnet an einer nicht bezeugten Zeit entscheiden
    # muesste, welche Semantik gilt. Die Version steht im predicateType, nie in einer Uhrzeit.
    #
    # WAS DER HINWEIS TUT UND WAS NICHT: er blockt nicht (ok bleibt unberuehrt), aber er nimmt dem
    # Wert jede Kraft. Ein selbst gesetztes observedAt darf keine Frische-, TTL-, Currentness- oder
    # Zeit-Assurance-Policy erfuellen — es ist eine Produzentenangabe, kein Beobachtungsbeleg.
    if isinstance(predicate, dict):
        _zeiten = predicate.get("times")
        _beob = (_zeiten or {}).get("observedAt") if isinstance(_zeiten, dict) else None
        if r["predicate_type_ok"]:
            r["time_semantics"] = "LEGACY_V0_1"
        # AN `predicate_type_ok` GEBUNDEN wie seine zwei Nachbarn in diesem Block.
        #
        # Der Satz sagt woertlich "this v0.1 receipt". Gemessen von einer adversarialen Linse am
        # 02.09.2026: er erschien auch, wenn der `predicateType` v0.2 oder voellig unbekannt war —
        # eine versionsspezifische Aussage ueber die Versionsgrenze getragen, in einem Feld, auf
        # das Verbraucher verzweigen sollen. `time_semantics` und der ABSENT-Zweig direkt darunter
        # waren gegattet, dieser Append nicht. Das Modul verlangt an zwei Stellen ausdruecklich
        # "KEIN RATEN UEBER VERSIONSGRENZEN".
        if _beob is not None and r["predicate_type_ok"]:
            r["observed_time_assurance"] = "SELF_DECLARED_OR_UNKNOWN"
            r["advisory_codes"].append("LEGACY_SELF_DECLARED_OBSERVED_AT")
            r["warnings"].append(
                "LEGACY_SELF_DECLARED_OBSERVED_AT: this v0.1 receipt carries a producer-supplied "
                "observedAt. It is structurally valid and does NOT make the receipt invalid, but it "
                "is a self-declaration, not an observation by a separate party — it must never "
                "satisfy a freshness, TTL, currentness or time-assurance policy. agent-review/v0.2 "
                "records such a time as a declared reviewCompleted claim and reserves observedAt "
                "for a named external observer.")
        elif r["predicate_type_ok"]:
            r["observed_time_assurance"] = "ABSENT"

    # ZWEI AUSSAGEN, ZWEI FELDER (Gegenlesung Runde 2, 31.08.2026 — angenommen).
    # `internal_consistency_ok` heisst: dieses Receipt ist in sich stimmig und unveraendert.
    # `ok` heisst: du darfst es als Beleg FUER DAS OBJEKT VOR DIR benutzen. Die zweite Aussage
    # kann ohne eine von aussen gesetzte Erwartung nicht getroffen werden, und eine Warnung daneben
    # traegt sie nicht: ein Aufrufer, der nur `ok` liest — etwa eine Pipeline, die prueft "gibt es
    # ein gueltiges Receipt" — bekaeme sonst gruen fuer ein Receipt, das zu einem anderen Vorgang
    # gehoert. Genau dieser Angriff wurde vorgelegt, und er traegt.
    _pruefe_sichtbaren_block(r, predicate, observed_body)

    r["internal_consistency_ok"] = bool(
        r["crypto_ok"] and r["structure_ok"] and r["predicate_type_ok"]
        and r["subject_binding_ok"] is not False
        and r["findings_root_ok"] is not False
        and r["assurance_ok"] is not False
        and r["body_core_digest_match"] not in ("MISMATCH", "NOT_MEASURABLE")
        and r["disclosure_core_digest_match"] not in ("MISMATCH", "NOT_MEASURABLE"))
    r["ok"] = bool(r["internal_consistency_ok"] and r["subject_expectation"] == "checked")
    if r["internal_consistency_ok"] and r["subject_expectation"] != "checked":
        r["errors"].append(
            "ok=False because no expected subject digest was supplied: the receipt is internally "
            "consistent (see internal_consistency_ok) but nothing here establishes that it belongs "
            "to the object you are looking at")

    from .automation_verdict import automation_summary  # noqa: PLC0415
    r["automation"] = automation_summary(r, required_checks={
        "crypto": "crypto_ok", "structure": "structure_ok", "policy": None,
        "references": ["internal_subject_consistency_ok", "subject_binding_ok", "findings_root_ok", "assurance_ok"],
    })
    return r


def verify_agent_review_v02(envelope: dict, public_key: bytes, *, strict: bool = False,
                            expected_subject_digest: str | None = None,
                            observed_body: str | None = None) -> dict:
    """Der v0.2-Verifier — getrennte Zeitachsen, kein Gesamturteil ueber Zeit.

    ER DEUTET v0.1 NIE STILLSCHWEIGEND NACH v0.2-REGELN. Ein v0.1-Receipt hat sein `observedAt`
    unter einer anderen Bedeutung erhalten; es hier als fehlende Observation zu werten waere eine
    rueckwirkende Umdeutung. Also: ablehnen, mit Verweis auf den richtigen Verifier.

    Er liefert dieselben Achsen wie v0.1 PLUS event_time_status, observation_time_status,
    signature_time_status und external_time_status. `policy_decision` bleibt None: ohne benannte
    relying-party-Policy gibt es keine Zeitfreigabe, und ein Verifier, der eine erfindet, nimmt
    dem Leser die Entscheidung ab, die ihm gehoert.
    """
    try:
        return _verify_v02_inner(envelope, public_key, strict=strict,
                                 expected_subject_digest=expected_subject_digest,
                                 observed_body=observed_body)
    except Exception as exc:                                     # noqa: BLE001 — dieselbe Huelle
        r = _empty_result()
        r["structure_ok"] = False
        r["reason_codes"].append("internal_error")
        r["reason_code"] = "internal_error"
        r["errors"].append(f"internal_error: the v0.2 verifier raised {type(exc).__name__} on this "
                           "input — this is a defect in the verifier, not a verdict about the receipt")
        return _finalize_failclosed(r)


def _verify_v02_inner(envelope: dict, public_key: bytes, *, strict: bool = False,
                      expected_subject_digest: str | None = None,
                      observed_body: str | None = None) -> dict:
    from . import dsse  # noqa: PLC0415
    from ._strict_json import loads_strict  # noqa: PLC0415
    from .budget import DEFAULT_BUDGET  # noqa: PLC0415
    r = _empty_result()
    r.update({"event_time_status": "NOT_EVALUATED", "observation_time_status": "NOT_EVALUATED",
              "signature_time_status": "NOT_EVALUATED", "external_time_status": "NOT_EVALUATED",
              "policy_decision": None})
    try:
        r["crypto_ok"] = bool(dsse.verify_envelope(envelope, public_key,
                                                   payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE))
        if not r["crypto_ok"]:
            r["errors"].append("DSSE signature verification failed — payload is unauthenticated")
        body = dsse.load_payload(envelope)
        DEFAULT_BUDGET.check("input_bytes", len(body))
        statement = loads_strict(body.decode("utf-8"))
    except (ProofBundleError, ValueError, UnicodeDecodeError) as exc:
        r["structure_ok"] = False
        r["errors"].append(f"DSSE payload is not a well-formed in-toto Statement: {exc}")
        return _finalize_failclosed(r)

    ptype = statement.get("predicateType") if isinstance(statement, dict) else None
    r["predicate_type_ok"] = ptype == AGENT_REVIEW_PREDICATE_TYPE_V02
    if not r["predicate_type_ok"]:
        if ptype == AGENT_REVIEW_PREDICATE_TYPE:
            r["reason_codes"].append("UNKNOWN_PREDICATE_VERSION")
            r["errors"].append(
                "predicateType is agent-review/v0.1 — this is the v0.2 verifier and it refuses "
                "rather than reinterpreting. In v0.1 a producer-supplied observedAt was allowed; "
                "judging it by v0.2 rules would rewrite what that receipt meant when it was signed")
        else:
            r["errors"].append(f"predicateType is {ptype!r}, expected agent-review/v0.2")

    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    shape_errs = validate_statement_shape(statement, predicate)
    r["errors"].extend(shape_errs)
    r["statement_shape_ok"] = not shape_errs
    # DIE CODES REISEN MIT (P0.1-Abnahme der Gegenlese Runde 2). Der Satz bleibt fuer
    # Menschen, der Code ist das, worauf eine Maschine sich verlassen darf: eine
    # umformulierte Fehlermeldung bricht sonst still jeden Verbraucher, der auf den Text
    # gematcht hat.
    #
    # DER VERTRAG ZWISCHEN DEN BEIDEN FELDERN, praezise (eine fruehere Fassung dieses
    # Kommentars sagte "`reason_code` ist die ABLEITUNG aus der Liste" — das war FALSCH und
    # eine adversariale Gegenlesung hat es am 01.09.2026 gemessen):
    #   `reason_codes`  traegt NUR FATALE Codes — Gruende, aus denen `ok` False wurde.
    #   `reason_code`   traegt den ERSTEN daraus, sonst None.
    #   `advisory_codes` traegt Hinweise, die den Ausgang NICHT bestimmen.
    #
    # DIE TRENNUNG IST AM 02.09.2026 ENTSTANDEN, weil eine adversariale Gegenlesung die Falle
    # gemessen hat, die die Vorfassung offen liess. Damals trug `reason_codes` ALLE Codes. Eine
    # fehlgeschlagene SIGNATURPRUEFUNG an einem Receipt mit `times.observedAt` kam so zurueck:
    #
    #     ok = False
    #     errors = ['DSSE signature verification failed — payload is unauthenticated']
    #     reason_code  = None
    #     reason_codes = ['LEGACY_SELF_DECLARED_OBSERVED_AT']
    #
    # Eine LEERE Liste sagt ehrlich "kein maschineller Grund". Eine Liste mit genau einem
    # Zeit-Hinweis laedt dazu ein, `reason_codes[0]` als Grund zu lesen — und der Grund war die
    # Signatur. Die Falle wurde fuer den SKALAR ausdruecklich geschlossen und fuer die LISTE offen
    # gelassen: ein Fix, der eine Haelfte schliesst. Jetzt kann ein Hinweis dort strukturell nicht
    # mehr stehen, statt dass ein Kommentar davor warnt.
    #
    # Ein informatorischer Code wird NIE zum `reason_code`. Ein GUELTIGES Receipt mit
    # `times.observedAt` hat ok=True, null Fehler, `reason_codes=[]`, `reason_code=None` und
    # `advisory_codes=[LEGACY_SELF_DECLARED_OBSERVED_AT]`.
    def _codes_sammeln(fehler) -> None:
        """Traegt die Codes einer Fehlerliste ein — EINE Stelle fuer beide Quellen."""
        for _e in fehler:
            _c = getattr(_e, "code", None)
            if _c and _c not in r["reason_codes"]:
                r["reason_codes"].append(_c)
        if r["reason_code"] is None and r["reason_codes"]:
            r["reason_code"] = r["reason_codes"][0]
    _codes_sammeln(shape_errs)
    struct_errs = validate_agent_review_v02_predicate(predicate, strict=strict)
    r["errors"].extend(struct_errs)
    _codes_sammeln(struct_errs)

    canonical_ok = None
    if _rfc8785_available():
        try:
            canonical_ok = _rfc8785_bytes(statement) == body
        except Exception:                                        # noqa: BLE001
            canonical_ok = False
        if canonical_ok is False:
            r["errors"].append("payload is not RFC-8785 canonical (hash_binding fail-closed)")
    else:
        r["errors"].append("RFC-8785 (JCS) canonicalizer unavailable — hash_binding fail-closed")

    r["structure_ok"] = ((not struct_errs) and (not shape_errs)
                         and bool(r["predicate_type_ok"]) and canonical_ok is True)
    r["time_semantics"] = "V0_2" if r["predicate_type_ok"] else None

    if isinstance(predicate, dict) and r["crypto_ok"] and not shape_errs and r["predicate_type_ok"]:
        r.update(_zeitachsen(predicate))
        # DERSELBE Helfer wie in v0.1 — ein Fix, der nur eine Kopie erreicht, ist der
        # Fehlermodus, gegen den dieser Auftrag gebaut ist.
        _zielbindung(r, predicate, statement, expected_subject_digest)

        _dv = predicate.get("declaration")
        dec_v2: dict = _dv if isinstance(_dv, dict) else {}
        # FAIL-CLOSED WIE IM v0.1-PFAD, und der Grund ist gemessen (Tiefen-Gate 5.1.0, 01.09.2026):
        # ist `declaration` KEIN Objekt, faellt `dec_v2` auf `{}`, damit ist `rungs` leer, damit
        # `over` leer, damit `assurance_ok = not [] = True` — die Achse meldet Gruen, obwohl sie
        # nichts geprueft hat. Der v0.1-Pfad hat dafuer seit jeher einen ausdruecklichen Riegel
        # (mit dem Kommentar, warum die Folgebloecke uebersprungen werden muessen); der v0.2-Pfad
        # hatte ihn nicht. Gleiche Eingabe, zwei Antworten.
        #
        # DIE KLASSE, zum dritten Mal in diesem Modul an einem Tag: "ein Fix erreichte nur eine
        # Kopie". Deshalb steht die Bedingung hier WOERTLICH gleich und wird von einem Test
        # gehalten, der BEIDE Pfade gegen dieselbe Eingabe faehrt.
        if not isinstance(_dv, dict):
            r["assurance_ok"] = False
            r["findings_root_ok"] = False
            r["errors"].append(
                "declaration must be an object — findingsRoot and assurance cannot be evaluated, "
                "so both fail closed rather than staying unknown")
        elif isinstance(dec_v2.get("findingsRoot"), str):
            try:
                r["findings_root_ok"] = findings_root(dec_v2.get("findings") or []) == dec_v2["findingsRoot"]
                if not r["findings_root_ok"]:
                    r["errors"].append("findingsRoot does not cover the published findings list")
            except AgentReviewError as exc:
                r["findings_root_ok"] = False
                r["errors"].append(f"findingsRoot not computable: {exc}")
        if isinstance(_dv, dict):
            # NUR wenn die Deklaration ein Objekt ist. Mein erster Entwurf setzte den Riegel oben
            # und liess diesen Block laufen — er ueberschrieb `assurance_ok` zwei Zeilen spaeter
            # wieder auf True. Dieselbe Falle, die der v0.1-Kommentar bereits namentlich nennt:
            # "ein Fix, der danach verworfen wird, sieht im Quelltext richtig aus und wirkt nicht."
            rungs = [i.get("assurance")
                     for i in (dec_v2.get("authoring") or []) + (dec_v2.get("reviewRuns") or [])
                     if isinstance(i, dict)]
            over = sorted({repr(x) for x in rungs
                           if x is not None and not is_member(x, _ASSURANCE_ALLOWED_V0_1)})
            r["assurance_ok"] = not over
            if over:
                r["errors"].append(f"assurance rung(s) {over} claimed in a Tier 1 receipt")

    _pruefe_sichtbaren_block(r, predicate, observed_body)

    r["internal_consistency_ok"] = bool(
        r["crypto_ok"] and r["structure_ok"] and r["predicate_type_ok"]
        and r["subject_binding_ok"] is not False
        and r["findings_root_ok"] is not False
        and r["assurance_ok"] is not False
        and r["body_core_digest_match"] not in ("MISMATCH", "NOT_MEASURABLE")
        and r["disclosure_core_digest_match"] not in ("MISMATCH", "NOT_MEASURABLE"))
    r["ok"] = bool(r["internal_consistency_ok"] and r["subject_expectation"] == "checked")
    if r["internal_consistency_ok"] and r["subject_expectation"] != "checked":
        r["errors"].append("ok=False because no expected subject digest was supplied")

    from .automation_verdict import automation_summary  # noqa: PLC0415
    # v0.2 FUEHRT eine Policy-Achse, also darf der Aufruf nicht "es gibt hier keine" sagen.
    #
    # `automation_summary` schreibt seinen Vertrag aus: `policy=None` heisst "this predicate type
    # carries no policy/authorization layer at all". Fuer v0.1 stimmt das. Fuer v0.2 NICHT — dessen
    # Ergebnis fuehrt `policy_decision`. GEMESSEN von einer adversarialen Linse am 02.09.2026:
    # `POLICY_NOT_EVALUATED` war fuer v0.2 strukturell unerreichbar, und `safeForAutomation` blieb
    # `True` selbst bei `event_time_status=CONFLICT` — den dasselbe Modul "a broken claim, not a
    # weak one" nennt und den `evaluate_time_policy` IMMER ablehnt.
    #
    # UND WARUM ES KEIN PFADVERGLEICH FAND: beide Verifier uebergaben DIESELBE Zeile. Ein
    # Vergleich v0.1 gegen v0.2 findet Gleichheit und meldet gruen. Eine Paritaetspruefung faengt
    # nur ASYMMETRISCHE Fehler; der geteilte Code ist der wahrscheinlichste Ort eines gemeinsamen
    # Irrtums.
    #
    # DIE FOLGE IST ABSICHTLICH STRENG: ohne uebergebene Policy bleibt `policy_decision` None, der
    # Blocker `POLICY_NOT_EVALUATED` greift, und `safeForAutomation` ist False. Ein Receipt, dessen
    # Policy nie ausgewertet wurde, IST nicht automatisierbar-sicher. Zulaessig ist das, weil v0.2
    # unveroeffentlicht ist: 0 Vorkommen im Tag v5.0.0, kein Aussteller, keine Receipts im Repo.
    r["automation"] = automation_summary(r, required_checks={
        "crypto": "crypto_ok", "structure": "structure_ok", "policy": "policy_decision",
        "references": ["internal_subject_consistency_ok", "subject_binding_ok", "findings_root_ok", "assurance_ok"],
    })
    return r
