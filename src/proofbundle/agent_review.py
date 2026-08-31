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

import hashlib
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

_REQUIRED_ALWAYS = ("schemaVersion", "reviewId", "subjectContext", "declaration",
                    "coverage", "times", "limitations")
_OPTIONAL = ("producer", "observations", "supersession", "planRef")
_ALLOWED_TOP = set(_REQUIRED_ALWAYS) | set(_OPTIONAL)

_PR_REQUIRED = ("kind", "forge", "repositoryId", "pullRequestNodeId", "headSha", "baseSha",
                "reviewedDiffDigest", "bodyCoreDigest")
_PR_ALLOWED = set(_PR_REQUIRED) | {"renderedDisclosureDigest", "humanRef"}
_ISSUE_REQUIRED = ("kind", "forge", "repositoryId", "issueNodeId", "bodyCoreDigest", "revisedAt")
_ISSUE_ALLOWED = set(_ISSUE_REQUIRED) | {"commentNodeId", "renderedDisclosureDigest", "humanRef"}

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
def validate_agent_review_predicate(predicate: Any, *, strict: bool = False) -> list[str]:
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
        errors.extend(f"subjectContext: {e}" for e in _validate_subject(predicate.get("subjectContext")))
    if "declaration" in predicate:
        errors.extend(f"declaration: {e}" for e in _validate_declaration(predicate.get("declaration")))
    if "coverage" in predicate:
        errors.extend(f"coverage: {e}" for e in _validate_coverage(predicate.get("coverage")))
    if "times" in predicate:
        errors.extend(f"times: {e}" for e in _validate_times(predicate.get("times")))

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
        errors.extend(f"supersession: {e}" for e in _validate_supersession(sup))

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
        return ["must be an object"]
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


def _validate_declaration(dec: Any) -> list[str]:
    errs: list[str] = []
    if not isinstance(dec, dict):
        return ["must be an object"]
    for k in dec:
        if k not in ("authoring", "reviewRuns", "findings", "findingsTotal",
                     "findingsRoot", "nonClaims"):
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
                    errs.extend(f"{listf}[{i}]: {e}" for e in _validate_assured(item))

    fnd = dec.get("findings")
    if "findings" in dec:
        if not isinstance(fnd, list):
            errs.append("findings must be an array")
        else:
            seen: set[str] = set()
            for i, f in enumerate(fnd):
                errs.extend(f"findings[{i}]: {e}" for e in _validate_finding(f))
                if isinstance(f, dict) and isinstance(f.get("id"), str):
                    if f["id"] in seen:
                        errs.append(f"findings[{i}]: duplicate id {f['id']!r}")
                    seen.add(f["id"])
    if "findingsRoot" in dec and not (isinstance(dec["findingsRoot"], str)
                                      and _SHA256_HEX.match(dec["findingsRoot"])):
        errs.append("findingsRoot must be a sha256 hex digest")

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
        return ["must be an object"]
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
        return ["must be an object"]
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


def _validate_coverage(cov: Any) -> list[str]:
    errs: list[str] = []
    if not isinstance(cov, dict):
        return ["must be an object"]
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
    for numf in ("observedRuns", "expectedRuns"):
        if numf in cov and cov[numf] is not None and not isinstance(cov[numf], int):
            errs.append(f"{numf} must be an integer or null")
    # COMPLETE is a strong word. It needs a stated expectation that the observation actually met —
    # otherwise 'complete' means 'I saw everything I happened to see' (F07).
    if cov.get("status") == "COMPLETE":
        obs, exp = cov.get("observedRuns"), cov.get("expectedRuns")
        if not (isinstance(obs, int) and isinstance(exp, int)):
            errs.append("status COMPLETE requires integer observedRuns and expectedRuns — without a "
                        "stated expectation, 'complete' is unfalsifiable")
        elif obs < exp:
            errs.append(f"status COMPLETE but observedRuns {obs} < expectedRuns {exp}")
        if cov.get("knownGaps"):
            errs.append("status COMPLETE cannot list knownGaps")
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
        return ["must be an object"]
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
        return ["must be an object"]
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
                           leaf_url: str | None = None, leaf_witnessed: bool = False) -> str:
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
                                 subject_sha256: str | None = None) -> dict:
    require_valid_agent_review_predicate(predicate)
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": subject_name or _subject_name(predicate),
                     "digest": {"sha256": subject_sha256 or _subject_digest(predicate)}}],
        "predicateType": AGENT_REVIEW_PREDICATE_TYPE,
        "predicate": predicate,
    }


def emit_agent_review(predicate: dict, signer, *, subject_name: str | None = None,
                      subject_sha256: str | None = None, keyid: str | None = None,
                      strict: bool = True) -> dict:
    """Sign an agent-review statement. Uses the existing DSSE path — no new crypto."""
    from . import dsse  # noqa: PLC0415
    errs = validate_agent_review_predicate(predicate, strict=strict)
    if errs:
        raise AgentReviewError("invalid agent-review predicate: " + "; ".join(errs))
    statement = build_agent_review_statement(predicate, subject_name=subject_name,
                                             subject_sha256=subject_sha256)
    return dsse.sign_envelope(_rfc8785_bytes(statement), signer,
                              payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE, keyid=keyid)


def _empty_result() -> dict:
    return {"ok": None, "structure_ok": None, "crypto_ok": None, "predicate_type_ok": None,
            "subject_binding_ok": None, "subject_expectation": "not_supplied",
            "findings_root_ok": None, "assurance_ok": None,
            "currentness": "CURRENTNESS_UNKNOWN", "automation": None,
            "warnings": [], "errors": []}


def _finalize_failclosed(r: dict) -> dict:
    from .automation_verdict import automation_summary  # noqa: PLC0415
    r["ok"] = False
    r["automation"] = automation_summary(r, required_checks={
        "crypto": "crypto_ok", "structure": "structure_ok", "policy": None,
        "references": ["subject_binding_ok", "findings_root_ok", "assurance_ok"]})
    return r


def verify_agent_review(envelope: dict, public_key: bytes, *, strict: bool = False,
                        expected_subject_digest: str | None = None) -> dict:
    """Verify a DSSE-signed agent-review receipt. Separate axes, never one collapsed PASS (F12).

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
        r["errors"].append(f"predicateType is {ptype!r}, expected agent-review/v0.1 (confusion attack?)")

    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    struct_errs = validate_agent_review_predicate(predicate, strict=strict)
    r["errors"].extend(struct_errs)

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

    r["structure_ok"] = (not struct_errs) and bool(r["predicate_type_ok"]) and canonical_ok is True

    if isinstance(predicate, dict) and r["crypto_ok"]:
        # Subject binding: the statement's subject digest must be the one derivable from the
        # signed subjectContext. A receipt copied onto another PR carries the old context and fails.
        try:
            derived = _subject_digest(predicate)
            subj = (statement.get("subject") or [{}])[0]
            claimed = ((subj.get("digest") or {}).get("sha256") or "")
            r["subject_binding_ok"] = derived == claimed
            if not r["subject_binding_ok"]:
                r["errors"].append(
                    "subject digest does not match the signed subjectContext — this receipt does not "
                    "bind the object it names")
            if expected_subject_digest is None:
                # DIE KORREKTUR AN EINER FALSCHEN BEHAUPTUNG VON MIR (31.08.2026, Gegenlesung).
                # Ich hatte geschrieben, ein auf einen fremden PR kopiertes Receipt falle durch die
                # Subject-Pruefung. Das ist FALSCH. `derived` und `claimed` stammen beide aus
                # demselben signierten subjectContext, also stimmen sie ueberein, solange niemand
                # das Statement von Hand baut. Wer ein gueltiges Receipt kopiert und behauptet, es
                # gehoere zu einem anderen PR, aendert am Envelope nichts — er luegt daneben.
                # Ohne eine von aussen gesetzte Erwartung ist das hier eine KONSISTENZ-Pruefung,
                # keine Bindung an das Objekt, das der Leser gerade ansieht. Das wird jetzt
                # ausgewiesen statt verschwiegen.
                r["warnings"].append(
                    "no expected_subject_digest was supplied: this run checked only that the receipt "
                    "is internally consistent, NOT that it belongs to the object you are looking at. "
                    "A valid receipt for a different pull request passes this check.")
            else:
                r["subject_expectation"] = "checked"
                if derived != expected_subject_digest:
                    r["subject_binding_ok"] = False
                    r["errors"].append(
                        f"subjectContext digest {derived[:16]}… is not the expected "
                        f"{expected_subject_digest[:16]}… (receipt belongs to a different pull "
                        "request or issue)")
        except (AgentReviewError, KeyError, TypeError, IndexError) as exc:
            r["subject_binding_ok"] = False
            r["errors"].append(f"subject binding not computable: {exc}")

        # findingsRoot, when present, must actually cover the published list (P0 test 11).
        dec = predicate.get("declaration") or {}
        if isinstance(dec.get("findingsRoot"), str):
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
        rungs = {i.get("assurance")
                 for i in (dec.get("authoring") or []) + (dec.get("reviewRuns") or [])
                 if isinstance(i, dict)}
        over = sorted(x for x in rungs if x not in _ASSURANCE_ALLOWED_V0_1 and x is not None)
        r["assurance_ok"] = not over
        if over:
            r["errors"].append(
                f"assurance rung(s) {over} claimed in a v0.1 receipt — this version has no witness "
                "outside the producing agent; a valid signature does not raise a self-report")

    r["ok"] = bool(
        r["crypto_ok"] and r["structure_ok"] and r["predicate_type_ok"]
        and r["subject_binding_ok"] is not False
        and r["findings_root_ok"] is not False
        and r["assurance_ok"] is not False)

    from .automation_verdict import automation_summary  # noqa: PLC0415
    r["automation"] = automation_summary(r, required_checks={
        "crypto": "crypto_ok", "structure": "structure_ok", "policy": None,
        "references": ["subject_binding_ok", "findings_root_ok", "assurance_ok"],
    })
    return r
