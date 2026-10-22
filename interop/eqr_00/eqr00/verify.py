"""Section 8 of the draft for one Evidence Qualification Receipt, and Section 10 for several.

A result keeps four things apart (Table 1 of Section 11): whether the receipt is valid, which
evaluation it carries, whether it qualifies for a policy that requires PASS (Section 8.1), and that
no authorization decision is made here (Sections 3 and 9). Requirement ids refer to requirements.json,
line numbers to the pinned plain-text copy of the draft. Readings chosen where the text allows more
than one are marked READING and listed in requirements_map.json and OFFENE_PUNKTE.

Input of :func:`verify`:

* ``receipt``: ``{"form": "jws", "compact": "<h>.<p>.<s>"}`` or ``{"form": "json", "text": "..."}``
  (or ``"b64u"`` for exact bytes that are not text).
* ``context``: the verifier's local inputs. ``now`` (RFC 3339); ``inter_domain`` (default true);
  ``trust.issuers`` (issuer URI -> ``keys`` by kid as Ed25519 JWK, and the ``profiles`` accepted from
  it); ``profiles`` (profile id -> accepted ``digest`` or the accepted profile as ``json``/``text``,
  ``required_conditions`` as a count, accepted ``evidence_classes``); ``proposition`` (``claim_id`` and
  the proposition as ``json``, ``text``, ``bytes_b64u`` or ``digest``); ``action`` and ``context`` the
  same way; ``require_action_binding``, ``require_context_binding``, ``high_consequence``;
  ``expected_nonce``; ``max_validity_seconds``; ``policy_requires_pass`` (default true).
"""
from __future__ import annotations

import copy
import hashlib

from . import DRAFT, DRAFT_SHA256, IMPLEMENTATION_VERSION, jws
from .wire import WireError, b64u_decode, check_digest, check_uri, decode_json, jcs, parse_time, sha256_b64u

STATUSES = ("pass", "fail", "indeterminate")                                           # S5.1-1
TOP_REQUIRED = ("version", "receipt_id", "issuer", "issued_at", "expires_at", "profile", "claim", "evaluation",
                "evidence")
TOP_OPTIONAL = ("context_digest", "action_digest", "supersedes", "nonce")
REF_MEMBERS = ("id", "hash_alg", "digest")
EVAL_MEMBERS = ("status", "requirements_satisfied", "blocking_contradictions")
HASH_ALG = "sha-256"
AUTHORIZATION = "not decided here: an EQR is one input to a separate authorization decision (Sections 3 and 9)"


class _Out:
    """The three kinds of outcome a check can have, kept apart."""

    def __init__(self):
        self.refusals = []       # the receipt is INVALID
        self.unverifiable = []   # a check could not run for want of a local input
        self.policy = []         # the receipt is valid and does not qualify under local policy
        self.notes = []          # kept for the reader, no effect on the verdicts

    def refuse(self, step, code, requirement, detail):
        self.refusals.append({"step": step, "code": code, "requirement": requirement, "detail": detail})

    def cannot(self, step, code, detail):
        self.unverifiable.append({"step": step, "code": code, "detail": detail})

    def decline(self, step, code, requirement, detail):
        self.policy.append({"step": step, "code": code, "requirement": requirement, "detail": detail})

    def note(self, step, code, detail):
        self.notes.append({"step": step, "code": code, "detail": detail})


def _local_digest(spec):
    """The sha-256 digest (base64url) of a local value: JSON through RFC 8785 (S5-1), text as UTF-8, exact
    bytes, or a digest the verifier already holds. Section 5 leaves non-JSON bytes to the profile (S5-2)."""
    if not isinstance(spec, dict):
        raise WireError("a local value is an object naming json, text, bytes_b64u or digest")
    forms = [k for k in ("json", "text", "bytes_b64u", "digest") if k in spec]
    if len(forms) != 1:
        raise WireError(f"a local value names exactly one form, this one {forms or 'none'}")
    form = forms[0]
    if form == "json":
        return sha256_b64u(jcs(spec["json"]))
    if form == "text":
        if not isinstance(spec["text"], str):
            raise WireError("text must be a string")
        return sha256_b64u(spec["text"].encode("utf-8"))
    if form == "bytes_b64u":
        return sha256_b64u(b64u_decode(spec["bytes_b64u"]))
    check_digest(spec["digest"])
    return spec["digest"]


def _ref(out, name, value):
    """profile and claim: an id, the hash algorithm and the digest of the exact bytes (Section 5).
    READING: the member names are those of the example in Section 5.2, the only names the text gives."""
    if not isinstance(value, dict):
        out.refuse(1, "MEMBER_TYPE", "S8-1", f"{name} must be an object with {REF_MEMBERS}")
        return False
    ok = True
    for m in REF_MEMBERS:
        if m not in value:
            out.refuse(1, "MISSING_MEMBER", "S8-1", f"{name}.{m} is missing")
            ok = False
    if "id" in value and (not isinstance(value["id"], str) or not value["id"]):
        out.refuse(1, "MEMBER_TYPE", "S8-1", f"{name}.id must be a non-empty string")
        ok = False
    if "hash_alg" in value and value["hash_alg"] != HASH_ALG:
        out.refuse(1, "HASH_ALG_UNSUPPORTED", "S5-5", f"{name}.hash_alg {value['hash_alg']!r}: only {HASH_ALG} "
                                                     "is implemented, and no other is guessed")
        ok = False
    if "digest" in value:
        try:
            check_digest(value["digest"])
        except WireError as exc:
            out.refuse(1, "DIGEST_FORM", "S5-5", f"{name}.digest: {exc}")
            ok = False
    extra = sorted(set(value) - set(REF_MEMBERS))
    if extra:
        out.note(1, "MEMBERS_NOT_INTERPRETED", f"{name}: {extra}")
    return ok


def _syntax(eqr, out):
    """Step 1: syntax and the supported version. Returns the parsed times or None."""
    if not isinstance(eqr, dict):
        out.refuse(1, "NOT_AN_OBJECT", "S8-1", "an EQR payload is a JSON object (Section 5)")
        return None
    for m in TOP_REQUIRED:
        if m not in eqr:
            # READING: every member Section 5 does not call optional is required.
            out.refuse(1, "MISSING_MEMBER", "S8-1", f"{m} is missing")
    extra = sorted(set(eqr) - set(TOP_REQUIRED) - set(TOP_OPTIONAL))
    if extra:
        out.note(1, "MEMBERS_NOT_INTERPRETED", f"top level: {extra}; nothing in them is read as a verdict")
    if "version" in eqr and eqr["version"] != "1":
        out.refuse(1, "VERSION_UNSUPPORTED", "S8-1", f"version {eqr['version']!r}: this reader supports the string "
                                                     "'1' only")
    for m in ("receipt_id", "issuer"):
        if m in eqr:
            try:
                check_uri(eqr[m])
            except WireError as exc:
                out.refuse(1, "URI_FORM", "S8-1", f"{m}: {exc}")
    times = {}
    for m in ("issued_at", "expires_at"):
        if m in eqr:
            try:
                times[m] = parse_time(eqr[m])
            except WireError as exc:
                out.refuse(1, "TIME_FORM", "S5-3", f"{m}: {exc}")
    for m in ("profile", "claim"):
        if m in eqr:
            _ref(out, m, eqr[m])
    for m in ("context_digest", "action_digest"):
        if m in eqr:
            try:
                check_digest(eqr[m])        # READING: these carry no hash_alg; sha-256 is mandatory to implement
            except WireError as exc:
                out.refuse(1, "DIGEST_FORM", "S5-5", f"{m}: {exc}")
    if "supersedes" in eqr and eqr["supersedes"] is not None:
        try:
            check_uri(eqr["supersedes"])
        except WireError as exc:
            out.refuse(1, "URI_FORM", "S8-1", f"supersedes: {exc}")
        if eqr["supersedes"] == eqr.get("receipt_id"):
            out.refuse(1, "SELF_SUPERSESSION", "S10-2", "a receipt cannot supersede itself")
    if "nonce" in eqr and (not isinstance(eqr["nonce"], str) or not eqr["nonce"]):
        out.refuse(1, "MEMBER_TYPE", "S8-1", "nonce must be a non-empty string")
    ev = eqr.get("evaluation")
    if "evaluation" in eqr:
        _evaluation(ev, out)
    if "evidence" in eqr:
        _evidence(eqr["evidence"], out)
    if "issued_at" in times and "expires_at" in times and times["expires_at"] <= times["issued_at"]:
        out.refuse(1, "VALIDITY_INTERVAL_EMPTY", "S5-3", "expires_at does not lie after issued_at")
    return times


def _evaluation(ev, out):
    if not isinstance(ev, dict):
        out.refuse(1, "MEMBER_TYPE", "S8-1", "evaluation must be an object")
        return
    for m in EVAL_MEMBERS:
        if m not in ev:
            out.refuse(1, "MISSING_MEMBER", "S8-1", f"evaluation.{m} is missing")
    st = ev.get("status")
    if "status" in ev and st not in STATUSES:
        out.refuse(1, "STATUS_UNKNOWN", "S5.1-1", f"evaluation.status {st!r} is none of {STATUSES} (exact, lower case)")
    rs = ev.get("requirements_satisfied")
    if "requirements_satisfied" in ev and not isinstance(rs, bool):
        out.refuse(1, "MEMBER_TYPE", "S8-1", "evaluation.requirements_satisfied must be true or false")
    bc = ev.get("blocking_contradictions")
    blocking = None
    if "blocking_contradictions" in ev:
        # READING: Section 5 allows "the number or digests" of unresolved blocking contradictions.
        if isinstance(bc, int) and not isinstance(bc, bool) and bc >= 0:
            blocking = bc
        elif isinstance(bc, list):
            for i, d in enumerate(bc):
                try:
                    check_digest(d)
                except WireError as exc:
                    out.refuse(1, "DIGEST_FORM", "S5-5", f"evaluation.blocking_contradictions[{i}]: {exc}")
            blocking = len(bc)
        else:
            out.refuse(1, "MEMBER_TYPE", "S8-1", "evaluation.blocking_contradictions must be a count or a list of "
                                                 "digests")
    if st in STATUSES and isinstance(rs, bool):
        # READING: a receipt whose members contradict each other is malformed (INVALID), not merely
        # non-qualifying; Section 5.1 and the definitions of Section 2 fix how they relate.
        if st == "pass" and (rs is not True or (blocking or 0) > 0):
            out.refuse(1, "EVALUATION_INCONSISTENT", "S5.1-4", "pass with unsatisfied requirements or blocking "
                                                               "contradictions")
        if st == "fail" and rs is True:
            out.refuse(1, "EVALUATION_INCONSISTENT", "S5.1-2", "fail while every requirement is satisfied")
        if st == "indeterminate" and rs is True:
            out.refuse(1, "EVALUATION_INCONSISTENT", "S5.1-3", "indeterminate while every requirement is satisfied")


def _evidence(evd, out):
    if not isinstance(evd, list):
        out.refuse(1, "MEMBER_TYPE", "S8-1", "evidence must be an array of descriptors")
        return
    for i, d in enumerate(evd):
        if not isinstance(d, dict):
            out.refuse(1, "MEMBER_TYPE", "S8-1", f"evidence[{i}] must be an object")
            continue
        if not isinstance(d.get("class"), str) or not d.get("class"):
            out.refuse(1, "MISSING_MEMBER", "S8-1", f"evidence[{i}].class is missing (Section 5: at least a digest "
                                                    "and an evidence class)")
        if d.get("hash_alg") != HASH_ALG:
            out.refuse(1, "HASH_ALG_UNSUPPORTED", "S5-5", f"evidence[{i}].hash_alg {d.get('hash_alg')!r}")
        try:
            check_digest(d.get("digest"))
        except WireError as exc:
            out.refuse(1, "DIGEST_FORM", "S5-5", f"evidence[{i}].digest: {exc}")
        if "fresh_until" in d:
            try:
                parse_time(d["fresh_until"])
            except WireError as exc:
                out.refuse(1, "TIME_FORM", "S5-3", f"evidence[{i}].fresh_until: {exc}")
        extra = sorted(set(d) - {"class", "hash_alg", "digest", "fresh_until"})
        if extra:
            out.note(1, "LOCAL_METADATA_NOT_DEREFERENCED", f"evidence[{i}]: {extra} kept, never fetched (Section 15)")


def verify(receipt, context) -> dict:
    out = _Out()
    context = context or {}
    trust = ((context.get("trust") or {}).get("issuers")) or {}
    payload, eqr, integrity = None, None, "none"
    header = signing_input = signature = None

    # ---- Steps 1 and 2: decode under the strict rule, then syntax, version, integrity and issuer
    form = receipt.get("form") if isinstance(receipt, dict) else None
    if form == "jws":
        try:
            header, payload, signing_input, signature = jws.split(receipt.get("compact"))
        except jws.JwsError as exc:
            out.refuse(1, "JWS_FORM", "S6-1", str(exc))
    elif form == "json":
        try:
            payload = receipt["text"].encode("utf-8") if "text" in receipt else b64u_decode(receipt.get("b64u"))
        except (WireError, AttributeError) as exc:
            out.refuse(1, "INPUT_FORM", "S8-1", f"receipt bytes: {exc}")
    else:
        out.refuse(1, "INPUT_FORM", "S8-1", f"receipt form {form!r} is neither jws nor json")
    if payload is not None:
        try:
            eqr = decode_json(payload)
        except WireError as exc:
            out.refuse(1, "STRICT_DECODING", "S8-1", str(exc))
    times = _syntax(eqr, out) if eqr is not None else None
    issuer = eqr.get("issuer") if isinstance(eqr, dict) else None
    if form == "jws" and header is not None:
        refusals, notes = jws.header_findings(header)
        for n in notes:
            out.note(2, "HEADER_NOT_USED", n)
        for r in refusals:
            out.refuse(2, "JWS_HEADER", "S6-1", r)
        if not refusals and isinstance(issuer, str):
            kid = header["kid"]
            jwk = ((trust.get(issuer) or {}).get("keys") or {}).get(kid)
            if jwk is None:
                elsewhere = sorted(i for i, cfg in trust.items() if kid in ((cfg or {}).get("keys") or {}))
                if elsewhere:
                    out.refuse(2, "ISSUER_KEY_MISMATCH", "S6-1", f"kid {kid!r} belongs to {elsewhere}, not to the issuer "
                                                                 f"{issuer!r} the receipt names")
                else:
                    out.refuse(2, "ISSUER_KEY_UNKNOWN", "S6-1", f"no configured key {kid!r} for issuer {issuer!r}; "
                                                                "nothing is fetched")
            else:
                try:
                    good = jws.verify_ed25519(jwk, signing_input, signature)
                except jws.JwsError as exc:
                    out.cannot(2, "TRUST_CONFIGURATION", str(exc))
                    good = None
                if good is False:
                    out.refuse(2, "SIGNATURE_INVALID", "S6-1", "the signature does not verify over the protected "
                                                               "header and the payload")
                elif good:
                    integrity = "verified"
    elif form == "json" and eqr is not None:
        if context.get("inter_domain", True):
            out.refuse(2, "NOT_INTEGRITY_PROTECTED", "S6-1", "an inter-domain EQR must be integrity protected and "
                                                             "bound to an authenticated issuer")
        else:
            integrity = "not required (intra-domain under local policy)"
            out.note(2, "INTRA_DOMAIN_UNPROTECTED", "accepted without integrity protection because local policy "
                                                    "declares the receipt intra-domain")

    ok_eqr = isinstance(eqr, dict)
    ev = eqr.get("evaluation") if ok_eqr and isinstance(eqr.get("evaluation"), dict) else {}
    status = ev.get("status") if ev.get("status") in STATUSES else None

    # ---- Step 3: freshness and nonce or transaction binding
    now = None
    if "now" not in context:
        out.cannot(3, "NO_VERIFICATION_TIME", "the context gives no verification time")
    else:
        try:
            now = parse_time(context["now"])
        except WireError as exc:
            out.cannot(3, "NO_VERIFICATION_TIME", str(exc))
    if ok_eqr and times and now is not None and "issued_at" in times and "expires_at" in times:
        if now < times["issued_at"]:
            out.refuse(3, "NOT_YET_VALID", "S8-1", "issued_at lies after the verification time")
        elif now >= times["expires_at"]:
            out.refuse(3, "EXPIRED", "S8-1", "the receipt expired before the verification time")
        mv = context.get("max_validity_seconds")
        if isinstance(mv, int) and (times["expires_at"] - times["issued_at"]).total_seconds() > mv:
            out.refuse(3, "VALIDITY_TOO_LONG", "S15-2", f"validity interval exceeds the local bound of {mv} s")
    if ok_eqr:
        expected = context.get("expected_nonce")
        if expected is not None:
            if "nonce" not in eqr:
                out.refuse(3, "NONCE_MISSING", "S15-2", "local policy expects a nonce and the receipt carries none")
            elif eqr["nonce"] != expected:
                out.refuse(3, "NONCE_MISMATCH", "S15-2", "the receipt's nonce is not the expected one")
        elif "nonce" in eqr:
            # READING: with no expected value there is nothing to validate the nonce against.
            out.note(3, "NONCE_NOT_CHECKED", "the receipt carries a nonce and local policy expects none")

    # ---- Step 4: the proposition digest against the proposition of the proposed action
    claim = eqr.get("claim") if ok_eqr and isinstance(eqr.get("claim"), dict) else {}
    prop = context.get("proposition")
    if ok_eqr and claim:
        if prop is None:
            out.cannot(4, "PROPOSITION_NOT_SUPPLIED", "the context gives no proposition to bind the receipt to")
        else:
            try:
                d = _local_digest(prop)
            except WireError as exc:
                out.cannot(4, "LOCAL_INPUT_INVALID", f"proposition: {exc}")
                d = None
            if d is not None and claim.get("digest") != d:
                out.refuse(4, "CLAIM_DIGEST_MISMATCH", "S15-1", "the receipt qualifies another proposition than the "
                                                                "one offered for this action")
            if "claim_id" in prop and claim.get("id") != prop["claim_id"]:
                out.refuse(4, "CLAIM_ID_MISMATCH", "S15-1", f"claim id {claim.get('id')!r} is not {prop['claim_id']!r}")

    # ---- Step 5: profile identifier and digest against an acceptable local profile
    profile = eqr.get("profile") if ok_eqr and isinstance(eqr.get("profile"), dict) else {}
    accepted = None
    if ok_eqr and profile:
        accepted = (context.get("profiles") or {}).get(profile.get("id"))
        if accepted is None:
            out.refuse(5, "PROFILE_NOT_ACCEPTED", "S15-3", f"profile {profile.get('id')!r} is not an acceptable local "
                                                           "profile")
        else:
            try:
                d = _local_digest({k: v for k, v in accepted.items() if k in ("json", "text", "bytes_b64u", "digest")})
            except WireError as exc:
                out.cannot(5, "LOCAL_INPUT_INVALID", f"accepted profile: {exc}")
                d = None
            if d is not None and profile.get("digest") != d:
                out.refuse(5, "PROFILE_DIGEST_MISMATCH", "S15-3", "the profile digest does not match the accepted "
                                                                  "profile bytes")
            rc = accepted.get("required_conditions")
            if status == "pass" and rc == 0:
                # READING: the verifier learns the size of the required-condition set from its accepted profile.
                out.refuse(5, "EMPTY_REQUIRED_SET_PASS", "S5.1-5", "pass under a profile with no required condition")

    # ---- Step 6: context and action digests when local policy requires them
    for name, member in (("action", "action_digest"), ("context", "context_digest")):
        if not ok_eqr:
            break
        required = bool(context.get(f"require_{name}_binding")) or (name == "action" and bool(
            context.get("high_consequence")))
        local = context.get(name)
        req_id = "S5-4" if name == "action" and context.get("high_consequence") else "S8-1"
        if member not in eqr:
            if required:
                out.refuse(6, f"{name.upper()}_BINDING_MISSING", req_id, f"local policy requires {member} and the "
                                                                         "receipt carries none")
            continue
        if local is None:
            if required:
                out.cannot(6, f"{name.upper()}_NOT_SUPPLIED", f"the context gives no {name} to compare {member} with")
            else:
                out.note(6, f"{name.upper()}_DIGEST_NOT_CHECKED", f"{member} present, no local {name} given")
            continue
        try:
            d = _local_digest(local)
        except WireError as exc:
            out.cannot(6, "LOCAL_INPUT_INVALID", f"{name}: {exc}")
            continue
        if eqr[member] != d:
            # READING: a present binding is compared whenever the local value is known (Section 15, authority
            # laundering), not only when local policy requires it.
            out.refuse(6, f"{name.upper()}_DIGEST_MISMATCH", "S15-1", f"the receipt is bound to another {name}")

    # ---- Step 7: local trust policy for the issuer and the evidence classes (the last line of Section 8.1)
    if ok_eqr:
        icfg = trust.get(issuer) if isinstance(issuer, str) else None
        if icfg is None:
            out.decline(7, "ISSUER_NOT_ACCEPTED", "S8-1", f"issuer {issuer!r} is not in the local trust policy")
        elif profile and profile.get("id") not in (icfg.get("profiles") or []):
            out.decline(7, "ISSUER_NOT_ACCEPTED_FOR_PROFILE", "S15-1", f"issuer {issuer!r} is not accepted for "
                                                                       f"profile {profile.get('id')!r}")
        classes = (accepted or {}).get("evidence_classes")
        evd = eqr.get("evidence") if isinstance(eqr.get("evidence"), list) else []
        for i, d in enumerate(evd):
            if isinstance(d, dict) and isinstance(classes, list) and d.get("class") not in classes:
                out.decline(7, "EVIDENCE_CLASS_NOT_ACCEPTED", "S8-1", f"evidence[{i}] class {d.get('class')!r}")
            if isinstance(d, dict) and now is not None and "fresh_until" in d:
                try:
                    if parse_time(d["fresh_until"]) <= now:
                        # READING: a descriptor that is stale at verification time keeps the receipt from qualifying
                        # (Section 15, replay after the evidence became stale).
                        out.decline(7, "EVIDENCE_STALE", "S15-2", f"evidence[{i}] fresh_until has passed")
                except WireError:
                    pass                            # already refused in step 1
        if status == "pass" and not evd:
            # READING: Section 5.1 says a profile that requires no evidence needs no EQR; a PASS without a single
            # evidence descriptor does not qualify.
            out.decline(7, "PASS_WITHOUT_EVIDENCE", "S5.1-5", "pass with no evidence descriptor")

    # ---- Step 8: expose the evaluation without rewriting it
    validity = "INVALID" if out.refusals else ("UNVERIFIABLE" if out.unverifiable else "VALID")
    exposed = status if validity == "VALID" else None
    reasons = []
    requires_pass = context.get("policy_requires_pass", True)
    if not requires_pass:
        reasons.append("local policy requires no PASS EQR here (Section 4); no qualification is claimed")
    if validity != "VALID":
        reasons.append(f"receipt {validity}")
    if exposed is not None and exposed != "pass":
        reasons.append(f"evaluation {exposed.upper()} does not satisfy a PASS requirement (Section 8.1)")
    reasons += [p["code"] for p in out.policy]
    qualifies = validity == "VALID" and exposed == "pass" and ev.get("requirements_satisfied") is True \
        and not ev.get("blocking_contradictions") and not out.policy
    if not requires_pass:
        qualifies = None
    if validity == "INVALID":
        table1 = "INVALID receipt"
    elif validity == "UNVERIFIABLE":
        table1 = "receipt not verifiable with the local inputs given"
    else:
        table1 = f"VALID receipt with {exposed.upper()}"
    return {
        "reader": {"name": "eqr00", "version": IMPLEMENTATION_VERSION, "draft": DRAFT, "draft_sha256": DRAFT_SHA256},
        "receipt_validity": validity,
        "table1": table1,
        "integrity": integrity,
        "evaluation_status": exposed,
        "embedded_status": ev.get("status") if ok_eqr else None,
        "qualification": {"policy_requires_pass": bool(requires_pass), "qualifies": qualifies, "reasons": reasons},
        "authorization": AUTHORIZATION,
        "refusals": out.refusals,
        "unverifiable": out.unverifiable,
        "policy": out.policy,
        "notes": out.notes,
        "receipt": ({k: copy.deepcopy(eqr.get(k)) for k in ("receipt_id", "issuer", "supersedes")}
                    if ok_eqr else {}),
        "payload_jcs_sha256": _content_digest(eqr) if ok_eqr else None,
    }


def _content_digest(eqr):
    try:
        return hashlib.sha256(jcs(eqr)).hexdigest()
    except WireError:
        return None


def _not_qualifying(result, reason):
    """A history finding withdraws a qualification; a policy that requires no PASS claimed none (None stays None)."""
    q = result["qualification"]
    if q["qualifies"] is not None:
        q["qualifies"] = False
    q["reasons"].append(reason)


def verify_set(receipts, context) -> dict:
    """Several receipts under one context, with the append-only rules of Section 10: a receipt id carried by two
    different contents is a mutation (S10-1, S7-4), a supersession never deletes its predecessor (S10-3), and a
    cycle of supersession is refused. READING: a receipt superseded by a valid successor stays valid historical
    evidence and no longer qualifies."""
    results = [verify(r, context) for r in receipts]
    findings = []
    by_id = {}
    for i, res in enumerate(results):
        rid = res["receipt"].get("receipt_id")
        if isinstance(rid, str):
            by_id.setdefault(rid, []).append(i)
    for rid, idxs in sorted(by_id.items()):
        if len({results[i]["payload_jcs_sha256"] for i in idxs}) > 1:
            findings.append({"code": "RECEIPT_MUTATED", "requirement": "S10-1", "receipt_id": rid,
                             "detail": "one receipt id carries different contents"})
            for i in idxs:
                results[i]["history"] = "mutated"
                _not_qualifying(results[i], "RECEIPT_MUTATED")
    nxt = {}
    for i, res in enumerate(results):
        pred = res["receipt"].get("supersedes")
        rid = res["receipt"].get("receipt_id")
        if isinstance(pred, str) and isinstance(rid, str):
            nxt.setdefault(rid, set()).add(pred)
            if pred not in by_id:
                findings.append({"code": "PREDECESSOR_NOT_PRESENTED", "requirement": "S10-3", "receipt_id": rid,
                                 "detail": f"{pred} is not among the receipts given; it is not taken as deleted"})
    for start in sorted(nxt):
        seen, cur = [], start
        while cur in nxt and cur not in seen:
            seen.append(cur)
            cur = sorted(nxt[cur])[0]
        if cur in seen:
            cyc = seen[seen.index(cur):]
            if min(cyc) == start:
                findings.append({"code": "SUPERSESSION_CYCLE", "requirement": "S10-2", "receipt_id": start,
                                 "detail": f"supersession returns to its start: {cyc}"})
                for i in (j for r in cyc for j in by_id.get(r, [])):
                    _not_qualifying(results[i], "SUPERSESSION_CYCLE")
    for i, res in enumerate(results):
        pred = res["receipt"].get("supersedes")
        if res["receipt_validity"] != "VALID" or not isinstance(pred, str):
            continue
        for j in by_id.get(pred, []):
            results[j].setdefault("superseded_by", []).append(res["receipt"]["receipt_id"])
            _not_qualifying(results[j], "SUPERSEDED")
    return {"receipts": results, "history": {"findings": findings,
                                             "retained": [r["receipt"].get("receipt_id") for r in results]}}
