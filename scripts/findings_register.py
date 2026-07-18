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
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

REGISTER_REL = "audit_artifacts/findings_register_361.json"

# Pinned root of trust (committed): the ed25519 public key the register MUST be signed by. Rotating the key
# is a deliberate, reviewed change to THIS constant — a register signed by any other key fails closed.
PINNED_PUBKEY_B64 = "RJPyprKWbAUi0kTKNTLP6MESoz40dYNJDN1xxRNGv2o="

_GATING_SEVERITIES = {"P0", "P1"}


def _canonical_bytes(body: dict) -> bytes:
    from proofbundle import canonical  # noqa: PLC0415
    return canonical.canonicalize_statement(body)


def _signature_ok(register: dict) -> tuple[bool, str]:
    sig = register.get("signature")
    if not isinstance(sig, dict):
        return False, "register carries no signature block"
    if sig.get("alg") != "ed25519":
        return False, f"unexpected signature alg {sig.get('alg')!r}"
    pub_b64 = sig.get("public_key_b64")
    if pub_b64 != PINNED_PUBKEY_B64:
        return False, "register public key does not match the pinned root of trust"
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
    (a fail-open the Berkeley gate reproduced). Now a finding is legitimately superseded ONLY by a PRESENT,
    DIFFERENT id; a dangling/self supersession, a non-string/empty id, or a non-dict entry is an ANOMALY that
    is NEVER dropped (the caller fails closed on any anomaly), so no finding can vanish from the count."""
    ids_present = {f["id"] for f in findings
                   if isinstance(f, dict) and isinstance(f.get("id"), str) and f.get("id")}
    effective: dict[str, dict] = {}
    contradictions: list[str] = []
    anomalies: list[str] = []
    legit_superseded: set[str] = set()
    for idx, f in enumerate(findings):
        if not isinstance(f, dict):
            anomalies.append(f"index{idx}:non-dict-entry")
            continue
        fid = f.get("id")
        if not isinstance(fid, str) or not fid:
            anomalies.append(f"index{idx}:bad-id={fid!r}")
            continue
        sby = f.get("superseded_by")
        if isinstance(sby, str) and sby:
            if sby == fid or sby not in ids_present:
                anomalies.append(f"{fid}:dangling-or-self-supersede={sby!r}")  # do NOT drop, fail-closed
            else:
                legit_superseded.add(fid)
    for f in findings:
        if not isinstance(f, dict):
            continue
        fid = f.get("id")
        if not isinstance(fid, str) or not fid or fid in legit_superseded:
            continue
        if fid in effective and effective[fid].get("status") != f.get("status"):
            contradictions.append(fid)
        effective[fid] = f
    return effective, contradictions, anomalies, legit_superseded


def verify_and_count(repo: Path | str = REPO) -> dict:
    """Fail-closed verify + count. Returns a verdict dict; never raises on a bad register."""
    repo = Path(repo)
    path = repo / REGISTER_REL
    triple = {"population_size": 0, "evaluated_count": 0, "source_digest": None}
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
    sig_ok, sig_detail = _signature_ok(register)
    if not sig_ok:
        return {"ok": False, "reason": f"register signature invalid: {sig_detail} (fail-closed)",
                "open_ids": [], **triple, "source_digest": source_digest}
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
                       if str(f.get("severity", "")).strip().upper() in _GATING_SEVERITIES
                       and str(f.get("status", "")).strip().lower() != "closed")
    ok = not open_p0p1
    reason = ("0 open P0/P1 from the signed structured register "
              f"({evaluated_count} findings evaluated, {source_digest})") if ok \
        else f"{len(open_p0p1)} open P0/P1 still present: {open_p0p1}"
    return {"ok": ok, "reason": reason, "open_ids": open_p0p1, "population_size": population_size,
            "evaluated_count": evaluated_count, "source_digest": source_digest}


def main(argv=None) -> int:
    r = verify_and_count(REPO)
    print(json.dumps(r, indent=2, ensure_ascii=False))
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
