#!/usr/bin/env python3
"""Offline verifier for an example authority revocation receipt.

Needs Python 3 and one library: cryptography (Ed25519).

Usage:
  python3 verify_revocation.py RECEIPT --customer-key keys/customer.pub.pem \
      --provider-key keys/provider.pub.pem --authority-digest HEX \
      --agent-digest HEX --action-time 2026-11-25T10:15:00Z
  python3 verify_revocation.py --selftest [CASES_DIR]

Final verdict, one of four fixed words:
  VALID_PROVIDER_CONFIRMED  customer revocation valid, provider countersignature valid  (exit 0)
  VALID_CUSTOMER_ONLY       customer revocation valid, no countersignature present      (exit 3)
  INVALID                   any check failed                                           (exit 1)
  UNRESOLVED                every check passed, but revokedAt equals the action time   (exit 4)
Usage errors exit 2. VALID_CUSTOMER_ONLY is never a provider confirmation. UNRESOLVED is never a
revocation that covers the action: the two times come from two clocks, so equality shows no order.

The type names under https://signed-evidence.org/ are provisional.
"""
import base64
import datetime
import hashlib
import json
import os
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
REVOCATION_TYPE = "https://signed-evidence.org/predicates/authority-revocation/v0.1"
ACK_TYPE = "https://signed-evidence.org/predicates/authority-revocation-ack/v0.1"
TIME_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
)
HEX64_RE = re.compile(r"[0-9a-f]{64}")


class Bad(Exception):
    pass


# ---------- helpers ----------

def _no_dupes(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise Bad("duplicate member name " + k)
        obj[k] = v
    return obj


def _check_values(v):
    """Allow only the JSON subset this example uses, so canonical form is exact."""
    if isinstance(v, dict):
        for k, x in v.items():
            if not k.isascii():
                raise Bad("non-ASCII member name")
            _check_values(x)
    elif isinstance(v, list):
        for x in v:
            _check_values(x)
    elif isinstance(v, bool) or v is None or isinstance(v, str):
        pass
    elif isinstance(v, int):
        if abs(v) > 9007199254740991:
            raise Bad("integer out of range")
    else:
        raise Bad("number type not allowed in this example")


def parse_json(data):
    if data.startswith(b"\xef\xbb\xbf"):
        raise Bad("byte order mark")
    try:
        v = json.loads(data.decode("utf-8"), object_pairs_hook=_no_dupes)
    except (UnicodeDecodeError, ValueError) as e:
        raise Bad("not JSON: %s" % e)
    _check_values(v)
    return v


def canonical(v):
    """RFC 8785 for the subset allowed by _check_values (ASCII keys, no floats)."""
    _check_values(v)
    try:
        return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except UnicodeEncodeError:
        raise Bad("unpaired surrogate")


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


def strict_b64(s):
    if not isinstance(s, str) or len(s) % 4 != 0:
        raise Bad("base64 form")
    try:
        b = base64.b64decode(s, validate=True)
    except ValueError:
        raise Bad("base64 form")
    if base64.b64encode(b).decode("ascii") != s:
        raise Bad("base64 pad bits")
    return b


def pae(ptype, payload):
    t = ptype.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def key_id(pub):
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "sha256:" + sha256_hex(raw)


# Ed25519 point check after RFC 8032: decoding as in Section 5.1.3, point addition as in the
# reference code of Section 6 (extended coordinates X, Y, Z, T).
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _point_add(a, b):
    pa = (a[1] - a[0]) * (b[1] - b[0]) % _P
    pb = (a[1] + a[0]) * (b[1] + b[0]) % _P
    pc = 2 * a[3] * b[3] * _D % _P
    pd = 2 * a[2] * b[2] % _P
    e, f, g, hh = pb - pa, pd - pc, pd + pc, pb + pa
    return (e * f % _P, g * hh % _P, f * g % _P, e * hh % _P)


def _point_mul(s, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        s >>= 1
    return q


def _is_identity(p):
    return p[0] % _P == 0 and (p[1] - p[2]) % _P == 0


def key_point_ok(raw):
    """True only for a canonical encoding of a curve point of prime order L.

    Under the identity point or another point of small or mixed order, a signature can verify
    without the private key: the key 01 followed by 31 zero bytes accepts the signature 01
    followed by 63 zero bytes for every message. Such a key must not be used to check a receipt."""
    if not isinstance(raw, bytes) or len(raw) != 32:
        return False
    y = int.from_bytes(raw, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    if y >= _P:
        return False
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        if sign:
            return False
        x = 0
    else:
        x = pow(x2, (_P + 3) // 8, _P)
        if (x * x - x2) % _P != 0:
            x = x * _SQRT_M1 % _P
        if (x * x - x2) % _P != 0:
            return False
        if (x & 1) != sign:
            x = _P - x
    a = (x, y, 1, x * y % _P)
    return not _is_identity(a) and _is_identity(_point_mul(_L, a))


def load_pub(path):
    with open(path, "rb") as f:
        k = serialization.load_pem_public_key(f.read())
    if not isinstance(k, Ed25519PublicKey):
        raise Bad("key is not Ed25519: " + path)
    raw = k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if not key_point_ok(raw):  # LOCK key_form
        raise Bad("key is not an Ed25519 point of prime order: " + path)
    return k


def parse_time(s):
    if not isinstance(s, str) or not TIME_RE.fullmatch(s):  # LOCK time_form
        raise Bad("time form")
    try:
        datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise Bad("not a calendar time")
    return s


# ---------- envelope ----------

def open_envelope(env, pub, results, prefix):
    """Envelope form, signature and canonical payload for one DSSE envelope. Returns (statement, payload bytes) or None."""
    try:
        if not isinstance(env, dict):
            raise Bad("envelope is not an object")
        for m in ("payload", "payloadType", "signatures"):
            if m not in env:
                raise Bad("missing " + m)
        if not env["payloadType"] == PAYLOAD_TYPE:  # LOCK payload_type
            raise Bad("payloadType")
        if not isinstance(env["signatures"], list) or not all(
                isinstance(s, dict) and isinstance(s.get("sig"), str) for s in env["signatures"]):
            raise Bad("signatures form")
        payload = strict_b64(env["payload"])
    except Bad as e:
        results.append((prefix + "envelope", "FAIL", str(e)))
        return None
    results.append((prefix + "envelope", "PASS", ""))

    msg = pae(PAYLOAD_TYPE, payload)
    good = False
    for s in env["signatures"]:
        try:
            pub.verify(strict_b64(s["sig"]), msg)
            good = True
        except (Bad, InvalidSignature, ValueError):
            pass
    if not good:  # LOCK signature
        results.append((prefix + "signature", "FAIL", "no signature verifies under the expected key"))
        return None
    results.append((prefix + "signature", "PASS", ""))

    try:
        st = parse_json(payload)
        if not canonical(st) == payload:  # LOCK canonical
            raise Bad("payload is not in canonical form")
    except Bad as e:
        results.append((prefix + "canonical", "FAIL", str(e)))
        return None
    results.append((prefix + "canonical", "PASS", ""))
    return st, payload


def check_statement(st, ptype, results, prefix):
    try:
        if not isinstance(st, dict):
            raise Bad("statement is not an object")
        if not st.get("_type") == STATEMENT_TYPE:  # LOCK statement_type
            raise Bad("_type")
        if not st.get("predicateType") == ptype:  # LOCK predicate_type
            raise Bad("predicateType")
        pred = st.get("predicate")
        if not isinstance(pred, dict):
            raise Bad("predicate is not an object")
        subj = st.get("subject")
        if not isinstance(subj, list) or len(subj) != 1 or not isinstance(subj[0], dict) \
                or not isinstance(subj[0].get("digest"), dict):
            raise Bad("subject must have exactly one entry with a digest")
        if not subj[0]["digest"].get("sha256") == sha256_hex(canonical(pred)):  # LOCK subject_digest
            raise Bad("subject digest does not match predicate")
    except Bad as e:
        results.append((prefix + "statement", "FAIL", str(e)))
        return None
    results.append((prefix + "statement", "PASS", ""))
    return pred


# ---------- main check ----------

def verify(bundle_bytes, customer_pub, provider_pub, authority_digest, agent_digest, action_time):
    results = []

    def done(verdict):
        return verdict, results

    try:
        bundle = parse_json(bundle_bytes)
        if not isinstance(bundle, dict) or "revocation" not in bundle:
            raise Bad("bundle needs member revocation")
        extra = set(bundle) - {"revocation", "countersignature"}
        if extra:
            raise Bad("unknown bundle members " + ",".join(sorted(extra)))
    except Bad as e:
        results.append(("bundle", "FAIL", str(e)))
        return done("INVALID")
    results.append(("bundle", "PASS", ""))

    # customer revocation
    opened = open_envelope(bundle["revocation"], customer_pub, results, "revocation.")
    if opened is None:
        return done("INVALID")
    st, payload = opened
    pred = check_statement(st, REVOCATION_TYPE, results, "revocation.")
    if pred is None:
        return done("INVALID")

    rv = pred.get("revoker") if isinstance(pred.get("revoker"), dict) else {}
    au = pred.get("authority") if isinstance(pred.get("authority"), dict) else {}
    ag = pred.get("agent") if isinstance(pred.get("agent"), dict) else {}
    try:
        revoked_at = parse_time(pred.get("revokedAt"))
    except Bad:
        revoked_at = None
    failed = False

    def mark(name, ok):
        results.append(("revocation." + name, "PASS" if ok else "FAIL", ""))
        return not ok

    ok = True
    if not (rv.get("role") == "customer"):  # LOCK revoker_role
        ok = False
    failed |= mark("revoker_role", ok)
    ok = True
    if not (rv.get("keyId") == key_id(customer_pub)):  # LOCK revoker_key
        ok = False
    failed |= mark("revoker_key", ok)
    ok = True
    if not (au.get("digestAlgorithm") == "jcs-sha256-v1" and au.get("digest") == authority_digest):  # LOCK authority_match
        ok = False
    failed |= mark("authority_match", ok)
    ok = True
    if not (ag.get("digestAlgorithm") == "jcs-sha256-v1" and ag.get("digest") == agent_digest):  # LOCK agent_match
        ok = False
    failed |= mark("agent_match", ok)
    ok = True
    if not (revoked_at is not None and revoked_at <= action_time):  # LOCK covers_action
        ok = False
    # revokedAt is the customer's statement and the action time is the caller's record: two clocks. Where the two
    # seconds are equal, nothing here shows which came first, so the receipt neither covers nor misses the action.
    tie = ok and revoked_at == action_time
    if tie:  # LOCK equal_times_unresolved
        results.append(("revocation.covers_action", "UNRESOLVED",
                        "revokedAt equals the action time; they come from two clocks, so their order is not shown"))
    else:
        failed |= mark("covers_action", ok)
    if failed:
        return done("INVALID")
    if tie:
        return done("UNRESOLVED")

    # provider countersignature
    if "countersignature" not in bundle:
        results.append(("countersignature", "ABSENT", "customer-signed only, no provider confirmation"))
        return done("VALID_CUSTOMER_ONLY")

    opened = open_envelope(bundle["countersignature"], provider_pub, results, "countersignature.")
    if opened is None:
        return done("INVALID")
    cst, _ = opened
    cpred = check_statement(cst, ACK_TYPE, results, "countersignature.")
    if cpred is None:
        return done("INVALID")
    rd = cpred.get("revocationDigest") if isinstance(cpred.get("revocationDigest"), dict) else {}
    if not (rd.get("digestAlgorithm") == "jcs-sha256-v1" and rd.get("digest") == sha256_hex(payload)):  # LOCK binds_revocation
        results.append(("countersignature.binds_revocation", "FAIL", "digest names another revocation"))
        return done("INVALID")
    results.append(("countersignature.binds_revocation", "PASS", ""))
    ak = cpred.get("acknowledger") if isinstance(cpred.get("acknowledger"), dict) else {}
    if not (ak.get("role") == "provider" and ak.get("keyId") == key_id(provider_pub)):  # LOCK acknowledger
        results.append(("countersignature.acknowledger", "FAIL", ""))
        return done("INVALID")
    results.append(("countersignature.acknowledger", "PASS", ""))
    try:
        received_at = parse_time(cpred.get("receivedAt"))
    except Bad:
        received_at = None
    if not (received_at is not None and received_at >= revoked_at):  # LOCK time_order
        results.append(("countersignature.time_order", "FAIL", "receivedAt before revokedAt"))
        return done("INVALID")
    results.append(("countersignature.time_order", "PASS", ""))
    return done("VALID_PROVIDER_CONFIRMED")


EXIT = {"VALID_PROVIDER_CONFIRMED": 0, "VALID_CUSTOMER_ONLY": 3, "INVALID": 1, "UNRESOLVED": 4}


def run_one(path, customer_key, provider_key, authority_digest, agent_digest, action_time):
    for name, h in (("authority-digest", authority_digest), ("agent-digest", agent_digest)):
        if not isinstance(h, str) or not HEX64_RE.fullmatch(h):  # LOCK digest_form
            raise Bad("--%s must be 64 lowercase hex characters" % name)
    parse_time(action_time)
    with open(path, "rb") as f:
        data = f.read()
    return verify(data, load_pub(customer_key), load_pub(provider_key),
                  authority_digest, agent_digest, action_time)


def selftest(base):
    """Run every case in expected.json, compare actual and expected, exit 0 only if all match.

    A case may set its own customerKey, providerKey, actionTime, authorityDigest or agentDigest.
    An input that the command line would refuse with exit 2 gives the verdict USAGE_ERROR here, with
    the first non-PASS check "arguments"."""
    with open(os.path.join(base, "cases", "expected.json"), "rb") as f:
        exp = json.loads(f.read())
    common = exp["inputs"]
    bad = 0
    for case in exp["cases"]:
        try:
            verdict, results = run_one(os.path.join(base, case["file"]),
                                       os.path.join(base, case.get("customerKey", common["customerKey"])),
                                       os.path.join(base, case.get("providerKey", common["providerKey"])),
                                       case.get("authorityDigest", common["authorityDigest"]),
                                       case.get("agentDigest", common["agentDigest"]),
                                       case.get("actionTime", common["actionTime"]))
        except Bad as e:
            verdict, results = "USAGE_ERROR", [("arguments", "FAIL", str(e))]
        failing = [n for n, r, _ in results if r != "PASS"]
        first = failing[0] if failing else None
        ok = verdict == case["verdict"] and first == case["firstNonPass"]
        bad += not ok
        print("%-4s %-44s want %-24s got %-24s at %s" % (
            "OK" if ok else "DIFF", case["file"], case["verdict"], verdict, first))
    print("cases %d, mismatches %d" % (len(exp["cases"]), bad))
    return 0 if bad == 0 else 1


def main(argv):
    if argv[:1] == ["--selftest"]:
        base = argv[1] if len(argv) > 1 else os.path.dirname(os.path.abspath(__file__))
        return selftest(base)
    import argparse
    p = argparse.ArgumentParser(description="Verify an example authority revocation receipt.")
    p.add_argument("receipt")
    p.add_argument("--customer-key", required=True)
    p.add_argument("--provider-key", required=True)
    p.add_argument("--authority-digest", required=True)
    p.add_argument("--agent-digest", required=True)
    p.add_argument("--action-time", required=True, help="UTC, form 2026-11-25T10:15:00Z")
    a = p.parse_args(argv)
    try:
        verdict, results = run_one(a.receipt, a.customer_key, a.provider_key,
                                   a.authority_digest, a.agent_digest, a.action_time)
    except (Bad, OSError, ValueError) as e:
        print("usage error: %s" % e)
        return 2
    for name, res, note in results:
        print("%-40s %-6s %s" % (name, res, note))
    print("VERDICT", verdict)
    if verdict == "VALID_CUSTOMER_ONLY":
        print("customer-signed only: the provider has not confirmed this revocation")
    return EXIT[verdict]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
