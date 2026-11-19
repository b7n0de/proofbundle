"""Verifier for draft-gruszka-signed-evaluation-receipts-04, from its text alone.

verify(receipt_bytes, vk) runs the eleven steps of Section 5 in order and
returns a dict: result PASS | FAIL | RESOURCE_LIMIT | INPUT_ERROR, step,
rule (profile rule for step 11), which (key | R), reason, and B when steps
1 to 3 obtained it.
"""
import re
import sys
from decimal import Decimal

from gemeinsam import b64, ijson, jcs
from gemeinsam import ed25519 as E

TYPE = "application/vnd.signed-evidence.eval-receipt+json"          # Section 4.2
PAYLOAD_SCHEMA = "https://signed-evidence.org/eval-receipt/v1"       # Section 3.2
COMMIT_ALG = "sha256-salted-v1"                                      # Section 3.2/3.3

PAYLOAD_MEMBERS = ["schema", "suite", "suite_version", "metric", "comparator", "threshold",
                   "score", "passed", "n", "model_id_commit", "dataset_id_commit",
                   "commit_alg", "timestamp"]                         # Table 1
OPTIONAL = ["criteria_digest"]

DECIMAL = re.compile(r"\A-?(0|[1-9][0-9]*)(\.[0-9]+)?\Z", re.ASCII)
TIMESTAMP = re.compile(r"\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z\Z", re.ASCII)
DIGEST = re.compile(r"\Asha256:[0-9a-f]{64}\Z", re.ASCII)
SP = b" "


def pae(type_str, body):
    """Section 4.1."""
    t = type_str.encode("utf-8")
    return b"DSSEv1" + SP + str(len(t)).encode() + SP + t + SP + str(len(body)).encode() + SP + body


def _leap(y):
    # RFC 3339 Appendix C
    return y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)


def timestamp_ok(s):
    m = TIMESTAMP.match(s)
    if not m:
        return False
    y, mo, dd, hh, mi, ss = (int(g) for g in m.groups())
    if not 1 <= mo <= 12:
        return False
    mdays = [31, 29 if _leap(y) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]
    if not 1 <= dd <= mdays:
        return False
    return hh <= 23 and mi <= 59 and ss <= 59


def _fail(step, reason, **kw):
    r = {"result": "FAIL", "step": step, "reason": reason}
    r.update(kw)
    return r


def _nonempty(v):
    return isinstance(v, str) and len(v) >= 1


def check_payload_members(obj):
    """Step 6. Returns None or the reason."""
    names = obj.names()
    allowed = set(PAYLOAD_MEMBERS) | set(OPTIONAL)
    missing = [m for m in PAYLOAD_MEMBERS if m not in names]
    extra = [m for m in names if m not in allowed]
    if missing:
        return "member missing: %s" % missing
    if extra:
        return "member not in Table 1: %s" % extra
    v = obj.as_dict()
    if v["schema"] != PAYLOAD_SCHEMA:
        return "schema is not the payload schema identifier"
    for m in ("suite", "suite_version", "metric"):
        if not _nonempty(v[m]):
            return "%s is not a non-empty string" % m
    if v["comparator"] not in (">=", ">", "<=", "<") or not isinstance(v["comparator"], str):
        return "comparator not in the set"
    for m in ("threshold", "score"):
        if not (isinstance(v[m], str) and DECIMAL.match(v[m])):
            return "%s is not a decimal string" % m
    if not isinstance(v["passed"], bool):
        return "passed is not true or false"
    n = v["n"]
    if not isinstance(n, ijson.Num) or isinstance(n, bool):
        return "n is not a number"
    x = n.double
    if not (x == int(x) if x == x and abs(x) != float("inf") else False):
        return "n is not an integer"
    if not 1 <= int(x) <= 2**53 - 1:
        return "n outside 1 to 2^53 - 1"
    for m in ("model_id_commit", "dataset_id_commit"):
        if not isinstance(v[m], str):
            return "%s is not a string" % m
    if v["commit_alg"] != COMMIT_ALG:
        return "commit_alg is not sha256-salted-v1"
    if not (isinstance(v["timestamp"], str) and timestamp_ok(v["timestamp"])):
        return "timestamp not in the fixed form or not a valid date-time"
    if "criteria_digest" in v and not isinstance(v["criteria_digest"], str):
        return "criteria_digest is not a string"
    return None


def compare(score, comparator, threshold):
    a, b = Decimal(score), Decimal(threshold)
    return {">=": a >= b, ">": a > b, "<=": a <= b, "<": a < b}[comparator]


def obtain_B(receipt):
    """Steps 1 to 3. Returns (B, obj) or a FAIL/RESOURCE_LIMIT dict."""
    # Step 1
    try:
        top, issues = ijson.parse(receipt)
    except ijson.ResourceLimit as e:
        return {"result": "RESOURCE_LIMIT", "step": 1, "reason": str(e)}
    except ijson.JsonError as e:
        return _fail(1, "receipt: %s" % e)
    if issues:
        return _fail(1, "receipt: %s %s" % issues[0])
    if not isinstance(top, ijson.Obj) or sorted(top.names()) != ["payload_b64", "schema", "signature"]:
        return _fail(1, "top-level value is not an object with exactly schema, payload_b64, signature")
    sig = top.get("signature")
    if not isinstance(sig, ijson.Obj) or sorted(sig.names()) not in (["alg", "sig"], ["alg", "key", "sig"]):
        return _fail(1, "signature is not an object with exactly alg, sig (, key)")
    # Step 2
    if top.get("schema") != TYPE:
        return _fail(2, "schema is not the type of Section 4.2")
    # Step 3
    B, why = b64.std_decode_canonical(top.get("payload_b64"))
    if B is None:
        return _fail(3, "payload_b64: %s" % why)
    return B, top


def verify(receipt, vk):
    if not isinstance(vk, (bytes, bytearray)) or len(vk) != 32:
        return {"result": "INPUT_ERROR", "step": None, "reason": "verification key input is not 32 octets"}
    r = obtain_B(receipt)
    if isinstance(r, dict):
        return r
    B, top = r
    # Step 4
    try:
        payload, issues = ijson.parse(B)
    except ijson.ResourceLimit as e:
        return {"result": "RESOURCE_LIMIT", "step": 4, "reason": str(e), "B": B}
    except ijson.JsonError as e:
        return _fail(4, "B: %s" % e, B=B)
    if issues:
        return _fail(4, "B: %s %s" % issues[0], B=B)
    if not isinstance(payload, ijson.Obj):
        return _fail(4, "B is not an object", B=B)
    # Step 5
    try:
        canon = jcs.serialize(payload)
    except jcs.NotSerializable as e:
        return _fail(5, "B has no RFC 8785 serialization: %s" % e, B=B)
    if canon != B:
        return _fail(5, "B is not its own RFC 8785 serialization", B=B)
    # Step 6
    why = check_payload_members(payload)
    if why:
        return _fail(6, why, B=B)
    v = payload.as_dict()
    # Step 7
    for m in ("model_id_commit", "dataset_id_commit") + (("criteria_digest",) if "criteria_digest" in v else ()):
        if not DIGEST.match(v[m]):
            return _fail(7, "%s does not have the pattern sha256: + 64 lowercase hex digits" % m, B=B)
    # Step 8
    if v["passed"] != compare(v["score"], v["comparator"], v["threshold"]):
        return _fail(8, "passed differs from score %s threshold" % v["comparator"], B=B)
    s = top.get("signature")
    # Step 9
    if s.get("alg") != "ed25519":
        return _fail(9, "signature.alg is not ed25519", B=B)
    sigb, why = b64.std_decode_canonical(s.get("sig"))
    if sigb is None or len(sigb) != 64:
        return _fail(9, "signature.sig is not canonical base64 of 64 bytes (%s)" % (why or "%d bytes" % len(sigb)), B=B)
    # Step 10
    if "key" in s.names():
        kb, why = b64.std_decode_canonical(s.get("key"))
        if kb is None or kb != bytes(vk):
            return _fail(10, "signature.key is not the canonical base64 of the verification key", B=B)
    # Step 11
    ok, rule, which = E.verify_profile(bytes(vk), sigb, pae(TYPE, B))
    if not ok:
        return _fail(11, "signature invalid under the profile", rule=rule, which=which, B=B)
    return {"result": "PASS", "step": None, "reason": None, "B": B}


def step_label(r):
    """Format like Table 2: 'all', '4', '11 (profile 2, key)'."""
    if r["result"] == "PASS":
        return "all"
    if r["result"] != "FAIL":
        return r["result"]
    if r["step"] == 11:
        if r.get("which") in ("key", "R"):
            return "11 (profile %d, %s)" % (r["rule"], r["which"])
        return "11 (profile %d)" % r["rule"]
    return str(r["step"])


if __name__ == "__main__":
    data = open(sys.argv[1], "rb").read()
    key = bytes.fromhex(sys.argv[2])
    res = verify(data, key)
    res.pop("B", None)
    print(res)
