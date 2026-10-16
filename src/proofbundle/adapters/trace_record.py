"""Offline verification of TRACE v0.2 Trust Records, independent of the TRACE reference code.

WHAT THIS IS. TRACE (Trust, Runtime Attestation, and Compliance Evidence, agentrust-io/trace-spec,
specification under the Community Specification License 1.0) defines the Trust Record: a signed
governance record for one AI agent run. This module checks such a record against trust material the
RELYING PARTY brings: the record-signing key, the policy bundle hash it expects, the workload
identities it accepts, the transcript hash it holds, a challenge nonce and the time window. Nothing
the record says about itself is trusted before its signature verified under a key the caller pinned.

WRITTEN FROM THE SPECIFICATION, NOT FROM THE REFERENCE. The rules below were read from
``spec/trace-v0.2.md`` and ``schema/trace-claim.json`` of agentrust-io/trace-spec at commit
``a131c6400eaa95007b16b84a96331ccf37a93b73`` (2026-10-16; schema SHA-256 in :data:`SPEC_PIN`). No
code of the ``agentrust-trace`` package or of the ``trace-tests`` suite is imported or copied, and the
tests of this module import neither. A second reading of a foreign format is only worth something
while it stays a second reading.

TWO BINDING FORMS, both named in section 3.2.2 of the specification:

* ``jws-compact``: an RFC 7515 compact JWS whose payload is the record (section 3.2, "Envelope: EAT
  ... JWT"). ``alg`` is ``ES256``, ``ES384`` or ``EdDSA`` (section 3.2.1) and nothing else; ``none``
  is refused before anything else is read. The payload bytes must be the RFC 8785 form of the
  record, because section 3.2.2 binds the signature to the canonical form, and a JWS signs the
  payload bytes as transmitted. The record carries no ``signature`` member in this form.
* ``embedded``: a JSON object with a top-level ``signature`` member, an Ed25519 signature in
  canonical unpadded base64url over the RFC 8785 form of the record without that member. This is the
  form the TRACE reference library and conformance suite produce. The specification fixes no
  encoding for an embedded ECDSA signature, so only an Ed25519 key is tried in this form, and a
  relying party holding only EC keys is told so (exit 2), not handed a cryptographic failure.

WHAT A PASS MEANS. A pass says: the record is well formed under the pinned schema and the rules of
the specification this module implements, it was signed by a key the relying party trusts, that key
is the record's own ``cnf`` key, the record is fresh in the relying party's window, and every
expectation the relying party supplied holds. It does NOT say the record is true. Section 3.3 lists
eight verification steps; steps 3, 4, 6, 7 and 8 need evidence a record does not carry (a silicon
root, reference integrity manifests, a SCITT receipt, SLSA provenance, a revocation bundle) and are
not performed here. They are named in every verdict (:data:`NOT_CHECKED`), and the automation verdict
therefore never reads safe: a verified record is evidence FOR a relying party's policy, never a
positive decision on its own.

EXIT CODES follow the house contract the AGT adapter uses: 0 verified; 1 a cryptographic or
structural failure; 2 input that could not be read under this profile, or relying-party trust
material that is itself unusable; 3 the record is cryptographically and structurally sound but a
relying-party requirement (time window, nonce, policy hash, subject, transcript hash) is not met.
"""
from __future__ import annotations

import hmac
import math
import re
import time
from dataclasses import dataclass, field
from ipaddress import IPv6Address
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .._strict_json import loads_strict
from .._wire_b64 import decode_b64url
from ..automation_verdict import automation_summary
from ..budget import DEFAULT_BUDGET
from ..errors import ProofBundleError, VerificationResult
from ..signature import ed25519_trust_anchor_weakness, verify_ecdsa_p256, verify_ed25519_pinned

__all__ = [
    "NOT_CHECKED",
    "SPEC_PIN",
    "TRACE_PROFILE_V0_2",
    "TraceVerdict",
    "exit_code",
    "jwk_thumbprint",
    "verify_trace_record",
]

#: The profile URI of a TRACE v0.2 record ("Changes from v0.1"; section 3.2).
TRACE_PROFILE_V0_2 = "tag:agentrust-io.com,2026:trace-v0.2"

#: The superseded v0.1 identifier. Named only so its refusal can say why: the cutover is "cutover,
#: not coexistence", and a v0.2 verifier MUST reject it ("Changes from v0.1").
_TRACE_PROFILE_V0_1 = "tag:agentrust.io,2026:trace-v0.1"

#: The profiles this module implements. A relying party may narrow the accepted set, never widen it
#: (section 3.3, verifier profile compatibility: an unimplemented profile in the declaration MUST be
#: refused).
_IMPLEMENTED_PROFILES = frozenset({TRACE_PROFILE_V0_2})

#: The revision this module was written against. The specification asks a conformance claim to name
#: the exact revision and the schema digest ("Authority and conformance claims").
SPEC_PIN: Dict[str, str] = {
    "repository": "https://github.com/agentrust-io/trace-spec",
    "commit": "a131c6400eaa95007b16b84a96331ccf37a93b73",
    "document": "spec/trace-v0.2.md",
    "schema": "schema/trace-claim.json",
    "schema_sha256": "289293315d5a480cebcb8962b4d2937738421040e4bb8dcd13c1540073443ae5",
}

#: Section 3.3 steps and section 3.2.3 obligations this module does not perform, in every verdict.
NOT_CHECKED: Tuple[str, ...] = (
    "3.3 step 3: signature chain to a known silicon root",
    "3.3 step 4: runtime measurements against published reference integrity manifests",
    "3.3 step 6: SCITT receipt on the named transparency log",
    "3.3 step 7: SLSA provenance to a trusted builder",
    "3.3 step 8 and 3.2.3: record-signing key revocation (no revocation bundle consumed, so no "
    "revocation check was performed)",
    "3.1.3: delegation chain (no parent record is resolved)",
    "3.1.2: references are pointers and are never resolved or treated as evidence",
)

#: JCS safe-integer bound (section 3.2.2, raised from a SHOULD in RFC 8785 Appendix B to a MUST).
_SAFE_INT = 9007199254740991

#: JWS algorithms of section 3.2.1, with the key type, curve and raw signature length each needs.
_ALGS: Dict[str, Tuple[str, str, int]] = {
    "EdDSA": ("OKP", "Ed25519", 64),
    "ES256": ("EC", "P-256", 64),
    "ES384": ("EC", "P-384", 96),
}

#: Coordinate length in bytes per curve (RFC 7518 section 6.2.1.2: the full coordinate size).
_CURVE_BYTES = {"Ed25519": 32, "P-256": 32, "P-384": 48}

#: Protected-header members this profile reads. Anything else is refused and reported by name: a
#: header member nobody reads is a member whose meaning two verifiers can disagree on (``b64``
#: changes the signing input, ``jwk``/``x5c``/``jku`` offer a key, ``crit`` demands an extension).
_HEADER_MEMBERS = frozenset({"alg", "typ", "kid"})

#: Private-key members (RFC 7517/7518). A trusted key or a ``cnf.jwk`` carrying one is refused.
_PRIVATE_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "k")

#: Check names whose failure means the input or the trust material could not be used (exit 2).
_UNREADABLE = frozenset({"verifier-config", "readable", "jws-header"})
#: Check names whose failure is cryptographic or structural (exit 1).
_INTEGRITY = frozenset({"signature", "cnf-binding", "canonical-payload", "profile", "structure"})


# --------------------------------------------------------------------------------------------
# Small readers. Every value below comes from a strict parse, so it is one of the exact JSON
# types; the readers still test the exact type, because `bool` is an `int` in Python and not a
# number in JSON.
# --------------------------------------------------------------------------------------------

def _is_int_value(v: Any) -> bool:
    """A JSON number whose value is an integer. Decided by value, not by spelling (section 3.2.2,
    "What counts as an integer"; JSON Schema 2020-12 Validation section 6.1.1): ``1785000000.0`` and
    ``1.785e9`` are the integer 1785000000."""
    if type(v) is int:
        return True
    return type(v) is float and math.isfinite(v) and v.is_integer()


def _int_value(v: Any) -> int:
    return int(v)


def _member_path(base: str, key: str) -> str:
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        return f"{base}.{key}" if base else key
    escaped = key.encode("unicode_escape").decode("ascii").replace('"', '\\"')
    return f'{base}["{escaped}"]'


def _canonicalizable(v: Any, path: str) -> Optional[str]:
    """Why ``v`` has no RFC 8785 form under section 3.2.2, or None. Iterative, so a deep value
    cannot exhaust the stack here (the parser already bounds depth)."""
    stack: List[Tuple[Any, str]] = [(v, path)]
    while stack:
        cur, p = stack.pop()
        t = type(cur)
        if t is float:
            if not math.isfinite(cur):
                return f"{p or '<record>'}: {cur!r} is not a JSON number (no RFC 8785 form)"
            if cur.is_integer() and abs(cur) > _SAFE_INT:
                return (f"{p or '<record>'}: the integer value {cur!r} is outside "
                        f"-{_SAFE_INT}..{_SAFE_INT} (section 3.2.2)")
        elif t is int:
            if abs(cur) > _SAFE_INT:
                return f"{p or '<record>'}: the integer is outside -{_SAFE_INT}..{_SAFE_INT} (section 3.2.2)"
        elif t is dict:
            for k, val in cur.items():
                stack.append((val, _member_path(p, k)))
        elif t is list:
            for i, val in enumerate(cur):
                stack.append((val, f"{p}[{i}]"))
    return None


def _jcs(obj: Any) -> bytes:
    import rfc8785  # noqa: PLC0415 - a core dependency, imported where it is used

    return rfc8785.dumps(obj)


def _parse_json_bytes(raw: bytes, what: str) -> Any:
    """UTF-8 strictly (RFC 8259 section 8.1), then the package's duplicate-refusing parser."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _Unreadable(f"{what} is not UTF-8: {exc}") from None
    try:
        return loads_strict(text)
    except (ProofBundleError, ValueError) as exc:
        raise _Unreadable(f"{what} is not strict JSON: {exc}") from None


class _Unreadable(Exception):
    """Internal: the input cannot be read under this profile (exit 2)."""


# --------------------------------------------------------------------------------------------
# Keys.
# --------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class _Key:
    kty: str
    crv: str
    raw: bytes          # Ed25519: 32 bytes; EC: the SEC1 uncompressed point
    thumbprint: str


def _b64url_field(jwk: Dict[str, Any], name: str, length: int) -> bytes:
    value = jwk.get(name)
    if type(value) is not str:
        raise ValueError(f"member {name!r} must be a base64url string")
    try:
        raw = decode_b64url(value)
    except ValueError:
        raise ValueError(f"member {name!r} is not canonical unpadded base64url") from None
    if len(raw) != length:
        raise ValueError(f"member {name!r} decodes to {len(raw)} bytes, expected {length}")
    return raw


def _thumbprint(kty: str, crv: str, x: str, y: Optional[str]) -> str:
    """RFC 7638 thumbprint over the required members, lexicographic order, no whitespace. Every
    member is ASCII here (fixed names, canonical base64url values), so the JSON is written directly."""
    import base64  # noqa: PLC0415
    import hashlib  # noqa: PLC0415

    if kty == "OKP":
        doc = '{"crv":"%s","kty":"OKP","x":"%s"}' % (crv, x)
    else:
        doc = '{"crv":"%s","kty":"EC","x":"%s","y":"%s"}' % (crv, x, y)
    return base64.urlsafe_b64encode(hashlib.sha256(doc.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


def _parse_public_jwk(jwk: Any) -> _Key:
    """A public OKP/Ed25519, EC/P-256 or EC/P-384 key from a JWK. Raises ValueError naming why not."""
    if type(jwk) is not dict:
        raise ValueError("a JWK must be a JSON object")
    present = [m for m in _PRIVATE_MEMBERS if m in jwk]
    if present:
        raise ValueError(f"the JWK carries private-key member(s) {present}; only public keys are accepted")
    kty, crv = jwk.get("kty"), jwk.get("crv")
    if kty == "OKP" and crv == "Ed25519":
        raw = _b64url_field(jwk, "x", 32)
        weakness = ed25519_trust_anchor_weakness(raw)
        if weakness is not None:
            raise ValueError(f"the Ed25519 key is {weakness} and cannot anchor trust")
        return _Key("OKP", "Ed25519", raw, _thumbprint("OKP", "Ed25519", jwk["x"], None))
    if kty == "EC" and crv in ("P-256", "P-384"):
        n = _CURVE_BYTES[crv]
        point = b"\x04" + _b64url_field(jwk, "x", n) + _b64url_field(jwk, "y", n)
        curve = ec.SECP256R1() if crv == "P-256" else ec.SECP384R1()
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(curve, point)
        except ValueError:
            raise ValueError(f"the {crv} point is not on the curve") from None
        return _Key("EC", crv, point, _thumbprint("EC", crv, jwk["x"], jwk["y"]))
    raise ValueError(f"unsupported key type kty={kty!r} crv={crv!r}; supported: OKP/Ed25519, EC/P-256, EC/P-384")


def jwk_thumbprint(jwk: Any) -> str:
    """RFC 7638 thumbprint of a public Ed25519, P-256 or P-384 JWK. Raises ValueError otherwise."""
    return _parse_public_jwk(jwk).thumbprint


def _verify_es384(point: bytes, signature: bytes, message: bytes) -> bool:
    """ECDSA P-384 with SHA-384 over a raw ``R || S`` signature (RFC 7518 section 3.4). Never raises."""
    if len(point) != 97 or point[:1] != b"\x04" or len(signature) != 96:
        return False
    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), point)
        r = int.from_bytes(signature[:48], "big")
        s = int.from_bytes(signature[48:], "big")
        pub.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA384()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _signature_valid(alg: str, key: _Key, signature: bytes, message: bytes) -> bool:
    if alg == "EdDSA":
        return verify_ed25519_pinned(key.raw, signature, message)
    if alg == "ES256":
        return verify_ecdsa_p256(key.raw, signature, message)
    if alg == "ES384":
        return _verify_es384(key.raw, signature, message)
    return False


# --------------------------------------------------------------------------------------------
# Structure: the pinned schema, re-derived. Violations are collected, not stopped at the first,
# and every member the schema does not name is reported by path.
# --------------------------------------------------------------------------------------------

_DIGEST = re.compile(r"sha(?:256:[0-9a-f]{64}|384:[0-9a-f]{96})")
# ECMA-262 `.` matches anything but a line terminator; `[^/]` matches line terminators too.
_LINE = "[^\n\r  ]"
_SUBJECT = re.compile(rf"(?:spiffe://[^/]+/{_LINE}+|did:[a-z0-9]+:{_LINE}+)")
_RETENTION = re.compile(
    r"P(?:[0-9]+W|(?:[0-9]+Y(?:[0-9]+M)?(?:[0-9]+D)?|[0-9]+M(?:[0-9]+D)?|[0-9]+D)"
    r"(?:T(?:[0-9]+H(?:[0-9]+M)?(?:[0-9]+S)?|[0-9]+M(?:[0-9]+S)?|[0-9]+S))?"
    r"|T(?:[0-9]+H(?:[0-9]+M)?(?:[0-9]+S)?|[0-9]+M(?:[0-9]+S)?|[0-9]+S))")
_SIGNATURE = re.compile(r"(?:[A-Za-z0-9_-]{1,85}|[A-Za-z0-9_-]{85}[AQgw]|[A-Za-z0-9_-]{87,})")
_PCR = re.compile(r"pcr:(?:[0-9]|1[0-9]|2[0-3])")

# RFC 3986 section 3, an absolute URI ("format": "uri" in JSON Schema 2020-12 section 7.3.5).
_U = r"A-Za-z0-9\-._~"
_S = r"!$&'()*+,;="
_PCT = r"%[0-9A-Fa-f]{2}"
_PCHAR = rf"(?:[{_U}{_S}:@]|{_PCT})"
_AUTHORITY = (rf"(?:(?:[{_U}{_S}:]|{_PCT})*@)?"
              rf"(?:\[[{_U}{_S}:]+\]|(?:[{_U}{_S}]|{_PCT})*)"
              r"(?::[0-9]*)?")
_HIER = (rf"(?://{_AUTHORITY}(?:/{_PCHAR}*)*"
         rf"|/(?:{_PCHAR}+(?:/{_PCHAR}*)*)?"
         rf"|{_PCHAR}+(?:/{_PCHAR}*)*"
         r"|)")
_URI = re.compile(rf"[A-Za-z][A-Za-z0-9+\-.]*:{_HIER}(?:\?(?:{_PCHAR}|[/?])*)?(?:#(?:{_PCHAR}|[/?])*)?")
_IPV_FUTURE = re.compile(rf"[vV][0-9A-Fa-f]+\.[{_U}{_S}:]+")


def _is_uri(v: str) -> bool:
    if _URI.fullmatch(v) is None:
        return False
    m = re.match(r"[A-Za-z][A-Za-z0-9+\-.]*://([^/?#]*)", v)
    if m is not None:
        host = m.group(1).rsplit("@", 1)[-1]
        if host.startswith("["):
            literal = host[1:host.index("]")]
            if literal[:1] in ("v", "V"):
                return _IPV_FUTURE.fullmatch(literal) is not None
            try:
                IPv6Address(literal)
            except ValueError:
                return False
    return True


class _Findings:
    def __init__(self) -> None:
        self.violations: List[str] = []
        self.unknown: List[Tuple[str, bool]] = []

    def bad(self, path: str, message: str) -> None:
        self.violations.append(f"{path or '<record>'}: {message}")

    def extra(self, path: str, permitted: bool) -> None:
        self.unknown.append((path, permitted))
        if not permitted:
            self.violations.append(f"{path}: member not defined by the TRACE v0.2 schema")


def _string(v: Any, p: str, f: _Findings, *, min_len: int = 0) -> bool:
    if type(v) is not str:
        f.bad(p, "must be a string")
        return False
    if len(v) < min_len:
        f.bad(p, f"must be at least {min_len} character(s)")
        return False
    return True


def _pattern(rx: "re.Pattern[str]", name: str):
    def check(v: Any, p: str, f: _Findings) -> None:
        if _string(v, p, f) and rx.fullmatch(v) is None:
            f.bad(p, f"does not match the {name} pattern")
    return check


def _enum(values: Sequence[str]):
    def check(v: Any, p: str, f: _Findings) -> None:
        if type(v) is not str or v not in values:
            f.bad(p, f"must be one of {list(values)}")
    return check


def _integer(lo: int, hi: int):
    def check(v: Any, p: str, f: _Findings) -> None:
        if not _is_int_value(v):
            f.bad(p, "must be an integer")
        elif not lo <= _int_value(v) <= hi:
            f.bad(p, f"must be within {lo}..{hi}")
    return check


def _str_check(min_len: int = 0):
    def check(v: Any, p: str, f: _Findings) -> None:
        _string(v, p, f, min_len=min_len)
    return check


def _uri(v: Any, p: str, f: _Findings) -> None:
    if _string(v, p, f) and not _is_uri(v):
        f.bad(p, "is not an RFC 3986 URI")


_digest = _pattern(_DIGEST, "digest")


def _object(v: Any, p: str, f: _Findings, required: Sequence[str], props: Dict[str, Any],
            extra: Any = None) -> bool:
    if type(v) is not dict:
        f.bad(p, "must be an object")
        return False
    for name in required:
        if name not in v:
            f.bad(_member_path(p, name), "required member is missing")
    for name, value in v.items():
        mp = _member_path(p, name)
        if name in props:
            props[name](value, mp, f)
        elif extra is not None:
            f.extra(mp, True)
            extra(value, mp, f)
        else:
            f.extra(mp, False)
    return True


def _array_of(item):
    def check(v: Any, p: str, f: _Findings) -> None:
        if type(v) is not list:
            f.bad(p, "must be an array")
            return
        for i, value in enumerate(v):
            item(value, f"{p}[{i}]", f)
    return check


def _model(v: Any, p: str, f: _Findings) -> None:
    _object(v, p, f, ("provider", "model_id"), {
        "provider": _str_check(), "model_id": _str_check(), "version": _str_check(),
        "weights_digest": _digest, "aibom_uri": _uri})


_PLATFORMS = ("intel-tdx", "amd-sev-snp", "azure-cvm-sev-snp", "nvidia-h100", "nvidia-blackwell",
              "aws-nitro", "arm-cca", "google-confidential-space", "tpm2", "software-only")


def _runtime(v: Any, p: str, f: _Findings) -> None:
    _object(v, p, f, ("platform", "measurement"), {
        "platform": _enum(_PLATFORMS), "measurement": _digest, "rim_uri": _uri,
        "nonce": _str_check(), "firmware_version": _str_check()})


def _policy(v: Any, p: str, f: _Findings) -> None:
    _object(v, p, f, ("bundle_hash", "enforcement_mode"), {
        "bundle_hash": _digest, "enforcement_mode": _enum(("enforce", "advisory", "silent", "declared")),
        "version": _str_check(), "policy_uri": _uri})


def _tool_transcript(v: Any, p: str, f: _Findings) -> None:
    _object(v, p, f, ("hash",), {
        "hash": _digest, "call_count": _integer(0, _SAFE_INT), "transcript_uri": _uri})


def _delegation(v: Any, p: str, f: _Findings) -> None:
    _object(v, p, f, ("parent_record_hash", "credential_id"), {
        "parent_record_hash": _digest, "credential_id": _str_check(1)})


def _origin(v: Any, p: str, f: _Findings) -> None:
    _object(v, p, f, ("kind", "producer"), {
        "kind": _enum(("self", "third-party-control-plane", "log-import")),
        "producer": _str_check(1), "source_event_id": _str_check(1),
        "ingested_at": _integer(1700000000, _SAFE_INT)})


def _reference(v: Any, p: str, f: _Findings) -> None:
    _object(v, p, f, ("rel", "id", "resolver"), {
        "rel": _str_check(1), "id": _str_check(1), "resolver": _str_check(1),
        "retention": _pattern(_RETENTION, "ISO 8601 duration"), "digest": _digest})


def _closure_entry(v: Any, p: str, f: _Findings) -> None:
    _object(v, p, f, ("id", "digest", "resolver"), {
        "id": _str_check(1), "digest": _digest, "resolver": _str_check(1)})


def _reproducibility(v: Any, p: str, f: _Findings) -> None:
    _object(v, p, f, ("function", "code_identity", "input_closure", "transcript_digest"), {
        "function": _str_check(1), "code_identity": _digest, "code_resolver": _str_check(1),
        "input_closure": _array_of(_closure_entry), "transcript_digest": _digest})


_DEPTHS = ("surface", "builder", "transitive")


def _build_provenance(v: Any, p: str, f: _Findings) -> None:
    _object(v, p, f, ("slsa_level", "digest"), {
        "slsa_level": _integer(0, 3), "builder": _str_check(), "digest": _digest,
        "provenance_uri": _uri, "provenance_depth": _enum(_DEPTHS)})


def _re_execution(v: Any, p: str, f: _Findings) -> None:
    if not _object(v, p, f, ("outcome",), {
            "outcome": _enum(("reproduced", "diverged", "not-attempted")),
            "observed_digest": _digest, "reason": _str_check(1),
            "verifier_code_identity": _digest}):
        return
    if v.get("outcome") == "diverged" and "observed_digest" not in v:
        f.bad(_member_path(p, "observed_digest"), "required when outcome is diverged")
    if v.get("outcome") == "not-attempted" and "reason" not in v:
        f.bad(_member_path(p, "reason"), "required when outcome is not-attempted")


def _layer(v: Any, p: str, f: _Findings) -> None:
    if not _object(v, p, f, ("outcome",), {
            "outcome": _enum(("established", "not-established")),
            "reason": _enum(("layer-not-measured", "measured-not-appraised",
                             "evidence-spans-multiple-boots"))}):
        return
    if "outcome" in v and v.get("outcome") == "not-established":
        if "reason" not in v:
            f.bad(_member_path(p, "reason"), "required when outcome is not-established")
    elif "reason" in v:
        f.bad(_member_path(p, "reason"), "must be absent unless outcome is not-established")


def _layers(v: Any, p: str, f: _Findings) -> None:
    if type(v) is not dict:
        f.bad(p, "must be an object")
        return
    if len(v) < 1:
        f.bad(p, "must name at least one layer")
    for name, value in v.items():
        _layer(value, _member_path(p, name), f)


def _platform_measurement(v: Any, p: str, f: _Findings) -> None:
    _object(v, p, f, ("measurement", "layers"), {"measurement": _digest, "layers": _layers})


def _appraisal(v: Any, p: str, f: _Findings) -> None:
    if not _object(v, p, f, ("status", "verifier"), {
            "status": _enum(("affirming", "warning", "contraindicated", "none")),
            "verifier": _uri, "policy_ref": _uri, "timestamp": _integer(-_SAFE_INT, _SAFE_INT),
            "provenance_depth_verified": _enum(_DEPTHS), "method": _enum(("re-execution",)),
            "re_execution": _re_execution, "platform_measurement": _platform_measurement}):
        return
    if v.get("method") == "re-execution" and "method" in v:
        if "re_execution" not in v:
            f.bad(_member_path(p, "re_execution"), "required when method is re-execution")
    elif "re_execution" in v:
        f.bad(_member_path(p, "re_execution"), "must be absent unless method is re-execution")
    if "platform_measurement" in v and v.get("status") == "none":
        f.bad(_member_path(p, "status"), "must not be none when platform_measurement is present (3.1.5 rule 5)")


def _canonicalizable_value(v: Any, p: str, f: _Findings) -> None:
    stack: List[Tuple[Any, str]] = [(v, p)]
    while stack:
        cur, cp = stack.pop()
        t = type(cur)
        if cur is None or t is str or t is bool:
            continue
        if t is int or t is float:
            if not _is_int_value(cur) or abs(_int_value(cur)) > _SAFE_INT:
                f.bad(cp, "must be a string, boolean, null, safe integer, array or object")
        elif t is list:
            for i, value in enumerate(cur):
                stack.append((value, f"{cp}[{i}]"))
        elif t is dict:
            for k, value in cur.items():
                stack.append((value, _member_path(cp, k)))
        else:  # pragma: no cover - a strict parse yields no other type
            f.bad(cp, "is not a JSON value")


def _jwk(v: Any, p: str, f: _Findings) -> None:
    string = _str_check()
    if not _object(v, p, f, ("kty",), {
            "kty": string, "crv": string, "x": string, "y": string, "n": string, "e": string,
            "kid": string}, extra=_canonicalizable_value):
        return
    needed = {"OKP": ("crv", "x"), "EC": ("crv", "x", "y"), "RSA": ("n", "e")}.get(v.get("kty"), ())
    for name in needed:
        if name not in v:
            f.bad(_member_path(p, name), f"required for kty {v.get('kty')}")
    for name in _PRIVATE_MEMBERS:
        if name in v:
            f.bad(_member_path(p, name), "private-key member is not allowed in cnf.jwk")


def _cnf(v: Any, p: str, f: _Findings) -> None:
    _object(v, p, f, ("jwk",), {"jwk": _jwk})


_TOP_REQUIRED = ("eat_profile", "iat", "subject", "model", "runtime", "policy", "data_class",
                 "build_provenance", "appraisal", "cnf")


def _check_structure(record: Dict[str, Any], form: str) -> _Findings:
    f = _Findings()

    def eat_profile(v: Any, p: str, fs: _Findings) -> None:
        if v != TRACE_PROFILE_V0_2 or type(v) is not str:
            fs.bad(p, f"must be {TRACE_PROFILE_V0_2!r}")

    def signature(v: Any, p: str, fs: _Findings) -> None:
        if form == "jws-compact":
            fs.bad(p, "an enveloping-signature profile omits the signature member (section 3.1)")
        else:
            _pattern(_SIGNATURE, "base64url signature")(v, p, fs)

    _object(record, "", f, _TOP_REQUIRED, {
        "eat_profile": eat_profile, "iat": _integer(1700000000, _SAFE_INT),
        "subject": _pattern(_SUBJECT, "subject"), "model": _model, "runtime": _runtime,
        "policy": _policy, "data_class": _str_check(), "tool_transcript": _tool_transcript,
        "delegation": _delegation, "origin": _origin, "references": _array_of(_reference),
        "reproducibility": _reproducibility, "build_provenance": _build_provenance,
        "appraisal": _appraisal, "transparency": _uri, "cnf": _cnf, "signature": signature})

    runtime = record.get("runtime")
    origin = record.get("origin")
    appraisal = record.get("appraisal")
    # Section 3.1.1: a record whose origin.kind is not self MUST carry runtime.platform software-only.
    if (type(origin) is dict and origin.get("kind") in ("third-party-control-plane", "log-import")
            and type(runtime) is dict and "platform" in runtime
            and runtime.get("platform") != "software-only"):
        f.bad("runtime.platform", "must be software-only when origin.kind is not self (section 3.1.1)")
    if type(appraisal) is dict and type(appraisal.get("platform_measurement")) is dict:
        pm = appraisal["platform_measurement"]
        # Section 3.1.5: on a TPM a layer key is pcr:0 .. pcr:23.
        if type(runtime) is dict and runtime.get("platform") == "tpm2" and type(pm.get("layers")) is dict:
            for name in pm["layers"]:
                if _PCR.fullmatch(name) is None:
                    f.bad(_member_path("appraisal.platform_measurement.layers", name),
                          "a tpm2 layer key must be pcr:0 .. pcr:23 (section 3.1.5)")
        # Section 3.1.5: the measurement MUST equal runtime.measurement.
        if ("measurement" in pm and type(runtime) is dict and "measurement" in runtime
                and pm.get("measurement") != runtime.get("measurement")):
            f.bad("appraisal.platform_measurement.measurement",
                  "must equal runtime.measurement (section 3.1.5)")
    return f


# --------------------------------------------------------------------------------------------
# The verdict.
# --------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class TraceVerdict:
    """The outcome of :func:`verify_trace_record`.

    ``result`` holds the named checks in the house vocabulary (:class:`VerificationResult`).
    ``profile`` and ``accepted_profiles`` are the verifier-result fields section 3.3 requires;
    ``profile`` is set only when the signature verified and the profile is in the accepted set.
    ``unknown_fields`` lists every member the schema does not name, as ``(path, permitted)``:
    permitted only inside ``cnf.jwk``, which RFC 7517 leaves open and the schema admits.
    ``not_checked`` names what this module never does (:data:`NOT_CHECKED`).
    ``automation`` is the house automation verdict; it never reads safe for a TRACE record."""

    result: VerificationResult
    form: Optional[str] = None
    alg: Optional[str] = None
    profile: Optional[str] = None
    accepted_profiles: Tuple[str, ...] = ()
    trusted_key_thumbprint: Optional[str] = None
    unknown_fields: Tuple[Tuple[str, bool], ...] = ()
    not_checked: Tuple[str, ...] = NOT_CHECKED
    policy: str = "NOT_EVALUATED"
    automation: Dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.result.ok

    def as_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "exit_code": exit_code(self),
            "form": self.form,
            "alg": self.alg,
            "profile": self.profile,
            "accepted_profiles": list(self.accepted_profiles),
            "trusted_key_thumbprint": self.trusted_key_thumbprint,
            "checks": self.result.as_dict()["checks"],
            "policy": self.policy,
            "revocation": "NOT_EVALUATED",
            "unknown_fields": [{"path": p, "permitted": ok} for p, ok in self.unknown_fields],
            "not_checked": list(self.not_checked),
            "automation": self.automation,
            "specification": dict(SPEC_PIN),
        }


def exit_code(verdict: TraceVerdict) -> int:
    """0 verified · 1 cryptographic or structural failure · 2 unreadable input or unusable trust
    material · 3 sound record, unmet relying-party requirement. Unreadable dominates: nothing else
    was judged. A cryptographic or structural failure dominates an unmet requirement, because a
    requirement judged on a record that is not intact judged attacker-chosen values."""
    if verdict.ok:
        return 0
    failed = [c.name for c in verdict.result.checks if c.ok is not True]
    if any(name in _UNREADABLE for name in failed):
        return 2
    if any(name in _INTEGRITY for name in failed):
        return 1
    return 3


def _finish(res: VerificationResult, *, form: Optional[str] = None, alg: Optional[str] = None,
            profile: Optional[str] = None, accepted: Tuple[str, ...] = (),
            thumbprint: Optional[str] = None, unknown: Tuple[Tuple[str, bool], ...] = (),
            policy_ok: Optional[bool] = None) -> TraceVerdict:
    names = {c.name: c.ok for c in res.checks}
    crypto_names = [n for n in ("signature", "cnf-binding", "canonical-payload") if n in names]
    crypto_ok = bool(crypto_names) and all(names[n] is True for n in crypto_names) and "signature" in names
    structure_ok = ("structure" in names and names["structure"] is True
                    and names.get("profile") is True)
    summary_input = {
        "ok": res.ok,
        "crypto_ok": crypto_ok,
        "structure_ok": structure_ok,
        "policy_ok": policy_ok,
        # Never True here: no revocation bundle is consumed (3.2.3) and no platform evidence is
        # appraised (3.3 steps 3, 4, 6, 7), so the automation verdict can never read safe.
        "revocation_checked": False,
        "platform_evidence_checked": False,
    }
    automation = automation_summary(summary_input, required_checks={
        "crypto": "crypto_ok", "structure": "structure_ok", "policy": "policy_ok",
        "references": ["revocation_checked", "platform_evidence_checked"]})
    policy = "NOT_EVALUATED" if policy_ok is None else ("OK" if policy_ok else "FAIL")
    return TraceVerdict(result=res, form=form, alg=alg, profile=profile, accepted_profiles=accepted,
                        trusted_key_thumbprint=thumbprint, unknown_fields=unknown, policy=policy,
                        automation=automation)


def _non_negative_int(name: str, v: Any) -> int:
    if type(v) is not int or v < 0:
        raise ValueError(f"{name} must be a non-negative integer number of seconds")
    return v


def _string_set(name: str, values: Any, *, digest: bool = False) -> Tuple[str, ...]:
    if type(values) not in (list, tuple, set, frozenset):
        raise ValueError(f"{name} must be a list of strings")
    items = tuple(values)
    if not items:
        raise ValueError(f"{name} is empty: an empty expectation would accept nothing")
    for item in items:
        if type(item) is not str:
            raise ValueError(f"{name} must hold strings only")
        if digest and _DIGEST.fullmatch(item) is None:
            raise ValueError(f"{name} holds {item!r}, which is not a sha256:/sha384: digest")
    return items


def _read_config(trusted_keys: Any, accepted_profiles: Any, max_age_seconds: Any,
                 max_future_skew_seconds: Any, now: Any, expected_nonce: Any,
                 expected_policy_hashes: Any, expected_subjects: Any,
                 expected_transcript_hash: Any) -> Dict[str, Any]:
    if type(trusted_keys) not in (list, tuple) or not trusted_keys:
        raise ValueError("trusted_keys must be a non-empty list of public JWKs supplied by the relying party")
    keys = []
    for i, jwk in enumerate(trusted_keys):
        try:
            keys.append(_parse_public_jwk(jwk))
        except ValueError as exc:
            raise ValueError(f"trusted_keys[{i}]: {exc}") from None
    if accepted_profiles is None:
        accepted: Tuple[str, ...] = (TRACE_PROFILE_V0_2,)
    else:
        accepted = _string_set("accepted_profiles", accepted_profiles)
        if _TRACE_PROFILE_V0_1 in accepted:
            raise ValueError("accepted_profiles names the superseded v0.1 identifier; the v0.2 cutover "
                             "is cutover, not coexistence")
        unimplemented = [p for p in accepted if p not in _IMPLEMENTED_PROFILES]
        if unimplemented:
            raise ValueError(f"accepted_profiles names {unimplemented}, which this verifier does not "
                             "implement (section 3.3: such a declaration MUST be refused)")
        accepted = tuple(dict.fromkeys(accepted))
    max_age = _non_negative_int("max_age_seconds", max_age_seconds)
    skew = _non_negative_int("max_future_skew_seconds", max_future_skew_seconds)
    if now is None:
        at = int(time.time())
    elif type(now) is not int:
        raise ValueError("now must be an integer Unix time in seconds, or None for the clock")
    else:
        at = now
    if expected_nonce is not None:
        if type(expected_nonce) is not str:
            raise ValueError("expected_nonce must be a string")
        try:
            expected_nonce.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("expected_nonce holds a lone surrogate and has no UTF-8 form") from None
    hashes_ = None if expected_policy_hashes is None else _string_set(
        "expected_policy_hashes", expected_policy_hashes, digest=True)
    subjects = None if expected_subjects is None else _string_set("expected_subjects", expected_subjects)
    if expected_transcript_hash is not None and (
            type(expected_transcript_hash) is not str or _DIGEST.fullmatch(expected_transcript_hash) is None):
        raise ValueError("expected_transcript_hash must be a sha256:/sha384: digest string")
    return {"keys": keys, "accepted": accepted, "max_age": max_age, "skew": skew, "now": at,
            "nonce": expected_nonce, "policy_hashes": hashes_, "subjects": subjects,
            "transcript_hash": expected_transcript_hash}


def _read_jws(text: str, res: VerificationResult,
              unknown: List[Tuple[str, bool]]) -> Optional[Tuple[str, bytes, bytes, Dict[str, Any]]]:
    """(alg, signing input, signature, record) of a compact JWS, or None after adding the failing check.
    Header members this profile does not read are appended to ``unknown`` as ``("header.<name>", False)``."""
    # The header is read first, so that an unsigned token is refused as such whatever its other
    # segments hold ("header.payload." is the usual spelling of alg none).
    if re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*", text) is None:
        res.add("readable", False, "neither a JSON object nor a compact JWS (three base64url segments "
                                   "separated by '.')")
        return None
    h64, p64, s64 = text.split(".")
    try:
        header_bytes = decode_b64url(h64)
    except ValueError:
        res.add("readable", False, "the JWS header segment is not canonical unpadded base64url "
                                   "(RFC 7515 section 2)")
        return None
    try:
        header = _parse_json_bytes(header_bytes, "the JWS protected header")
    except _Unreadable as exc:
        res.add("readable", False, str(exc))
        return None
    if type(header) is not dict:
        res.add("readable", False, "the JWS protected header is not a JSON object")
        return None
    alg = header.get("alg")
    if type(alg) is str and alg.lower() == "none":
        res.add("jws-header", False, "alg 'none' is refused: an unsigned token has no signature binding "
                                     "(section 3.2.2)")
        return None
    if alg not in _ALGS:
        res.add("jws-header", False, f"alg {alg!r} is not one of ES256, ES384, EdDSA (section 3.2.1)")
        return None
    others = sorted(k for k in header if k not in _HEADER_MEMBERS)
    unknown.extend((_member_path("header", k), False) for k in others)
    if others:
        res.add("jws-header", False, f"header member(s) {others} are not read by this profile and are "
                                     "refused rather than ignored (only alg, typ, kid)")
        return None
    for name in ("typ", "kid"):
        if name in header and type(header[name]) is not str:
            res.add("jws-header", False, f"header member {name!r} must be a string")
            return None
    if not p64 or not s64:
        res.add("readable", False, "a compact JWS needs a non-empty payload and signature segment")
        return None
    try:
        payload_bytes = decode_b64url(p64)
        signature = decode_b64url(s64)
    except ValueError:
        res.add("readable", False, "a JWS segment is not canonical unpadded base64url (RFC 7515 section 2)")
        return None
    try:
        record = _parse_json_bytes(payload_bytes, "the JWS payload")
    except _Unreadable as exc:
        res.add("readable", False, str(exc))
        return None
    if type(record) is not dict:
        res.add("readable", False, "the JWS payload is not a JSON object")
        return None
    res.add("jws-header", True, f"alg {alg}" + (f", typ {header['typ']}" if "typ" in header else ""))
    return alg, (h64 + "." + p64).encode("ascii"), signature, record


def verify_trace_record(
    record: Any,
    *,
    trusted_keys: Any,
    now: Optional[int] = None,
    max_age_seconds: int = 86400,
    max_future_skew_seconds: int = 300,
    expected_nonce: Optional[str] = None,
    expected_policy_hashes: Optional[Iterable[str]] = None,
    expected_subjects: Optional[Iterable[str]] = None,
    expected_transcript_hash: Optional[str] = None,
    accepted_profiles: Optional[Iterable[str]] = None,
) -> TraceVerdict:
    """Verify one TRACE v0.2 Trust Record, given as its wire bytes (``bytes`` or ``str``).

    ``trusted_keys`` is the relying party's list of public JWKs (OKP/Ed25519, EC/P-256, EC/P-384).
    The record's own ``cnf.jwk`` never supplies trust: the signature must verify under a trusted
    key, and the record's ``cnf.jwk`` must then name that same key by RFC 7638 thumbprint (section
    3.2.2, "made by the key in cnf").

    The time window is the relying party's: ``now`` (default: the clock), ``max_age_seconds``
    (default 86400) and ``max_future_skew_seconds`` (default 300) are the section 3.2.2 defaults.
    The age check cannot be switched off; section 3.2.2 says a verifier MUST enforce one.

    Expectations are optional and each is checked only when supplied: ``expected_nonce`` against
    ``runtime.nonce`` (section 3.2.2), ``expected_policy_hashes`` against ``policy.bundle_hash``
    (section 3.3 step 5), ``expected_subjects`` against ``subject`` (the relying party's scope) and
    ``expected_transcript_hash`` against ``tool_transcript.hash``. With none supplied the policy
    verdict is NOT_EVALUATED.

    Never raises for any input: unusable trust material and unreadable bytes come back as failing
    checks (exit 2), and every other outcome as a check of its own.
    """
    res = VerificationResult()
    try:
        cfg = _read_config(trusted_keys, accepted_profiles, max_age_seconds, max_future_skew_seconds,
                           now, expected_nonce, expected_policy_hashes, expected_subjects,
                           expected_transcript_hash)
    except ValueError as exc:
        res.add("verifier-config", False, str(exc))
        return _finish(res)
    accepted: Tuple[str, ...] = cfg["accepted"]

    # Read. Bytes or text only: a parsed dict has already lost duplicate members and spellings.
    if type(record) is bytes:
        raw = record
    elif type(record) is str:
        try:
            raw = record.encode("utf-8")
        except UnicodeEncodeError:
            res.add("readable", False, "the record text holds a lone surrogate and has no UTF-8 form")
            return _finish(res, accepted=accepted)
    else:
        res.add("readable", False, "pass the record's wire bytes (bytes or str), not a parsed object: "
                                   "duplicate members and number spellings are lost in a parsed object")
        return _finish(res, accepted=accepted)
    if len(raw) > DEFAULT_BUDGET.input_bytes:
        res.add("readable", False, f"the record is {len(raw)} bytes, over the input budget of "
                                   f"{DEFAULT_BUDGET.input_bytes}")
        return _finish(res, accepted=accepted)

    form: str
    signature: Optional[bytes]
    header_unknown: List[Tuple[str, bool]] = []
    if raw.lstrip(b" \t\r\n")[:1] == b"{":
        form, alg = "embedded", "EdDSA"
        try:
            obj = _parse_json_bytes(raw, "the record")
        except _Unreadable as exc:
            res.add("readable", False, str(exc))
            return _finish(res, form=form, accepted=accepted)
        if type(obj) is not dict:
            res.add("readable", False, "the record is not a JSON object")
            return _finish(res, form=form, accepted=accepted)
        rec: Dict[str, Any] = obj
        signing_input: Optional[bytes] = None
        payload_bytes: Optional[bytes] = None
    else:
        form = "jws-compact"
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            res.add("readable", False, "neither a JSON object nor a compact JWS (non-ASCII bytes)")
            return _finish(res, form=form, accepted=accepted)
        parsed = _read_jws(text, res, header_unknown)
        if parsed is None:
            return _finish(res, form=form, accepted=accepted, unknown=tuple(header_unknown))
        alg, signing_input, signature, rec = parsed
        payload_bytes = decode_b64url(text.split(".")[1])

    why = _canonicalizable(rec, "")
    if why is not None:
        res.add("readable", False, f"the record has no RFC 8785 form: {why}")
        return _finish(res, form=form, alg=alg, accepted=accepted)
    res.add("readable", True, form)

    # Signature first (section 3.3 step 1): nothing the record says is trusted before this.
    verified_key: Optional[_Key] = None
    if form == "embedded":
        sig_value = rec.get("signature")
        candidates = [k for k in cfg["keys"] if k.kty == "OKP"]
        if not candidates:
            res.add("verifier-config", False, "the embedded form is defined here for Ed25519 only (the "
                                              "specification fixes no embedded ECDSA encoding), and the "
                                              "relying party supplied no Ed25519 key")
            return _finish(res, form=form, alg=alg, accepted=accepted)
        if "signature" not in rec:
            res.add("signature", False, "the record carries no signature member and arrived in no "
                                        "envelope: no signature binding (section 3.2.2)")
        elif type(sig_value) is not str:
            res.add("signature", False, "the signature member is not a string")
        else:
            try:
                signature = decode_b64url(sig_value)
            except ValueError:
                signature = None
            if signature is None:
                res.add("signature", False, "the signature is not canonical unpadded base64url "
                                            "(section 3.2.2, RFC 4648 section 3.5)")
            else:
                message = _jcs({k: v for k, v in rec.items() if k != "signature"})
                for key in candidates:
                    if _signature_valid("EdDSA", key, signature, message):
                        verified_key = key
                        break
                res.add("signature", verified_key is not None,
                        "Ed25519 over the RFC 8785 form of the record without its signature member"
                        if verified_key is not None else
                        "the signature does not verify under any trusted Ed25519 key")
    else:
        kty, crv, sig_len = _ALGS[alg]
        candidates = [k for k in cfg["keys"] if k.kty == kty and k.crv == crv]
        if not candidates:
            res.add("signature", False, f"alg {alg} needs a {kty}/{crv} key and the relying party "
                                        "trusts none: the token's alg does not match the trusted keys")
        elif len(signature) != sig_len:
            res.add("signature", False, f"an {alg} signature is {sig_len} bytes, this one is {len(signature)}")
        else:
            for key in candidates:
                if _signature_valid(alg, key, signature, signing_input):
                    verified_key = key
                    break
            res.add("signature", verified_key is not None,
                    f"{alg} over the JWS signing input" if verified_key is not None else
                    f"the signature does not verify under any trusted {crv} key")

    thumbprint = None
    if verified_key is not None:
        thumbprint = verified_key.thumbprint
        cnf = rec.get("cnf")
        jwk = cnf.get("jwk") if type(cnf) is dict else None
        try:
            cnf_thumb = _parse_public_jwk(jwk).thumbprint
            detail = None
        except ValueError as exc:
            cnf_thumb, detail = None, f"cnf.jwk does not name a usable public key: {exc}"
        bound = cnf_thumb is not None and hmac.compare_digest(cnf_thumb, verified_key.thumbprint)
        res.add("cnf-binding", bound,
                "cnf.jwk names the key that verified the signature" if bound else
                (detail or "cnf.jwk names a different key than the one that verified the signature "
                           "(section 3.2.2: the binding is a signature by the key in cnf)"))
        if form == "jws-compact":
            canonical = _jcs(rec)
            same = payload_bytes == canonical
            res.add("canonical-payload", same,
                    "the payload bytes are the RFC 8785 form of the record" if same else
                    "the payload bytes are not the RFC 8785 form of the record, so the signature is "
                    "not over the canonical form (section 3.2.2)")

    # Profile and structure. Reported even when the signature failed: refusing is safe on
    # unauthenticated values, trusting is not, and nothing below grants trust.
    profile_value = rec.get("eat_profile")
    if profile_value in accepted and type(profile_value) is str:
        res.add("profile", True, profile_value)
    elif profile_value == _TRACE_PROFILE_V0_1:
        res.add("profile", False, "the superseded v0.1 profile; a v0.2 verifier MUST reject it "
                                  "(Changes from v0.1)")
    else:
        res.add("profile", False, f"eat_profile {profile_value!r} is outside the accepted set {list(accepted)}")
    findings = _check_structure(rec, form)
    if findings.violations:
        shown = "; ".join(findings.violations[:6])
        more = len(findings.violations) - 6
        res.add("structure", False, shown + (f"; and {more} more" if more > 0 else ""))
    else:
        res.add("structure", True, "conforms to the TRACE v0.2 schema and the section 3.1 rules")
    unknown = tuple(header_unknown) + tuple(findings.unknown)

    crypto_ok = verified_key is not None and all(
        c.ok is True for c in res.checks if c.name in ("cnf-binding", "canonical-payload"))
    policy_ok: Optional[bool] = None
    if crypto_ok:
        # Freshness (section 3.2.2), always: the window is the relying party's, never the record's.
        iat = rec.get("iat")
        if not _is_int_value(iat):
            res.add("freshness", False, "iat is not an integer value, so freshness cannot be established")
        else:
            age = cfg["now"] - _int_value(iat)
            if age < -cfg["skew"]:
                res.add("freshness", False, f"iat is {-age}s in the future, beyond the allowed skew of "
                                            f"{cfg['skew']}s")
            elif age > cfg["max_age"]:
                res.add("freshness", False, f"iat is {age}s old, beyond the maximum age of {cfg['max_age']}s")
            else:
                res.add("freshness", True, f"iat is {age}s old at {cfg['now']} (max age {cfg['max_age']}s, "
                                           f"skew {cfg['skew']}s)")
        runtime = rec.get("runtime") if type(rec.get("runtime")) is dict else {}
        policy = rec.get("policy") if type(rec.get("policy")) is dict else {}
        transcript = rec.get("tool_transcript") if type(rec.get("tool_transcript")) is dict else {}
        verdicts: List[bool] = []
        if cfg["nonce"] is not None:
            actual = runtime.get("nonce")
            same = type(actual) is str and hmac.compare_digest(actual.encode("utf-8"), cfg["nonce"].encode("utf-8"))
            res.add("nonce", same, "runtime.nonce echoes the challenge" if same else
                    "runtime.nonce is absent or does not echo the challenge (section 3.2.2)")
            verdicts.append(same)
        if cfg["policy_hashes"] is not None:
            actual = policy.get("bundle_hash")
            same = type(actual) is str and actual in cfg["policy_hashes"]
            res.add("policy-hash", same, "policy.bundle_hash is a bundle the relying party expects" if same
                    else "policy.bundle_hash is not a bundle the relying party expects (section 3.3 step 5)")
            verdicts.append(same)
        if cfg["subjects"] is not None:
            actual = rec.get("subject")
            same = type(actual) is str and actual in cfg["subjects"]
            res.add("subject", same, "subject is in the relying party's scope" if same else
                    "subject is outside the relying party's scope")
            verdicts.append(same)
        if cfg["transcript_hash"] is not None:
            actual = transcript.get("hash")
            # Compared as bytes: compare_digest refuses a str holding a non-ASCII character, and the
            # record's value is the record's, whatever it holds.
            same = type(actual) is str and hmac.compare_digest(actual.encode("utf-8"),
                                                               cfg["transcript_hash"].encode("ascii"))
            res.add("transcript-hash", same, "tool_transcript.hash equals the transcript the relying party "
                                             "holds" if same else
                    "tool_transcript.hash is absent or differs from the transcript the relying party holds")
            verdicts.append(same)
        if verdicts:
            policy_ok = all(verdicts)

    profile = profile_value if crypto_ok and any(
        c.name == "profile" and c.ok is True for c in res.checks) else None
    return _finish(res, form=form, alg=alg, profile=profile, accepted=accepted, thumbprint=thumbprint,
                   unknown=unknown, policy_ok=policy_ok)
