"""Offline verification of Sigstore bundles carrying GitHub Artifact Attestations and npm provenance.

WHAT THIS IS. A Sigstore bundle (sigstore/protobuf-specs, media types 0.1 to 0.3) carries one
signature, the material to verify it (a Fulcio leaf certificate or a key hint), transparency-log
entries and optional RFC 3161 timestamps. A GitHub Artifact Attestation (actions/attest-build-provenance)
and npm provenance (``npm publish --provenance``) are such bundles around a DSSE envelope whose payload
is an in-toto Statement v1 with a SLSA Provenance v1 predicate; npm adds a second bundle, the publish
attestation, signed by the registry's own key. This module checks one such bundle against trust
material the RELYING PARTY brings: the Sigstore trusted root (Fulcio CAs, Rekor and CT log keys, TSAs),
the digest of the artifact it holds, the identity it expects and, for the npm publish attestation, the
registry's keys document. Nothing the bundle says about itself is trusted before it verified under that
material, and nothing is fetched.

WRITTEN FROM THE SPECIFICATIONS, NOT FROM A CLIENT. The rules below were read from the documents pinned
in :data:`SPEC_PIN` (each by commit). No Sigstore client library is imported or copied, and the tests of
this module import none. Where a rule comes from a producer's source code rather than a specification
(the cross-checks between the predicate and the certificate, ``predicate-binding``), it is reported as a
note and decides no verdict (owner decision of 2026-10-26), and :data:`SPEC_PIN` names the file.

WHAT A PASS MEANS. A pass says: the bundle is well formed under its media type, its one signature verifies
under the key of a leaf certificate that a trusted Fulcio CA issued and a trusted CT log logged, at a time
that a trusted transparency log (or TSA) vouches for and at which every certificate of the chain was
valid; the log entry commits to exactly this signature and certificate; the payload is an in-toto
Statement v1 of the profile's predicate type whose predicate is well formed under its buildType; the
certificate names the identity the relying party expects; and a subject names the artifact digest the
relying party holds. It does NOT say that the build was honest, that the workflow is benign, or that a
predicate field is true: the predicate is written by the workflow that signed it, and whether it agrees
with the certificate is a note (``predicate-binding: agrees`` or ``predicate-binding: differs``).
Revocation, log consistency over time and freshness are not judged (:data:`NOT_CHECKED`), so the
automation verdict never reads safe.

EXIT CODES follow the house contract of the TRACE and AGT readers: 0 verified; 1 a cryptographic or
structural failure; 2 input that could not be read under this profile, a feature this module does not
implement, or relying-party trust material that is itself unusable; 3 the bundle is cryptographically
and structurally sound but a relying-party requirement (identity, artifact digest, subject name) is not
met.
"""
from __future__ import annotations

import calendar
import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from cryptography.exceptions import UnsupportedAlgorithm

from .. import merkle
from .._membership import is_member
from .._statement_payload import STATEMENT_TYPE, load_statement_strict, statement_subject_problem
from .._strict_json import loads_strict
from .._wire_b64 import decode_b64, decode_b64_either
from ..automation_verdict import automation_summary
from ..budget import DEFAULT_BUDGET, render_safe
from ..canonical import _bytes_von, _ein_stand, _zeichen_von
from ..dsse import pae
from ..errors import ProofBundleError, VerificationResult
from ..signature import verify_ed25519_pinned

__all__ = [
    "NOT_CHECKED",
    "PROFILES",
    "SPEC_PIN",
    "SigstoreVerdict",
    "exit_code",
    "verify_sigstore_bundle",
]

# --------------------------------------------------------------------------------------------
# Pins and constants.
# --------------------------------------------------------------------------------------------

#: The documents this module was written against, each by commit (retrieved 2026-10-26).
SPEC_PIN: Dict[str, str] = {
    "sigstore_bundle": "sigstore/protobuf-specs@a008f6f9d68b430dd0340398861e67e753a46281:protos/sigstore_bundle.proto",
    "sigstore_rekor": "sigstore/protobuf-specs@a008f6f9d68b430dd0340398861e67e753a46281:protos/sigstore_rekor.proto",
    "sigstore_trustroot":
        "sigstore/protobuf-specs@a008f6f9d68b430dd0340398861e67e753a46281:protos/sigstore_trustroot.proto",
    "client_spec": "sigstore/architecture-docs@82f7d950a04ee4430ba536383efe957e806c0fd0:client-spec.md",
    "rekor_spec": "sigstore/architecture-docs@82f7d950a04ee4430ba536383efe957e806c0fd0:rekor-spec.md",
    "fulcio_oids": "sigstore/fulcio@62a73e3fc56696ad7fe8ef9d49b8c82dd2689d59:docs/oid-info.md",
    "dsse": "secure-systems-lab/dsse@b531b787bb3e5f0c3e1c19cee84da1c5d569b061:protocol.md",
    "intoto_statement": "in-toto/attestation@50bf01716982189898823e90586075f37cd9bb7d:spec/v1/statement.md",
    "slsa_provenance_v1": "slsa-framework/slsa@7b05aeb8ce7722d4c55849370dc903dca1de0933:docs/spec/v1.0/provenance.md",
    "github_buildtype": "actions/buildtypes@055cb51e699272e4928520287e99d91fd8e9cca2:workflow/v1/README.md",
    "slsa_github_buildtype":
        "slsa-framework/github-actions-buildtypes@5f855ef0106dad3ee0e0f1046dc31b3b65152956:workflow/v1/README.md",
    "github_producer": "actions/toolkit@0c3a9c332b678ff1e776f93d728a4ad279803abe:packages/attest/src/provenance.ts",
    "npm_producer": "npm/cli@311ff5effbb1f96181c89a1ce6ebfe0c369e1ec1:lib/utils/provenance.js",
    "npm_publish_predicate": "npm/attestation@34f164c30ea75a364646e2439d9d1408bea57585:specs/publish/v0.1/README.md",
    "rfc6962": "RFC 6962 sections 2.1.1 (inclusion proof) and 3.2 (SCT signature input)",
}

#: What this module never does, named in every verdict.
NOT_CHECKED: Tuple[str, ...] = (
    "revocation: Sigstore has no revocation for Fulcio leaf certificates; key compromise of a trusted log, "
    "CA or TSA is not detected",
    "log consistency over time: no consistency proof between checkpoints is read, so a split view by the "
    "log is not detected (rekor-spec 10.2)",
    "freshness: the trusted root is taken as given; its own TUF metadata and expiry are the relying party's",
    "dsse envelopeHash (Rekor dsse v0.0.1) and intoto content.hash (Rekor intoto v0.0.2): the preimage "
    "is the envelope as Rekor canonicalized it, which no specification pins; payloadHash, the signature "
    "and the verifier ARE compared",
    "predicate fields are producer testimony, not facts; their agreement with the certificate follows "
    "the producers' code and is a note (predicate-binding), never a check",
    "Rekor v2 entries, messageSignature bundles and the GitLab variant of npm provenance are refused as "
    "not implemented (exit 2), never read",
)

_BUNDLE_MEDIA_TYPES: Dict[str, int] = {
    "application/vnd.dev.sigstore.bundle+json;version=0.1": 1,
    "application/vnd.dev.sigstore.bundle+json;version=0.2": 2,
    "application/vnd.dev.sigstore.bundle+json;version=0.3": 3,
    "application/vnd.dev.sigstore.bundle.v0.3+json": 3,
}
_TRUSTED_ROOT_MEDIA_TYPES = frozenset({
    "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
    "application/vnd.dev.sigstore.trustedroot.v0.1+json",
    "application/vnd.dev.sigstore.trustedroot.v0.2+json",
})

INTOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
#: in-toto Statement v0.1. Measured 2026-10-26: the npm publish attestation of sigstore@3.0.0 is a v0.1
#: Statement, so the npm-publish profile reads it; the SLSA profiles read v1 only.
STATEMENT_V0_1 = "https://in-toto.io/Statement/v0.1"
SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1"
NPM_PUBLISH_V0_1 = "https://github.com/npm/attestation/tree/main/specs/publish/v0.1"
GITHUB_BUILD_TYPE = "https://actions.github.io/buildtypes/workflow/v1"
NPM_GITHUB_BUILD_TYPE = "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"
NPM_GITLAB_BUILD_TYPE = "https://github.com/npm/cli/gitlab/v0alpha1"
GITHUB_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com"
NPM_REGISTRY = "https://registry.npmjs.org"

#: The profiles this module implements, by what each reads. ``signer``: a Fulcio certificate or a
#: registry key; ``predicate_type``: the one predicate type the profile reads; ``build_types``: the
#: buildTypes it accepts; ``issuer``: the OIDC issuer it expects unless the relying party names another.
#: Measured 2026-10-26 on the cli/cli test fixtures: GitHub attestations made in 2024 carry the
#: slsa-framework buildType that npm still writes, later ones the actions.github.io buildType, so the
#: GitHub profile reads both, each under its own producer's binding rules.
PROFILES: Dict[str, Dict[str, Any]] = {
    "github-artifact-attestation": {"signer": "fulcio", "predicate_type": SLSA_PROVENANCE_V1,
                                    "build_types": (GITHUB_BUILD_TYPE, NPM_GITHUB_BUILD_TYPE),
                                    "issuer": GITHUB_ACTIONS_ISSUER,
                                    "statement_types": (STATEMENT_TYPE,)},
    "npm-provenance": {"signer": "fulcio", "predicate_type": SLSA_PROVENANCE_V1,
                       "build_types": (NPM_GITHUB_BUILD_TYPE,), "issuer": GITHUB_ACTIONS_ISSUER,
                       "statement_types": (STATEMENT_TYPE,)},
    "npm-publish": {"signer": "key", "predicate_type": NPM_PUBLISH_V0_1, "build_types": (), "issuer": None,
                    "statement_types": (STATEMENT_TYPE, STATEMENT_V0_1)},
}

#: Fulcio certificate extensions (sigstore/fulcio docs/oid-info.md): name, OID, and whether the value is
#: the raw UTF-8 bytes (the deprecated 1.1 to 1.6) or a DER UTF8String (1.8 and later).
_FULCIO_EXTENSIONS: Tuple[Tuple[str, str, bool], ...] = (
    ("issuer_v1", "1.3.6.1.4.1.57264.1.1", False),
    ("github_workflow_trigger", "1.3.6.1.4.1.57264.1.2", False),
    ("github_workflow_sha", "1.3.6.1.4.1.57264.1.3", False),
    ("github_workflow_name", "1.3.6.1.4.1.57264.1.4", False),
    ("github_workflow_repository", "1.3.6.1.4.1.57264.1.5", False),
    ("github_workflow_ref", "1.3.6.1.4.1.57264.1.6", False),
    ("issuer", "1.3.6.1.4.1.57264.1.8", True),
    ("build_signer_uri", "1.3.6.1.4.1.57264.1.9", True),
    ("build_signer_digest", "1.3.6.1.4.1.57264.1.10", True),
    ("runner_environment", "1.3.6.1.4.1.57264.1.11", True),
    ("source_repository_uri", "1.3.6.1.4.1.57264.1.12", True),
    ("source_repository_digest", "1.3.6.1.4.1.57264.1.13", True),
    ("source_repository_ref", "1.3.6.1.4.1.57264.1.14", True),
    ("source_repository_identifier", "1.3.6.1.4.1.57264.1.15", True),
    ("source_repository_owner_uri", "1.3.6.1.4.1.57264.1.16", True),
    ("source_repository_owner_identifier", "1.3.6.1.4.1.57264.1.17", True),
    ("build_config_uri", "1.3.6.1.4.1.57264.1.18", True),
    ("build_config_digest", "1.3.6.1.4.1.57264.1.19", True),
    ("build_trigger", "1.3.6.1.4.1.57264.1.20", True),
    ("run_invocation_uri", "1.3.6.1.4.1.57264.1.21", True),
    ("source_repository_visibility_at_signing", "1.3.6.1.4.1.57264.1.22", True),
)
_OTHERNAME_SAN_OID = "1.3.6.1.4.1.57264.1.7"
#: Identity keys a relying party may pin: the SAN, the issuer, and every non-deprecated extension.
_IDENTITY_KEYS = frozenset({"san", "issuer"} | {name for name, _, der in _FULCIO_EXTENSIONS
                                                 if der and name != "issuer"})
#: Identity keys that name a workflow or repository. A Fulcio certificate is issued to anyone with an
#: OIDC token, so a policy that names only the issuer accepts every GitHub workflow in the world.
_NAMING_KEYS = frozenset({"san", "build_signer_uri", "build_config_uri", "source_repository_uri",
                          "source_repository_identifier", "source_repository_owner_uri",
                          "source_repository_owner_identifier"})

#: Rekor v1 entry kinds this module reads, by (kind, version).
_KINDS = frozenset({("dsse", "0.0.1"), ("intoto", "0.0.2")})

#: Check names whose failure means the input or the trust material could not be used (exit 2).
_UNREADABLE = frozenset({"verifier-config", "readable", "media-type", "unsupported"})
#: Check names whose failure is cryptographic or structural (exit 1).
_INTEGRITY = frozenset({"bundle-structure", "certificate", "public-key", "signature", "tlog-entry",
                        "tlog-body", "tlog-set", "tlog-inclusion", "tlog-checkpoint", "tlog-threshold",
                        "timestamp-authority", "signing-time", "certificate-chain", "sct", "statement",
                        "predicate-type", "predicate"})
#: Check names whose failure is an unmet relying-party requirement (exit 3).
_REQUIREMENT = frozenset({"identity", "subject-digest", "subject-name"})

#: The most transparency-log entries and RFC 3161 timestamps one bundle may carry. Each entry costs a
#: body parse, two signature checks and a Merkle walk, and the input budget alone admitted 1500 copies
#: of one entry (2.56 s, measured 2026-10-26 before this bound); a threshold above 8 is refused anyway.
_MAX_ENTRIES = 32
#: The events a GitHub workflow buildType may describe (both workflow/v1 specifications, contract GH-05).
_GITHUB_EVENTS = frozenset({"create", "release", "push", "workflow_dispatch"})
_INT64_MAX = 2 ** 63 - 1
_DECIMAL = re.compile(r"\A(0|[1-9][0-9]{0,18})\Z")
_RFC3339 = re.compile(r"\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]{1,9})?Z\Z")
_LOWER_HEX = re.compile(r"\A[0-9a-f]+\Z")
_DIGEST_ARG = re.compile(r"\A(sha256|sha384|sha512):([0-9a-f]+)\Z")
_SRI_ARG = re.compile(r"\A(sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})\Z")
_DIGEST_LEN = {"sha256": 32, "sha384": 48, "sha512": 64}
_EM_DASH = "\u2014"  # EM DASH, the signed-note signature line marker


# --------------------------------------------------------------------------------------------
# Small readers over values from the strict parser. They test the exact type: `bool` is an
# `int` in Python and not a number in JSON.
# --------------------------------------------------------------------------------------------

class _Unreadable(Exception):
    """Internal: the input or the trust material cannot be read under this profile (exit 2)."""


class _Fail(Exception):
    """Internal: a named check fails with a message."""

    def __init__(self, check: str, message: str) -> None:
        super().__init__(message)
        self.check = check


def _camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in rest)


def _members(obj: Any, path: str, allowed: Sequence[str], required: Sequence[str] = (),
             check: str = "bundle-structure") -> Dict[str, Any]:
    """``obj`` as an object holding only ``allowed`` members and every ``required`` one.

    protobuf's JSON mapping reads a field under its lowerCamel JSON name AND under its proto name
    (``mediaType`` and ``media_type``), so two readers can disagree about which of two spellings wins.
    Only the JSON name is read here; the proto name is refused by name, and so is any member the message
    does not define, as protojson does by default."""
    if type(obj) is not dict:
        raise _Fail(check, f"{path} must be a JSON object")
    for key in obj:
        if is_member(key, allowed):
            continue
        if is_member(_camel(key), allowed):
            raise _Fail(check, f"{path}.{render_safe(key, quote=False)} is the proto field name of "
                               f"{_camel(key)}; only the JSON name is read, so that two readers cannot "
                               "disagree about which spelling wins")
        raise _Fail(check, f"{path} has a member this message does not define: {render_safe(key)}")
    for key in required:
        if key not in obj:
            raise _Fail(check, f"{path}.{key} is required")
    return obj


def _string(v: Any, path: str, check: str = "bundle-structure", *, empty: bool = False) -> str:
    if type(v) is not str or (not empty and not v):
        raise _Fail(check, f"{path} must be a {'' if empty else 'non-empty '}string")
    return v


def _int64(v: Any, path: str, check: str = "bundle-structure") -> int:
    """A non-negative int64 in either protojson spelling: a JSON integer or a decimal string. A string
    with a leading zero, a sign or anything but digits is refused, so one value has one string form."""
    if type(v) is int and 0 <= v <= _INT64_MAX:
        return v
    if type(v) is str and _DECIMAL.match(v) and int(v) <= _INT64_MAX:
        return int(v)
    raise _Fail(check, f"{path} must be a non-negative int64 (a JSON integer or a decimal string "
                       f"without a leading zero), got {render_safe(v)}")


def _b64(v: Any, path: str, check: str = "bundle-structure") -> bytes:
    """A protojson ``bytes`` field: standard base64, padded, canonical (`_wire_b64.decode_b64`)."""
    if type(v) is not str:
        raise _Fail(check, f"{path} must be a base64 string")
    try:
        return decode_b64(v)
    except ValueError:
        raise _Fail(check, f"{path} is not canonical standard base64") from None


def _list(v: Any, path: str, check: str = "bundle-structure") -> list:
    if type(v) is not list:
        raise _Fail(check, f"{path} must be an array")
    return v


def _rfc3339_ns(v: Any, path: str) -> int:
    """A protobuf Timestamp in its JSON form (RFC 3339, UTC ``Z``) as integer nanoseconds."""
    m = _RFC3339.match(v) if type(v) is str else None
    if m is None:
        raise _Unreadable(f"{path} must be an RFC 3339 UTC timestamp, got {render_safe(v)}")
    year, month, day, hour, minute, second = (int(g) for g in m.groups()[:6])
    try:
        datetime(year, month, day, hour, minute, second)
    except ValueError:
        raise _Unreadable(f"{path} is not a calendar date: {render_safe(v)}") from None
    frac = m.group(7) or "."
    nanos = int((frac[1:] + "000000000")[:9])
    return calendar.timegm((year, month, day, hour, minute, second)) * 1_000_000_000 + nanos


def _dt_ns(dt: datetime) -> int:
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return calendar.timegm(dt.timetuple()) * 1_000_000_000 + dt.microsecond * 1000


def _iso(ns: int) -> str:
    return datetime.fromtimestamp(ns // 1_000_000_000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def _plain(value: Any, depth: int = 0) -> Any:
    """A caller's JSON-shaped argument with every text read by what it stores (`canonical._zeichen_von`)
    and every container read through its base type, so no method of the caller's values decides what the
    checks compare (the reading the TRACE reader gives its arguments). ``canonical._ein_stand`` has
    already copied the containers; it hands text subclasses on as they are. A value nested deeper than the
    parser's depth bound is None, which every reader refuses."""
    if depth > DEFAULT_BUDGET.json_depth:
        return None
    typ = type(value)
    if issubclass(typ, str):
        return _zeichen_von(value)
    if issubclass(typ, dict):
        return {(_zeichen_von(k) if issubclass(type(k), str) else k): _plain(v, depth + 1)
                for k, v in dict.items(value)}
    if issubclass(typ, (list, tuple)):
        return [_plain(v, depth + 1) for v in (list.__iter__(value) if issubclass(typ, list)
                                                else tuple.__iter__(value))]
    return value


def _wire(value: Any, what: str) -> bytes:
    """The wire bytes of a caller's ``bytes`` or ``str``, read by what it stores. A parsed object is
    refused: duplicate members and number spellings are lost in it."""
    if issubclass(type(value), (bytes, bytearray)):
        raw = _bytes_von(value)
    elif issubclass(type(value), str):
        try:
            raw = _zeichen_von(value).encode("utf-8")
        except UnicodeEncodeError:
            raise _Unreadable(f"{what} holds a lone surrogate and has no UTF-8 form") from None
    else:
        raise _Unreadable(f"pass {what} as its wire bytes (bytes or str), not a parsed object: duplicate "
                          "members and number spellings are lost in a parsed object")
    if len(raw) > DEFAULT_BUDGET.input_bytes:
        raise _Unreadable(f"{what} is {len(raw)} bytes, over the input budget of {DEFAULT_BUDGET.input_bytes}")
    return raw


# --------------------------------------------------------------------------------------------
# Keys, signatures and certificates. `cryptography` is a core dependency of the package.
# --------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class _Key:
    """A verification key read from its SubjectPublicKeyInfo DER: ``kind`` is 'p256', 'p384' or
    'ed25519', ``material`` the uncompressed EC point or the 32 raw Ed25519 bytes, ``der`` the SPKI."""
    kind: str
    material: bytes
    der: bytes


#: The one DER prefix of each SubjectPublicKeyInfo this module reads, and the length of what follows:
#: id-ecPublicKey on prime256v1 or secp384r1 with an uncompressed point (RFC 5480), and id-Ed25519 (RFC
#: 8410). A key in any other encoding, a compressed point included, is not read. No generic key loader
#: of `cryptography` is called: it builds whatever type the bytes name, and an Ed25519 key built that way
#: would bypass the package's refusal of weak trust anchors (`signature.verify_ed25519_pinned`).
_SPKI_PREFIXES = (
    ("p256", bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200"), 65),
    ("p384", bytes.fromhex("3076301006072a8648ce3d020106052b81040022036200"), 97),
    ("ed25519", bytes.fromhex("302a300506032b6570032100"), 32),
)


def _read_key(der: bytes) -> _Key:
    """The key of ``der``, or ValueError when it is no SPKI of the three kinds above."""
    for kind, prefix, length in _SPKI_PREFIXES:
        if der.startswith(prefix) and len(der) == len(prefix) + length:
            material = der[len(prefix):]
            if kind != "ed25519" and material[:1] != b"\x04":
                raise ValueError("an EC point that is not uncompressed")
            return _Key(kind=kind, material=material, der=der)
    raise ValueError("not a SubjectPublicKeyInfo of an ECDSA P-256, ECDSA P-384 or Ed25519 key")


def _spki_der(key: Any) -> bytes:
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


#: keyDetails of the trusted root, by the key kind each names.
_KEY_DETAILS = {"PKIX_ECDSA_P256_SHA_256": "p256", "PKIX_ECDSA_P384_SHA_384": "p384", "PKIX_ED25519": "ed25519"}


def _verify(key: _Key, signature: bytes, message: bytes) -> bool:
    """One signature under one key: ECDSA (DER, SHA-256 on P-256, SHA-384 on P-384), built from its
    point, or Ed25519 through `signature.verify_ed25519_pinned`, which refuses a weak trust anchor. A key
    of any other kind verifies nothing."""
    from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
    from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
    try:
        if key.kind == "p256":
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), key.material).verify(
                signature, message, ec.ECDSA(hashes.SHA256()))
        elif key.kind == "p384":
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), key.material).verify(
                signature, message, ec.ECDSA(hashes.SHA384()))
        elif key.kind == "ed25519":
            return verify_ed25519_pinned(key.material, signature, message)
        else:
            return False
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _der_utf8string(raw: bytes) -> Optional[str]:
    """The text of a DER UTF8String that fills ``raw`` exactly, or None. Definite, minimal lengths."""
    if len(raw) < 2 or raw[0] != 0x0C:
        return None
    first = raw[1]
    if first < 0x80:
        length, start = first, 2
    elif first in (0x81, 0x82, 0x83):
        n = first & 0x7F
        if len(raw) < 2 + n or raw[2] == 0:
            return None
        length = int.from_bytes(raw[2:2 + n], "big")
        start = 2 + n
        if length < 0x80:
            return None
    else:
        return None
    if start + length != len(raw):
        return None
    try:
        return raw[start:].decode("utf-8")
    except UnicodeDecodeError:
        return None


@dataclass(frozen=True)
class _Leaf:
    cert: Any
    der: bytes
    key: _Key
    san: str
    extensions: Dict[str, str]
    not_before: int
    not_after: int


def _read_leaf(der: bytes) -> _Leaf:
    """The leaf certificate read under Fulcio's certificate profile, or `_Fail("certificate", ...)`."""
    from cryptography import x509  # noqa: PLC0415
    from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID  # noqa: PLC0415
    try:
        cert = x509.load_der_x509_certificate(der)
        exts = cert.extensions
        version = cert.version
    except (ValueError, x509.DuplicateExtension, x509.InvalidVersion) as exc:
        raise _Fail("certificate", f"the leaf certificate is not a well-formed X.509 certificate: {exc}") from None
    if version is not x509.Version.v3:
        raise _Fail("certificate", "the leaf certificate is not X.509 v3")
    known_critical = {ExtensionOID.KEY_USAGE, ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                      ExtensionOID.EXTENDED_KEY_USAGE}
    for ext in exts:
        if ext.critical and ext.oid not in known_critical:
            raise _Fail("certificate", f"the leaf carries a critical extension this verifier does not "
                                       f"process: {ext.oid.dotted_string} (RFC 5280 section 4.2)")
    try:
        bc = exts.get_extension_for_class(x509.BasicConstraints).value
        if bc.ca:
            raise _Fail("certificate", "the leaf certificate is a CA certificate")
    except x509.ExtensionNotFound:
        pass
    try:
        ku = exts.get_extension_for_class(x509.KeyUsage).value
        eku = exts.get_extension_for_class(x509.ExtendedKeyUsage).value
        san_ext = exts.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as exc:
        raise _Fail("certificate", f"the leaf lacks an extension Fulcio always writes: {exc}") from None
    if not ku.digital_signature:
        raise _Fail("certificate", "the leaf's key usage does not include digitalSignature")
    if ExtendedKeyUsageOID.CODE_SIGNING not in eku:
        raise _Fail("certificate", "the leaf's extended key usage does not include codeSigning")
    if len(cert.subject) != 0:
        raise _Fail("certificate", "the leaf's subject is not empty; Fulcio names the identity in the SAN only")
    if not exts.get_extension_for_class(x509.SubjectAlternativeName).critical:
        raise _Fail("certificate", "the leaf's subject alternative name is not critical")
    if list(eku) != [ExtendedKeyUsageOID.CODE_SIGNING]:
        raise _Fail("certificate", "the leaf's extended key usage is not codeSigning alone")
    names = list(san_ext)
    if len(names) != 1:
        raise _Fail("certificate", f"the leaf names {len(names)} subject alternative names; a Fulcio "
                                   "certificate names exactly one identity, and two would be two identities")
    name = names[0]
    if isinstance(name, (x509.UniformResourceIdentifier, x509.RFC822Name)):
        san = name.value
    elif isinstance(name, x509.OtherName) and name.type_id.dotted_string == _OTHERNAME_SAN_OID:
        text = _der_utf8string(name.value)
        if text is None:
            raise _Fail("certificate", "the leaf's otherName SAN is not a DER UTF8String")
        san = text
    else:
        raise _Fail("certificate", f"the leaf's SAN is of a kind Fulcio does not issue: {type(name).__name__}")
    values: Dict[str, str] = {}
    by_oid = {ext.oid.dotted_string: ext for ext in exts}
    for ext_name, oid, is_der in _FULCIO_EXTENSIONS:
        ext = by_oid.get(oid)
        if ext is None:
            continue
        raw = ext.value.value if isinstance(ext.value, x509.UnrecognizedExtension) else None
        if raw is None:
            raise _Fail("certificate", f"extension {oid} could not be read as an opaque value")
        text = _der_utf8string(raw) if is_der else None
        if not is_der:
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = None
        if text is None:
            raise _Fail("certificate", f"extension {oid} ({ext_name}) is not {'a DER UTF8String' if is_der else 'UTF-8'}")
        values[ext_name] = text
    if "issuer" in values and "issuer_v1" in values and values["issuer"] != values["issuer_v1"]:
        raise _Fail("certificate", "the leaf names two different OIDC issuers (1.3.6.1.4.1.57264.1.1 and .1.8)")
    if "issuer" not in values and "issuer_v1" in values:
        values["issuer"] = values["issuer_v1"]
    if "issuer" not in values:
        raise _Fail("certificate", "the leaf names no OIDC issuer (1.3.6.1.4.1.57264.1.8)")
    try:
        key = _read_key(_spki_der(cert.public_key()))
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise _Fail("unsupported", f"the leaf key is not one this module verifies with (ECDSA P-256, P-384, "
                                   f"Ed25519): {exc}") from None
    nb, na = _dt_ns(_not_before(cert)), _dt_ns(_not_after(cert))
    if nb > na:
        raise _Fail("certificate", "the leaf's validity period is empty")
    return _Leaf(cert=cert, der=der, key=key, san=san, extensions=values, not_before=nb, not_after=na)


def _not_before(cert: Any) -> datetime:
    return cert.not_valid_before_utc


def _not_after(cert: Any) -> datetime:
    return cert.not_valid_after_utc


# --------------------------------------------------------------------------------------------
# The trusted root (relying-party trust material).
# --------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class _Log:
    base_url: str
    key: _Key
    key_der: bytes
    log_id: bytes
    checkpoint_key_id: Optional[bytes]
    start: int
    end: Optional[int]

    def valid_at(self, ns: int) -> bool:
        return self.start <= ns and (self.end is None or ns <= self.end)


@dataclass(frozen=True)
class _Authority:
    uri: str
    chain: Tuple[Any, ...]
    start: int
    end: Optional[int]

    def valid_at(self, ns: int) -> bool:
        return self.start <= ns and (self.end is None or ns <= self.end)


@dataclass(frozen=True)
class _TrustedRoot:
    tlogs: Tuple[_Log, ...]
    ctlogs: Tuple[_Log, ...]
    cas: Tuple[_Authority, ...]
    tsas: Tuple[_Authority, ...]
    skipped: Tuple[str, ...]


def _valid_for(v: Any, path: str) -> Tuple[int, Optional[int]]:
    try:
        obj = _members(v, path, ("start", "end"), ("start",), check="verifier-config")
    except _Fail as exc:
        raise _Unreadable(str(exc)) from None
    start = _rfc3339_ns(obj["start"], path + ".start")
    end = _rfc3339_ns(obj["end"], path + ".end") if "end" in obj else None
    if end is not None and end < start:
        raise _Unreadable(f"{path} ends before it starts")
    return start, end


def _read_logs(entries: Any, path: str, skipped: List[str]) -> Tuple[_Log, ...]:
    logs = []
    for i, entry in enumerate(entries):
        p = f"{path}[{i}]"
        try:
            obj = _members(entry, p, ("baseUrl", "hashAlgorithm", "publicKey", "logId", "checkpointKeyId",
                                      "operator"), ("baseUrl", "publicKey", "logId"), check="verifier-config")
            pk = _members(obj["publicKey"], p + ".publicKey", ("rawBytes", "keyDetails", "validFor"),
                          ("rawBytes", "keyDetails", "validFor"), check="verifier-config")
            log_id = _b64(_members(obj["logId"], p + ".logId", ("keyId",), ("keyId",),
                                   check="verifier-config")["keyId"], p + ".logId.keyId", "verifier-config")
            cp = None
            if "checkpointKeyId" in obj:
                cp = _b64(_members(obj["checkpointKeyId"], p + ".checkpointKeyId", ("keyId",), ("keyId",),
                                   check="verifier-config")["keyId"], p + ".checkpointKeyId.keyId",
                          "verifier-config")
            raw = _b64(pk["rawBytes"], p + ".publicKey.rawBytes", "verifier-config")
            base_url = _string(obj["baseUrl"], p + ".baseUrl", "verifier-config")
            details = _string(pk["keyDetails"], p + ".publicKey.keyDetails", "verifier-config")
            if "hashAlgorithm" in obj and obj["hashAlgorithm"] != "SHA2_256":
                skipped.append(f"{p}: Merkle hash {render_safe(obj['hashAlgorithm'])} is not SHA2_256")
                continue
        except _Fail as exc:
            raise _Unreadable(str(exc)) from None
        start, end = _valid_for(pk["validFor"], p + ".publicKey.validFor")
        kind = _KEY_DETAILS.get(details)
        if kind is None:
            # A key this module cannot verify with can vouch for nothing here; skipping it only narrows
            # what verifies. It is named in the verdict.
            skipped.append(f"{p}: key details {render_safe(details)} are not implemented")
            continue
        try:
            key = _read_key(raw)
        except ValueError as exc:
            raise _Unreadable(f"{p}.publicKey.rawBytes: {exc}") from None
        if key.kind != kind:
            raise _Unreadable(f"{p}.publicKey is a {key.kind} key, but keyDetails says {details}")
        # A Rekor v1 log and a CT log are identified by SHA-256 over the DER SubjectPublicKeyInfo of their
        # key (contract SV-19); a Rekor v2 (Ed25519) log carries its checkpoint key ID there instead.
        if kind != "ed25519" and not hmac.compare_digest(log_id, hashlib.sha256(raw).digest()):
            raise _Unreadable(f"{p}.logId is not the SHA-256 of the log's public key")
        logs.append(_Log(base_url=base_url, key=key, key_der=raw, log_id=log_id, checkpoint_key_id=cp,
                         start=start, end=end))
    return tuple(logs)


def _read_authorities(entries: Any, path: str) -> Tuple[_Authority, ...]:
    from cryptography import x509  # noqa: PLC0415
    out = []
    for i, entry in enumerate(entries):
        p = f"{path}[{i}]"
        try:
            obj = _members(entry, p, ("subject", "uri", "certChain", "validFor", "operator"),
                           ("certChain", "validFor"), check="verifier-config")
            chain_obj = _members(obj["certChain"], p + ".certChain", ("certificates",), ("certificates",),
                                 check="verifier-config")
            certs = _list(chain_obj["certificates"], p + ".certChain.certificates", "verifier-config")
            if not certs:
                raise _Fail("verifier-config", f"{p}.certChain.certificates is empty")
            ders = [_b64(_members(c, f"{p}.certChain.certificates[{j}]", ("rawBytes",), ("rawBytes",),
                                  check="verifier-config")["rawBytes"],
                         f"{p}.certChain.certificates[{j}].rawBytes", "verifier-config")
                    for j, c in enumerate(certs)]
            uri = _string(obj.get("uri", ""), p + ".uri", "verifier-config", empty=True)
        except _Fail as exc:
            raise _Unreadable(str(exc)) from None
        try:
            chain = tuple(x509.load_der_x509_certificate(d) for d in ders)
            for cert in chain:
                cert.public_key()
        except (ValueError, UnsupportedAlgorithm) as exc:
            raise _Unreadable(f"{p}.certChain holds a certificate that does not parse: {exc}") from None
        start, end = _valid_for(obj["validFor"], p + ".validFor")
        out.append(_Authority(uri=uri, chain=chain, start=start, end=end))
    return tuple(out)


def _read_trusted_root(raw: bytes) -> _TrustedRoot:
    root = _parse_json_bytes(raw, "the trusted root")
    try:
        obj = _members(root, "trustedRoot", ("mediaType", "tlogs", "certificateAuthorities", "ctlogs",
                                             "timestampAuthorities"), ("mediaType",), check="verifier-config")
        for key in ("tlogs", "certificateAuthorities", "ctlogs", "timestampAuthorities"):
            if key in obj:
                _list(obj[key], "trustedRoot." + key, "verifier-config")
    except _Fail as exc:
        raise _Unreadable(str(exc)) from None
    if not is_member(obj["mediaType"], _TRUSTED_ROOT_MEDIA_TYPES):
        raise _Unreadable(f"the trusted root's mediaType {render_safe(obj['mediaType'])} is not one this "
                          "module reads")
    skipped: List[str] = []
    return _TrustedRoot(
        tlogs=_read_logs(obj.get("tlogs", []), "trustedRoot.tlogs", skipped),
        ctlogs=_read_logs(obj.get("ctlogs", []), "trustedRoot.ctlogs", skipped),
        cas=_read_authorities(obj.get("certificateAuthorities", []), "trustedRoot.certificateAuthorities"),
        tsas=_read_authorities(obj.get("timestampAuthorities", []), "trustedRoot.timestampAuthorities"),
        skipped=tuple(skipped))


@dataclass(frozen=True)
class _RegistryKey:
    keyid: str
    key: _Key
    der: bytes
    expires: Optional[int]


def _read_registry_keys(raw: bytes) -> Dict[str, _RegistryKey]:
    """The npm registry keys document (``/-/npm/v1/keys``): ``{"keys": [{expires, keyid, keytype, scheme,
    key}]}``. Only ``ecdsa-sha2-nistp256`` keys are read; ``expires`` null means no expiry."""
    doc = _parse_json_bytes(raw, "the registry keys document")
    out: Dict[str, _RegistryKey] = {}
    try:
        obj = _members(doc, "keys", ("keys",), ("keys",), check="verifier-config")
        for i, entry in enumerate(_list(obj["keys"], "keys.keys", "verifier-config")):
            p = f"keys.keys[{i}]"
            e = _members(entry, p, ("expires", "keyid", "keytype", "scheme", "key"),
                         ("expires", "keyid", "keytype", "scheme", "key"), check="verifier-config")
            keyid = _string(e["keyid"], p + ".keyid", "verifier-config")
            if e["keytype"] != "ecdsa-sha2-nistp256" or e["scheme"] != "ecdsa-sha2-nistp256":
                raise _Fail("verifier-config", f"{p} is a {render_safe(e['keytype'])} key; only "
                                               "ecdsa-sha2-nistp256 is read")
            der = _b64(e["key"], p + ".key", "verifier-config")
            expires = None if e["expires"] is None else _rfc3339_ns(e["expires"], p + ".expires")
            if keyid in out:
                raise _Fail("verifier-config", f"{p}: keyid {render_safe(keyid)} is listed twice")
            try:
                key = _read_key(der)
            except ValueError as exc:
                raise _Fail("verifier-config", f"{p}.key: {exc}") from None
            if key.kind != "p256":
                raise _Fail("verifier-config", f"{p}.key is not a P-256 key")
            out[keyid] = _RegistryKey(keyid=keyid, key=key, der=der, expires=expires)
    except _Fail as exc:
        raise _Unreadable(str(exc)) from None
    if not out:
        raise _Unreadable("the registry keys document lists no key")
    return out


# --------------------------------------------------------------------------------------------
# The bundle.
# --------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class _Entry:
    position: int
    log_index: int
    log_id: bytes
    kind: str
    version: str
    integrated_time: int
    set_signature: Optional[bytes]
    proof: Optional[Dict[str, Any]]
    body: Optional[bytes]


@dataclass(frozen=True)
class _Bundle:
    version: int
    leaf_der: Optional[bytes]
    extra_chain: int
    key_hint: Optional[str]
    entries: Tuple[_Entry, ...]
    timestamps: Tuple[bytes, ...]
    payload_type: str
    payload: bytes
    signature: bytes
    keyid: Optional[str]


def _read_entry(entry: Any, p: str, position: int, version: int) -> _Entry:
    obj = _members(entry, p, ("logIndex", "logId", "kindVersion", "integratedTime", "inclusionPromise",
                              "inclusionProof", "canonicalizedBody"), ("logId", "kindVersion"))
    log_id = _b64(_members(obj["logId"], p + ".logId", ("keyId",), ("keyId",))["keyId"], p + ".logId.keyId")
    kv = _members(obj["kindVersion"], p + ".kindVersion", ("kind", "version"), ("kind", "version"))
    kind = _string(kv["kind"], p + ".kindVersion.kind")
    ver = _string(kv["version"], p + ".kindVersion.version")
    # proto3 JSON omits a zero int64, so an absent logIndex or integratedTime is 0.
    log_index = _int64(obj.get("logIndex", 0), p + ".logIndex")
    integrated = _int64(obj.get("integratedTime", 0), p + ".integratedTime")
    set_sig = None
    if "inclusionPromise" in obj:
        promise = _members(obj["inclusionPromise"], p + ".inclusionPromise", ("signedEntryTimestamp",),
                           ("signedEntryTimestamp",))
        set_sig = _b64(promise["signedEntryTimestamp"], p + ".inclusionPromise.signedEntryTimestamp")
    proof = None
    if "inclusionProof" in obj:
        pr = _members(obj["inclusionProof"], p + ".inclusionProof",
                      ("logIndex", "rootHash", "treeSize", "hashes", "checkpoint"),
                      ("rootHash", "treeSize", "checkpoint"))
        hashes = [_b64(h, f"{p}.inclusionProof.hashes[{j}]", "bundle-structure")
                  for j, h in enumerate(_list(pr.get("hashes", []), p + ".inclusionProof.hashes"))]
        if len(hashes) > DEFAULT_BUDGET.merkle_path:
            raise _Fail("bundle-structure", f"{p}.inclusionProof.hashes holds {len(hashes)} hashes, over the "
                                            f"budget of {DEFAULT_BUDGET.merkle_path}")
        cp = _members(pr["checkpoint"], p + ".inclusionProof.checkpoint", ("envelope",), ("envelope",))
        proof = {"log_index": _int64(pr.get("logIndex", 0), p + ".inclusionProof.logIndex"),
                 "root_hash": _b64(pr["rootHash"], p + ".inclusionProof.rootHash"),
                 "tree_size": _int64(pr["treeSize"], p + ".inclusionProof.treeSize"),
                 "hashes": hashes,
                 "checkpoint": _string(cp["envelope"], p + ".inclusionProof.checkpoint.envelope")}
    elif version >= 2:
        raise _Fail("bundle-structure", f"{p}.inclusionProof is required from bundle version 0.2 on")
    if version == 1 and set_sig is None:
        raise _Fail("bundle-structure", f"{p}.inclusionPromise is required in a version 0.1 bundle")
    body = _b64(obj["canonicalizedBody"], p + ".canonicalizedBody") if "canonicalizedBody" in obj else None
    return _Entry(position=position, log_index=log_index, log_id=log_id, kind=kind, version=ver,
                  integrated_time=integrated, set_signature=set_sig, proof=proof, body=body)


def _read_bundle(doc: Any, version: int) -> _Bundle:
    obj = _members(doc, "bundle", ("mediaType", "verificationMaterial", "dsseEnvelope", "messageSignature"),
                   ("mediaType", "verificationMaterial"))
    if "messageSignature" in obj:
        raise _Fail("unsupported", "a messageSignature bundle is not read by these profiles; GitHub Artifact "
                                   "Attestations and npm provenance carry a DSSE envelope")
    if "dsseEnvelope" not in obj:
        raise _Fail("bundle-structure", "bundle.dsseEnvelope is required (the content oneof is empty)")
    vm = _members(obj["verificationMaterial"], "bundle.verificationMaterial",
                  ("publicKey", "x509CertificateChain", "certificate", "tlogEntries", "timestampVerificationData"))
    forms = [k for k in ("publicKey", "x509CertificateChain", "certificate") if k in vm]
    if len(forms) != 1:
        raise _Fail("bundle-structure", f"verificationMaterial must carry exactly one of publicKey, "
                                        f"x509CertificateChain, certificate; it carries {forms or 'none'}")
    leaf_der: Optional[bytes] = None
    extra = 0
    hint: Optional[str] = None
    if forms[0] == "certificate":
        if version < 3:
            raise _Fail("bundle-structure", "verificationMaterial.certificate exists from bundle version 0.3 on")
        leaf_der = _b64(_members(vm["certificate"], "bundle.verificationMaterial.certificate", ("rawBytes",),
                                 ("rawBytes",))["rawBytes"], "bundle.verificationMaterial.certificate.rawBytes")
    elif forms[0] == "x509CertificateChain":
        chain = _members(vm["x509CertificateChain"], "bundle.verificationMaterial.x509CertificateChain",
                         ("certificates",), ("certificates",))
        certs = _list(chain["certificates"], "bundle.verificationMaterial.x509CertificateChain.certificates")
        if not certs:
            raise _Fail("bundle-structure", "x509CertificateChain.certificates is empty")
        ders = [_b64(_members(c, f"bundle.verificationMaterial.x509CertificateChain.certificates[{i}]",
                              ("rawBytes",), ("rawBytes",))["rawBytes"],
                     f"bundle.verificationMaterial.x509CertificateChain.certificates[{i}].rawBytes")
                for i, c in enumerate(certs)]
        leaf_der, extra = ders[0], len(ders) - 1
    else:
        pk = _members(vm["publicKey"], "bundle.verificationMaterial.publicKey", ("hint",))
        hint = _string(pk.get("hint", ""), "bundle.verificationMaterial.publicKey.hint", empty=True)
    raw_entries = _list(vm.get("tlogEntries", []), "bundle.verificationMaterial.tlogEntries")
    if len(raw_entries) > _MAX_ENTRIES:
        raise _Fail("bundle-structure", f"the bundle carries {len(raw_entries)} log entries, over the bound of "
                                        f"{_MAX_ENTRIES}")
    entries = tuple(_read_entry(e, f"bundle.verificationMaterial.tlogEntries[{i}]", i, version)
                    for i, e in enumerate(raw_entries))
    stamps: List[bytes] = []
    if "timestampVerificationData" in vm:
        tvd = _members(vm["timestampVerificationData"], "bundle.verificationMaterial.timestampVerificationData",
                       ("rfc3161Timestamps",))
        raw_stamps = _list(tvd.get("rfc3161Timestamps", []),
                           "bundle.verificationMaterial.timestampVerificationData.rfc3161Timestamps")
        if len(raw_stamps) > _MAX_ENTRIES:
            raise _Fail("bundle-structure", f"the bundle carries {len(raw_stamps)} RFC 3161 timestamps, over the "
                                            f"bound of {_MAX_ENTRIES}")
        for i, t in enumerate(raw_stamps):
            p = f"bundle.verificationMaterial.timestampVerificationData.rfc3161Timestamps[{i}]"
            stamps.append(_b64(_members(t, p, ("signedTimestamp",), ("signedTimestamp",))["signedTimestamp"],
                               p + ".signedTimestamp"))
    # Read closed like every message of the bundle, although DSSE says to ignore an unknown envelope
    # field (contract DS-03; a deviation, docs/SIGSTORE_BUNDLE_VERIFIER.md).
    env = _members(obj["dsseEnvelope"], "bundle.dsseEnvelope", ("payload", "payloadType", "signatures"),
                   ("payload", "payloadType", "signatures"))
    sigs = _list(env["signatures"], "bundle.dsseEnvelope.signatures")
    if len(sigs) != 1:
        raise _Fail("bundle-structure", f"a DSSE envelope in a bundle MUST have exactly one signature; this one "
                                        f"has {len(sigs)} (sigstore_bundle.proto, Bundle.content)")
    sig_obj = _members(sigs[0], "bundle.dsseEnvelope.signatures[0]", ("sig", "keyid"), ("sig",))
    keyid = None
    if "keyid" in sig_obj:
        keyid = _string(sig_obj["keyid"], "bundle.dsseEnvelope.signatures[0].keyid", empty=True)
    try:
        payload = decode_b64_either(_string(env["payload"], "bundle.dsseEnvelope.payload"))
        signature = decode_b64_either(_string(sig_obj["sig"], "bundle.dsseEnvelope.signatures[0].sig"))
    except ValueError:
        raise _Fail("bundle-structure", "a DSSE field is not canonical base64 (standard or URL-safe, padded)") from None
    return _Bundle(version=version, leaf_der=leaf_der, extra_chain=extra, key_hint=hint, entries=entries,
                   timestamps=tuple(stamps),
                   payload_type=_string(env["payloadType"], "bundle.dsseEnvelope.payloadType"),
                   payload=payload, signature=signature, keyid=keyid)


# --------------------------------------------------------------------------------------------
# Transparency log: body, SET, inclusion proof and checkpoint.
# --------------------------------------------------------------------------------------------

def _pem_der(text: Any, what: str, check: str) -> bytes:
    """The DER inside the one PEM block of ``text`` (RFC 7468: a CERTIFICATE or a PUBLIC KEY), compared by
    DER, never by text. The base64 lines are joined and read as canonical standard base64."""
    if type(text) is not bytes:
        raise _Fail(check, f"{what} is not PEM")
    try:
        lines = text.decode("ascii").strip().split("\n")
    except UnicodeDecodeError:
        raise _Fail(check, f"{what} is not ASCII PEM") from None
    for label in ("CERTIFICATE", "PUBLIC KEY"):
        if lines[0] == f"-----BEGIN {label}-----" and lines[-1] == f"-----END {label}-----" and len(lines) > 2:
            try:
                return decode_b64("".join(lines[1:-1]))
            except ValueError:
                raise _Fail(check, f"{what} holds a {label} block that is not canonical base64") from None
    raise _Fail(check, f"{what} is not exactly one PEM CERTIFICATE or PUBLIC KEY block")


def _hash_member(obj: Any, p: str) -> str:
    h = _members(obj, p, ("algorithm", "value"), ("algorithm", "value"), check="tlog-body")
    if h["algorithm"] != "sha256":
        raise _Fail("tlog-body", f"{p}.algorithm is {render_safe(h['algorithm'])}, not sha256")
    value = _string(h["value"], p + ".value", "tlog-body")
    if len(value) != 64 or not _LOWER_HEX.match(value):
        raise _Fail("tlog-body", f"{p}.value is not 64 lowercase hex characters")
    return value


def _check_body(entry: _Entry, bundle: _Bundle, verifier_der: bytes) -> None:
    """The Rekor v1 entry body commits to exactly this signature, this verifier (certificate or key)
    and this payload (client-spec 4.4: same signature, same key or certificate, subject matches)."""
    assert entry.body is not None
    try:
        body = _parse_json_bytes(entry.body, "the canonicalized body")
    except _Unreadable as exc:
        raise _Fail("tlog-body", str(exc)) from None
    top = _members(body, "body", ("apiVersion", "kind", "spec"), ("apiVersion", "kind", "spec"), check="tlog-body")
    if top["kind"] != entry.kind or top["apiVersion"] != entry.version:
        raise _Fail("tlog-body", f"the body is {render_safe(top['kind'])} {render_safe(top['apiVersion'])}, but "
                                 f"kindVersion says {entry.kind} {entry.version}")
    payload_sha = hashlib.sha256(bundle.payload).hexdigest()
    if entry.kind == "dsse":
        spec = _members(top["spec"], "body.spec", ("envelopeHash", "payloadHash", "signatures"),
                        ("envelopeHash", "payloadHash", "signatures"), check="tlog-body")
        _hash_member(spec["envelopeHash"], "body.spec.envelopeHash")
        if not hmac.compare_digest(_hash_member(spec["payloadHash"], "body.spec.payloadHash"), payload_sha):
            raise _Fail("tlog-body", "body.spec.payloadHash is not the SHA-256 of the envelope's payload")
        sigs = _list(spec["signatures"], "body.spec.signatures", "tlog-body")
        if len(sigs) != 1:
            raise _Fail("tlog-body", f"body.spec.signatures holds {len(sigs)} signatures; the bundle carries one")
        s = _members(sigs[0], "body.spec.signatures[0]", ("signature", "verifier"), ("signature", "verifier"),
                     check="tlog-body")
        logged_sig = _b64(s["signature"], "body.spec.signatures[0].signature", "tlog-body")
        logged_verifier = _pem_der(_b64(s["verifier"], "body.spec.signatures[0].verifier", "tlog-body"),
                                   "body.spec.signatures[0].verifier", "tlog-body")
    elif entry.kind == "intoto":
        spec = _members(top["spec"], "body.spec", ("content",), ("content",), check="tlog-body")
        content = _members(spec["content"], "body.spec.content", ("envelope", "hash", "payloadHash"),
                           ("envelope", "hash", "payloadHash"), check="tlog-body")
        _hash_member(content["hash"], "body.spec.content.hash")
        if not hmac.compare_digest(_hash_member(content["payloadHash"], "body.spec.content.payloadHash"),
                                   payload_sha):
            raise _Fail("tlog-body", "body.spec.content.payloadHash is not the SHA-256 of the envelope's payload")
        env = _members(content["envelope"], "body.spec.content.envelope", ("payloadType", "signatures"),
                       ("payloadType", "signatures"), check="tlog-body")
        if env["payloadType"] != bundle.payload_type:
            raise _Fail("tlog-body", "the logged envelope has another payloadType than the bundle's")
        sigs = _list(env["signatures"], "body.spec.content.envelope.signatures", "tlog-body")
        if len(sigs) != 1:
            raise _Fail("tlog-body", f"the logged envelope holds {len(sigs)} signatures; the bundle carries one")
        s = _members(sigs[0], "body.spec.content.envelope.signatures[0]", ("sig", "publicKey", "keyid"),
                     ("sig", "publicKey"), check="tlog-body")
        # intoto v0.0.2 stores the DSSE sig base64-encoded once more: base64(base64(signature)).
        inner = _b64(s["sig"], "body.spec.content.envelope.signatures[0].sig", "tlog-body")
        try:
            logged_sig = decode_b64(inner.decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            raise _Fail("tlog-body", "the logged sig is not base64 of the base64 signature (intoto v0.0.2)") from None
        logged_verifier = _pem_der(_b64(s["publicKey"], "body.spec.content.envelope.signatures[0].publicKey",
                                        "tlog-body"), "body.spec.content.envelope.signatures[0].publicKey",
                                   "tlog-body")
    else:
        raise _Fail("unsupported", f"Rekor kind {entry.kind} {entry.version} is not read")
    if not hmac.compare_digest(logged_sig, bundle.signature):
        raise _Fail("tlog-body", "the log entry commits to another signature than the bundle's")
    if not hmac.compare_digest(logged_verifier, verifier_der):
        raise _Fail("tlog-body", "the log entry commits to another certificate or key than the bundle's")


def _set_payload(entry: _Entry) -> bytes:
    """The bytes a Rekor v1 Signed Entry Timestamp signs: the canonical JSON of body, integratedTime,
    logID (lowercase hex) and logIndex (the GLOBAL index), keys sorted, no whitespace."""
    assert entry.body is not None
    import base64  # noqa: PLC0415 - encoding only; decoding goes through _wire_b64
    doc = {"body": base64.b64encode(entry.body).decode("ascii"), "integratedTime": entry.integrated_time,
           "logID": entry.log_id.hex(), "logIndex": entry.log_index}
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("ascii")


def _parse_note(text: str) -> Tuple[str, int, bytes, bytes, List[Tuple[str, bytes]]]:
    """A signed note (C2SP signed-note / tlog-checkpoint): origin, size, root, the signed text, and the
    signature lines as (name, base64-decoded blob). No control character but the newline (SV-44),
    canonical standard base64 (SV-45), and no two lines with one key name and key ID (SV-47)."""
    if any(ch < " " and ch != "\n" for ch in text) or "\x7f" in text:
        raise _Fail("tlog-checkpoint", "the checkpoint holds a control character other than newline")
    if "\n\n" not in text:
        raise _Fail("tlog-checkpoint", "the checkpoint has no blank line between text and signatures")
    body, sig_block = text.split("\n\n", 1)
    lines = body.split("\n")
    if len(lines) < 3 or any(not line for line in lines):
        raise _Fail("tlog-checkpoint", "the checkpoint text needs origin, size and root on non-empty lines")
    origin, size_text, root_text = lines[0], lines[1], lines[2]
    if not _DECIMAL.match(size_text):
        raise _Fail("tlog-checkpoint", "the checkpoint size is not a decimal without a leading zero")
    try:
        root = decode_b64(root_text)
    except ValueError:
        raise _Fail("tlog-checkpoint", "the checkpoint root is not canonical standard base64") from None
    if not sig_block.endswith("\n"):
        raise _Fail("tlog-checkpoint", "the checkpoint's signature block does not end in a newline")
    sigs: List[Tuple[str, bytes]] = []
    for line in sig_block[:-1].split("\n"):
        parts = line.split(" ")
        if len(parts) != 3 or parts[0] != _EM_DASH or not parts[1]:
            raise _Fail("tlog-checkpoint", "a checkpoint signature line is not 'EM DASH, name, base64'")
        try:
            blob = decode_b64(parts[2])
        except ValueError:
            raise _Fail("tlog-checkpoint", "a checkpoint signature is not canonical standard base64") from None
        if len(blob) < 5:
            raise _Fail("tlog-checkpoint", "a checkpoint signature is shorter than its key hint")
        if any(name == parts[1] and other[:4] == blob[:4] for name, other in sigs):
            raise _Fail("tlog-checkpoint", "two checkpoint signature lines share key name and key ID")
        sigs.append((parts[1], blob))
    if len(sigs) > DEFAULT_BUDGET.signatures:
        raise _Fail("tlog-checkpoint", "the checkpoint carries more signature lines than the budget allows")
    return origin, int(size_text), root, (body + "\n").encode("utf-8"), sigs


def _checkpoint_hint(log: _Log, name: str) -> bytes:
    """The 4-byte key hint a signature line of ``log`` carries: SHA-256 of the SPKI DER for an ECDSA
    log (Rekor v1, trustroot proto), SHA-256(name || 0x0A || 0x01 || key) for an Ed25519 log (C2SP)."""
    if log.key.kind == "ed25519":
        return hashlib.sha256(name.encode("utf-8") + b"\n\x01" + log.key.material).digest()[:4]
    return hashlib.sha256(log.key_der).digest()[:4]


def _check_checkpoint(log: _Log, proof: Dict[str, Any]) -> str:
    """The checkpoint is signed by ``log`` and names the proof's tree size and root. Returns the origin."""
    origin, size, root, signed, sigs = _parse_note(proof["checkpoint"])
    # Lines of other keys are ignored; every line of the log's key must verify, and one must exist (SV-46).
    mine = [(name, blob) for name, blob in sigs if hmac.compare_digest(blob[:4], _checkpoint_hint(log, name))]
    if not mine:
        raise _Fail("tlog-checkpoint", "no signature line of the checkpoint names the log's key")
    if not all(_verify(log.key, blob[4:], signed) for _, blob in mine):
        raise _Fail("tlog-checkpoint", "a signature line of the log's key does not verify")
    if size != proof["tree_size"] or not hmac.compare_digest(root, proof["root_hash"]):
        raise _Fail("tlog-checkpoint", "the signed checkpoint names another tree size or root than the "
                                       "inclusion proof")
    return origin


def _find_log(logs: Sequence[_Log], log_id: bytes) -> Optional[_Log]:
    for log in logs:
        if hmac.compare_digest(log.log_id, log_id):
            return log
    return None


# --------------------------------------------------------------------------------------------
# Certificate chain and SCT.
# --------------------------------------------------------------------------------------------

def _chain_problem(leaf: Any, ca: _Authority, at: int) -> Optional[str]:
    """Why ``leaf`` does not chain to ``ca`` at time ``at`` (RFC 5280 path validation in the hybrid
    model of client-spec 4.3), or None. Intermediates come from the trusted root only."""
    from cryptography import x509  # noqa: PLC0415
    from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
    if not ca.valid_at(at):
        return f"the CA {ca.uri or '(no uri)'} is not valid at {_iso(at)}"
    path = (leaf,) + ca.chain
    for i, cert in enumerate(path):
        if not _dt_ns(_not_before(cert)) <= at <= _dt_ns(_not_after(cert)):
            return f"certificate {i} of the path is not valid at {_iso(at)}"
    for depth, (child, parent) in enumerate(zip(path, path[1:])):
        try:
            child.verify_directly_issued_by(parent)
        except (ValueError, TypeError, InvalidSignature) as exc:
            return f"certificate {depth} is not issued by certificate {depth + 1}: {exc}"
        try:
            bc = parent.extensions.get_extension_for_class(x509.BasicConstraints).value
            ku = parent.extensions.get_extension_for_class(x509.KeyUsage).value
        except (x509.ExtensionNotFound, ValueError):
            return f"certificate {depth + 1} lacks basicConstraints or keyUsage"
        if not bc.ca or not ku.key_cert_sign:
            return f"certificate {depth + 1} is not a CA allowed to sign certificates"
        if bc.path_length is not None and depth > bc.path_length:
            return f"certificate {depth + 1} allows a path length of {bc.path_length}"
    return None


def _sct_problem(leaf: _Leaf, issuer: Any, ctlogs: Sequence[_Log]) -> Optional[str]:
    """None when an SCT embedded in the leaf verifies under a trusted CT log (RFC 6962 section 3.2)."""
    from cryptography import x509  # noqa: PLC0415
    from cryptography.x509.certificate_transparency import LogEntryType, Version  # noqa: PLC0415
    try:
        scts = leaf.cert.extensions.get_extension_for_class(x509.PrecertificateSignedCertificateTimestamps).value
    except x509.ExtensionNotFound:
        return "the leaf carries no embedded SCT"
    try:
        tbs = leaf.cert.tbs_precertificate_bytes
    except ValueError as exc:
        return f"the precertificate TBS cannot be rebuilt: {exc}"
    issuer_key_hash = hashlib.sha256(_spki_der(issuer.public_key())).digest()
    tried = []
    for sct in scts:
        log = _find_log(ctlogs, sct.log_id)
        if log is None:
            tried.append(f"SCT from unknown log {sct.log_id.hex()[:16]}")
            continue
        when = _dt_ns(sct.timestamp)
        if not log.valid_at(when):
            tried.append(f"SCT from {log.base_url} outside its validity")
            continue
        if sct.version is not Version.v1 or sct.entry_type is not LogEntryType.PRE_CERTIFICATE:
            tried.append("SCT of another version or entry type")
            continue
        ms = when // 1_000_000
        ext = sct.extension_bytes
        signed = (b"\x00\x00" + ms.to_bytes(8, "big") + b"\x00\x01" + issuer_key_hash
                  + len(tbs).to_bytes(3, "big") + tbs + len(ext).to_bytes(2, "big") + ext)
        if _verify(log.key, sct.signature, signed):
            return None
        tried.append(f"SCT from {log.base_url} does not verify")
    return "no embedded SCT verifies under a trusted CT log: " + "; ".join(tried)


# --------------------------------------------------------------------------------------------
# RFC 3161 timestamps (needs rfc3161-client, the [anchors] extra).
# --------------------------------------------------------------------------------------------

def _verify_timestamp(token: bytes, signature: bytes, tsas: Sequence[_Authority]) -> int:
    """The verified genTime of ``token`` over ``signature`` in nanoseconds, or `_Fail`."""
    try:
        import rfc3161_client as tsp  # noqa: PLC0415
    except ImportError:
        raise _Fail("unsupported", "the bundle carries an RFC 3161 timestamp and verifying it needs "
                                   "rfc3161-client (proofbundle[anchors]); it was not verified") from None
    problems = []
    try:
        response = tsp.decode_timestamp_response(token)
        gen = _dt_ns(response.tst_info.gen_time)
    except Exception as exc:  # noqa: BLE001 - a foreign parser's every refusal is a failed token
        raise _Fail("timestamp-authority", f"the RFC 3161 response does not parse: {exc}") from None
    for tsa in tsas:
        if not tsa.valid_at(gen):
            problems.append(f"{tsa.uri or 'a TSA'} is not valid at {_iso(gen)}")
            continue
        try:
            builder = tsp.VerifierBuilder().tsa_certificate(tsa.chain[0]).add_root_certificate(tsa.chain[-1])
            for inter in tsa.chain[1:-1]:
                builder = builder.add_intermediate_certificate(inter)
            builder.build().verify_message(response, signature)
            return gen
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{tsa.uri or 'a TSA'}: {exc}")
    raise _Fail("timestamp-authority", "the RFC 3161 timestamp verifies under no trusted TSA: "
                + ("; ".join(problems) or "the trusted root lists no TSA"))


# --------------------------------------------------------------------------------------------
# The statement and its predicate.
# --------------------------------------------------------------------------------------------

def _load_statement(payload: bytes, accepted: Tuple[str, ...]) -> Dict[str, Any]:
    """The DSSE payload as an in-toto Statement of one of the ``accepted`` types.

    A v1 Statement is read by the package's one Statement oracle (`_statement_payload.load_statement_strict`:
    the strict parser, ``_type`` exactly v1, a subject whose every entry names an artifact by digest). A v0.1
    Statement, which only the npm-publish profile accepts, is read by the same parser and the same subject
    rule; only its ``_type`` differs."""
    try:
        doc = _parse_json_bytes(payload, "the DSSE payload")
    except _Unreadable as exc:
        raise _Fail("statement", str(exc)) from None
    if type(doc) is not dict:
        raise _Fail("statement", "the DSSE payload is not a JSON object")
    kind = doc.get("_type")
    if kind == STATEMENT_V0_1 and doc.get("predicateType") == "https://slsa.dev/provenance/v0.2" \
            and STATEMENT_V0_1 not in accepted:
        raise _Fail("unsupported", "a Statement v0.1 with SLSA Provenance v0.2 (npm's GitLab provenance, contract "
                                   "NP-07) is not implemented")
    if type(kind) is not str or not is_member(kind, accepted):
        raise _Fail("statement", f"_type {render_safe(kind)} is not one of {list(accepted)}")
    if kind == STATEMENT_TYPE:
        try:
            return load_statement_strict(payload)
        except ProofBundleError as exc:
            raise _Fail("statement", str(exc)) from None
    problem = statement_subject_problem(doc)
    if problem is not None:
        raise _Fail("statement", f"the statement names no artifact by digest: {problem}")
    # in-toto v0.1 makes subject[*].name required, non-empty and unique (contract IT-19).
    names = [s.get("name") for s in doc["subject"]]
    if any(type(n) is not str or not n for n in names) or len(set(names)) != len(names):
        raise _Fail("statement", "a v0.1 Statement needs a non-empty, unique name on every subject")
    return doc


#: A URI as a scheme, a colon and no whitespace or control character, in ASCII classes only: `\s` is a
#: Unicode class in Python and another one in ECMA-262, so a schema validator would read it differently.
_URI = re.compile(r"\A[A-Za-z][A-Za-z0-9+.\-]*:[^\x00-\x20\x7f]+\Z")


def _descriptor(v: Any, p: str) -> None:
    """An in-toto ResourceDescriptor: an object with at least one of uri, digest, content."""
    if type(v) is not dict:
        raise _Fail("predicate", f"{p} must be a ResourceDescriptor object")
    if not any(k in v for k in ("uri", "digest", "content")):
        raise _Fail("predicate", f"{p} carries none of uri, digest, content")
    for k in ("name", "uri", "mediaType", "downloadLocation", "content"):
        if k in v and type(v[k]) is not str:
            raise _Fail("predicate", f"{p}.{k} must be a string")
    if "digest" in v:
        d = v["digest"]
        if type(d) is not dict or not d or any(type(x) is not str or not x for x in d.values()):
            raise _Fail("predicate", f"{p}.digest must be a non-empty map of strings")


def _present(obj: Dict[str, Any], key: str) -> Any:
    """``obj[key]``, or None when it is unset, null or empty: SLSA Provenance v1 says unset, null and empty
    field values MUST be interpreted equivalently (contract SP-03)."""
    value = obj.get(key)
    return None if value is None or value == {} or value == [] or value == "" else value


def _object(v: Any, path: str, required: Sequence[str], check: str = "predicate") -> Dict[str, Any]:
    """An object whose ``required`` members are set. Members it does not name are ignored, as SLSA
    (SP-02) and in-toto (IT-07) require of a consumer; only ``externalParameters`` is read closed."""
    if type(v) is not dict:
        raise _Fail(check, f"{path} must be an object")
    for key in required:
        if _present(v, key) is None:
            raise _Fail(check, f"{path}.{key} is required")
    return v


def _slsa_v1(pred: Any) -> Dict[str, Any]:
    """The SLSA Provenance v1 shape (provenance.md, "Schema"): the REQUIRED fields set and typed. Unknown
    fields are ignored (SP-02), and an unset, null or empty optional field is read as absent (SP-03)."""
    obj = _object(pred, "predicate", ("buildDefinition", "runDetails"))
    bd = _object(obj["buildDefinition"], "predicate.buildDefinition", ("buildType", "externalParameters"))
    if type(bd["buildType"]) is not str or not _URI.match(bd["buildType"]):
        raise _Fail("predicate", "predicate.buildDefinition.buildType must be a URI")
    if type(bd["externalParameters"]) is not dict:
        raise _Fail("predicate", "predicate.buildDefinition.externalParameters must be an object")
    internal = _present(bd, "internalParameters")
    if internal is not None and type(internal) is not dict:
        raise _Fail("predicate", "predicate.buildDefinition.internalParameters must be an object")
    deps = _present(bd, "resolvedDependencies") or []
    for i, d in enumerate(_list(deps, "predicate.buildDefinition.resolvedDependencies", "predicate")):
        _descriptor(d, f"predicate.buildDefinition.resolvedDependencies[{i}]")
    rd = _object(obj["runDetails"], "predicate.runDetails", ("builder",))
    builder = _object(rd["builder"], "predicate.runDetails.builder", ("id",))
    if type(builder["id"]) is not str or not _URI.match(builder["id"]):
        raise _Fail("predicate", "predicate.runDetails.builder.id must be a URI")
    md = _present(rd, "metadata")
    if md is not None:
        md = _object(md, "predicate.runDetails.metadata", ())
        for k in ("startedOn", "finishedOn"):
            if _present(md, k) is not None:
                try:
                    _rfc3339_ns(md[k], "predicate.runDetails.metadata." + k)
                except _Unreadable as exc:
                    raise _Fail("predicate", str(exc)) from None
        if _present(md, "invocationId") is not None and type(md["invocationId"]) is not str:
            raise _Fail("predicate", "predicate.runDetails.metadata.invocationId must be a string")
    for i, d in enumerate(_list(_present(rd, "byproducts") or [], "predicate.runDetails.byproducts", "predicate")):
        _descriptor(d, f"predicate.runDetails.byproducts[{i}]")
    return obj


def _workflow_params(bd: Dict[str, Any]) -> Dict[str, str]:
    """The GitHub workflow external parameters: exactly ``workflow`` {ref, repository, path}. The
    buildType says consumers SHOULD reject unrecognized external parameters."""
    ext = _members(bd["externalParameters"], "predicate.buildDefinition.externalParameters", ("workflow",),
                   ("workflow",), check="predicate")
    wf = _members(ext["workflow"], "predicate.buildDefinition.externalParameters.workflow",
                  ("ref", "repository", "path"), ("ref", "repository", "path"), check="predicate")
    for k in ("ref", "repository", "path"):
        _string(wf[k], "predicate.buildDefinition.externalParameters.workflow." + k, "predicate")
    if not wf["ref"].startswith("refs/"):
        raise _Fail("predicate", "externalParameters.workflow.ref must be a git ref starting with refs/")
    if not wf["repository"].startswith("https://") or wf["repository"].endswith(".git"):
        raise _Fail("predicate", "externalParameters.workflow.repository must be an https URI without .git")
    return wf


def _github_internal(bd: Dict[str, Any], required: Sequence[str]) -> Dict[str, str]:
    ip = _present(bd, "internalParameters")
    if type(ip) is not dict or type(ip.get("github")) is not dict:
        raise _Fail("predicate", "internalParameters.github is required by this buildType")
    gh = ip["github"]
    for k in required:
        _string(gh.get(k), "predicate.buildDefinition.internalParameters.github." + k, "predicate")
    return gh


def _source_commits(bd: Dict[str, Any], wf: Dict[str, str]) -> List[Any]:
    """The gitCommit of each resolved dependency that names the workflow's source, in order."""
    uri = "git+" + wf["repository"] + "@" + wf["ref"]
    return [d["digest"].get("gitCommit") for d in _present(bd, "resolvedDependencies") or []
            if type(d) is dict and d.get("uri") == uri and type(d.get("digest")) is dict]


def _github_build_type(bd: Dict[str, Any]) -> None:
    """What the actions.github.io buildType itself requires (actions/buildtypes workflow/v1, :data:`SPEC_PIN`):
    the four internal parameters (MUST, contract GH-08) and a resolved dependency naming the source commit
    (MUST, GH-09). The slsa-framework buildType makes both optional, so it is not held to them."""
    wf = _workflow_params(bd)
    _github_internal(bd, ("event_name", "repository_id", "repository_owner_id", "runner_environment"))
    if not any(type(c) is str and c for c in _source_commits(bd, wf)):
        raise _Fail("predicate", "resolvedDependencies must name the source git+" + render_safe(
            wf["repository"] + "@" + wf["ref"], quote=False) + " with a gitCommit digest (actions.github.io "
            "buildType)")


def _github_event(bd: Dict[str, Any], leaf: _Leaf) -> None:
    """The event that triggered the run is one of the four both GitHub workflow buildTypes name: "This
    build type MUST NOT be used for any other event type unless this specification is first updated"
    (actions/buildtypes and slsa-framework/github-actions-buildtypes workflow/v1, contract GH-05, owner
    decision of 2026-10-26). The predicate states the event in internalParameters.github.event_name, the
    certificate in its build trigger, which Fulcio copied from the OIDC token; each that is stated must
    be one of the four, so a predicate cannot hide the run's event, and at least one must be stated."""
    ip = _present(bd, "internalParameters")
    gh = ip["github"] if type(ip) is dict and type(ip.get("github")) is dict else {}
    stated = [(where, value) for where, value in (
        ("the predicate's internalParameters.github.event_name", gh.get("event_name")),
        ("the certificate's build trigger (1.3.6.1.4.1.57264.1.20)", leaf.extensions.get("build_trigger")))
        if value is not None]
    if not stated:
        raise _Fail("predicate", "neither the predicate nor the certificate names the event that triggered the "
                                 "run, and the buildType may describe only create, release, push or "
                                 "workflow_dispatch")
    for where, value in stated:
        if type(value) is not str or not is_member(value, _GITHUB_EVENTS):
            raise _Fail("predicate", f"{where} is {render_safe(value)}; the buildType "
                                     f"{render_safe(bd['buildType'])} MUST NOT be used for an event other than "
                                     "create, release, push or workflow_dispatch")


def _binding(checks: List[Tuple[str, Any, Optional[str]]]) -> List[str]:
    """Each (what, predicate value, certificate value) that disagrees, or that the certificate lacks."""
    out = []
    for what, in_predicate, in_certificate in checks:
        if in_certificate is None:
            out.append(f"the certificate carries no {what}")
        elif in_predicate != in_certificate:
            out.append(f"{what}: the predicate says {render_safe(in_predicate)}, the certificate says "
                       f"{render_safe(in_certificate)}")
    return out


def _check_slsa_binding(pred: Dict[str, Any], leaf: _Leaf) -> str:
    """Whether the predicate agrees with what Fulcio wrote into the certificate from the OIDC token, as a
    note that decides no verdict.

    These equalities come from the PRODUCERS (actions/toolkit attest provenance.ts and npm/cli
    lib/utils/provenance.js, :data:`SPEC_PIN`), which build both from the same token claims; no
    specification states them, so a disagreement is reported and not judged (owner decision of
    2026-10-26). A disagreement says the signed predicate describes another run than the one the
    certificate was issued to, or that a producer changed its rules."""
    bd, rd = pred["buildDefinition"], pred["runDetails"]
    wf = _workflow_params(bd)
    e = leaf.extensions
    ip = _present(bd, "internalParameters")
    gh: Dict[str, Any] = ip["github"] if type(ip) is dict and type(ip.get("github")) is dict else {}
    commits = _source_commits(bd, wf)
    problems = [] if len(commits) == 1 else [f"resolvedDependencies names the source {len(commits)} times"]
    checks: List[Tuple[str, Any, Optional[str]]] = [
        ("source repository", wf["repository"], e.get("source_repository_uri")),
        ("source ref", wf["ref"], e.get("source_repository_ref")),
        ("build config", wf["repository"] + "/" + wf["path"] + "@" + wf["ref"], e.get("build_config_uri")),
        ("run invocation", (_present(rd, "metadata") or {}).get("invocationId"), e.get("run_invocation_uri")),
        ("trigger", gh.get("event_name"), e.get("build_trigger")),
        ("repository id", gh.get("repository_id"), e.get("source_repository_identifier")),
        ("repository owner id", gh.get("repository_owner_id"), e.get("source_repository_owner_identifier")),
    ]
    if len(commits) == 1:
        checks.insert(2, ("source commit", commits[0], e.get("source_repository_digest")))
    if bd["buildType"] == GITHUB_BUILD_TYPE:
        checks += [("builder (signer workflow)", rd["builder"]["id"], e.get("build_signer_uri")),
                   ("runner environment", gh.get("runner_environment"), e.get("runner_environment"))]
    else:
        runner = e.get("runner_environment")
        checks.append(("builder (runner)", rd["builder"]["id"],
                       None if runner is None else "https://github.com/actions/runner/" + runner))
    problems += _binding(checks)
    rules = "producer rules, SPEC_PIN github_producer and npm_producer; a note, no verdict depends on it"
    if problems:
        return "predicate-binding: differs from the certificate: " + "; ".join(problems) + f" ({rules})"
    return ("predicate-binding: agrees with the certificate in " + ", ".join(what for what, _, _ in checks)
            + f" ({rules})")


def _check_npm_publish(pred: Any, statement: Dict[str, Any]) -> None:
    obj = _object(pred, "predicate", ("name", "version", "registry"))
    name = _string(obj["name"], "predicate.name", "predicate")
    version = _string(obj["version"], "predicate.version", "predicate")
    if obj["registry"] != NPM_REGISTRY:
        raise _Fail("predicate", f"predicate.registry is {render_safe(obj['registry'])}, not {NPM_REGISTRY}")
    purl = "pkg:npm/" + (("%40" + name[1:]) if name.startswith("@") else name) + "@" + version
    names = [s.get("name") for s in statement["subject"]]
    if names != [purl]:
        raise _Fail("predicate", f"the publish attestation's one subject must be {render_safe(purl)}, got "
                                 f"{render_safe(names)}")


# --------------------------------------------------------------------------------------------
# The verdict.
# --------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class SigstoreVerdict:
    """The outcome of :func:`verify_sigstore_bundle`.

    ``result`` holds the named checks in the house vocabulary (:class:`VerificationResult`).
    ``signing_times`` are the verified times (Unix seconds) the certificate chain was judged at;
    ``identity`` the SAN and Fulcio extensions read from the leaf (set once the certificate check
    passed); ``predicate_type`` and ``subjects`` what the statement names (set once the signature
    verified). ``notes`` names what was read but deliberately not counted (a superfluous chain
    certificate, a trusted-root entry this module cannot use, a checkpoint origin).
    ``not_checked`` names what this module never does (:data:`NOT_CHECKED`)."""

    result: VerificationResult
    profile: Optional[str] = None
    bundle_version: Optional[str] = None
    signing_times: Tuple[int, ...] = ()
    identity: Dict[str, str] = field(default_factory=dict)
    predicate_type: Optional[str] = None
    subjects: Tuple[str, ...] = ()
    notes: Tuple[str, ...] = ()
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
            "profile": self.profile,
            "bundle_version": self.bundle_version,
            "signing_times": list(self.signing_times),
            "identity": dict(self.identity),
            "predicate_type": self.predicate_type,
            "subjects": list(self.subjects),
            "checks": self.result.as_dict()["checks"],
            "policy": self.policy,
            "notes": list(self.notes),
            "not_checked": list(self.not_checked),
            "automation": self.automation,
            "specification": dict(SPEC_PIN),
        }


@_ein_stand
def exit_code(verdict: SigstoreVerdict) -> int:
    """0 verified · 1 cryptographic or structural failure · 2 unreadable input, an unimplemented
    feature or unusable trust material · 3 sound bundle, unmet relying-party requirement. Unreadable
    dominates: nothing else was judged. A cryptographic or structural failure dominates an unmet
    requirement. A failed check of a name in none of the three classes counts as structural, so a
    check added without a class can never read as a mere requirement."""
    if verdict.ok:
        return 0
    failed = [c.name for c in verdict.result.checks if c.ok is not True]
    if any(is_member(name, _UNREADABLE) for name in failed):
        return 2
    if any(not is_member(name, _REQUIREMENT) for name in failed):
        return 1
    return 3


def _finish(res: VerificationResult, *, profile: Optional[str] = None, version: Optional[int] = None,
            times: Sequence[int] = (), identity: Optional[Dict[str, str]] = None,
            predicate_type: Optional[str] = None, subjects: Sequence[str] = (),
            notes: Sequence[str] = (), policy_ok: Optional[bool] = None) -> SigstoreVerdict:
    names = {c.name: c.ok for c in res.checks}
    crypto_ok = all(names.get(n) is True for n in ("signature", "signing-time")) and all(
        ok is True for n, ok in names.items() if is_member(n, _INTEGRITY))
    structure_ok = names.get("bundle-structure") is True and names.get("statement") is True
    automation = automation_summary({
        "ok": res.ok, "crypto_ok": crypto_ok, "structure_ok": structure_ok, "policy_ok": policy_ok,
        # Never True here: no revocation exists for Fulcio leaves and no log consistency is judged.
        "revocation_checked": False, "log_consistency_checked": False,
    }, required_checks={"crypto": "crypto_ok", "structure": "structure_ok", "policy": "policy_ok",
                        "references": ["revocation_checked", "log_consistency_checked"]})
    policy = "NOT_EVALUATED" if policy_ok is None else ("OK" if policy_ok else "FAIL")
    return SigstoreVerdict(result=res, profile=profile,
                           bundle_version=None if version is None else f"0.{version}",
                           signing_times=tuple(t // 1_000_000_000 for t in times),
                           identity=dict(identity or {}), predicate_type=predicate_type,
                           subjects=tuple(subjects), notes=tuple(notes), policy=policy, automation=automation)


def _read_config(profile: Any, identity: Any, artifact_digest: Any, expected_subject_name: Any,
                 tlog_threshold: Any) -> Dict[str, Any]:
    if not is_member(profile, PROFILES):
        raise ValueError(f"profile must be one of {sorted(PROFILES)}, got {render_safe(profile)}")
    spec = PROFILES[profile]
    if type(artifact_digest) is not str:
        raise ValueError("artifact_digest is required: 'sha256:<hex>', 'sha512:<hex>' or an SRI string "
                         "('sha512-<base64>'); an attestation verified without the artifact names nothing you hold")
    m = _DIGEST_ARG.match(artifact_digest)
    if m is not None:
        alg, hexval = m.group(1), m.group(2)
    else:
        m = _SRI_ARG.match(artifact_digest)
        if m is None:
            raise ValueError(f"artifact_digest {render_safe(artifact_digest)} is neither 'alg:hex' nor an SRI string")
        alg = m.group(1)
        try:
            hexval = decode_b64(m.group(2)).hex()
        except ValueError:
            raise ValueError("artifact_digest's SRI value is not canonical base64") from None
    if len(hexval) != 2 * _DIGEST_LEN[alg]:
        raise ValueError(f"artifact_digest is not a {alg} digest ({2 * _DIGEST_LEN[alg]} hex characters)")
    pinned: Dict[str, str] = {}
    if spec["signer"] == "fulcio":
        if identity is None or type(identity) is not dict:
            raise ValueError("identity is required for a certificate-signed profile: a mapping of 'san', "
                             "'issuer' and Fulcio extension names to the exact values expected")
        for k, v in identity.items():
            if not is_member(k, _IDENTITY_KEYS):
                raise ValueError(f"identity names {render_safe(k)}, which is not one of {sorted(_IDENTITY_KEYS)}")
            if type(v) is not str or not v:
                raise ValueError(f"identity[{k!r}] must be a non-empty string (compared exactly)")
            pinned[k] = v
        pinned.setdefault("issuer", spec["issuer"])
        if not any(is_member(k, _NAMING_KEYS) for k in pinned):
            raise ValueError("identity names no workflow or repository (one of "
                             f"{sorted(_NAMING_KEYS)}); an issuer alone accepts every workflow in the world")
    elif identity is not None:
        raise ValueError(f"profile {profile} is signed by a registry key; identity does not apply")
    if expected_subject_name is not None and (type(expected_subject_name) is not str or not expected_subject_name):
        raise ValueError("expected_subject_name must be a non-empty string or None")
    if type(tlog_threshold) is not int or not 0 <= tlog_threshold <= 8:
        raise ValueError("tlog_threshold must be an integer within 0..8")
    return {"profile": profile, "spec": spec, "alg": alg, "hex": hexval, "identity": pinned,
            "subject_name": expected_subject_name, "tlog_threshold": tlog_threshold}


@_ein_stand
def verify_sigstore_bundle(
    bundle: Any,
    *,
    trusted_root: Any,
    artifact_digest: str,
    profile: str,
    identity: Optional[Mapping[str, str]] = None,
    registry_keys: Any = None,
    expected_subject_name: Optional[str] = None,
    tlog_threshold: int = 1,
) -> SigstoreVerdict:
    """Verify one Sigstore bundle (wire bytes, ``bytes`` or ``str``) under one profile of :data:`PROFILES`.

    ``trusted_root`` is the relying party's Sigstore trusted root, as its wire bytes (the
    ``trusted_root.json`` of the instance it trusts: the public-good instance for public repositories
    and npm, GitHub's own for private repositories). ``artifact_digest`` is the digest of the artifact
    the relying party holds, ``sha256:<hex>``, ``sha512:<hex>`` or an SRI string such as npm's
    ``dist.integrity``; a subject of the statement must carry it.

    ``identity`` (certificate profiles) maps ``san``, ``issuer`` and Fulcio extension names
    (``build_signer_uri``, ``source_repository_uri``, ``runner_environment``, ...) to the EXACT values
    expected; ``issuer`` defaults to the profile's issuer, and at least one key must name a workflow or
    repository. ``registry_keys`` (npm-publish) is the registry's keys document as wire bytes.
    ``expected_subject_name`` is compared with every subject's name when given. ``tlog_threshold``
    (default 1) is the number of distinct trusted logs whose entries must verify; 0 is for an instance
    without a transparency log (GitHub's private-repository instance), which then needs a verified
    RFC 3161 timestamp.

    The body never raises: unusable trust material and unreadable bytes come back as failing checks
    (exit 2), every other outcome as a check of its own. The arguments are read once at the call
    (``canonical._ein_stand``, like every public function of this package)."""
    res = VerificationResult()
    try:
        cfg = _read_config(_plain(profile), _plain(identity), _plain(artifact_digest), _plain(expected_subject_name),
                           tlog_threshold)
    except ValueError as exc:
        res.add("verifier-config", False, str(exc))
        return _finish(res)
    prof: str = cfg["profile"]
    spec = cfg["spec"]
    notes: List[str] = []
    try:
        root = _read_trusted_root(_wire(trusted_root, "the trusted root"))
        keys = None
        if spec["signer"] == "key":
            if registry_keys is None:
                raise _Unreadable("profile npm-publish needs registry_keys, the registry's keys document")
            keys = _read_registry_keys(_wire(registry_keys, "the registry keys document"))
        elif registry_keys is not None:
            raise _Unreadable(f"profile {prof} is certificate-signed; registry_keys does not apply")
    except _Unreadable as exc:
        res.add("verifier-config", False, str(exc))
        return _finish(res, profile=prof)
    notes.extend(f"trusted root entry skipped: {s}" for s in root.skipped)
    if cfg["tlog_threshold"] > len({log.log_id for log in root.tlogs}):
        res.add("verifier-config", False, f"tlog_threshold {cfg['tlog_threshold']} exceeds the trusted logs")
        return _finish(res, profile=prof, notes=notes)
    res.add("verifier-config", True, f"profile {prof}")

    # Read.
    try:
        raw = _wire(bundle, "the bundle")
        doc = _parse_json_bytes(raw, "the bundle")
    except _Unreadable as exc:
        res.add("readable", False, str(exc))
        return _finish(res, profile=prof, notes=notes)
    if type(doc) is not dict:
        res.add("readable", False, "the bundle is not a JSON object")
        return _finish(res, profile=prof, notes=notes)
    res.add("readable", True, f"{len(raw)} bytes of strict JSON")
    media = doc.get("mediaType")
    version = _BUNDLE_MEDIA_TYPES.get(media) if type(media) is str else None
    if version is None:
        res.add("media-type", False, f"mediaType {render_safe(doc.get('mediaType'))} is not a Sigstore bundle "
                                     "media type this module reads (0.1, 0.2, 0.3)")
        return _finish(res, profile=prof, notes=notes)
    res.add("media-type", True, f"bundle version 0.{version}")

    state: Dict[str, Any] = {"times": [], "identity": None, "predicate_type": None, "subjects": []}
    try:
        _verify_body(res, prof, spec, cfg, root, keys, doc, version, notes, state)
    except _Fail as exc:
        res.add(exc.check, False, str(exc))
    policy_ok = None
    if all(c.ok is True for c in res.checks if not is_member(c.name, _REQUIREMENT)):
        policy_ok = all(c.ok is True for c in res.checks if is_member(c.name, _REQUIREMENT)) and any(
            is_member(c.name, _REQUIREMENT) for c in res.checks)
    return _finish(res, profile=prof, version=version, times=state["times"], identity=state["identity"],
                   predicate_type=state["predicate_type"], subjects=state["subjects"], notes=notes,
                   policy_ok=policy_ok)


def _verify_body(res: VerificationResult, prof: str, spec: Dict[str, Any], cfg: Dict[str, Any],
                 root: _TrustedRoot, keys: Optional[Dict[str, _RegistryKey]], doc: Dict[str, Any],
                 version: int, notes: List[str], state: Dict[str, Any]) -> None:
    """The checks after the bundle was read, in the order of client-spec section 4. Each failure is
    raised as `_Fail` and ends the run: a later check judged on a bundle that is not intact would
    judge attacker-chosen values."""
    b = _read_bundle(doc, version)
    res.add("bundle-structure", True, f"{len(b.entries)} log entries, {len(b.timestamps)} RFC 3161 timestamps")
    if b.extra_chain:
        notes.append(f"{b.extra_chain} chain certificate(s) after the leaf were ignored: intermediates are "
                     "taken from the trusted root only (client-spec 4.6, out-of-band intermediate CAs)")

    # The signer: a Fulcio leaf or a registry key.
    leaf: Optional[_Leaf] = None
    reg: Optional[_RegistryKey] = None
    if spec["signer"] == "fulcio":
        if b.leaf_der is None:
            raise _Fail("bundle-structure", f"profile {prof} needs a Fulcio certificate; the bundle carries a key hint")
        leaf = _read_leaf(b.leaf_der)
        signer_key, verifier_der = leaf.key, leaf.der
        res.add("certificate", True, f"Fulcio leaf, {leaf.key.kind}, SAN {render_safe(leaf.san)}")
        state["identity"] = dict(leaf.extensions, san=leaf.san)
    elif spec["signer"] == "key":
        assert keys is not None
        if b.key_hint is None:
            raise _Fail("bundle-structure", f"profile {prof} needs a public key hint; the bundle carries a certificate")
        reg = keys.get(b.key_hint)
        if reg is None:
            raise _Fail("public-key", f"key hint {render_safe(b.key_hint)} names no key of the registry document")
        if b.keyid is not None and b.keyid != b.key_hint:
            raise _Fail("public-key", "the DSSE signature's keyid and the bundle's key hint differ "
                                      "(sigstore_bundle.proto: they MUST be exactly the same)")
        signer_key, verifier_der = reg.key, reg.der
        res.add("public-key", True, f"registry key {render_safe(b.key_hint)}")
    else:
        raise _Fail("verifier-config", f"profile {prof} names no signer kind this module knows")

    # The one signature, over the DSSE pre-authentication encoding.
    if not _verify(signer_key, b.signature, pae(b.payload_type, b.payload)):
        raise _Fail("signature", "the DSSE signature does not verify under the "
                                 + ("leaf certificate's key" if leaf is not None else "registry key"))
    res.add("signature", True, "DSSE PAE signature verifies")

    # Transparency log entries.
    times: List[int] = []
    verified_logs = set()
    for entry in b.entries:
        where = f"tlogEntries[{entry.position}]"
        log = _find_log(root.tlogs, entry.log_id)
        if log is None:
            raise _Fail("tlog-entry", f"{where} names a log the trusted root does not list "
                                      f"({entry.log_id.hex()[:16]}...)")
        if not is_member((entry.kind, entry.version), _KINDS):
            raise _Fail("unsupported", f"{where} is a Rekor {render_safe(entry.kind)} {render_safe(entry.version)} "
                                       "entry; this module reads dsse 0.0.1 and intoto 0.0.2 (Rekor v1)")
        if entry.body is None:
            raise _Fail("unsupported", f"{where} carries no canonicalizedBody, and this module does not "
                                       "rebuild one")
        _check_body(entry, b, verifier_der)
        res.add("tlog-body", True, f"{where}: {entry.kind} {entry.version} commits to this signature and signer")
        if entry.set_signature is not None:
            if not _verify(log.key, entry.set_signature, _set_payload(entry)):
                raise _Fail("tlog-set", f"{where}: the signed entry timestamp does not verify under {log.base_url}")
            at = entry.integrated_time * 1_000_000_000
            if not log.valid_at(at):
                raise _Fail("tlog-set", f"{where}: integratedTime {_iso(at)} is outside the log key's validity")
            times.append(at)
            res.add("tlog-set", True, f"{where}: integratedTime {_iso(at)} signed by {log.base_url}")
        if entry.proof is not None:
            proof = entry.proof
            if not proof["log_index"] < proof["tree_size"]:
                raise _Fail("tlog-inclusion", f"{where}: the proof's index is not inside its tree")
            if not merkle.verify_inclusion(entry.body, proof["log_index"], proof["tree_size"], proof["hashes"],
                                           proof["root_hash"]):
                raise _Fail("tlog-inclusion", f"{where}: the inclusion proof does not lead from the body to the root")
            res.add("tlog-inclusion", True, f"{where}: leaf {proof['log_index']} of {proof['tree_size']}")
            origin = _check_checkpoint(log, proof)
            res.add("tlog-checkpoint", True, f"{where}: checkpoint signed by {log.base_url}")
            notes.append(f"{where}: checkpoint origin {render_safe(origin)} (reported, not pinned)")
        verified_logs.add(log.log_id)
    if len(verified_logs) < cfg["tlog_threshold"]:
        raise _Fail("tlog-threshold", f"{len(verified_logs)} trusted log(s) verified, {cfg['tlog_threshold']} required")
    if b.entries:
        res.add("tlog-threshold", True, f"{len(verified_logs)} of {cfg['tlog_threshold']} required log(s)")

    for i, token in enumerate(b.timestamps):
        gen = _verify_timestamp(token, b.signature, root.tsas)
        times.append(gen)
        res.add("timestamp-authority", True, f"rfc3161Timestamps[{i}]: genTime {_iso(gen)}")

    # A time for the signature (client-spec 4.2), inside the signer's validity.
    if not times:
        raise _Fail("signing-time", "no verified time source: no signed entry timestamp and no RFC 3161 "
                                    "timestamp verified, and an unsigned integratedTime is not trusted")
    state["times"] = times
    for at in times:
        if leaf is not None and not leaf.not_before <= at <= leaf.not_after:
            raise _Fail("signing-time", f"the leaf certificate was not valid at the verified time {_iso(at)}")
        if reg is not None and reg.expires is not None and at > reg.expires:
            raise _Fail("signing-time", f"the registry key had expired at the verified time {_iso(at)}")
    res.add("signing-time", True, ", ".join(_iso(t) for t in times))

    # Certificate path at every verified time (hybrid model), then the embedded SCT.
    if leaf is not None:
        issuer = None
        for at in times:
            problems = []
            for ca in root.cas:
                why = _chain_problem(leaf.cert, ca, at)
                if why is None:
                    issuer = ca.chain[0]
                    break
                problems.append(why)
            else:
                raise _Fail("certificate-chain", f"the leaf does not chain to a trusted CA at {_iso(at)}: "
                            + ("; ".join(problems) or "the trusted root lists no CA"))
        res.add("certificate-chain", True, f"chains to a trusted CA at {len(times)} verified time(s)")
        why = _sct_problem(leaf, issuer, root.ctlogs)
        if why is not None:
            raise _Fail("sct", why)
        res.add("sct", True, "an embedded SCT verifies under a trusted CT log")

    # The statement.
    if b.payload_type != INTOTO_PAYLOAD_TYPE:
        raise _Fail("statement", f"payloadType {render_safe(b.payload_type)} is not {INTOTO_PAYLOAD_TYPE}")
    statement = _load_statement(b.payload, spec["statement_types"])
    state["subjects"] = [s.get("name") if type(s.get("name")) is str else "" for s in statement["subject"]]
    res.add("statement", True, f"in-toto {statement['_type'].rsplit('/', 1)[-1]} Statement, {len(statement['subject'])} subject(s)")
    ptype = statement.get("predicateType")
    state["predicate_type"] = ptype if type(ptype) is str else None
    if ptype != spec["predicate_type"]:
        raise _Fail("predicate-type", f"predicateType {render_safe(ptype)} is not {spec['predicate_type']}, the "
                                      f"one predicate profile {prof} reads")
    res.add("predicate-type", True, spec["predicate_type"])
    pred = statement.get("predicate")
    if spec["predicate_type"] == SLSA_PROVENANCE_V1:
        assert leaf is not None
        slsa = _slsa_v1(pred)
        if prof == "npm-provenance" and slsa["buildDefinition"]["buildType"] == NPM_GITLAB_BUILD_TYPE:
            raise _Fail("unsupported", "npm provenance built on GitLab CI is not implemented in this profile")
        build_type = slsa["buildDefinition"]["buildType"]
        if not is_member(build_type, spec["build_types"]):
            raise _Fail("predicate", f"buildType {render_safe(build_type)} is not one of {list(spec['build_types'])}")
        _workflow_params(slsa["buildDefinition"])
        if build_type == GITHUB_BUILD_TYPE:
            _github_build_type(slsa["buildDefinition"])
        _github_event(slsa["buildDefinition"], leaf)
        res.add("predicate", True, f"SLSA Provenance v1, buildType {build_type}")
        notes.append(_check_slsa_binding(slsa, leaf))
    elif spec["predicate_type"] == NPM_PUBLISH_V0_1:
        _check_npm_publish(pred, statement)
        res.add("predicate", True, "npm publish attestation v0.1")
    else:
        raise _Fail("predicate-type", f"profile {prof} names a predicate type this module does not read")

    # Relying-party requirements: identity, artifact digest, subject name. Each is judged.
    if leaf is not None:
        got = dict(leaf.extensions, san=leaf.san)
        wrong = [f"{k}: expected {render_safe(v)}, certificate says {render_safe(got.get(k))}"
                 for k, v in sorted(cfg["identity"].items()) if got.get(k) != v]
        res.add("identity", not wrong, "; ".join(wrong) if wrong else
                "certificate names " + ", ".join(sorted(cfg["identity"])) + " as expected")
    alg, want = cfg["alg"], cfg["hex"]
    hits = [i for i, s in enumerate(statement["subject"])
            if type(s["digest"].get(alg)) is str and hmac.compare_digest(s["digest"][alg], want)]
    res.add("subject-digest", bool(hits), f"subject[{hits[0]}] carries {alg}:{want[:16]}..." if hits else
            f"no subject carries {alg}:{want[:16]}... (the attestation is about another artifact)")
    if cfg["subject_name"] is not None:
        named = [s.get("name") for s in statement["subject"]]
        res.add("subject-name", cfg["subject_name"] in named,
                f"subject names {render_safe(named)}, expected {render_safe(cfg['subject_name'])}")
