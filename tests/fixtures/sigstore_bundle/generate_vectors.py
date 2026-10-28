"""Build the vectors of tests/test_sigstore_bundle.py: synthetic Sigstore bundles from fixed test keys,
and byte edits of the public bundles under public/.

WHY SYNTHETIC VECTORS. A public bundle can only be broken, never re-signed: every edit of it fails at the
first signature it touches, so a negative built from it says nothing about the checks after that one. A
test instance of Sigstore (a Fulcio-like CA, a CT log, a Rekor-like log, an npm-like registry key, each
a fixed test key below) can sign a bundle that is intact in every respect but one, so each negative
vector fails at exactly the step it names and nowhere earlier. Every key is derived from a fixed scalar
and every ECDSA signature is deterministic (RFC 6979), so this script writes the same bytes on every run.

INDEPENDENT OF THE VERIFIER. Nothing here imports proofbundle. The RFC 6962 tree, the SCT signing input,
the checkpoint note, the Signed Entry Timestamp payload and the Rekor bodies are written out below from
the specifications named in tests/fixtures/sigstore_bundle/README.md, so a vector does not inherit a
mistake of the code it tests.

Run it from the repository root: ``python tests/fixtures/sigstore_bundle/generate_vectors.py``. It needs a
cryptography release with deterministic ECDSA (``ecdsa_deterministic`` on the certificate builder); the
verifier itself does not.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

HERE = Path(__file__).resolve().parent

# --------------------------------------------------------------------------------------------
# Test keys. TEST MATERIAL ONLY: the scalars are printed here on purpose.
# --------------------------------------------------------------------------------------------


def _key(scalar: int, curve: Any = None) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(scalar, curve or ec.SECP256R1())


ROOT_KEY = _key(0x5157_0001, ec.SECP384R1())
INTERMEDIATE_KEY = _key(0x5157_0002, ec.SECP384R1())
FOREIGN_ROOT_KEY = _key(0x5157_0003, ec.SECP384R1())
LEAF_KEY = _key(0x5157_1001)
OTHER_KEY = _key(0x5157_1002)
CT_KEY = _key(0x5157_2001)
FOREIGN_CT_KEY = _key(0x5157_2002)
REKOR_KEY = _key(0x5157_3001)
FOREIGN_REKOR_KEY = _key(0x5157_3002)
REGISTRY_KEY = _key(0x5157_4001)
FOREIGN_REGISTRY_KEY = _key(0x5157_4002)


def _hash_for(key: Any) -> hashes.HashAlgorithm:
    return hashes.SHA384() if isinstance(key.curve, ec.SECP384R1) else hashes.SHA256()


def _sign(key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    return key.sign(data, ec.ECDSA(_hash_for(key), deterministic_signing=True))


def _spki(key: Any) -> bytes:
    pub = key.public_key() if hasattr(key, "public_key") else key
    return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _canonical(obj: Any) -> bytes:
    """Sorted keys, no whitespace: the form Rekor stores its bodies in and signs its SET over."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# --------------------------------------------------------------------------------------------
# Times. Every vector lives in one fixed hour of 2026.
# --------------------------------------------------------------------------------------------

T0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
INTEGRATED = int(T0.timestamp()) + 60
CA_FROM = datetime(2025, 1, 1, tzinfo=timezone.utc)
CA_UNTIL = datetime(2035, 1, 1, tzinfo=timezone.utc)

# --------------------------------------------------------------------------------------------
# DER and TLS framing.
# --------------------------------------------------------------------------------------------


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def der_utf8(text: str) -> bytes:
    raw = text.encode("utf-8")
    return b"\x0c" + _der_len(len(raw)) + raw


def der_octets(raw: bytes) -> bytes:
    return b"\x04" + _der_len(len(raw)) + raw


# --------------------------------------------------------------------------------------------
# The test CA, its leaf certificates and their embedded SCTs (RFC 6962 sections 3.2 and 3.3).
# --------------------------------------------------------------------------------------------


def _ca_cert(key: Any, issuer_key: Any, issuer_name: x509.Name, name: x509.Name, serial: int,
             path_length: int) -> x509.Certificate:
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer_name)
               .public_key(key.public_key()).serial_number(serial)
               .not_valid_before(CA_FROM).not_valid_after(CA_UNTIL)
               .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
               .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                            key_encipherment=False, data_encipherment=False,
                                            key_agreement=False, key_cert_sign=True, crl_sign=True,
                                            encipher_only=False, decipher_only=False), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    return builder.sign(issuer_key, hashes.SHA384(), ecdsa_deterministic=True)


ROOT_NAME = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "proofbundle test"),
                       x509.NameAttribute(NameOID.COMMON_NAME, "test-fulcio-root")])
INTERMEDIATE_NAME = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "proofbundle test"),
                               x509.NameAttribute(NameOID.COMMON_NAME, "test-fulcio-intermediate")])
FOREIGN_NAME = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "proofbundle test"),
                          x509.NameAttribute(NameOID.COMMON_NAME, "foreign-ca-not-trusted")])
ROOT_CERT = _ca_cert(ROOT_KEY, ROOT_KEY, ROOT_NAME, ROOT_NAME, 1, 1)
INTERMEDIATE_CERT = _ca_cert(INTERMEDIATE_KEY, ROOT_KEY, ROOT_NAME, INTERMEDIATE_NAME, 2, 0)
# The foreign CA reuses the intermediate's NAME, so a verifier that matched by name alone would accept it.
FOREIGN_CERT = _ca_cert(FOREIGN_ROOT_KEY, FOREIGN_ROOT_KEY, INTERMEDIATE_NAME, INTERMEDIATE_NAME, 3, 0)

FULCIO_OIDS = {
    "issuer": "1.3.6.1.4.1.57264.1.8", "build_signer_uri": "1.3.6.1.4.1.57264.1.9",
    "build_signer_digest": "1.3.6.1.4.1.57264.1.10", "runner_environment": "1.3.6.1.4.1.57264.1.11",
    "source_repository_uri": "1.3.6.1.4.1.57264.1.12", "source_repository_digest": "1.3.6.1.4.1.57264.1.13",
    "source_repository_ref": "1.3.6.1.4.1.57264.1.14", "source_repository_identifier": "1.3.6.1.4.1.57264.1.15",
    "source_repository_owner_uri": "1.3.6.1.4.1.57264.1.16",
    "source_repository_owner_identifier": "1.3.6.1.4.1.57264.1.17",
    "build_config_uri": "1.3.6.1.4.1.57264.1.18", "build_config_digest": "1.3.6.1.4.1.57264.1.19",
    "build_trigger": "1.3.6.1.4.1.57264.1.20", "run_invocation_uri": "1.3.6.1.4.1.57264.1.21",
    "source_repository_visibility_at_signing": "1.3.6.1.4.1.57264.1.22",
}
#: The deprecated extensions a vector writes. Their value is the raw UTF-8 bytes, without DER (fulcio
#: docs/oid-info.md, 1.1 to 1.6).
LEGACY_OIDS = {"github_workflow_trigger": "1.3.6.1.4.1.57264.1.2"}
SCT_LIST_OID = ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")


def _sct(ct_key: Any, tbs: bytes, issuer_public_key: Any, ms: int) -> bytes:
    """One serialized SignedCertificateTimestamp over a precertificate entry (RFC 6962 section 3.2)."""
    issuer_key_hash = hashlib.sha256(_spki(issuer_public_key)).digest()
    signed = (b"\x00\x00" + ms.to_bytes(8, "big") + b"\x00\x01" + issuer_key_hash
              + len(tbs).to_bytes(3, "big") + tbs + b"\x00\x00")
    sig = _sign(ct_key, signed)
    log_id = hashlib.sha256(_spki(ct_key)).digest()
    return (b"\x00" + log_id + ms.to_bytes(8, "big") + b"\x00\x00" + b"\x04\x03"
            + len(sig).to_bytes(2, "big") + sig)


def leaf_cert(extensions: Dict[str, str], san: str, *, issuer_key: Any = INTERMEDIATE_KEY,
              issuer_cert: x509.Certificate = INTERMEDIATE_CERT, ct_key: Optional[Any] = CT_KEY,
              key: Any = LEAF_KEY, not_before: datetime = T0, minutes: int = 10,
              extra_sans: tuple = (), subject: Optional[x509.Name] = None) -> x509.Certificate:
    """A Fulcio-shaped leaf: empty subject, one URI SAN, codeSigning, the Fulcio extensions, and (with a
    ``ct_key``) an embedded SCT over the precertificate TBS."""
    def builder() -> x509.CertificateBuilder:
        b = (x509.CertificateBuilder().subject_name(subject or x509.Name([])).issuer_name(issuer_cert.subject)
             .public_key(key.public_key()).serial_number(0x5157_0000_0001)
             .not_valid_before(not_before).not_valid_after(not_before + timedelta(minutes=minutes))
             .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                          key_encipherment=False, data_encipherment=False, key_agreement=False,
                                          key_cert_sign=False, crl_sign=False, encipher_only=False,
                                          decipher_only=False), critical=True)
             .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=False)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                            critical=False)
             .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(u) for u in (san,) + extra_sans]),
                            critical=True))
        for name, value in extensions.items():
            if name in LEGACY_OIDS:
                ext = x509.UnrecognizedExtension(ObjectIdentifier(LEGACY_OIDS[name]), value.encode("utf-8"))
            else:
                ext = x509.UnrecognizedExtension(ObjectIdentifier(FULCIO_OIDS[name]), der_utf8(value))
            b = b.add_extension(ext, critical=False)
        return b

    if ct_key is None:
        return builder().sign(issuer_key, hashes.SHA384(), ecdsa_deterministic=True)
    pre = builder().sign(issuer_key, hashes.SHA384(), ecdsa_deterministic=True)
    sct = _sct(ct_key, pre.tbs_certificate_bytes, issuer_key.public_key(), int(not_before.timestamp()) * 1000)
    sct_list = len(sct).to_bytes(2, "big") + sct
    final = (builder().add_extension(
        x509.UnrecognizedExtension(SCT_LIST_OID, der_octets(len(sct_list).to_bytes(2, "big") + sct_list)),
        critical=False).sign(issuer_key, hashes.SHA384(), ecdsa_deterministic=True))
    assert final.tbs_precertificate_bytes == pre.tbs_certificate_bytes, "precertificate TBS drifted"
    return final


def _pem(cert_or_key: Any) -> bytes:
    if isinstance(cert_or_key, x509.Certificate):
        return cert_or_key.public_bytes(serialization.Encoding.PEM)
    return cert_or_key.public_key().public_bytes(serialization.Encoding.PEM,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)


# --------------------------------------------------------------------------------------------
# The test log: RFC 6962 tree, checkpoint note, Signed Entry Timestamp.
# --------------------------------------------------------------------------------------------


def _leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def tree_hash(leaves: List[bytes]) -> bytes:
    if len(leaves) == 1:
        return _leaf_hash(leaves[0])
    k = _split(len(leaves))
    return _node(tree_hash(leaves[:k]), tree_hash(leaves[k:]))


def audit_path(leaves: List[bytes], m: int) -> List[bytes]:
    """RFC 6962 section 2.1.1 PATH(m, D[n]), leaf to root."""
    if len(leaves) == 1:
        return []
    k = _split(len(leaves))
    if m < k:
        return audit_path(leaves[:k], m) + [tree_hash(leaves[k:])]
    return audit_path(leaves[k:], m - k) + [tree_hash(leaves[:k])]


LOG_NAME = "rekor.test.example"
LOG_ORIGIN = "rekor.test.example - 4242"
OTHER_LEAVES = [b"entry zero", b"entry one", b"entry two", b"entry four"]
LEAF_INDEX = 3
GLOBAL_INDEX = 100003


def checkpoint(size: int, root: bytes, key: Any = REKOR_KEY, bad_second_line: bool = False) -> str:
    text = f"{LOG_ORIGIN}\n{size}\n{_b64(root)}\n"
    hint = hashlib.sha256(_spki(key)).digest()[:4]
    note = text + "\n" + f"\u2014 {LOG_NAME} {_b64(hint + _sign(key, text.encode('utf-8')))}\n"
    if bad_second_line:
        # A second line under the log's key ID whose signature is over other text (contract SV-46).
        note += f"\u2014 mirror.{LOG_NAME} {_b64(hint + _sign(key, b'other text'))}\n"
    return note


def set_payload(body: bytes, integrated: int, log_key: Any, log_index: int) -> bytes:
    return _canonical({"body": _b64(body), "integratedTime": integrated,
                       "logID": hashlib.sha256(_spki(log_key)).hexdigest(), "logIndex": log_index})


# --------------------------------------------------------------------------------------------
# The identity, the statements and the trust material.
# --------------------------------------------------------------------------------------------

ISSUER = "https://token.actions.githubusercontent.com"
REPO = "https://github.com/octo-org/octo-repo"
REF = "refs/heads/main"
COMMIT = "4f2b8d0c6a1e9b7d3c5a2f8e1d4b6c9a0e3f7b2d"
WORKFLOW = ".github/workflows/release.yml"
WORKFLOW_URI = f"{REPO}/{WORKFLOW}@{REF}"
RUN = f"{REPO}/actions/runs/4242/attempts/1"

EXTENSIONS = {
    "issuer": ISSUER, "build_signer_uri": WORKFLOW_URI, "build_signer_digest": COMMIT,
    "runner_environment": "github-hosted", "source_repository_uri": REPO, "source_repository_digest": COMMIT,
    "source_repository_ref": REF, "source_repository_identifier": "123456",
    "source_repository_owner_uri": "https://github.com/octo-org", "source_repository_owner_identifier": "654321",
    "build_config_uri": WORKFLOW_URI, "build_config_digest": COMMIT, "build_trigger": "push",
    "run_invocation_uri": RUN, "source_repository_visibility_at_signing": "public",
}

ARTIFACT = b"octo-artifact release bytes v1\n"
NPM_TARBALL = b"octo-pkg 1.0.0 tarball bytes\n"
GITHUB_BUILD_TYPE = "https://actions.github.io/buildtypes/workflow/v1"
NPM_BUILD_TYPE = "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"


def provenance_statement(build_type: str = GITHUB_BUILD_TYPE, *, npm: bool = False) -> Dict[str, Any]:
    """The statement actions/attest-build-provenance (GITHUB_BUILD_TYPE, or NPM_BUILD_TYPE in 2024) or
    npm publish --provenance (NPM_BUILD_TYPE, ``npm=True``) writes for the run the EXTENSIONS describe."""
    github = {"event_name": "push", "repository_id": "123456", "repository_owner_id": "654321"}
    if build_type == GITHUB_BUILD_TYPE:
        github["runner_environment"] = "github-hosted"
        builder = WORKFLOW_URI
    else:
        builder = "https://github.com/actions/runner/github-hosted"
    if npm:
        subject = [{"name": "pkg:npm/octo-pkg@1.0.0", "digest": {"sha512": hashlib.sha512(NPM_TARBALL).hexdigest()}}]
    else:
        subject = [{"name": "octo-artifact.tar.gz", "digest": {"sha256": hashlib.sha256(ARTIFACT).hexdigest()}}]
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subject,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": build_type,
                "externalParameters": {"workflow": {"ref": REF, "repository": REPO, "path": WORKFLOW}},
                "internalParameters": {"github": github},
                "resolvedDependencies": [{"uri": f"git+{REPO}@{REF}", "digest": {"gitCommit": COMMIT}}],
            },
            "runDetails": {"builder": {"id": builder}, "metadata": {"invocationId": RUN}},
        },
    }


def publish_statement() -> Dict[str, Any]:
    return {
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [{"name": "pkg:npm/octo-pkg@1.0.0", "digest": {"sha512": hashlib.sha512(NPM_TARBALL).hexdigest()}}],
        "predicateType": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
        "predicate": {"name": "octo-pkg", "version": "1.0.0", "registry": "https://registry.npmjs.org"},
    }


def registry_keyid(key: Any) -> str:
    return "SHA256:" + _b64(hashlib.sha256(_spki(key)).digest()).rstrip("=")


def trusted_root(log_id_of: Any = None) -> bytes:
    """The test instance's trusted root. ``log_id_of`` names another key whose hash is written as the
    Rekor log's logId, for the vector that a log ID must be the hash of the log's own key (SV-19)."""
    def log(base: str, key: Any, id_key: Any = None) -> Dict[str, Any]:
        return {"baseUrl": base, "hashAlgorithm": "SHA2_256",
                "publicKey": {"rawBytes": _b64(_spki(key)), "keyDetails": "PKIX_ECDSA_P256_SHA_256",
                              "validFor": {"start": "2025-01-01T00:00:00Z"}},
                "logId": {"keyId": _b64(hashlib.sha256(_spki(id_key or key)).digest())}}
    der = serialization.Encoding.DER
    root = {
        "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
        "tlogs": [log("https://rekor.test.example", REKOR_KEY, log_id_of)],
        "certificateAuthorities": [{
            "subject": {"organization": "proofbundle test", "commonName": "test-fulcio"},
            "uri": "https://fulcio.test.example",
            "certChain": {"certificates": [{"rawBytes": _b64(INTERMEDIATE_CERT.public_bytes(der))},
                                           {"rawBytes": _b64(ROOT_CERT.public_bytes(der))}]},
            "validFor": {"start": "2025-01-01T00:00:00Z"}}],
        "ctlogs": [log("https://ctfe.test.example", CT_KEY)],
        "timestampAuthorities": [],
    }
    return json.dumps(root, indent=2).encode("utf-8") + b"\n"


def registry_keys() -> bytes:
    doc = {"keys": [
        {"expires": "2026-01-01T00:00:00.000Z", "keyid": registry_keyid(FOREIGN_REGISTRY_KEY),
         "keytype": "ecdsa-sha2-nistp256", "scheme": "ecdsa-sha2-nistp256", "key": _b64(_spki(FOREIGN_REGISTRY_KEY))},
        {"expires": None, "keyid": registry_keyid(REGISTRY_KEY),
         "keytype": "ecdsa-sha2-nistp256", "scheme": "ecdsa-sha2-nistp256", "key": _b64(_spki(REGISTRY_KEY))},
    ]}
    return json.dumps(doc, indent=2).encode("utf-8") + b"\n"


# --------------------------------------------------------------------------------------------
# The bundle builder. Each keyword is one controlled departure from an intact bundle.
# --------------------------------------------------------------------------------------------


def bundle(*, version: str = "0.3", statement: Optional[Dict[str, Any]] = None, kind: str = "dsse",
           signer: str = "fulcio", extensions: Optional[Dict[str, str]] = None, san: str = WORKFLOW_URI,
           cert: Optional[x509.Certificate] = None, payload: Optional[bytes] = None,
           payload_type: str = "application/vnd.in-toto+json", dsse_key: Any = None,
           log_key: Any = REKOR_KEY, set_key: Any = None, checkpoint_key: Any = REKOR_KEY,
           integrated: int = INTEGRATED, set_integrated: Optional[int] = None, promise: bool = True,
           proof: bool = True, flip_proof_hash: bool = False, checkpoint_root: Optional[bytes] = None,
           bad_checkpoint_line: bool = False,
           body_edit: Optional[Callable[[Dict[str, Any]], None]] = None,
           body_cert: Optional[x509.Certificate] = None, timestamps: bool = True,
           registry_key: Any = REGISTRY_KEY, cert_edit: Optional[Callable[[bytes], bytes]] = None,
           edit: Optional[Callable[[Dict[str, Any]], None]] = None) -> bytes:
    """An intact bundle unless a keyword says otherwise. ``dsse_key`` signs the envelope (default: the
    leaf key, or the registry key for ``signer="registry"``); ``set_key`` signs the SET (default: the log
    key); ``set_integrated`` is the time the SET signs while ``integrated`` is the time the entry states."""
    if statement is None:
        statement = provenance_statement()
    body_bytes = payload if payload is not None else json.dumps(statement, indent=2).encode("utf-8")
    if signer == "fulcio":
        leaf = cert if cert is not None else leaf_cert(extensions if extensions is not None else EXTENSIONS, san)
        signing_key = dsse_key or LEAF_KEY
        verifier_pem = _pem(body_cert if body_cert is not None else leaf)
    else:
        leaf = None
        signing_key = dsse_key or registry_key
        verifier_pem = _pem(registry_key)
    pae = (b"DSSEv1 " + str(len(payload_type)).encode() + b" " + payload_type.encode() + b" "
           + str(len(body_bytes)).encode() + b" " + body_bytes)
    sig = _sign(signing_key, pae)
    envelope = {"payload": _b64(body_bytes), "payloadType": payload_type,
                "signatures": [{"sig": _b64(sig), "keyid": registry_keyid(registry_key) if signer == "registry" else ""}]}
    payload_hash = {"algorithm": "sha256", "value": hashlib.sha256(body_bytes).hexdigest()}
    envelope_hash = {"algorithm": "sha256", "value": hashlib.sha256(_canonical(envelope)).hexdigest()}
    if kind == "dsse":
        rekor = {"apiVersion": "0.0.1", "kind": "dsse",
                 "spec": {"envelopeHash": envelope_hash, "payloadHash": payload_hash,
                          "signatures": [{"signature": _b64(sig), "verifier": _b64(verifier_pem)}]}}
    else:
        rekor = {"apiVersion": "0.0.2", "kind": "intoto",
                 "spec": {"content": {"envelope": {"payloadType": payload_type, "signatures": [
                     {"publicKey": _b64(verifier_pem), "sig": _b64(_b64(sig).encode("ascii"))}]},
                     "hash": envelope_hash, "payloadHash": payload_hash}}}
    if body_edit is not None:
        body_edit(rekor)
    body = _canonical(rekor)
    leaves = OTHER_LEAVES[:LEAF_INDEX] + [body] + OTHER_LEAVES[LEAF_INDEX:]
    root = tree_hash(leaves)
    path = audit_path(leaves, LEAF_INDEX)
    if flip_proof_hash:
        path[0] = bytes([path[0][0] ^ 0x01]) + path[0][1:]
    entry: Dict[str, Any] = {
        "logIndex": str(GLOBAL_INDEX),
        "logId": {"keyId": _b64(hashlib.sha256(_spki(log_key)).digest())},
        "kindVersion": {"kind": rekor["kind"], "version": rekor["apiVersion"]},
        "integratedTime": str(integrated),
    }
    if promise:
        signed_time = integrated if set_integrated is None else set_integrated
        entry["inclusionPromise"] = {"signedEntryTimestamp": _b64(_sign(
            set_key or log_key, set_payload(body, signed_time, log_key, GLOBAL_INDEX)))}
    if proof:
        entry["inclusionProof"] = {
            "logIndex": str(LEAF_INDEX), "rootHash": _b64(root), "treeSize": str(len(leaves)),
            "hashes": [_b64(h) for h in path],
            "checkpoint": {"envelope": checkpoint(len(leaves), checkpoint_root or root, checkpoint_key,
                                                  bad_checkpoint_line)}}
    entry["canonicalizedBody"] = _b64(body)
    material: Dict[str, Any] = {}
    der = serialization.Encoding.DER
    if leaf is None:
        material["publicKey"] = {"hint": registry_keyid(registry_key)}
    elif version == "0.3":
        leaf_der = leaf.public_bytes(der)
        material["certificate"] = {"rawBytes": _b64(cert_edit(leaf_der) if cert_edit else leaf_der)}
    else:
        material["x509CertificateChain"] = {"certificates": [{"rawBytes": _b64(leaf.public_bytes(der))}]}
    material["tlogEntries"] = [entry]
    if timestamps:
        material["timestampVerificationData"] = {}
    media = ("application/vnd.dev.sigstore.bundle.v0.3+json" if version == "0.3"
             else f"application/vnd.dev.sigstore.bundle+json;version={version}")
    doc = {"mediaType": media, "verificationMaterial": material, "dsseEnvelope": envelope}
    if edit is not None:
        edit(doc)
    return json.dumps(doc, indent=2).encode("utf-8") + b"\n"


# --------------------------------------------------------------------------------------------
# The cases. Each names the contract step it exercises, the profile, and the verdict a reader of the
# specifications expects: the exit code and the one check that fails (None for a positive control).
# --------------------------------------------------------------------------------------------

GITHUB_IDENTITY = {"source_repository_uri": REPO, "build_signer_uri": WORKFLOW_URI}
NPM_IDENTITY = {"source_repository_uri": REPO}
SHA256_ARTIFACT = "sha256:" + hashlib.sha256(ARTIFACT).hexdigest()
SHA512_TARBALL = "sha512:" + hashlib.sha512(NPM_TARBALL).hexdigest()
SRI_TARBALL = "sha512-" + _b64(hashlib.sha512(NPM_TARBALL).digest())


def version_document(*, name: str = "octo-pkg", version: str = "1.0.0", integrity: str = SRI_TARBALL,
                     key: Any = REGISTRY_KEY, keyid: Optional[str] = None, message: Optional[str] = None,
                     signatures: bool = True) -> bytes:
    """The registry's version document (``https://registry.npmjs.org/<name>/<version>``), cut to the
    members the reader uses, with a registry signature in dist.signatures over
    ``${name}@${version}:${dist.integrity}`` (npm docs, "About registry signatures") unless ``message``
    names another signed text."""
    dist: Dict[str, Any] = {"integrity": integrity, "shasum": hashlib.sha1(NPM_TARBALL).hexdigest(),
                            "tarball": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"}
    if signatures:
        signed = (message if message is not None else f"{name}@{version}:{integrity}").encode("utf-8")
        dist["signatures"] = [{"sig": _b64(_sign(key, signed)), "keyid": keyid or registry_keyid(key)}]
    return json.dumps({"name": name, "version": version, "dist": dist}, indent=2).encode("utf-8") + b"\n"


def package_json(*, name: str = "octo-pkg", version: str = "1.0.0", repository: Any = None,
                 drop_repository: bool = False) -> bytes:
    """The package.json of the npm tarball, with the repository in the object form npm normalizes it to
    (npm docs, package.json "repository") unless ``repository`` names another value."""
    doc: Dict[str, Any] = {"name": name, "version": version, "description": "test package of the vectors"}
    if not drop_repository:
        doc["repository"] = repository if repository is not None else {"type": "git", "url": f"git+{REPO}.git"}
    return json.dumps(doc, indent=2).encode("utf-8") + b"\n"


def _with(base: Dict[str, Any], **changes: Any) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    out.update(changes)
    return out


def _statement_edit(fn: Callable[[Dict[str, Any]], None], build_type: str = GITHUB_BUILD_TYPE, *,
                    npm: bool = False) -> Dict[str, Any]:
    st = provenance_statement(build_type, npm=npm)
    fn(st)
    return st


def _dispatch_inputs_and_vars(st: Dict[str, Any]) -> None:
    bd = st["predicate"]["buildDefinition"]
    bd["externalParameters"].update(inputs={"version": "1.2.3"}, vars={"REGION": "eu"})
    bd["internalParameters"]["github"]["event_name"] = "workflow_dispatch"


def _event(name: str) -> Callable[[Dict[str, Any]], None]:
    def fn(st: Dict[str, Any]) -> None:
        st["predicate"]["buildDefinition"]["internalParameters"]["github"]["event_name"] = name
    return fn


def _legacy_trigger(event: str, *, modern: Optional[str] = None) -> Dict[str, str]:
    """EXTENSIONS with the run's event in the deprecated extension 1.2 instead of the build trigger 1.20, or
    with ``modern`` in 1.20 beside it. Fulcio copies both from the token's event_name claim."""
    out = {k: v for k, v in EXTENSIONS.items() if k != "build_trigger"}
    if modern is not None:
        out["build_trigger"] = modern
    out["github_workflow_trigger"] = event
    return out


def _two_subjects(digest_name: str, other_name: str) -> Callable[[Dict[str, Any]], None]:
    """Two subjects: ``digest_name`` carries the artifact's digest, ``other_name`` another digest."""
    def fn(st: Dict[str, Any]) -> None:
        st["subject"] = [{"name": digest_name, "digest": {"sha256": hashlib.sha256(ARTIFACT).hexdigest()}},
                         {"name": other_name, "digest": {"sha256": hashlib.sha256(b"other artifact").hexdigest()}}]
    return fn


def _two_npm_subjects(st: Dict[str, Any]) -> None:
    """octo-pkg@1.0.0 with another digest, and the tarball's digest under another package."""
    st["subject"] = [
        {"name": "pkg:npm/octo-pkg@1.0.0", "digest": {"sha512": hashlib.sha512(b"other tarball").hexdigest()}},
        {"name": "pkg:npm/other-pkg@1.0.0", "digest": {"sha512": hashlib.sha512(NPM_TARBALL).hexdigest()}}]


def _other_repository(st: Dict[str, Any]) -> None:
    """The predicate names another repository than the certificate, consistently with itself."""
    other = "https://github.com/octo-org/other-repo"
    bd = st["predicate"]["buildDefinition"]
    bd["externalParameters"]["workflow"]["repository"] = other
    bd["resolvedDependencies"][0]["uri"] = f"git+{other}@{REF}"


def _dup_key_payload() -> bytes:
    text = json.dumps(provenance_statement(), indent=2)
    # A second predicateType member: two parsers can read two statements from these signed bytes.
    return text.replace('"predicateType": "https://slsa.dev/provenance/v1",',
                        '"predicateType": "https://slsa.dev/provenance/v1",\n  '
                        '"predicateType": "https://example.com/other-predicate/v1",', 1).encode("utf-8")


def _flip_payload(doc: Dict[str, Any]) -> None:
    raw = bytearray(base64.b64decode(doc["dsseEnvelope"]["payload"]))
    raw[raw.index(b"octo-artifact")] ^= 0x20
    doc["dsseEnvelope"]["payload"] = _b64(bytes(raw))


def _two_signatures(doc: Dict[str, Any]) -> None:
    doc["dsseEnvelope"]["signatures"].append(copy.deepcopy(doc["dsseEnvelope"]["signatures"][0]))


def _proto_name(doc: Dict[str, Any]) -> None:
    doc["verification_material"] = doc.pop("verificationMaterial")


def _drop(*path: str) -> Callable[[Dict[str, Any]], None]:
    def fn(doc: Dict[str, Any]) -> None:
        node: Any = doc
        for key in path[:-1]:
            node = node[key] if not key.isdigit() else node[int(key)]
        del node[path[-1]]
    return fn


def _entry(doc: Dict[str, Any]) -> Dict[str, Any]:
    return doc["verificationMaterial"]["tlogEntries"][0]


def _checkpoint_edit(fn: Callable[[str], str]) -> Callable[[Dict[str, Any]], None]:
    def edit(doc: Dict[str, Any]) -> None:
        cp = _entry(doc)["inclusionProof"]["checkpoint"]
        cp["envelope"] = fn(cp["envelope"])
    return edit


def _non_canonical_root(note: str) -> str:
    """The checkpoint root with a pad bit set: the same bytes to a lenient decoder, another string."""
    lines = note.split("\n")
    root = lines[2]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    value = alphabet.index(root[42])
    lines[2] = root[:42] + alphabet[value | 1 if value & 3 == 0 else value & ~3] + root[43:]
    return "\n".join(lines)


def _duplicate_signature_line(note: str) -> str:
    return note + note.split("\n\n", 1)[1]


def _chain_with_intermediates(doc: Dict[str, Any]) -> None:
    der = serialization.Encoding.DER
    doc["verificationMaterial"]["x509CertificateChain"]["certificates"] += [
        {"rawBytes": _b64(INTERMEDIATE_CERT.public_bytes(der))}, {"rawBytes": _b64(ROOT_CERT.public_bytes(der))}]


def _url_safe_without_keyid(doc: Dict[str, Any]) -> None:
    env = doc["dsseEnvelope"]
    env["payload"] = env["payload"].replace("+", "-").replace("/", "_")
    env["signatures"][0]["sig"] = env["signatures"][0]["sig"].replace("+", "-").replace("/", "_")
    del env["signatures"][0]["keyid"]


def _leaf_version_5(der: bytes) -> bytes:
    """The leaf's DER with the version field set to 5: no X.509 version, so no certificate."""
    marker = bytes([0xA0, 0x03, 0x02, 0x01, 0x02])
    i = der.index(marker)
    return der[:i + 4] + b"\x05" + der[i + 5:]


def trusted_root_unknown_curve() -> bytes:
    """The test root with the Rekor key's curve OID changed to one no library knows (1.2.840.10045.3.1.9)."""
    doc = json.loads(trusted_root())
    spki = bytearray(base64.b64decode(doc["tlogs"][0]["publicKey"]["rawBytes"]))
    i = spki.index(bytes.fromhex("2a8648ce3d030107"))
    spki[i + 7] = 0x09
    doc["tlogs"][0]["publicKey"]["rawBytes"] = _b64(bytes(spki))
    return json.dumps(doc, indent=2).encode("utf-8") + b"\n"

def cases() -> List[Dict[str, Any]]:
    gh = {"profile": "github-artifact-attestation", "artifactDigest": SHA256_ARTIFACT, "identity": GITHUB_IDENTITY}
    npm = {"profile": "npm-provenance", "artifactDigest": SHA512_TARBALL, "identity": NPM_IDENTITY,
           "build": {"statement": provenance_statement(NPM_BUILD_TYPE, npm=True), "kind": "intoto", "version": "0.2"}}
    pub = {"profile": "npm-publish", "artifactDigest": SHA512_TARBALL, "registryKeys": "trust/test_registry_keys.json",
           "expectedSubjectName": "pkg:npm/octo-pkg@1.0.0",
           "build": {"statement": publish_statement(), "signer": "registry", "kind": "intoto", "version": "0.2"}}
    foreign_leaf = leaf_cert(EXTENSIONS, WORKFLOW_URI, issuer_key=FOREIGN_ROOT_KEY, issuer_cert=FOREIGN_CERT)
    other_identity = dict(EXTENSIONS, build_signer_uri=f"{REPO}/.github/workflows/attacker.yml@{REF}",
                          build_config_uri=f"{REPO}/.github/workflows/attacker.yml@{REF}")
    return [
        # Positive controls: without them a verifier that refused everything would pass every negative.
        dict(gh, caseId="pos-github-v03-dsse", steps=["SB-01", "SB-03", "SB-06", "SB-11", "SB-26", "SV-01", "SV-08", "SV-09", "SV-13", "SV-14", "SV-15", "SV-17", "SV-21", "SV-26", "SV-38", "SV-41", "SV-48", "DS-06", "IT-01", "SP-04", "GH-02", "GH-04", "GH-06", "GH-08", "GH-09", "GH-10", "GH-11", "GH-16"],
             build={}, exitCode=0, failedCheck=None,
             rationale="An intact v0.3 bundle as actions/attest-build-provenance writes it, signed by the test "
                       "instance: every check passes."),
        dict(gh, caseId="pos-github-v02-chain-slsa-buildtype", build={"version": "0.2", "kind": "dsse",
             "statement": provenance_statement(NPM_BUILD_TYPE)}, steps=["SB-06", "SB-13", "SB-22", "SB-27", "SV-37", "GH-17", "GH-18"], exitCode=0, failedCheck=None,
             rationale="A v0.2 bundle with an x509CertificateChain and the slsa-framework buildType that GitHub "
                       "attestations of 2024 carry."),
        dict(gh, caseId="pos-github-v01-promise-only", build={"version": "0.1", "proof": False},
             steps=["SB-20", "SV-08"], exitCode=0, failedCheck=None,
             rationale="A v0.1 bundle carries the inclusion promise and no inclusion proof; the client MUST "
                       "validate the promise (sigstore_bundle.proto, VerificationMaterial.tlog_entries)."),
        dict(npm, caseId="pos-npm-provenance-v02-intoto", steps=["NP-05", "NP-06", "NP-08", "NP-16", "SV-34", "SP-01"], exitCode=0, failedCheck=None,
             rationale="npm provenance as npm publish --provenance writes it: a v0.2 bundle, a Rekor intoto "
                       "0.0.2 entry, a sha512 subject."),
        dict(npm, caseId="pos-npm-provenance-sri-digest", artifactDigest=SRI_TARBALL, steps=["NP-09", "NP-08"], exitCode=0,
             failedCheck=None, rationale="The relying party passes npm's dist.integrity (SRI) as the digest."),
        dict(pub, caseId="pos-npm-publish-v02", steps=["NP-03", "NP-04", "NP-11", "IT-09", "IT-19", "SB-17"], exitCode=0, failedCheck=None,
             rationale="The npm publish attestation: a v0.1 Statement signed by the registry key named by hint."),

        dict(gh, caseId="pos-github-unknown-and-null-predicate-fields", build={"statement": _statement_edit(
             lambda st: st["predicate"].update({"https://example.com/extension": {"x": 1}})
             or st["predicate"]["runDetails"].update(byproducts=None)
             or st["predicate"]["runDetails"]["builder"].update(version=None, note="ignored"))},
             steps=["SP-02", "SP-03", "IT-07"], exitCode=0, failedCheck=None,
             rationale="Unrecognized predicate fields are ignored (SP-02) and null reads as unset (SP-03)."),

        # Readable, media type, structure (exit 2 for unreadable, 1 for structural).
        dict(gh, caseId="neg-duplicate-key-in-bundle", build={}, raw=("duplicate-top", None), steps=["SB-35"],
             exitCode=2, failedCheck="readable",
             rationale="Ambiguous JSON: a second mediaType member. A last-wins parser and a first-wins parser read "
                       "two bundles; the strict parser refuses it."),
        dict(gh, caseId="neg-proto-field-name", build={"edit": _proto_name}, steps=["SB-31", "SB-32"], exitCode=1,
             failedCheck="bundle-structure",
             rationale="protojson reads verification_material as verificationMaterial; two spellings of one field "
                       "are refused by name."),
        dict(gh, caseId="neg-unknown-media-type", build={"edit": lambda d: d.update(
             mediaType="application/vnd.dev.sigstore.bundle+json;version=0.9")}, steps=["SB-01", "SB-02"], exitCode=2,
             failedCheck="media-type", rationale="An unknown bundle version is not read."),
        dict(gh, caseId="neg-two-dsse-signatures", build={"edit": _two_signatures}, steps=["SB-15", "DS-15"],
             exitCode=1, failedCheck="bundle-structure",
             rationale="A DSSE envelope in a bundle MUST have exactly one signature."),
        dict(gh, caseId="neg-v02-without-inclusion-proof", build={"version": "0.2", "proof": False},
             steps=["SB-21"], exitCode=1, failedCheck="bundle-structure",
             rationale="From bundle version 0.2 on, every log entry carries an inclusion proof."),
        dict(gh, caseId="neg-v01-without-promise", build={"version": "0.1", "promise": False},
             steps=["SB-20"], exitCode=1, failedCheck="bundle-structure",
             rationale="A v0.1 log entry needs its inclusion promise."),
        dict(gh, caseId="neg-certificate-field-in-v02", build={"version": "0.2", "edit": lambda d: d[
             "verificationMaterial"].update(certificate=d["verificationMaterial"].pop("x509CertificateChain")[
                 "certificates"][0])}, steps=["SB-05", "SB-11"], exitCode=1, failedCheck="bundle-structure",
             rationale="The single-certificate form exists from version 0.3 on."),

        # Changed bytes.
        dict(gh, caseId="neg-payload-byte-changed", build={"edit": _flip_payload}, steps=["DS-09", "SV-54"], exitCode=1,
             failedCheck="signature", rationale="One payload byte changed after signing."),
        dict(gh, caseId="neg-duplicate-key-in-signed-payload", build={"payload": _dup_key_payload()},
             steps=["DS-11", "DS-14"], exitCode=1, failedCheck="statement",
             rationale="Ambiguous JSON inside the signed payload: the signature covers it, the statement is refused."),

        # Foreign signer.
        dict(gh, caseId="neg-foreign-ca", build={"cert": foreign_leaf}, steps=["SV-13", "SB-09", "SV-22"], exitCode=1,
             failedCheck="certificate-chain",
             rationale="The leaf is issued by a CA outside the trusted root that carries the trusted "
                       "intermediate's name; the log entry and SCT are otherwise intact."),
        dict(gh, caseId="neg-envelope-signed-by-other-key", build={"dsse_key": OTHER_KEY}, steps=["DS-09", "SV-54"],
             exitCode=1, failedCheck="signature",
             rationale="The envelope is signed by a key that is not the leaf's."),
        dict(gh, caseId="neg-unknown-log", build={"log_key": FOREIGN_REKOR_KEY, "checkpoint_key": FOREIGN_REKOR_KEY},
             steps=["SV-19"], exitCode=1, failedCheck="tlog-entry",
             rationale="The entry names a log the trusted root does not list."),
        dict(gh, caseId="neg-set-by-foreign-key", build={"set_key": FOREIGN_REKOR_KEY}, steps=["SV-08", "SB-25"],
             exitCode=1, failedCheck="tlog-set",
             rationale="The signed entry timestamp names the trusted log but is signed by another key."),
        dict(gh, caseId="neg-checkpoint-by-foreign-key", build={"checkpoint_key": FOREIGN_REKOR_KEY},
             steps=["SV-41", "SV-46", "SB-28"], exitCode=1, failedCheck="tlog-checkpoint",
             rationale="The checkpoint over the proof's root is not signed by the log."),
        dict(gh, caseId="neg-inclusion-proof-hash-changed", build={"flip_proof_hash": True},
             steps=["SV-38", "SV-40", "SB-27"], exitCode=1, failedCheck="tlog-inclusion",
             rationale="One audit-path hash changed: the proof no longer leads from the body to the root."),
        dict(gh, caseId="neg-checkpoint-names-other-root", build={"checkpoint_root": b"\x11" * 32},
             steps=["SV-41"], exitCode=1, failedCheck="tlog-checkpoint",
             rationale="The log signed a checkpoint, but over another root than the proof's."),
        dict(gh, caseId="neg-no-sct", build={"cert": leaf_cert(EXTENSIONS, WORKFLOW_URI, ct_key=None)},
             steps=["SV-17", "SV-18"], exitCode=1, failedCheck="sct",
             rationale="The leaf carries no SCT: it was not logged in a trusted CT log."),
        dict(gh, caseId="neg-sct-from-unknown-ct-log",
             build={"cert": leaf_cert(EXTENSIONS, WORKFLOW_URI, ct_key=FOREIGN_CT_KEY)}, steps=["SV-17", "SV-19"],
             exitCode=1, failedCheck="sct", rationale="The only SCT comes from a CT log the trusted root does not list."),
        dict(gh, caseId="neg-log-body-other-certificate",
             build={"body_cert": leaf_cert(EXTENSIONS, WORKFLOW_URI, key=OTHER_KEY)}, steps=["SV-29", "SB-26"], exitCode=1,
             failedCheck="tlog-body", rationale="The log entry commits to another certificate than the bundle's."),
        dict(gh, caseId="neg-log-body-other-payload-hash", build={"body_edit": lambda r: r["spec"]["payloadHash"].update(
             value="00" * 32)}, steps=["SV-30", "SV-33"], exitCode=1, failedCheck="tlog-body",
             rationale="The log entry commits to another payload than the envelope's."),

        # Time.
        dict(gh, caseId="neg-no-time-source", build={"promise": False}, steps=["SB-24", "SV-01"], exitCode=1,
             failedCheck="signing-time",
             rationale="A v0.3 bundle with an inclusion proof but no signed entry timestamp and no RFC 3161 "
                       "timestamp: integratedTime is unsigned and MUST NOT be trusted."),
        dict(gh, caseId="neg-no-log-entry", build={"edit": lambda d: d["verificationMaterial"].pop("tlogEntries")},
             steps=["SV-57", "SV-55"], exitCode=1, failedCheck="tlog-threshold",
             rationale="No transparency-log entry where the relying party requires one log (the default)."),
        dict(gh, caseId="neg-time-after-certificate-expiry",
             build={"integrated": int(T0.timestamp()) + 3600}, steps=["SB-30", "SV-14"], exitCode=1,
             failedCheck="signing-time",
             rationale="The log signed a time one hour after the signing, when the ten-minute leaf had expired."),
        dict(gh, caseId="neg-integrated-time-changed", build={"set_integrated": INTEGRATED,
             "integrated": INTEGRATED + 5}, steps=["SV-08", "SV-09"], exitCode=1, failedCheck="tlog-set",
             rationale="integratedTime was changed after the log signed the entry timestamp."),
        dict(pub, caseId="neg-registry-key-expired", build=_with(pub["build"], registry_key=FOREIGN_REGISTRY_KEY),
             steps=["NP-12"], exitCode=1, failedCheck="signing-time",
             rationale="Signed and logged consistently under the registry's retired key, whose expiry "
                       "(2026-01-01) precedes the log's signed time (2026-01-15)."),
        dict(gh, caseId="neg-no-time-source-without-log", tlogThreshold=0, build={"promise": False},
             steps=["SV-12", "SB-24"], exitCode=1, failedCheck="signing-time",
             rationale="With no log required (GitHub's private instance), a bundle still needs a verified time; an "
                       "unsigned integratedTime is none."),
        dict(gh, caseId="neg-leaf-with-subject", build={"cert": leaf_cert(EXTENSIONS, WORKFLOW_URI, subject=x509.Name(
             [x509.NameAttribute(NameOID.COMMON_NAME, "octo-org/octo-repo")]))}, steps=["SV-25"], exitCode=1,
             failedCheck="certificate", rationale="A Fulcio leaf has an empty subject; the identity is the SAN."),
        dict(gh, caseId="neg-checkpoint-second-line-of-log-key-fails", build={"bad_checkpoint_line": True},
             steps=["SV-46", "SV-43"], exitCode=1, failedCheck="tlog-checkpoint",
             rationale="One line under the log's key verifies, a second under the same key does not: rejected."),
        dict(gh, caseId="neg-trusted-root-log-id-not-key-hash", trustedRoot="trust/test_trusted_root_bad_log_id.json",
             build={}, steps=["SV-19"], exitCode=2, failedCheck="verifier-config",
             rationale="A trusted root whose Rekor logId is not the SHA-256 of the log key is unusable trust material."),
        dict(npm, caseId="neg-npm-gitlab-provenance-not-implemented", build=_with(npm["build"], statement=dict(
             provenance_statement(NPM_BUILD_TYPE, npm=True), _type="https://in-toto.io/Statement/v0.1",
             predicateType="https://slsa.dev/provenance/v0.2")), steps=["NP-07"], exitCode=2,
             failedCheck="unsupported", rationale="npm's GitLab provenance (Statement v0.1, SLSA v0.2) is refused as "
                                                  "not implemented, never read."),
        dict(gh, caseId="neg-leaf-two-sans", build={"cert": leaf_cert(EXTENSIONS, WORKFLOW_URI, extra_sans=(
             "https://github.com/octo-org/other-repo/.github/workflows/release.yml@refs/heads/main",))},
             steps=["SV-25"], exitCode=1, failedCheck="certificate",
             rationale="Two subject alternative names are two identities; a Fulcio leaf names one."),

        # Identity (relying-party requirement, exit 3) and predicate-certificate consistency (exit 1).
        dict(gh, caseId="neg-foreign-workflow-identity", build={"extensions": other_identity,
             "san": f"{REPO}/.github/workflows/attacker.yml@{REF}", "statement": _statement_edit(
                 lambda st: st["predicate"]["runDetails"]["builder"].update(
                     id=f"{REPO}/.github/workflows/attacker.yml@{REF}")
                 or st["predicate"]["buildDefinition"]["externalParameters"]["workflow"].update(
                     path=".github/workflows/attacker.yml"))}, steps=["SV-21", "GH-20", "GH-22"], exitCode=3,
             failedCheck="identity",
             rationale="A sound attestation from another workflow of the same repository than the one expected."),
        dict(gh, caseId="neg-foreign-issuer", identity=dict(GITHUB_IDENTITY, issuer="https://issuer.example.com"),
             build={}, steps=["SV-21", "GH-21"], exitCode=3, failedCheck="identity",
             rationale="The relying party expects another OIDC issuer."),
        dict(gh, caseId="pos-binding-note-other-repository", build={"statement": _statement_edit(
             _other_repository)}, steps=["SP-13", "GH-09", "SP-12"], exitCode=0,
             failedCheck=None, expectedNotes=["predicate-binding: differs", "source repository: the predicate says "
                                              "'https://github.com/octo-org/other-repo'"],
             rationale="The signed predicate names another repository than the certificate Fulcio issued. The "
                       "comparison follows the producers' code, not a specification, so it is a note and the "
                       "verdict stands (owner decision 2026-10-26)."),

        # Statement and predicate.
        dict(gh, caseId="neg-wrong-predicate-type", build={"statement": _statement_edit(
             lambda st: st.update(predicateType="https://slsa.dev/provenance/v0.2"))}, steps=["IT-05", "SP-17", "SP-01"],
             exitCode=1, failedCheck="predicate-type", rationale="A sound statement of another predicate type."),
        dict(gh, caseId="neg-statement-v01-under-github", build={"statement": _statement_edit(
             lambda st: st.update(_type="https://in-toto.io/Statement/v0.1"))}, steps=["IT-01", "IT-09", "IT-17"], exitCode=1,
             failedCheck="statement", rationale="The GitHub profile reads in-toto Statement v1 only."),
        dict(gh, caseId="neg-payload-type-not-in-toto", build={"payload_type": "application/json"},
             steps=["SB-16", "DS-10", "SV-52"], exitCode=1, failedCheck="statement",
             rationale="The envelope's payloadType is not application/vnd.in-toto+json."),
        dict(gh, caseId="neg-empty-subject", build={"statement": _statement_edit(lambda st: st.update(subject=[]))},
             steps=["IT-02"], exitCode=1, failedCheck="statement",
             rationale="A statement without a subject names no artifact."),
        dict(gh, caseId="neg-builder-id-missing", build={"statement": _statement_edit(
             lambda st: st["predicate"]["runDetails"]["builder"].pop("id"))}, steps=["SP-11"], exitCode=1,
             failedCheck="predicate", rationale="runDetails.builder.id is REQUIRED in SLSA Provenance v1."),
        dict(gh, caseId="neg-unknown-build-type", build={"statement": _statement_edit(
             lambda st: st["predicate"]["buildDefinition"].update(buildType="https://example.com/build/v1"))},
             steps=["SP-06", "GH-03"], exitCode=1, failedCheck="predicate",
             rationale="A buildType the profile does not read."),
        dict(gh, caseId="neg-unrecognized-external-parameter", build={"statement": _statement_edit(
             lambda st: st["predicate"]["buildDefinition"]["externalParameters"].update(inputs={"x": "y"}))},
             steps=["SP-08", "GH-07"], exitCode=1, failedCheck="predicate",
             rationale="Consumers SHOULD reject unrecognized external parameters (actions/buildtypes workflow/v1)."),

        # Subject.
        dict(gh, caseId="neg-wrong-subject-digest", artifactDigest="sha256:" + hashlib.sha256(b"other").hexdigest(),
             build={}, steps=["IT-18", "SV-53", "SP-16"], exitCode=3, failedCheck="subject-digest",
             rationale="A sound attestation about another artifact than the one the relying party holds."),
        dict(pub, caseId="neg-npm-subject-name", expectedSubjectName="pkg:npm/octo-pkg@1.0.1", steps=["NP-03", "NP-08"],
             exitCode=3, failedCheck="subject-name", rationale="The relying party expects another package version."),
        dict(pub, caseId="neg-npm-publish-v01-subject-without-name", build=_with(pub["build"], statement=dict(
             publish_statement(), subject=[{"digest": {"sha512": hashlib.sha512(NPM_TARBALL).hexdigest()}}])),
             steps=["IT-19"], exitCode=1, failedCheck="statement",
             rationale="A v0.1 Statement requires a name on every subject."),
        dict(pub, caseId="neg-npm-key-not-in-registry", build=_with(pub["build"], edit=lambda d: d[
             "verificationMaterial"]["publicKey"].update(hint="SHA256:not-a-registry-key")), steps=["NP-04", "SB-17"],
             exitCode=1, failedCheck="public-key", rationale="The key hint names no key of the registry document."),

        # Single rules without a vector of their own until 2026-10-26.
        dict(gh, caseId="neg-kind-version-not-the-body", build={"edit": lambda d: _entry(d).update(
             kindVersion={"kind": "intoto", "version": "0.0.2"})}, steps=["SB-23", "SV-31"], exitCode=1,
             failedCheck="tlog-body", rationale="kindVersion names another kind than the logged body has."),
        dict(gh, caseId="neg-checkpoint-control-character", build={"edit": _checkpoint_edit(
             lambda n: n.replace(" - 4242", "\t- 4242", 1))}, steps=["SV-44"], exitCode=1,
             failedCheck="tlog-checkpoint", rationale="A note holds no control character but the newline."),
        dict(gh, caseId="neg-checkpoint-non-canonical-base64", build={"edit": _checkpoint_edit(_non_canonical_root)},
             steps=["SV-45"], exitCode=1, failedCheck="tlog-checkpoint",
             rationale="A pad bit set in the root: the same bytes to a lenient decoder, refused as non-canonical."),
        dict(gh, caseId="neg-checkpoint-duplicate-signature-line", build={"edit": _checkpoint_edit(
             _duplicate_signature_line)}, steps=["SV-47"], exitCode=1, failedCheck="tlog-checkpoint",
             rationale="Two signature lines with one key name and one key ID."),
        dict(gh, caseId="neg-proof-index-outside-tree", build={"edit": lambda d: _entry(d)["inclusionProof"].update(
             logIndex="5")}, steps=["SV-39"], exitCode=1, failedCheck="tlog-inclusion",
             rationale="The proof's leaf index equals the tree size."),
        dict(gh, caseId="neg-unknown-member-in-log-entry", build={"edit": lambda d: _entry(d).update(extra=1)},
             steps=["SB-34"], exitCode=1, failedCheck="bundle-structure",
             rationale="A member the TransparencyLogEntry message does not define."),
        dict(gh, caseId="pos-chain-with-superfluous-intermediate-and-root", build={"version": "0.2",
             "edit": _chain_with_intermediates}, steps=["SB-08", "SB-10", "SV-22", "SV-23", "SV-24"], exitCode=0,
             failedCheck=None, rationale="A v0.2 chain that also carries the intermediate and the root: they are "
                                         "ignored, the chain is built from the trusted root."),
        dict(gh, caseId="pos-dsse-url-safe-base64-without-keyid", build={"edit": _url_safe_without_keyid},
             steps=["DS-02", "DS-04", "DS-05"], exitCode=0, failedCheck=None,
             rationale="DSSE fields in the URL-safe alphabet and no keyid: both are allowed."),
        dict(gh, caseId="neg-resolved-dependency-without-locator", build={"statement": _statement_edit(
             lambda st: st["predicate"]["buildDefinition"]["resolvedDependencies"].append({"name": "x"}))},
             steps=["IT-15", "SP-10"], exitCode=1, failedCheck="predicate",
             rationale="A ResourceDescriptor needs one of uri, digest, content."),
        dict(gh, caseId="neg-external-parameters-missing", build={"statement": _statement_edit(
             lambda st: st["predicate"]["buildDefinition"].pop("externalParameters"))},
             steps=["SP-05"], exitCode=1, failedCheck="predicate",
             rationale="buildDefinition.externalParameters is REQUIRED."),
        dict(gh, caseId="neg-started-on-not-rfc3339", build={"statement": _statement_edit(
             lambda st: st["predicate"]["runDetails"]["metadata"].update(startedOn="2026-01-15 10:00"))},
             steps=["SP-14", "IT-11"], exitCode=1, failedCheck="predicate",
             rationale="A Timestamp field is an RFC 3339 string in UTC."),
        dict(gh, caseId="pos-identity-by-repository-id", identity={"source_repository_identifier": "123456"},
             build={}, steps=["GH-23", "GH-19"], exitCode=0, failedCheck=None,
             rationale="The relying party pins the numeric repository ID, which survives a rename."),
        dict(gh, caseId="pos-subject-with-two-algorithms", build={"statement": _statement_edit(
             lambda st: st["subject"][0]["digest"].update(sha512=hashlib.sha512(ARTIFACT).hexdigest()))},
             steps=["IT-14", "IT-04", "IT-13"], exitCode=0, failedCheck=None,
             rationale="Two DigestSets match if any field the relying party accepts matches."),

        # Found by the self-review of 2026-10-26 (measured before the fix: a raw InvalidVersion, a raw
        # UnsupportedAlgorithm, and exit 0 after 2.56 s for 1500 copies of one entry).
        dict(gh, caseId="neg-leaf-unknown-x509-version", build={"cert_edit": _leaf_version_5}, steps=["SV-25"],
             exitCode=1, failedCheck="certificate",
             rationale="A leaf whose version field is not v1, v2 or v3 is malformed, not an exception."),
        dict(gh, caseId="neg-trusted-root-unknown-curve", trustedRoot="trust/test_trusted_root_unknown_curve.json",
             build={}, steps=["SV-58"], exitCode=2, failedCheck="verifier-config",
             rationale="A trusted-root key on a curve the module cannot load is unusable trust material."),
        dict(gh, caseId="neg-too-many-log-entries", build={"edit": lambda d: d["verificationMaterial"].update(
             tlogEntries=[{}] * 33)}, steps=["SV-56"], exitCode=1, failedCheck="bundle-structure",
             rationale="More log entries than the count bound of 32: 33 empty entries, refused before any is "
                       "read (owner decision of 2026-10-26: empty entries instead of copies, under 10 KB)."),

        # Relying-party configuration.
        dict(gh, caseId="neg-identity-issuer-only", identity={"issuer": ISSUER}, build={}, steps=["SV-20", "GH-20"],
             exitCode=2, failedCheck="verifier-config",
             rationale="An issuer alone accepts every GitHub workflow; the policy must name a workflow or repository."),

        # Owner decisions of 2026-10-26 (Nachtrag 1).
        dict(gh, caseId="neg-dsse-envelope-unknown-member", build={"edit": lambda d: d["dsseEnvelope"].update(
             extra="unsigned")}, steps=["DS-03", "SB-34"], exitCode=1, failedCheck="bundle-structure",
             rationale="DSSE says to ignore an unrecognized envelope field; in a bundle the envelope is read "
                       "closed like every other message (a deviation from DSSE, named in the documentation)."),
        dict(gh, caseId="neg-dsse-signature-unknown-member", build={"edit": lambda d: d["dsseEnvelope"][
             "signatures"][0].update(extra="unsigned")}, steps=["DS-03", "SB-34"], exitCode=1,
             failedCheck="bundle-structure",
             rationale="The same deviation for a member of the envelope's one signature."),
        dict(gh, caseId="neg-github-source-dependency-missing", build={"statement": _statement_edit(
             lambda st: st["predicate"]["buildDefinition"].update(resolvedDependencies=[]))}, steps=["GH-09"],
             exitCode=1, failedCheck="predicate",
             rationale="The actions.github.io buildType says resolvedDependencies MUST contain the source commit; "
                       "a rule of the specification, so a failing check and not a note."),
        dict(gh, caseId="pos-slsa-buildtype-without-source-dependency", build={"version": "0.2", "statement":
             _statement_edit(lambda st: st["predicate"]["buildDefinition"].update(resolvedDependencies=[]),
                             NPM_BUILD_TYPE)}, steps=["SP-13"], exitCode=0, failedCheck=None,
             expectedNotes=["predicate-binding: differs", "resolvedDependencies names the source 0 times"],
             rationale="The slsa-framework buildType says resolvedDependencies SHOULD contain the source commit; "
                       "its absence is reported in the binding note and decides no verdict."),
        dict(gh, caseId="neg-github-event-pull-request", build={
             "statement": _statement_edit(_event("pull_request")),
             "cert": leaf_cert(dict(EXTENSIONS, build_trigger="pull_request"), WORKFLOW_URI)}, steps=["GH-05"],
             exitCode=1, failedCheck="predicate",
             rationale="The actions.github.io buildType MUST NOT be used for an event other than create, release, "
                       "push or workflow_dispatch; predicate and certificate agree on pull_request."),
        dict(gh, caseId="neg-github-event-certificate-pull-request-target", build={
             "cert": leaf_cert(dict(EXTENSIONS, build_trigger="pull_request_target"), WORKFLOW_URI)},
             steps=["GH-05"], exitCode=1, failedCheck="predicate",
             rationale="The predicate says push, the certificate Fulcio issued says the run was triggered by "
                       "pull_request_target: the run's event is the certificate's, and the buildType must not "
                       "describe it."),
        dict(npm, caseId="neg-slsa-buildtype-event-schedule", build=_with(npm["build"], statement=_statement_edit(
             _event("schedule"), NPM_BUILD_TYPE, npm=True), cert=leaf_cert(dict(EXTENSIONS, build_trigger="schedule"),
                                                                           WORKFLOW_URI)),
             steps=["GH-05"], exitCode=1, failedCheck="predicate",
             rationale="The slsa-framework buildType carries the same rule in the same words "
                       "(github-actions-buildtypes workflow/v1)."),
        dict(gh, caseId="pos-slsa-buildtype-dispatch-inputs-and-vars", build={"version": "0.2", "statement":
             _statement_edit(_dispatch_inputs_and_vars, NPM_BUILD_TYPE),
             "cert": leaf_cert(dict(EXTENSIONS, build_trigger="workflow_dispatch"), WORKFLOW_URI)},
             steps=["GH-07", "SP-08"], exitCode=0, failedCheck=None,
             rationale="The slsa-framework buildType defines the external parameters inputs, release and vars "
                       "beside workflow; a run of workflow_dispatch with inputs and vars is well formed."),
        dict(gh, caseId="neg-slsa-buildtype-inputs-and-release", build={"version": "0.2", "statement":
             _statement_edit(lambda st: (_dispatch_inputs_and_vars(st), st["predicate"]["buildDefinition"][
                 "externalParameters"].update(release={"name": "v1"})), NPM_BUILD_TYPE),
             "cert": leaf_cert(dict(EXTENSIONS, build_trigger="workflow_dispatch"), WORKFLOW_URI)},
             steps=["GH-07"], exitCode=1, failedCheck="predicate",
             rationale="At most one of inputs or release can be set (slsa-framework buildType)."),
        dict(gh, caseId="pos-github-event-workflow-dispatch", build={
             "statement": _statement_edit(_event("workflow_dispatch")),
             "cert": leaf_cert(dict(EXTENSIONS, build_trigger="workflow_dispatch"), WORKFLOW_URI)}, steps=["GH-05"],
             exitCode=0, failedCheck=None, rationale="workflow_dispatch is one of the four events the buildType names."),

        # The registry signature in dist.signatures (NP-10, owner answer 8 of 2026-10-26).
        dict(pub, caseId="pos-npm-registry-signature", versionDoc={}, steps=["NP-10", "NP-11", "NP-14"],
             exitCode=0, failedCheck=None,
             rationale="The registry's signature over name@version:integrity verifies under the registry key "
                       "the keys document lists, valid at the publish attestation's verified time."),
        dict(pub, caseId="neg-npm-registry-signature-over-other-text", versionDoc={
             "message": "octo-pkg@1.0.1:" + SRI_TARBALL}, steps=["NP-10"], exitCode=1,
             failedCheck="registry-signature",
             rationale="The signature is the registry key's, but over another version than the document names."),
        dict(pub, caseId="neg-npm-registry-signature-unknown-keyid", versionDoc={"keyid": "SHA256:not-a-registry-key"},
             steps=["NP-10", "NP-11"], exitCode=1, failedCheck="registry-signature",
             rationale="The signature's keyid names no key of the registry keys document (pacote: "
                       "EMISSINGSIGNATUREKEY)."),
        dict(pub, caseId="neg-npm-registry-signature-expired-key", versionDoc={"key": FOREIGN_REGISTRY_KEY},
             steps=["NP-10", "NP-12"], exitCode=1, failedCheck="registry-signature",
             rationale="Signed by a registry key that expired 2026-01-01, before the publish attestation's "
                       "verified time 2026-01-15 (pacote: EEXPIREDSIGNATUREKEY)."),
        dict(pub, caseId="neg-npm-registry-signature-missing", versionDoc={"signatures": False}, steps=["NP-14"],
             exitCode=1, failedCheck="registry-signature",
             rationale="No dist.signatures although the registry publishes signing keys."),
        dict(pub, caseId="neg-npm-registry-signature-other-integrity", versionDoc={
             "integrity": "sha512-" + _b64(hashlib.sha512(b"other tarball").digest())}, steps=["NP-10", "NP-09"],
             exitCode=1, failedCheck="registry-signature",
             rationale="A sound registry signature over another tarball's integrity than the publish attestation "
                       "names."),
        dict(pub, caseId="neg-npm-registry-signature-other-version", versionDoc={"version": "1.0.1"},
             steps=["NP-10", "NP-03"], exitCode=1, failedCheck="registry-signature",
             rationale="A sound registry signature for another version than the publish attestation names."),

        # The package.json of the tarball against the certificate (NP-15, owner answer 8 of 2026-10-26).
        dict(npm, caseId="pos-npm-package-json-repository", packageJsonDoc={}, steps=["NP-15", "NP-08"],
             exitCode=0, failedCheck=None,
             rationale="package.json names the package of the provenance's subject and, in npm's normalized "
                       "object form, the repository the certificate names."),
        dict(npm, caseId="pos-npm-package-json-shorthand", packageJsonDoc={"repository": "github:octo-org/octo-repo"},
             steps=["NP-15"], exitCode=0, failedCheck=None,
             rationale="The shortcut form github:<owner>/<repo> of npm's package.json documentation."),
        dict(npm, caseId="neg-npm-package-json-other-repository", packageJsonDoc={
             "repository": {"type": "git", "url": "git+https://github.com/octo-org/other-repo.git"}}, steps=["NP-15"],
             exitCode=3, failedCheck="package-json",
             rationale="package.json names another repository than the one the provenance was built from."),
        dict(npm, caseId="neg-npm-package-json-repository-case", packageJsonDoc={
             "repository": {"type": "git", "url": "git+https://github.com/Octo-Org/octo-repo.git"}}, steps=["NP-15"],
             exitCode=3, failedCheck="package-json",
             rationale="The repository must match case-sensitively (npm docs, generating provenance statements)."),
        dict(npm, caseId="neg-npm-package-json-no-repository", packageJsonDoc={"drop_repository": True},
             steps=["NP-15"], exitCode=3, failedCheck="package-json",
             rationale="Provenance requires a public repository in package.json."),
        dict(npm, caseId="neg-npm-package-json-other-version", packageJsonDoc={"version": "1.0.1"},
             steps=["NP-15", "NP-08"], exitCode=3, failedCheck="package-json",
             rationale="The package.json is of another version than the provenance's subject."),

        # Review of pull request 429, round 1 (2026-10-28). Measured before the fix: each negative here was
        # exit 0, and the positive control of the deprecated trigger carried a binding note that differed.
        dict(gh, caseId="neg-github-legacy-trigger-pull-request", build={
             "cert": leaf_cert(_legacy_trigger("pull_request"), WORKFLOW_URI)}, steps=["GH-05"], exitCode=1,
             failedCheck="predicate",
             rationale="The predicate says push, the certificate carries the run's event only in the deprecated "
                       "extension 1.2, as pull_request. Fulcio copies 1.2 and 1.20 from the same claim of the token, "
                       "so the run's event is the certificate's whichever of the two carries it."),
        dict(npm, caseId="neg-slsa-buildtype-legacy-trigger-pull-request", build=_with(npm["build"], cert=leaf_cert(
             _legacy_trigger("pull_request"), WORKFLOW_URI)), steps=["GH-05"], exitCode=1, failedCheck="predicate",
             rationale="The same for npm provenance under the slsa-framework buildType."),
        dict(gh, caseId="neg-trigger-extensions-disagree", build={
             "cert": leaf_cert(_legacy_trigger("pull_request", modern="push"), WORKFLOW_URI)},
             steps=["GH-05", "SV-25"], exitCode=1, failedCheck="certificate",
             rationale="The deprecated extension 1.2 says pull_request, the build trigger 1.20 says push. Both copy "
                       "one claim of the token, so a leaf naming two events is malformed, like one naming two "
                       "issuers."),
        dict(gh, caseId="pos-github-legacy-trigger-push", build={
             "cert": leaf_cert(_legacy_trigger("push"), WORKFLOW_URI)}, steps=["GH-05"], exitCode=0, failedCheck=None,
             rationale="The run's event only in the deprecated extension 1.2, as push: allowed, and the binding note "
                       "compares the predicate's event with it."),
        dict(gh, caseId="neg-subject-name-on-another-subject", expectedSubjectName="octo-artifact.tar.gz",
             build={"statement": _statement_edit(_two_subjects("unrelated.bin", "octo-artifact.tar.gz"))},
             steps=["IT-18", "SV-53"], exitCode=3, failedCheck="subject-name",
             rationale="The subject that carries the artifact's digest is unrelated.bin. The expected name belongs to "
                       "another subject with another digest, so it does not name the artifact."),
        dict(gh, caseId="pos-subject-name-on-the-digest-subject", expectedSubjectName="octo-artifact.tar.gz",
             build={"statement": _statement_edit(_two_subjects("octo-artifact.tar.gz", "other.bin"))},
             steps=["IT-18"], exitCode=0, failedCheck=None,
             rationale="Two subjects, and the one that carries the artifact's digest has the expected name."),
        dict(npm, caseId="neg-npm-package-json-on-another-subject", packageJsonDoc={}, build=_with(npm["build"],
             statement=_statement_edit(_two_npm_subjects, NPM_BUILD_TYPE, npm=True)), steps=["NP-15", "NP-08"],
             exitCode=3, failedCheck="package-json",
             rationale="package.json names octo-pkg@1.0.0, a subject of the provenance with another digest. The "
                       "subject that carries the tarball's digest is another package."),
    ]


def _raw_edit(data: bytes, how: Any) -> bytes:
    kind, _ = how
    if kind == "duplicate-top":
        return data.replace(b'{\n  "mediaType": ', b'{\n  "mediaType": "application/vnd.dev.sigstore.bundle+json;'
                                                  b'version=0.1",\n  "mediaType": ', 1)
    raise ValueError(kind)


def write() -> List[Dict[str, Any]]:
    out = HERE / "synthetic"
    out.mkdir(exist_ok=True)
    (HERE / "trust").mkdir(exist_ok=True)
    (HERE / "trust" / "test_trusted_root.json").write_bytes(trusted_root())
    (HERE / "trust" / "test_registry_keys.json").write_bytes(registry_keys())
    (HERE / "trust" / "test_trusted_root_bad_log_id.json").write_bytes(trusted_root(log_id_of=FOREIGN_REKOR_KEY))
    (HERE / "trust" / "test_trusted_root_unknown_curve.json").write_bytes(trusted_root_unknown_curve())
    manifest = []
    for case in cases():
        data = bundle(**case.get("build", {}))
        if "raw" in case:
            data = _raw_edit(data, case["raw"])
        name = f"synthetic/{case['caseId']}.json"
        (HERE / name).write_bytes(data)
        entry = {"caseId": case["caseId"], "input": name,
                 "trustedRoot": case.get("trustedRoot", "trust/test_trusted_root.json"),
                 "profile": case["profile"], "artifactDigest": case["artifactDigest"],
                 "expected": {"exitCode": case["exitCode"], "failedCheck": case["failedCheck"]},
                 "steps": case["steps"], "rationale": case["rationale"],
                 "sha256": hashlib.sha256(data).hexdigest()}
        for key in ("identity", "registryKeys", "expectedSubjectName", "tlogThreshold", "expectedNotes"):
            if key in case:
                entry[key] = case[key]
        for key, suffix, make in (("versionDoc", "version", version_document),
                                  ("packageJsonDoc", "package", package_json)):
            if key in case:
                extra = make(**case[key])
                path = f"synthetic/{case['caseId']}.{suffix}.json"
                (HERE / path).write_bytes(extra)
                entry[EXTRA_INPUTS[key]] = path
                entry[EXTRA_INPUTS[key] + "Sha256"] = hashlib.sha256(extra).hexdigest()
        manifest.append(entry)
    return manifest


#: Further inputs of a case beside the bundle, by the key a case names them under and the manifest key.
EXTRA_INPUTS = {"versionDoc": "versionDocument", "packageJsonDoc": "packageJson"}




# --------------------------------------------------------------------------------------------
# Public vectors: the bundles under public/ as fetched (sources in README.md), the two npm bundles
# extracted from the registry's attestations document, and byte edits of them.
# --------------------------------------------------------------------------------------------

PUBLIC_GOOD_ROOT = "../checkpoint/trusted_root.json"
NPM_330 = {"sha512": "3c73227e187710de25a0c7070b3ea5deffe5bb3813df36bef5ff2cb9b1a078c3636c98f31f8223fd8a17dc6beefa46a8b894"
                     "489557531c70911000d87fe66d78"}
NPM_210 = {"sha512": "90f223f992e4c88dd068cd2a5fc57f9d2b30798343dd6e38f29c240e04ba090ef831f84490847c4e82b9232c78e8a2584"
                     "63b1e55c0f7469f730265008fa6633f"}
CUSTOM_ISSUER_ARTIFACT = "sha256:afa27b44d43b02a9fea41d13cedc2e4016cfcf87c5dbf990e593669aa8ce286d"
REUSABLE_ARTIFACT = "sha256:49a3aa6075e0f49f82843e74b5baa614ad2a588e6675612bf108a0a008c5ac25"
SIGSTORE_JS_REPO = "https://github.com/sigstore/sigstore-js"
REUSABLE_SIGNER = ("https://github.com/github/artifact-attestations-workflows/.github/workflows/attest.yml"
                   "@09b495c3f12c7881b3cc17209a327792065c1a1d")


def _public_cases() -> List[Dict[str, Any]]:
    prov = "public/npm-sigstore-3.0.0-provenance.sigstore.json"
    publ = "public/npm-sigstore-3.0.0-publish.sigstore.json"
    custom = "public/ghcli-custom-issuer.sigstore.json"
    reusable = "public/ghcli-reusable-workflow-attestation.sigstore.json"
    npm_prov = {"input": prov, "trustedRoot": PUBLIC_GOOD_ROOT, "profile": "npm-provenance",
                "artifactDigest": "sha512:" + NPM_330["sha512"],
                "identity": {"source_repository_uri": SIGSTORE_JS_REPO,
                             "build_signer_uri": SIGSTORE_JS_REPO + "/.github/workflows/release.yml@refs/heads/main"}}
    npm_pub = {"input": publ, "trustedRoot": PUBLIC_GOOD_ROOT, "profile": "npm-publish",
               "artifactDigest": "sha512:" + NPM_330["sha512"], "registryKeys": "public/npm-registry-keys.json",
               "expectedSubjectName": "pkg:npm/sigstore@3.0.0"}
    gh_custom = {"input": custom, "trustedRoot": PUBLIC_GOOD_ROOT, "profile": "github-artifact-attestation",
                 "artifactDigest": CUSTOM_ISSUER_ARTIFACT,
                 "identity": {"issuer": "https://token.actions.githubusercontent.com/hammer-time",
                              "source_repository_uri": "https://github.com/too-legit/attest"}}
    gh_reusable = {"input": reusable, "trustedRoot": PUBLIC_GOOD_ROOT, "profile": "github-artifact-attestation",
                   "artifactDigest": REUSABLE_ARTIFACT,
                   "identity": {"source_repository_owner_uri": "https://github.com/malancas",
                                "build_signer_uri": REUSABLE_SIGNER}}
    return [
        dict(npm_prov, caseId="pub-npm-sigstore-3.0.0-provenance", exitCode=0, failedCheck=None, steps=["NP-01", "NP-05", "NP-16", "SV-09", "SV-17", "SV-34", "SV-48"],
             rationale="npm provenance of sigstore@3.0.0 as the registry serves it, against the public-good root."),
        dict(npm_pub, caseId="pub-npm-sigstore-3.0.0-publish", exitCode=0, failedCheck=None, steps=["NP-03", "NP-04", "NP-11", "NP-12", "IT-19"],
             rationale="The registry's publish attestation of sigstore@3.0.0, signed by the registry key that "
                       "expired 2025-01-29, logged 2024-10-14."),
        dict(gh_custom, caseId="pub-ghcli-custom-issuer", exitCode=0, failedCheck=None, steps=["GH-04", "GH-10", "GH-16", "SB-03", "SV-33"],
             rationale="A GitHub Artifact Attestation (v0.3, dsse) with an enterprise issuer, cli/cli test data."),
        dict(gh_reusable, caseId="pub-ghcli-reusable-workflow", exitCode=0, failedCheck=None, steps=["GH-10", "GH-22", "SP-13"],
             rationale="A GitHub Artifact Attestation signed by a reusable workflow, slsa-framework buildType."),
        dict(caseId="pub-ghcli-sigstore-js-2.1.0", input="public/ghcli-sigstore-js-2.1.0-bundle.json",
             trustedRoot=PUBLIC_GOOD_ROOT, profile="npm-provenance", artifactDigest="sha512:" + NPM_210["sha512"],
             identity={"source_repository_uri": SIGSTORE_JS_REPO}, exitCode=0, failedCheck=None, steps=["NP-05", "SB-01", "SV-37"],
             rationale="npm provenance of sigstore@2.1.0 in a v0.3 bundle (intoto 0.0.2), cli/cli test data."),
        dict(npm_prov, caseId="pub-neg-npm-provenance-other-artifact", artifactDigest="sha512:" + NPM_210["sha512"],
             exitCode=3, failedCheck="subject-digest", steps=["IT-18", "SV-53"],
             rationale="A sound attestation of sigstore@3.0.0 offered for the sigstore@2.1.0 tarball."),
        dict(gh_custom, caseId="pub-neg-custom-issuer-default-issuer",
             identity={"source_repository_uri": "https://github.com/too-legit/attest"}, exitCode=3,
             failedCheck="identity", steps=["SV-21", "GH-21"],
             rationale="Without an explicit issuer the GitHub profile expects token.actions.githubusercontent.com; "
                       "the certificate names another issuer."),
        dict(gh_reusable, caseId="pub-neg-reusable-caller-as-signer",
             identity={"build_signer_uri": "https://github.com/malancas/attest-demo/.github/workflows/"
                                           "attest-reusable.yml@refs/heads/main"},
             exitCode=3, failedCheck="identity", steps=["GH-22", "GH-10"],
             rationale="Foreign workflow identity: the relying party expects the caller's workflow as the signer, "
                       "the certificate names the reusable workflow."),
        dict(npm_prov, caseId="pub-neg-npm-provenance-payload-byte-changed",
             input="public/neg-npm-sigstore-3.0.0-provenance-payload-byte-changed.sigstore.json",
             exitCode=1, failedCheck="signature", steps=["DS-09"], rationale="One payload byte changed."),
        dict(npm_prov, caseId="pub-neg-npm-provenance-duplicate-key",
             input="public/neg-npm-sigstore-3.0.0-provenance-duplicate-key.sigstore.json",
             exitCode=2, failedCheck="readable", steps=["SB-35"], rationale="A duplicated mediaType member."),
        dict(npm_pub, caseId="pub-neg-publish-under-provenance-profile", profile="npm-provenance",
             registryKeys=None, expectedSubjectName=None, identity={"source_repository_uri": SIGSTORE_JS_REPO},
             exitCode=1, failedCheck="bundle-structure", steps=["SB-12", "NP-04"],
             rationale="The registry-key bundle offered where a Fulcio-signed provenance is expected."),
        dict(gh_reusable, caseId="pub-neg-reusable-under-test-root", trustedRoot="trust/test_trusted_root.json",
             exitCode=1, failedCheck="tlog-entry", steps=["SV-19", "SV-58"],
             rationale="Foreign trust root: the relying party trusts the test instance, not the public-good one."),
        dict(npm_pub, caseId="pub-neg-publish-with-test-registry-keys", registryKeys="trust/test_registry_keys.json",
             exitCode=1, failedCheck="public-key", steps=["NP-04", "NP-11"],
             rationale="The registry keys document of the test instance does not list npm's key."),
        dict(npm_pub, caseId="pub-npm-sigstore-3.0.0-registry-signature",
             versionDocument="public/npm-sigstore-3.0.0-version.json", exitCode=0, failedCheck=None,
             steps=["NP-10", "NP-11", "NP-12"],
             rationale="The registry's signature of sigstore@3.0.0 in dist.signatures, as the registry serves the "
                       "version document, under the key that expired 2025-01-29."),
        dict(npm_pub, caseId="pub-neg-npm-registry-signature-changed",
             versionDocument="public/neg-npm-sigstore-3.0.0-version-signature-changed.json", exitCode=1,
             failedCheck="registry-signature", steps=["NP-10"],
             rationale="One base64 character of the registry signature changed."),
        dict(npm_prov, caseId="pub-npm-sigstore-3.0.0-package-json", packageJson="public/npm-sigstore-3.0.0-package.json",
             exitCode=0, failedCheck=None, steps=["NP-15", "NP-08"],
             rationale="The package.json inside sigstore-3.0.0.tgz names git+https://github.com/sigstore/sigstore-js.git, "
                       "the repository the provenance's certificate names."),
        dict(npm_prov, caseId="pub-neg-npm-package-json-of-2.1.0",
             packageJson="public/ghcli-sigstore-js-2.1.0-package.json", exitCode=3, failedCheck="package-json",
             steps=["NP-15", "NP-08"],
             rationale="The package.json of sigstore@2.1.0 offered with the provenance of sigstore@3.0.0."),
        dict(caseId="pub-unsupported-message-signature", input="public/sigstore-python-bundle-v3-github.whl.sigstore.json",
             trustedRoot=PUBLIC_GOOD_ROOT, profile="github-artifact-attestation",
             artifactDigest="sha256:" + "00" * 32, identity={"source_repository_uri": "https://github.com/x/y"},
             exitCode=2, failedCheck="unsupported", steps=["SB-14", "SV-27"],
             rationale="A hashedrekord messageSignature bundle (sigstore-python test asset) is refused as not "
                       "implemented, never read."),
    ]


def write_public() -> List[Dict[str, Any]]:
    doc = json.loads((HERE / "public" / "npm-sigstore-3.0.0-attestations.json").read_text(encoding="utf-8"))
    by_type = {a["predicateType"]: a["bundle"] for a in doc["attestations"]}
    prov = json.dumps(by_type["https://slsa.dev/provenance/v1"], indent=2).encode("utf-8") + b"\n"
    publ = json.dumps(by_type["https://github.com/npm/attestation/tree/main/specs/publish/v0.1"],
                      indent=2).encode("utf-8") + b"\n"
    (HERE / "public" / "npm-sigstore-3.0.0-provenance.sigstore.json").write_bytes(prov)
    (HERE / "public" / "npm-sigstore-3.0.0-publish.sigstore.json").write_bytes(publ)
    edited = json.loads(prov)
    _flip_payload_byte(edited)
    (HERE / "public" / "neg-npm-sigstore-3.0.0-provenance-payload-byte-changed.sigstore.json").write_bytes(
        json.dumps(edited, indent=2).encode("utf-8") + b"\n")
    (HERE / "public" / "neg-npm-sigstore-3.0.0-provenance-duplicate-key.sigstore.json").write_bytes(
        prov.replace(b'{\n  "mediaType": ', b'{\n  "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",\n'
                                            b'  "mediaType": ', 1))
    version = (HERE / "public" / "npm-sigstore-3.0.0-version.json").read_bytes()
    sig = json.loads(version)["dist"]["signatures"][0]["sig"]
    changed = sig[:20] + ("A" if sig[20] != "A" else "B") + sig[21:]
    (HERE / "public" / "neg-npm-sigstore-3.0.0-version-signature-changed.json").write_bytes(
        version.replace(sig.encode("ascii"), changed.encode("ascii"), 1))
    manifest = []
    for case in _public_cases():
        data = (HERE / case["input"]).read_bytes()
        entry = {k: case[k] for k in ("caseId", "input", "trustedRoot", "profile", "artifactDigest")}
        entry["expected"] = {"exitCode": case["exitCode"], "failedCheck": case["failedCheck"]}
        entry.update(steps=case["steps"], rationale=case["rationale"], sha256=hashlib.sha256(data).hexdigest())
        for key in ("identity", "registryKeys", "expectedSubjectName"):
            if case.get(key) is not None:
                entry[key] = case[key]
        for key in EXTRA_INPUTS.values():
            if case.get(key) is not None:
                entry[key] = case[key]
                entry[key + "Sha256"] = hashlib.sha256((HERE / case[key]).read_bytes()).hexdigest()
        manifest.append(entry)
    return manifest


def _flip_payload_byte(doc: Dict[str, Any]) -> None:
    raw = bytearray(base64.b64decode(doc["dsseEnvelope"]["payload"]))
    raw[raw.index(b"sigstore")] ^= 0x20
    doc["dsseEnvelope"]["payload"] = _b64(bytes(raw))


def main() -> None:
    for name, cases_ in (("synthetic_cases.json", write()), ("public_cases.json", write_public())):
        (HERE / name).write_text(json.dumps({"generator": "tests/fixtures/sigstore_bundle/generate_vectors.py",
                                             "cases": cases_}, indent=2) + "\n", encoding="utf-8")
        print(f"{name}: {len(cases_)} cases", file=sys.stderr)


if __name__ == "__main__":
    main()
