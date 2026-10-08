"""in-toto Statement v1 view of an eval receipt (self-hosted predicate type).

A self-hosted `predicateType` URI is fully in-toto-spec-conform and the right choice for a solo v0.x
(no official in-toto/attestation PR needed). See PREDICATE.md.

HONESTY (important): the `subject.digest` here is a SALTED COMMITMENT to the model identifier, NOT the
content hash of an artifact. Placing it under the standard `sha256` key would suggest an artifact hash
and mislead generic in-toto verifiers. in-toto permits arbitrary digest keys, so we use a unique custom
key `proofbundleModelCommitV1`; the `subject.name` is the descriptive `model-id-commitment`; and the
predicate mirrors the note in `subject_digest_note`. Full artifact digests come only once a model artifact
exists (deferred, see the roadmap).
"""
from __future__ import annotations

import binascii
import copy
import hashlib
import hmac
import json
import re
from collections import Counter
from typing import Any, Optional

from ._membership import require_switch, type_name
from ._verdict import require_bool_verdict, require_eval_claim
from ._wire_b64 import decode_b64
from ._strict_json import loads_strict
from .budget import render_safe
from .canonical import (CONTENT_ROOT_ALG, CanonicalizerUnavailable, _ein_stand, _plain_for_jcs,
                        _type_name, _zeichen_von, canonicalize_statement)
from .errors import BundleFormatError, ProofBundleError, SwitchTypeError

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://b7n0de.com/proofbundle/eval-receipt/v0.1"
VERIFIER_ID = "https://b7n0de.com/proofbundle"
MODEL_COMMIT_DIGEST_KEY = "proofbundleModelCommitV1"
DATASET_COMMIT_DIGEST_KEY = "proofbundleDatasetCommitV1"

# The dedicated eval-result predicate (the shape proposed upstream in in-toto/attestation#565). Distinct
# from the self-hosted eval-receipt view above and from the community test-result mapping below: it
# extends the test-result shape with a threshold-based `claims[]`, privacy-preserving salted-commitment
# subjects, and an optional binding to the external signed receipt. predicateType is a VENDOR namespace
# for now (common practice, cf. cosign.sigstore.dev/…, apko.dev/…); the migration path to an in-toto.io
# namespace is documented in docs/IN_TOTO_PROFILE.md and needs a redirect PR only there. Status: PROPOSED
# — under discussion at in-toto/attestation#565, NOT standardized.
EVAL_RESULT_PREDICATE_TYPE = "https://b7n0de.com/attestation/eval-result/v0.1"
# The revised #575 draft (2026-09-28: `evaluator` in place of `verifier`, one identification each for model
# and dataset, `evidence[]` in place of `receipt`) under ITS OWN type version. v0.1 above was emitted and
# signed by released versions; a consumer that keys on the type must never read those bytes under the
# revised rules, nor revised bytes under the old ones. So v0.1 keeps its contract unchanged (signature,
# content root, type) and v0.2 adds the shape of the revised draft to the verdict (gate G2).
EVAL_RESULT_V02_PREDICATE_TYPE = "https://b7n0de.com/attestation/eval-result/v0.2"
EVAL_RESULT_PREDICATE_TYPES = (EVAL_RESULT_PREDICATE_TYPE, EVAL_RESULT_V02_PREDICATE_TYPE)
# DSSE payloadType for an in-toto Statement is the canonical Statement media type (in-toto spec v1
# envelope.md), NOT a predicate-specific subtype. Pinned so sign and verify agree.
INTOTO_STATEMENT_PAYLOAD_TYPE = "application/vnd.in-toto+json"

# Content-root algorithm ids for these DSSE export paths (ADR 0002 / WP2 activation, 2.1.0). The DEFAULT is
# CONTENT_ROOT_ALG ("jcs-sha256-v1"): SHA-256 over the RFC-8785 (JCS) canonical Statement bytes, unifying
# these paths with the decision-receipt content root so cross-predicate composition matches byte-for-byte.
# The historic serializer (json.dumps(sort_keys=True) via `_canonical_body`, the released 2.0.0 wire) is
# retained as a NAMED legacy algorithm — an explicit declared mode, never an unlabeled fallback. A Statement
# DECLARES its algorithm in a top-level `contentRootAlg` field (in-toto Statement v1 allows additional
# top-level properties, additionalProperties:true), so the declaration is inside the signed payload and
# cannot be flipped after signing. ABSENT `contentRootAlg` ⇒ legacy (this is how already-signed 2.0.0
# receipts, which carry no field, keep verifying); absence is NEVER silently treated as jcs.
LEGACY_CONTENT_ROOT_ALG = "legacy-sortkeys-json-v0"

# Subject profiles (what the Statement's `subject` IS). Documented per profile in docs/IN_TOTO_PROFILE.md.
#   receipt      — the eval receipt itself (a binder digest; reveals nothing about the model). DEFAULT.
#   public-model — a disclosed public model artifact (caller supplies its real sha256).
#   release-gate — a release artifact gated on a passed eval ("deploy only if the eval passed"; SLSA hook).
SUBJECT_PROFILES = ("receipt", "public-model", "release-gate")

# An export is commitment-only. If a caller hands us an enriched claim that still carries a plaintext
# identifier or a raw salt, we REFUSE to export rather than risk leaking it into a portable attestation.
_FORBIDDEN_PLAINTEXT_KEYS = (
    "model_id", "dataset_id", "model_name", "dataset_name", "model_salt", "dataset_salt", "salt", "salts")
# The minimal claim fields the eval-result predicate needs; export refuses a claim missing any of them.
_EXPORT_REQUIRED = ("suite", "metric", "comparator", "threshold", "passed", "n", "model_id_commit",
                    "dataset_id_commit", "timestamp")

# in-toto test-result predicate v0.1 (verified 2026-07 against in-toto/attestation spec/predicates/
# test-result.md). result ∈ {PASSED, WARNED, FAILED} (uppercase); configuration is a required list of
# ResourceDescriptor, each of which MUST carry one of uri/digest/content (a bare name is invalid). The
# predicate has NO native metric fields and NO top-level annotations, so metric details go into a
# ResourceDescriptor.annotations map. The DSSE payloadType is pinned so sign and verify agree.
TEST_RESULT_PREDICATE_TYPE = "https://in-toto.io/attestation/test-result/v0.1"
TEST_RESULT_PAYLOAD_TYPE = "application/vnd.in-toto.test-result+json"
_RESULT_ENUM = {True: "PASSED", False: "FAILED"}   # WARNED is unused (proofbundle asserts a pass/fail threshold)

_SUBJECT_DIGEST_NOTE = (
    "subject.digest is a salted commitment to the model identifier (key "
    f"{MODEL_COMMIT_DIGEST_KEY}), NOT an artifact content hash — do not treat it as sha256.")


def _commit_hex(commit: str) -> str:
    """Extract the hex of a `sha256:<hex>` salted commitment (the value that goes into the digest)."""
    return commit.split(":", 1)[1] if ":" in commit else commit


def _eigen(wert: Any, wo: str, name: str = "") -> Any:
    """The one reading of a caller's argument: its plain copy (`canonical._plain_for_jcs`), or this
    module's BundleFormatError naming the site and where the value sits.

    THE CLASS OF ROUND 8, at the exporters. Each producer below takes one copy of every JSON-shaped
    argument first, and judges, builds, serializes and signs only that copy: the claim, and
    ``harness``, ``anchors``, ``subject``, ``subject_digest``, ``root_b64``, ``url``, ``keyid``, the
    profile names and ``content_root_alg``. Measured at c8205c18: `_require_export_fields` and the
    plaintext guard read the claim through its own ``get``, ``==`` and ``__contains__`` before the
    claim rule's copy existed (a str subclass whose ``__eq__`` raised escaped as that exception), the
    legacy serializer (json.dumps) wrote a ``harness`` dict subclass through its own ``items()``, and
    ``resolve_subject`` built a ``release-gate`` subject digest from ``subject_sha256.lower()``, the
    caller's own method. A statement builder returns the copy, so a tuple comes back as the list it is
    written as.

    An argument that must be a string is read with `_eigener_text`, and a caller-attested flag with
    `_eigene_flagge` (round 9)."""
    return _plain_for_jcs(wert, lambda text: BundleFormatError(f"{wo}: {text}"), name)


def _eigener_text(wert: Any, wo: str, name: str) -> Optional[str]:
    """`_eigen` for an argument that must be a string or None: its plain copy, or this module's
    BundleFormatError naming the argument and the type. `_eigener_pflichttext` refuses None too.

    THE CLASS OF ROUND 9, lens run 7 at ee489403. `_eigen` accepts every JSON value, and a value of
    the wrong JSON type then reached a comparison, a message or the binder's ``json.dumps``. Measured
    at ee489403: ``root_b64`` or ``content_root_alg`` set to ``10**5000`` at ``export_intoto_dsse``
    and ``subject_profile=10**5000`` at ``export_eval_result_dsse`` raised a raw ValueError from a
    message that interpolated the value, and a ``url``, ``keyid``, ``subject_name`` or
    ``subject_profile`` that is a number, a list or an object was written into the signed statement
    or envelope. The type is checked on the copy, so a ``str`` subclass is accepted as the characters
    it holds and no method of the caller runs."""
    kopie = _eigen(wert, wo, name)
    return None if kopie is None else _text_oder_abweisung(kopie, wo, name)


def _eigener_pflichttext(wert: Any, wo: str, name: str) -> str:
    """`_eigener_text` for an argument that must be a string and has no absent form."""
    return _text_oder_abweisung(_eigen(wert, wo, name), wo, name)


def _text_oder_abweisung(kopie: Any, wo: str, name: str) -> str:
    if type(kopie) is not str:
        raise BundleFormatError(f"{wo}: {name} must be a string, got {_type_name(type(kopie))}")
    return kopie


def _eigene_flagge(wert: Any, name: str) -> bool:
    """A caller-attested flag (``prereg_verified``, ``anchor_verified``) as the bool it is, or
    :class:`~proofbundle.errors.SwitchTypeError` naming the flag and the type it got
    (`_membership.require_switch`, the one rule for a switch in this package).

    R-B4 AT THE FLAGS (round 9). The flags were read by their truth, so any non-empty string was
    true. Measured at ee489403 and on main 20e91c8e: ``export_svr_dsse(env, signer,
    anchor_verified="false")`` signed ``PROOFBUNDLE_ANCHOR_VALID``. `_verdict.require_bool_verdict`
    holds the same rule for ``passed``: a refusal, not a coercion, because only the caller knows what
    ``"false"`` or ``1`` was meant to say. ``bool`` cannot be subclassed, so ``type(wert) is bool``
    holds exactly when the caller passed True or False, and no code of the caller runs. Round 9 refused
    with this module's own BundleFormatError; the flags now answer as every other switch does."""
    require_switch(wert, name)
    return wert


def _claim_once(claim: Any) -> Any:
    """The caller's claim read ONCE from its storage (`_plain_value.plain_json`), so that every check
    of an exporter and every field it writes read one value (lens run 8 at fddc00f4, the sweep of
    finding B). The exporters checked `claim.get(k)` and wrote `claim[k]`, asked `k in claim` and read
    the issuer through `get`; a dict subclass could answer each of those differently from what it
    stores. A value that is not a dict is handed on unchanged, so the exporter's own refusal names it.
    The type is the object's own (`type`), not `isinstance`, which reads a caller's `__class__`."""
    if not issubclass(type(claim), dict):
        return claim
    from ._plain_value import plain_json  # noqa: PLC0415
    return plain_json(claim, what="the claim", error=BundleFormatError)


def _text_once(value: Any, refusal: str) -> str:
    """A selector the caller hands in (a subject profile, a content-root algorithm, a subject name or
    digest), read ONCE as the text it holds, or `BundleFormatError(refusal)`. Each was compared through
    the caller's `__eq__` and then written or compared again (lens run 8, the sweep of finding B)."""
    from .signature import plain_text  # noqa: PLC0415
    text = plain_text(value)
    if text is None:
        raise BundleFormatError(refusal)
    return text


def _alg_once(content_root_alg: Any) -> str:
    return _text_once(content_root_alg, f"unknown contentRootAlg of type {type_name(content_root_alg)} "
                                        "(ADR 0002 §1; no silent default)")

@_ein_stand(fehler=BundleFormatError)
def to_intoto_statement(claim: dict, *, root_b64: Optional[str] = None,
                        harness: Optional[dict] = None) -> dict:
    """Build an in-toto Statement v1 whose predicate is the eval receipt.

    `root_b64` (from the signed bundle's merkle root) binds the statement to the receipt. `harness`
    (e.g. {"name": "inspect_ai", "version": "0.3.217"}) is optional. The subject digest is the model
    commitment under a custom key (never `sha256`).
    """
    claim = _claim_once(claim)
    claim = require_eval_claim(claim, wo="to_intoto_statement")
    verdikt = require_bool_verdict(claim, wo="to_intoto_statement")
    root_b64 = _eigener_text(root_b64, "to_intoto_statement", "root_b64")
    harness = _eigen(harness, "to_intoto_statement", "harness")
    predicate: dict[str, Any] = {
        "verifier": {"id": VERIFIER_ID},
        "evaluatedAt": claim["timestamp"],
        "suite": claim["suite"],
        "claims": [{
            "metric": claim["metric"], "comparator": claim["comparator"],
            "threshold": claim["threshold"], "passed": verdikt,
        }],
        "datasetCommit": claim.get("dataset_id_commit"),
        "subject_digest_note": _SUBJECT_DIGEST_NOTE,
    }
    if harness:
        predicate["harness"] = harness
    if root_b64:
        predicate["receipt"] = {"schema": "proofbundle/v0.1", "root_b64": root_b64}
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [{
            "name": "model-id-commitment",
            "digest": {MODEL_COMMIT_DIGEST_KEY: _commit_hex(claim["model_id_commit"])},
        }],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }
    return statement


def _canonical_body(statement: dict) -> bytes:
    """LEGACY (`legacy-sortkeys-json-v0`) Statement serialization: json.dumps(sort_keys=True). This is the
    released 2.0.0 wire; it is NOT full RFC-8785 (it does not normalize number formatting or string
    escaping), so it cannot carry a stable cross-implementation content root (ADR 0002). Retained as the
    NAMED legacy serializer so already-signed 2.0.0 receipts keep verifying byte-for-byte and legacy
    re-emission stays possible; new exports default to `jcs-sha256-v1` (see `_serialize_statement`)."""
    return json.dumps(statement, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


#: What a PRESENT but unusable `contentRootAlg` resolves to. It is deliberately not a registered id,
#: so `_serialize_statement` refuses it the same way it refuses any unknown one, and it names what was
#: found so the verdict says more than "unknown".
_PRESENT_BUT_UNUSABLE = "invalid-contentRootAlg"


def _declared_content_root_alg(statement: Any) -> str:
    """The content-root algorithm a Statement DECLARES via its top-level `contentRootAlg`. ABSENT ⇒ legacy
    (`legacy-sortkeys-json-v0`) — this is how released 2.0.0 receipts, which carry no field, keep verifying.
    Absence is NEVER silently treated as jcs (ADR 0002 §Migration 2, mirroring merkle.hash_alg).

    ABSENT AND PRESENT-BUT-UNUSABLE ARE NOT THE SAME THING, and until 2026-09-23 they were. S26, deep
    gate run 5, finding `L1-600-CRA-01`: the guard below was `isinstance(alg, str) and alg`, so a
    PRESENT value that is not a non-empty string fell through to the absence branch and resolved to
    LEGACY with `ok=true`. Measured before the fix, all six of `""`, `0`, `True`, `[]`, `{}` and
    `null` resolved to legacy, while an unknown STRING id correctly failed closed one line later in
    `_serialize_statement`. A document that declares something unusable was read as a document that
    declares nothing.

    THE HONEST BOUNDARY, because it belongs in the finding and not only in the fix: `contentRootAlg`
    sits INSIDE the signed payload, so this is not a signature bypass. The damage is that the verdict
    describes signed content wrongly, that a receipt which the contract says to reject is accepted,
    and that a stricter foreign verifier rules differently on identical bytes.

    THE CLASS: `(field ABSENT) == (resolved algorithm == LEGACY)` must hold strictly. Every algorithm
    or selector field read from parsed content has this shape, in both languages, which is why the
    guard here distinguishes the two states instead of widening the accepted type.
    """
    if not isinstance(statement, dict):
        return LEGACY_CONTENT_ROOT_ALG
    if "contentRootAlg" not in statement:
        return LEGACY_CONTENT_ROOT_ALG          # genuinely absent — the 2.0.0 receipts
    alg = statement["contentRootAlg"]
    if isinstance(alg, str) and alg:
        return alg                               # present and shaped like an id; registration is checked later
    return _PRESENT_BUT_UNUSABLE                 # present and unusable — fail-closed, never legacy


def _serialize_statement(statement: dict, content_root_alg: str) -> bytes:
    """Serialize a Statement under a NAMED content-root algorithm — no silent default between algorithms.

    * `jcs-sha256-v1` → RFC-8785 (JCS) canonical bytes via the shared `canonical.canonicalize_statement`
      (lazily needs the `[eval]` extra; a missing extra is a fail-closed `CanonicalizerUnavailable`);
    * `legacy-sortkeys-json-v0` → the historic `_canonical_body` (json.dumps(sort_keys=True), stdlib only).

    An unknown/unregistered id is a fail-closed error: a verifier MUST NOT default a missing/unknown
    algorithm (that is exactly where an algorithm-confusion attack would hide, ADR 0002 §1)."""
    if content_root_alg == CONTENT_ROOT_ALG:
        return canonicalize_statement(statement)
    if content_root_alg == LEGACY_CONTENT_ROOT_ALG:
        return _canonical_body(statement)
    raise BundleFormatError(
        f"unknown contentRootAlg {render_safe(content_root_alg)}: no silent default for a missing/unknown "
        "algorithm (algorithm-confusion guard, ADR 0002 §1)")


def _declare_content_root_alg(statement: dict, content_root_alg: str) -> dict:
    """Return the Statement with its content-root algorithm DECLARED. `jcs-sha256-v1` adds the top-level
    `contentRootAlg` field (part of the signed payload, so it cannot be flipped after signing); legacy adds
    NO field, so a legacy re-emission is byte-identical to the released 2.0.0 wire (absent ⇒ legacy on
    verify). An unknown id is a fail-closed error."""
    if content_root_alg == CONTENT_ROOT_ALG:
        return {**statement, "contentRootAlg": CONTENT_ROOT_ALG}
    if content_root_alg == LEGACY_CONTENT_ROOT_ALG:
        return {k: v for k, v in statement.items() if k != "contentRootAlg"}
    raise BundleFormatError(
        f"unknown contentRootAlg {render_safe(content_root_alg)} (ADR 0002 §1; no silent default)")


def _content_root_binding(statement: Any, body: bytes) -> tuple[bool, Optional[str], str]:
    """Verify the transmitted payload IS canonical for its OWN declared content-root algorithm. Fail-closed.

    Returns ``(ok, alg, detail)``. The verifier reads the DECLARED `contentRootAlg` (absent ⇒ legacy) and
    re-serializes the Statement with EXACTLY that algorithm, then checks byte-equality against the exact
    transmitted payload — it never re-canonicalizes to COMPUTE a root and never falls back between algorithms.
    A payload that deviates from its own declared canonical form is rejected (this is the P0 guard: a
    `json.dumps(sort_keys=True)` body offered AS `jcs-sha256-v1` is rejected — unless it also happens to be
    valid JCS — while the same body declared/absent as legacy verifies). Verifying `jcs-sha256-v1` canonicality
    needs the `[eval]` extra; without it this is fail-closed (never a silent pass over possibly non-canonical
    bytes). Legacy verification is stdlib-only, so released 2.0.0 receipts verify on a base install."""
    alg = _declared_content_root_alg(statement)
    # THE SENTINEL DRIVES THE DECISION, IT DOES NOT GET REPORTED AS SIGNED CONTENT. Codex, review of
    # 2026-09-23 on PR 254: for canonical bytes of `{"contentRootAlg":null}` the verdict correctly
    # said ok=False, and then named `content_root_alg="invalid-contentRootAlg"` and "unknown
    # contentRootAlg 'invalid-contentRootAlg'" — a string that appears NOWHERE in the signed
    # payload, and the same for every unusable type. The shared builder below feeds all three
    # verify_*_dsse surfaces, so one place fixed it for all three.
    #
    # The signature boundary and the fail-closed verdict were never in question; what was wrong is
    # that the verdict claimed the document declared something it did not. `gemeldet` is therefore
    # None (nothing usable was declared) and the detail names the type actually found.
    unbrauchbar = alg is _PRESENT_BUT_UNUSABLE or alg == _PRESENT_BUT_UNUSABLE
    gemeldet: Optional[str] = None if unbrauchbar else alg
    if unbrauchbar:
        roh = statement.get("contentRootAlg") if isinstance(statement, dict) else None
        return False, gemeldet, (
            f"contentRootAlg is present but unusable (found {type(roh).__name__} {render_safe(roh)}); a "
            "declaration that names no algorithm is refused rather than read as absent")
    if not isinstance(statement, dict):
        return False, gemeldet, "payload is not a JSON in-toto Statement object"
    try:
        expected = _serialize_statement(statement, alg)
    except CanonicalizerUnavailable:
        return False, alg, ("cannot verify jcs-sha256-v1 canonicality — install proofbundle[eval] "
                            "(fail-closed; never a silent pass over non-canonical bytes)")
    except (ProofBundleError, ValueError) as exc:
        # adversarial re-audit round 3: the BASE ProofBundleError (CanonicalizerUnavailable already handled
        # above) keeps any sibling — a BudgetExceeded/UnsupportedError from serialization — fail-closed here.
        # adversarial re-audit round 4: rfc8785.dumps raises FloatDomainError (NaN/Infinity) and IntegerDomainError
        # (an oversized JSON integer under loads_strict's digit cap) — BOTH ValueError subclasses, NOT
        # ProofBundleError. A hostile signed statement carrying such a value escaped verify_*_dsse raw
        # (_content_root_binding runs even when ok=False). Catching the ValueError family fails it closed.
        return False, alg, str(exc)
    if expected != body:
        return False, alg, (f"payload is not canonical for its declared contentRootAlg={alg!r} "
                            "(algorithm-confusion / tamper, fail-closed)")
    return True, alg, ""


@_ein_stand(fehler=BundleFormatError)
def to_test_result_statement(claim: dict, *, subject_digest: dict, root_b64: Optional[str] = None,
                             harness: Optional[dict] = None, url: Optional[str] = None,
                             content_root_alg: str = CONTENT_ROOT_ALG) -> dict:
    """Build a STANDARD in-toto Statement v1 with the generic `test-result/v0.1` predicate (v0.9).

    Unlike ``to_intoto_statement`` (self-hosted predicate), this maps the receipt onto the community
    test-result predicate so a generic in-toto verifier understands it: ``result`` is PASSED/FAILED from
    the threshold; ``configuration`` lists ResourceDescriptors for the model and dataset commitments (each
    carries a real ``digest`` — a salted commitment hex under a proofbundle-specific algorithm key, never
    ``sha256`` — so ``name``-only descriptors, which are invalid, are avoided). Metric details (metric,
    comparator, threshold, passed, stderr) have no native field in test-result, so they live in the model
    descriptor's ``annotations``. ``subject_digest`` is a real DigestSet ({alg: hex}) for the receipt.

    ``subject_digest`` is read by ``dict()`` over its plain copy, as before, and ``dict()`` decides
    what is accepted: an object, and a list each of whose items has exactly two elements, which
    ``dict()`` reads as a key and a value. That covers a list of ``[alg, hex]`` pairs, and also a
    two-character string (``["ab"]`` gives {"a": "b"}), an object with two keys, whose keys are
    read (``[{"k": 1, "v": 2}]`` gives {"k": "v"}), and a pair whose key is no string (``[[1, "x"]]``
    gives {1: "x"}). What ``dict()`` refuses is this function's BundleFormatError (round 9: at
    ee489403 None, 5, "ab", [1] and True raised ``dict()``'s raw TypeError or ValueError). The round-9
    wording said every value other than an object or a list of pairs was refused; lens run 8 showed
    the three above read, and round 10 corrects the sentence without changing the behaviour.
    """
    wo = "to_test_result_statement"
    claim = _claim_once(claim)
    content_root_alg = _alg_once(content_root_alg)
    claim = require_eval_claim(claim, wo=wo)
    verdikt = require_bool_verdict(claim, wo=wo)
    subject_digest = _eigen(subject_digest, wo, "subject_digest")
    try:
        digest = dict(subject_digest)
    except (TypeError, ValueError) as exc:
        raise BundleFormatError(
            f"{wo}: subject_digest must be a JSON object (a DigestSet such as {{\"sha256\": <hex>}}), "
            f"got {_type_name(type(subject_digest))} {render_safe(subject_digest)}") from exc
    root_b64 = _eigener_text(root_b64, wo, "root_b64")
    harness = _eigen(harness, wo, "harness")
    url = _eigener_text(url, wo, "url")
    content_root_alg = _eigener_pflichttext(content_root_alg, wo, "content_root_alg")
    model_desc: dict[str, Any] = {
        "name": "model-id-commitment",
        "digest": {MODEL_COMMIT_DIGEST_KEY: _commit_hex(claim["model_id_commit"])},
        "annotations": {
            "suite": claim["suite"],
            "metric": claim["metric"],
            "comparator": claim["comparator"],
            "threshold": claim["threshold"],
            "passed": verdikt,
            "evaluatedAt": claim["timestamp"],
            "note": ("digest is a SALTED COMMITMENT to the model id, not an artifact content hash; "
                     "proofbundle attests authenticity+integrity of the claimed result, not the correctness "
                     "of the computation"),
        },
    }
    if claim.get("provenance"):
        model_desc["annotations"]["provenance"] = claim["provenance"]
    if harness:
        model_desc["annotations"]["harness"] = harness
    if root_b64:
        model_desc["annotations"]["receipt"] = {"schema": "proofbundle/v0.1", "root_b64": root_b64}
    configuration = [model_desc]
    dataset_commit = claim.get("dataset_id_commit")
    if dataset_commit:
        configuration.append({
            "name": "dataset-id-commitment",
            "digest": {DATASET_COMMIT_DIGEST_KEY: _commit_hex(dataset_commit)},
        })
    predicate: dict[str, Any] = {
        # `_RESULT_ENUM[verdikt]` and not `[bool(...)]`: the enum is keyed by True/False, so an indexing
        # KeyError would be the honest failure for anything else — but the refusal above says WHICH field
        # and WHICH type, which a KeyError never could.
        "result": _RESULT_ENUM[verdikt],
        "configuration": configuration,
    }
    suite = claim.get("suite")
    if suite:
        key = "passedTests" if verdikt else "failedTests"
        predicate[key] = [str(suite)]
    if url:
        predicate["url"] = url
    return _declare_content_root_alg({
        "_type": STATEMENT_TYPE,
        "subject": [{"name": "eval-receipt", "digest": digest}],
        "predicateType": TEST_RESULT_PREDICATE_TYPE,
        "predicate": predicate,
    }, content_root_alg)


@_ein_stand(aussen={"signer": "signierer"}, fehler=BundleFormatError)
def export_intoto_dsse(claim: dict, signer, *, root_b64: Optional[str] = None,
                       harness: Optional[dict] = None, url: Optional[str] = None,
                       keyid: Optional[str] = None,
                       content_root_alg: str = CONTENT_ROOT_ALG) -> dict:
    """Export a receipt as a DSSE-signed in-toto test-result attestation (v0.9). The native bundle stays
    the source of truth; this is an interop export. Returns a DSSE envelope. The subject digest is the
    sha256 of a stable *binder* over the receipt's model + dataset commitments, root, and timestamp — a
    real hex digest that binds the attestation to the receipt without revealing the model (not a hash of
    the statement body, and never the model's own sha256).

    The signed Statement declares its content-root algorithm (default `jcs-sha256-v1`, ADR 0002). Pass
    `content_root_alg=LEGACY_CONTENT_ROOT_ALG` for a byte-identical legacy re-emission (json.dumps root,
    no field).

    A value the serializer cannot write (NaN, an infinity or an integer beyond the JCS range under
    the default algorithm, an integer past the interpreter's digit limit under the legacy one, a
    value nested deeper than the serializer recurses) is this function's BundleFormatError (round 9;
    at ee489403 rfc8785's FloatDomainError or IntegerDomainError, the budget's BudgetExceeded, or a
    raw ValueError or RecursionError from json.dumps). See `_signed_body_refusal`."""
    wo = "export_intoto_dsse"
    claim = _claim_once(claim)
    content_root_alg = _alg_once(content_root_alg)
    _refuse_to_vouch_for_a_key_nobody_holds(claim, "refusing to export the test-result attestation")
    claim = require_eval_claim(claim, wo=wo)
    root_b64 = _eigener_text(root_b64, wo, "root_b64")
    harness = _eigen(harness, wo, "harness")
    url = _eigener_text(url, wo, "url")
    keyid = _eigener_text(keyid, wo, "keyid")
    content_root_alg = _eigener_pflichttext(content_root_alg, wo, "content_root_alg")
    from . import dsse  # noqa: PLC0415 — lazy: keeps the verify core free of the DSSE module

    # subject_digest binds to the receipt: sha256 of the model+dataset commitments + root (stable, hex).
    binder = json.dumps({
        "model_id_commit": claim["model_id_commit"],
        "dataset_id_commit": claim.get("dataset_id_commit"),
        "root_b64": root_b64,
        "timestamp": claim["timestamp"],
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    subject_digest = {"sha256": hashlib.sha256(binder).hexdigest()}
    statement = to_test_result_statement(claim, subject_digest=subject_digest, root_b64=root_b64,
                                         harness=harness, url=url, content_root_alg=content_root_alg)
    try:
        body = _serialize_statement(statement, content_root_alg)
    except (CanonicalizerUnavailable, BundleFormatError):
        raise
    except (ProofBundleError, ValueError, RecursionError) as exc:
        raise _signed_body_refusal(wo, exc) from exc
    return dsse.sign_envelope(body, signer, payload_type=TEST_RESULT_PAYLOAD_TYPE, keyid=keyid)


def _signed_body_refusal(wo: str, exc: BaseException) -> BundleFormatError:
    """The exporter's BundleFormatError for a statement its serializer cannot write.

    THE SERIALIZER RUNS AFTER THE COPY, and what it refuses is the exporter's refusal, like what the
    copy refuses (round 9, lens run 7 at ee489403). The copy passes every JSON value, and three kinds
    reached the serializer raw: under ``jcs-sha256-v1`` rfc8785's FloatDomainError (NaN, an infinity),
    IntegerDomainError (2**53, 2**64) and the structural budget's BudgetExceeded (10**5000); under
    the legacy algorithm json.dumps's ValueError for an integer past the interpreter's digit limit
    and its RecursionError for a value nested within a few levels of the copy's own depth limit
    (``export_intoto_dsse`` harness 984 to 989 levels, ``export_eval_result_dsse`` harness and
    anchors 987 to 988, ``export_svr_dsse`` policy 986 to 990, measured from one caller). The
    serializer is called inline at each exporter and only the refusal is built here, so no frame is
    added before it and the deepest statement written stays as deep as before.

    ``CanonicalizerUnavailable`` (a missing extra) and this module's own BundleFormatError (an
    unknown algorithm) pass through unchanged. The verify path keeps its own handling in
    `_content_root_binding`."""
    if isinstance(exc, RecursionError):
        return BundleFormatError(f"{wo}: the statement nests too deep to serialize")
    return BundleFormatError(
        f"{wo}: the statement cannot be serialized: {render_safe(str(exc), quote=False)}")


def _intoto_verify_result(sig_ok, binding_ok, statement, alg, detail, expected_predicate_type) -> dict:
    """Shared verify-result builder for the three DSSE verify functions (WP-I1). ``ok`` conjuncts the
    signature, the content-root binding, AND — unless ``expected_predicate_type`` is None — that the
    statement's ``predicateType`` equals it (predicate-confusion defense). ``predicate_type_ok`` carries
    the granular verdict; ``predicate_type`` the value found."""
    got = statement.get("predicateType") if isinstance(statement, dict) else None
    if expected_predicate_type is None:
        type_ok = None
        merged_detail = detail
    else:
        type_ok = (got == expected_predicate_type)
        merged_detail = detail if type_ok else (
            (detail + "; " if detail else "")
            + f"predicateType {render_safe(got)} != expected {render_safe(expected_predicate_type)} "
              "(confusion attack?)")
    ok = bool(sig_ok) and binding_ok and (type_ok is not False)
    return {"ok": ok, "statement": statement, "predicate_type": got,
            "predicate_type_ok": type_ok, "content_root_alg": alg,
            "content_root_ok": binding_ok, "content_root_detail": merged_detail}


def _commit_field(value: Any) -> Any:
    """A predicate's commitment hex in the claim's `sha256:<hex>` spelling, so the claim rule's own
    pattern judges it. A non-string stays as it is and the rule refuses its type."""
    return "sha256:" + value if isinstance(value, str) else value


def _eval_result_claim_fields(predicate: dict) -> list:
    """(label, claim fields or a reason) for each part of an eval-result predicate that carries
    claim fields.

    The mapping is the inverse of `to_eval_result_predicate`. A predicate field that is ABSENT maps
    to nothing (docs/upstream/eval-result.md: absence makes no claim, and C2 of
    tests/test_intoto_content_root_migration.py signs a predicate with none of these fields). A
    PRESENT container of the wrong shape is a reason of its own, because naming a field inside it
    would describe a structure that is not there.
    """
    teile: list = []
    if "claims" in predicate:
        claims = predicate["claims"]
        if not isinstance(claims, list):
            teile.append(("claims", f"must be an array of claim objects, got {type(claims).__name__}"))
        else:
            for i, eintrag in enumerate(claims):
                if not isinstance(eintrag, dict):
                    teile.append((f"claims[{i}]", f"must be an object, got {type(eintrag).__name__}"))
                    continue
                teile.append((f"claims[{i}]", {k: eintrag[k] for k in (
                    "metric", "comparator", "threshold", "passed") if k in eintrag}))
    if "sampleSize" in predicate:
        teile.append(("sampleSize", {"n": predicate["sampleSize"]}))
    if "commitments" in predicate:
        commitments = predicate["commitments"]
        if not isinstance(commitments, dict):
            teile.append(("commitments", f"must be an object, got {type(commitments).__name__}"))
            commitments = {}
        for rolle, feld in (("model", "model_id_commit"), ("dataset", "dataset_id_commit")):
            if rolle not in commitments:
                continue
            c = commitments[rolle]
            if not isinstance(c, dict):
                teile.append((f"commitments.{rolle}", f"must be an object, got {type(c).__name__}"))
                continue
            # `salted: true` is what makes `value` a commitment (upstream spec, `commitments`), and
            # the one algorithm the claim rule knows is a salted one.
            if c.get("salted") is not True:
                teile.append((f"commitments.{rolle}", "salted must be true for a sha256-salted-v1 "
                              f"commitment, got {render_safe(c.get('salted'))}"))
                continue
            teile.append((f"commitments.{rolle}",
                          {"commit_alg": c.get("alg"), feld: _commit_field(c.get("value"))}))
    if "suite" in predicate:
        suite = predicate["suite"]
        if not isinstance(suite, dict):
            teile.append(("suite", f"must be an object {{name, version}}, got {type(suite).__name__}"))
        else:
            teile.append(("suite", {k: suite[q] for q, k in (("name", "suite"),
                                                              ("version", "suite_version"))
                                    if q in suite}))
    for q, k in (("evaluatedAt", "timestamp"), ("assuranceLevel", "assurance_level")):
        if q in predicate:
            teile.append((q, {k: predicate[q]}))
    if "preRegistration" in predicate:
        pre = predicate["preRegistration"]
        if not isinstance(pre, dict):
            teile.append(("preRegistration", f"must be an object, got {type(pre).__name__}"))
        elif "value" in pre:
            teile.append(("preRegistration", {"prereg_sha256": pre["value"]}))
    return teile


def _descriptor_claim_fields(bezeichnung: str, eintrag: Any) -> tuple[list, list]:
    """(teile, urteile) for one resource descriptor, wherever it stands in a statement of the
    verifier's own type: an entry of a test-result `configuration`, or an entry of the `subject` of
    either statement.

    THE OWNERSHIP RULE, one function for every place a descriptor stands. A descriptor is ours when
    its digest carries `proofbundleModelCommitV1` or `proofbundleDatasetCommitV1`; the claim rule
    then judges its commitment (`_commit_field`) and its annotations, and an annotated boolean
    `passed` is returned in `urteile`, with the annotated `suite`, for the verdict agreement of the
    test-result predicate. A descriptor that is an object with an object digest carrying neither key
    is a generic one and is not judged (test A1 of tests/test_intoto_content_root_migration.py
    verifies one with digest {"x": "y"}); one without a digest makes no claim. A present descriptor
    that is not an object, a present digest that is not an object, and annotations of ours that are
    not an object are reasons, the rule `_eval_result_claim_fields` states for containers.

    Until this function the rule stood in the configuration walk alone. Measured at 6893586f: a
    validly signed test-result or eval-result statement whose `subject` was
    [{"name": "model-id-commitment", "digest": {"proofbundleModelCommitV1": "x"}}] verified ok=True
    with predicate_claim_ok True, and `proofbundle intoto --verify` printed PASS.
    """
    if not isinstance(eintrag, dict):
        return [(bezeichnung, f"must be an object, got {type(eintrag).__name__}")], []
    if "digest" not in eintrag:
        return [], []
    digest = eintrag["digest"]
    if not isinstance(digest, dict):
        return [(f"{bezeichnung}.digest", f"must be an object, got {type(digest).__name__}")], []
    felder = {}
    for schluessel, feld in ((MODEL_COMMIT_DIGEST_KEY, "model_id_commit"),
                             (DATASET_COMMIT_DIGEST_KEY, "dataset_id_commit")):
        if schluessel in digest:
            felder[feld] = _commit_field(digest[schluessel])
    if not felder:
        return [], []
    urteile: list = []
    if "annotations" in eintrag:
        notizen = eintrag["annotations"]
        if not isinstance(notizen, dict):
            return [(f"{bezeichnung}.annotations",
                     f"must be an object, got {type(notizen).__name__}")], []
        for q, k in (("suite", "suite"), ("metric", "metric"), ("comparator", "comparator"),
                     ("threshold", "threshold"), ("passed", "passed"), ("evaluatedAt", "timestamp"),
                     ("provenance", "provenance")):
            if q in notizen:
                felder[k] = notizen[q]
        if isinstance(notizen.get("passed"), bool):
            suite = notizen.get("suite")
            urteile.append((notizen["passed"], suite if isinstance(suite, str) else None))
    return [(bezeichnung, felder)], urteile


def _descriptor_list_claim_fields(bezeichnung: str, liste: Any) -> tuple[list, list]:
    """`_descriptor_claim_fields` over a PRESENT list of descriptors; a list of the wrong shape is a
    reason of its own."""
    if not isinstance(liste, list):
        return [(bezeichnung, f"must be an array of resource descriptors, got "
                              f"{type(liste).__name__}")], []
    teile: list = []
    urteile: list = []
    for i, eintrag in enumerate(liste):
        t, u = _descriptor_claim_fields(f"{bezeichnung}[{i}]", eintrag)
        teile.extend(t)
        urteile.extend(u)
    return teile, urteile


def _subject_claim_fields(statement: dict) -> tuple[list, list]:
    """The statement's `subject` under the ownership rule. An absent subject makes no claim."""
    if "subject" not in statement:
        return [], []
    return _descriptor_list_claim_fields("subject", statement["subject"])


def _eval_result_statement_claim_fields(statement: dict, predicate: dict) -> list:
    """What `verify_eval_result_dsse` judges: the predicate's claim fields and the subject."""
    return ([(f"predicate {b}", f) for b, f in _eval_result_claim_fields(predicate)]
            + _subject_claim_fields(statement)[0])


_CASE_LISTS = ("passedTests", "warnedTests", "failedTests")


def _verdict_agreement(predicate: dict, urteile: list) -> list:
    """Reasons why the generic fields of a test-result predicate contradict a verdict of ours.

    `urteile` holds (passed, suite or None) of every descriptor of ours that annotates a boolean
    `passed`. Nothing is judged without one: a generic test result is not ours to judge.

    `result`, when present, is PASSED exactly when `passed` is true, which is how
    `to_test_result_statement` writes them. The case lists follow the rule
    `verifier_block.validate_test_result_statement` holds for its own statements: each present list
    is an array of strings; the lists derive the result (FAILED when any case failed, else WARNED
    when any case warned, else PASSED), and a statement whose lists name no case is not a test
    result; no case is listed twice. The derived result must be the verdict's. And the annotated
    suite is listed where its verdict puts it, `passedTests` for true and `failedTests` for false,
    because that is the list the export writes it into. A generic verifier reads `result` and the
    lists; a statement where they contradict the signed verdict beside them is not one this export
    produces. Measured at 6893586f: `result` PASSED with the suite listed under `failedTests`, and
    `passedTests` naming another suite, each verified ok=True.
    """
    if not urteile:
        return []
    if "result" in predicate:
        for urteil, _ in urteile:
            erwartet = _RESULT_ENUM[urteil]
            if predicate["result"] != erwartet:
                return [("result", f"must be {erwartet!r} when passed is {urteil}, "
                                   f"got {render_safe(predicate['result'])}")]
    listen: dict = {}
    for name in _CASE_LISTS:
        if name in predicate:
            liste = predicate[name]
            if not (isinstance(liste, list) and all(isinstance(x, str) for x in liste)):
                return [(name, f"must be an array of strings, got {render_safe(liste)}")]
            listen[name] = liste
    if not listen:
        return []
    bestanden = listen.get("passedTests", [])
    gewarnt = listen.get("warnedTests", [])
    gescheitert = listen.get("failedTests", [])
    if not (bestanden or gewarnt or gescheitert):
        return [("case lists", "name no case; a statement over zero cases is not a test result")]
    abgeleitet = "FAILED" if gescheitert else ("WARNED" if gewarnt else "PASSED")
    for urteil, suite in urteile:
        if abgeleitet != _RESULT_ENUM[urteil]:
            return [("case lists", f"derive {abgeleitet!r} ({len(gescheitert)} failed, "
                                   f"{len(gewarnt)} warned, {len(bestanden)} passed), which "
                                   f"contradicts passed {urteil}")]
        wo = "passedTests" if urteil else "failedTests"
        if suite is not None and suite not in listen.get(wo, []):
            return [(wo, f"must list the suite {render_safe(suite)} whose verdict is passed "
                         f"{urteil}, got {render_safe(listen.get(wo))}")]
    doppelt = sorted(x for x, n in Counter(bestanden + gewarnt + gescheitert).items() if n > 1)
    if doppelt:
        return [("case lists", f"list a case more than once: {render_safe(doppelt)}")]
    return []


def _test_result_claim_fields(statement: dict, predicate: dict) -> list:
    """(label, claim fields or a reason) for what `verify_intoto_dsse` judges: every descriptor of
    ours in the predicate's `configuration` and in the statement's `subject`
    (`_descriptor_claim_fields`), every container on the way to one that has the wrong shape, and
    the agreement of the generic fields with the signed verdict (`_verdict_agreement`).

    The inverse of `to_test_result_statement`. An ABSENT `configuration` or `digest` makes no
    claim. A PRESENT container of the wrong shape is a reason of its own, the rule
    `_eval_result_claim_fields` states. Measured at 835df85b: with `configuration` an object, the
    single entry in place of the list, or a digest written as a list of pairs, the walk found no
    entry, judged nothing and reported predicate_claim_ok=True over a placeholder commitment.
    """
    subjekt_teile, urteile = _subject_claim_fields(statement)
    teile: list = []
    if "configuration" in predicate:
        teile, konfig_urteile = _descriptor_list_claim_fields("configuration",
                                                              predicate["configuration"])
        urteile = konfig_urteile + urteile
    teile.extend(_verdict_agreement(predicate, urteile))
    return [(f"predicate {b}", f) for b, f in teile] + subjekt_teile


def _judge_claim_fields(res: dict, eigener_typ: str, felder_von) -> dict:
    """Fold the claim rule over a verified statement's predicate and subject into the verdict.
    Never raises.

    ``predicate_claim_ok`` is True when the statement has this verifier's own predicate type and
    every claim field it carries passes `evalclaim._field_violation`, False when one does not or
    when a container on the way to one has the wrong shape (then ``ok`` is False and the reason is
    appended to ``content_root_detail``), and None when the statement is of another type or not an
    object, so there is nothing this rule knows to judge.
    The predicate type of the STATEMENT decides, not ``expected_predicate_type``: with the type
    check opted out (scripts/pre_tag_attestation.py does), a foreign predicate is still not judged
    by the eval-claim rule.

    Measured at 62e8bbab: a validly signed envelope whose commitments were `sha256:x`,
    `not-a-commitment` or 64 upper-case hex digits verified ok=True through both verifiers.

    ``felder_von(statement, predicate)`` returns each part with its full label ("predicate
    claims[0]", "subject[0]"), because the subject stands beside the predicate and not in it.
    """
    statement = res.get("statement")
    if not (isinstance(statement, dict) and statement.get("predicateType") == eigener_typ):
        res["predicate_claim_ok"] = None
        return res
    from .evalclaim import _field_violation  # noqa: PLC0415 - evalclaim imports the bundle core
    grund = None
    # A statement of this verifier's own type whose predicate is PRESENT and not an object is a
    # reason, not "nothing to judge". Measured at 835df85b: the eval-result predicate or the
    # test-result predicate wrapped in a list verified ok=True with a placeholder commitment, and
    # `proofbundle intoto --verify` printed PASS. An absent predicate is the empty one (in-toto
    # Statement v1: unset is treated the same as set-but-empty), so it carries no claim fields.
    predicate = statement.get("predicate", {})
    if not isinstance(predicate, dict):
        grund = f"predicate must be an object, got {type(predicate).__name__}"
        predicate = {}
    try:
        for bezeichnung, felder in ([] if grund else felder_von(statement, predicate)):
            fehler = felder if isinstance(felder, str) else _field_violation(felder)
            if fehler is not None:
                grund = f"{bezeichnung}: {fehler}"
                break
    except (ProofBundleError, ValueError, TypeError, RecursionError) as exc:
        grund = f"predicate claim fields could not be judged ({type(exc).__name__})"
    res["predicate_claim_ok"] = grund is None
    if grund is not None:
        res["ok"] = False
        res["content_root_detail"] = (
            (res["content_root_detail"] + "; " if res["content_root_detail"] else "") + grund)
    return res


@_ein_stand(fehler=BundleFormatError)
def verify_intoto_dsse(envelope: dict, public_key: bytes, *,
                       expected_predicate_type: str = TEST_RESULT_PREDICATE_TYPE) -> dict:
    """Verify a DSSE-signed in-toto test-result attestation from ``export_intoto_dsse``. Returns
    {ok, statement, predicate_type, predicate_type_ok, content_root_alg, content_root_ok,
    content_root_detail}. ``ok`` is True iff the Ed25519 signature over the DSSE PAE verifies, the
    payloadType is the pinned test-result media type, the payload is canonical for its DECLARED
    contentRootAlg (absent ⇒ legacy; ADR 0002), AND the statement's ``predicateType`` equals
    ``expected_predicate_type`` (WP-I1: the type was previously only RETURNED, so ``ok`` was True for a
    swapped-predicate confusion attack — an SVR or eval-result envelope accepted as a test-result).
    Pass ``expected_predicate_type=None`` to opt out of the type check (returns it as before).

    ``ok`` also requires that every eval-claim field a configuration or subject entry carrying a
    proofbundle commitment digest holds passes the claim rule, and that `result` and the case lists
    agree with the `passed` such an entry annotates (``predicate_claim_ok``, see
    `_judge_claim_fields`). A generic test-result entry without such a digest is not judged.

    ``expected_predicate_type`` is the caller's configuration, not untrusted input: it is read as
    its plain copy and must be a string or None, else this function raises BundleFormatError (round
    9; at ee489403 ``10**5000`` raised a raw ValueError from the mismatch message, and a ``str``
    subclass was compared through its own ``__eq__``). The verdict on the envelope never raises.

    The envelope is read once, as the plain copy of what it stores (`dsse._read_once`), and the
    returned statement is parsed from the payload bytes the signature was checked over (round 11).
    An envelope holding a value that is no JSON value is refused, ok=False."""
    from . import dsse  # noqa: PLC0415
    from .errors import ProofBundleError  # noqa: PLC0415

    erwartet = _eigener_text(expected_predicate_type, "verify_intoto_dsse", "expected_predicate_type")
    try:
        # RE-GATE never-raise: crypto verify + body load + input_bytes budget + strict parse inside the
        # never-raise guard; a wide/oversized (BudgetExceeded) / dup-key (BundleFormatError) / malformed
        # untrusted envelope yields a fail-closed verdict, never a raw exception out of this dict-returning
        # verify surface (mirrors decision/outcome/run_ledger).
        # ONE READING (round 11, L4): `body` is the payload the signature was checked over, read once
        # from the plain copy of the envelope. At fa555f13 `verify_envelope` and `load_payload` were two
        # readings of the caller's object, and a dict subclass answering the second read with another
        # payload verified ok=True over a statement nobody signed. The same holds for the two
        # verifiers below (L5, L6).
        ok, body = dsse._verify_and_load(envelope, public_key, payload_type=TEST_RESULT_PAYLOAD_TYPE)
        statement = loads_strict(body.decode("utf-8"))   # WP-C1: duplicate keys rejected fail-closed
    except (ProofBundleError, ValueError, UnicodeDecodeError) as exc:
        return _judge_claim_fields(_intoto_verify_result(False, False, None, None,
                                                         f"DSSE payload rejected (fail-closed): {exc}",
                                                         erwartet),
                                   TEST_RESULT_PREDICATE_TYPE, _test_result_claim_fields)
    binding_ok, alg, detail = _content_root_binding(statement, body)
    return _judge_claim_fields(
        _intoto_verify_result(ok, binding_ok, statement, alg, detail, erwartet),
        TEST_RESULT_PREDICATE_TYPE, _test_result_claim_fields)


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# eval-result predicate (in-toto/attestation#565 proposal) — subject profiles, salted commitments.
# ─────────────────────────────────────────────────────────────────────────────────────────────────

def _is_sha256_hex(value: Any) -> bool:
    """True iff `value` is a 64-char lowercase hex string (a DigestSet sha256, per in-toto DigestSet rules)."""
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _commitment(commit: Optional[str], alg: Optional[str]) -> Optional[dict]:
    """A salted-commitment digest object `{alg, value, salted}` — never a plain artifact hash. `commit` is
    the receipt's `sha256:<hex>` form; the `salted:true` flag makes the privacy semantics explicit so a
    generic verifier never mistakes it for a content digest."""
    if not commit:
        return None
    return {"alg": alg or "sha256-salted-v1", "value": _commit_hex(commit), "salted": True}


def _forbid_plaintext_in_export(claim: dict) -> None:
    """Fail closed if the claim carries a plaintext identifier or a raw salt. An export must stay
    commitment-only — leaking a secret into a portable attestation is the one thing this path must never
    do (Paket 2 test 1). This guard is what the salt-leak mutation operator targets."""
    leaked = [k for k in _FORBIDDEN_PLAINTEXT_KEYS if k in claim]
    if leaked:
        raise BundleFormatError(
            f"refusing to export: claim carries plaintext/secret field(s) {leaked}; the in-toto export is "
            "commitment-only and must never carry a model/dataset name or a salt")


def _refuse_to_vouch_for_a_key_nobody_holds(claim: Any, wo: str) -> None:
    """Refuse to SIGN a statement over a claim whose issuer key the trust-anchor rule refuses.

    SPEC section 4b lets the bundle's own key keep the section 4a profile when a receipt is VERIFIED,
    because a relying party's trust in it comes from a pin that carries the rule. An export that SIGNS
    is a different act: proofbundle then vouches, under a real key, for what it read. Measured on
    053c7800 (lens run 1, out-of-scope finding 3): `export_svr_dsse` signed
    PROOFBUNDLE_SIGNATURE_VALID and PROOFBUNDLE_THRESHOLD_MET over a PASS receipt that nobody signed
    under the identity point, and the SVR verified under the exporter's key. The eval-result and
    test-result exports signed the same claim just as readily. A claim carries its issuer (the key
    `decode_eval_claim` binds to the signature), so the key is judged here, with the shared rule and
    the one issuer parser. A claim that names no ed25519 key has nothing to judge and is not refused
    here; whoever hands such a claim to an exporter is answering for it themselves."""
    from .evalclaim import _issuer_key_weakness  # noqa: PLC0415
    from .signature import TRUST_ANCHOR_REFUSAL  # noqa: PLC0415
    # By the claim's own type: `isinstance` reads a caller's `__class__`, and the `get` of an object that
    # only claims to be a dict is its own code (the exporter's own reading refuses such a claim next).
    grund = _issuer_key_weakness(claim.get("issuer")) if issubclass(type(claim), dict) else None
    if grund is not None:
        raise BundleFormatError(
            f"{wo}: the receipt's issuer key is a {grund} Ed25519 key, refused as a trusted key: "
            f"{TRUST_ANCHOR_REFUSAL[grund]} — proofbundle does not sign a statement over a receipt "
            "that key 'signed' (SPEC section 4b)")


def _require_export_fields(claim: dict) -> bool:
    """Refuse to export an invalid/incomplete receipt claim (Paket 2 test 3).

    RETURNS THE VALIDATED VERDICT, and that return type is the fix for a review finding rather than a
    convenience. See the comment at the emit site: a caller that re-reads the field instead of using
    this value can be handed a different value than the one that was checked.
    """
    if not isinstance(claim, dict):
        raise BundleFormatError("eval-result export needs a claim object")
    missing = [k for k in _EXPORT_REQUIRED if claim.get(k) in (None, "")]
    if missing:
        raise BundleFormatError(f"refusing to export: claim is missing required field(s) {missing}")
    # PRESENCE IS NOT TYPE, and `passed` is in _EXPORT_REQUIRED, which is exactly why this was missed:
    # the field was required and therefore looked checked. `"false"` is a non-empty string, so it passes
    # the loop above; R-B4. The type check belongs here rather than at each caller of this function.
    return require_bool_verdict(claim, wo="refusing to export")


@_ein_stand(fehler=BundleFormatError)
def resolve_subject(profile: str, claim: dict, *, root_b64: Optional[str] = None,
                    subject_name: Optional[str] = None, subject_sha256: Optional[str] = None) -> list:
    """Build the Statement `subject` for a subject profile. Every subject carries a real `digest` (in-toto
    matches on the digest alone). See SUBJECT_PROFILES for what each subject IS.

    * ``receipt`` (default): the subject is the receipt; the digest is the sha256 of a stable binder over
      the model+dataset commitments, the merkle root, and the timestamp — a real hex digest that binds the
      attestation to the receipt WITHOUT revealing the model.
    * ``public-model`` / ``release-gate``: the subject is a disclosed artifact; the caller supplies its real
      lowercase-hex sha256 (`subject_sha256`) and a name (`subject_name`).

    Every argument is read once, as its plain copy (`_eigen`), before it is compared or used. A
    ``subject_sha256`` that is not a string is refused, where ``.lower()`` of it raised a raw
    AttributeError. ``profile``, ``root_b64``, ``subject_name`` and ``subject_sha256`` must be strings
    (the last three may be None), checked on the copy (round 9): a ``subject_name`` that is a number,
    a list or an object was written as the subject's name, and a ``profile`` of ``10**5000`` raised
    a raw ValueError from the refusal that named it.
    """
    wo = "resolve_subject"
    claim = _claim_once(claim)
    profile = _text_once(profile, f"unknown subject profile of type {type_name(profile)} "
                                  f"(one of {', '.join(SUBJECT_PROFILES)})")
    if subject_name is not None:
        subject_name = _text_once(subject_name, "subject_name must be text")
    if subject_sha256 is not None:
        subject_sha256 = _text_once(subject_sha256, "subject_sha256 must be text")
    profile = _eigener_pflichttext(profile, wo, "profile")
    if profile == "receipt":
        claim = require_eval_claim(claim, wo=wo)
        root_b64 = _eigener_text(root_b64, wo, "root_b64")
        if not claim.get("model_id_commit") or not claim.get("timestamp"):
            raise BundleFormatError("receipt subject profile needs model_id_commit and timestamp")
        binder = json.dumps({
            "model_id_commit": claim["model_id_commit"],
            "dataset_id_commit": claim.get("dataset_id_commit"),
            "root_b64": root_b64,
            "timestamp": claim["timestamp"],
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return [{"name": "eval-receipt", "digest": {"sha256": hashlib.sha256(binder).hexdigest()}}]
    if profile in ("public-model", "release-gate"):
        subject_name = _eigener_text(subject_name, wo, "subject_name")
        subject_sha256 = _eigener_text(subject_sha256, wo, "subject_sha256")
        sha = subject_sha256.lower() if subject_sha256 is not None else ""
        if not subject_name or not _is_sha256_hex(sha):
            raise BundleFormatError(
                f"subject profile '{profile}' requires --subject-name and a 64-char hex --subject-sha256")
        return [{"name": subject_name, "digest": {"sha256": sha}}]
    raise BundleFormatError(
        f"unknown subject profile {render_safe(profile)} (one of {', '.join(SUBJECT_PROFILES)})")


@_ein_stand(fehler=BundleFormatError)
def to_eval_result_predicate(claim: dict, *, root_b64: Optional[str] = None,
                             harness: Optional[dict] = None, anchors: Optional[list] = None,
                             subject_profile: str = "receipt") -> dict:
    """Build the `eval-result/v0.1` predicate (lowerCamelCase, RFC-3339 speaking time fields, salted
    commitments, digests as {alg, value}). Validates the claim and refuses to leak secrets first. Only
    fields with real data are emitted (no fabricated `signedAt`/`preRegisteredAt`)."""
    # Twice on purpose: first on the plain copy of the claim handed in, so the plaintext guard
    # answers before the claim rule (which would refuse a plaintext key only as an unknown field);
    # then on the claim read back, so the verdict written below is the value in the canonical bytes.
    # The first pass read the caller's object until round 8 (its `get`, `==` and `__contains__`).
    wo = "to_eval_result_predicate"
    claim = _claim_once(claim)
    subject_profile = _text_once(subject_profile, f"unknown subject profile of type "
                                                  f"{type_name(subject_profile)}")
    claim = _eigen(claim, wo)
    _require_export_fields(claim)
    _forbid_plaintext_in_export(claim)
    claim = require_eval_claim(claim, wo=wo)
    verdikt = _require_export_fields(claim)
    root_b64 = _eigener_text(root_b64, wo, "root_b64")
    harness = _eigen(harness, wo, "harness")
    anchors = _eigen(anchors, wo, "anchors")
    subject_profile = _eigener_pflichttext(subject_profile, wo, "subject_profile")
    predicate: dict[str, Any] = {
        "verifier": {"id": VERIFIER_ID},
        "evaluatedAt": claim["timestamp"],
        "suite": {"name": claim["suite"], "version": claim.get("suite_version")},
        "claims": [{
            "metric": claim["metric"], "comparator": claim["comparator"],
            # THE VALIDATED VALUE, NOT A SECOND READ -- and this comment replaces one that argued
            # for the wrong thing. It said: `claim["passed"]` raw rather than `bool(...)`, because
            # `_require_export_fields` above already refuses anything that is not a boolean. That
            # argument was about COERCION and passed over the ACCESSOR: what was validated is
            # `claim.get("passed")`, what was emitted is `claim["passed"]`. For a dict whose `get`
            # and `__getitem__` disagree those are two values. Measured 2026-09-24 with a dict
            # subclass whose `get("passed")` returns True while the stored item is `"false"`: the
            # validation passed, the predicate carried the string, and the DSSE path signed it.
            # THE CLASS: a check through one accessor and a use through another. The guard is not a
            # third accessor but PASSING THE VALIDATED VALUE ON.
            "threshold": claim["threshold"], "passed": verdikt,
        }],
        "sampleSize": claim["n"],
        "commitments": {
            "model": _commitment(claim["model_id_commit"], claim.get("commit_alg")),
            "dataset": _commitment(claim.get("dataset_id_commit"), claim.get("commit_alg")),
        },
        "assuranceLevel": claim.get("assurance_level", "self_attested"),
        "subjectProfile": subject_profile,
    }
    if subject_profile == "receipt":
        predicate["subjectDigestNote"] = (
            "subject.digest is a binder over the receipt commitments+root, not an artifact hash")
    prereg = claim.get("prereg_sha256")
    if prereg:
        predicate["preRegistration"] = {"alg": "sha256", "value": prereg}
    if root_b64:
        predicate["receipt"] = {"schema": "proofbundle/v0.1", "merkleRootB64": root_b64}
    if harness:
        predicate["harness"] = harness
    if anchors:
        predicate["anchors"] = anchors
    return predicate


@_ein_stand(fehler=BundleFormatError)
def to_eval_result_statement(claim: dict, *, subject: list, root_b64: Optional[str] = None,
                             harness: Optional[dict] = None, anchors: Optional[list] = None,
                             subject_profile: str = "receipt",
                             content_root_alg: str = CONTENT_ROOT_ALG) -> dict:
    """A STANDARD in-toto Statement v1 carrying the eval-result predicate. Declares its content-root
    algorithm (default `jcs-sha256-v1`, ADR 0002); legacy adds no `contentRootAlg` field."""
    content_root_alg = _alg_once(content_root_alg)
    predicate = to_eval_result_predicate(claim, root_b64=root_b64, harness=harness,
                                         anchors=anchors, subject_profile=subject_profile)
    subject = _eigen(subject, "to_eval_result_statement", "subject")
    content_root_alg = _eigener_pflichttext(content_root_alg, "to_eval_result_statement", "content_root_alg")
    return _declare_content_root_alg({
        "_type": STATEMENT_TYPE,
        "subject": subject,
        "predicateType": EVAL_RESULT_PREDICATE_TYPE,
        "predicate": predicate,
    }, content_root_alg)


@_ein_stand(aussen={"signer": "signierer"}, fehler=BundleFormatError)
def export_eval_result_dsse(claim: dict, signer, *, subject_profile: str = "receipt",
                            subject_name: Optional[str] = None, subject_sha256: Optional[str] = None,
                            root_b64: Optional[str] = None, harness: Optional[dict] = None,
                            anchors: Optional[list] = None, keyid: Optional[str] = None,
                            content_root_alg: str = CONTENT_ROOT_ALG) -> dict:
    """Export a receipt as a DSSE-signed in-toto Statement with the eval-result predicate. Deterministic:
    identical inputs produce byte-identical statement bytes. The signed Statement declares its content-root
    algorithm (default `jcs-sha256-v1`, ADR 0002 / WP2 activation). Pass
    `content_root_alg=LEGACY_CONTENT_ROOT_ALG` for a byte-identical legacy re-emission (released 2.0.0 wire:
    json.dumps root, no field).

    The string arguments are checked as strings whether or not the profile reads them (round 9), and
    a value the serializer cannot write is this function's BundleFormatError (`_signed_body_refusal`)."""
    from . import dsse  # noqa: PLC0415 — lazy: keeps the verify core free of the DSSE module

    wo = "export_eval_result_dsse"
    claim = _claim_once(claim)
    content_root_alg = _alg_once(content_root_alg)
    subject_profile = _text_once(subject_profile, f"unknown subject profile of type "
                                                  f"{type_name(subject_profile)}")
    claim = _eigen(claim, wo)              # the one reading of the caller's claim (round 8)
    _require_export_fields(claim)          # fail-closed BEFORE building the (receipt-profile) subject binder
    _forbid_plaintext_in_export(claim)
    _refuse_to_vouch_for_a_key_nobody_holds(claim, "refusing to export the eval-result attestation")
    claim = require_eval_claim(claim, wo=wo)
    subject_profile = _eigener_pflichttext(subject_profile, wo, "subject_profile")
    subject_name = _eigener_text(subject_name, wo, "subject_name")
    subject_sha256 = _eigener_text(subject_sha256, wo, "subject_sha256")
    root_b64 = _eigener_text(root_b64, wo, "root_b64")
    harness = _eigen(harness, wo, "harness")
    anchors = _eigen(anchors, wo, "anchors")
    keyid = _eigener_text(keyid, wo, "keyid")
    content_root_alg = _eigener_pflichttext(content_root_alg, wo, "content_root_alg")
    subject = resolve_subject(subject_profile, claim, root_b64=root_b64,
                              subject_name=subject_name, subject_sha256=subject_sha256)
    statement = to_eval_result_statement(claim, subject=subject, root_b64=root_b64, harness=harness,
                                         anchors=anchors, subject_profile=subject_profile,
                                         content_root_alg=content_root_alg)
    try:
        body = _serialize_statement(statement, content_root_alg)
    except (CanonicalizerUnavailable, BundleFormatError):
        raise
    except (ProofBundleError, ValueError, RecursionError) as exc:
        raise _signed_body_refusal(wo, exc) from exc
    return dsse.sign_envelope(body, signer, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE, keyid=keyid)


@_ein_stand(fehler=BundleFormatError)
def verify_eval_result_dsse(envelope: dict, public_key: bytes, *,
                            expected_predicate_type: Optional[str] = EVAL_RESULT_PREDICATE_TYPE) -> dict:
    """Verify a DSSE-signed eval-result attestation. Returns {ok, statement, predicate_type,
    predicate_type_ok, content_root_alg, content_root_ok, content_root_detail, predicate_claim_ok,
    predicate_shape_ok, predicate_shape_detail}. `ok` is True iff the Ed25519 signature over the DSSE PAE
    verifies, payloadType is the pinned in-toto Statement media type, the payload is canonical for its
    DECLARED contentRootAlg (absent ⇒ legacy; ADR 0002), the statement's `predicateType` equals
    `expected_predicate_type` (WP-I1: predicate-confusion defense — the type was previously only returned,
    so a swapped SVR/test-result envelope was accepted as an eval-result), AND, for a statement that
    declares `EVAL_RESULT_V02_PREDICATE_TYPE`, its predicate has the v0.2 shape
    (`classify_eval_result_v02_predicate`).

    `ok` also requires that every eval-claim field the predicate carries (claims[], sampleSize,
    commitments, suite, evaluatedAt, assuranceLevel, preRegistration) passes the claim rule, and so
    does every subject entry carrying a proofbundle commitment digest (`predicate_claim_ok`, see
    `_judge_claim_fields`). An absent field is not judged.

    The default still expects v0.1, and a v0.1 statement is judged exactly as before (no shape check,
    `predicate_shape_ok` None). To verify v0.2, pass `expected_predicate_type=EVAL_RESULT_V02_PREDICATE_TYPE`.
    Pass `expected_predicate_type=None` to opt out of the type check; the shape of a v0.2 statement is
    checked all the same. ``expected_predicate_type`` must be a string or None, and the envelope is read
    once, as for `verify_intoto_dsse`."""
    from . import dsse  # noqa: PLC0415
    from .errors import ProofBundleError  # noqa: PLC0415

    erwartet = _eigener_text(expected_predicate_type, "verify_eval_result_dsse", "expected_predicate_type")
    try:
        # RE-GATE never-raise (mirror verify_intoto_dsse): crypto + load + budget + parse inside the guard;
        # a wide/oversized/dup-key/malformed untrusted envelope yields a fail-closed verdict, never a raw
        # exception out of this dict-returning verify surface.
        ok, body = dsse._verify_and_load(envelope, public_key, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE)
        statement = loads_strict(body.decode("utf-8"))   # WP-C1: duplicate keys rejected fail-closed
    except (ProofBundleError, ValueError, UnicodeDecodeError) as exc:
        res = _judge_claim_fields(_intoto_verify_result(False, False, None, None,
                                                        f"DSSE payload rejected (fail-closed): {exc}",
                                                        erwartet),
                                  EVAL_RESULT_PREDICATE_TYPE, _eval_result_statement_claim_fields)
        res["predicate_shape_ok"], res["predicate_shape_detail"] = None, ""
        return res
    binding_ok, alg, detail = _content_root_binding(statement, body)
    res = _judge_claim_fields(
        _intoto_verify_result(ok, binding_ok, statement, alg, detail, erwartet),
        EVAL_RESULT_PREDICATE_TYPE, _eval_result_statement_claim_fields)
    # THE CONTRACT FOLLOWS THE TYPE THE SIGNED STATEMENT DECLARES, not the type the caller expected: a
    # v0.2 statement is judged under v0.2 even when the caller opted out of the type check, and a v0.1
    # statement is never judged under v0.2. v0.1 has no shape contract and gets none now (G2: old
    # evidence stays verifiable under its old contract); `None` says that no shape was checked.
    if res["predicate_type"] == EVAL_RESULT_V02_PREDICATE_TYPE:
        shape_ok, shape_detail = classify_eval_result_v02_predicate(statement)
        res["predicate_shape_ok"], res["predicate_shape_detail"] = shape_ok, shape_detail
        if not shape_ok:
            res["ok"] = False
            res["content_root_detail"] = (
                (res["content_root_detail"] + "; " if res["content_root_detail"] else "") + shape_detail)
    else:
        res["predicate_shape_ok"], res["predicate_shape_detail"] = None, ""
    return res


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# eval-result v0.2 — the revised in-toto/attestation#575 draft (docs/upstream/eval-result.md).
# ─────────────────────────────────────────────────────────────────────────────────────────────────

# A URI with a scheme and no whitespace or control character (RFC 3986 shape, not a registry lookup).
_URI_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9+.\-]*:[^\s\x00-\x1f\x7f]+\Z")
_RFC3339_RE = re.compile(
    r"\A(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?(?:[Zz]|[+-](\d{2}):(\d{2}))\Z")
_LOWER_HEX_RE = re.compile(r"\A[0-9a-f]+\Z")
# The claim builder's grammar for a decimal string (evalclaim._DECIMAL_RE): the draft says "decimal
# string" and gives no grammar, so this is the reading implemented (ambiguity A3, docs/IN_TOTO_PROFILE.md).
_DECIMAL_STRING_RE = re.compile(r"\A-?[0-9]+(\.[0-9]+)?\Z")
# Fixed output lengths of the hash functions: a digest under one of these names that has another length,
# or is not lowercase hex, names no content. Every other algorithm name only needs a non-empty string.
_HEX_DIGEST_LENGTHS = (("md5", 32), ("sha1", 40), ("sha224", 56), ("sha256", 64), ("sha384", 96),
                       ("sha512", 128), ("sha512_224", 56), ("sha512_256", 64), ("sha3_224", 56),
                       ("sha3_256", 64), ("sha3_384", 96), ("sha3_512", 128))
_V02_COMPARATORS = (">=", ">", "<=", "<")
_V02_ASSURANCE_LEVELS = ("self_attested", "third_party", "reproduced", "enclave_attested")
_RD_STRING_FIELDS = ("name", "uri", "mediaType", "downloadLocation", "content")
# The algorithms whose digest over an inline `content` this verifier can recompute. A DigestSet may name
# others; for those the content is not compared, and that is stated, not hidden.
_CONTENT_DIGESTS = (("sha256", hashlib.sha256), ("sha384", hashlib.sha384), ("sha512", hashlib.sha512),
                    ("sha224", hashlib.sha224), ("sha1", hashlib.sha1), ("sha3_256", hashlib.sha3_256),
                    ("sha3_384", hashlib.sha3_384), ("sha3_512", hashlib.sha3_512))
_MAX_SAFE_INT = 2 ** 53 - 1


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _is_rfc3339(value: Any) -> bool:
    """An RFC 3339 date-time with an offset, and a real calendar date (no month 13, no 30 February)."""
    if not isinstance(value, str):
        return False
    m = _RFC3339_RE.match(value)
    if not m:
        return False
    year, month, day, hour, minute, second = (int(m.group(i)) for i in range(1, 7))
    if not 1 <= month <= 12:
        return False
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days = (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)[month - 1]
    if not (1 <= day <= days and hour <= 23 and minute <= 59 and second <= 60):
        return False
    if m.group(8) is not None and (int(m.group(8)) > 23 or int(m.group(9)) > 59):
        return False
    return True


def _digest_set_problem(value: Any) -> str:
    """'' for a usable DigestSet, else what is wrong with it."""
    if not isinstance(value, dict):
        return f"digest must be a DigestSet object, got {type(value).__name__}"
    if not value:
        return "digest is empty"
    for alg, hexval in value.items():
        if not _nonempty_str(alg):
            return "digest has an empty algorithm name"
        if not _nonempty_str(hexval):
            return f"digest {alg[:40]!r} must be a non-empty string"
        for name, length in _HEX_DIGEST_LENGTHS:
            if alg == name and (len(hexval) != length or not _LOWER_HEX_RE.match(hexval)):
                return f"digest {alg!r} must be {length} lowercase hex characters"
    return ""


def _descriptor_problem(value: Any, where: str) -> str:
    """'' for a ResourceDescriptor that MUST carry `digest` (model, dataset, evidence entries)."""
    if not isinstance(value, dict):
        return f"{where} must be a ResourceDescriptor object, got {type(value).__name__}"
    if "digest" not in value:
        return f"{where} MUST carry digest"
    problem = _digest_set_problem(value["digest"])
    if problem:
        return f"{where}: {problem}"
    for field in _RD_STRING_FIELDS:
        if field in value and not isinstance(value[field], str):
            return f"{where}.{field} must be a string"
    if "annotations" in value and not isinstance(value["annotations"], dict):
        return f"{where}.annotations must be an object"
    if "content" in value:
        # The digest identifies the decoded bytes of `content` (draft, evidence field rules). `content` is
        # bytes in the ResourceDescriptor, carried in JSON as standard base64 (the house's one strict
        # decoder: canonical, padded); a digest that names other bytes contradicts its descriptor.
        try:
            decoded = decode_b64(value["content"])
        except (binascii.Error, ValueError):
            return f"{where}.content must be canonical standard base64 (the descriptor's bytes)"
        for name, function in _CONTENT_DIGESTS:
            if name in value["digest"] and function(decoded).hexdigest() != value["digest"][name]:
                return f"{where}: digest {name!r} does not identify the decoded content"
    return ""


def _commitment_problem(value: Any, where: str) -> str:
    """'' for a commitment entry `{alg, value, salted}`. A present entry that is not usable (null, a
    list, a missing field) is refused, never read as absent."""
    if not isinstance(value, dict):
        return f"{where} must be an object {{alg, value, salted}}, got {type(value).__name__}"
    if not _nonempty_str(value.get("alg")):
        return f"{where}.alg must be a non-empty string"
    hexval = value.get("value")
    if not (isinstance(hexval, str) and _LOWER_HEX_RE.match(hexval)):
        return f"{where}.value must be a non-empty lowercase hex string"
    if value.get("salted") is not True:
        return f"{where}.salted must be true (each commitment entry MUST set it to true)"
    return ""


def _claim_problems(claim: Any, where: str) -> list:
    if not isinstance(claim, dict):
        return [f"{where} must be an object {{metric, comparator, threshold, passed}}"]
    out = []
    if not _nonempty_str(claim.get("metric")):
        out.append(f"{where}.metric must be a non-empty string")
    comparator = claim.get("comparator")
    if not (isinstance(comparator, str) and comparator in _V02_COMPARATORS):
        out.append(f"{where}.comparator must be one of >=, >, <=, <")
    threshold = claim.get("threshold")
    if not (isinstance(threshold, str) and _DECIMAL_STRING_RE.match(threshold)):
        out.append(f"{where}.threshold must be a decimal string, never a JSON number")
    if not isinstance(claim.get("passed"), bool):
        out.append(f"{where}.passed must be a boolean")
    return out


def _eval_result_v02_predicate_problems(pred: Any) -> list:
    """Every way `pred` departs from the v0.2 predicate. Unknown fields are ignored at every level (in-toto
    parsing rules); a KNOWN field that is present must be usable, and a present-but-unusable value is
    refused rather than read as absent."""
    if not isinstance(pred, dict):
        return [f"predicate must be an object, got {type(pred).__name__}"]
    out = []
    evaluator = pred.get("evaluator")
    if not isinstance(evaluator, dict):
        hint = " (found `verifier`, the v0.1 role name)" if "verifier" in pred else ""
        out.append(f"evaluator is required: an object with id, the URI of the party that ran the evaluation{hint}")
    elif not (isinstance(evaluator.get("id"), str) and _URI_RE.match(evaluator["id"])):
        out.append("evaluator.id is required and must be a URI (TypeURI)")
    if not _is_rfc3339(pred.get("evaluatedAt")):
        out.append("evaluatedAt is required and must be an RFC 3339 date-time with an offset")
    suite = pred.get("suite")
    if not (isinstance(suite, dict) and _nonempty_str(suite.get("name")) and _nonempty_str(suite.get("version"))):
        out.append("suite is required: {name, version}, both non-empty strings")
    claims = pred.get("claims")
    if not isinstance(claims, list) or not claims:
        out.append("claims is required: one or more {metric, comparator, threshold, passed}")
    else:
        for i, claim in enumerate(claims):
            out.extend(_claim_problems(claim, f"claims[{i}]"))
    size = pred.get("sampleSize")
    if not (isinstance(size, int) and not isinstance(size, bool) and 0 <= size <= _MAX_SAFE_INT):
        out.append("sampleSize is required: a non-negative integer")
    commitments: Any = pred.get("commitments", {})
    if not isinstance(commitments, dict):
        out.append(f"commitments must be an object, got {type(commitments).__name__}")
        commitments = {}
    for identity in ("model", "dataset"):
        forms = [form for form, present in ((f"commitments.{identity}", identity in commitments),
                                            (f"a top-level {identity} descriptor", identity in pred)) if present]
        if len(forms) != 1:
            found = " and ".join(forms) if forms else "neither"
            out.append(f"{identity} must be identified exactly once, by commitments.{identity} or by a "
                       f"top-level {identity} ResourceDescriptor; found {found}")
        elif identity in pred:
            problem = _descriptor_problem(pred[identity], identity)
            if problem:
                out.append(problem)
        else:
            problem = _commitment_problem(commitments[identity], f"commitments.{identity}")
            if problem:
                out.append(problem)
    level = pred.get("assuranceLevel")
    if not (isinstance(level, str) and level in _V02_ASSURANCE_LEVELS):
        out.append("assuranceLevel must be one of " + ", ".join(_V02_ASSURANCE_LEVELS))
    profile = pred.get("subjectProfile")
    if not (isinstance(profile, str) and profile in SUBJECT_PROFILES):
        out.append("subjectProfile must be one of " + ", ".join(SUBJECT_PROFILES))
    if "preRegistration" in pred:
        prereg = pred["preRegistration"]
        if not (isinstance(prereg, dict) and _nonempty_str(prereg.get("alg"))
                and isinstance(prereg.get("value"), str) and _LOWER_HEX_RE.match(prereg["value"])):
            out.append("preRegistration must be {alg, value} with a lowercase hex value")
    if "evidence" in pred:
        evidence = pred["evidence"]
        if not isinstance(evidence, list):
            out.append(f"evidence must be an array of ResourceDescriptors, got {type(evidence).__name__}")
        else:
            for i, entry in enumerate(evidence):
                problem = _descriptor_problem(entry, f"evidence[{i}]")
                if problem:
                    out.append(problem)
    if "harness" in pred:
        harness = pred["harness"]
        if not (isinstance(harness, dict) and _nonempty_str(harness.get("name"))
                and _nonempty_str(harness.get("version"))):
            out.append("harness must carry name and version as non-empty strings")
        elif "digest" in harness:
            problem = _digest_set_problem(harness["digest"])
            if problem:
                out.append(f"harness: {problem}")
    return out


def classify_eval_result_v02_predicate(statement: Any) -> tuple[bool, str]:
    """Judge a Statement against eval-result v0.2 (the revised #575 draft). Returns ``(ok, detail)``;
    ``detail`` names every violation, joined by "; ", and is empty when ok. Never raises: the input is
    the content of a signed envelope, which is untrusted however valid the signature is.

    Refused: an absent or non-URI ``evaluator.id``; a model or dataset identified twice or not at all
    (``commitments.<x>`` against a predicate-level ResourceDescriptor, both locations inspected, subject
    and evidence never counted); a present representation that fails its own rules (a commitment whose
    ``salted`` is not ``true``, a descriptor without a usable ``digest``); an evidence entry without a
    usable ``digest``, or whose ``content`` is not the bytes its digest names; a required field that is
    absent or of the wrong type; a Statement whose ``_type`` is not Statement v1 or whose subject carries
    no digest. Ignored: every unknown field, at every level, including the v0.1 ``receipt`` block,
    ``anchors`` and ``subjectDigestNote``. Not refused: an evidence entry without ``mediaType``, ``uri`` or
    ``downloadLocation`` (the draft says SHOULD), and an evaluator that is also the signer (the same party
    MAY hold more than one role)."""
    if not isinstance(statement, dict):
        return False, f"statement must be a JSON object, got {type(statement).__name__}"
    out = []
    if statement.get("_type") != STATEMENT_TYPE:
        out.append(f"_type must be {STATEMENT_TYPE}")
    subject = statement.get("subject")
    if not isinstance(subject, list) or not subject:
        out.append("subject must be a non-empty array")
    else:
        for i, entry in enumerate(subject):
            problem = _descriptor_problem(entry, f"subject[{i}]")
            if problem:
                out.append(problem)
    out.extend(_eval_result_v02_predicate_problems(statement.get("predicate")))
    return (not out), "; ".join(out)


def receipt_evidence(receipt_bytes: bytes, *, uri: Optional[str] = None) -> dict:
    """The `evidence[]` entry for an eval receipt: a ResourceDescriptor whose digest is the SHA-256 of the
    receipt file's exact bytes, so a generic consumer can fetch the file and compare.

    WHICH BYTES. A proofbundle receipt is one JSON file that carries the signed payload, the signature and
    the Merkle tree together, so the digest over the file covers the signature as the draft requires
    for a signed receipt whose envelope is part of what is supplied. The Merkle root that v0.1 carried in
    its `receipt` block is NOT written here, neither as the digest nor beside it: an internal root is not
    a substitute for the digest of the artifact. A caller that cannot hash the receipt it refers to
    writes no evidence entry for it. `uri` is where the receipt can be fetched (the draft's SHOULD)."""
    if not isinstance(receipt_bytes, (bytes, bytearray)):
        raise BundleFormatError(
            f"receipt_evidence needs the receipt file's bytes, got {type(receipt_bytes).__name__}")
    descriptor: dict[str, Any] = {
        "name": "eval-receipt",
        "digest": {"sha256": hashlib.sha256(bytes(receipt_bytes)).hexdigest()},
        "mediaType": "application/json",
    }
    if uri is not None:
        if not (isinstance(uri, str) and _URI_RE.match(uri)):
            raise BundleFormatError("receipt_evidence: uri must be a URI")
        descriptor["uri"] = uri
    return descriptor


def to_eval_result_v02_predicate(claim: dict, *, evaluator_id: str, subject_profile: str = "receipt",
                                 model: Optional[dict] = None, dataset: Optional[dict] = None,
                                 evidence: Optional[list] = None, harness: Optional[dict] = None) -> dict:
    """Build the eval-result v0.2 predicate from a receipt claim.

    * ``evaluator_id``: the URI of the party that ran the evaluation. Required, no default: proofbundle
      records a result, it does not run the evaluation, so its own URI would name the wrong party.
    * ``model`` / ``dataset``: a ResourceDescriptor with a real ``digest`` for a PUBLIC identity. When given,
      it replaces the salted commitment for that identity; when not, the commitment is written. Each
      identity is therefore identified exactly once.
    * ``evidence``: ResourceDescriptors, each with a ``digest`` of the artifact it names (see
      ``receipt_evidence``). None writes no evidence: nothing is derived from ``root_b64`` here.

    ``subjectDigestNote`` stays for the receipt profile: its subject digest is a binder that names no file,
    and the note says so. ``anchors`` is not written: the draft scoped it out, and an external anchor is
    carried as an ``evidence`` entry with its own digest. Refuses a claim that carries a plaintext
    identifier or a salt, and a claim without ``suite_version`` (the draft requires ``suite.version``)."""
    verdikt = _require_export_fields(claim)
    _forbid_plaintext_in_export(claim)
    if not (isinstance(evaluator_id, str) and _URI_RE.match(evaluator_id)):
        raise BundleFormatError(
            "eval-result v0.2 needs evaluator_id, the URI of the party that ran the evaluation; there is no "
            "default, because the tool that records a result is not the party that produced it")
    suite_version = claim.get("suite_version")
    if not _nonempty_str(suite_version):
        raise BundleFormatError("eval-result v0.2 needs the claim's suite_version: suite is {name, version}")
    predicate: dict[str, Any] = {
        "evaluator": {"id": evaluator_id},
        "evaluatedAt": claim["timestamp"],
        "suite": {"name": claim["suite"], "version": suite_version},
        # `verdikt`, the validated value, never a second read of claim["passed"] (see to_eval_result_predicate).
        "claims": [{"metric": claim["metric"], "comparator": claim["comparator"],
                    "threshold": claim["threshold"], "passed": verdikt}],
        "sampleSize": claim["n"],
    }
    commitments: dict[str, Any] = {}
    if model is None:
        commitments["model"] = _commitment(claim["model_id_commit"], claim.get("commit_alg"))
    else:
        predicate["model"] = copy.deepcopy(model)
    if dataset is None:
        commitments["dataset"] = _commitment(claim["dataset_id_commit"], claim.get("commit_alg"))
    else:
        predicate["dataset"] = copy.deepcopy(dataset)
    if commitments:
        predicate["commitments"] = commitments
    predicate["assuranceLevel"] = claim.get("assurance_level", "self_attested")
    predicate["subjectProfile"] = subject_profile
    if subject_profile == "receipt":
        predicate["subjectDigestNote"] = (
            "subject.digest is a binder over the receipt commitments+root, not an artifact hash")
    prereg = claim.get("prereg_sha256")
    if prereg:
        predicate["preRegistration"] = {"alg": "sha256", "value": prereg}
    if evidence is not None:
        predicate["evidence"] = copy.deepcopy(evidence)
    if harness is not None:
        predicate["harness"] = copy.deepcopy(harness)
    problems = _eval_result_v02_predicate_problems(predicate)
    if problems:
        raise BundleFormatError(
            "refusing to emit an eval-result v0.2 predicate its own verifier refuses: " + "; ".join(problems))
    return predicate


def to_eval_result_v02_statement(claim: dict, *, subject: list, evaluator_id: str,
                                 subject_profile: str = "receipt", model: Optional[dict] = None,
                                 dataset: Optional[dict] = None, evidence: Optional[list] = None,
                                 harness: Optional[dict] = None,
                                 content_root_alg: str = CONTENT_ROOT_ALG) -> dict:
    """A STANDARD in-toto Statement v1 carrying the eval-result v0.2 predicate, with its content-root
    algorithm declared (default `jcs-sha256-v1`). Refuses to return a Statement that
    `classify_eval_result_v02_predicate` would refuse."""
    statement = _declare_content_root_alg({
        "_type": STATEMENT_TYPE,
        "subject": subject,
        "predicateType": EVAL_RESULT_V02_PREDICATE_TYPE,
        "predicate": to_eval_result_v02_predicate(
            claim, evaluator_id=evaluator_id, subject_profile=subject_profile, model=model, dataset=dataset,
            evidence=evidence, harness=harness),
    }, content_root_alg)
    ok, detail = classify_eval_result_v02_predicate(statement)
    if not ok:
        raise BundleFormatError(f"refusing to emit an eval-result v0.2 statement its own verifier refuses: {detail}")
    return statement


def export_eval_result_v02_dsse(claim: dict, signer, *, evaluator_id: str, subject_profile: str = "receipt",
                                subject_name: Optional[str] = None, subject_sha256: Optional[str] = None,
                                root_b64: Optional[str] = None, model: Optional[dict] = None,
                                dataset: Optional[dict] = None, evidence: Optional[list] = None,
                                harness: Optional[dict] = None, keyid: Optional[str] = None,
                                content_root_alg: str = CONTENT_ROOT_ALG) -> dict:
    """Export a receipt claim as a DSSE-signed eval-result v0.2 Statement. `root_b64` feeds the receipt
    profile's subject binder; the receipt itself is referenced through `evidence` (`receipt_evidence`).
    Deterministic: identical inputs give byte-identical statement bytes. Verify with
    `verify_eval_result_dsse(..., expected_predicate_type=EVAL_RESULT_V02_PREDICATE_TYPE)`."""
    from . import dsse  # noqa: PLC0415 — lazy: keeps the verify core free of the DSSE module

    _require_export_fields(claim)          # fail-closed BEFORE building the (receipt-profile) subject binder
    _forbid_plaintext_in_export(claim)
    subject = resolve_subject(subject_profile, claim, root_b64=root_b64,
                              subject_name=subject_name, subject_sha256=subject_sha256)
    statement = to_eval_result_v02_statement(
        claim, subject=subject, evaluator_id=evaluator_id, subject_profile=subject_profile, model=model,
        dataset=dataset, evidence=evidence, harness=harness, content_root_alg=content_root_alg)
    body = _serialize_statement(statement, content_root_alg)
    return dsse.sign_envelope(body, signer, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE, keyid=keyid)


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# SVR export — the in-toto Summary Verification Result (svr/v0.1). A verifier's summary; passing only.
# ─────────────────────────────────────────────────────────────────────────────────────────────────

# predicateType is EXACT (in-toto/attestation SVR predicate, PR #470). Property strings are type-generic
# with a PROOFBUNDLE_ prefix (never a vendor/service name), per the SVR property-string convention.
SVR_PREDICATE_TYPE = "https://in-toto.io/attestation/svr/v0.1"

# WATCH: in-toto/attestation#551 proposes making `verifier.policies` a REQUIRED field for SVR v0.2. It is
# open and uncommented as of 2026-07-05. If it lands, this export must add a policies array — tracked in
# the report. `policy` here is the OPTIONAL v0.1 extension field ({uri, digest}), not the #551 change.


def _now_rfc3339z() -> str:
    from datetime import datetime, timezone  # noqa: PLC0415
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@_ein_stand(fehler=(BundleFormatError, SwitchTypeError))
def svr_properties(result, claim: dict, *, prereg_verified: bool = False,
                   anchor_verified: bool = False) -> list:
    """Map a real VerificationResult + claim to the SVR property strings — ONLY the checks that genuinely
    passed. A missing optional check produces NO property (never a placeholder).

    **No-Overclaim scope (6-lens review):** `PROOFBUNDLE_SIGNATURE_VALID` / `PROOFBUNDLE_RECEIPT_UNCHANGED`
    / `PROOFBUNDLE_THRESHOLD_MET` / `PROOFBUNDLE_SAMPLE_ROOT_VALID` are derived from the passed
    `VerificationResult`/`claim` here. But `PROOFBUNDLE_PREREG_BOUND` and `PROOFBUNDLE_ANCHOR_VALID` are
    emitted PURELY from the caller's `prereg_verified` / `anchor_verified` flags — this function does NOT
    call `anchors.verify_anchors()` and does not check the anchor itself. They are CALLER-ATTESTED: the
    caller MUST have run a real offline anchor verification before passing the flag, or the signed SVR
    asserts a property it did not verify. A present prereg hash or an `anchors[]` block alone is NOT a
    verified binding.

    A check of `result` earns its property only when its `ok` is True itself; any other value earns
    none (round 10, R-B4 at the checks: `ok` was read by its truth, and "false" earned it). When a
    name comes more than once, every check of that name must have `ok` True, whatever the order
    (round 11)."""
    # THE MOST LOAD-BEARING OF THE SIX SITES, because what it decides gets SIGNED. Measured 2026-09-24:
    # `passed="false"` put PROOFBUNDLE_THRESHOLD_MET into a signed SVR while the real `False` produced an
    # empty property list. This function is public, so the check belongs here and not only at
    # `export_svr_dsse`, whose `decode_eval_claim` now refuses a non-boolean one layer earlier. R-B4.
    #
    # AND THE WHOLE CLAIM, not only `passed` (6.2.0). Measured at 835df85b: for a claim with
    # comparator `==`, threshold `inf`, `sha256:x` and a samples block of root "x", n -1, leaf_alg
    # "md5", which decode refuses, this function returned THRESHOLD_MET and SAMPLE_ROOT_VALID. The
    # first call keeps its message, which names field and type; the verdict used below is read from
    # the claim as the rule read it back. The first call reads the plain copy of the claim since
    # round 8; on the caller's object it asked the object's own `get("passed")`. The two flags are
    # read as their plain copies too, and since round 9 each must be True or False (`_eigene_flagge`):
    # a flag was read by its truth, so `anchor_verified="false"` signed PROOFBUNDLE_ANCHOR_VALID
    # (measured at ee489403 and on main 20e91c8e), R-B4 at the flags. A NumPy boolean, an int 0 or 1
    # and a string are refused.
    claim = _eigen(claim, "svr_properties")
    # Nachtrag 48/48b (`KRAXO-CLOUD-N46B-N48B-BINDUNG-NACH-REVIEW-01`, Z309, F3): the digest of the claim exactly
    # as passed, under the same fixed JCS encoding verify_bundle recorded over the signed payload bytes. Used by
    # the result<->claim binding below; captured before require_eval_claim normalises, from the plain copy.
    from .decision import _rfc8785_available as _jcs_ok, _rfc8785_bytes as _jcs  # noqa: PLC0415
    try:
        _claim_digest = hashlib.sha256(_jcs(claim)).hexdigest() if _jcs_ok() else None
    except Exception:   # noqa: BLE001 - a non-canonicalizable claim is simply not bound (fail-closed below)
        _claim_digest = None
    prereg_verified = _eigene_flagge(prereg_verified, "prereg_verified")
    anchor_verified = _eigene_flagge(anchor_verified, "anchor_verified")
    require_bool_verdict(claim, wo="svr_properties")
    claim = require_eval_claim(claim, wo="svr_properties")
    verdikt = require_bool_verdict(claim, wo="svr_properties")
    # A check of `result` counts only when its `ok` is the exact True (round 10), compared by
    # identity, so neither the value's `__bool__` nor its `__class__` is asked. R-B4 at the checks:
    # the caller builds `result`, and `ok` was read by its truth. Measured at 493c2f86:
    # `Check("ed25519-signature", "false")` and `Check("merkle-inclusion", "false")` gave
    # PROOFBUNDLE_SIGNATURE_VALID and PROOFBUNDLE_RECEIPT_UNCHANGED, so did [0], 1 and "true", an
    # object's own `__bool__` ran, and False gave neither.
    #
    # A NAME THAT COMES TWICE (round 11, lens run 10 at fa555f13, finding L10). The checks were folded
    # into a dict by name, so the last check of a name decided: `ed25519-signature` False then True
    # earned PROOFBUNDLE_SIGNATURE_VALID, True then False did not. The rule now is the conjunction
    # `VerificationResult.ok` already applies to the whole result: a property is earned only when its
    # name has at least one check and every check of that name has `ok` True. One failed check of a
    # name withholds the property in any order. Refusing a repeated name was the other rule; it would
    # turn a result that records a check once per signer or per anchor into an error on a surface
    # whose output lists passing properties only, where withholding is already the fail-closed
    # answer. A name is compared by its characters (`canonical._zeichen_von`).
    # The checks read without attribute access that can raise: since deep gate run 6 a result of the caller's
    # own class reaches this body as a stand-in that holds nothing (`canonical._fremdkoerper`), and
    # `result.checks` raised AttributeError for it; such a result earns no property.
    verdikte: dict = {}
    roh: Any = getattr(result, "checks", None)
    gelistet = (list(list.__iter__(roh)) if issubclass(type(roh), list)
                else list(tuple.__iter__(roh)) if issubclass(type(roh), tuple) else [])
    for check in gelistet:
        name = _zeichen_von(getattr(check, "name", None))
        if name is not None:
            verdikte.setdefault(name, []).append(getattr(check, "ok", None))

    def _verdient(name: str) -> bool:
        oks = verdikte.get(name, [])
        return bool(oks) and all(ok is True for ok in oks)

    # Nachtrag 48/48b (`KRAXO-CLOUD-N46B-N48B-BINDUNG-NACH-REVIEW-01`, Z309, F3): no property derived from the
    # result and the claim without binding to EXACTLY this verified claim. The result must be one this process's
    # verify_bundle produced — an authentic origin token, not a hand-built result with matching checks (the
    # svr_properties reproducer the review names) — AND its recorded payload digest must equal this claim's digest
    # under the fixed JCS encoding. Merkle-root equality alone is not enough; a result of another claim, or a
    # mutated claim with a reused result, is refused with no property. export_svr_dsse passes the result and the
    # claim of the same verified bundle, so it keeps its internally-bound positive path.
    _vpd = getattr(result, "verified_payload_digest", None)
    _origin_ok = callable(getattr(result, "origin_authentic", None)) and result.origin_authentic()
    _claim_bound = (_origin_ok and isinstance(_vpd, str) and isinstance(_claim_digest, str)
                    and hmac.compare_digest(_vpd, _claim_digest))
    if not _claim_bound:
        return []

    props = []
    if _verdient("ed25519-signature"):
        props.append("PROOFBUNDLE_SIGNATURE_VALID")
    if _verdient("merkle-inclusion"):
        props.append("PROOFBUNDLE_RECEIPT_UNCHANGED")
    if verdikt:
        props.append("PROOFBUNDLE_THRESHOLD_MET")
    if claim.get("samples"):
        props.append("PROOFBUNDLE_SAMPLE_ROOT_VALID")
    if prereg_verified and claim.get("prereg_sha256"):
        props.append("PROOFBUNDLE_PREREG_BOUND")
    if anchor_verified:
        props.append("PROOFBUNDLE_ANCHOR_VALID")
    return props


@_ein_stand(aussen={"signer": "signierer"}, fehler=(BundleFormatError, SwitchTypeError))
def export_svr_dsse(bundle: dict, signer, *, time_created: Optional[str] = None,
                    policy: Optional[dict] = None, prereg_verified: bool = False,
                    anchor_verified: bool = False, keyid: Optional[str] = None,
                    content_root_alg: str = CONTENT_ROOT_ALG) -> dict:
    """Emit an in-toto SVR (svr/v0.1) for a receipt — after a real, passing signature/merkle/threshold
    verification (done here).

    Refuses (fail-closed) if the receipt is not a valid eval receipt, does not cryptographically verify,
    OR did not pass its threshold. SVR carries only PASSING property strings; there is no FAILED form
    (that would be a VSA with a PASSED|FAILED verdict — deliberately NOT implemented here, see docs). The
    subject is the receipt digest; no secrets ever enter the statement.

    **Caller-attested properties (No-Overclaim, 6-lens review):** `prereg_verified` / `anchor_verified`
    are NOT verified by this function — it does not call `anchors.verify_anchors()`. If you pass them, the
    signed SVR asserts `PROOFBUNDLE_PREREG_BOUND` / `PROOFBUNDLE_ANCHOR_VALID` on your word; run a real
    offline anchor verification first, or leave them False. Each flag must be True or False; any other
    value, the string "false" among them, is a :class:`~proofbundle.errors.SwitchTypeError` (round 9,
    R-B4; `_membership.require_switch`).

    ``time_created`` and ``keyid`` must be strings or None and ``content_root_alg`` a string, and a
    value the serializer cannot write is a BundleFormatError (round 9, `_signed_body_refusal`)."""
    from . import dsse  # noqa: PLC0415
    from .bundle import recompute_merkle_root_b64, verify_bundle  # noqa: PLC0415
    from .errors import ProofBundleError  # noqa: PLC0415
    from .evalclaim import _eine_lesung, decode_eval_claim  # noqa: PLC0415

    # THE BUNDLE IS READ ONCE (lens run 8, the sweep of finding B; named as not checked by the lens):
    # the claim was decoded from one read, the signature verified over a second and the subject root
    # taken from a third. A path is loaded once, a dict is copied from its storage, and every step
    # below reads that one value.
    content_root_alg = _alg_once(content_root_alg)
    # A path by its own type and as its characters: `isinstance` reads a caller's `__class__`, and a
    # `str` subclass's own `__fspath__` would be the caller's code.
    if issubclass(type(bundle), str):
        from .bundle import load_bundle  # noqa: PLC0415
        try:
            bundle = load_bundle(str.__str__(bundle))
        except (ProofBundleError, OSError, ValueError, TypeError) as exc:
            # the answer `decode_eval_claim` gives for a path it cannot load
            raise BundleFormatError("SVR export needs a valid, issuer-bound eval receipt") from exc
    elif issubclass(type(bundle), dict):   # its own type: `isinstance` reads a caller's `__class__`
        from ._plain_value import plain_json  # noqa: PLC0415
        bundle = plain_json(bundle, what="the bundle", error=BundleFormatError)
    try:
        # ONE READING (round 11, class A): decode, verify_bundle and recompute_merkle_root_b64 below each
        # read the bundle, and each read the caller's object. Measured at fa555f13 with a dict subclass
        # answering another receipt's `merkle` from its third read on: the SVR was signed with a subject
        # binding that other receipt's root. All three read the one plain copy now (a path is loaded once).
        bundle = _eine_lesung(bundle)
        claim = decode_eval_claim(bundle)
    except ProofBundleError as exc:   # a non-receipt / malformed bundle → clean fail-closed, not a raw error
        raise BundleFormatError(f"SVR export needs a valid eval receipt ({exc})") from exc
    if claim is None:
        raise BundleFormatError("SVR export needs a valid, issuer-bound eval receipt")
    # BEFORE ANYTHING IS SIGNED. The receipt verified under the section 4a profile, which is right for
    # a verifier and wrong for a statement proofbundle signs: PROOFBUNDLE_SIGNATURE_VALID under a
    # small-order key would attest a signature nobody made.
    _refuse_to_vouch_for_a_key_nobody_holds(claim, "refusing to emit SVR")
    # The claim is the one decode parsed. The caller's other arguments go into the signed statement,
    # so each is read once, as its plain copy, like the other exporters' (round 8): `policy` was
    # written by the legacy serializer through a dict subclass's own `items()`.
    wo = "export_svr_dsse"
    time_created = _eigener_text(time_created, wo, "time_created")
    policy = _eigen(policy, wo, "policy")
    prereg_verified = _eigene_flagge(prereg_verified, "prereg_verified")
    anchor_verified = _eigene_flagge(anchor_verified, "anchor_verified")
    keyid = _eigener_text(keyid, wo, "keyid")
    content_root_alg = _eigener_pflichttext(content_root_alg, wo, "content_root_alg")
    result = verify_bundle(bundle)
    if not result.ok:
        raise BundleFormatError(
            "refusing to emit SVR: the receipt does not verify — an SVR carries only passing properties "
            "and has no FAILED form (a VSA would be the PASSED|FAILED format)")
    if not claim.get("passed"):
        raise BundleFormatError(
            "refusing to emit SVR: the eval did not pass its threshold — SVR summarizes a PASS, a failed "
            "eval has no positive summary")
    props = svr_properties(result, claim, prereg_verified=prereg_verified, anchor_verified=anchor_verified)
    subject = resolve_subject("receipt", claim, root_b64=recompute_merkle_root_b64(bundle).get("stated_b64"))
    verifier: dict[str, Any] = {"id": VERIFIER_ID}
    if policy:
        verifier["policy"] = policy
    statement = _declare_content_root_alg({
        "_type": STATEMENT_TYPE,
        "subject": subject,
        "predicateType": SVR_PREDICATE_TYPE,
        "predicate": {
            "verifier": verifier,
            "timeCreated": time_created or _now_rfc3339z(),
            "properties": props,
        },
    }, content_root_alg)
    try:
        body = _serialize_statement(statement, content_root_alg)
    except (CanonicalizerUnavailable, BundleFormatError):
        raise
    except (ProofBundleError, ValueError, RecursionError) as exc:
        raise _signed_body_refusal(wo, exc) from exc
    return dsse.sign_envelope(body, signer, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE, keyid=keyid)


@_ein_stand
def classify_svr_predicate_shape(statement: Any) -> tuple[bool, str]:
    """Structural check of an SVR Statement's predicate — the shape every consumer dereferences.

    RT-06 (deep gate 2026-09-05, L3-600-06): a VALIDLY SIGNED SVR whose ``predicate`` was a list, or whose
    ``properties`` was an int, made ``proofbundle svr --verify`` print ``[PASS] SVR attestation`` and then
    crash on the dereference. The signature proves who signed the bytes; it says nothing about whether
    the bytes have the shape the consumer is about to walk. So the shape is checked HERE, as part of the
    library verdict, and a consumer never has to guess. Returns ``(ok, detail)``; ``detail`` is empty
    when ok. Deliberately narrow: only what svr/v0.1 declares (predicate object, ``properties`` a list of
    strings, ``verifier`` an object when present, ``timeCreated`` a string when present).

    NAMED ``classify_`` ON PURPOSE (2026-09-05, after the never-raise family property reported it): this
    function takes UNTRUSTED input (a statement out of a signed envelope) and must JUDGE rather than crash,
    so it belongs in the never-raise denominator — and the ``classify_`` family is how that denominator is
    built. Widening the allowlist by one bespoke name would have put it beside the property instead of
    under it; the family test now fuzzes this function like every sibling.

    The statement is read once, into the plain copy of what it stores (round 12)."""
    from .canonical import _pruefkopie  # noqa: PLC0415
    try:
        statement = _pruefkopie(statement)
    except ValueError as exc:
        return False, f"statement is not a JSON object: {exc}"
    if not isinstance(statement, dict):
        return False, "statement is not a JSON object"
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        return False, f"SVR predicate must be an object, got {type(predicate).__name__}"
    props = predicate.get("properties")
    if not isinstance(props, list):
        return False, f"SVR predicate.properties must be a list of strings, got {type(props).__name__}"
    if not all(isinstance(p, str) for p in props):
        return False, "SVR predicate.properties must contain strings only"
    if "verifier" in predicate and not isinstance(predicate["verifier"], dict):
        return False, "SVR predicate.verifier must be an object"
    if "timeCreated" in predicate and not isinstance(predicate["timeCreated"], str):
        return False, "SVR predicate.timeCreated must be a string"
    return True, ""


@_ein_stand(fehler=BundleFormatError)
def verify_svr_dsse(envelope: dict, public_key: bytes, *,
                    expected_predicate_type: str = SVR_PREDICATE_TYPE) -> dict:
    """Verify a DSSE-signed SVR attestation. Returns {ok, statement, predicate_type, predicate_type_ok,
    content_root_alg, content_root_ok, content_root_detail}. `ok` requires the signature, the canonical
    contentRootAlg (absent ⇒ legacy; ADR 0002), AND the statement's `predicateType` == the SVR type
    (WP-I1: predicate-confusion defense — a swapped eval-result/test-result envelope was accepted as an
    SVR because the type was only returned). Pass `expected_predicate_type=None` to opt out. It must
    be a string or None, and the envelope is read once, as for `verify_intoto_dsse`."""
    from . import dsse  # noqa: PLC0415
    from .errors import ProofBundleError  # noqa: PLC0415

    erwartet = _eigener_text(expected_predicate_type, "verify_svr_dsse", "expected_predicate_type")
    try:
        # RE-GATE never-raise (mirror verify_intoto_dsse): crypto + load + budget + parse inside the guard;
        # a wide/oversized/dup-key/malformed untrusted envelope yields a fail-closed verdict, never a raw
        # exception out of this dict-returning verify surface.
        ok, body = dsse._verify_and_load(envelope, public_key, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE)
        statement = loads_strict(body.decode("utf-8"))   # WP-C1: duplicate keys rejected fail-closed
    except (ProofBundleError, ValueError, UnicodeDecodeError) as exc:
        return _intoto_verify_result(False, False, None, None,
                                     f"DSSE payload rejected (fail-closed): {exc}",
                                     erwartet)
    binding_ok, alg, detail = _content_root_binding(statement, body)
    res = _intoto_verify_result(ok, binding_ok, statement, alg, detail, erwartet)
    # RT-06 (L3-600-06): the predicate SHAPE is part of the verdict. A signed statement whose predicate
    # is not what svr/v0.1 declares is not an SVR that verified — ``ok`` stays False and the reason is
    # named, so no consumer prints PASS and then walks a list that is an int.
    shape_ok, shape_detail = classify_svr_predicate_shape(statement)
    res["predicate_shape_ok"] = shape_ok
    if not shape_ok:
        res["ok"] = False
        res["content_root_detail"] = (
            (res["content_root_detail"] + "; " if res["content_root_detail"] else "") + shape_detail)
    return res
