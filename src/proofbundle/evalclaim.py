"""Eval receipts (v0.4): sign + Merkle-anchor a canonical eval CLAIM.

A receipt is tamper-evident signed evidence of exactly one thing — *suite S scored `comparator` threshold
T, passed=…* — carrying only SALTED commitments to the model and dataset identifiers,
never the weights, the data, or the plaintext names. A third party verifies the
threshold was met, offline, from one file, without ever seeing the model or dataset.

Honest scope (see EVAL_CLAIM.md): the receipt proves `passed` against `threshold`
and hides the model/dataset via salted commitments. It does NOT prove the evaluation
itself was well designed or that the suite measures what it claims — those are human
judgements. What it removes is the need to simply *trust the number*.

Layering: the claim payload is canonicalized with RFC 8785 JCS **only on the emit
path** (a lazy dependency). The verify path (`decode_eval_claim`) never canonicalizes —
it checks the exact stored bytes that `verify_bundle` already authenticated — so the
verifier stays dependency-free (cryptography + stdlib only).
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import unicodedata
from typing import Any, Optional, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .bundle import SCHEMA as BUNDLE_SCHEMA, _verify_bundle, load_bundle
from .emit import emit_bundle
from .budget import render_keys_safe, render_safe
from .canonical import _ein_stand, _plain_for_jcs, _type_name, _zeichen_von
from .errors import BundleFormatError, ProofBundleError
from ._wire_b64 import decode_b64, decode_b64url
from ._membership import is_bool, is_member
from ._strict_json import enforce_structural_budget

EVAL_CLAIM_SCHEMA = "proofbundle/eval-claim/v0.1"
COMMIT_ALG = "sha256-salted-v1"
_COMPARATORS = {">=", ">", "<=", "<"}
_MAX_SAFE_INT = 2 ** 53 - 1
# 2**53 - 1 is the largest magnitude with 53 bits, so |v| > 2**53 - 1 exactly when v has more bits.
_SAFE_INT_BITS = 53
# The published eval-claim schema's decimal pattern for threshold/score (no exponent, no sign+, no spaces).
_DECIMAL_RE = re.compile(r"\A-?[0-9]+(\.[0-9]+)?\Z")
_COMMIT_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")   # schema: model_id_commit / dataset_id_commit  # \A..\Z (not ^..$): $ matches before a trailing newline
# Assurance level (v1.1): how much a PASS is worth. Signed into the claim (tamper-evident + bound to the
# issuer, so a third party cannot alter it) — but issuer-DECLARED: a dishonest issuer can sign a higher level,
# the signature attributes that claim to them, it does not make it true. Ordered weakest→strongest. Default
# self_attested — the 1.0 integrations emit self-attested, and claiming more would be dishonest.
ASSURANCE_LEVELS = ("self_attested", "third_party", "reproduced", "enclave_attested")
DEFAULT_ASSURANCE = "self_attested"
# The exact key set of an eval claim; decode/validate reject anything else.
_REQUIRED = {"schema", "suite", "suite_version", "metric", "comparator", "threshold",
             "passed", "n", "model_id_commit", "dataset_id_commit", "commit_alg", "issuer", "timestamp",
             "assurance_level"}
_OPTIONAL = {"context_binding", "ci95", "multiple_testing", "prereg_sha256", "provenance", "samples",
             "evaluation_card_sha256"}
# The schema's type for the fields no older check reached (R-B1). Required and optional alike: a
# present field is checked even when its value is null, because the schema types it and null is
# none of those types. `_claim_violation` reads these.
_COMMITMENT_FIELDS = ("model_id_commit", "dataset_id_commit")
_STRING_FIELDS = ("suite_version", "timestamp", "context_binding", "multiple_testing",
                  "prereg_sha256", "evaluation_card_sha256")
_OBJECT_FIELDS = ("provenance", "samples")

__all__ = [
    "EVAL_CLAIM_SCHEMA", "COMMIT_ALG", "ASSURANCE_LEVELS", "canonicalize", "build_eval_claim",
    "emit_eval_receipt", "decode_eval_claim", "salted_commit", "issuer_fingerprint",
    "claim_warnings", "verify_commitment", "check_freshness", "sd_jwt_hidden_count",
    "eval_evidence_class", "SCORE_EVIDENCE_CLASSES", "EXACT_SCORE_VERIFIED",
    "THRESHOLD_VERDICT_VERIFIED", "SCORE_COMMITMENT_PRESENT", "SCORE_WITHHELD",
    "METHODOLOGY_NOT_EVALUATED", "enclave_assurance_proven",
    "classify_eval_claim", "CLAIM_VALID", "CLAIM_REFUSED_UNKNOWN_SCHEMA", "CLAIM_INVALID",
]

# R2 of the receipt-envelope profile: a refusal is a SEPARATE outcome, not `invalid`. A consumer must
# be able to tell "this receipt is invalid" from "I cannot judge this receipt". `decode_eval_claim`
# returns None for BOTH — its documented contract, relied on by callers, and changing it would be a
# breaking SemVer step. `classify_eval_claim` is the ADDITIVE way to get the distinction: new
# function, no existing caller affected, released contract untouched.
CLAIM_VALID = "valid"
CLAIM_REFUSED_UNKNOWN_SCHEMA = "refused_unknown_schema"
CLAIM_INVALID = "invalid"


class EvalClaimError(ValueError):
    """Raised for a malformed eval claim (float in payload, non-NFC string, unsafe int, …)."""


@_ein_stand(aussen={"signer": "signierer"})
def issuer_fingerprint(signer: Ed25519PrivateKey) -> str:
    """The `issuer` field value: ed25519:<base64 of the 32-byte raw public key>."""
    raw = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return "ed25519:" + base64.b64encode(raw).decode("ascii")


def _issuer_key_weakness(issuer) -> Optional[str]:
    """Why the key an `issuer` value names cannot stand as a trusted Ed25519 key, or None.

    The ONE reading of the issuer format for everything that judges it: `show-eval --expect-issuer`
    and the exporters in `intoto` that sign a statement over a claim. The rule itself is the shared
    `signature.ed25519_trust_anchor_weakness`. A value that is not `ed25519:` plus the canonical base64
    of exactly 32 bytes names no key and is None: it can match nothing and vouches for nothing.

    The issuer is read once, as the plain text it holds (`signature.plain_text`, lens run 7 at
    75c3aa48, the sweep of F2): the prefix test, the slice and the decoder ran the `startswith`,
    `__getitem__` and `encode` of a `str` subclass, which could answer for a real key while the claim
    holds the identity point."""
    from .signature import ed25519_trust_anchor_weakness, plain_text  # noqa: PLC0415
    text = plain_text(issuer)
    if text is None or not text.startswith("ed25519:"):
        return None
    try:
        raw = decode_b64(text[len("ed25519:"):])
    except (ValueError, TypeError):
        return None
    if len(raw) != 32:
        return None
    return ed25519_trust_anchor_weakness(raw)


@_ein_stand
def salted_commit(identifier: str, salt: bytes) -> str:
    """Salted commitment to an identifier: sha256:<hex> over salt || utf8(identifier).

    The salt (>=16 bytes, high entropy) stays with the issuer and is NEVER in the payload,
    so the identifier cannot be recovered from the commitment — not even via a rainbow table
    over known model names like gpt-4o.
    """
    # Salt and identifier are read once (lens run 8, the sweep of finding B): the length check asked the
    # caller's `__len__` while the hash read the salt through its `__add__`, so a salt could pass as 16
    # bytes and commit as none. The stored bytes are checked and hashed.
    from .signature import plain_bytes, plain_text  # noqa: PLC0415
    salt_bytes = plain_bytes(salt)
    if salt_bytes is None or len(salt_bytes) < 16:
        raise EvalClaimError("commitment salt must be at least 16 bytes")
    ident = plain_text(identifier)
    if ident is None:
        raise EvalClaimError("the committed identifier must be a string")
    return "sha256:" + hashlib.sha256(salt_bytes + ident.encode("utf-8")).hexdigest()


def _is_unsafe_int(value) -> bool:
    """True for an integer outside the IEEE-754 safe range, that is beyond +-(2**53-1).

    THE ONE TEST for that range. The emit profile (`_reject_non_jcs`) and the claim rule
    (`_claim_violation`, through `_first_unsafe_integer`) both ask this function. Until 6.2.0 only
    the emit profile asked, so `decode_eval_claim` accepted `provenance={"run_attempts": 2**53}`
    while `emit_eval_receipt` refused it, although EVAL_CLAIM.md section 4 names the range for the
    claim and not for one of its two readers.

    The type asked is the object's own, not ``__class__``: an object whose ``__class__`` claims
    int raised a raw TypeError from ``abs`` here (measured at 93b3c6f5; on main 1e95b197 from the
    same test inside the profile walk).

    The magnitude is read with ``int.bit_length``, the base method, and not with ``abs()``, which
    calls the subclass's own ``__abs__`` (round 8, lens run 6 at c8205c18: an int subclass whose
    ``__abs__`` raised KeyError escaped ``canonicalize`` and ``emit_eval_receipt`` as that KeyError).
    ``bit_length`` counts the bits of the magnitude, so the test is the same range.
    """
    typ = type(value)
    return (issubclass(typ, int) and not issubclass(typ, bool)
            and int.bit_length(value) > _SAFE_INT_BITS)


def _first_unsafe_integer(value) -> Optional[int]:
    """The first integer outside the safe range anywhere inside `value`, or None.

    Iterative rather than recursive, and it visits each container once, so a deep or a cyclic
    Python object handed to the emitter cannot make the claim rule raise. On the verify path the
    strict parser has already bounded depth and size.

    A container is read by its stored contents, as `canonical._plain_for_jcs` copies it for the
    serializer, and its type is its own, not ``__class__``. Measured at 93b3c6f5: a list subclass
    whose ``__iter__`` showed nothing hid 2**60 from this walk, and an object whose ``__class__``
    claims dict raised a raw AttributeError here.
    """
    stapel: list = [value]
    gesehen: set = set()
    while stapel:
        wert = stapel.pop()
        if _is_unsafe_int(wert):
            return wert
        typ = type(wert)
        if issubclass(typ, dict) or issubclass(typ, list) or issubclass(typ, tuple):
            if id(wert) in gesehen:
                continue
            gesehen.add(id(wert))
            stapel.extend(dict.values(wert) if issubclass(typ, dict)
                          else list.__iter__(wert) if issubclass(typ, list) else tuple.__iter__(wert))
    return None


def _reject_non_jcs(value) -> None:
    """Reject values that RFC 8785 / this profile forbids in a claim (`_reject_non_jcs_walk`).

    A value nested deeper than the interpreter recurses is the typed refusal `_jcs_bytes` gives for
    the same depth, not a RecursionError. Measured at 5a21b199 and on main 1e95b197: `canonicalize`
    raised a bare RecursionError for a provenance of 995 and of 5000 nested lists, from the walk
    below, which runs before the serializer. `emit_eval_receipt` raised it on main only; at 5a21b199
    `_claim_read_back` already turned it into this refusal."""
    try:
        _reject_non_jcs_walk(value)
    except RecursionError as e:
        raise EvalClaimError("canonicalization failed: the claim nests too deep to serialize") from e


def _reject_non_jcs_walk(value) -> None:
    """Recursively reject values that RFC 8785 / this profile forbids in a claim.

    It judges what the serializer writes: a container by its stored contents and a string by its
    characters, the reading of `canonical._plain_for_jcs`, and every type by the object's own type,
    not ``__class__``. Measured at 93b3c6f5 and on main 1e95b197 (where this walk is
    `_reject_non_jcs`): `canonicalize` wrote a float held by a dict subclass whose ``values()``
    showed nothing, although this profile forbids floats, and objects whose ``__class__`` claims
    dict, str or int raised a raw AttributeError or TypeError.
    Each type is asked with its own `issubclass` call, not a tuple of types, which would cost a level
    of recursion depth (see `canonical._plain_value`)."""
    typ = type(value)
    if issubclass(typ, bool):
        return
    if issubclass(typ, float):
        raise EvalClaimError("float values are forbidden; use a decimal STRING (e.g. \"0.80\")")
    if issubclass(typ, int):
        if _is_unsafe_int(value):
            raise EvalClaimError(
                f"integer {render_safe(value)} exceeds the IEEE-754 safe range (2**53-1)")
        return
    if issubclass(typ, str):
        zeichen = str.__str__(value)
        if unicodedata.normalize("NFC", zeichen) != zeichen:
            raise EvalClaimError("string is not NFC-normalized")
        return
    if value is None:
        return
    if issubclass(typ, dict):
        for v in list(dict.values(value)):
            _reject_non_jcs_walk(v)
        return
    if issubclass(typ, list) or issubclass(typ, tuple):
        for v in list(list.__iter__(value) if issubclass(typ, list) else tuple.__iter__(value)):
            _reject_non_jcs_walk(v)
        return
    raise EvalClaimError(f"unsupported value type {_type_name(typ)}")


@_ein_stand
def canonicalize(claim: dict) -> bytes:
    """RFC 8785 JCS canonical bytes of a claim — EMIT PATH ONLY.

    Enforces the profile before serializing: no Python float, NFC strings, safe-range ints.
    Duplicate keys cannot exist in a Python dict; when parsing claim JSON from text, use
    `load_claim_text` which rejects duplicate keys. Uses the rfc8785 library (lazy import)
    for the UTF-16 code-unit key sort + compact UTF-8 serialization.

    The claim is read ONCE, from its storage (lens run 8 at fddc00f4, the sweep of findings B and D):
    the profile check walked a dict subclass's `values()` and an int subclass's `__abs__`, and the
    canonicaliser wrote what its own reads returned, so a claim could pass the check as one value and
    be serialised as another. The plain copy is what is checked and what is written.

    The copy is `_plain_value.plain_json`, and the JCS copy of it (`canonical._plain_for_jcs`); the
    profile and the serializer read only that copy (round 8). A value that is not a JSON type is
    refused there, and so is a subclass of ``int`` or ``float``. Measured at c8205c18: an int subclass
    whose ``__int__`` returns -1 and which holds 5 was written as -1, and one whose ``__abs__`` raised
    escaped as that exception.
    """
    from ._plain_value import plain_json  # noqa: PLC0415
    claim = plain_json(claim, what="the claim", error=EvalClaimError)
    claim = _plain_for_jcs(claim, EvalClaimError)
    _reject_non_jcs(claim)
    return _jcs_bytes(claim)


def _jcs_bytes(claim) -> bytes:
    """RFC 8785 bytes of `claim` WITHOUT the emit profile (NFC strings, no floats).

    `canonicalize` is this plus the profile. The exporters in `intoto` and `sdjwt_issue` read a claim
    back through this function: they export what `decode_eval_claim` accepts, and the verify path
    does not hold a claim to the emit profile.

    The serializer gets a plain copy (`canonical._plain_for_jcs`): every key and every string a
    plain `str`. Measured at 6893586f: a `str` subclass key in `provenance` whose `encode` raised
    LookupError or returned an int escaped the emitter and every producer as a raw exception,
    because rfc8785 sorts keys through that method and this function maps only named exception
    types. The copy removes the method from the reading instead of widening the except.
    """
    try:
        import rfc8785  # noqa: PLC0415 — lazy: only the emit path pulls the JCS dependency
    except ImportError as e:
        raise EvalClaimError(
            "emitting eval receipts needs an RFC 8785 canonicalizer — install with: "
            "pip install \"proofbundle[eval]\"") from e
    try:
        return rfc8785.dumps(_plain_for_jcs(claim, rfc8785.CanonicalizationError))
    except (rfc8785.FloatDomainError, rfc8785.IntegerDomainError, rfc8785.CanonicalizationError) as e:
        raise EvalClaimError(f"canonicalization failed: {e}") from e
    except RecursionError as e:
        raise EvalClaimError("canonicalization failed: the claim nests too deep to serialize") from e
    except (UnicodeEncodeError, UnicodeDecodeError) as e:
        # rfc8785 turns a lone surrogate in a string VALUE into CanonicalizationError, but it sorts
        # object KEYS by encoding them as UTF-16, and that step raises a raw UnicodeEncodeError.
        # Measured at 835df85b with `provenance={"\ud800": 1}`: decode refused the claim, while
        # `emit_eval_receipt` and every exporter raised UnicodeEncodeError instead of their typed
        # refusal. A string that cannot be encoded is the same defect wherever it sits.
        raise EvalClaimError(f"canonicalization failed: a string cannot be encoded ({e.reason})") from e


@_ein_stand
def load_claim_text(text: str) -> dict:
    """Parse claim JSON text, rejecting duplicate keys (JCS forbids them).

    Delegates to the shared strict parser (:func:`proofbundle._strict_json.loads_strict`) so this
    path has the SAME robustness as every other verify path: a duplicate key and a pathologically
    deep nesting (``RecursionError``, CWE-674) both become a clean malformed-input error, never a
    raw traceback. Re-raised as :class:`EvalClaimError` (a ``ValueError``) so existing
    ``except (ValueError, EvalClaimError)`` handling at the call sites — including the batch
    verifier ``hf_evals.verify_eval_results_entry`` — stays correct and never crashes."""
    from ._strict_json import loads_strict  # noqa: PLC0415
    if not isinstance(text, (str, bytes, bytearray)):
        # adversarial re-audit round 8: a non-str/bytes primary makes loads_strict's len(text)/json.loads(text)
        # raise a raw TypeError BEFORE any typed path — this public load_ primitive's docstring promises
        # "never a raw traceback", so a type-confused input maps to the documented EvalClaimError.
        raise EvalClaimError(f"claim text must be str or bytes, got {type(text).__name__} (malformed)")
    try:
        claim = loads_strict(text)
    except ProofBundleError as e:
        # adversarial re-audit round 3: catch the BASE ProofBundleError — loads_strict raises a SIBLING
        # BudgetExceeded (over-width/over-node input) NOT a BundleFormatError, which `except BundleFormatError`
        # let escape as a raw traceback. Both map to the DOCUMENTED EvalClaimError (a ValueError).
        raise EvalClaimError(str(e)) from e
    # THE RETURN TYPE IS PART OF THE PROMISE, not only the argument type. The signature says
    # `-> dict` and the docstring says "never a raw traceback", but valid JSON is also `[]`, `"x"`
    # and `1` — and a caller that does `claim.get(...)` on those gets an AttributeError, which is
    # in no call site's except list. Measured 2026-09-19 at the head 79f66a2: a correctly signed
    # bundle (verify_bundle.ok True, Merkle and signature intact) whose payload is `[]` made
    # `decode_eval_claim` raise instead of returning None, against its own documented contract.
    #
    # THE SAME CLASS WAS CLOSED ONCE BEFORE, on the INPUT side (round 8, the isinstance check
    # above). Closing it on the input and leaving it on the output is how a repaired class comes
    # back through the other door. `EvalClaimError` is a ValueError, so every existing
    # `except (ValueError, EvalClaimError)` at the call sites — decode_eval_claim,
    # classify_eval_claim, the CLI and hf_evals — turns this into the documented outcome without
    # a single caller change.
    if not isinstance(claim, dict):
        raise EvalClaimError(
            f"claim must be a JSON object, got {type(claim).__name__} (malformed)")
    return claim


@_ein_stand
def build_eval_claim(*, suite: str, suite_version: str, metric: str, comparator: str,
                     threshold: str, score: str, n: int, model_id: str, dataset_id: str,
                     issuer: str, timestamp: str, context_binding: Optional[str] = None,
                     ci95: Optional[Sequence[str]] = None, multiple_testing: Optional[str] = None,
                     prereg_sha256: Optional[str] = None, provenance: Optional[dict] = None,
                     assurance_level: str = DEFAULT_ASSURANCE,
                     samples: Optional[dict] = None,
                     evaluation_card_sha256: Optional[str] = None,
                     model_salt: Optional[bytes] = None, dataset_salt: Optional[bytes] = None):
    """Build a valid eval claim from raw values. Computes `passed` ITSELF from the comparator
    (never trusts the caller), creates salted commitments, and returns (claim, salts) with the
    salts SEPARATE (never in the payload).

    threshold/score are decimal STRINGS (never floats). Returns:
        (claim: dict, salts: {"model_salt": bytes, "dataset_salt": bytes})

    EVERY VALUE THAT IS CHECKED HERE IS READ ONCE, and the claim is built from those reads and copied
    from storage before its last check (lens run 8 at fddc00f4, the sweep of finding B). The comparator
    and the assurance level were checked through the caller's `__eq__`/`__hash__`, `n` through its
    comparisons, the samples through `__iter__`, `get` and `__getitem__`; what a caller's class answered
    there could differ from what it stores and from what the receipt then signs.

    ``comparator`` and ``assurance_level`` are compared by their characters, and those characters
    are what the claim carries (round 10); any other value is refused as before. Measured at
    493c2f86: a ``str`` subclass holding "==" whose ``__eq__`` and ``__hash__`` claimed ">=" passed
    the comparator check and built a claim with comparator "==", and one holding "bogus" passed the
    ``assurance_level`` check.
    """
    from ._plain_value import plain_int, plain_json, plain_list  # noqa: PLC0415
    from .signature import plain_text  # noqa: PLC0415
    comparator_text = plain_text(comparator)
    if comparator_text is None or not is_member(comparator_text, _COMPARATORS):
        raise EvalClaimError(f"comparator must be one of {sorted(_COMPARATORS)}")
    comparator = comparator_text
    level_text = plain_text(assurance_level)
    if level_text is None or level_text not in ASSURANCE_LEVELS:
        raise EvalClaimError(f"assurance_level must be one of {list(ASSURANCE_LEVELS)}")
    assurance_level = level_text
    # threshold/score must match the PUBLISHED schema's decimal pattern exactly — reject "1e2",
    # "Infinity", "+5", " 5 " etc. that Decimal() would accept but jsonschema rejects (schema-conformance).
    gelesen = []
    for name, val in (("threshold", threshold), ("score", score)):
        text = plain_text(val)
        if text is None:
            raise EvalClaimError(f"{name} must be a decimal STRING, not {type(val).__name__}")
        if not _DECIMAL_RE.match(text):
            raise EvalClaimError(f"{name} must be a plain decimal string (^-?[0-9]+(\\.[0-9]+)?$), got {text!r}")
        gelesen.append(text)
    threshold, score = gelesen
    if plain_int(n) is None or n < 0 or n > _MAX_SAFE_INT:
        raise EvalClaimError(f"n must be a non-negative integer <= 2**53-1, got {n!r}")
    passed = _passed_by(score, comparator, threshold)
    # the salts are read once as their stored bytes: the commitment is taken over them, and they are
    # what is handed back beside the claim (lens run 8, the sweep of finding B)
    from .signature import plain_bytes  # noqa: PLC0415
    m_salt = plain_bytes(model_salt) if model_salt is not None else os.urandom(16)
    d_salt = plain_bytes(dataset_salt) if dataset_salt is not None else os.urandom(16)
    if m_salt is None or d_salt is None:
        raise EvalClaimError("commitment salt must be at least 16 bytes")
    claim = {
        "schema": EVAL_CLAIM_SCHEMA, "suite": suite, "suite_version": suite_version,
        "metric": metric, "comparator": comparator, "threshold": threshold, "passed": passed,
        "n": n, "model_id_commit": salted_commit(model_id, m_salt),
        "dataset_id_commit": salted_commit(dataset_id, d_salt), "commit_alg": COMMIT_ALG,
        "issuer": issuer, "timestamp": timestamp, "assurance_level": assurance_level,
    }
    if context_binding is not None:
        claim["context_binding"] = context_binding
    if ci95 is not None:
        # the list read once from storage, a text entry as the text it holds; any other entry is
        # converted once with `str`, as before
        stored_ci = plain_list(ci95)
        claim["ci95"] = [plain_text(x) if plain_text(x) is not None else str(x)
                         for x in (stored_ci if stored_ci is not None else ci95)]
        # The claim rule judges the interval HERE, with its own reason, and the builder does not
        # reformat a number. Measured on 126ed1dc: `ci95=[1e-05, 0.5]` became ["1e-05", "0.5"] and
        # `[nan, inf]` became ["nan", "inf"]; the emitter signed both, and since R-B1 it refuses
        # both. Turning a float into a plain decimal here would be one more float formatter beside
        # the adapters' own, which already disagree (adapters/lm_eval.py and adapters/inspect_ai.py
        # always round to 12 places, adapters/eee.py keeps repr() unless it has an exponent), and
        # the signature types `ci95` as decimal
        # strings, like `threshold` and `score`, whose floats this builder already refuses. What
        # built a signable claim before still does: a decimal string, an int, and a float whose
        # `str()` is a plain decimal (0.81) give the same claim as on 126ed1dc.
        reason = _field_violation({"ci95": claim["ci95"]})
        if reason is not None:
            raise EvalClaimError(reason)
    if multiple_testing is not None:
        claim["multiple_testing"] = multiple_testing
    if prereg_sha256 is not None:
        claim["prereg_sha256"] = prereg_sha256
    if evaluation_card_sha256 is not None:
        claim["evaluation_card_sha256"] = evaluation_card_sha256
    if provenance is not None:
        claim["provenance"] = provenance
    if samples is not None and isinstance(samples, dict):
        samples = plain_json(samples, what="samples", error=EvalClaimError)
    if samples is not None:
        # v1.5 per-sample commitment: {"root_b64", "n", "leaf_alg"} from
        # proofbundle.persample.build_sample_tree — the samples root is SIGNED with the claim,
        # so tree-size lies and post-hoc sample swaps are closed at the signature layer
        # (an RFC 6962 inclusion proof constrains n only up to path-shape equivalence).
        if not isinstance(samples, dict) or set(samples) - {"root_b64", "n", "leaf_alg"}:
            raise EvalClaimError("samples must be {root_b64, n, leaf_alg} (see persample module)")
        try:
            root_raw = decode_b64(samples["root_b64"])
        except (KeyError, ValueError, TypeError) as exc:
            raise EvalClaimError("samples.root_b64 must be valid base64") from exc
        if len(root_raw) != 32:
            raise EvalClaimError("samples.root_b64 must decode to a 32-byte SHA-256 root")
        s_n = samples.get("n")
        if isinstance(s_n, bool) or not isinstance(s_n, int) or s_n <= 0:
            raise EvalClaimError("samples.n must be a positive integer")
        if s_n != n:
            raise EvalClaimError(
                f"samples.n ({s_n}) must equal the claim's n ({n}) — the committed tree covers "
                "exactly the samples the aggregate was computed over, no more, no fewer")
        if samples.get("leaf_alg") != "sha256-rfc6962-sdjwt-v1":
            raise EvalClaimError("samples.leaf_alg must be 'sha256-rfc6962-sdjwt-v1'")
        claim["samples"] = {"root_b64": samples["root_b64"], "n": s_n,
                            "leaf_alg": samples["leaf_alg"]}
    # the rest (issuer, timestamp, provenance, ci95…) is copied from storage once, and that copy is
    # what the profile check judges and what is returned for signing
    claim = plain_json(claim, what="the claim", error=EvalClaimError)
    _reject_non_jcs(claim)
    return claim, {"model_salt": m_salt, "dataset_salt": d_salt}


def _claim_violation(claim: dict) -> Optional[str]:
    """Name the first reason the verifier refuses ``claim``, or return None when it accepts it.

    ONE validation for both boundaries. ``decode_eval_claim`` turns a reason into its documented
    refusal, None; ``emit_eval_receipt`` raises it as ``EvalClaimError`` before anything is
    canonicalized or signed. So the package cannot sign a claim its own verifier refuses. Until
    this function existed the checks lived inline in ``decode_eval_claim``, and the emitter ran a
    subset of them: measured at 2290d6c1, ``emit_eval_receipt`` signed 14 of 15 probe claims that
    decode refused (comparator, threshold, passed, n, metric, suite, commit_alg, schema and the
    samples block among them). Two copies of one rule are two promises, and that is what two copies
    had drifted into.

    What stays OUTSIDE, because it is not a property of the claim alone: the issuer binding (the
    claim's ``issuer`` against the key that signed the bundle, which the emitter sets from its
    signer) and ``expected_context`` (the caller's expectation, not the claim's shape).

    Order of the checks: key set and schema first, then the fields in the order the verify boundary
    grew them. Each earlier block's comment in the history of ``decode_eval_claim`` still applies:

    - comparator enum and decimal threshold (release-review CRITICAL): a hand-built claim could
      carry an out-of-enum comparator or a non-finite threshold ("inf") and collapse a downstream
      verdict check into a tautology.
    - assurance_level enum (verify-lens L3, 2026-07-09): the level is printed VERBATIM on the CLI's
      ASSURANCE line, so a value with embedded newlines could forge extra CRYPTO:/POLICY: lines.
    - A-15 (2026-09-19): `passed`, `n` and `metric` typed, because every downstream reader coerces
      instead of checking; `bool("false")` is True. `passed` goes through the shared ``is_bool``
      (R-B4) so the boundary and the public exporters answer the question with one function.
    - Domains (A TYPE IS NOT A DOMAIN): `0 <= n <= 2**53-1` (EVAL_CLAIM.md), minLength 1 on
      `metric` and `suite`, `commit_alg` const. Measured at bfc3f42 against hand-signed claims,
      7 of 7 documented domains were accepted before this block existed.
    - R-B1 (6.2.0): both commitments in the form ``salted_commit`` produces
      (``sha256:<64 lowercase hex>``, ``_COMMIT_RE``), the string type of the six fields in
      ``_STRING_FIELDS``, ``ci95`` as exactly two plain decimal strings, ``provenance`` and
      ``samples`` as JSON objects. A PRESENT optional field is checked even when its value is null:
      the schema types it, and null is none of those types.
    - samples (v1.6 external review, release-review #8): exactly ``{root_b64, n, leaf_alg}``,
      ``leaf_alg`` fixed, ``samples.n`` an int equal to the claim's ``n`` and at least 1 (schema
      minimum), and a root that decodes to 32 bytes.

    - The IEEE-754 safe range (6.2.0, follow-up to R-B1): no integer beyond +-(2**53-1) anywhere in
      the claim, through `_is_unsafe_int`, the same test the emit profile asks. EVAL_CLAIM.md
      section 4 names the range for the claim; until then only the emitter held it, and decode
      accepted `provenance={"run_attempts": 2**53}`.

    Never raises for a dict: every message goes through the bounded renderer, because the values it
    names are untrusted, and the one decoding step (the samples root) is caught and named.

    The checks on single fields live in `_field_violation`, and this function adds the one check a
    single field cannot answer: the key set. The verifiers in `intoto` call `_field_violation` on
    the claim fields a signed predicate carries, so a predicate field is judged by this rule too and
    not by a copy of it.
    """
    # F3 (v1.9.2): the exact key set is a verify-path invariant as much as an emit-side one.
    missing = _REQUIRED - set(claim)
    if missing:
        return f"claim missing required fields: {sorted(missing)}"
    extra = set(claim) - _REQUIRED - _OPTIONAL
    if extra:
        return f"claim has unknown fields: {render_keys_safe(extra)}"
    return _field_violation(claim)


def _passed_by(score: str, comparator: str, threshold: str) -> bool:
    """The verdict a decimal ``score`` earns against ``comparator`` and ``threshold``.

    ONE MAPPING for the three places that recompute ``passed`` from a score: ``build_eval_claim``
    (which computes the verdict it signs), ``eval_evidence_class`` (which checks a signed score
    against the signed verdict) and ``sdjwt_issue.issue_sd_jwt`` (which refuses a disclosed
    ``exact_score`` that contradicts the always-open ``passed``). Each had its own copy of the table
    until the third one was needed. The caller has checked both numbers as plain decimal strings and
    the comparator as one of ``_COMPARATORS``.
    """
    from decimal import Decimal  # noqa: PLC0415
    s, t = Decimal(score), Decimal(threshold)
    return {">=": s >= t, ">": s > t, "<=": s <= t, "<": s < t}[comparator]


def _decimal_violation(name: str, value) -> Optional[str]:
    """Why `value` is not a plain decimal string, or None. The one check behind `threshold` in the
    claim rule and behind the disclosed `exact_score` of `sdjwt_issue.issue_sd_jwt`."""
    if isinstance(value, str) and _DECIMAL_RE.match(value):
        return None
    return f"{name} must be a plain decimal string (^-?[0-9]+(\\.[0-9]+)?$), got {render_safe(value)}"


def _field_violation(claim: dict) -> Optional[str]:
    """Every check of `_claim_violation` that reads a field, applied to the fields PRESENT in `claim`.

    For a whole claim the key-set check in `_claim_violation` runs first, so every required field is
    present here and the presence tests below change nothing. They exist for the second kind of
    caller, which holds only some of a claim's fields: an in-toto predicate carries `claims[]`,
    `sampleSize` and `commitments`, and no `schema` or `issuer`. Absent means no statement about the
    field, never a default in its place. A PRESENT field that is null or of the wrong type is still
    refused, as before.
    """
    if "schema" in claim and claim.get("schema") != EVAL_CLAIM_SCHEMA:
        return f"schema must be {EVAL_CLAIM_SCHEMA!r}, got {render_safe(claim.get('schema'))}"
    if "comparator" in claim and not is_member(claim.get("comparator"), _COMPARATORS):
        return (f"comparator must be one of {sorted(_COMPARATORS)}, "
                f"got {render_safe(claim.get('comparator'))}")
    if "threshold" in claim:
        grund = _decimal_violation("threshold", claim.get("threshold"))
        if grund is not None:
            return grund
    if "assurance_level" in claim and claim.get("assurance_level") not in ASSURANCE_LEVELS:
        return f"assurance_level must be one of {list(ASSURANCE_LEVELS)}"
    if "passed" in claim and not is_bool(claim.get("passed")):
        return f"passed must be a boolean, got {render_safe(claim.get('passed'))}"
    n = claim.get("n")
    if "n" in claim and (isinstance(n, bool) or not isinstance(n, int) or not (0 <= n <= _MAX_SAFE_INT)):
        return f"n must be an integer in 0..2**53-1, got {render_safe(n)}"
    for name in ("metric", "suite"):                 # schema: string, minLength 1
        value = claim.get(name)
        if name in claim and not (isinstance(value, str) and value):
            return f"{name} must be a non-empty string, got {render_safe(value)}"
    if "commit_alg" in claim and claim.get("commit_alg") != COMMIT_ALG:   # schema: const
        return f"commit_alg must be {COMMIT_ALG!r}, got {render_safe(claim.get('commit_alg'))}"
    for name in _COMMITMENT_FIELDS:
        value = claim.get(name)
        if name in claim and not (isinstance(value, str) and _COMMIT_RE.match(value)):
            return (f"{name} must be a salted commitment sha256:<64 lowercase hex>, the form "
                    f"salted_commit produces; got {render_safe(value)}")
    for name in _STRING_FIELDS:
        if name in claim and not isinstance(claim[name], str):
            return f"{name} must be a string, got {render_safe(claim[name])}"
    if "ci95" in claim:
        ci95 = claim["ci95"]
        # A tuple is accepted as an array on the emit path, where a caller hands a Python object and
        # the canonicalizer writes it as one; a decoded payload only ever holds lists.
        if not (isinstance(ci95, (list, tuple)) and len(ci95) == 2
                and all(isinstance(x, str) and _DECIMAL_RE.match(x) for x in ci95)):
            return ("ci95 must be exactly two plain decimal strings (^-?[0-9]+(\\.[0-9]+)?$), "
                    f"got {render_safe(ci95)}")
    for name in _OBJECT_FIELDS:
        if name in claim and not isinstance(claim[name], dict):
            return f"{name} must be a JSON object, got {render_safe(claim[name])}"
    samples = claim.get("samples")
    if samples is not None:
        if set(samples) != {"root_b64", "n", "leaf_alg"}:
            return (f"samples must hold exactly root_b64, n and leaf_alg, "
                    f"got {render_keys_safe(samples)}")
        if samples.get("leaf_alg") != "sha256-rfc6962-sdjwt-v1":
            return ("samples.leaf_alg must be 'sha256-rfc6962-sdjwt-v1', "
                    f"got {render_safe(samples.get('leaf_alg'))}")
        s_n = samples.get("n")
        if isinstance(s_n, bool) or not isinstance(s_n, int) or s_n != n:
            return f"samples.n must be an integer equal to n ({n}), got {render_safe(s_n)}"
        # schema: samples.n minimum 1. The equality above lets n == samples.n == 0 through, and
        # a committed tree over zero samples is not one that build_eval_claim or build_sample_tree
        # makes.
        if s_n < 1:
            return f"samples.n must be at least 1, got {s_n}"
        try:
            root_ok = len(decode_b64(samples["root_b64"])) == 32
        except (ValueError, TypeError):
            root_ok = False
        if not root_ok:
            return ("samples.root_b64 must be standard base64 of a 32-byte root, "
                    f"got {render_safe(samples['root_b64'])}")
    for name, value in claim.items():
        unsafe = _first_unsafe_integer(value)
        if unsafe is not None:
            return (f"{name} holds integer {render_safe(unsafe)}, which exceeds the IEEE-754 "
                    "safe range (2**53-1)")
    return None


def _claim_read_back(claim, *, profile: bool) -> tuple:
    """The claim as a verifier will read it: checked, serialized, parsed back from those bytes, checked
    again. Returns ``(claim_read_back, canonical_bytes)`` or raises ``EvalClaimError``.

    Every producer of signed or digested output from an eval claim goes through here:
    `emit_eval_receipt` with ``profile=True`` (the canonicalization profile of EVAL_CLAIM.md section
    4 on top), and the exporters in `intoto` and `sdjwt_issue` through
    `_verdict.require_eval_claim` with ``profile=False``, because they export what
    `decode_eval_claim` accepts.

    WHY THE SECOND CHECK, on the parsed bytes and not only on the object. The object is what the
    caller hands in; the bytes are what gets signed, and the two can differ. Measured at 62e8bbab:
    an `int` subclass holding 500 whose `__int__` returns -1 passed the check as 500 and was
    serialized as -1, because rfc8785 calls `int()`; a `str` subclass that compares equal to
    anything passed `schema` and `commit_alg` and was serialized as "x" and "md5-plain". The emitter
    signed both claims and `decode_eval_claim` refused both receipts. Checking the parsed bytes
    judges what a verifier will read, and the caller of this function builds its output from the
    parsed claim, so the value checked and the value used are one value.

    The first check stays, before the serializer, so a refusal names the field before the serializer
    meets a float or an unsafe integer and names that instead.

    THE OBJECT HANDED IN IS READ ONCE, into the plain copy (`canonical._plain_for_jcs`), and every
    check, the serializer and the caller of this function see only that copy (round 8). Measured at
    c8205c18, when the first check read the caller's object: an int subclass whose ``__abs__`` or
    comparisons raised, a list subclass whose ``__len__`` raised, a dict subclass whose
    ``__iter__`` raised in ``samples`` and a str subclass whose ``__bool__`` raised each escaped as
    that exception, and an object whose ``__class__`` claims str raised a raw TypeError from the
    decimal pattern in ``threshold``. The copy refuses what is not a JSON type, names where it sits,
    and reads a subclass of ``str``, ``int`` or ``float`` as the value it holds, so the read-back
    below no longer meets an object that serializes as something else.
    """
    claim = _plain_for_jcs(claim, EvalClaimError)
    if type(claim) is not dict:
        raise EvalClaimError(f"claim must be a JSON object, got {type(claim).__name__}")
    reason = _claim_violation(claim)
    if reason is not None:
        raise EvalClaimError(reason)
    try:
        payload = canonicalize(claim) if profile else _jcs_bytes(claim)
    except RecursionError as exc:
        raise EvalClaimError("canonicalization failed: the claim nests too deep to serialize") from exc
    # The resource limits exist only once the claim is serialized. `load_claim_text` is the reader
    # the verify path uses (loads_strict: size, nodes, depth, string length, integer size).
    try:
        read_back = load_claim_text(payload.decode("utf-8"))
    except EvalClaimError as exc:
        raise EvalClaimError(f"the canonical claim exceeds a limit of the verifier: {exc}") from exc
    reason = _claim_violation(read_back)
    if reason is not None:
        raise EvalClaimError(f"{reason} (in the canonical bytes; the object handed in did not "
                             "serialize to what it compared as)")
    if profile:
        # The emit profile on the bytes too, for the same reason as the rule: measured at 835df85b,
        # a `str` subclass whose `__ne__` always answers False passed the NFC test on the object
        # (`normalize(...) != value`) and a decomposed `suite` was signed.
        try:
            _reject_non_jcs(read_back)
        except EvalClaimError as exc:
            raise EvalClaimError(f"{exc} (in the canonical bytes)") from exc
    return read_back, payload


@_ein_stand(aussen={"signer": "signierer"})
def emit_eval_receipt(claim: dict, signer: Ed25519PrivateKey, *, prior_leaves: Sequence[bytes] = (),
                      sd_jwt: Optional[dict] = None) -> dict:
    """Emit a proofbundle/v0.1 bundle whose payload is the canonical eval claim.

    Sets `issuer` to the signer's fingerprint automatically (binding the receipt to the key),
    canonicalizes, and calls emit_bundle. The returned bundle is verified unchanged by verify_bundle.

    Refuses, with ``EvalClaimError`` naming the field, every claim that ``decode_eval_claim`` would
    refuse, through the same ``_claim_violation`` the verifier calls, before anything is
    canonicalized or signed, and again on the canonical bytes it signs. The two normalizations
    above come first and are the only ones: the issuer is this signer's, and a missing
    ``assurance_level`` is ``self_attested``. On top of that the emitter enforces two parts of the
    canonicalization profile (section 4 of EVAL_CLAIM.md) that the verify path does not re-check
    because it never canonicalizes: NFC strings and no floats. The third part, safe-range integers,
    is part of the claim rule since 6.2.0 and holds at both boundaries.

    The claim is read once, into the plain copy (`canonical._plain_for_jcs`), before the two
    normalizations; nothing after reads the caller's object (round 8). ``dict()`` of the caller's
    object read a dict subclass through its own ``keys()`` and ``__getitem__`` and any other mapping
    or iterable through its own methods. ``dict()`` now runs on the copy, so a claim given as a list
    or a tuple of ``[key, value]`` pairs is read as before, and a mapping that is not a JSON object
    (a ``UserDict``, a ``MappingProxyType``) and an iterator, a generator or a dict view of pairs
    are refused as not JSON values. A shape ``dict()`` cannot
    read is ``EvalClaimError`` now, where it was a raw TypeError or ValueError.

    THE PAIR FORM REFUSES A DUPLICATE KEY, as the copy does for an object (round 11, lens run 10 at
    fa555f13, finding L9). ``dict()`` keeps the last of two pairs with one key, so ``passed`` False
    then True was signed as True: the caller's input contradicted itself and the emitter chose. Two
    keys whose characters are equal are one JSON key, and ``EvalClaimError`` names it now, whatever
    the order.
    """
    # READ ONCE (lens run 8 at fddc00f4, the sweep of finding B): `dict(claim)` copied the top level
    # only, and the profile check then read nested values and numbers through their own methods while
    # the canonicaliser wrote their storage. The plain copy is what is checked and what is signed.
    # By the claim's own type, not `isinstance`, which reads a caller's `__class__`.
    if issubclass(type(claim), dict):
        from ._plain_value import plain_json  # noqa: PLC0415
        claim = plain_json(claim, what="the claim", error=EvalClaimError)
    claim = _plain_for_jcs(claim, EvalClaimError)
    paare = claim
    try:
        claim = dict(claim)
    except (TypeError, ValueError) as exc:
        raise EvalClaimError(f"claim must be a JSON object, got {type(claim).__name__}") from exc
    if type(paare) is list and len(claim) != len(paare):
        # `dict()` read every item as exactly one key and one value, so fewer keys than items means a
        # key came twice. Only the plain copy is read here, so no code of the caller runs.
        gesehen: set = set()
        doppelt: Any = None
        for schluessel, _ in paare:
            if schluessel in gesehen:
                doppelt = schluessel
                break
            gesehen.add(schluessel)
        raise EvalClaimError(
            f"claim key {render_safe(doppelt)} appears twice in the pair form; JSON has one key for "
            "both, and the emitter does not choose between them")
    claim["issuer"] = issuer_fingerprint(signer)
    # A claim without an explicit assurance_level is self_attested — the weakest, safest default; never
    # silently elevate. (v1.1: keeps pre-1.1 claim JSONs emittable while binding the honest level.)
    claim.setdefault("assurance_level", DEFAULT_ASSURANCE)
    # Measured at 126ed1dc, this function signed `model_id_commit: "sha256:x"`; at 2290d6c1 it still
    # signed 14 of 15 claims the verifier refuses, because it ran only part of the verifier's checks.
    # Now it runs all of them, as one call, before canonicalization, so the reason names the field
    # rather than a float or an integer the canonicalizer happens to meet first; and it runs them
    # again on the canonical bytes it is about to sign (`_claim_read_back`, measured reason there).
    #
    # Resource limits: the verify path reads these exact bytes with load_claim_text (inside
    # `_claim_read_back`) and bounds the bundle's payload_b64 STRING with enforce_structural_budget.
    # Measured at 2290d6c1: this function signed a claim whose provenance nested 70 deep, one
    # holding 250 000 list items, and one whose payload_b64 ran past the 1 000 000-character string
    # bound; decode refused all three. The same two readers run here, so a size the verifier refuses
    # is not signed either.
    _, payload = _claim_read_back(claim, profile=True)
    try:
        enforce_structural_budget({"payload_b64": base64.b64encode(payload).decode("ascii")})
    except ProofBundleError as exc:
        raise EvalClaimError(f"the canonical claim exceeds a limit of the verifier: {exc}") from exc
    return emit_bundle(payload, signer, prior_leaves=prior_leaves, sd_jwt_vc=sd_jwt)


def _eine_lesung(bundle: Any) -> Any:
    """THE ONE READING of a caller's bundle (round 11): a path through ``load_bundle``, anything else
    through the structural budget and the plain copy (`canonical._plain_for_jcs`).

    Everything after reads only what this returns, which nobody else holds. The copy reads what the
    object stores, through the base types' methods, and a ``str`` subclass as the characters it
    holds: no ``__getitem__``, ``get`` or ``__contains__`` of a dict subclass and no ``encode`` of a
    ``str`` subclass runs. The budget comes first, because it bounds the depth the copy recurses
    over, and it reads stored contents too. What the copy refuses (a value that is no JSON value, a
    key that is not a string, two keys with the same characters) is a BundleFormatError, and a tuple
    is read as the array JSON writes it.

    The type is asked of the object's own type, not with ``isinstance``, which reads ``__class__``."""
    if issubclass(type(bundle), str):
        return load_bundle(str.__str__(bundle))
    enforce_structural_budget(bundle)
    return _plain_for_jcs(bundle, BundleFormatError)


def _claim_of_verified(bundle: dict, claim: Any, expected_context: Any) -> Optional[dict]:
    """The checks `decode_eval_claim` makes on a claim parsed from a VERIFIED bundle's payload, or
    None. ``bundle`` is the plain copy that was verified, so the issuer binding reads the key the
    signature was checked under.

    Every check on the claim itself lives in ``_claim_violation``, which the emitter calls too. What
    stays here is what needs the bundle or the caller: the issuer binding and ``expected_context``."""
    # Every check on the claim's own content, the same call the emitter makes. The history of
    # each check (F3, the release-review CRITICAL, L3, A-15, the domains round, R-B1, the v1.6
    # samples invariants) is in the docstring of _claim_violation, next to the check.
    if _claim_violation(claim) is not None:
        return None
    # Issuer binding: the claim's issuer must be the key that signed the bundle. Bundle-side,
    # so it stays here; the emitter satisfies it by setting the issuer from its own signer.
    sig_pub_b64 = bundle["signature"]["public_key_b64"]
    want = "ed25519:" + base64.b64encode(decode_b64(sig_pub_b64)).decode("ascii")
    if claim.get("issuer") != want:
        return None
    if expected_context is not None:
        erwartet = _zeichen_von(expected_context)
        if erwartet is None or claim.get("context_binding") != erwartet:
            return None
    return claim


@_ein_stand
def decode_eval_claim(bundle, *, expected_context: Optional[str] = None) -> Optional[dict]:
    """Verify the bundle, then check the signing key matches the claim's `issuer` field.

    Returns the parsed claim on success, None on any failure. Dependency-free (no JCS import):
    it parses the exact in-memory payload bytes that verify_bundle already authenticated.

    A str ``bundle`` is a PATH. It is resolved to a dict EXACTLY ONCE, before verification, and the
    same object is both verified and parsed — a second re-read of the path would be a TOCTOU (CWE-367)
    file-race window (a swap between the two reads could return content whose signature was never
    checked). Release-review fix 2026-07-02.

    THE SAME HOLDS FOR AN OBJECT since round 11 (lens run 10 at fa555f13, findings L1 and L2). A
    dict was read twice, once by ``verify_bundle`` and once to parse ``payload_b64``, both through
    the caller's object, and the issuer binding read ``signature.public_key_b64`` a second time too.
    Measured at fa555f13 (and by the lens on main 31816e08): a dict subclass storing the signed
    payload whose ``__getitem__`` answered with another from the second read on, and a plain dict whose
    ``payload_b64`` was a ``str`` subclass with its own ``encode``, each returned a claim the
    signature does not cover (``passed`` True, ``suite`` "forged-suite"). The object is now read
    once (`_eine_lesung`); the payload bytes the signature was checked over are the bytes parsed,
    and the issuer binding reads the key from the same copy. A bundle holding a value that is no
    JSON value is None.

    v1.6 verify-side invariants (external review: guarantees must hold on the VERIFY path, not
    only in the blessed emitter): when the claim carries ``samples``, its shape, 32-byte root,
    ``leaf_alg`` and ``samples.n == n`` are re-validated here — a hand-signed claim that lies
    about the committed tree size is rejected. ``expected_context`` enforces the signed
    ``context_binding`` field (cross-context replay guard): if supplied and the claim's binding
    is absent or different, the claim is rejected. It is compared by its characters (round 10,
    `canonical._zeichen_von`): a ``str`` subclass is read as the characters it holds, and a value
    that is no string is a refusal, None. Measured at 493c2f86: a ``str`` subclass whose ``__ne__``
    answers False, and an object of another type whose ``__ne__`` answers False, returned the claim
    of a receipt bound to another context and of a receipt with no binding.

    Every check on the claim itself lives in ``_claim_violation``, which the emitter calls too, so a
    claim this function refuses is one ``emit_eval_receipt`` will not sign. What stays here is what
    needs the bundle or the caller: the signature, the issuer binding and ``expected_context``.

    R-B1 (6.2.0): the constraints of ``schemas/eval_claim_v0_1.schema.json`` that the older checks
    did not reach are refused as well: both commitment patterns, six string types, ``ci95``,
    ``provenance`` and ``samples`` as objects, and ``samples.n >= 1``. The boundary stays STRICTER
    than the schema in two places (integers within +-(2**53-1) anywhere in the claim, which covers
    ``n <= 2**53-1``, and a 32-byte samples root), and it is meant to accept nothing the schema
    rejects. ``tests/test_eval_claim_commitment_pattern_holds.py``
    measures that with ``jsonschema`` as the oracle over a generated corpus; a measurement over that
    corpus, not a proof over every input.
    """
    try:
        # ONE READING: a PATH is resolved to a dict once, an object is read once into its plain copy,
        # and the signature, the parse and the issuer binding all read that one result.
        bundle = _eine_lesung(bundle)
        result, payload = _verify_bundle(bundle)
        if not result.ok:
            return None
        claim = load_claim_text(payload.decode("utf-8"))
        return _claim_of_verified(bundle, claim, expected_context)
    except (ProofBundleError, KeyError, ValueError, TypeError, EvalClaimError, OSError):
        # MJSON-01 (RE-GATE never-raise): the documented contract is "Returns the parsed claim on success,
        # None on any failure". load_bundle (a bad path str -> OSError) and verify_bundle (a non-bundle dict
        # -> UnsupportedError / BundleFormatError, both ProofBundleError) previously ran OUTSIDE this try, so
        # a non-bundle / non-path argument raised a raw exception instead of returning None. Both now sit
        # inside the guard and the except covers the malformed-input family, so decode_eval_claim on
        # {'not':'a bundle'} / [1,2,3] / a bad path all return None as documented.
        return None


def _names_a_foreign_bundle_format(bundle) -> bool:
    """True only for a bundle whose top-level `schema` is a present, non-empty string other than ours.

    Read without walking the document: one key, one type check, one comparison, so it adds no work
    that the structural budget in ``verify_bundle`` would otherwise have bounded.
    """
    if not isinstance(bundle, dict) or "schema" not in bundle:
        return False
    schema = bundle["schema"]
    return isinstance(schema, str) and bool(schema) and schema != BUNDLE_SCHEMA


@_ein_stand
def classify_eval_claim(bundle, *, expected_context: Optional[str] = None) -> tuple:
    """Three-outcome classification of a bundle: (outcome, claim-or-None).

    ``CLAIM_VALID`` — verified, and the claim is a sound eval claim (the claim is returned).
    ``CLAIM_REFUSED_UNKNOWN_SCHEMA`` — the bundle VERIFIES, but its payload declares a schema this
    verifier does not know; or the envelope itself declares a format that is not ours (see below).
    That is not a defect of the receipt; it is the limit of this verifier, and reporting it as
    `invalid` would put a wrong verdict on someone else's sound artifact.
    ``CLAIM_INVALID`` — everything genuinely judgeable and wrong: a broken signature, a payload that
    is not JSON, a known schema carrying a malformed claim.

    ORDER MATTERS AND IS DELIBERATE. Authenticity is decided FIRST: a bundle whose signature does not
    verify is `invalid` no matter what schema its PAYLOAD names, because a broken signature IS
    judgeable and "I cannot judge this" would be the weaker, wrong answer. Only an AUTHENTIC payload
    can earn a refusal at the claim level.

    ONE STEP COMES BEFORE AUTHENTICITY, and it is the envelope's own identifier. A bundle whose
    top-level `schema` names a format that is not `proofbundle/v0.1` is `CLAIM_REFUSED_UNKNOWN_SCHEMA`
    too. Its signature is not judgeable here, because this verifier does not know how that format is
    signed, and judging it as a broken `proofbundle/v0.1` would be the best-effort reading R2 rules
    out. Until 2026-09-25 this returned `invalid`: `verify_bundle` raises `UnsupportedError` for the
    foreign identifier, and the broad `except` below folded that typed refusal into the invalid
    outcome. Measured 2026-09-05 with an `inspect-receipts` 0.3 receipt in issue 147 (release scope
    line Z.278).

    THE REFUSAL NEEDS A DECLARATION. Only a PRESENT, non-empty string that is not ours counts as a
    foreign identifier. An ABSENT `schema` declares no other format, and a present value that is not
    a usable identifier (a number, a list, an empty string) declares nothing either; both stay
    `invalid`, fail-closed, as `verify_bundle` rules them. An unknown `signature.alg` or
    `merkle.hash_alg` INSIDE a `proofbundle/v0.1` bundle also stays `invalid`: our own schema fixes
    both values, so a bundle that names ours and breaks it is judgeable. What renaming the envelope
    identifier buys a forger is therefore a refusal instead of `invalid`, never `valid`.

    THE RESOURCE LIMITS COME BEFORE THE IDENTIFIER, in both transports (Codex on PR 268, measured).
    A path is read through ``load_bundle``, which applies the byte cap and the structural limits
    before any field can be looked at, so a foreign document over them was `invalid` by path and
    refused as a dict. The dict path now applies the same structural limits (nodes, depth, string
    length, integer size) first. What remains different, and is stated rather than hidden: a dict
    carries no bytes, so the ``input_bytes`` cap cannot be applied to it. That is the same asymmetry
    ``verify_bundle`` has for our own format on its dict path.

    ONE READING (round 11, lens run 10 at fa555f13, finding L3). The bundle was read three times,
    for the identifier and ``verify_bundle``, for the parse, and again inside ``decode_eval_claim``,
    each time through the caller's object. Measured at fa555f13 (and by the lens on main 31816e08):
    a dict subclass storing the signed payload whose ``__getitem__`` answered with another from the fourth read on
    gave ``CLAIM_VALID`` with a claim the signature does not cover. The object is read once now
    (`_eine_lesung`, the budget first, as above), and the identifier, the signature, the parse and
    the claim checks read that one copy; the claim is parsed from the payload bytes that were
    verified. A dict holding a value that is no JSON value is ``CLAIM_INVALID``, whatever its
    identifier names: it is no JSON document of any format.

    Never raises — same never-raise contract as ``decode_eval_claim``.
    """
    try:
        bundle = _eine_lesung(bundle)
        if _names_a_foreign_bundle_format(bundle):
            return (CLAIM_REFUSED_UNKNOWN_SCHEMA, None)
        result, payload = _verify_bundle(bundle)
        if not result.ok:
            return (CLAIM_INVALID, None)
        claim = load_claim_text(payload.decode("utf-8"))
    except (ProofBundleError, KeyError, ValueError, TypeError, EvalClaimError, OSError):
        return (CLAIM_INVALID, None)
    if not isinstance(claim, dict):
        return (CLAIM_INVALID, None)
    if claim.get("schema") != EVAL_CLAIM_SCHEMA:
        return (CLAIM_REFUSED_UNKNOWN_SCHEMA, None)
    try:
        decoded = _claim_of_verified(bundle, claim, expected_context)
    except (ProofBundleError, KeyError, ValueError, TypeError, EvalClaimError):
        decoded = None
    if decoded is None:
        return (CLAIM_INVALID, None)
    return (CLAIM_VALID, decoded)


@_ein_stand
def claim_warnings(claim: dict) -> list:
    """Honest trust warnings for an already-verified claim (v1.1). A verified signature proves authorship +
    integrity, NOT that the number is true or the study was pre-registered. The weakest combination —
    self_attested with no pre-registration — is where an issuer could publish the best of many runs; surface
    it so a strong signature never masks a weak assurance. Returns a list of human-readable strings."""
    out = []
    level = claim.get("assurance_level", DEFAULT_ASSURANCE)
    if level == "self_attested" and not claim.get("prereg_sha256"):
        out.append("self_attested with no prereg_sha256 — the weakest assurance: trust rests entirely on the "
                   "issuer, who could publish the best of many runs. Pre-register (prereg_sha256) or use a "
                   "higher assurance_level (reproduced / enclave_attested) to strengthen it.")
    return out


# P0-B (Hardening 3.0.1 §7.1) — the machine-readable SCORE-evidence verdicts. A receipt today signs a
# THRESHOLD VERDICT (`passed` against the signed `comparator`/`threshold`): the exact score is used at
# emit time to COMPUTE `passed` and is then DISCARDED (build_eval_claim never stores it), so no output
# may imply an exact score was verified. The other classes are reachable only through the optional,
# additive exact-score profile (§7.2, EXPERIMENTAL, NOT part of the frozen 3.x core).
EXACT_SCORE_VERIFIED = "EXACT_SCORE_VERIFIED"
THRESHOLD_VERDICT_VERIFIED = "THRESHOLD_VERDICT_VERIFIED"
SCORE_COMMITMENT_PRESENT = "SCORE_COMMITMENT_PRESENT"
SCORE_WITHHELD = "SCORE_WITHHELD"
METHODOLOGY_NOT_EVALUATED = "METHODOLOGY_NOT_EVALUATED"
SCORE_EVIDENCE_CLASSES = (EXACT_SCORE_VERIFIED, THRESHOLD_VERDICT_VERIFIED,
                          SCORE_COMMITMENT_PRESENT, SCORE_WITHHELD)


@_ein_stand
def eval_evidence_class(claim: dict) -> dict:
    """Classify what SCORE evidence a VERIFIED eval claim carries (never call on an unverified claim).

    Returns ``{"score_evidence": <class>, "methodology": METHODOLOGY_NOT_EVALUATED, "detail": <str>}``.

    Today every receipt is ``THRESHOLD_VERDICT_VERIFIED``: the frozen v0.1 schema has no ``score``
    field, so a receipt proves only that ``passed`` holds for the signed ``comparator``/``threshold``.
    ``methodology`` is ALWAYS ``METHODOLOGY_NOT_EVALUATED`` — a receipt never judges whether the suite
    measures what it claims (No-Overclaim §0.5).

    The remaining classes are reachable only through the optional, additive exact-score profile (§7.2,
    field names provisional pending its ADR, EXPERIMENTAL, not in the 3.x core): a signed decimal-string
    ``score`` whose recomputed ``passed`` AGREES → ``EXACT_SCORE_VERIFIED`` (a score present but
    inconsistent with ``passed`` is a decode-time FAIL; if seen here it degrades to the threshold
    verdict, never a false EXACT); a signed score COMMITMENT → ``SCORE_COMMITMENT_PRESENT`` (a binding,
    NOT a range proof: it does not prove the hidden score crossed the threshold, §7.3); an explicit
    withheld marker → ``SCORE_WITHHELD``.
    """
    methodology = METHODOLOGY_NOT_EVALUATED
    comparator = claim.get("comparator")
    threshold = claim.get("threshold")
    passed = claim.get("passed")
    score = claim.get("score")
    if (isinstance(score, str) and _DECIMAL_RE.match(score) and is_member(comparator, _COMPARATORS)
            and isinstance(threshold, str) and _DECIMAL_RE.match(threshold) and isinstance(passed, bool)):
        assert isinstance(comparator, str)  # narrowed by is_member above; assures mypy for the call
        from decimal import InvalidOperation  # noqa: PLC0415
        try:
            recomputed: Optional[bool] = _passed_by(score, comparator, threshold)
        except InvalidOperation:
            recomputed = None
        if recomputed is passed:
            return {"score_evidence": EXACT_SCORE_VERIFIED, "methodology": methodology,
                    "detail": "exact score signed and consistent with the threshold verdict"}
        return {"score_evidence": THRESHOLD_VERDICT_VERIFIED, "methodology": methodology,
                "detail": "score present but not consistent with `passed` — only the threshold verdict stands"}
    if claim.get("score_commit") or claim.get("score_commitment"):
        return {"score_evidence": SCORE_COMMITMENT_PRESENT, "methodology": methodology,
                "detail": "a score COMMITMENT is present — a binding, NOT a range proof: it does not "
                          "prove the hidden score crossed the threshold"}
    if claim.get("score_withheld") is True:
        return {"score_evidence": SCORE_WITHHELD, "methodology": methodology,
                "detail": "the exact score is deliberately withheld; only the threshold verdict is signed"}
    return {"score_evidence": THRESHOLD_VERDICT_VERIFIED, "methodology": methodology,
            "detail": "proves `passed` against the signed threshold, not an exact score"}


@_ein_stand
def verify_commitment(identifier: str, salt: bytes, commitment: str) -> bool:
    """Check that a PRESENTED identifier (+ its salt) matches a salted commitment in a claim
    (``model_id_commit`` / ``dataset_id_commit``). Makes a model-swap visible: a claim that silently swapped
    the model cannot produce a matching (identifier, salt). Constant-time compare; the salt stays outside the
    payload (the holder presents it to a verifier out of band).

    The three inputs of the comparison are read as what they hold (round 10): ``identifier`` and
    ``commitment`` as their characters (`canonical._zeichen_von`), ``salt`` as its stored bytes, each
    through the base type and never through a method of the caller; a value of another type is False.
    Measured at 493c2f86: an ``identifier`` holding "other" whose ``encode`` returned the committed
    identifier's bytes, and a ``commitment`` object whose ``__str__`` returned the right commitment,
    each verified True.

    AN INPUT THAT CANNOT BE ENCODED IS FALSE, not a raw exception (round 10, second commit). Measured
    at 493c2f86, at 6b223d8e and on main 31816e08: a ``commitment`` holding a character outside ASCII
    raised a raw TypeError from ``hmac.compare_digest``, which compares a ``str`` only when it is
    ASCII, and an ``identifier`` holding a lone surrogate raised a raw UnicodeEncodeError from
    ``salted_commit``, because UTF-8 cannot encode it. A commitment is ``sha256:`` and hex digits, so
    one outside ASCII matches nothing; it is refused before the comparison, which now compares the
    ASCII bytes. An identifier that UTF-8 cannot encode cannot be the committed one."""
    kennung = _zeichen_von(identifier)
    zusage = _zeichen_von(commitment)
    salz_typ = type(salt)
    if kennung is None or zusage is None:
        return False   # RE-GATE never-raise: a non-str PRESENTED identifier is a fail-closed False, not a
        # raw AttributeError from identifier.encode() inside salted_commit (untrusted presentation input).
    # adversarial re-audit round 7: the `salt` is the SAME out-of-band presentation channel — a non-bytes salt
    # is a raw TypeError from len(salt) in salted_commit; guard it here too (the identifier-only guard was
    # half-finished).
    gespeichert: Any = salt
    if issubclass(salz_typ, bytes):
        salz = bytes.__getitem__(gespeichert, slice(None))
    elif issubclass(salz_typ, bytearray):
        salz = bytes(bytearray.__getitem__(gespeichert, slice(None)))
    else:
        return False
    if not zusage.isascii():
        return False
    try:
        expected = salted_commit(kennung, salz)
    except (EvalClaimError, UnicodeEncodeError):
        return False
    import hmac  # noqa: PLC0415
    return hmac.compare_digest(expected.encode("ascii"), zusage.encode("ascii"))


@_ein_stand(aussen={"now": "uhr"})
def check_freshness(claim: dict, max_age_seconds: Optional[int] = None, now=None) -> dict:
    """Replay check (v1.1): parse the claim's timestamp and report its age. A receipt carries a timestamp but
    verify never judged it — an old receipt could be replayed as new. Returns
    {"parsed": bool, "age_seconds": int|None, "fresh": bool|None, "reason": str}. ``fresh`` is None when no
    ``max_age_seconds`` bound is given (age reported, not judged). ISO parsing (normalizes a trailing Z)."""
    from datetime import datetime, timezone  # noqa: PLC0415
    from .canonical import _zahl_von  # noqa: PLC0415
    # One reading of each caller value, by what it holds (round 12): the claim as the plain copy of what
    # it stores, the clock by its own type, the bound as an exact number (a subclass of int or float is
    # refused below, PR 293's rule; round 12 read the number it stores).
    gelesen: Any = claim
    if issubclass(type(claim), dict):
        try:
            gelesen = _plain_for_jcs(claim, ValueError)
        except ValueError:
            gelesen = None
    claim = gelesen
    if max_age_seconds is not None and type(max_age_seconds) is not bool and _zahl_von(max_age_seconds) is not None:
        max_age_seconds = _zahl_von(max_age_seconds)
    if type(claim) is not dict:   # `type()`: after the copy a dict is a plain dict (round 12)
        # adversarial re-audit round 7: the natural RP pattern check_freshness(decode_eval_claim(bundle)) passes a
        # None (decode returns None on a non-eval bundle) straight into claim.get(...) — a raw AttributeError.
        # A non-dict claim is a fail-closed "not parsed" verdict, never a crash.
        return {"parsed": False, "age_seconds": None, "fresh": None, "reason": "claim is not a dict"}
    # adversarial re-audit round 4 (G1 non-primary args): the primary `claim` was guarded, but a non-datetime
    # `now` reached `ref.tzinfo` (AttributeError) and a non-numeric `max_age_seconds` reached `0 <= age <= ...`
    # (TypeError) — both are natural RP/policy mis-values (policy.evaluate_policy forwards the untrusted
    # max_iat_age_seconds straight in). A malformed config arg is a fail-closed "not parsed" verdict, never a crash.
    if now is not None and not issubclass(type(now), datetime):
        return {"parsed": False, "age_seconds": None, "fresh": None, "reason": "invalid 'now' (not a datetime)"}
    if max_age_seconds is not None and type(max_age_seconds) not in (int, float):   # exact (round 12)
        return {"parsed": False, "age_seconds": None, "fresh": None,
                "reason": "invalid 'max_age_seconds' (not a number)"}
    ts = claim.get("timestamp")
    if not isinstance(ts, str):
        return {"parsed": False, "age_seconds": None, "fresh": None, "reason": "no timestamp"}
    raw = ts[:-1] + "+00:00" if ts.endswith("Z") else ts
    try:
        dt = datetime.fromisoformat(raw)
    except (ValueError, OverflowError):
        return {"parsed": False, "age_seconds": None, "fresh": None, "reason": f"unparseable timestamp {ts!r}"}
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    ref = now or datetime.now(timezone.utc)
    if ref.tzinfo is None:
        ref = ref.replace(tzinfo=timezone.utc)
    # RT-06 neighbour of L3-600-07 (sweep of every datetime site, 2026-09-05): an aware timestamp whose
    # UTC instant lies outside year 1..9999 (``0001-01-01T00:00:00+23:00``) parses fine and then raises
    # OverflowError in the SUBTRACTION — reachable from show-eval (age line) and from a policy
    # max_iat_age_seconds. Out of range is "not parsed", never a crash on a never-raise surface.
    try:
        age = int((ref - dt).total_seconds())
    except OverflowError:
        return {"parsed": False, "age_seconds": None, "fresh": None,
                "reason": f"timestamp {ts!r} is out of the representable range"}
    if max_age_seconds is None:
        return {"parsed": True, "age_seconds": age, "fresh": None, "reason": f"age {age}s (no bound given)"}
    fresh = 0 <= age <= max_age_seconds
    return {"parsed": True, "age_seconds": age, "fresh": fresh,
            "reason": (f"age {age}s within {max_age_seconds}s" if fresh
                       else f"age {age}s outside [0, {max_age_seconds}]s — possible replay or clock skew")}


@_ein_stand
def sd_jwt_hidden_count(bundle) -> Optional[int]:
    """Number of selectively-disclosable (currently withheld) SD-JWT fields in a bundle, so that OMISSION is
    visible: a receipt can hide claims behind the SD-JWT ``_sd`` digests. Returns the count, or None if the
    bundle carries no SD-JWT. Reads the issuer JWT payload's ``_sd`` array without verifying the SD-JWT
    (that is the holder/verifier's job); purely a disclosure-transparency signal."""
    if isinstance(bundle, str):
        bundle = load_bundle(bundle)
    sd = bundle.get("sd_jwt_vc") if isinstance(bundle, dict) else None
    if not sd:
        return None
    # the canonical bundle form (the only one verify_bundle accepts) stores the compact SD-JWT under "compact";
    # sd_jwt/token are accepted as fallbacks for a bare token dict/string.
    token = sd if isinstance(sd, str) else (sd.get("compact") or sd.get("sd_jwt") or sd.get("token") or "")
    if not isinstance(token, str) or "." not in token:
        return None
    from ._strict_json import loads_strict  # noqa: PLC0415
    try:
        jwt = token.split("~", 1)[0]                     # issuer JWT, before any disclosures
        payload_b64 = jwt.split(".")[1]
        # JWS segments are unpadded base64url; decode_b64url refuses a padded spelling (one wire form).
        # F12 (release-audit follow-up 2026-07-12): loads_strict, not json.loads — a 5th SD-JWT
        # issuer-payload parse site of the same parser-differential class. A duplicate key (e.g. two
        # `_sd`) → BundleFormatError → None (honest "cannot count"), never a silent last-wins count.
        payload = loads_strict(decode_b64url(payload_b64).decode("utf-8"))
    except (ProofBundleError, ValueError, KeyError, IndexError):
        # adversarial re-audit round 3 (repro-confirmed): sd_jwt_hidden_count is PUBLIC — a node-heavy embedded
        # payload made loads_strict raise a SIBLING BudgetExceeded that `except BundleFormatError` let escape
        # as a raw DoS traceback. The BASE ProofBundleError catch maps every over-limit/malformed case to None.
        return None
    if not isinstance(payload, dict):                    # a valid-JSON non-object payload → nothing to count
        return None
    sd_arr = payload.get("_sd")
    return len(sd_arr) if isinstance(sd_arr, list) else None


@_ein_stand
def enclave_assurance_proven(claim: dict, bundle, *, eat_jws: Optional[str] = None,
                             verifier_pubkey: Optional[bytes] = None,
                             expected_profile: Optional[str] = None,
                             now: Optional[int] = None) -> Optional[bool]:
    """Whether a signed ``assurance_level=enclave_attested`` claim is BACKED by a verified TEE
    Attestation Result bound to THIS receipt — analogous to ``decision.action_outcome_proven``:
    presence + binding makes a declared level *verifiable*, not merely *asserted*.

    Returns ``None`` when the claim does not declare ``enclave_attested`` (not applicable — mirrors
    ``action_outcome_proven``'s ``None`` for a non-``executed`` outcome). Returns ``False`` when
    ``enclave_attested`` IS declared but no ``eat_jws``/``verifier_pubkey`` was supplied, or the
    supplied EAT does not verify or does not bind this receipt — the honesty limit:
    ``assurance_level`` is issuer-declared (THREAT_MODEL.md), and stays exactly that, a string,
    until corroborated. Returns ``True`` only when an EAT Attestation Result, checked offline
    against ``verifier_pubkey`` via ``proofbundle.experimental.enclave.verify_enclave_attestation``,
    reports ``ok=True`` with ``eat_nonce == enclave_binding_for(bundle)`` — bound to THIS receipt's
    exact signed payload, not merely well-formed.

    **Additive, EXPERIMENTAL by construction.** This reaches into
    ``proofbundle.experimental.enclave`` (the v2.0 preview TEE bridge, docs/EXPERIMENTAL_ENCLAVE.md)
    ONLY when actually called with an ``eat_jws`` — importing/using ``proofbundle.evalclaim`` never
    triggers the subpackage's ``ExperimentalWarning`` by itself (the import is lazy, function-local,
    mirroring the ``rfc8785`` lazy import in :func:`canonicalize`). **Never force-promotes:** an
    ``enclave_attested`` claim with no (or a failing) corroboration is NEITHER upgraded NOR
    downgraded in the claim itself — the signed ``assurance_level`` string is unchanged either way;
    this function only reports, additively, whether it is BACKED.
    """
    if not isinstance(claim, dict) or claim.get("assurance_level") != "enclave_attested":
        return None
    if not eat_jws or verifier_pubkey is None or bundle is None:
        return False
    try:
        from .experimental.enclave import enclave_binding_for, verify_enclave_attestation  # noqa: PLC0415
        binding = enclave_binding_for(bundle)
        res = verify_enclave_attestation(eat_jws, verifier_pubkey=verifier_pubkey,
                                         expected_binding=binding, expected_profile=expected_profile,
                                         now=now)
    except (ProofBundleError, ValueError, TypeError, KeyError):
        # adversarial re-audit round 3: the enclave path funnels through loads_strict (BudgetExceeded) and may
        # hit PQUnavailable — both ProofBundleError SIBLINGS that `except BundleFormatError` let escape. The
        # BASE catch keeps this corroboration reporter fail-closed (unverifiable → not BACKED → False).
        return False
    return bool(res.get("ok"))
