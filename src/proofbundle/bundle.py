"""Evidence bundle model and offline verification.

An evidence bundle is a single self-contained JSON document. ``verify_bundle``
checks, fully offline and without any running log server:

  1. ed25519-signature   the payload is signed by the stated public key
  2. merkle-inclusion    the payload is anchored under the stated tree root
                         (RFC 6962 / RFC 9162 inclusion proof)
  3. sd-jwt (optional)   any embedded SD-JWT selective-disclosure credential is
                         well formed and, if a key is given, issuer-signed

The verifier treats ``payload`` as opaque bytes: it proves *that these exact
bytes were signed and anchored*, not what they mean. That keeps v0.1 small and
correct. Turning a reproducible eval run into such a payload is the job of the
eval-receipt emitter (see :mod:`proofbundle.evalclaim`, since v0.4).

Malformed input (wrong types, missing or unknown fields) is rejected with a
``BundleFormatError`` — never a raw traceback — so a caller gets the documented
malformed exit code, not a crash.
"""

from __future__ import annotations

import base64
import hmac
from typing import Optional, Union

from . import merkle
from ._strict_json import loads_strict
from .errors import BundleFormatError, UnsupportedError, VerificationResult
from .kbjwt import holder_key_from_cnf, split_key_binding, verify_key_binding
from .signature import verify_ed25519
from .sdjwt import verify_sd_jwt

__all__ = ["SCHEMA", "verify_bundle", "load_bundle", "recompute_merkle_root_b64",
           "root_authenticity_summary", "AUTOMATION_BLOCKER_REASONS"]

# AP-1 §5.3: the human-legible reason for each automationBlockers enum value. Kept HERE, next to the
# blocker logic in root_authenticity_summary, so the human `SAFE_FOR_AUTOMATION` line and the JSON flag
# can never drift apart (one source of truth — Iteration F). A blocker with no entry falls back to its
# raw enum string, so a future blocker is never silently unexplained.
AUTOMATION_BLOCKER_REASONS = {
    "CRYPTO_FAILED": "Cryptographic verification did not pass",
    "ROOT_NOT_AUTHENTICATED": "The Merkle root was not authenticated against a relying-party value "
                              "(--expected-root or a policy trusted_roots entry)",
    "TREE_CONTEXT_NOT_AUTHENTICATED": "Root and tree size were not authenticated ATOMICALLY from one "
                                      "source (a signed checkpoint via --trusted-checkpoint / policy "
                                      "trusted_checkpoints, or an --expected-root + "
                                      "--expected-tree-size pair) — a root-bytes-only pin cannot "
                                      "detect a tree-size/leaf-index relabel (A-P0-1)",
    "POLICY_NOT_EVALUATED": "No trust policy was evaluated (supply --policy to authorise a signer)",
    "POLICY_FAILED": "The supplied trust policy was not satisfied",
    "SIGNER_NOT_PINNED": "The trust policy pins no trusted signer identity (attributes to nobody)",
    "TEMPLATE_NOT_INSTANTIATED": "The trust policy is a raw template (requiresIdentityOverlay:true) — "
                                 "instantiate it with a signer identity before depending on it for automation",
    "POLICY_EXPIRED": "The trust policy has expired (its valid_until is in the past)",
    "POLICY_WARNINGS_PRESENT": "The trust policy carries a warning that blocks automation",
    "ANCHOR_REQUIRED_FAILED": "A required external time anchor did not verify",
    "PUBLIC_TRANSPARENCY_REQUIRED_FAILED": "A required public-transparency proof did not verify",
    "REPLAY_BINDING_REQUIRED_FAILED": "A required replay/audience binding did not verify",
}


def _issuer_requires_holder_binding(sd_part: str) -> bool:
    """True iff the issuer-signed SD-JWT payload carries a usable ``cnf`` holder key (RFC 7800) — i.e. the
    issuer REQUIRES proof-of-possession. A presentation without a valid Key Binding JWT is then a bearer
    downgrade and MUST fail. Malformed/absent → False (no cnf ⇒ no binding required, backward-compatible).
    A DUPLICATE key → True (fail-closed, F12): treating an ambiguous-because-duplicated payload as
    'no binding required' would be the exact inversion _strict_json.py warns about."""
    try:
        issuer_jwt = sd_part.split("~", 1)[0]
        payload_b64 = issuer_jwt.split(".")[1].encode("ascii")
        payload = loads_strict(base64.urlsafe_b64decode(payload_b64 + b"=" * (-len(payload_b64) % 4)))
        return isinstance(payload, dict) and holder_key_from_cnf(payload) is not None
    except BundleFormatError:
        # A duplicated key in the issuer payload must NOT read as "no cnf ⇒ no binding required" (that
        # inversion would let a duplicate-cnf payload skip holder binding entirely). Fail-closed: demand
        # binding. The bundle already fails at the sd-jwt-disclosures structure gate; this is belt-and-braces.
        return True
    except Exception:  # noqa: BLE001 — any other malformed/absent payload ⇒ no binding required (backward-compat)
        return False

SCHEMA = "proofbundle/v0.1"

# Allowed keys per object — SPEC.md §3: a verifier MUST reject unknown fields (schema is
# additionalProperties: false). Enforced here so the code matches its own normative spec.
# `anchors` is an OPTIONAL, EXPERIMENTAL detached layer (external time anchors, SPEC.md §7i / the
# `[anchors]` extra): the core crypto verifier merely TOLERATES the field so an anchored receipt is not
# rejected as malformed — it never verifies the anchors here, so a bundle's crypto verdict is identical
# whether or not it carries `anchors`. Anchor verification is a separate, opt-in relying-party step
# (`proofbundle.anchors.verify_anchors` / `verify --require-anchor`), never part of this offline core.
_TOP_KEYS = {"schema", "payload_b64", "signature", "merkle", "sd_jwt_vc", "anchors"}
_SIG_KEYS = {"alg", "public_key_b64", "sig_b64"}
_MERKLE_KEYS = {"hash_alg", "leaf_index", "tree_size", "inclusion_proof_b64", "root_b64"}
_SD_KEYS = {"compact", "issuer_public_key_b64"}


def _sd_jwt_carries_eval_root_commitment(sd_payload) -> bool:
    """N1 (audit 2026-07-13; discriminator hardened after pre-land L1 review): True iff an SD-JWT issuer
    payload carries the eval-binding ROOT COMMITMENT (``receipt.root_b64``, a non-empty base64 string)
    that ``check_binds_bundle`` binds against — i.e. it CLAIMS to be anchored to a proofbundle merkle
    root. That commitment is the exact cross-receipt substitution vector, so it (NOT a heuristic
    word-match on generic keys like ``passed``/``suite``/``threshold``) is what marks an eval SD-JWT
    grafted onto a non-eval payload. `issue_sd_jwt` always writes ``receipt.root_b64`` always-open, so a
    genuine eval SD-JWT is caught even if its ``passed``/``threshold`` facts are moved into selective
    disclosures; a generic SD-JWT-VC (``iss``/``vct``, no receipt commitment) is not an eval graft and
    stays in scope (backward-compatible). Residual (documented, out of scope): a SELF-SIGNED credential
    that hides even ``receipt.root_b64`` in a disclosure asserts no always-open anchoring claim and cannot
    forge a trusted-issuer graft (the genuine emitter never does this)."""
    if not isinstance(sd_payload, dict):
        return False
    receipt = sd_payload.get("receipt")
    # Fire on the PRESENCE of a receipt.root_b64 string, INCLUDING "" (L1 pre-land audit F3): an empty root
    # commits nothing concrete, but "an eval-shaped commitment present yet evading N1" should not exist. A
    # generic SD-JWT-VC has no receipt object at all, so this never false-refuses one.
    return isinstance(receipt, dict) and isinstance(receipt.get("root_b64"), str)


def _b64d(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise BundleFormatError(f"field {field} is not valid base64") from exc


def _require(obj: dict, key: str, field: str):
    if key not in obj:
        raise BundleFormatError(f"missing field {field}")
    return obj[key]


def _require_dict(obj, field: str) -> dict:
    """The value must be a JSON object — a string/list/number is malformed, not a crash."""
    if not isinstance(obj, dict):
        raise BundleFormatError(f"field {field} must be a JSON object")
    return obj


def _require_int(obj: dict, key: str, field: str) -> int:
    """The value must be a JSON integer — reject floats (SPEC §2) and non-numeric strings/None."""
    val = _require(obj, key, field)
    if isinstance(val, bool) or not isinstance(val, int):   # bool is an int subclass; a float/str/None is not
        raise BundleFormatError(f"field {field} must be an integer, got {type(val).__name__}")
    return val


def _reject_unknown(obj: dict, allowed: set, field: str) -> None:
    extra = set(obj) - allowed
    if extra:
        raise BundleFormatError(f"unknown field(s) in {field}: {sorted(extra)}")


def _require_hash_alg(mk: dict) -> str:
    """``merkle.hash_alg`` is REQUIRED (v1.6+, SPEC.md §5) and its value MUST be the one supported
    algorithm: a silently-defaulted OR silently-accepted-arbitrary value is exactly where a future
    multi-alg version would hide an alg-confusion attack. The only realistic way to hit the
    missing-field case is a bundle emitted before v1.6 — every emitter since then always writes the
    field — so that error carries a migration hint rather than a bare "missing field". Shared by
    :func:`verify_bundle` and :func:`recompute_merkle_root_b64` so neither the presence check NOR
    the value check can drift apart between the two call sites (LOW finding, 2026-07-09: the value
    check used to be duplicated separately in each function)."""
    if "hash_alg" not in mk:
        raise BundleFormatError(
            "missing field merkle.hash_alg — REQUIRED since v1.6 (SPEC.md §5). Migrate a "
            'pre-v1.6 bundle by adding "hash_alg": "sha256-rfc6962" to its merkle object; '
            "every proofbundle emitter since v1.6 writes this field automatically.")
    hash_alg = mk["hash_alg"]
    if hash_alg != "sha256-rfc6962":
        raise UnsupportedError(f"merkle hash_alg {hash_alg!r} not supported in v0.1")
    return hash_alg


def load_bundle(path: str) -> dict:
    """Read and JSON-parse a bundle file. Deeply-nested JSON overflows the parser's C-recursion; that
    is malformed input, so it is mapped to BundleFormatError (the documented exit-2 path) rather than
    escaping as a raw RecursionError traceback (verify-lens L3, 2026-07-09)."""
    with open(path, "r", encoding="utf-8") as handle:
        # WP-C1: duplicate keys are rejected fail-closed (loads_strict) — the native bundle path
        # silently kept the LAST duplicate (e.g. a second `root_b64`/`sig_b64`), a classic parser
        # differential across JSON implementations. loads_strict ALSO owns the RecursionError →
        # BundleFormatError mapping for deep nesting (the old outer handler here became dead code).
        return loads_strict(handle.read())


def verify_bundle(bundle: Union[dict, str], *, expected_aud=None, expected_nonce=None,
                  expected_root_b64: Optional[str] = None,
                  expected_tree_size: Optional[int] = None) -> VerificationResult:
    """Verify an evidence bundle (a dict or a path to a JSON file).

    ``expected_aud`` / ``expected_nonce`` (v1.3): when the bundle carries a Key Binding JWT, these enforce
    RFC 9901 §7.3 replay/audience binding — the KB-JWT's ``aud`` MUST match ``expected_aud`` and its
    ``nonce`` MUST match ``expected_nonce``. If omitted, the KB-JWT signature + disclosure binding are still
    checked, but the relying party has NOT bound the presentation to itself/this transaction — a stale or
    cross-audience replay would still verify. A relying party doing challenge-response MUST pass both.

    ``expected_root_b64`` / ``expected_tree_size`` (P0-A, Hardening 3.0.1 §6.2): RELYING-PARTY root
    authentication. The native Merkle root is NOT part of the signature input (SPEC §5), so the SAME
    signed payload verifies under DIFFERENT roots — a *coherent one-leaf rewrap* re-anchors the payload
    at index 0 of a 2-leaf tree with a foreign sibling, and inclusion still holds. Merkle inclusion alone
    therefore proves CONSISTENCY under the stated root, NOT that the root is authentic. When the relying
    party supplies an authenticated root / tree size (out of band: a pinned value, a signed checkpoint,
    the trusted_roots of a policy), these are enforced bit-exactly and a mismatch FAILS (adds the
    ``root-authenticity`` / ``tree-size`` checks). ``expected_root_b64`` is decoded and compared to the
    stated root's BYTES (canonicalization-agnostic). Absent, root authenticity stays NOT_EVALUATED and
    the crypto verdict is unchanged (backward-compatible) — see ``root_authenticity_summary``.
    """
    if isinstance(bundle, str):
        bundle = load_bundle(bundle)
    if not isinstance(bundle, dict):
        raise BundleFormatError("bundle must be a JSON object")

    schema = bundle.get("schema")
    if schema != SCHEMA:
        raise UnsupportedError(f"unsupported schema {schema!r}, expected {SCHEMA!r}")
    _reject_unknown(bundle, _TOP_KEYS, "bundle")
    # WP-A7: the anchors field stays UNVERIFIED here (crypto verdict identical with/without it),
    # but its STRUCTURE follows the published JSON Schema — in a v0.1 bundle `target` is the enum
    # receipt|preRegistration only (SPEC §7i: `statement` is exclusively for DETACHED decision
    # evidence). The docs promised "rejected as malformed (exit 2)"; the code now matches them.
    anchors_field = bundle.get("anchors")
    if anchors_field is not None:
        if not isinstance(anchors_field, list):
            raise BundleFormatError("field anchors must be a list")
        for i, entry in enumerate(anchors_field):
            if not isinstance(entry, dict):
                raise BundleFormatError(f"anchors[{i}] must be a JSON object")
            tgt = entry.get("target")
            if tgt not in ("receipt", "preRegistration"):
                raise BundleFormatError(
                    f"anchors[{i}].target {tgt!r} is not allowed in a proofbundle/v0.1 bundle "
                    "(receipt|preRegistration only; 'statement' is for detached decision evidence)")

    result = VerificationResult()
    payload = _b64d(_require(bundle, "payload_b64", "payload_b64"), "payload_b64")

    # 1. signature over the payload
    sig = _require_dict(_require(bundle, "signature", "signature"), "signature")
    _reject_unknown(sig, _SIG_KEYS, "signature")
    alg = sig.get("alg")
    if alg != "ed25519":
        raise UnsupportedError(f"signature alg {alg!r} not supported in v0.1")
    pub = _b64d(_require(sig, "public_key_b64", "signature.public_key_b64"), "signature.public_key_b64")
    raw_sig = _b64d(_require(sig, "sig_b64", "signature.sig_b64"), "signature.sig_b64")
    sig_ok = verify_ed25519(pub, raw_sig, payload)
    result.add("ed25519-signature", sig_ok, "payload signed by stated key" if sig_ok else "invalid signature")

    # 2. merkle inclusion of the payload
    mk = _require_dict(_require(bundle, "merkle", "merkle"), "merkle")
    _reject_unknown(mk, _MERKLE_KEYS, "merkle")
    _require_hash_alg(mk)   # presence + value both enforced by the shared helper
    leaf_index = _require_int(mk, "leaf_index", "merkle.leaf_index")
    tree_size = _require_int(mk, "tree_size", "merkle.tree_size")
    proof_list = _require(mk, "inclusion_proof_b64", "merkle.inclusion_proof_b64")   # required per SPEC §5
    if not isinstance(proof_list, list):
        raise BundleFormatError("field merkle.inclusion_proof_b64 must be a list")
    proof = [_b64d(p, "merkle.inclusion_proof_b64[]") for p in proof_list]
    root = _b64d(_require(mk, "root_b64", "merkle.root_b64"), "merkle.root_b64")
    incl_ok = merkle.verify_inclusion(payload, leaf_index, tree_size, proof, root)
    result.add(
        "merkle-inclusion",
        incl_ok,
        f"anchored at index {leaf_index} of {tree_size} (Merkle-consistent under the STATED root)"
        if incl_ok else "inclusion proof failed",
    )

    # 2b. P0-A (§6.2): relying-party root authentication. The stated root is NOT signed, so inclusion
    # alone does not authenticate it; only a bit-exact match against a root/size the relying party
    # obtained out of band does. Adds a check ONLY when the RP supplies an expectation — absent, root
    # authenticity is NOT_EVALUATED and the verdict is unchanged (backward-compatible).
    if expected_root_b64 is not None:
        exp_root = _b64d(expected_root_b64, "expected_root_b64")
        root_ok = hmac.compare_digest(root, exp_root)
        result.add("root-authenticity", root_ok,
                   "stated root matches the expected authenticated root" if root_ok
                   else "stated root does NOT match the expected root — possible root/rewrap substitution")
    if expected_tree_size is not None:
        # strict: a real int only — reject bool (1==True) and float (1==1.0), matching _require_int.
        size_ok = (isinstance(expected_tree_size, int) and not isinstance(expected_tree_size, bool)
                   and tree_size == expected_tree_size)
        result.add("tree-size", size_ok,
                   f"tree_size {tree_size} matches the expected size" if size_ok
                   else f"tree_size {tree_size} != expected {expected_tree_size} — possible tree-size substitution")

    # 3. optional SD-JWT selective disclosure credential
    sd = bundle.get("sd_jwt_vc")
    kb_binding_checked = False   # F4: did a KB-JWT (the aud/nonce carrier) actually get verified?
    if sd is not None:
        sd = _require_dict(sd, "sd_jwt_vc")
        _reject_unknown(sd, _SD_KEYS, "sd_jwt_vc")
        compact = _require(sd, "compact", "sd_jwt_vc.compact")
        if not isinstance(compact, str):   # malformed input → BundleFormatError, never a raw traceback
            raise BundleFormatError("field sd_jwt_vc.compact must be a string")
        issuer_pub = None
        if sd.get("issuer_public_key_b64"):
            issuer_pub = _b64d(sd["issuer_public_key_b64"], "sd_jwt_vc.issuer_public_key_b64")
        sd_res = verify_sd_jwt(compact, issuer_pub)
        result.add("sd-jwt-disclosures", sd_res["structure_ok"], sd_res["detail"])
        if sd_res["sig_checked"]:
            result.add(
                "sd-jwt-issuer-signature",
                sd_res["sig_ok"],
                "issuer signature valid" if sd_res["sig_ok"] else "issuer signature invalid",
            )
        else:
            # WP-C2 (6-lens review, Owner-GO breaking / secure-by-default): sd_jwt_vc sits OUTSIDE
            # payload_b64, so the bundle's Ed25519 signature does NOT cover it. A present sd_jwt_vc whose
            # ISSUER SIGNATURE was never verified (no sd_jwt_vc.issuer_public_key_b64) carries disclosures
            # anyone could have authored — previously .ok could still be True over attacker-chosen
            # "disclosed" values. Now a FAILING check makes .ok False (reason: unsigned); there is no
            # opt-out. Supply issuer_public_key_b64 to authenticate the disclosures.
            result.add(
                "sd-jwt-issuer-signature", False,
                "sd_jwt_vc present but no issuer_public_key_b64 — its disclosures are unauthenticated "
                "(reason: unsigned; the bundle signature does not cover sd_jwt_vc). Supply the issuer key.")
        # v1.2/v1.3, fail-closed: a KB-JWT that is PRESENT must verify (RFC 9901 §4.3), AND if the issuer
        # bound a `cnf` holder key (proof-of-possession REQUIRED) a presentation with NO KB-JWT is a bearer
        # downgrade — anyone who sees the disclosed SD-JWT could replay it — so that MUST fail. expected_aud/
        # expected_nonce (v1.3) enforce RFC 9901 §7.3 replay/audience binding when the relying party supplies
        # them. Bundles issued without `cnf` and with no KB-JWT verify exactly as before (backward-compatible).
        #
        # The holder-binding check is only MEANINGFUL when the issuer signature was actually verified: the `cnf`
        # holder key is declared INSIDE the issuer-signed JWT, so without a checked issuer signature an attacker
        # could forge the whole SD-JWT (issuer JWT + cnf + matching KB-JWT). Only run it when the issuer
        # public key was supplied AND its signature verified (release-review HIGH fix) — otherwise the SD-JWT is
        # unauthenticated and no holder-binding claim over it can be trusted.
        if sd_res.get("sig_checked") and sd_res.get("sig_ok"):
            sd_part, kb = split_key_binding(compact)
            if kb is not None:
                kb_res = verify_key_binding(compact, expected_aud=expected_aud, expected_nonce=expected_nonce)
                result.add("sd-jwt-key-binding", kb_res["ok"], kb_res["detail"])
                kb_binding_checked = True
            elif _issuer_requires_holder_binding(sd_part):
                result.add(
                    "sd-jwt-key-binding", False,
                    "issuer bound a holder key (cnf) but the presentation carries NO Key Binding JWT — "
                    "required proof-of-possession is missing (bearer downgrade, RFC 9901 §4.3)")
        elif not sd_res.get("sig_checked"):
            # v1.6 fail-closed (external review, CRITICAL): gating holder-binding on issuer
            # verification opened a KEY-OMISSION downgrade — strip the KB-JWT AND drop
            # issuer_public_key_b64, and a cnf-bound credential silently passed as a bearer
            # token. A `cnf`-carrying SD-JWT whose issuer cannot be verified is REFUSED, never
            # "structure-only passed". SD-JWTs without `cnf` keep the documented no-key
            # backward-compat path unchanged.
            sd_part, _ = split_key_binding(compact)
            if _issuer_requires_holder_binding(sd_part):
                result.add(
                    "sd-jwt-key-binding", False,
                    "SD-JWT declares a cnf holder key but NO issuer key was supplied — holder "
                    "binding is unverifiable, refusing (fail-closed; supply "
                    "sd_jwt_vc.issuer_public_key_b64)")

        # WP-C1 (6-lens review, Owner-GO): bind the sd_jwt_vc to THIS bundle. sd_jwt_vc is outside the
        # signed payload, so an issuer-VALID SD-JWT from bundle B can be swapped into bundle A (cross-receipt
        # credential substitution) — its always-open claims (passed/threshold/comparator/suite/issuer +
        # receipt root) must match A's own signed claim + merkle root, else the disclosures do NOT belong to
        # this bundle. Only meaningful once the issuer signature verified (an unsigned SD-JWT already fails C2).
        if sd_res.get("sig_checked") and sd_res.get("sig_ok"):
            import json as _json  # noqa: PLC0415
            from .sdjwt_issue import _jwt_payload as _sd_payload  # noqa: PLC0415
            from .sdjwt_issue import check_binds_bundle  # noqa: PLC0415
            try:
                _sd_p = _sd_payload(compact)
            except (BundleFormatError, ValueError, KeyError, IndexError):
                # F12: a duplicate-key payload yields {} here → the issuer-identity check is skipped, but the
                # bundle already fails at the sd-jwt-disclosures structure gate (verify_sd_jwt rejects the
                # duplicate) and check_binds_bundle returns False → net fail-closed.
                _sd_p = {}

            # WP-C1 (2nd-lens fix): the issuer signature verifies under sd_jwt_vc.issuer_public_key_b64,
            # but that key is ATTACKER-CHOSEN — it lives outside the bundle signature. A self-signed SD-JWT
            # that NAMES a trusted issuer in its always-open `issuer` claim while being signed by a DIFFERENT
            # key is a forged identity (valid signature, wrong signer). Bind the verifying key to the claimed
            # issuer: fingerprint(issuer_pub) MUST equal the disclosed `issuer`. Only when an issuer is
            # actually disclosed (an SD-JWT with no issuer claim asserts no identity to forge).
            _disc_issuer = _sd_p.get("issuer") if isinstance(_sd_p, dict) else None
            if _disc_issuer is not None and issuer_pub is not None:
                _verifying_fp = "ed25519:" + base64.b64encode(issuer_pub).decode("ascii")
                result.add(
                    "sd-jwt-issuer-identity", _disc_issuer == _verifying_fp,
                    "SD-JWT issuer key matches the disclosed issuer" if _disc_issuer == _verifying_fp else
                    "sd_jwt_vc issuer signature verifies under a key that is NOT the disclosed issuer "
                    "(reason: issuer-key-mismatch — forged identity: a valid signature by the wrong signer)")

            try:
                _claim = _json.loads(base64.b64decode(bundle["payload_b64"]).decode("utf-8"))
            except (ValueError, KeyError, TypeError):
                _claim = None
            _root = (bundle.get("merkle") or {}).get("root_b64")
            # only an eval-claim bundle carries the always-open fields check_binds_bundle compares; a
            # non-eval payload with an sd_jwt_vc is out of scope for this binding (nothing to bind against).
            if isinstance(_claim, dict) and _claim.get("schema") == "proofbundle/eval-claim/v0.1" and _root:
                bound = check_binds_bundle(compact, _claim, _root)
                result.add(
                    "sd-jwt-bundle-binding", bound,
                    "sd_jwt_vc always-open claims + receipt root match this bundle" if bound else
                    "sd_jwt_vc disclosures do NOT bind this bundle (reason: unbound/mismatch — cross-receipt "
                    "substitution; the SD-JWT's passed/threshold/comparator/suite/issuer/root differ from the "
                    "signed claim)")
            elif _sd_jwt_carries_eval_root_commitment(_sd_p):
                # N1 (audit 2026-07-13, L1 live PoC; discriminator hardened after pre-land L1 review): an
                # EVAL SD-JWT (issue_sd_jwt writes the always-open root commitment receipt.root_b64) MUST
                # bind to a proofbundle/eval-claim/v0.1 payload — check_binds_bundle above is the only
                # binding for it. Grafted onto a NON-eval payload it has nothing to bind against, so
                # previously the exact same issuer-valid eval SD-JWT verified CRYPTO: OK on ANY
                # opaque-payload bundle (cross-receipt substitution, sd_jwt_ok stayed true, zero operator
                # signal). Fail-closed (Reifegradpolitik §0.6: never a silent PASS for insecure legacy
                # behaviour). Keying on receipt.root_b64 (the real substitution vector) rather than a
                # word-match on generic keys catches a graft even when passed/threshold are moved into
                # disclosures, and never false-refuses a GENERIC SD-JWT-VC (iss/vct, no receipt commitment,
                # e.g. examples/example_bundle.json), which carries no eval anchoring claim and is out of
                # scope (backward-compatible).
                result.add(
                    "sd-jwt-bundle-binding", False,
                    "sd_jwt_vc carries an eval-claim root commitment (receipt.root_b64) but the signed "
                    "payload is not a proofbundle/eval-claim/v0.1 claim, so that anchoring claim cannot be "
                    "bound to this bundle (reason: unbindable eval SD-JWT — a valid issuer signature does not "
                    "make an unbound eval anchoring claim belong to this receipt; refused fail-closed)")

    # F4 (v1.9.2, fail-closed): supplying expected_aud/expected_nonce asks for RFC 9901 §7.3
    # replay/audience binding. A bundle with no verifiable KB-JWT (no sd_jwt_vc at all, or an
    # sd_jwt_vc without a Key Binding JWT) carries nothing to bind to — returning OK anyway is a
    # downgrade trap: the verifier believes the presentation was bound to its aud/nonce when it was
    # not. Refuse the binding it asked for but cannot be enforced. Verifiers that pass no expected_*
    # are unaffected (backward-compatible: the check only fires when a binding was actually requested).
    if (expected_aud is not None or expected_nonce is not None) and not kb_binding_checked:
        result.add(
            "sd-jwt-key-binding", False,
            "expected_aud/expected_nonce were supplied but the bundle carries no verifiable Key "
            "Binding JWT — the requested replay/audience binding cannot be enforced (fail-closed)")

    return result


def root_authenticity_summary(result: VerificationResult, *,
                              policy_authenticated_root: Optional[bool] = None,
                              policy_ok: Optional[bool] = None,
                              anchor_ok: Optional[bool] = None,
                              signer_trusted: Optional[bool] = None,
                              policy_warnings: Optional[list] = None,
                              policy_expired: Optional[bool] = None,
                              requires_identity_overlay: Optional[bool] = None,
                              public_transparency_ok: Optional[bool] = None,
                              replay_ok: Optional[bool] = None,
                              tree_context_authenticated: Optional[bool] = None,
                              checkpoint_authenticity: Optional[str] = None) -> dict:
    """Structured root-authenticity verdicts (P0-A §6.3), derived from a completed VerificationResult.

    Separates what Merkle inclusion actually proves from what it does NOT, as three-state strings so a
    consumer never mistakes 'not checked' for 'passed':

      payloadSignature   PASS/FAIL         — the payload is signed by the stated key
      merkleConsistency  PASS/FAIL         — the payload is Merkle-consistent under the STATED root
      rootAuthenticity   PASS/FAIL/NOT_EVALUATED — was the stated root authenticated against a
                         relying-party value (``expected_root``, or a policy's ``trusted_roots``)?
      publicTransparency NOT_EVALUATED     — a public-log receipt is the separate §10 profile
      safeForAutomation  bool              — True ONLY if the whole crypto verdict passed, the root was
                                             affirmatively authenticated, AND a supplied trust policy
                                             PASSED with a real signer pin (P0-B, audit 2026-07-13)
      automationBlockers list[str]         — every reason safeForAutomation is false, so a consumer
                                             keying off the flag sees exactly WHY (fail-closed)

    ``policy_authenticated_root`` folds the policy layer's root verdict in when no explicit
    ``root-authenticity`` check ran (e.g. the root matched a policy ``trusted_roots`` entry).
    ``policy_ok`` / ``anchor_ok`` are the relying-party gate verdicts (True/False/None=not-evaluated).
    P0-B: ``safeForAutomation`` is a GLOBAL trust verdict, so ``policy_ok`` must be True (a policy that
    passed) — ``None`` (no policy evaluated) can never make it true. ``policy_warnings`` (the vacuous
    'attributes to nobody' lint) forces it false too: a policy that pins no signer authorises no
    identity, so a crypto-valid, root-pinned receipt under it is NOT automation-safe.
    """
    by = {c.name: c.ok for c in result.checks}

    def _tri(name: str) -> str:
        return "PASS" if by.get(name) else ("FAIL" if name in by else "NOT_EVALUATED")

    if "root-authenticity" in by:
        root_auth = "PASS" if by["root-authenticity"] else "FAIL"
    elif policy_authenticated_root is True:
        root_auth = "PASS"
    elif policy_authenticated_root is False:
        root_auth = "FAIL"
    else:
        root_auth = "NOT_EVALUATED"

    # A-P0-1 §5.3: the differentiated tree-context verdicts. `root_auth` above is the root-BYTES
    # verdict; TREE_CONTEXT_AUTHENTICITY additionally requires that root and tree_size were
    # authenticated ATOMICALLY from one source (a signed checkpoint, a policy trusted_checkpoints
    # match, or an RP-supplied root+size PAIR). A naked root pin reaches at most
    # ROOT_BYTES_AUTHENTICITY: PASS — never TREE_CONTEXT_AUTHENTICITY: PASS (§5.5).
    if tree_context_authenticated is True:
        tree_context = "PASS"
    elif tree_context_authenticated is False:
        tree_context = "FAIL"
    else:
        tree_context = "NOT_EVALUATED"
    cp_auth = checkpoint_authenticity if checkpoint_authenticity in ("PASS", "FAIL") \
        else "NOT_EVALUATED"
    if tree_context == "PASS" and cp_auth == "PASS":
        root_trust_level = "CHECKPOINT"
    elif tree_context == "PASS":
        root_trust_level = "ROOT_AND_TREE_SIZE_PINNED"
    elif root_auth == "PASS":
        root_trust_level = "ROOT_BYTES_ONLY"
    else:
        root_trust_level = "NONE"
    # P0-B (audit 2026-07-13): the former `policy_ok is not False` let policy_ok=None (no policy
    # evaluated) through → a crypto-valid, root-pinned receipt looked automation-safe though NO trusted
    # signer was ever authorised. safeForAutomation is now a GLOBAL trust verdict: policy_ok must be True
    # AND carry no vacuous 'attributes to nobody' warning. Every failed condition is surfaced in
    # automationBlockers (fail-closed, so the flag is never a silent yes).
    # P0-B / AP-1 §5 (audit 2026-07-13): safeForAutomation is a GLOBAL trust verdict. Variant A (strict):
    # true ONLY when crypto passed, the root was authenticated, a supplied policy PASSED (policy_ok is
    # True — None/no-policy never qualifies), that policy actually PINS a trusted signer (signer_trusted),
    # and no required anchor / public-transparency / replay gate FAILED. automationBlockers enumerates
    # every reason it is false (fail-closed, never a silent yes). NOTE for 3.1.1: public_transparency_ok
    # and replay_ok are relying-party gates that are None (not-requested) on the current core — the §10
    # public-transparency policy section is 3.2.0, and replay (aud/nonce) already fails the crypto verdict
    # (CRYPTO_FAILED) when a required KB-JWT is absent — so these two blockers are defined for forward
    # compatibility and stay dormant unless a future policy layer supplies a False verdict.
    blockers: list[str] = []
    if not bool(result.ok):
        blockers.append("CRYPTO_FAILED")
    if root_auth != "PASS":
        blockers.append("ROOT_NOT_AUTHENTICATED")
    if tree_context != "PASS":
        # A-P0-1 §5.4: safeForAutomation requires the ATOMIC (root, tree_size) authentication —
        # root bytes alone cannot detect the 2→3-leaf relabel, so they never authorise automation.
        blockers.append("TREE_CONTEXT_NOT_AUTHENTICATED")
    if policy_ok is None:
        blockers.append("POLICY_NOT_EVALUATED")
    elif policy_ok is False:
        blockers.append("POLICY_FAILED")
    elif signer_trusted is not True and not requires_identity_overlay:
        blockers.append("SIGNER_NOT_PINNED")   # policy passed but pins no trusted identity (attributes to nobody)
    elif signer_trusted is True and policy_warnings:
        blockers.append("POLICY_WARNINGS_PRESENT")   # signer pinned yet the policy still warns (forward-compat)
    if requires_identity_overlay:
        # AP-2 §6.2 (L2 pre-land audit): a RAW template (requiresIdentityOverlay:true) is never automation-safe
        # — reported as its OWN blocker, not SIGNER_NOT_PINNED, which would be factually wrong when the template
        # actually does match a signer (the real reason is the un-cleared template-lifecycle flag). Independent
        # of the policy_ok chain since A-P0-2: the eval path now FAILS a raw template (policy:not_template →
        # POLICY_FAILED), and the honest template blocker must still be reported alongside it.
        blockers.append("TEMPLATE_NOT_INSTANTIATED")
    # AP-2 §6.4 lifecycle: an EXPIRED policy is unsafe to automate on even if it otherwise passed (a stale
    # signer pin the relying party has since rotated away from). Independent of the signer/warning chain so
    # it is reported alongside, never in place of, another reason.
    if policy_expired is True:
        blockers.append("POLICY_EXPIRED")
    if anchor_ok is False:
        blockers.append("ANCHOR_REQUIRED_FAILED")
    if public_transparency_ok is False:
        blockers.append("PUBLIC_TRANSPARENCY_REQUIRED_FAILED")
    if replay_ok is False:
        blockers.append("REPLAY_BINDING_REQUIRED_FAILED")
    return {
        "payloadSignature": _tri("ed25519-signature"),
        "merkleConsistency": _tri("merkle-inclusion"),
        # A-P0-1 §5.3: differentiated statuses. `rootAuthenticity` is kept as a WIRE-COMPAT ALIAS of
        # the root-BYTES verdict (it never asserted more than bytes); the undifferentiated reading
        # of it as full root trust is retired — automation keys off treeContextAuthenticity.
        "rootAuthenticity": root_auth,
        "rootBytesAuthenticity": root_auth,
        "treeContextAuthenticity": tree_context,
        "checkpointAuthenticity": cp_auth,
        "rootTrustLevel": root_trust_level,
        "publicTransparency": "NOT_EVALUATED",
        "safeForAutomation": not blockers,
        "automationBlockers": blockers,
    }


def recompute_merkle_root_b64(bundle: Union[dict, str]) -> dict:
    """Recompute the Merkle root from the bundle's own payload + inclusion proof (v1.2, issue #2).

    Debugging aid for ``proofbundle verify --verbose``: returns
    ``{"stated_b64": ..., "recomputed_b64": ...}`` where ``recomputed_b64`` is None when the
    proof cannot be evaluated (e.g. index out of range, proof too short/long). Performs the
    same strict format validation as :func:`verify_bundle` — malformed input raises
    ``BundleFormatError``, never a raw traceback.
    """
    if isinstance(bundle, str):
        bundle = load_bundle(bundle)
    if not isinstance(bundle, dict):
        raise BundleFormatError("bundle must be a JSON object")
    payload = _b64d(_require(bundle, "payload_b64", "payload_b64"), "payload_b64")
    mk = _require_dict(_require(bundle, "merkle", "merkle"), "merkle")
    # Validate hash_alg the SAME way verify_bundle does — REQUIRED, not silently defaulted, and the value
    # checked (release-review #13: the docstring claimed strict-as-verify_bundle but this defaulted a
    # missing hash_alg; the shared `_require_hash_alg` helper above keeps both call sites' presence AND
    # value checks from drifting apart).
    _require_hash_alg(mk)
    leaf_index = _require_int(mk, "leaf_index", "merkle.leaf_index")
    tree_size = _require_int(mk, "tree_size", "merkle.tree_size")
    proof_list = _require(mk, "inclusion_proof_b64", "merkle.inclusion_proof_b64")
    if not isinstance(proof_list, list):
        raise BundleFormatError("field merkle.inclusion_proof_b64 must be a list")
    proof = [_b64d(p, "merkle.inclusion_proof_b64[]") for p in proof_list]
    # Display the stated root in CANONICAL base64 (re-encode from the decoded bytes), so a non-canonical but
    # byte-equal stated root does not read as a spurious mismatch next to the canonical recomputed root (LOW #10/#15).
    stated_b64 = base64.b64encode(_b64d(_require(mk, "root_b64", "merkle.root_b64"), "merkle.root_b64")).decode("ascii")
    try:
        recomputed = merkle.root_from_inclusion(
            leaf_index, tree_size, merkle.leaf_hash(payload), proof)
        recomputed_b64 = base64.b64encode(recomputed).decode("ascii")
    except ValueError as exc:
        return {"stated_b64": stated_b64, "recomputed_b64": None, "detail": str(exc)}
    return {"stated_b64": stated_b64, "recomputed_b64": recomputed_b64, "detail": ""}
