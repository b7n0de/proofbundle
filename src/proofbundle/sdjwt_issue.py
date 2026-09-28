"""SD-JWT issuance per RFC 9901 — the differentiation feature (v0.5).

Issue an eval receipt so a holder can disclose `passed` + `threshold` while WITHHOLDING the exact score
and the identifier openings. The existing verifier (proofbundle.sdjwt) stays; this adds issuance.

Source of truth: the signed canonical bundle payload (evalclaim) is the ONLY truth. This SD-JWT is a
derived view — its always-open claims are copied bit-exact from that payload, and it binds the bundle
anchor via `receipt.root_b64`. Sign the SD-JWT with the SAME Ed25519 key that signed the bundle (matching
the `issuer` field). A holder cannot lift a claim under a different key.

Always-open (plaintext JWT claims, NEVER a disclosure): passed, threshold, comparator, suite, issuer,
receipt.root_b64. Selectively-disclosable (via `_sd` + disclosures): the exact metric value, ci95, and
the identifier-commitment openings (identifier + salt).

RFC 9901 §4.2.4.1 digest byte-chain (the subtle, load-bearing detail): for each disclosable field, a
CSPRNG salt of ≥128 bit (base64url); the disclosure is base64url(UTF-8(JSON array [salt, name, value]));
the digest placed in `_sd` is **base64url(SHA-256(ASCII bytes of the base64url-ENCODED disclosure
string)))** — hashed over the ENCODED string, NOT over the JSON bytes. `_sd_alg` = "sha-256" at the top
level. The JWT is signed with EdDSA. Compact form is tilde-separated: JWT~disclosure1~...~ (trailing ~).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any, Optional, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ._strict_json import loads_strict
from .budget import render_safe
from .canonical import _feld_von, _plain_for_jcs, _zeichen_von
from .errors import BundleFormatError, ProofBundleError
from ._wire_b64 import decode_b64url
from ._membership import as_dict, is_member
from ._verdict import require_bool_verdict, require_eval_claim
from .signature import TRUST_ANCHOR_REFUSAL, ed25519_trust_anchor_weakness, plain_bytes

SD_ALG = "sha-256"
# sd_hash / disclosure digests use the SD-JWT's declared _sd_alg — the kbjwt verifier reads _sd_alg from the
# issuer payload, so the presenter MUST hash with the same algorithm (not a hardcoded sha256). Release-review fix.
_HASH_BY_SD_ALG = {"sha-256": hashlib.sha256, "sha-384": hashlib.sha384, "sha-512": hashlib.sha512}
_SALT_BYTES = 16  # 128 bit

# SD-JWT VC syntactic markers (v1.3). draft-ietf-oauth-sd-jwt-vc-17 (2026-07) is at the IESG
# ("Publication Requested"), not yet an RFC — we adopt ONLY its four stable interop markers:
# header `typ: dc+sd-jwt` (media type application/dc+sd-jwt; stable since the vc+sd-jwt rename,
# though NOT yet IANA-registered — registration lands with RFC publication), a `vct` type URI,
# the optional `status` claim (Token Status List), and `cnf` (already present since v1.2). The
# type-metadata resolution machinery is deliberately NOT implemented (network-bound, still churning).
SD_JWT_TYP = "dc+sd-jwt"
DEFAULT_VCT = "https://b7n0de.com/proofbundle/vct/eval-receipt/v1"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_disclosure(name: str, value, salt_b64: str) -> tuple[str, str]:
    """Return (disclosure_b64url, digest_b64url) per RFC 9901 §4.2.4.1.

    The digest hashes the ASCII bytes of the base64url-ENCODED disclosure string (not the JSON bytes)."""
    disclosure_json = json.dumps([salt_b64, name, value])            # array [salt, name, value]
    disclosure_b64 = _b64url(disclosure_json.encode("utf-8"))
    digest = _b64url(hashlib.sha256(disclosure_b64.encode("ascii")).digest())
    return disclosure_b64, digest


def issue_sd_jwt(claim: dict, signer: Ed25519PrivateKey, *, root_b64: str,
                 exact_score: Optional[str] = None, ci95: Optional[Sequence[str]] = None,
                 model_id_opening: Optional[Sequence] = None,
                 dataset_id_opening: Optional[Sequence] = None,
                 holder_public_key: Optional[bytes] = None,
                 vct: str = DEFAULT_VCT,
                 status: Optional[dict] = None) -> str:
    """Issue a compact SD-JWT for the eval claim, signed with `signer` (must match claim['issuer']).

    Openings are (identifier, salt_hex) pairs the issuer may later reveal; `exact_score`/`ci95` are the
    withheld numeric detail. All extras are selectively-disclosable; the pass/threshold facts are open.

    `holder_public_key` (raw 32-byte Ed25519, v1.2) binds a holder key via the `cnf.jwk` claim
    (RFC 7800), enabling Key Binding JWT presentations verified by :mod:`proofbundle.kbjwt`. A key
    the trust-anchor rule refuses (low-order or non-canonical, SPEC section 4b) raises ValueError
    before anything is signed. The key is `bytes` or `bytearray`, read once from its own storage
    (`signature.plain_bytes`); any other type raises ValueError, a `memoryview`, an `array` or a
    numpy array included: pass `bytes(...)` of it.

    v1.3 (SD-JWT VC markers): the header `typ` is ``dc+sd-jwt`` and the payload carries a `vct`
    type URI (override per profile). `status` (build via
    :func:`proofbundle.statuslist.status_claim`) points the receipt into a Token Status List;
    verifying a bundled list snapshot lives in :mod:`proofbundle.statuslist`.

    The claim goes through the rule ``decode_eval_claim`` applies before anything is signed, and the
    always-open values are read from the claim as parsed back from its canonical bytes (see
    ``_verdict.require_eval_claim``). Measured at 62e8bbab: this function signed a claim with
    comparator ``==``, threshold ``inf``, n=-1, commit_alg ``md5-plain`` and schema ``x``.

    The two withheld numbers are judged as well: ``ci95`` by the claim rule's own ``ci95`` check, and
    ``exact_score`` as a plain decimal string, the form ``build_eval_claim`` requires of ``score``.
    Measured at 835df85b: disclosures ``["inf", "nan"]`` and ``"1e400"`` were signed. The openings
    are not judged: no verifier in this package reads them; a relying party checks a presented pair
    against the commitment with ``evalclaim.verify_commitment``.

    Each argument that is checked is read ONCE, into a plain value, and that value is judged and
    signed. Measured at 6893586f: ``ci95`` was judged on one iteration of the caller's object and
    signed from a second, so a list subclass whose first iteration gave ["0.1", "0.2"] got
    ["inf", "nan"] signed, floats got [NaN, Infinity] signed, and one whose ``__len__`` said 2 got
    three values signed; a ``holder_public_key`` whose ``__len__`` said 32 got 64 bytes signed into
    ``cnf``; a ``status`` whose ``__contains__`` claimed a ``status_list`` got signed without one.

    A disclosed ``exact_score`` must earn the always-open verdict: the claim's comparator and
    threshold map it to the claim's ``passed``. Measured at 6893586f: ``exact_score`` "0.10" was
    signed beside passed=true for ``>=`` 0.80.

    EVERY JSON-SHAPED ARGUMENT IS READ ONCE, into the plain copy (`canonical._plain_for_jcs`), and
    only the copy is judged, serialized and signed (round 8): the claim (inside
    ``require_eval_claim``), ``root_b64``, ``vct``, ``ci95``, ``exact_score``, ``status`` and the two
    openings. A value that is not a JSON type is refused, naming where it sits. ``root_b64`` and
    ``vct`` must be strings. Measured at c8205c18: ``list(ci95)`` called a list subclass's own
    ``__iter__``; ``str.__str__`` raised a raw TypeError for an ``exact_score`` or ``ci95`` item whose
    ``__class__`` claims str; ``isinstance(status, dict)`` ran a ``__class__`` property of the status;
    a ``status`` holding a dict whose metaclass hides ``dict`` from its MRO was signed through that
    dict's own ``items()``; and ``root_b64`` and ``vct`` went unjudged into ``json.dumps``, so None, a
    number or a list was signed and any other object raised json's TypeError.
    """
    claim = require_eval_claim(claim, wo="issue_sd_jwt")
    from .canonical import _plain_for_jcs  # noqa: PLC0415

    def _fehler(art: type):
        """The refusal of the copy, with this function's name in front. Called only on a refusal, so
        the copy below starts at the same stack depth as before (the deepest `status` that signs
        depends on it)."""
        return lambda text: art(f"issue_sd_jwt: {text}")

    zeichen = {}
    for name, wert in (("root_b64", root_b64), ("vct", vct)):
        kopie = _plain_for_jcs(wert, _fehler(ValueError), name)
        if type(kopie) is not str:
            raise ValueError(f"issue_sd_jwt: {name} must be a string, got {type(kopie).__name__}")
        zeichen[name] = kopie
    root_b64, vct = zeichen["root_b64"], zeichen["vct"]
    # THE ISSUER VALUE IS NOT JUDGED HERE, on purpose. The claim rule requires the field and leaves
    # its value to the issuer binding, which compares it with the key that signed a BUNDLE; this
    # function holds no bundle, and its signer need not be the claim's issuer as far as issuance
    # goes. A relying party learns the mismatch where it verifies: `verify_bundle` reports
    # `sd-jwt-issuer-identity` and `sd-jwt-bundle-binding` as failed (measured at 835df85b with the
    # SD-JWT issued over another key's fingerprint).
    from .evalclaim import (  # noqa: PLC0415 - evalclaim imports the bundle core
        _decimal_violation, _field_violation, _passed_by,
    )
    # One read each, then only the plain value, which the rule, the verdict comparison and the
    # disclosure all read. A tuple is read as the list it is written as; a value that is not a JSON
    # type is refused by the copy, with the argument's name.
    if ci95 is not None:
        ci95 = _plain_for_jcs(ci95, _fehler(BundleFormatError), "ci95")
    if exact_score is not None:
        exact_score = _plain_for_jcs(exact_score, _fehler(BundleFormatError), "exact_score")
    for grund in (None if ci95 is None else _field_violation({"ci95": ci95}),
                  None if exact_score is None else _decimal_violation("exact_score", exact_score)):
        if grund is not None:
            raise BundleFormatError(f"issue_sd_jwt: {grund}")
    always_open = {
        # NOT `claim["passed"]`: the value is SIGNED a few lines below, so its type is established here
        # rather than assumed, and the VALIDATED value is used rather than a second read of the field
        # (R-B4, CWE-1287). The establisher lives in `_verdict` because it used to live here AND in
        # `intoto.py` as two independent copies — see that module for why one file is not one class.
        #
        # WHY THIS SITE IS THE WORST OF THE SIX, kept here because `_verdict`'s shared message can no
        # longer say it: the four `intoto` sites build a statement a caller MAY then sign; this one
        # copies `passed` into the ALWAYS-OPEN JWT claims and `signer.sign` puts a signature over it
        # immediately. Measured 2026-09-24 at tag `v6.1.0` (`dcac5aee`): `passed` as the STRING "false"
        # was issued verbatim into a signed SD-JWT, and `check_binds_bundle` accepted it as bound,
        # because that check compares the field to the bundle payload for EQUALITY and both sides
        # carried the same string. A relying party that reads the always-open `passed` the way Python
        # reads truthiness gets a pass out of a genuinely valid signature. Nothing downstream can
        # repair that; the type has to be established before the signature exists.
        #
        # WHY IT WAS NOT IN THE FIRST PASS OF R-B4, stated because the omission is the lesson.
        # `tests/test_never_raise_surface_family_property.py:188` classifies `issue_*` as a producer
        # that "builds an artefact from its OWN already-checked values", and line 197 says whoever
        # turns such a function into a consumer of untrusted input must move it into the denominator.
        # For `claim` that premise was simply false: the dict comes from the caller and no boundary
        # stands between it and the signature. The classification was right about the family and wrong
        # about this argument, so the fix makes the premise TRUE here rather than reclassifying the
        # function — raising on a bad caller argument is, per that same line 190, correct for a producer.
        #
        # AND THIS FUNCTION HAS TWO DISJOINT REFUSAL FAMILIES. The refusal above is a
        # `BundleFormatError`, which is NOT a `ValueError` (measured), while the `status` and
        # `holder_public_key` checks below raise a genuine `ValueError`. No single `except` covers all
        # refusals of `issue_sd_jwt`, and a third form exists one layer out where
        # `evalclaim.decode_eval_claim` refuses by returning None and raising nothing. The three are
        # measured in `tests/test_abweisungsformen_sind_drei.py`; an earlier wording here promised the
        # opposite and was wrong on the day it landed.
        "passed": require_bool_verdict(claim, wo="issue_sd_jwt"), "threshold": claim["threshold"],
        "comparator": claim["comparator"], "suite": claim["suite"],
        "issuer": claim["issuer"], "receipt": {"root_b64": root_b64},
        "vct": vct,
    }
    if exact_score is not None:
        # THE DISCLOSURE MUST NOT CONTRADICT THE VERDICT BESIDE IT, the rule `intoto` holds for a
        # test-result `result` against the `passed` annotation. The score has passed the decimal
        # check above, and the comparator and threshold are the claim's, judged by the claim rule.
        ergibt = _passed_by(exact_score, claim["comparator"], claim["threshold"])
        if ergibt is not always_open["passed"]:
            raise BundleFormatError(
                f"issue_sd_jwt: exact_score {render_safe(exact_score)} with comparator "
                f"{render_safe(claim['comparator'])} and threshold {render_safe(claim['threshold'])} "
                f"gives passed={ergibt}, and the claim says passed={always_open['passed']}; a "
                "disclosure that contradicts the always-open verdict is not signed")
    if status is not None:
        # READ ONCE, from its storage (lens run 8 at fddc00f4, finding B): the check asked the caller's
        # `__contains__`, the payload wrote the stored items, so a dict subclass answering True for
        # `"status_list"` while holding none was signed without one. The plain copy is what is checked
        # and what is signed.
        # With every key as its characters (`canonical._plain_for_jcs`): lens run 4 at c3ca546b:
        # `dict(status)` kept a `str` subclass key whose `__hash__` and `__eq__` claimed to be
        # "status_list", so the membership test passed and the signed status carried another key; a
        # non-string key or two keys equal as characters are refused. A circular or too deeply nested
        # status is this ValueError too (lens run 5 at 5a21b199: a raw KeyError and a raw
        # RecursionError). The type is the object's own, not `isinstance`, which reads `__class__`
        # (round 8).
        if not issubclass(type(status), dict):
            raise ValueError("status must be a dict with a status_list member "
                             "(use proofbundle.statuslist.status_claim)")
        from ._plain_value import plain_json  # noqa: PLC0415
        status = plain_json(status, what="status", error=ValueError)
        status = _plain_for_jcs(status, _fehler(ValueError), "status")
        if type(status) is not dict or "status_list" not in status:
            raise ValueError("status must be a dict with a status_list member "
                             "(use proofbundle.statuslist.status_claim)")
        always_open["status"] = status
    if holder_public_key is not None:
        # READ ONCE, AND ONLY WHAT WAS READ IS JUDGED AND WRITTEN (lens run 7 at 75c3aa48, F1). The rule
        # read the key through `len()` and `bytes()`, the caller's `__len__` and `__bytes__`, and
        # `_b64url` wrote the key's own buffer: a `bytes` or `bytearray` subclass whose `__bytes__`
        # returns a real key while its own bytes are the identity point passed and was bound, and under
        # v6.0.0 and v6.1.0 a Key Binding JWT signed by nobody verified against it. The one value read
        # here is judged, measured and written; no method of the caller's runs.
        schluessel = plain_bytes(holder_public_key)
        if schluessel is None:
            # F3 of the same run: a memoryview, an `array('B')`, a ctypes byte array or a numpy uint8
            # array holding a real key was written at a4e2fa5c and was refused at 75c3aa48 with the
            # rule's length reason, which is wrong for 32 bytes. It stays refused, for its type.
            raise ValueError("holder_public_key must be bytes or bytearray holding a raw 32-byte "
                             "Ed25519 public key; a buffer of another type is not read, pass bytes(...) "
                             "of it")
        if len(schluessel) != 32:
            raise ValueError("holder_public_key must be a raw 32-byte Ed25519 public key")
        # THE HOLDER KEY IS AUTHORISED HERE, so it gets the trust-anchor rule before it is written and
        # signed, the rule `kbjwt.verify_key_binding` applies to the same `cnf.jwk` (SPEC section 4b).
        # Only the length was checked, so a small-order or non-canonical key was bound as the holder:
        # measured at a4e2fa5c for all 13 weak encodings of the contract, and at the tags v6.0.0 and
        # v6.1.0, where the same lines stand and a Key Binding JWT signed by nobody (R = identity,
        # S = 0) under the identity point verified with "key binding valid". An issuer that binds a key
        # nobody holds vouches for a possession no one can prove, so the key is refused where it enters.
        schwaeche = ed25519_trust_anchor_weakness(schluessel)
        if schwaeche is not None:
            raise ValueError(f"holder_public_key is a {schwaeche} Ed25519 key, refused as a trusted key "
                             f"before it is bound: {TRUST_ANCHOR_REFUSAL[schwaeche]}")
        always_open["cnf"] = {"jwk": {"kty": "OKP", "crv": "Ed25519",
                                      "x": _b64url(schluessel)}}
    disclosures: list[str] = []
    sd_digests: list[str] = []

    def _add(name: str, value):
        d, dig = _make_disclosure(name, value, _b64url(os.urandom(_SALT_BYTES)))
        disclosures.append(d)
        sd_digests.append(dig)

    if exact_score is not None:
        _add("exact_score", exact_score)
    if ci95 is not None:
        _add("ci95", ci95)            # the plain list judged above, not a second read
    for name, oeffnung in (("model_id_opening", model_id_opening),
                           ("dataset_id_opening", dataset_id_opening)):
        if oeffnung is None:
            continue
        # The opening is not judged (see above), but it is read once, as a JSON value, and written
        # as that copy. `list()` then runs on the copy, so a list, a tuple, a string and a JSON object
        # give the list they gave before. `list()` of the caller's object ran its own `__iter__` and
        # accepted any iterable (bytes, a set, a generator); those are refused as not JSON values.
        kopie = _plain_for_jcs(oeffnung, _fehler(ValueError), name)
        if type(kopie) is not list and type(kopie) is not str and type(kopie) is not dict:
            raise ValueError(f"issue_sd_jwt: {name} must be a sequence such as "
                             f"(identifier, salt_hex), got {type(kopie).__name__}")
        # The serializer's own depth, as for `status` below (round 9): the disclosure's json.dumps
        # starts a few frames below the copy, so an opening nested within those frames of the copy's
        # limit passed the copy and raised a raw RecursionError there. Measured at ee489403 from one
        # caller: `model_id_opening` 988 to 991 levels deep and `dataset_id_opening` 989 to 992.
        # Caught here, inline, so no frame is added before the serializer.
        try:
            _add(name, list(kopie))
        except RecursionError as exc:
            raise ValueError(f"issue_sd_jwt: {name}: the value nests too deep to serialize") from exc

    payload = dict(always_open)
    if sd_digests:
        payload["_sd"] = sd_digests
        payload["_sd_alg"] = SD_ALG

    header = {"alg": "EdDSA", "typ": SD_JWT_TYP}
    try:
        nutzlast = json.dumps(payload)
    except RecursionError as exc:
        # The serializer's own depth, the one refusal the copy of `status` cannot give: the copy reads
        # as deep as the interpreter recurses, and json.dumps starts a few frames further down. Measured
        # on Python 3.10.12 with the copy's depth refusal in place: a status nested within two levels
        # of that limit passed the copy and raised a raw RecursionError here. `status` is the member
        # meant to hold nested values; the claim values are the read-back claim, which the verifier's
        # reader bounds at 64 levels.
        raise ValueError("the SD-JWT payload nests too deep to serialize") from exc
    signing_input = _b64url(json.dumps(header).encode("utf-8")) + "." + _b64url(nutzlast.encode("utf-8"))
    signature = signer.sign(signing_input.encode("ascii"))
    jwt = signing_input + "." + _b64url(signature)

    # compact: JWT ~ disclosure1 ~ ... ~ (trailing tilde, no key-binding JWT in v0.5)
    return "~".join([jwt, *disclosures]) + "~"


def present_with_key_binding(compact: str, holder_signer: Ed25519PrivateKey, *,
                             aud: str, nonce: str, iat: int) -> str:
    """Append a Key Binding JWT to a compact SD-JWT presentation (RFC 9901 §4.3, v1.2).

    ``compact`` must end with ``~`` (no KB yet); the holder signs over its own header/payload,
    where ``sd_hash`` commits to the exact presented ``JWT~disclosures...~`` ASCII bytes with the
    SD-JWT's ``_sd_alg`` hash — so dropping or swapping a disclosure after signing is detectable.
    ``iat`` is the POSIX issuance time chosen by the holder (explicit, not sampled here, so
    presentations are reproducible in tests).

    The compact is presented byte for byte as handed, and ``sd_hash`` is computed over exactly the
    bytes this function emits. The issuer JWT belongs to a foreign issuer and is never rewritten, an
    ES256 signature with a high s included (finding D1, owner decision 2026-09-26). The one
    signature this function makes is the holder's EdDSA signature over the KB-JWT.
    """
    # THE PRESENTED COMPACT AND THE TIME ARE READ ONCE (lens run 8, the sweep of finding B): the tilde
    # check, the payload read and the `sd_hash` went through the caller's `endswith`, `split` and
    # `encode`, and the presentation was built with its `__add__`, so what was hashed could differ from
    # what was presented. Now one exact `str` is checked, hashed and extended, and `iat` is an exact
    # `int` (a subclass of `int` is refused, like every number a producer both checks and writes).
    # Round 12 found the same at cd5d39f4: a `str` subclass's own `encode` fed sd_hash and its own
    # `__add__` wrote the result.
    from ._plain_value import plain_int  # noqa: PLC0415
    from .signature import plain_text  # noqa: PLC0415
    compact_text = plain_text(compact)
    if compact_text is None or not compact_text.endswith("~"):
        raise ValueError("compact SD-JWT already carries a key binding JWT (or is malformed)")
    compact = compact_text
    if plain_int(iat) is None:
        raise ValueError("iat must be a POSIX timestamp integer")
    # sd_hash MUST use the SD-JWT's OWN declared _sd_alg (read from the presented compact's issuer payload),
    # matching the kbjwt verifier — not a hardcoded module constant (release-review fix #9/#10).
    # adversarial re-audit round 3: a node-heavy/oversized issuer payload makes _jwt_payload raise
    # BudgetExceeded (a ProofBundleError) — map it to this constructor's DOCUMENTED ValueError (like the
    # "or is malformed" branch above), so a bad compact never leaks a foreign exception type to the holder.
    try:
        _issuer_payload = _jwt_payload(compact)
    except ProofBundleError as exc:
        raise ValueError(f"presented SD-JWT issuer payload is malformed or oversized: {exc}") from exc
    sd_alg = _issuer_payload.get("_sd_alg", SD_ALG)
    if not is_member(sd_alg, _HASH_BY_SD_ALG):
        raise ValueError(f"unsupported _sd_alg {sd_alg!r} in the presented SD-JWT")
    sd_hash = _b64url(_HASH_BY_SD_ALG[sd_alg](compact.encode("ascii")).digest())
    header = {"alg": "EdDSA", "typ": "kb+jwt"}
    payload = {"iat": iat, "aud": aud, "nonce": nonce, "sd_hash": sd_hash}
    signing_input = _b64url(json.dumps(header).encode("utf-8")) + "." + _b64url(json.dumps(payload).encode("utf-8"))
    signature = holder_signer.sign(signing_input.encode("ascii"))
    return compact + signing_input + "." + _b64url(signature)


def issuer_matches(claim: dict, signer: Ed25519PrivateKey) -> bool:
    """True iff the claim's issuer fingerprint equals the signer's public key (bundle↔SD-JWT same key)."""
    raw = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    # The stored issuer by its characters (round 12): neither a dict subclass's own `get` nor a `str`
    # subclass's own `__eq__` decides the match.
    issuer = _zeichen_von(_feld_von(claim, "issuer"))
    return issuer == "ed25519:" + base64.b64encode(raw).decode("ascii")


def _jwt_payload(compact: str) -> dict:
    """Decode the always-open JWT payload of a compact SD-JWT (the part before the first '~').

    F12 (2026-07-12): loads_strict, so a DUPLICATE key raises BundleFormatError (the always-open claims
    read here — issuer/passed/threshold/... — must not silently last-wins across implementations). The
    verify-time callers (check_binds_bundle, bundle.py's identity check) catch it fail-closed."""
    jwt = compact.split("~", 1)[0]
    payload_b64 = jwt.split(".")[1]
    # JWS segments are unpadded base64url; decode_b64url refuses a padded spelling (one wire form).
    entschluesselt = loads_strict(decode_b64url(payload_b64).decode("utf-8"))
    if not isinstance(entschluesselt, dict):
        # A-16 neighbour (2026-09-19): THE SAME CLASS the `as_dict` at check_binds_bundle patches at the
        # ACCESS site — but `present_with_key_binding` reads `_issuer_payload.get("_sd_alg", ...)` WITHOUT
        # it, so a compact whose payload segment is `[]`/`"x"`/`1` raised a bare AttributeError past an
        # `except ProofBundleError`. Patching each access site leaves the next caller to rediscover the
        # hole; the annotation is enforced here instead. BundleFormatError is a ProofBundleError, which
        # BOTH existing callers already catch — no call-site change, and the documented ValueError /
        # fail-closed False stay exactly as they were.
        raise BundleFormatError(
            f"SD-JWT payload must be a JSON object, got {type(entschluesselt).__name__} (malformed)")
    return entschluesselt


def check_binds_bundle(compact: str, claim: dict, root_b64: str) -> bool:
    """No-Fake binding: the SD-JWT's always-open claims MUST match the signed bundle payload bit-exact and
    bind its merkle root. A derived SD-JWT that diverges from its bundle source of truth is rejected.

    ``root_b64`` is compared by its characters (round 10, `canonical._zeichen_von`), with the root the
    SD-JWT carries as a string; a ``root_b64`` that is no string never binds. Measured at 493c2f86: a
    ``str`` subclass holding another root whose ``__eq__`` answers True, and an object of another type
    whose ``__eq__`` answers True, each bound an SD-JWT to a root it does not carry."""
    wurzel = _zeichen_von(root_b64)
    # The presentation and the claim are read once, by what they store (round 12): the fields compared
    # are the claim's stored values and the SD-JWT's own characters, and no `__ne__` of a `str`
    # subclass value and no `get` of a dict subclass decides the binding.
    compact = _zeichen_von(compact) if _zeichen_von(compact) is not None else compact
    gelesen: Any
    try:
        gelesen = _plain_for_jcs(claim, ValueError) if issubclass(type(claim), dict) else None
    except ValueError:
        gelesen = None
    if type(compact) is not str or wurzel is None or gelesen is None:   # `type()` (round 12)
        # adversarial re-audit round 7: a non-str presented `compact` is a fail-closed False, not a raw
        # AttributeError from compact.split('~') in _jwt_payload — the except tuple below omits AttributeError/
        # TypeError, and this verify-side check_* is the peer the flagship verify_bundle calls.
        return False
    try:
        # as_dict, not the bare return: _jwt_payload is annotated -> dict but decodes attacker JSON, so a
        # payload that is a bare array/scalar returns a non-dict and crashed `p.get(field)` below with a
        # raw AttributeError out of the flagship verify_bundle path (deep gate iter9 Linse A neighbor —
        # only `p.get("receipt")` was guarded, `p` itself was not). A non-dict payload can never bind.
        p = as_dict(_jwt_payload(compact))
    except (ProofBundleError, ValueError, KeyError, IndexError):
        # a duplicate-key (BundleFormatError) or malformed payload cannot bind → False, fail-closed (F12).
        # adversarial re-audit round 3: the BASE ProofBundleError also catches loads_strict's SIBLING
        # BudgetExceeded on a node-heavy compact, which `except BundleFormatError` let escape verify.
        return False
    # `claim` is an attacker-controllable, only-schema-checked bundle payload — read every field with
    # .get() (WP-C1 6-lens review): a missing field must yield a mismatch (unbound → False), never a
    # raw KeyError traceback out of the verify path. Guarding against `None == None` matching a genuinely
    # absent SD-JWT field would be a false bind, so a claim missing a required field can never bind.
    for field in ("passed", "threshold", "comparator", "suite", "issuer"):
        if field not in gelesen or p.get(field) != gelesen.get(field):
            return False
    # as_dict, not `(x or {})`: a truthy non-dict `receipt` (str/list/int/True from attacker JSON) slips
    # through the falsy-only idiom and crashes the downstream .get with a raw AttributeError out of the
    # flagship verify_bundle path (deep gate iter9 Linse A). as_dict closes the class.
    gebunden = as_dict(p.get("receipt")).get("root_b64")
    return type(gebunden) is str and gebunden == wurzel
