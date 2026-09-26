"""Offline verification of Agent Governance Toolkit (AGT) MCP governance receipts.

WHAT THIS IS. AGT (github.com/microsoft/agent-governance-toolkit, MIT) emits signed receipts for
MCP tool calls: an Ed25519 signature over a canonical JSON payload, optionally a second signature
from a separate authorizer, and a `parent_receipt_hash` chain link. This module verifies such a
receipt WITHOUT AGT installed and without network access, from the receipt JSON alone.

NO AGT CODE IS COPIED. The format was read from the published tree at commit
``a917ad4ac04aff11a5e9e21f6a26b91642b750cd`` (2026-09-24) and re-derived here; the wire format is
the interface, and an interface can be re-implemented. AGT is MIT, Copyright (c) Microsoft
Corporation. The conformance vectors in ``tests/`` are produced by our own generator, not taken
from AGT.

THE ONE THING A READER MUST KNOW, and it is the reason this module exists in this shape.
AGT's ``canonical_payload`` carries the docstring "RFC 8785 JCS canonical JSON" and is implemented
as ``json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)``. Those two are NOT the
same serializer, and they diverge on the field every receipt carries. Measured 2026-09-23 on a
receipt produced by AGT's own signer:

    timestamp 1758600000.0   json.dumps -> 1758600000.0     RFC 8785 -> 1758600000
    payload_hash in receipt  f35ba4cf191963b9…  == sha256(json.dumps form)
    sha256(RFC 8785 form)    f7d770b4e6c1fff4…  != the above
    Ed25519 signature        valid against the json.dumps form, REJECTED against RFC 8785

So a verifier that implements the DOCUMENTED format rejects valid receipts. This module therefore
verifies against the form AGT actually signs, and says so, rather than quietly accepting whichever
of the two happens to match. Silently trying both would be the very re-interpretation this house
forbids: it would turn "the receipt is valid" into "one of two readings of the receipt is valid",
and a reader could not tell which.

WHAT HAPPENS THE DAY AGT SWITCHES TO REAL JCS, because an independent review asked and the answer
is not "try both". A receipt carries no canonical-form version, so the form cannot be read off the
document; it has to be a decision the verifier states. The migration is therefore the same one
this house already made for its own wire: name BOTH forms, default to absence meaning the older
one, and never let an unlabelled receipt silently resolve to the newer. Until AGT emits a form
marker there is nothing to switch on, and a second attempt would accept a receipt under a form its
issuer never claimed. The trigger is already wired rather than left to memory:
``test_die_gesignte_form_ist_sortkeys_json_nicht_rfc8785`` goes RED the day the two forms agree,
and that red is the signal to add the second named form.

EXIT CODES follow the house contract used by ``proofbundle verify`` (WP-B2): 0 when the receipt
verifies, 1 on a cryptographic or structural failure, 2 on malformed input, 3 when the crypto is
sound but a supplied relying-party requirement (a trusted authorizer key, an expiry horizon) is not
met. The split matters: a receipt can be perfectly signed and still not satisfy the policy a
relying party brings to it, and those two are different answers.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Optional, Sequence

from .._membership import is_member
from ..errors import VerificationResult
from ..signature import TRUST_ANCHOR_REFUSAL, ed25519_trust_anchor_weakness, verify_ed25519_pinned

__all__ = [
    "AGT_AUTHORIZATION_TYPE",
    "AGT_CANONICAL_FORM",
    "AGTReceiptError",
    "canonical_payload",
    "canonical_authorization_payload",
    "payload_hash",
    "verify_agt_receipt",
    "verify_agt_receipt_chain",
]

#: The type URI AGT binds into the external-authorization payload. Read from the tree, not invented.
AGT_AUTHORIZATION_TYPE = "https://agent-governance.org/receipts/external-authorization/v1"

#: The serializer AGT actually signs with. NAMED, because AGT's own docstring names a different one
#: and the difference is load-bearing (see the module docstring). This identifier is ours; it exists
#: so a verdict can say WHICH canonical form it verified against.
AGT_CANONICAL_FORM = "sortkeys-json-utf8"

#: The payload fields, in the order AGT builds them. Optional ones are present only when set.
_PFLICHTFELDER = ("agent_did", "args_hash", "cedar_decision", "cedar_policy_id",
                  "receipt_id", "timestamp", "tool_name")
_WAHLFELDER = ("parent_receipt_hash", "session_id")

#: The decisions AGT's implementation uses. NOTE for anyone reading the proposal instead of the
#: code: the proposal document says "permit/deny", the implementation says "allow"/"deny". A
#: verifier that accepts "permit" would accept a receipt AGT never emits.
_ENTSCHEIDUNGEN = frozenset({"allow", "deny"})

#: EVERY field that speaks of an external authorization. The detector below reads ALL of them.
#:
#: Codex, review of this branch: the first version looked at only authorizer_id,
#: authorization_signature and authorizer_public_key. All of these sit OUTSIDE the signed payload,
#: so setting exactly those three to null left `assurance_level="externally_authorized"`,
#: `authorization_expires_at` and `authorization_nonce` standing, kept the signature and the
#: payload hash valid, and turned a receipt this verifier had REJECTED (exit 3) into one it
#: ACCEPTED (ok=True, exit 0). Removable evidence must never improve a verdict.
#:
#: THE CLASS is a partial-shape detector over a field set an attacker can choose from: whichever
#: subset the detector does not read is the subset that can be stripped. The fix is not three more
#: names, it is reading the WHOLE set and demanding completeness once any member appears.
_AUTORISIERUNGSFELDER = ("authorizer_id", "authorization_signature", "authorizer_public_key",
                         "authorization_expires_at", "authorization_nonce")

#: The assurance_level value that CLAIMS an external authorization. A receipt claiming it owes a
#: complete and valid one, whatever else was stripped.
_EXTERN_BEHAUPTET = "externally_authorized"


class AGTReceiptError(ValueError):
    """Malformed input: the bytes are not a readable AGT receipt. Exit code 2, never 1.

    Kept apart from a verification failure on purpose. "I cannot read this" and "I read this and
    the signature is wrong" are different answers, and folding them together loses the one a caller
    needs to act on.
    """


def _text(receipt: Dict[str, Any], feld: str) -> str:
    wert = receipt.get(feld)
    if not isinstance(wert, str):
        raise AGTReceiptError(f"{feld} is {type(wert).__name__}, expected a string")
    return wert


def canonical_payload(receipt: Dict[str, Any]) -> bytes:
    """The bytes AGT signs. `sort_keys` JSON with compact separators and raw UTF-8.

    NOT RFC 8785, although AGT's docstring says so; see the module docstring for the measurement.
    The signature fields are excluded because they cover this payload.
    """
    if not isinstance(receipt, dict):
        raise AGTReceiptError(f"receipt is {type(receipt).__name__}, expected an object")
    fehlend = [f for f in _PFLICHTFELDER if f not in receipt]
    if fehlend:
        raise AGTReceiptError(f"receipt lacks required field(s): {', '.join(sorted(fehlend))}")
    daten: Dict[str, Any] = {f: receipt[f] for f in _PFLICHTFELDER}
    for f in _WAHLFELDER:
        if receipt.get(f) is not None:
            daten[f] = receipt[f]
    return json.dumps(daten, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def payload_hash(receipt: Dict[str, Any]) -> str:
    """SHA-256 over :func:`canonical_payload`. This is what `parent_receipt_hash` points at."""
    return hashlib.sha256(canonical_payload(receipt)).hexdigest()


def canonical_authorization_payload(receipt: Dict[str, Any]) -> bytes:
    """The bytes an external authorizer signs. Binds the receipt payload hash and the nonce."""
    fehlend = [f for f in ("authorizer_id", "authorization_expires_at", "authorization_nonce")
               if receipt.get(f) is None]
    if fehlend:
        raise AGTReceiptError(
            f"external authorization metadata is incomplete: {', '.join(sorted(fehlend))}")
    daten = {
        "authorizer_id": receipt["authorizer_id"],
        "authorization_expires_at": receipt["authorization_expires_at"],
        "authorization_nonce": receipt["authorization_nonce"],
        "receipt_payload_hash": payload_hash(receipt),
        "type": AGT_AUTHORIZATION_TYPE,
    }
    return json.dumps(daten, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _ed25519_gueltig(pubkey_hex: str, signatur_hex: str, nutzlast: bytes) -> bool:
    """One Ed25519 check. Returns False on any failure; never raises for bad input.

    A verifier that raises on a malformed key cannot finish a verdict over a list of receipts, and
    an unfinished verdict reads like a clean one.

    THROUGH THE HOUSE PRIMITIVE, not a second path to `cryptography` (deep gate Z195), and for EVERY
    key through the trust-anchor rule (SPEC section 4b). Until 6.2.0 the receipt's own signer key got
    the plain SPEC section 4a check, "as a bundle's key does", and only the authorizer key the rule.
    The comparison did not hold: a bundle's key is trusted through a relying party's pin, which
    carries the rule, while nothing pins an AGT signer key. Measured on 126ed1dc: signer key
    0100..00 (the identity point) with the signature R = identity, S = 0 gave `signature` True and
    `ok` True, a receipt nobody signed. And AGT's authorization binds `receipt_payload_hash`, not
    `signer_public_key`, so the same swap under an authorized receipt kept the authorization valid.
    SPEC section 4b names every key that is not the bundle's own; this one is not.
    """
    try:
        schluessel = bytes.fromhex(pubkey_hex)
        signatur = bytes.fromhex(signatur_hex)
    except (ValueError, TypeError):
        return False
    return verify_ed25519_pinned(schluessel, signatur, nutzlast)


def _schwaeche(pubkey_hex) -> "str | None":
    """Why a hex-spelled key cannot stand as a trusted Ed25519 key (`low-order`, `non-canonical`),
    or None. Text that decodes to no 32-byte key is None here: it names no key, verifies nothing and
    matches nothing, and the signature check or the list comparison says so on its own."""
    try:
        roh = bytes.fromhex(pubkey_hex)
    except (ValueError, TypeError):
        return None
    grund = ed25519_trust_anchor_weakness(roh)
    return grund if grund in ("low-order", "non-canonical") else None


def _abgewiesen(feld: str, grund: str) -> str:
    """The one sentence every refusal of a key in this module carries, with the shared reason text."""
    return (f"{feld} is a {grund} Ed25519 key, refused as a trusted key before any signature "
            f"arithmetic: {TRUST_ANCHOR_REFUSAL[grund]}")


def _abgewiesene_liste(schluessel) -> "str | None":
    """The refusal of a relying party's `trusted_authorizer_keys`, or None when every entry can stand.

    AT THE LIST, when a key is AUTHORISED, not only when a receipt happens to name it. A weak key on
    that list authorised nothing before either, because the authorization signature goes through the
    rule; but the list stood as accepted, and the defect showed only on the one receipt that used it.
    The trust policy refuses a weak pin when it is LOADED (`policy._validate_pinned_ed25519_pubkey`),
    and this list is the same kind of object. An entry that decodes to no 32-byte key is left alone,
    as before: it names no key and matches nothing. A container this function cannot walk is left to
    the comparison further down, unchanged."""
    if not isinstance(schluessel, (list, tuple, set, frozenset)):
        return None
    gruende = []
    for i, eintrag in enumerate(schluessel):
        grund = _schwaeche(eintrag)
        if grund is not None:
            gruende.append(_abgewiesen(f"trusted_authorizer_keys[{i}] ({str(eintrag)[:16]}…)", grund))
    return "; ".join(gruende) or None


def _derselbe_schluessel(a_hex: str, b_hex: str) -> bool:
    """Whether two hex spellings name the same key BYTES. Hex is case-insensitive, so `ab…` and `AB…`
    are one key; comparing the strings counted them as two, and `authorizer-key-distinct` passed for a
    receipt whose authorizer was its own signer spelled in capitals (deep gate Z195, the identity-by-
    encoding half of L1-Z195-02). Text that is not hex compares as text."""
    try:
        return bytes.fromhex(a_hex) == bytes.fromhex(b_hex)
    except (ValueError, TypeError):
        return a_hex == b_hex


def verify_agt_receipt(
    receipt: Dict[str, Any],
    *,
    trusted_authorizer_keys: Optional[Sequence[str]] = None,
    require_external_authorization: bool = False,
    now: Optional[float] = None,
) -> VerificationResult:
    """Verify one AGT receipt offline.

    `trusted_authorizer_keys` is the relying party's list; an external authorization is only
    ACCEPTED when its key is on that list AND differs from the receipt signer key. Without the
    list, an externally authorized receipt still verifies cryptographically, and the verdict says
    the authorization was not evaluated. That is not a pass for the authorization.

    WHAT THE AUTHORIZATION CHECKS DO NOT SAY, named because an independent review found the earlier
    check name claiming it. Two distinct keys are two keys, not two organizations: an admin key and
    a service key of the same operator satisfy every check here. AGT's own proposal says the same —
    "different keys alone cannot prove organizational independence" — and the check is therefore
    called `authorizer-key-distinct`, which is what it measures, rather than something that sounds
    like independence. Whether an authorizer is operationally independent is a deployment and
    key-custody property, and no signature can carry it.

    A CALLER WHO READS ONLY `.ok` LOSES THE REASON. `ok` is False for an unreadable receipt, a
    broken signature and an unmet relying-party requirement alike; those are three different
    answers and they are told apart by the check NAMES and by :func:`exit_code`, not by `ok`. The
    same review raised this, and the honest answer is that `ok` is a summary and a summary is not a
    diagnosis.

    `now` is the instant expiry is judged at. Default is the receipt's own `timestamp`, because
    this is the OFFLINE reading: the proposal states that offline verification evaluates expiration
    at the signed receipt timestamp while a live adapter evaluates it at execution time. Passing a
    wall-clock value here gives the live reading; the verdict names which one was used.

    EVERY KEY GOES THROUGH THE TRUST-ANCHOR RULE (SPEC section 4b): the signer key, the authorizer
    key and each key on `trusted_authorizer_keys`. A low-order or non-canonical key is refused before
    any signature arithmetic, and the check says which key and why. A weak key on the relying
    party's list refuses the list before the receipt is read (`trusted-authorizer-keys`, exit 2, the
    malformed-input code, as a weak pin in a trust policy is).
    """
    ergebnis = VerificationResult()
    if trusted_authorizer_keys is not None:
        liste = _abgewiesene_liste(trusted_authorizer_keys)
        if liste is not None:
            ergebnis.add("trusted-authorizer-keys", False, liste)
            return ergebnis
    # NEVER-RAISE AT THE VERIFY SURFACE, and the house gate was right to insist. The first version
    # let `canonical_payload` raise through here so that unreadable input could be told apart from
    # a failed check. The type-confusion gate refused it: a verifier that crashes on a broken
    # document does not judge, and a caller who forgets one `except` reads a crash as nothing at
    # all. Both properties are kept instead of traded — the unreadability becomes a NAMED check, and
    # `exit_code` maps that one name to 2 while every other failure maps to 1.
    try:
        nutzlast = canonical_payload(receipt)
    except AGTReceiptError as fehler:
        ergebnis.add("readable", False, str(fehler))
        return ergebnis

    # THROUGH `is_member`, NOT THROUGH `in`. `cedar_decision` comes out of the receipt, so it is
    # attacker-controlled, and `_ENTSCHEIDUNGEN` hashes. An unhashable value would raise TypeError
    # at a verify surface that promises never to raise; the house guard measures exactly this shape
    # and it caught this line on 2026-09-23. `is_member` answers False for a value that cannot be
    # an element, which is the correct answer and lets the rejection below fire as written.
    entscheidung = _text(receipt, "cedar_decision")
    bekannt = is_member(entscheidung, _ENTSCHEIDUNGEN)
    ergebnis.add(
        "decision-vocabulary", bekannt,
        f"cedar_decision={entscheidung!r}" if bekannt else
        f"cedar_decision={entscheidung!r} is not one of {sorted(_ENTSCHEIDUNGEN)} — note that the "
        f"AGT proposal document says permit/deny while the implementation says allow/deny")

    signatur = receipt.get("signature")
    pubkey = receipt.get("signer_public_key")
    if not isinstance(signatur, str) or not isinstance(pubkey, str) or not signatur or not pubkey:
        ergebnis.add("signature", False, "receipt carries no signature or no signer public key")
        return ergebnis
    schwaeche = _schwaeche(pubkey)
    if schwaeche is not None:
        ergebnis.add("signature", False, _abgewiesen("signer_public_key", schwaeche))
    else:
        ergebnis.add(
            "signature", _ed25519_gueltig(pubkey, signatur, nutzlast),
            f"Ed25519 over the {AGT_CANONICAL_FORM} payload, {len(nutzlast)} bytes")

    # The receipt may carry its own payload_hash. If it does and it disagrees, say so: a receipt
    # whose self-reported hash does not match its own bytes is telling two stories.
    selbst = receipt.get("payload_hash")
    if isinstance(selbst, str) and selbst:
        ergebnis.add("payload-hash-self-consistent", selbst == payload_hash(receipt),
                     f"receipt states {selbst[:16]}…")

    behauptet_extern = receipt.get("assurance_level") == _EXTERN_BEHAUPTET
    hat_autorisierung = behauptet_extern or any(
        receipt.get(f) is not None for f in _AUTORISIERUNGSFELDER)
    if require_external_authorization and not hat_autorisierung:
        ergebnis.add("external-authorization", False,
                     "required by the caller, but the receipt carries none")
        return ergebnis
    if not hat_autorisierung:
        return ergebnis

    # COMPLETENESS IS DEMANDED, not assumed. Once anything speaks of an authorization — a field, or
    # an assurance_level claiming one — every part must be there. Otherwise the subset an attacker
    # leaves standing decides the verdict.
    fehlend = [f for f in _AUTORISIERUNGSFELDER if receipt.get(f) is None]
    if fehlend:
        grund = ("assurance_level claims an external authorization" if behauptet_extern
                 else "some authorization fields are present")
        ergebnis.add("external-authorization-complete", False,
                     f"{grund}, but these are missing: {', '.join(sorted(fehlend))} — a receipt "
                     f"whose authorization can be stripped field by field must not verify")
        return ergebnis
    a_sig = receipt.get("authorization_signature")
    a_key = receipt.get("authorizer_public_key")
    if not isinstance(a_sig, str) or not isinstance(a_key, str) or not a_sig or not a_key:
        ergebnis.add("external-authorization-complete", False,
                     "authorization signature or authorizer key is present but not a string")
        return ergebnis
    # RECORDED IN BOTH DIRECTIONS, and the reason is a test of mine that was wrong. It asserted
    # this check appears on a correctly authorized receipt; it did not, because the check was only
    # added on the failing branch. A property that is only named when it is violated is invisible
    # when it holds, and a reader of a green verdict cannot tell whether it was examined.
    derselbe = _derselbe_schluessel(a_key, pubkey)
    ergebnis.add("authorizer-key-distinct", not derselbe,
                 "authorizer key differs from the receipt signer key" if not derselbe else
                 "authorizer key equals the receipt signer key — a second signature from the same "
                 "key adds no second party at all")
    if derselbe:
        return ergebnis

    a_nutzlast = canonical_authorization_payload(receipt)
    a_schwaeche = _schwaeche(a_key)
    if a_schwaeche is not None:
        ergebnis.add("external-authorization-signature", False,
                     _abgewiesen("authorizer_public_key", a_schwaeche))
    else:
        ergebnis.add("external-authorization-signature",
                     _ed25519_gueltig(a_key, a_sig, a_nutzlast),
                     f"Ed25519 over the authorization payload, type {AGT_AUTHORIZATION_TYPE}")

    frist = receipt.get("authorization_expires_at")
    zeitpunkt = receipt.get("timestamp") if now is None else now
    quelle = "the receipt timestamp (offline reading)" if now is None else "the supplied instant"
    if isinstance(frist, (int, float)) and isinstance(zeitpunkt, (int, float)):
        ergebnis.add("external-authorization-unexpired", float(zeitpunkt) <= float(frist),
                     f"judged at {quelle}")
    else:
        ergebnis.add("external-authorization-unexpired", False,
                     "expiry or reference instant is not a number")

    if trusted_authorizer_keys is None:
        # NOT a pass. The check is recorded as not evaluated so the verdict cannot be read as
        # "the authorizer was trusted".
        ergebnis.add("external-authorization-trusted", False,
                     "no trusted authorizer keys supplied — the authorization was NOT evaluated "
                     "against a relying party's list, and this is not an acceptance")
    else:
        ergebnis.add("external-authorization-trusted", a_key in set(trusted_authorizer_keys),
                     f"authorizer key {a_key[:16]}… against {len(trusted_authorizer_keys)} "
                     f"trusted key(s)")
    return ergebnis


def verify_agt_receipt_chain(
    receipts: Sequence[Dict[str, Any]],
    **kwargs: Any,
) -> VerificationResult:
    """Verify a receipt chain: every receipt, plus every `parent_receipt_hash` link.

    An empty sequence is a failure, not a clean chain. A run that examined nothing looks exactly
    like a run that found nothing, and this house has paid for that confusion before.
    """
    ergebnis = VerificationResult()
    # THE SHAPE IS CHECKED BEFORE THE EMPTINESS, and the order is the whole point. `not receipts`
    # is True for `[]` and for `0` and `False` alike, so a truthy non-sequence such as `True` or
    # `-1` slipped past it and died on `enumerate` with a bare TypeError. Measured by the house
    # type-confusion gate on this very module: "TypeError on payload True: 'bool' object is not
    # iterable". A verifier that raises instead of judging is the defect this gate exists to catch.
    if not isinstance(receipts, (list, tuple)):
        ergebnis.add("chain-readable", False,
                     f"receipts is {type(receipts).__name__}, expected a list or tuple")
        return ergebnis
    if not receipts:
        ergebnis.add("chain-non-empty", False, "no receipts supplied — nothing was examined")
        return ergebnis

    for i, r in enumerate(receipts):
        teil = verify_agt_receipt(r, **kwargs)
        for c in teil.checks:
            ergebnis.add(f"[{i}] {c.name}", c.ok, c.detail)

    for i in range(1, len(receipts)):
        # Same never-raise rule as above: an unreadable link is a named finding, not a crash that
        # abandons the remaining receipts. A chain verdict that stops halfway is not a verdict.
        try:
            erwartet = payload_hash(receipts[i - 1])
        except AGTReceiptError as fehler:
            ergebnis.add(f"[{i}] chain-link", False,
                         f"the previous receipt is not readable, so no link can be checked: {fehler}")
            continue
        gefunden = receipts[i].get("parent_receipt_hash")
        ergebnis.add(f"[{i}] chain-link", gefunden == erwartet,
                     f"parent_receipt_hash={str(gefunden)[:16]}… expected {erwartet[:16]}…")
    return ergebnis


#: Strips ONLY a leading chain index such as "[0] ". An independent review read the earlier
#: `split("] ", 1)[-1]` as taking the LAST segment and called it broken for a name containing
#: "] ". Measured, that reading was wrong: with maxsplit=1 the call already returns everything
#: after the FIRST "] ", which is the name. The residual fragility is real though — an
#: UNPREFIXED name containing "] " would still be cut — so the prefix is now matched as a prefix
#: instead of being inferred from a separator that may also occur inside the name.
_KETTENPRAEFIX = re.compile(r"^\[\d+\] ")


def _blanker_name(name: str) -> str:
    return _KETTENPRAEFIX.sub("", name, count=1)


def exit_code(ergebnis: VerificationResult) -> int:
    """Map a verdict onto the house exit-code contract.

    0 verified · 1 cryptographic or structural failure · 2 malformed input · 3 crypto sound but a
    relying-party requirement unmet. Malformed input is the named check `readable` or
    `chain-readable` (unreadable input is not a failed verification, it is a failed reading) or
    `trusted-authorizer-keys` (the relying party's own list names a key the trust-anchor rule
    refuses, the way a weak pin makes a trust policy malformed).
    """
    if ergebnis.ok:
        return 0
    # UNREADABLE FIRST, because it dominates: if the bytes could not be read, nothing else was
    # examined, and reporting a signature failure over input that was never parsed would name the
    # wrong cause. A refused list is the same kind of answer: nothing was judged against it.
    for c in ergebnis.checks:
        if not c.ok and _blanker_name(c.name) in ("readable", "chain-readable",
                                                  "trusted-authorizer-keys"):
            return 2
    # STRUCTURAL FAILURES ARE EXIT 1, and Codex was right to separate them. Exit 3 states "crypto
    # sound but a relying-party requirement unmet", so a receipt that is structurally broken on its
    # own — incomplete authorization, an authorizer equal to the signer — must not borrow that
    # code: no relying party asked for anything. Only `external-authorization-trusted`, which is
    # judged against a list the CALLER supplies, is a relying-party matter.
    krypto = {"signature", "external-authorization-signature", "payload-hash-self-consistent",
              "decision-vocabulary", "chain-link", "chain-non-empty",
              "external-authorization", "external-authorization-complete",
              "authorizer-key-distinct", "external-authorization-unexpired"}
    for c in ergebnis.checks:
        if c.ok:
            continue
        name = _blanker_name(c.name)
        if name in krypto:
            return 1
    return 3
