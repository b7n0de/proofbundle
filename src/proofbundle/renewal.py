"""B3 renewal chain — an ERS-compatible ArchiveTimeStampSequence (EXPERIMENTAL; ADR 0006).

The longevity mechanism: an anchor keeps its force across decades by RENEWAL before its algorithms age.
Modeled char-precise on RFC 4998 (Evidence Record Syntax):

* ``ArchiveTimeStamp`` (ATS) — the atomic archive timestamp over a digest of the covered objects, at a
  time, backed by a time anchor.
* ``ArchiveTimeStampChain`` — a run of ATS sharing ONE hash algorithm. **Timestamp renewal** appends a
  new ATS to the SAME chain (covering the prior ATS) when a timestamp's key/signature algorithm weakens.
* ``ArchiveTimeStampSequence`` — a run of chains. **Hash-tree renewal** starts a NEW chain whose first
  ATS covers ALL prior ATS *and* the data objects, under a new (stronger) hash algorithm, when the hash
  algorithm weakens.

Both runs are ordered strictly ascending by time. RFC 4998 operating rule: after each renewal only the
single newest ATS (``last_ats``) needs watching for expiry / algorithm weakening.

This is a JSON-native model (proofbundle serializes JSON, not ASN.1). An ASN.1 RFC-4998 / XMLERS export
for preservation-service interop is a separate adapter; where no offline reference validator is available
it is reported as a clean OPEN (see ADR 0006), never a fake pass.

The hash algorithm of every ATS is resolved through the B2 registry (``hashalg``): fail-closed on a
missing / unknown / deprecated algorithm — a renewal never introduces a weak hash.
"""
from __future__ import annotations

import base64
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Optional

from .budget import int_magnitude_ok
from .budget import render_safe as _rs
from .errors import Check, ProofBundleError, VerificationResult
from .hashalg import HASH_REGISTRY, HashAlgError, compute_digest, resolve_hash_alg
from .pqsig import PQUnavailable, sign_mldsa, verify_hybrid, verify_mldsa
from .signature import verify_ed25519

# ATS signature algorithms (the RFC-4998 TimeStampToken role, B3↔B5 wiring). A renewal may UPGRADE the
# algorithm (ed25519 → hybrid → mldsa65) so the signature layer migrates toward PQ before it weakens.
_SIG_ALGS = ("ed25519", "hybrid-ed25519-mldsa65", "mldsa65")

# A digest is lowercase hex — this excludes the _SEP separator, closing the delimiter-injection where a
# single crafted string equal to _SEP.join(real_digests) would hash identically to the multi-object set.
_HEXRE = re.compile(r"\A[0-9a-f]+\Z")

__all__ = [
    "ArchiveTimeStamp",
    "RenewalError",
    "RenewalPolicy",
    "VerifiedAnchorResult",
    "anchor_proof_digest",
    "build_initial_sequence",
    "renew_timestamp",
    "renew_hashtree",
    "verify_sequence",
    "last_ats",
    "evaluate_renewal_policy",
]

_CONFIRMED = "confirmed"
_SEP = "\n"


def _as_dict(v):
    """adversarial re-audit r5/r6 class-fix: Config-Sub-Feld als dict, sonst {} (das ``_as_dict(x.get(k))``-Idiom ersetzte nur FALSY)."""
    return v if isinstance(v, dict) else {}


def _as_list(v):
    return v if isinstance(v, (list, tuple)) else []


def _refuse_giant_int(*values) -> None:
    """Signed-bytes guard (Deep-Gate iter9 Linse C, fix-the-CLASS not the instance): token()/_ats_content
    build the material a signature is computed over, so a shortened render is NOT an option — it would
    change the signed bytes. An ATS field that is an implausibly large INT trips CPython's int->str cap
    (CVE-2020-10735) the moment it is interpolated, raising a raw ValueError. EVERY field folded into the
    signed string carries that exposure, not just ``time`` (the one an earlier round guarded); refuse the
    magnitude with a typed error on all of them. The never-raise verify surfaces catch it fail-closed."""
    for v in values:
        if isinstance(v, int) and not isinstance(v, bool) and not int_magnitude_ok(v):
            raise ProofBundleError(
                f"ATS field is an implausibly large integer ({v.bit_length()} bits) — refused before "
                "rendering the signed bytes (a shortened render would change them)")


class RenewalError(ProofBundleError):
    """A renewal was attempted without a confirmed prior anchor, or with a broken/weak input."""


@dataclass(frozen=True)
class ArchiveTimeStamp:
    """One RFC-4998 ArchiveTimeStamp: a covered digest under a hash algorithm, at a time, authenticated by
    a time-authority SIGNATURE (the RFC-4998 TimeStampToken role).

    ``covered_digest`` is the hex digest this ATS commits to (a hash-tree root over its covered objects).
    ``sig_alg`` is the signature algorithm (``ed25519`` | ``hybrid-ed25519-mldsa65`` | ``mldsa65``; ``""``
    = unsigned/legacy) and ``signatures`` a tuple of ``(alg-part, base64-signature)`` pairs over the ATS
    CONTENT (``_ats_content``). The signature is the real trust anchor: renewal migrates it toward PQ.
    ``anchor_status`` is the legacy structural marker, used only when no ``authority_keys`` are supplied to
    ``verify_sequence`` (a real signature check supersedes it). ``time`` orders the sequence + drives expiry.
    ``renewal_seed_evidence_class`` is provenance metadata (never part of ``token()``, purely descriptive):
    ``""`` for an ATS that is not itself a renewal (the initial ATS from ``build_initial_sequence``),
    ``"cryptographically_verified"`` when the renewal that produced this ATS was seeded from a bound,
    verified ``VerifiedAnchorResult`` (finding 09), or ``"self_asserted_status"`` when it was seeded from
    the legacy bare ``anchor_status`` label alone.

    ``external_token_type`` / ``external_token`` / ``external_token_frozen`` (Finding 14a-b, additive; ADR
    0006 B3 OPEN item "binding an ATS to a real external RFC-3161 token / OTS proof"): an OPTIONAL, DETACHED
    binding of THIS ATS's ``covered_digest`` to a real external time-stamp proof — ``"rfc3161-tsa"`` (an
    RFC 3161 DER token) or ``"opentimestamps"`` (a serialized OTS proof), verified by
    ``_verify_ats_external_token`` via the ALREADY-HARDENED standalone verifiers in ``anchors_rfc3161.py`` /
    ``anchors_ots.py`` (pure glue, no new cryptography). ``external_token_frozen`` mirrors ``anchors.py``'s
    own ``frozen`` block (chain material FROZEN at emit time, e.g. TSA root/cert DER or a Bitcoin block
    header — evidence, never trust; the caller's ``rp_trust`` at verify time is the trust source, same WP-A1
    discipline as ``anchors.py``). Like ``anchors.py``'s detached anchors, this is DELIBERATELY excluded from
    ``token()``: it is out-of-band CORROBORATING evidence about this ATS's own identity, not part of that
    identity — folding a multi-KB DER blob into every later renewal's covering hash would be both a design
    smell and needlessly expensive. Empty defaults (``""`` / ``b""`` / ``{}``) mean "no external token" and
    are fully backward compatible with every existing ATS/sequence."""

    hash_alg: str
    covered_digest: str
    time: int
    anchor_status: str = _CONFIRMED
    sig_alg: str = ""
    signatures: tuple = field(default_factory=tuple)
    renewal_seed_evidence_class: str = ""
    external_token_type: str = ""
    external_token: bytes = b""
    external_token_frozen: dict = field(default_factory=dict)

    def token(self) -> str:
        """The stable string a later ATS covers when it renews this one — RFC 4998 timestamp renewal covers
        the prior timestamp token INCLUDING its signature. Unsigned ATS keep the legacy (base) form so
        existing sequences are unaffected.

        THIS RENDER IS NOT A DIAGNOSTIC — it is the covered material. The `render_safe` helper used at
        the diagnostic sites must NOT be used here: shortening a huge value would change the signed
        bytes, and every existing signature over this token would stop verifying. A defensive
        abbreviation is worse than the crash it prevents when the string IS the contract.

        So the magnitude is REFUSED instead of rendered differently. A time whose decimal form would
        trip CPython's int->str cap (CVE-2020-10735) is not a legitimate timestamp under any reading —
        it is refused with a typed error, the same fail-closed direction the rest of this module takes.
        """
        # fix-the-CLASS (Deep-Gate iter9 Linse C): EVERY field folded into the covered token carries the
        # int->str exposure, not only `time`; refuse an implausible magnitude on all of them.
        _refuse_giant_int(self.time, self.hash_alg, self.covered_digest, self.sig_alg)
        base = f"{self.hash_alg}:{self.covered_digest}:{self.time}"
        if not self.sig_alg:
            return base
        # a malformed `signatures` (non-iterable container, or entries that are not (str, str) 2-tuples)
        # cannot be well-formed signed bytes — refuse it typed here, rather than let `sorted(...)` raise a
        # raw TypeError out of the covering check (which catches ProofBundleError, NOT TypeError). This is
        # token()'s OWN iteration; _verify_ats_signature guards a SEPARATE one, so both need the guard.
        if not isinstance(self.signatures, (list, tuple)) or not all(
                isinstance(it, tuple) and len(it) == 2
                and isinstance(it[0], str) and isinstance(it[1], str)
                for it in self.signatures):
            raise ProofBundleError(
                "ATS signatures must be a sequence of (alg, base64) string pairs — refused before "
                "rendering the covered token (a malformed signatures field cannot be signed bytes)")
        sig_part = ";".join(f"{a}={s}" for a, s in sorted(self.signatures))
        return f"{base}:{self.sig_alg}:{sig_part}"


@dataclass(frozen=True)
class VerifiedAnchorResult:
    """Evidence that a specific PRIOR ArchiveTimeStamp was independently, cryptographically verified — e.g.
    a real OTS/Bitcoin confirmation check, an RFC-3161 TSA verification, or an authority-signature check
    via ``verify_sequence(..., authority_keys=...)`` — rather than trusted from its bare ``anchor_status``
    label (finding 09: ``anchor_status="confirmed"`` is ALSO proofbundle's own default field value AND
    ``build_initial_sequence``'s default, so an unsigned, never-actually-anchored ATS satisfies the label
    trivially; ``verify_sequence`` is fail-closed about this, but ``renew_timestamp``/``renew_hashtree``
    historically were not).

    ``proof_digest`` BINDS this result to the EXACT prior ATS being renewed (``anchor_proof_digest(prior)``,
    i.e. SHA-256 of ``prior.token()``) — a verification performed for one ArchiveTimeStamp must not be
    replayable onto a different one, even a later link in the SAME renewal chain. ``verifier_id`` /
    ``policy_digest`` / ``verified_at`` are provenance (who verified it, under which policy, when);
    construct this from the output of a real verification, never hand-typed alongside ``verified=True``
    (No-Fake)."""

    verified: bool
    proof_digest: str
    verifier_id: str
    policy_digest: str
    verified_at: int


_ANCHOR_PROOF_HASH = "sha256"


def anchor_proof_digest(ats: ArchiveTimeStamp) -> str:
    """The canonical binding digest for a ``VerifiedAnchorResult.proof_digest`` over ``ats``: SHA-256
    (fixed, independent of ``ats.hash_alg`` — evidence about WHICH ArchiveTimeStamp was verified is a
    separate concern from what hash that ATS's own covering commits under) of ``ats.token()`` (which
    already folds in the ATS's hash algorithm, covered digest, time, and signature — so a verification
    bound to one ATS cannot be silently satisfied by a structurally different one)."""
    return compute_digest(ats.token().encode(), _ANCHOR_PROOF_HASH)


def _ats_content(hash_alg: str, covered_digest: str, time: int, sig_alg: str) -> bytes:
    """The exact bytes a time authority SIGNS for an ATS (domain-separated, pre-signature).

    ``sig_alg`` IS bound into the signed bytes (algorithm-confusion defense, JWT-``alg`` class): a
    signature produced under one algorithm label cannot be relabeled to a weaker one and re-verified — a
    hybrid ATS's ed25519 leg, if relabeled ``sig_alg="ed25519"``, would be checked against DIFFERENT bytes
    and fail. Without this binding a post-quantum attacker could downgrade a hybrid/mldsa65 ATS to its
    classical leg with no forgery."""
    # Deep-Gate iter9 Linse C (fix-the-CLASS): this builds the SIGNED bytes, so — like token() — an
    # implausible magnitude is REFUSED, never shortened. The earlier guard covered only `time`; every
    # field interpolated here (sig_alg/hash_alg/covered_digest as a giant int too) has the same int->str
    # exposure. _verify_ats_signature, a never-raise surface, catches this typed refusal fail-closed.
    _refuse_giant_int(time, hash_alg, covered_digest, sig_alg)
    return f"archivetimestamp/v1\n{sig_alg}\n{hash_alg}\n{covered_digest}\n{time}".encode()


def _sign_ats_content(content: bytes, sig_alg: str, signers: dict) -> tuple:
    """Produce the ``signatures`` tuple for ``content`` under ``sig_alg`` from ``signers`` (a dict
    ``{"ed25519": ed25519_private_key, "mldsa65": mldsa65_private_key}``). Fail-closed on a missing signer
    or an unknown algorithm."""
    if sig_alg not in _SIG_ALGS:
        raise RenewalError(f"unknown ATS signature algorithm {_rs(sig_alg)} (one of {_SIG_ALGS})")
    sigs: list[tuple[str, str]] = []
    if sig_alg in ("ed25519", "hybrid-ed25519-mldsa65"):
        ed = signers.get("ed25519")
        if ed is None:
            raise RenewalError(f"sig_alg {sig_alg!r} needs an 'ed25519' signer")
        sigs.append(("ed25519", base64.b64encode(bytes(ed.sign(content))).decode("ascii")))
    if sig_alg in ("mldsa65", "hybrid-ed25519-mldsa65"):
        m = signers.get("mldsa65")
        if m is None:
            raise RenewalError(f"sig_alg {sig_alg!r} needs an 'mldsa65' signer")
        sigs.append(("mldsa65", base64.b64encode(sign_mldsa(m, content)).decode("ascii")))
    return tuple(sigs)


def _verify_ats_signature(ats: ArchiveTimeStamp, authority_keys: dict) -> bool:
    """True iff the ATS carries a valid time-authority signature under ``authority_keys`` (a dict of raw
    public keys ``{"ed25519": bytes, "mldsa65": bytes}``). Fail-closed: an unsigned ATS, a missing key for
    the declared algorithm, or a bad/absent signature is False. A hybrid ATS requires BOTH legs valid."""
    authority_keys = _as_dict(authority_keys)  # adversarial re-audit r6: non-dict kwarg fail-closed
    if not ats.sig_alg:
        return False
    try:
        content = _ats_content(ats.hash_alg, ats.covered_digest, ats.time, ats.sig_alg)
    except ProofBundleError:
        # _ats_content refuses an implausible field magnitude by raising (it builds signed bytes); this is
        # a never-raise verdict surface, so a malformed ATS is a fail-closed False, not a propagated
        # exception (fix-the-CLASS: the refusal and its catch are the two ends of one contract).
        return False
    # robust against a malformed signatures field (None / non-2-tuple entries) — fail-closed, never raise
    sigmap: dict[str, str] = {}
    # Deep-Gate iter9 Linse 3c: eine non-iterable .signatures (int/bool/float/object) crasht die
    # for-Schleife roh ('object is not iterable'); der bestehende Kommentar deckte nur None/non-2-tuple
    # EINTRAEGE, nicht einen non-iterable CONTAINER.
    _sigs = ats.signatures if isinstance(ats.signatures, (list, tuple)) else ()
    for item in _sigs:
        if isinstance(item, tuple) and len(item) == 2:
            a, s = item
            if isinstance(a, str) and isinstance(s, str):
                sigmap[a] = s

    def _dec(part: str) -> bytes:
        try:
            return base64.b64decode(sigmap.get(part, ""), validate=True)
        except (ValueError, TypeError):
            return b""

    if ats.sig_alg == "ed25519":
        pub = authority_keys.get("ed25519")
        return isinstance(pub, (bytes, bytearray)) and verify_ed25519(bytes(pub), _dec("ed25519"), content)
    # adversarial re-audit round 5: an attacker-presented ATS merely LABELS sig_alg='mldsa65'/'hybrid'; on a build
    # without FIPS-204 ML-DSA (the common case) verify_mldsa/verify_hybrid raise PQUnavailable (a
    # ProofBundleError sibling) which escaped verify_sequence raw. A verdict-returning verify surface must fail
    # closed on attacker-influenceable PQ input, never raise — parity with trust_pack._verify_signature_for_alg.
    if ats.sig_alg == "mldsa65":
        pub = authority_keys.get("mldsa65")
        try:
            return pub is not None and verify_mldsa(pub, _dec("mldsa65"), content)
        except PQUnavailable:
            return False
    if ats.sig_alg == "hybrid-ed25519-mldsa65":
        edp, mp = authority_keys.get("ed25519"), authority_keys.get("mldsa65")
        if edp is None or mp is None:
            return False
        try:
            return verify_hybrid(classical_pub=edp, classical_sig=_dec("ed25519"),
                                 pq_pub=mp, pq_sig=_dec("mldsa65"), message=content)
        except PQUnavailable:
            return False
    return False


def _verify_ats_external_token(ats: ArchiveTimeStamp, *, rp_trust: Optional[dict] = None,
                               now: Optional[int] = None) -> dict:
    """Finding 14a-b glue: verify ``ats``'s DETACHED ``external_token`` against its OWN ``covered_digest``
    via the ALREADY-HARDENED standalone anchor verifiers (``anchors_rfc3161.verify_rfc3161`` /
    ``anchors_ots.verify_opentimestamps``) — pure dispatch, no new cryptography (ADR 0006 B3 OPEN item).

    ``canonical_root`` is ``ats.covered_digest`` decoded from hex — exactly the bytes an RFC 3161 / OTS
    proof would timestamp for this ATS, the SAME role ``anchors.py`` gives a receipt's ``canonicalRoot``.
    ``rp_trust`` is the caller's OWN relying-party trust material (TSA roots / Bitcoin block headers, WP-A1)
    — ``ats.external_token_frozen`` is producer-controlled EVIDENCE, never trust, exactly mirroring
    ``anchors_rfc3161.py`` / ``anchors_ots.py``'s own documented discipline.

    Returns the verifier's own ``{ok, warn, status, detail, ...}`` dict. Never raises (mirrors
    ``_verify_ats_signature``'s never-raise, fail-closed contract): an absent/unknown token type, a
    non-hex ``covered_digest``, a missing optional-extra import, or a raising verifier all come back as
    ``{"ok": False, ...}``, never propagate an exception to the caller."""
    if ats.external_token_type not in ("rfc3161-tsa", "opentimestamps") or not ats.external_token:
        return {"ok": False, "warn": False, "status": "absent", "detail": "no external token on this ATS"}
    try:
        canonical_root = bytes.fromhex(ats.covered_digest)
    except (ValueError, TypeError):
        return {"ok": False, "warn": False, "status": "malformed",
                "detail": "covered_digest is not valid hex — cannot bind the external token"}
    frozen = ats.external_token_frozen if isinstance(ats.external_token_frozen, dict) else {}
    try:
        if ats.external_token_type == "rfc3161-tsa":
            from . import anchors_rfc3161  # noqa: PLC0415
            return anchors_rfc3161.verify_rfc3161(ats.external_token, canonical_root, frozen=frozen,
                                                  now=now, rp_trust=rp_trust)
        from . import anchors_ots  # noqa: PLC0415
        return anchors_ots.verify_opentimestamps(ats.external_token, canonical_root, frozen=frozen,
                                                 now=now, rp_trust=rp_trust)
    except Exception as exc:  # noqa: BLE001 - a verifier must never crash the caller (fail-closed contract)
        return {"ok": False, "warn": False, "status": "verifier_error",
                "detail": f"external token verifier error (fail-closed): {exc}"}


def _is_deprecated_hash(alg: str) -> bool:
    """True iff ``alg`` is a KNOWN but deprecated registry hash (sha1/md5). An unknown/absent alg is not
    'deprecated' (it fails the resolvable-hash check instead)."""
    # Deep-Gate iter9 Linse 3b: ein unhashable hash_alg (list/dict) crasht HASH_REGISTRY.get(alg) roh.
    # Ein Nicht-String ist kein bekannter Algorithmus -> nicht deprecated (faellt sonst am Resolve-Check).
    if not isinstance(alg, str):
        return False
    spec = HASH_REGISTRY.get(alg)
    return spec is not None and spec.status == "deprecated"


def _validate_digests(data_digests: Sequence[str]) -> None:
    """Fail closed unless every data digest is lowercase hex — this excludes the ``_SEP`` separator, so a
    single crafted string cannot masquerade as ``_SEP.join`` of several real digests (set/cardinality
    confusion). A sha256/sha512/sha3 digest is always lowercase hex."""
    for d in data_digests:
        if not (isinstance(d, str) and _HEXRE.match(d)):
            raise RenewalError(
                f"data digest must be a non-empty lowercase-hex string (no separators), got {d!r}")


def _cover_data(data_digests: Sequence[str], hash_alg: str, *, allow_deprecated: bool = False) -> str:
    """Hash-tree root over the DATA objects (order-independent: sorted) under ``hash_alg``."""
    _validate_digests(data_digests)
    payload = _SEP.join(sorted(data_digests)).encode()
    return compute_digest(payload, hash_alg, allow_deprecated=allow_deprecated)


def _cover_prior_and_data(prior: Sequence[ArchiveTimeStamp], data_digests: Sequence[str],
                          hash_alg: str, *, allow_deprecated: bool = False) -> str:
    """Hash-tree root over ALL prior ATS (in time order) PLUS the data objects, under ``hash_alg`` — the
    covered digest of a hash-tree-renewal ATS (RFC 4998: a new chain covers everything before it)."""
    _validate_digests(data_digests)
    items = [a.token() for a in prior] + sorted(data_digests)
    return compute_digest(_SEP.join(items).encode(), hash_alg, allow_deprecated=allow_deprecated)


def _make_ats(hash_alg: str, covered: str, time: int, anchor_status: str,
              sig_alg: str, signers: Optional[dict], *,
              renewal_seed_evidence_class: str = "") -> ArchiveTimeStamp:
    """Construct an ATS, signing its content when ``sig_alg`` is set (the RFC-4998 TimeStampToken).
    ``renewal_seed_evidence_class`` tags HOW the prior anchor was established when this ATS is itself a
    renewal (finding 09); the default ``""`` is for a non-renewal (initial) ATS."""
    sigs: tuple = ()
    if sig_alg:
        sigs = _sign_ats_content(_ats_content(hash_alg, covered, time, sig_alg), sig_alg, signers or {})
    return ArchiveTimeStamp(hash_alg, covered, time, anchor_status, sig_alg, sigs,
                            renewal_seed_evidence_class)


def build_initial_sequence(data_digests: Sequence[str], *, hash_alg: str, time: int,
                           anchor_status: str = _CONFIRMED, sig_alg: str = "",
                           signers: Optional[dict] = None) -> list[list[ArchiveTimeStamp]]:
    """The original evidence: one chain with one ATS over the data objects' hash-tree root.

    When ``sig_alg`` + ``signers`` are given the ATS is authenticated by a time-authority signature (the
    RFC-4998 TimeStampToken; verify with ``authority_keys``). Fail-closed on a weak/unknown hash."""
    resolve_hash_alg(hash_alg)  # current-only: never seed a sequence with a deprecated hash
    if not data_digests:
        raise RenewalError("cannot anchor an empty set of data objects")
    ats = _make_ats(hash_alg, _cover_data(data_digests, hash_alg), time, anchor_status, sig_alg, signers)
    return [[ats]]


def _newest(sequence: list[list[ArchiveTimeStamp]]) -> ArchiveTimeStamp:
    if not sequence or not sequence[-1]:
        raise RenewalError("sequence has no ArchiveTimeStamp")
    return sequence[-1][-1]


def _all_ats(sequence: list[list[ArchiveTimeStamp]]) -> list[ArchiveTimeStamp]:
    return [a for chain in sequence for a in chain]


def _require_prior_anchor(prior: ArchiveTimeStamp, *,
                          prior_verification: Optional[VerifiedAnchorResult],
                          require_verified_prior: bool) -> str:
    """Fail-closed gate on the PRIOR ArchiveTimeStamp a renewal is about to extend. Returns the evidence
    class actually relied on (finding 09), tagged by the caller onto the new ATS's
    ``renewal_seed_evidence_class``: ``"cryptographically_verified"`` when a bound, verified
    ``VerifiedAnchorResult`` was supplied, else ``"self_asserted_status"`` (the legacy bare
    ``anchor_status`` label — a HONEST, documented compat boundary: the DEFAULT behavior of every
    existing caller is unchanged, since ``anchor_status="confirmed"`` is also the field default and
    ``build_initial_sequence``'s default; only ``require_verified_prior=True`` or an explicitly supplied
    ``prior_verification`` raises the bar).

    RFC 4998: a renewal extends a VALID prior timestamp. Renewing over an unanchored (pending) prior — or,
    when ``prior_verification`` is supplied, over one whose verification does not hold or does not BIND to
    THIS exact prior — is meaningless: there is nothing whose validity is being carried forward.
    """
    if prior_verification is not None:
        if not isinstance(prior_verification, VerifiedAnchorResult):
            raise RenewalError("prior_verification must be a VerifiedAnchorResult")
        expected_digest = anchor_proof_digest(prior)
        if not (prior_verification.verified is True
                and isinstance(prior_verification.proof_digest, str)
                and prior_verification.proof_digest == expected_digest):
            raise RenewalError(
                "prior_verification does not verify, or its proof_digest does not bind to this prior "
                "ArchiveTimeStamp (expected sha256(prior.token())) — a verification result computed for "
                "a DIFFERENT ArchiveTimeStamp (e.g. an earlier link in the same chain) cannot seed this "
                "renewal (fail-closed, finding 09)")
        return "cryptographically_verified"
    if require_verified_prior:
        raise RenewalError(
            "require_verified_prior=True but no prior_verification (VerifiedAnchorResult) was supplied — "
            "the bare anchor_status label is a self-asserted marker, not cryptographic proof, and "
            "anchor_status='confirmed' is also proofbundle's own default value (fail-closed, finding 09)")
    # legacy path: trust the bare structural marker (self-asserted, no cryptographic proof) — unchanged
    # default behavior, the documented finding-09 compat boundary.
    if prior.anchor_status != _CONFIRMED:
        raise RenewalError(
            f"cannot renew: the prior ArchiveTimeStamp is not confirmed (anchor_status="
            f"{prior.anchor_status!r}) — renew_without_prior_anchor is a fail-closed error")
    return "self_asserted_status"


def _require_int_time(time, prior: "ArchiveTimeStamp") -> None:
    # renew_timestamp/renew_hashtree vergleichen `time <= prior.time`; ein non-int auf einer Seite
    # crashte diesen Vergleich ROH, bevor die RenewalError darunter feuern konnte (Deep-Gate iter9 L2).
    # Das sind raise-Idiom-Konstruktoren (keine never-raise-Verifizierer), also ist der Fix ein
    # typisierter RenewalError — dieselbe fail-closed-Richtung, die das Modul sonst nimmt.
    for label, t in (("renewal", time), ("prior ATS", prior.time)):
        if not isinstance(t, int) or isinstance(t, bool):
            raise RenewalError(f"{label} time must be an int, got {type(t).__name__} (fail-closed)")


def renew_timestamp(sequence: list[list[ArchiveTimeStamp]], *, time: int,
                    anchor_status: str = _CONFIRMED, sig_alg: Optional[str] = None,
                    signers: Optional[dict] = None,
                    prior_verification: Optional[VerifiedAnchorResult] = None,
                    require_verified_prior: bool = False) -> list[list[ArchiveTimeStamp]]:
    """Timestamp renewal: append an ATS to the LAST chain (SAME hash algorithm), covering the prior ATS.

    Used when a timestamp's key/signature algorithm weakens but the hash is still strong. This is where the
    signature layer MIGRATES: pass a stronger ``sig_alg`` (e.g. ``hybrid-ed25519-mldsa65`` → ``mldsa65``)
    + ``signers`` to re-sign the covered prior token under the upgraded algorithm. ``sig_alg=None`` keeps
    the prior algorithm. Time strictly after the prior; fail-closed if the prior anchor is not confirmed.

    ``prior_verification`` (finding 09): an optional ``VerifiedAnchorResult`` proving the PRIOR ATS was
    independently, cryptographically verified (not merely labeled ``anchor_status="confirmed"`` — which is
    also the field default). When supplied it must verify and its ``proof_digest`` must bind to this exact
    prior; ``require_verified_prior=True`` makes it MANDATORY (no bare-label fallback). Neither argument
    changes the default (unverified-label) behavior of an existing caller — additive, fail-closed only when
    opted into. The produced ATS's ``renewal_seed_evidence_class`` records which path was taken."""
    prior = _newest(sequence)
    evidence_class = _require_prior_anchor(
        prior, prior_verification=prior_verification, require_verified_prior=require_verified_prior)
    _require_int_time(time, prior)
    if time <= prior.time:
        raise RenewalError(f"renewal time {_rs(time)} must be strictly after the prior ATS time {_rs(prior.time)}")
    covered = compute_digest(prior.token().encode(), prior.hash_alg)
    new_sig_alg = prior.sig_alg if sig_alg is None else sig_alg
    new = _make_ats(prior.hash_alg, covered, time, anchor_status, new_sig_alg, signers,
                    renewal_seed_evidence_class=evidence_class)
    out = [list(chain) for chain in sequence]
    out[-1].append(new)
    return out


def renew_hashtree(sequence: list[list[ArchiveTimeStamp]], data_digests: Sequence[str], *,
                   new_hash_alg: str, time: int, anchor_status: str = _CONFIRMED,
                   sig_alg: Optional[str] = None,
                   signers: Optional[dict] = None,
                   prior_verification: Optional[VerifiedAnchorResult] = None,
                   require_verified_prior: bool = False) -> list[list[ArchiveTimeStamp]]:
    """Hash-tree renewal: start a NEW chain whose first ATS covers all prior ATS + the data objects under
    ``new_hash_alg``. Used when the hash algorithm weakens. Like ``renew_timestamp`` the signature layer may
    migrate (``sig_alg`` + ``signers``). Time strictly after the prior; fail-closed on a weak/unknown new
    hash or an unconfirmed prior anchor.

    ``prior_verification`` / ``require_verified_prior`` (finding 09): same contract as
    ``renew_timestamp`` — an optional (or, with ``require_verified_prior=True``, mandatory) bound,
    cryptographically verified proof of the prior ATS, additive and fail-closed only when opted into."""
    resolve_hash_alg(new_hash_alg)  # current-only
    prior = _newest(sequence)
    evidence_class = _require_prior_anchor(
        prior, prior_verification=prior_verification, require_verified_prior=require_verified_prior)
    _require_int_time(time, prior)
    if time <= prior.time:
        raise RenewalError(f"renewal time {_rs(time)} must be strictly after the prior ATS time {_rs(prior.time)}")
    covered = _cover_prior_and_data(_all_ats(sequence), data_digests, new_hash_alg)
    new_sig_alg = prior.sig_alg if sig_alg is None else sig_alg
    new_chain = [_make_ats(new_hash_alg, covered, time, anchor_status, new_sig_alg, signers,
                           renewal_seed_evidence_class=evidence_class)]
    return [list(chain) for chain in sequence] + [new_chain]


def last_ats(sequence: list[list[ArchiveTimeStamp]]) -> ArchiveTimeStamp:
    """The single newest ATS — the ONLY one RFC 4998 requires watching for expiry (operating rule)."""
    return _newest(sequence)


def verify_sequence(sequence: list[list[ArchiveTimeStamp]], data_digests: Sequence[str], *,
                    authority_keys: Optional[dict] = None,
                    anchor_verifier: Optional[Callable[[ArchiveTimeStamp], bool]] = None,
                    allow_unauthenticated_anchor: bool = False,
                    require_pq: bool = False,
                    require_current_hash: bool = False,
                    rp_trust: Optional[dict] = None,
                    require_external_token: bool = False,
                    known_newest_token_digest: Optional[str] = None,
                    ) -> VerificationResult:
    """Verify an ArchiveTimeStampSequence end-to-end, walking the newest strong anchor back to the origin.

    Fail-closed checks:
      * every ATS uses a resolvable (non-weak) hash algorithm;
      * the sequence is strictly ascending in time (``sequence_ordered_ascending_by_time``);
      * each timestamp-renewal ATS covers exactly the prior ATS in its chain, and each new chain's first
        ATS covers all-prior-ATS + the data objects (``break_in_sequence_fails``);
      * the covered data recomputes from ``data_digests`` (``tamper_after_renewal_fails``);
      * the newest ATS is authenticated (see the anchor modes below).

    ANCHOR — safe by default. An authenticated anchor is REQUIRED unless the caller explicitly opts into
    the weak structural-only mode:
      * ``authority_keys`` (RECOMMENDED, B3↔B5 wiring): a dict of the relying party's trusted time-authority
        public keys ``{"ed25519": bytes, "mldsa65": bytes}``. The newest ATS MUST carry a valid signature
        (``_verify_ats_signature``) under those keys — a real cryptographic anchor, PQ-capable. A hybrid ATS
        needs both legs. The key material comes from the relying party (WP-A1), never the sequence itself.
      * ``anchor_verifier``: a caller callback bound to an external proof (e.g. an OTS proof), when the
        anchor is not a native ATS signature.
      * ``allow_unauthenticated_anchor=True`` (EXPLICIT opt-in): fall back to the bare ``anchor_status``
        string, which is NOT cryptographically bound (excluded from ``token()``) — a STRUCTURAL check only.
        A PASS here means "structurally consistent", never "cryptographically anchored".
      * NONE of the above: fail closed — the newest-anchor check is FALSE with a clear message. This makes
        a naive ``verify_sequence(seq, data)`` refuse to certify an unauthenticated anchor (API-safety audit).

    ``require_pq`` (PQ floor): the newest ATS's PQ signature must be VERIFIED, not merely labeled. A PQ leg
    is only cryptographically checked in ``authority_keys`` mode (``_verify_ats_signature`` verifies the
    hybrid/mldsa65 signature); in ``anchor_verifier`` / unauthenticated / no-anchor modes the ATS signature
    is never checked, so a ``sig_alg`` label alone is not proof — ``require_pq`` fails closed there (No-Fake).

    ``require_current_hash`` (hash-strength floor): by default a DEPRECATED newest hash is TOLERATED (a
    hash-tree-renewed sequence must stay verifiable while its once-used hash ages; ``evaluate_renewal_policy``
    is what flags a deprecated newest as renewal-overdue). A deprecated newest hash is always SURFACED as a
    ``renewal:current_hash`` check so ``.ok`` alone never hides it; ``require_current_hash=True`` makes it a
    hard fail-closed error for a relying party that wants one call to reject a weak-hash anchor.

    ``rp_trust`` / ``require_external_token`` (Finding 14a-b, additive; ADR 0006 B3 OPEN item): an OPTIONAL,
    ADDITIONAL corroboration of the newest ATS against a REAL external RFC-3161/OTS proof, when the newest
    ATS carries ``external_token_type`` (glue over the already-hardened standalone verifiers via
    ``_verify_ats_external_token`` — never a replacement for the PRIMARY anchor modes above). Not surfaced
    at all when the newest ATS has no ``external_token_type`` (fully backward compatible with every existing
    sequence). ``rp_trust`` is the caller's own relying-party trust material (TSA roots / Bitcoin block
    headers, WP-A1 — mirrors ``anchors.py`` exactly: the ATS's own frozen chain material is evidence, never
    trust). A legitimate non-final external-token state (OTS ``pending`` / ``needs_rp_trust``) is TOLERATED
    by default (``renewal:external_token`` stays ``ok`` — mirrors the WARN tolerance ``anchors.verify_anchors``
    already uses); ``require_external_token=True`` demands the FULL verified state, not merely pending.

    ``known_newest_token_digest`` (Finding 14a-c, additive; ADR 0006 B3 OPEN item "truncation/rollback
    detection... needs an external append-only log, RFC 4998 does not solve this inherently"): RFC 4998 does
    not itself defend against presenting a STALE PREFIX of a legitimately-renewed sequence — dropping the
    later renewal ATS yields a structurally valid (shorter) sequence that verifies unchanged. No
    ``RelyingPartyStateStore`` exists yet in this repo, so this is the additive-parameter fallback: pass the
    ``anchor_proof_digest`` of the newest ATS the relying party last observed for this evidence chain (from
    its own persisted state); the ``renewal:no_rollback`` check FAILS when that remembered ATS is no longer
    present ANYWHERE in the presented sequence (truncated away) and PASSES when it is still present —
    whether unchanged or followed by legitimate further renewals (forward progress). Not surfaced when
    omitted (fully backward compatible).
    """
    result = VerificationResult()

    # shape guard: an untrusted/deserialized sequence must be a list of chains (lists) of ArchiveTimeStamp
    # — a malformed shape fails closed, never an uncaught crash (the never-raise contract).
    if not isinstance(sequence, (list, tuple)) or not all(
            isinstance(chain, (list, tuple)) and all(isinstance(a, ArchiveTimeStamp) for a in chain)
            for chain in sequence):
        result.checks.append(Check(
            "renewal:shape", False,
            "sequence must be a list of chains (lists) of ArchiveTimeStamp"))
        return result

    def _default_anchor(a: ArchiveTimeStamp) -> bool:
        return a.anchor_status == _CONFIRMED

    def _signature_anchor(a: ArchiveTimeStamp) -> bool:
        return _verify_ats_signature(a, authority_keys or {})

    def _no_anchor(_a: ArchiveTimeStamp) -> bool:
        return False

    anchor_mode: str
    if authority_keys is not None:
        verify_anchor: Callable[[ArchiveTimeStamp], bool] = _signature_anchor
        anchor_mode = "authority signature"
    elif anchor_verifier is not None:
        verify_anchor = anchor_verifier
        anchor_mode = "caller anchor_verifier"
    elif allow_unauthenticated_anchor:
        verify_anchor = _default_anchor
        anchor_mode = "structural-only (unauthenticated, opted-in)"
    else:
        verify_anchor = _no_anchor
        anchor_mode = "none supplied"
    flat = _all_ats(sequence)
    if not flat:
        result.checks.append(Check("renewal:nonempty", False, "sequence has no ArchiveTimeStamp"))
        return result
    # Finding 15b (DoS guard): refuse an absurdly long renewal sequence BEFORE the covering-check loop below
    # runs — a hash-tree-renewal chain-start covers ALL prior ATS tokens (`_cover_prior_and_data`), so a
    # sequence with many chain-starts is O(n) per chain-start, O(n * chain-starts) worst case for the whole
    # walk. A legitimate renewal history (decades of periodic algorithm-ageing renewals) is nowhere near
    # this bound; an attacker-assembled sequence with millions of ATS is.
    from .budget import DEFAULT_BUDGET  # noqa: PLC0415
    if not DEFAULT_BUDGET.within("renewal_ats_chain", len(flat)):
        result.checks.append(Check(
            "renewal:budget", False,
            f"sequence has {len(flat)} ArchiveTimeStamp entries (> budget.renewal_ats_chain="
            f"{DEFAULT_BUDGET.renewal_ats_chain}) — refusing (DoS guard, Finding 15b)"))
        return result

    # 1) strictly ascending time across the whole sequence. Guard non-int times (fail-closed, never raise
    #    a TypeError on a hand-built/deserialized sequence with a str time — the "malformed → False" contract).
    times = [a.time for a in flat]
    if not all(isinstance(t, int) and not isinstance(t, bool) for t in times):
        result.checks.append(Check("renewal:ordered", False, f"ATS times must be integers: [{', '.join(_rs(t) for t in times)}]"))
        ordered = False
    elif not all(int_magnitude_ok(t) for t in times):
        # DIE GROESSE, NICHT NUR DER TYP — und der Check gehoert HIERHIN, nicht in `token()`.
        #
        # `token()` refuses an implausible magnitude by RAISING, because there the rendered string
        # IS the signed material and a shortened form would break every existing signature. But
        # this function is a never-raise surface: it owes the caller a VERDICT. Left to `token()`
        # (called further down at the covering check), the refusal would escape as an exception —
        # typed, but still an exception out of a surface whose contract forbids one.
        #
        # Same magnitude, two correct answers, because the two places have different contracts.
        result.checks.append(Check(
            "renewal:ordered", False,
            "ATS time is implausibly large: ["
            + ", ".join(_rs(t) for t in times) + "] — refused fail-closed"))
        # UND ZURUECK, nicht nur markiert. Die erste Fassung setzte `ordered = False` wie der
        # Typ-Check daneben und liess die Funktion weiterlaufen — bis zum `prior.token()` weiter
        # unten, das dann doch warf. Der Typ-Check darf weiterlaufen (ein `str` rendert harmlos),
        # dieser nicht: die Groesse ist genau das, woran das Rendern scheitert. Dieselbe Form wie
        # der Ketten-Budget-Check ein paar Zeilen hoeher, der ebenfalls sofort zurueckgibt.
        return result
    else:
        ordered = all(times[i] < times[i + 1] for i in range(len(times) - 1))
        result.checks.append(Check("renewal:ordered", ordered,
                                   "ATS strictly ascending by time" if ordered
                                   else f"ATS not strictly ascending: [{', '.join(_rs(t) for t in times)}]"))

    # 2) each ATS uses a KNOWN hash algorithm. A now-DEPRECATED algorithm is TOLERATED here: the whole
    #    point of renewal is that a hash-tree-renewed sequence survives the ageing of an algorithm it once
    #    used — verifying a historical chain must not crash or hard-fail just because its (superseded) hash
    #    later became deprecated (the renewal POLICY, evaluate_renewal_policy, is what flags a deprecated
    #    NEWEST ATS as overdue). Only an UNKNOWN/absent algorithm — which cannot be computed at all — fails.
    algs_ok = True
    for a in flat:
        try:
            resolve_hash_alg(a.hash_alg, allow_deprecated=True)
        except HashAlgError as exc:
            algs_ok = False
            result.checks.append(Check(f"renewal:hashalg:{_rs(a.hash_alg)}", False, str(exc)))
    if algs_ok:
        result.checks.append(Check("renewal:hashalg", True, "all ATS use a known hash algorithm"))

    # 3) covering: walk each chain; the first ATS of chain 0 covers the data, the first ATS of every
    #    later chain covers (all ATS before it) + data, and each subsequent ATS in a chain covers the
    #    prior ATS's token.
    seen_before: list[ArchiveTimeStamp] = []
    covering_ok = True
    for ci, chain in enumerate(sequence):
        for ai, a in enumerate(chain):
            try:
                # allow_deprecated: a historical chain's superseded hash must still recompute (see check 2);
                # an unknown/absent algorithm raises HashAlgError → this ATS fails closed (no crash).
                if not (isinstance(a.covered_digest, str) and _HEXRE.match(a.covered_digest)):
                    raise HashAlgError("covered digest is not lowercase hex")
                if ai == 0 and ci == 0:
                    expect = _cover_data(data_digests, a.hash_alg, allow_deprecated=True)
                elif ai == 0:
                    expect = _cover_prior_and_data(seen_before, data_digests, a.hash_alg,
                                                   allow_deprecated=True)
                else:
                    prior = chain[ai - 1]
                    expect = compute_digest(prior.token().encode(), a.hash_alg, allow_deprecated=True)
            except ProofBundleError as exc:  # base class (HashAlgError/RenewalError sind Subtypen):
                # faengt AUCH token()s Magnitude-Guard auf eine Riesen-.time (Deep-Gate iter9 L2) —
                # diese exportierte Flaeche ist never-raise, ein malformer ATS faellt beim Cover-Check
                covering_ok = False
                result.checks.append(Check(f"renewal:cover:c{ci}a{ai}", False,
                                           f"covered digest not verifiable: {exc}"))
                seen_before.append(a)
                continue
            if a.covered_digest != expect:
                covering_ok = False
                result.checks.append(Check(
                    f"renewal:cover:c{ci}a{ai}", False,
                    "covered digest does not recompute (a break in the sequence or tampered data)"))
            seen_before.append(a)
    if covering_ok:
        result.checks.append(Check("renewal:cover", True,
                                   "every ATS covers its prior objects; data recomputes"))

    # 3b) truncation / rollback detection (Finding 14a-c, ADR 0006 B3 OPEN item, additive): a STALE PREFIX
    #     of a legitimately-renewed sequence is itself a structurally valid (shorter) sequence — the covering
    #     check above says nothing about whether LATER renewals were dropped. Only evaluated when the caller
    #     supplies known_newest_token_digest (its own persisted last-observed state); absent -> not surfaced.
    if known_newest_token_digest is not None:
        _known_present = any(anchor_proof_digest(a) == known_newest_token_digest for a in flat)
        result.checks.append(Check(
            "renewal:no_rollback", _known_present,
            "the relying party's previously-known newest ArchiveTimeStamp is still present in this "
            "sequence (no truncation/rollback)" if _known_present else
            "known_newest_token_digest is not present anywhere in this sequence — possible truncation/"
            "rollback to an older prefix (fail-closed)"))

    # 4) the newest ATS must be anchored (only the last ATS is watched, RFC 4998 operating rule). The
    #    anchor_mode is surfaced in the detail so a reader can tell a real signature from the weak
    #    structural fallback (API-safety audit: the PASS text must not conflate the two).
    newest = flat[-1]
    anchored = bool(verify_anchor(newest))
    result.checks.append(Check("renewal:last_anchor", anchored,
                               f"newest ATS anchored via {anchor_mode}" if anchored
                               else f"newest ATS not anchored (mode: {anchor_mode}) — supply authority_keys "
                                    "for a cryptographic anchor"))

    # 4b) optional, ADDITIONAL corroboration of the newest ATS against a REAL external RFC-3161/OTS proof
    #     (Finding 14a-b, ADR 0006 B3 OPEN item, pure glue — never a replacement for the anchor modes above).
    #     Only surfaced when the newest ATS actually carries an external_token_type (fully backward
    #     compatible with every existing sequence that does not use this additive field).
    if newest.external_token_type:
        _ext = _verify_ats_external_token(newest, rp_trust=rp_trust)
        _ext_ok = bool(_ext.get("ok"))
        if not require_external_token:
            # a legitimate non-final state (OTS pending / needs_rp_trust) is tolerated by default, mirroring
            # anchors.verify_anchors' own WARN-does-not-hard-fail discipline; require_external_token demands
            # the FULL verified state.
            _ext_ok = _ext_ok or bool(_ext.get("warn"))
        result.checks.append(Check(
            "renewal:external_token", _ext_ok,
            f"newest ATS external token ({_rs(newest.external_token_type)}): {_ext.get('detail', '')}"))
    elif require_external_token:
        # Fail-closed (crypto-review, 2026-07-15): external_token_type/external_token are DELIBERATELY
        # excluded from the signed ATS bytes (token()/_ats_content()), so an attacker or MITM can strip them
        # from an otherwise authority-signed ATS without breaking any other check. A caller that DEMANDS the
        # external token (require_external_token=True) must therefore get a FAILING check when it is absent —
        # otherwise the whole external-token block is silently skipped and .ok is unaffected (a no-op "require").
        result.checks.append(Check(
            "renewal:external_token", False,
            "require_external_token=True but the newest ATS carries no external_token_type — a detached "
            "RFC-3161/OTS proof is not part of the signed ATS bytes, so its absence (or MITM stripping) is "
            "only caught here; fail-closed."))

    # 5) optional post-quantum strength floor: the newest ATS's signature must carry a PQ leg (mldsa65 or
    #    hybrid), so a relying party that wants PQ protection is not satisfied by a (forgeable-after-quantum)
    #    ed25519-only anchor even while it still holds the ed25519 key for legacy validation.
    if require_pq:
        # No-Fake: require_pq means the PQ leg was actually VERIFIED, not merely labeled. The mldsa leg is
        # only cryptographically checked in authority-signature mode (_verify_ats_signature verifies the
        # hybrid/mldsa65 signature over _ats_content); in anchor_verifier / unauthenticated / no-anchor modes
        # the ATS signature is never checked, so a PQ label on newest.sig_alg proves nothing — fail closed.
        # fix-the-CLASS: a non-str sig_alg (attacker-built ATS) crashed `"mldsa" in (int or "")` with a
        # raw TypeError; normalize for the membership test, render every field through _rs.
        _sig_label = newest.sig_alg if isinstance(newest.sig_alg, str) else ""
        pq_verified = anchored and anchor_mode == "authority signature" and "mldsa" in _sig_label
        if pq_verified:
            pq_detail = (f"newest ATS carries a VERIFIED PQ leg (sig_alg {_rs(newest.sig_alg)}, authority "
                         "signature)")
        elif anchor_mode != "authority signature":
            pq_detail = (f"require_pq needs authority_keys to verify a PQ signature; anchor mode is "
                         f"{anchor_mode!r} (a PQ label on sig_alg alone is not verification, fail-closed)")
        else:
            pq_detail = f"newest ATS sig_alg {_rs(newest.sig_alg)} has no verified PQ leg (require_pq)"
        result.checks.append(Check("renewal:pq_floor", pq_verified, pq_detail))

    # hash-strength floor: a DEPRECATED newest hash is tolerated by default (historical-chain survival) but
    # must never be hidden behind .ok — surface it as a check, and fail closed when require_current_hash.
    # require_current_hash demands a KNOWN CURRENT hash: a deprecated OR unknown newest hash fails closed
    # (an unknown hash also fails the resolvable-hash check above; here it is never mislabeled "current").
    newest_dep = _is_deprecated_hash(newest.hash_alg)
    _spec = HASH_REGISTRY.get(newest.hash_alg) if isinstance(newest.hash_alg, str) else None
    newest_current = _spec is not None and _spec.status == "current"
    if newest_dep or require_current_hash:
        hash_ok = newest_current if require_current_hash else True
        if newest_dep:
            hash_detail = (f"newest ATS hash {_rs(newest.hash_alg)} is deprecated"
                           + (" (require_current_hash, fail-closed)" if require_current_hash
                              else " — .ok reflects structure, not hash strength; call evaluate_renewal_policy "
                                   "or pass require_current_hash=True to reject"))
        elif newest_current:
            hash_detail = f"newest ATS hash {_rs(newest.hash_alg)} is current"
        else:
            hash_detail = f"newest ATS hash {_rs(newest.hash_alg)} is not a known current hash (require_current_hash)"
        result.checks.append(Check("renewal:current_hash", hash_ok, hash_detail))
    return result


# --- B4 renewal policy and triggers ------------------------------------------------------------


@dataclass(frozen=True)
class RenewalPolicy:
    """When the newest ArchiveTimeStamp must be renewed. Purely local — NEVER fetches anything.

    ``deprecated_algs`` are hash algorithms considered weak by policy (a renewal is overdue regardless of
    age when the newest ATS uses one). ``max_ats_age`` is the maximum age (in the same integer unit as an
    ATS ``time``) before the newest ATS is overdue. ``strictness`` decides the report: ``warn`` (an overdue
    renewal is a WARN) or ``fail`` (an overdue renewal is a hard FAIL). Following the RFC-4998 operating
    rule, ONLY the newest ATS is examined."""

    deprecated_algs: frozenset[str] = frozenset()
    max_ats_age: Optional[int] = None
    strictness: str = "warn"

    @classmethod
    def from_dict(cls, obj: dict) -> "RenewalPolicy":
        strictness = obj.get("strictness", "warn")
        if strictness not in ("warn", "fail"):
            raise RenewalError(f"renewal policy strictness must be 'warn' or 'fail', got {strictness!r}")
        return cls(
            deprecated_algs=frozenset(_as_list(obj.get("deprecated_algs", []))),
            max_ats_age=obj.get("max_ats_age"),
            strictness=strictness,
        )


def evaluate_renewal_policy(sequence: list[list[ArchiveTimeStamp]], *, policy: RenewalPolicy,
                            now: int) -> VerificationResult:
    """Report whether the newest ArchiveTimeStamp is overdue for renewal, per ``policy`` (no network).

    Examines ONLY the newest ATS (``watch_only_last_ats``). It is overdue when its hash algorithm is in
    ``policy.deprecated_algs`` OR (``max_ats_age`` set AND ``now - newest.time > max_ats_age``). An overdue
    renewal is a WARN or a FAIL per ``policy.strictness``; a fresh, strong newest ATS is a PASS."""
    result = VerificationResult()
    # 6-lens gate L3-02: a type-confused sequence ('notlist', [123], [['x']], [[{}]], ...) reached
    # _newest(sequence).hash_alg as a raw AttributeError/TypeError, and an empty sequence raised RenewalError,
    # out of this exported never-raise surface. Fail closed with the SAME renewal:shape / renewal:nonempty
    # checks the sibling verify_sequence already carries (a shared shape contract), never an uncaught crash.
    if not isinstance(sequence, (list, tuple)) or not all(
            isinstance(chain, (list, tuple)) and all(isinstance(a, ArchiveTimeStamp) for a in chain)
            for chain in sequence):
        result.checks.append(Check("renewal:shape", False,
                                   "sequence must be a list of chains (lists) of ArchiveTimeStamp"))
        return result
    if not sequence or not sequence[-1]:
        result.checks.append(Check("renewal:nonempty", False, "sequence has no ArchiveTimeStamp"))
        return result
    newest = _newest(sequence)
    # Deep-Gate iter9 L2: eine non-int newest.time erreichte `now - newest.time` als rohen TypeError
    # aus dieser never-raise-Flaeche. Fail-closed mit typisiertem Check, gleiche Richtung wie der Shape-Guard.
    if not isinstance(newest.time, int) or isinstance(newest.time, bool):
        result.checks.append(Check("renewal:time_malformed", False,
                                   f"newest ATS time must be an int, got {type(newest.time).__name__} (fail-closed)"))
        return result
    # fix-the-CLASS (Deep-Gate iter9 Linse C): `now` is the OTHER operand of `now - newest.time` below; an
    # earlier round guarded newest.time but left the caller's `now` unchecked, so a non-int `now` still
    # crashed this never-raise surface with a raw TypeError. Same guard, same fail-closed direction.
    if not isinstance(now, int) or isinstance(now, bool):
        result.checks.append(Check("renewal:now_malformed", False,
                                   f"now must be an int, got {type(now).__name__} (fail-closed)"))
        return result

    reasons = []
    if isinstance(newest.hash_alg, str) and newest.hash_alg in policy.deprecated_algs:
        reasons.append(f"newest ATS uses policy-deprecated hash {newest.hash_alg!r}")
    # Future-dated guard (No-Fake): a newest.time AFTER `now` is anomalous — the freshness/age test below
    # ((now - newest.time) > max_ats_age) goes NEGATIVE for a future time and would report it as perpetually
    # fresh, so a future date could otherwise permanently evade the renewal-due signal. Flag it as overdue.
    _ints = all(isinstance(v, int) and not isinstance(v, bool) for v in (newest.time, now))
    if _ints and newest.time > now:
        reasons.append(f"newest ATS time {_rs(newest.time)} is in the future (now={_rs(now)}) — anomalous, not fresh")
    if policy.max_ats_age is not None and (now - newest.time) > policy.max_ats_age:
        reasons.append(f"newest ATS age {_rs(now - newest.time)} exceeds max {_rs(policy.max_ats_age)}")

    if not reasons:
        result.checks.append(Check("renewal:policy", True,
                                   f"newest ATS ({_rs(newest.hash_alg)}, age {_rs(now - newest.time)}) is within "
                                   "policy — no renewal due"))
        return result

    overdue_ok = policy.strictness == "warn"  # WARN → not a hard fail; FAIL → ok=False
    label = "WARN" if overdue_ok else "FAIL"
    detail = f"renewal overdue ({label}): " + "; ".join(reasons)
    result.checks.append(Check("renewal:policy", overdue_ok, detail))
    return result
