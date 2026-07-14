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

from .errors import Check, ProofBundleError, VerificationResult
from .hashalg import HASH_REGISTRY, HashAlgError, compute_digest, resolve_hash_alg
from .pqsig import sign_mldsa, verify_hybrid, verify_mldsa
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
    "build_initial_sequence",
    "renew_timestamp",
    "renew_hashtree",
    "verify_sequence",
    "last_ats",
    "evaluate_renewal_policy",
]

_CONFIRMED = "confirmed"
_SEP = "\n"


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
    ``verify_sequence`` (a real signature check supersedes it). ``time`` orders the sequence + drives expiry."""

    hash_alg: str
    covered_digest: str
    time: int
    anchor_status: str = _CONFIRMED
    sig_alg: str = ""
    signatures: tuple = field(default_factory=tuple)

    def token(self) -> str:
        """The stable string a later ATS covers when it renews this one — RFC 4998 timestamp renewal covers
        the prior timestamp token INCLUDING its signature. Unsigned ATS keep the legacy (base) form so
        existing sequences are unaffected."""
        base = f"{self.hash_alg}:{self.covered_digest}:{self.time}"
        if not self.sig_alg:
            return base
        sig_part = ";".join(f"{a}={s}" for a, s in sorted(self.signatures))
        return f"{base}:{self.sig_alg}:{sig_part}"


def _ats_content(hash_alg: str, covered_digest: str, time: int, sig_alg: str) -> bytes:
    """The exact bytes a time authority SIGNS for an ATS (domain-separated, pre-signature).

    ``sig_alg`` IS bound into the signed bytes (algorithm-confusion defense, JWT-``alg`` class): a
    signature produced under one algorithm label cannot be relabeled to a weaker one and re-verified — a
    hybrid ATS's ed25519 leg, if relabeled ``sig_alg="ed25519"``, would be checked against DIFFERENT bytes
    and fail. Without this binding a post-quantum attacker could downgrade a hybrid/mldsa65 ATS to its
    classical leg with no forgery."""
    return f"archivetimestamp/v1\n{sig_alg}\n{hash_alg}\n{covered_digest}\n{time}".encode()


def _sign_ats_content(content: bytes, sig_alg: str, signers: dict) -> tuple:
    """Produce the ``signatures`` tuple for ``content`` under ``sig_alg`` from ``signers`` (a dict
    ``{"ed25519": ed25519_private_key, "mldsa65": mldsa65_private_key}``). Fail-closed on a missing signer
    or an unknown algorithm."""
    if sig_alg not in _SIG_ALGS:
        raise RenewalError(f"unknown ATS signature algorithm {sig_alg!r} (one of {_SIG_ALGS})")
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
    if not ats.sig_alg:
        return False
    content = _ats_content(ats.hash_alg, ats.covered_digest, ats.time, ats.sig_alg)
    # robust against a malformed signatures field (None / non-2-tuple entries) — fail-closed, never raise
    sigmap: dict[str, str] = {}
    for item in ats.signatures or ():
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
    if ats.sig_alg == "mldsa65":
        pub = authority_keys.get("mldsa65")
        return pub is not None and verify_mldsa(pub, _dec("mldsa65"), content)
    if ats.sig_alg == "hybrid-ed25519-mldsa65":
        edp, mp = authority_keys.get("ed25519"), authority_keys.get("mldsa65")
        if edp is None or mp is None:
            return False
        return verify_hybrid(classical_pub=edp, classical_sig=_dec("ed25519"),
                             pq_pub=mp, pq_sig=_dec("mldsa65"), message=content)
    return False


def _is_deprecated_hash(alg: str) -> bool:
    """True iff ``alg`` is a KNOWN but deprecated registry hash (sha1/md5). An unknown/absent alg is not
    'deprecated' (it fails the resolvable-hash check instead)."""
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
              sig_alg: str, signers: Optional[dict]) -> ArchiveTimeStamp:
    """Construct an ATS, signing its content when ``sig_alg`` is set (the RFC-4998 TimeStampToken)."""
    sigs: tuple = ()
    if sig_alg:
        sigs = _sign_ats_content(_ats_content(hash_alg, covered, time, sig_alg), sig_alg, signers or {})
    return ArchiveTimeStamp(hash_alg, covered, time, anchor_status, sig_alg, sigs)


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


def _require_prior_anchor(prior: ArchiveTimeStamp) -> None:
    # RFC 4998: a renewal extends a VALID prior timestamp. Renewing over an unanchored (pending) prior is
    # meaningless — there is nothing whose validity is being carried forward.
    if prior.anchor_status != _CONFIRMED:
        raise RenewalError(
            f"cannot renew: the prior ArchiveTimeStamp is not confirmed (anchor_status="
            f"{prior.anchor_status!r}) — renew_without_prior_anchor is a fail-closed error")


def renew_timestamp(sequence: list[list[ArchiveTimeStamp]], *, time: int,
                    anchor_status: str = _CONFIRMED, sig_alg: Optional[str] = None,
                    signers: Optional[dict] = None) -> list[list[ArchiveTimeStamp]]:
    """Timestamp renewal: append an ATS to the LAST chain (SAME hash algorithm), covering the prior ATS.

    Used when a timestamp's key/signature algorithm weakens but the hash is still strong. This is where the
    signature layer MIGRATES: pass a stronger ``sig_alg`` (e.g. ``hybrid-ed25519-mldsa65`` → ``mldsa65``)
    + ``signers`` to re-sign the covered prior token under the upgraded algorithm. ``sig_alg=None`` keeps
    the prior algorithm. Time strictly after the prior; fail-closed if the prior anchor is not confirmed."""
    prior = _newest(sequence)
    _require_prior_anchor(prior)
    if time <= prior.time:
        raise RenewalError(f"renewal time {time} must be strictly after the prior ATS time {prior.time}")
    covered = compute_digest(prior.token().encode(), prior.hash_alg)
    new_sig_alg = prior.sig_alg if sig_alg is None else sig_alg
    new = _make_ats(prior.hash_alg, covered, time, anchor_status, new_sig_alg, signers)
    out = [list(chain) for chain in sequence]
    out[-1].append(new)
    return out


def renew_hashtree(sequence: list[list[ArchiveTimeStamp]], data_digests: Sequence[str], *,
                   new_hash_alg: str, time: int, anchor_status: str = _CONFIRMED,
                   sig_alg: Optional[str] = None,
                   signers: Optional[dict] = None) -> list[list[ArchiveTimeStamp]]:
    """Hash-tree renewal: start a NEW chain whose first ATS covers all prior ATS + the data objects under
    ``new_hash_alg``. Used when the hash algorithm weakens. Like ``renew_timestamp`` the signature layer may
    migrate (``sig_alg`` + ``signers``). Time strictly after the prior; fail-closed on a weak/unknown new
    hash or an unconfirmed prior anchor."""
    resolve_hash_alg(new_hash_alg)  # current-only
    prior = _newest(sequence)
    _require_prior_anchor(prior)
    if time <= prior.time:
        raise RenewalError(f"renewal time {time} must be strictly after the prior ATS time {prior.time}")
    covered = _cover_prior_and_data(_all_ats(sequence), data_digests, new_hash_alg)
    new_sig_alg = prior.sig_alg if sig_alg is None else sig_alg
    new_chain = [_make_ats(new_hash_alg, covered, time, anchor_status, new_sig_alg, signers)]
    return [list(chain) for chain in sequence] + [new_chain]


def last_ats(sequence: list[list[ArchiveTimeStamp]]) -> ArchiveTimeStamp:
    """The single newest ATS — the ONLY one RFC 4998 requires watching for expiry (operating rule)."""
    return _newest(sequence)


def verify_sequence(sequence: list[list[ArchiveTimeStamp]], data_digests: Sequence[str], *,
                    authority_keys: Optional[dict] = None,
                    anchor_verifier: Optional[Callable[[ArchiveTimeStamp], bool]] = None,
                    allow_unauthenticated_anchor: bool = False,
                    require_pq: bool = False,
                    require_current_hash: bool = False
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

    # 1) strictly ascending time across the whole sequence. Guard non-int times (fail-closed, never raise
    #    a TypeError on a hand-built/deserialized sequence with a str time — the "malformed → False" contract).
    times = [a.time for a in flat]
    if not all(isinstance(t, int) and not isinstance(t, bool) for t in times):
        result.checks.append(Check("renewal:ordered", False, f"ATS times must be integers: {times}"))
        ordered = False
    else:
        ordered = all(times[i] < times[i + 1] for i in range(len(times) - 1))
        result.checks.append(Check("renewal:ordered", ordered,
                                   "ATS strictly ascending by time" if ordered
                                   else f"ATS not strictly ascending: {times}"))

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
            result.checks.append(Check(f"renewal:hashalg:{a.hash_alg}", False, str(exc)))
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
            except (HashAlgError, RenewalError) as exc:
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

    # 4) the newest ATS must be anchored (only the last ATS is watched, RFC 4998 operating rule). The
    #    anchor_mode is surfaced in the detail so a reader can tell a real signature from the weak
    #    structural fallback (API-safety audit: the PASS text must not conflate the two).
    newest = flat[-1]
    anchored = bool(verify_anchor(newest))
    result.checks.append(Check("renewal:last_anchor", anchored,
                               f"newest ATS anchored via {anchor_mode}" if anchored
                               else f"newest ATS not anchored (mode: {anchor_mode}) — supply authority_keys "
                                    "for a cryptographic anchor"))

    # 5) optional post-quantum strength floor: the newest ATS's signature must carry a PQ leg (mldsa65 or
    #    hybrid), so a relying party that wants PQ protection is not satisfied by a (forgeable-after-quantum)
    #    ed25519-only anchor even while it still holds the ed25519 key for legacy validation.
    if require_pq:
        # No-Fake: require_pq means the PQ leg was actually VERIFIED, not merely labeled. The mldsa leg is
        # only cryptographically checked in authority-signature mode (_verify_ats_signature verifies the
        # hybrid/mldsa65 signature over _ats_content); in anchor_verifier / unauthenticated / no-anchor modes
        # the ATS signature is never checked, so a PQ label on newest.sig_alg proves nothing — fail closed.
        pq_verified = anchored and anchor_mode == "authority signature" and "mldsa" in (newest.sig_alg or "")
        if pq_verified:
            pq_detail = (f"newest ATS carries a VERIFIED PQ leg (sig_alg {newest.sig_alg!r}, authority "
                         "signature)")
        elif anchor_mode != "authority signature":
            pq_detail = (f"require_pq needs authority_keys to verify a PQ signature; anchor mode is "
                         f"{anchor_mode!r} (a PQ label on sig_alg alone is not verification, fail-closed)")
        else:
            pq_detail = f"newest ATS sig_alg {newest.sig_alg!r} has no verified PQ leg (require_pq)"
        result.checks.append(Check("renewal:pq_floor", pq_verified, pq_detail))

    # hash-strength floor: a DEPRECATED newest hash is tolerated by default (historical-chain survival) but
    # must never be hidden behind .ok — surface it as a check, and fail closed when require_current_hash.
    newest_dep = _is_deprecated_hash(newest.hash_alg)
    if newest_dep or require_current_hash:
        hash_ok = not (newest_dep and require_current_hash)
        if newest_dep and require_current_hash:
            hash_detail = f"newest ATS hash {newest.hash_alg!r} is deprecated (require_current_hash, fail-closed)"
        elif newest_dep:
            hash_detail = (f"newest ATS hash {newest.hash_alg!r} is deprecated — .ok reflects structure, not "
                           "hash strength; call evaluate_renewal_policy or pass require_current_hash=True to reject")
        else:
            hash_detail = f"newest ATS hash {newest.hash_alg!r} is current"
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
            deprecated_algs=frozenset(obj.get("deprecated_algs", []) or []),
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
    newest = _newest(sequence)

    reasons = []
    if newest.hash_alg in policy.deprecated_algs:
        reasons.append(f"newest ATS uses policy-deprecated hash {newest.hash_alg!r}")
    # Future-dated guard (No-Fake): a newest.time AFTER `now` is anomalous — the freshness/age test below
    # ((now - newest.time) > max_ats_age) goes NEGATIVE for a future time and would report it as perpetually
    # fresh, so a future date could otherwise permanently evade the renewal-due signal. Flag it as overdue.
    _ints = all(isinstance(v, int) and not isinstance(v, bool) for v in (newest.time, now))
    if _ints and newest.time > now:
        reasons.append(f"newest ATS time {newest.time} is in the future (now={now}) — anomalous, not fresh")
    if policy.max_ats_age is not None and (now - newest.time) > policy.max_ats_age:
        reasons.append(f"newest ATS age {now - newest.time} exceeds max {policy.max_ats_age}")

    if not reasons:
        result.checks.append(Check("renewal:policy", True,
                                   f"newest ATS ({newest.hash_alg}, age {now - newest.time}) is within "
                                   "policy — no renewal due"))
        return result

    overdue_ok = policy.strictness == "warn"  # WARN → not a hard fail; FAIL → ok=False
    label = "WARN" if overdue_ok else "FAIL"
    detail = f"renewal overdue ({label}): " + "; ".join(reasons)
    result.checks.append(Check("renewal:policy", overdue_ok, detail))
    return result
