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

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Optional

from .errors import Check, ProofBundleError, VerificationResult
from .hashalg import HashAlgError, compute_digest, resolve_hash_alg

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
    """One RFC-4998 ArchiveTimeStamp: a covered digest under a hash algorithm, at a time, with an anchor.

    ``covered_digest`` is the hex digest this ATS commits to (a hash-tree root over its covered objects).
    ``anchor_status`` models the backing time anchor (``confirmed`` = the OTS/RFC-3161 proof is verified;
    ``pending`` = not yet). ``time`` orders the sequence and drives expiry."""

    hash_alg: str
    covered_digest: str
    time: int
    anchor_status: str = _CONFIRMED

    def token(self) -> str:
        """The stable string a later ATS covers when it renews this one (the timestamp token stand-in)."""
        return f"{self.hash_alg}:{self.covered_digest}:{self.time}"


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


def build_initial_sequence(data_digests: Sequence[str], *, hash_alg: str, time: int,
                           anchor_status: str = _CONFIRMED) -> list[list[ArchiveTimeStamp]]:
    """The original evidence: one chain with one ATS over the data objects' hash-tree root.

    The sequence is a list of chains; each chain a list of ATS. Fail-closed on a weak/unknown hash."""
    resolve_hash_alg(hash_alg)  # current-only: never seed a sequence with a deprecated hash
    if not data_digests:
        raise RenewalError("cannot anchor an empty set of data objects")
    ats = ArchiveTimeStamp(hash_alg, _cover_data(data_digests, hash_alg), time, anchor_status)
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
                    anchor_status: str = _CONFIRMED) -> list[list[ArchiveTimeStamp]]:
    """Timestamp renewal: append an ATS to the LAST chain (SAME hash algorithm), covering the prior ATS.

    Used when a timestamp's key/signature algorithm weakens but the hash is still strong. Time must be
    strictly greater than the prior ATS. Fail-closed if the prior anchor is not confirmed."""
    prior = _newest(sequence)
    _require_prior_anchor(prior)
    if time <= prior.time:
        raise RenewalError(f"renewal time {time} must be strictly after the prior ATS time {prior.time}")
    new = ArchiveTimeStamp(prior.hash_alg, compute_digest(prior.token().encode(), prior.hash_alg),
                           time, anchor_status)
    out = [list(chain) for chain in sequence]
    out[-1].append(new)
    return out


def renew_hashtree(sequence: list[list[ArchiveTimeStamp]], data_digests: Sequence[str], *,
                   new_hash_alg: str, time: int,
                   anchor_status: str = _CONFIRMED) -> list[list[ArchiveTimeStamp]]:
    """Hash-tree renewal: start a NEW chain whose first ATS covers all prior ATS + the data objects under
    ``new_hash_alg``. Used when the hash algorithm weakens. Time strictly after the prior ATS; fail-closed
    on a weak/unknown new hash or an unconfirmed prior anchor."""
    resolve_hash_alg(new_hash_alg)  # current-only
    prior = _newest(sequence)
    _require_prior_anchor(prior)
    if time <= prior.time:
        raise RenewalError(f"renewal time {time} must be strictly after the prior ATS time {prior.time}")
    covered = _cover_prior_and_data(_all_ats(sequence), data_digests, new_hash_alg)
    new_chain = [ArchiveTimeStamp(new_hash_alg, covered, time, anchor_status)]
    return [list(chain) for chain in sequence] + [new_chain]


def last_ats(sequence: list[list[ArchiveTimeStamp]]) -> ArchiveTimeStamp:
    """The single newest ATS — the ONLY one RFC 4998 requires watching for expiry (operating rule)."""
    return _newest(sequence)


def verify_sequence(sequence: list[list[ArchiveTimeStamp]], data_digests: Sequence[str], *,
                    anchor_verifier: Optional[Callable[[ArchiveTimeStamp], bool]] = None
                    ) -> VerificationResult:
    """Verify an ArchiveTimeStampSequence end-to-end, walking the newest strong anchor back to the origin.

    Fail-closed checks:
      * every ATS uses a resolvable (non-weak) hash algorithm;
      * the sequence is strictly ascending in time (``sequence_ordered_ascending_by_time``);
      * each timestamp-renewal ATS covers exactly the prior ATS in its chain, and each new chain's first
        ATS covers all-prior-ATS + the data objects (``break_in_sequence_fails``);
      * the covered data recomputes from ``data_digests`` (``tamper_after_renewal_fails``);
      * the newest ATS has a confirmed anchor (``anchor_verifier``; default: anchor_status == confirmed).

    SECURITY — ``anchor_verifier``: the DEFAULT only checks the bare ``anchor_status`` string, which is
    NOT cryptographically bound (it is deliberately excluded from ``token()``, so no hash in the chain
    covers it — anyone who can construct/edit the sequence JSON can set it to "confirmed"). The default is
    a STRUCTURAL check only. For real trust a caller MUST pass an ``anchor_verifier`` that verifies each
    ATS against an actual external time-anchor proof (e.g. an RFC-3161 token or an OTS proof via
    ``anchors_ots.verify_opentimestamps``). Treat a PASS under the default anchor_verifier as
    "structurally consistent", never as "cryptographically anchored".
    """
    result = VerificationResult()
    verify_anchor = anchor_verifier or (lambda a: a.anchor_status == _CONFIRMED)
    flat = _all_ats(sequence)
    if not flat:
        result.checks.append(Check("renewal:nonempty", False, "sequence has no ArchiveTimeStamp"))
        return result

    # 1) strictly ascending time across the whole sequence
    times = [a.time for a in flat]
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

    # 4) the newest ATS must be anchored (only the last ATS is watched, RFC 4998 operating rule)
    newest = flat[-1]
    anchored = bool(verify_anchor(newest))
    result.checks.append(Check("renewal:last_anchor", anchored,
                               "newest ATS is anchored" if anchored
                               else "newest ATS has no confirmed anchor — renewal is overdue/unbacked"))
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
