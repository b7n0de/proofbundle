"""B2 hash-agility — an explicit registry of hash algorithms with fail-closed resolution and a
dual-hash helper (ADR 0006).

Why this module exists. proofbundle's surfaces already DECLARE their hash construction per artifact
(``merkle.hash_alg = "sha256-rfc6962"``, ``contentRootAlg = "jcs-sha256-v1"``, a checkpoint's
``hashAlg``). What was missing for long-term evidence is a single agility layer: one registry that
says which hash PRIMITIVES are allowed, which are deprecated, and a resolver that NEVER silently
defaults a missing/unknown/weak algorithm — the exact place an algorithm-confusion attack would hide
(RFC 7696 §2.1; ADR 0002 §2 warns of the same at the content-root level). The algorithm id maps to the
RFC 4998 (ERS) ``digestAlgorithm`` OID, so the B3 renewal chain builds directly on this registry.

Model: the IANA Named Information Hash Algorithm registry (RFC 6920) — an id, a status
(``current`` / ``deprecated``), and enough to compute and size the digest. Deprecation follows the NIST
transition (SHA-1 retired; SHA-256/384/512 and the SHA-3 family current — NIST FIPS 180-4 / 202,
SP 800-131A).

Fail-closed contract:
  * an absent/empty id is ``MissingHashAlgId`` — there is NO implicit SHA-256;
  * an id not in the registry is ``UnknownHashAlg``;
  * a deprecated id is ``DeprecatedHashAlg`` unless the caller explicitly opts into legacy verification
    (``allow_deprecated=True``) — a verifier may need to read an old receipt, but nothing NEW is ever
    produced with a weak hash, and a dual-hash's PASS requires at least one current algorithm.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Optional

from .budget import DEFAULT_BUDGET, render_safe
from .errors import Check, ProofBundleError, VerificationResult

__all__ = [
    "HASH_REGISTRY",
    "HashAlg",
    "HashAlgError",
    "MissingHashAlgId",
    "UnknownHashAlg",
    "DeprecatedHashAlg",
    "resolve_hash_alg",
    "compute_digest",
    "compute_dual_hash",
    "verify_dual_hash",
]


class HashAlgError(ProofBundleError):
    """Base class for every hash-agility failure (a subclass of ``ProofBundleError``)."""


class MissingHashAlgId(HashAlgError):
    """No algorithm id was given. Fail-closed: proofbundle never defaults a missing hash to SHA-256."""


class UnknownHashAlg(HashAlgError):
    """The algorithm id is not in ``HASH_REGISTRY``. Fail-closed: an unknown hash is never trusted."""


class DeprecatedHashAlg(HashAlgError):
    """The algorithm is known but deprecated and the caller did not opt into legacy verification."""


@dataclass(frozen=True)
class HashAlg:
    """One registry entry: how to compute the digest, its size, its status, and its ERS OID.

    ``ers_oid`` is the RFC 4998 ``digestAlgorithm`` ``AlgorithmIdentifier`` OID, so a renewal chain (B3)
    references the same identity this registry defines. ``hashlib_name`` is the ``hashlib.new`` name."""

    id: str
    hashlib_name: str
    digest_size: int
    status: str  # "current" | "deprecated"
    ers_oid: str

    def new(self) -> "hashlib._Hash":
        return hashlib.new(self.hashlib_name)


# The allowed hash primitives. SHA-256/384/512 (FIPS 180-4) and SHA3-256/512 (FIPS 202) are current;
# SHA-1 and MD5 are deprecated (kept only so a verifier can READ and clearly reject a legacy receipt).
# OIDs are the NIST/RFC AlgorithmIdentifier values used by RFC 4998 digestAlgorithm.
HASH_REGISTRY: dict[str, HashAlg] = {
    "sha256": HashAlg("sha256", "sha256", 32, "current", "2.16.840.1.101.3.4.2.1"),
    "sha384": HashAlg("sha384", "sha384", 48, "current", "2.16.840.1.101.3.4.2.2"),
    "sha512": HashAlg("sha512", "sha512", 64, "current", "2.16.840.1.101.3.4.2.3"),
    "sha3-256": HashAlg("sha3-256", "sha3_256", 32, "current", "2.16.840.1.101.3.4.2.8"),
    "sha3-512": HashAlg("sha3-512", "sha3_512", 64, "current", "2.16.840.1.101.3.4.2.10"),
    "sha1": HashAlg("sha1", "sha1", 20, "deprecated", "1.3.14.3.2.26"),
    "md5": HashAlg("md5", "md5", 16, "deprecated", "1.2.840.113549.2.5"),
}


def resolve_hash_alg(alg_id: Optional[str], *, allow_deprecated: bool = False) -> HashAlg:
    """Resolve an algorithm id to its registry entry, fail-closed.

    Raises ``MissingHashAlgId`` for an absent/empty id (no implicit default), ``UnknownHashAlg`` for an
    id not in the registry, and ``DeprecatedHashAlg`` for a weak algorithm unless ``allow_deprecated``.
    """
    if not alg_id or not isinstance(alg_id, str):
        raise MissingHashAlgId(
            "a hash algorithm id is required — proofbundle never defaults a missing hash to SHA-256")
    spec = HASH_REGISTRY.get(alg_id)
    if spec is None:
        # deep gate 2026-09-05 (L3-600-01, hashalg member): the id comes from an untrusted digests map; a
        # huge int (or a tuple holding one) tripped the int->str cap inside this message as a raw ValueError.
        raise UnknownHashAlg(
            f"unknown hash algorithm {render_safe(alg_id)} — not in the allowed registry "
            f"({', '.join(sorted(HASH_REGISTRY))})")
    if spec.status == "deprecated" and not allow_deprecated:
        raise DeprecatedHashAlg(
            f"hash algorithm {render_safe(alg_id)} is deprecated and rejected by default; a legacy verifier must "
            "opt in explicitly (allow_deprecated=True)")
    return spec


def compute_digest(data: bytes, alg_id: str, *, allow_deprecated: bool = False) -> str:
    """Hex digest of ``data`` under ``alg_id`` (fail-closed on missing/unknown/deprecated)."""
    spec = resolve_hash_alg(alg_id, allow_deprecated=allow_deprecated)
    h = spec.new()
    h.update(data)
    return h.hexdigest()


def compute_dual_hash(data: bytes, alg_ids: Sequence[str]) -> dict[str, str]:
    """Digests of ``data`` under two or more DISTINCT CURRENT algorithms — for a NEW receipt.

    A dual hash lets an old receipt survive the deprecation of one hash: as long as a second,
    independent current hash still binds the same bytes, the evidence keeps its force while a renewal
    (B3) migrates it. A new receipt therefore requires at least two distinct current algorithms; a
    deprecated algorithm is rejected outright (nothing new is produced with a weak hash)."""
    seen: dict[str, HashAlg] = {}
    for alg_id in alg_ids:
        spec = resolve_hash_alg(alg_id)  # current-only: no allow_deprecated on the produce path
        if spec.id in seen:
            raise HashAlgError(f"dual hash needs DISTINCT algorithms, {spec.id!r} was given twice")
        seen[spec.id] = spec
    if len(seen) < 2:
        raise HashAlgError(
            "a dual hash needs at least two distinct current algorithms "
            "(e.g. sha256 + sha512 or sha256 + sha3-256)")
    return {alg_id: compute_digest(data, alg_id) for alg_id in seen}


def _enforce_structural_budget(obj, *, budget=None):
    """Lokaler Zugriff auf den Strukturwaechter, spaet importiert (Zirkelbezug-frei)."""
    from ._strict_json import enforce_structural_budget  # noqa: PLC0415
    enforce_structural_budget(obj, budget=budget)


def verify_dual_hash(data: bytes, digests: Mapping[str, str]) -> VerificationResult:
    """Verify that EVERY declared digest binds ``data``, and that at least one is a CURRENT algorithm.

    Fail-closed: an empty map fails; an unknown algorithm fails; a single mismatching leg fails the
    whole result; a bag of only-deprecated digests fails even when the bytes match (a legacy-only
    receipt has lost its force and must be renewed, not silently accepted). A deprecated leg is checked
    (``allow_deprecated``) so its presence is visible, but it cannot by itself carry a PASS."""
    result = VerificationResult()
    if not isinstance(digests, Mapping) or not digests:
        result.checks.append(Check("hashalg:dual", False,
                                   "digests must be a non-empty mapping of alg -> hex"))
        return result
    if not isinstance(data, (bytes, bytearray, memoryview)):
        # 6-lens gate L3-02: compute_digest(data, ...) -> h.update(data) raised a raw TypeError on a non-bytes
        # `data` (the digests + each expected are guarded, but the primary data arg was not). This public
        # never-raise surface must return a fail-closed VerificationResult, not crash a relying party.
        result.checks.append(Check("hashalg:dual", False, "data must be bytes-like"))
        return result
    # DAS STRUKTURBUDGET GILT AUCH FUER EIN ARGUMENT, DAS NICHT DAS ERSTE IST (deep gate Lauf 9,
    # L2-600-DUALHASH-NODES-INERT-01, P3). `digests` ist eine unvertraute Abbildung, und die Schleife
    # darunter arbeitet PRO EINTRAG. Gemessen: eine Million Eintraege kosteten 3,68 s und +399 MB,
    # linear unbegrenzt — waehrend derselbe Inhalt ueber den Parse-Weg an `json_nodes` abgewiesen
    # wird. Die Ablehnung muss auf BEIDEN Wegen gleich ausfallen, sonst ist die Schranke eine Aussage
    # ueber den Eingabeweg statt ueber die Last.
    #
    # Diese Flaeche darf nie werfen, deshalb wird die Budgetverletzung in einen fail-closed Check
    # uebersetzt statt durchgereicht.
    #
    # GEFANGEN WIRD ProofBundleError, NICHT NUR BudgetExceeded (Gegenlesung 09.09.2026 durch
    # qwen3.8:27b, Frage F6 — ihr Befund war richtig und meiner falsch). Der Waechter wirft ZWEI
    # Arten: `BudgetExceeded` bei Ueberbreite und `BundleFormatError` bei Uebertiefe. Sein eigener
    # Docstring sagt das woertlich, und die erste Fassung dieses Blocks fing nur die erste.
    # GEMESSEN: `digests` mit einem 300 Ebenen tiefen Wert liess `BundleFormatError: JSON nesting
    # is too deep` durch diese never-raise-Flaeche entweichen. Ein Fix gegen eine Ueberlast hatte
    # damit einen neuen Weg geoeffnet, den Aufrufer abstuerzen zu lassen.
    #
    # Beide sind ProofBundleError-Subklassen, also faengt die Oberklasse beide — und jede kuenftige
    # Art, die der Waechter dazubekommt, ebenfalls. Eine Aufzaehlung neben einer Hierarchie ist eine
    # zweite Quelle und wandert nicht mit.
    #
    # FAENGT DIESE OBERKLASSE ZU VIEL? Die Gegenlesung liess das als NICHT PRUEFBAR offen, weil ihr
    # `_strict_json.py` nicht vorlag — zu Recht, denn eine Ausnahme, die NICHTS mit dem Budget zu
    # tun hat, waere hier als "digests exceed the structural budget" gemeldet und haette ihre
    # eigentliche Ursache verdeckt. NACHGEMESSEN per AST ueber
    # `_strict_json._enforce_structural_budget` (09.09.2026): 28 Aufrufe, davon 0 unbenennbare;
    # genau ZWEI Wurf-Arten (BudgetExceeded an 5 Stellen, BundleFormatError an 2), und alles sonst
    # Aufgerufene ist ein Builtin (append, bit_length, isinstance, items, len, pop, type). Der Fang
    # kann hier also keine fremde Ursache tarnen.
    #
    # Die Zahl der UNBENENNBAREN Aufrufe steht mit im Ergebnis, weil die erste Messung sie
    # stillschweigend wegfilterte: "es gab keine" und "ich habe keine gesehen" sind verschiedene
    # Aussagen, und nur die erste traegt.
    #
    # OHNE DIE GROESSEN-ACHSE `int_bits` (Vollsuite 09.09.2026, zwei rote Faelle in
    # tests/test_ablehnungstext_rendert_beschraenkt.py). Diese Flaeche hat die Magnitude-Klasse
    # BEREITS geloest, und zwar besser: `render_safe` BESCHREIBT einen riesigen Schluessel
    # (`<int, 16610 bits>`), statt ihn zu drucken, und die Ablehnung nennt damit den Uebeltaeter.
    # Der Budget-Waechter haette davor abgebrochen und nur allgemein "int_bits ueberschritten"
    # gemeldet — dieselbe Ablehnung, aber ohne die Angabe, WELCHER Eintrag sie ausgeloest hat.
    #
    # Der Fund, gegen den dieser Block gebaut ist, war die ANZAHL der Eintraege (eine Million
    # Digest-Eintraege = 3,68 s und +399 MB), nicht die Groesse eines einzelnen. Die Achsen
    # `json_nodes`, `json_depth` und `string_len` bleiben deshalb scharf; nur `int_bits` tritt hier
    # zurueck, weil sie an dieser Flaeche schon typisiert behandelt wird — und der rote Test ist der
    # Beleg dafuer, dass sie es tut.
    _budget_ohne_intachse = replace(DEFAULT_BUDGET, int_bits=1 << 30)
    try:
        _enforce_structural_budget(digests, budget=_budget_ohne_intachse)
    except ProofBundleError as exc:
        result.checks.append(Check("hashalg:dual", False,
                                   f"digests exceed the structural budget: {exc}"))
        return result

    current_ok = 0
    for alg_id, expected in digests.items():
        try:
            spec = resolve_hash_alg(alg_id, allow_deprecated=True)
        except HashAlgError as exc:
            # the Check NAME renders the untrusted key too (quote=False keeps 'hashalg:sha256' byte-identical
            # for every real id; only an unrenderable/huge key is described instead of printed)
            result.checks.append(Check(f"hashalg:{render_safe(alg_id, quote=False)}", False, str(exc)))
            continue
        actual = compute_digest(data, alg_id, allow_deprecated=True)
        # KEINE NORMALISIERUNG DES ERWARTETEN (deep gate Lauf 9, L1-600-HEXCASE-01, P3).
        # Hier stand `actual == expected.lower()`. `actual` ist per Konstruktion die kanonische
        # Kleinbuchstaben-Hexform; das `.lower()` auf der ANDEREN Seite machte daraus zwei
        # akzeptierte Drahtformen desselben Digests — ein signiertes Artefakt hatte auf dieser
        # oeffentlichen Flaeche mehr als eine gueltige Schreibweise.
        #
        # Das ist dieselbe Eigenschaft, die `_wire_b64` auf der base64-Achse durchsetzt: der Wert
        # wird als die Form verglichen, die er zu sein ERKLAERT. Der Sweep von damals fegte die
        # base64-Achse und liess die Hex-Achse stehen — ein Klassenfix, der eine Achse traf und die
        # benachbarte nicht.
        #
        # Ehrliche Einordnung: ein FALSCHER Digest wurde nie angenommen (gemessen), deshalb P3.
        # Eine abweichende Schreibweise bekommt ihren EIGENEN Grund, damit sie nicht als
        # inhaltlicher Fehlschlag missverstanden wird.
        match = isinstance(expected, str) and actual == expected
        detail = "digest matches" if match else "digest mismatch"
        if (not match and isinstance(expected, str) and expected.lower() == actual):
            detail = ("digest matches the payload but is not in canonical lowercase hex — a digest "
                      "field has exactly one accepted wire form")
        if match and spec.status == "deprecated":
            detail = "digest matches but algorithm is deprecated (does not carry a PASS on its own)"
        result.checks.append(Check(f"hashalg:{render_safe(alg_id, quote=False)}", match, detail))
        if match and spec.status == "current":
            current_ok += 1

    all_match = all(c.ok for c in result.checks)
    if all_match and current_ok == 0:
        result.checks.append(Check(
            "hashalg:current-binding", False,
            "no CURRENT-algorithm digest binds the payload — a legacy-only receipt must be renewed"))
    return result
