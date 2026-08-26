"""Deep-Gate iter9, 4. Runde (2026-08-26): drei WIDERLEGT-Funde + eine No-Fake-Unterbehauptung.

Generator-Haertung statt Punktfixture (B7_STANDING_BERKELEY_GATE_LEARNS): jeder Fund haertet eine
PROPERTY ueber viele Eingaben, mit einem STRUKTURELL UNABHAENGIGEN Orakel (Anti-Paritaet).

- Linse 1 (Merkle): verify_consistency pruefte `fn == 0` statt RFC 9162 §2.1.4.2 `sn == 0`. `fn == 0` ist
  fuer eine Zweierpotenz-first VACUOUS (first=1 -> fn=0 von Anfang an) und akzeptierte JEDE second — der
  Lens-Exploit (1,2) akzeptierte {3..32}. Fix: `sn == 0`. Beweis der Korrektheit: proofbundle stimmt
  danach mit einem unabhaengigen RFC-6962-bis-Dekompositions-Orakel (Trillian-Stil, Laengen-Check statt
  Shift-Loop) exakt ueberein. Die verbleibende SCHMALE Groessen-Ambiguitaet ist inhaerent (das Orakel
  akzeptiert dieselbe Menge) und durch atomares (size,root) aus signierten STHs abgesichert.
  Plus No-Fake: die verify_inclusion-Docstring bezifferte die Ambiguitaet als 'N±1' statt der Bande.
- Linse 2 (Renewal): ArchiveTimeStamp.time ohne Typ-Guard -> non-int Zeit crashte roh.
- iter9-Selbstfund (rfc3161): frozen=None (REQUIRED-Arg fehlgerufen) -> roher AttributeError statt Verdikt.
"""
import pytest
from proofbundle.merkle import (
    leaf_hash, _node_hash, merkle_tree_hash, consistency_proof, verify_consistency,
    inclusion_proof, verify_inclusion,
)
from proofbundle.renewal import (ArchiveTimeStamp, verify_sequence, evaluate_renewal_policy,
                                 renew_timestamp, renew_hashtree, RenewalPolicy, RenewalError)
from proofbundle.anchors_rfc3161 import verify_rfc3161
from proofbundle.errors import ProofBundleError


# --- Unabhaengiges Orakel: RFC-6962-bis-Dekomposition (Trillian-Stil), NICHT proofbundles Shift-Loop. ---
def _oracle_consistency(size1, size2, proof, root1, root2):
    if size1 == 0 or size1 > size2:
        return False
    if size1 == size2:
        return len(proof) == 0 and root1 == root2
    inner = ((size1 - 1) ^ (size2 - 1)).bit_length()
    border = bin((size1 - 1) >> inner).count("1")
    shift = (size1 & -size1).bit_length() - 1  # trailing zeros of size1
    inner -= shift
    if size1 == (1 << shift):
        seed, start = root1, 0
    else:
        if not proof:
            return False
        seed, start = proof[0], 1
    if len(proof) != start + inner + border:  # die Groessen-Bindung des Referenz-Algorithmus
        return False
    p = proof[start:]
    mask = (size1 - 1) >> shift

    def chain_inner(s, pr, idx):
        for i, h in enumerate(pr):
            s = _node_hash(s, h) if ((idx >> i) & 1) == 0 else _node_hash(h, s)
        return s

    def chain_inner_right(s, pr, idx):
        for i, h in enumerate(pr):
            if ((idx >> i) & 1) == 1:
                s = _node_hash(h, s)
        return s

    def chain_border_right(s, pr):
        for h in pr:
            s = _node_hash(h, s)
        return s

    h1 = chain_border_right(chain_inner_right(seed, p[:inner], mask), p[inner:])
    h2 = chain_border_right(chain_inner(seed, p[:inner], mask), p[inner:])
    return h1 == root1 and h2 == root2


class TestMerkleConsistencyFnSnFix:
    def test_ursprungs_1_2_bande_geschlossen(self):
        """Der Lens-Exploit: ein echter (1,2)-Beweis darf NICHT unter second {3..32} akzeptiert werden."""
        leaves = [leaf_hash(b"a"), leaf_hash(b"b")]
        r1, r2 = merkle_tree_hash(leaves[:1]), merkle_tree_hash(leaves)
        proof = consistency_proof(leaves, 1)
        assert verify_consistency(1, 2, proof, r1, r2) is True
        assert all(not verify_consistency(1, N, proof, r1, r2) for N in range(3, 33))

    def test_stimmt_exakt_mit_unabhaengigem_orakel(self):
        """Stark + anti-Paritaet: proofbundle == RFC-6962-bis-Dekompositions-Orakel ueber viele Tripel.

        Faengt sowohl den `fn==0`-Bug (proofbundle waere permissiver als das Orakel) ALS AUCH ein
        Ueber-Fixen (proofbundle waere strenger). 0 Divergenzen ist die Korrektheitsaussage."""
        divergenzen = []
        for second in range(2, 40):
            leaves = [leaf_hash(bytes([i % 256, i >> 8])) for i in range(second)]
            r2 = merkle_tree_hash(leaves)
            for first in range(1, second):
                r1 = merkle_tree_hash(leaves[:first])
                proof = consistency_proof(leaves, first)
                for n2 in range(first, second * 2 + 3):
                    pb = verify_consistency(first, n2, proof, r1, r2)
                    orc = _oracle_consistency(first, n2, proof, r1, r2)
                    if pb != orc:
                        divergenzen.append((first, second, n2, pb, orc))
        assert divergenzen == [], f"proofbundle weicht vom Referenz-Orakel ab: {divergenzen[:10]}"

    def test_das_orakel_diskriminiert_wirklich(self):
        """Kontrolle gegen ein triviales Orakel: es lehnt die (1,2)-Bande ab, akzeptiert aber (1,3)->4 —
        also urteilt es, statt alles/nichts zu sagen (sonst waere die 0-Divergenz-Aussage wertlos)."""
        leaves2 = [leaf_hash(b"a"), leaf_hash(b"b")]
        p12 = consistency_proof(leaves2, 1)
        r1_2, r2_2 = merkle_tree_hash(leaves2[:1]), merkle_tree_hash(leaves2)
        assert not _oracle_consistency(1, 5, p12, r1_2, r2_2)  # (1,2)-Bande abgelehnt
        leaves3 = [leaf_hash(bytes([i])) for i in range(3)]
        p13 = consistency_proof(leaves3, 1)
        r1_3, r2_3 = merkle_tree_hash(leaves3[:1]), merkle_tree_hash(leaves3)
        assert _oracle_consistency(1, 4, p13, r1_3, r2_3)  # inhaerente Nachbar-Akzeptanz


class TestVerifyInclusionDocstringEhrlich:
    def test_docstring_nennt_die_bande_nicht_nur_n_plus_minus_1(self):
        doc = verify_inclusion.__doc__ or ""
        assert "WHOLE BAND" in doc and ("NOT merely" in doc or "not merely" in doc.lower())
        # gemessene Realitaet: die Bande ist breiter als N±1
        N, idx = 255, 0
        L = [leaf_hash(bytes([i % 256])) for i in range(N)]
        root, leaf, proof = merkle_tree_hash(L), L[idx], inclusion_proof(L, idx)
        akzeptiert = [m for m in range(1, 513) if m != N and verify_inclusion(leaf, idx, m, proof, root)]
        assert len(akzeptiert) > 2


class TestRenewalTimeConsumersFailClosed:
    """Linse 2: `.time` ohne Typ-Guard crashte roh. Der ETABLIERTE Vertrag (test_renewal_signed:
    test_non_int_time_fails_closed_not_raise) ist: ein ATS mit non-int .time IST konstruierbar, und die
    KONSUMENTEN behandeln ihn fail-closed (verify_*: Verdikt ok=False, kein raise) bzw. typisiert (renew_*:
    RenewalError). Der Fix sitzt an den vier Konsumenten, NICHT an der Konstruktion."""
    D = "ab" * 32

    def test_ats_mit_non_int_zeit_ist_konstruierbar(self):
        assert ArchiveTimeStamp("sha256", self.D, "1000", "confirmed").time == "1000"

    def test_verify_sequence_single_non_int_ok_false_kein_raise(self):
        a = ArchiveTimeStamp("sha256", self.D, "1000", "confirmed")
        assert verify_sequence([[a]], [self.D]).ok is False

    def test_verify_sequence_giant_plus_str_ok_false_kein_raise(self):
        # Lens-2-#1: die if/elif-Kombination liess einen Riesen-int an token() → ProofBundleError, vom
        # `except (HashAlgError, RenewalError)` NICHT gefangen. Jetzt `except ProofBundleError` → fail-closed.
        ag = ArchiveTimeStamp("sha256", self.D, 1 << 9000, "confirmed")
        as_ = ArchiveTimeStamp("sha256", self.D, "x", "confirmed")
        assert verify_sequence([[ag], [as_]], [self.D]).ok is False

    def test_evaluate_renewal_policy_non_int_ok_false_kein_raise(self):
        a = ArchiveTimeStamp("sha256", self.D, "x", "confirmed")
        res = evaluate_renewal_policy([[a]], policy=RenewalPolicy(max_ats_age=100), now=2000)
        assert res.ok is False

    def test_renew_non_int_prior_typisiert_kein_roher_crash(self):
        # renew_* sind raise-Idiom-Konstruktoren -> typisierter RenewalError, nie roher TypeError
        a = ArchiveTimeStamp("sha256", self.D, "x", "confirmed")
        with pytest.raises(RenewalError):
            renew_timestamp([[a]], time=3000, anchor_status="confirmed")
        with pytest.raises(RenewalError):
            renew_hashtree([[a]], [self.D], new_hash_alg="sha256", time=3000, anchor_status="confirmed")

    def test_riesen_int_konstruierbar_token_weist_ab(self):
        with pytest.raises(ProofBundleError):
            ArchiveTimeStamp("sha256", self.D, 1 << 9000, "confirmed").token()


class TestRfc3161FrozenNoneTyped:
    """frozen ist ein REQUIRED-Argument; frozen=None ist ein Fehlaufruf -> typisiert, nie roher Crash."""

    @pytest.mark.parametrize("rp", [{}, {"trusted_tsa_roots": ["x"]}, None])
    def test_frozen_none_immer_typisiert(self, rp):
        with pytest.raises(ProofBundleError):
            verify_rfc3161(b"garbage", b"\x00" * 32, frozen=None, rp_trust=rp)
