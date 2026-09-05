"""Die inkrementelle Praefix-Deckung muss dasselbe ERGEBNIS liefern wie der naive Weg — Byte fuer Byte.

WARUM DIESE DATEI EXISTIERT. ``verify_sequence`` rechnete die Deckung eines Kettenanfangs bis
2026-09-05 fuer JEDEN Kettenanfang neu ueber alle vorherigen ATS (``_cover_prior_and_data``). Das war
quadratisch INNERHALB der Schranke ``budget.renewal_ats_chain``, die genau das verhindern sollte
(deep gate 6.0.0, L2-600-01, P2): 10.000 Eintraege — der GROESSTE ZUGELASSENE Wert, denn
``budget.within`` prueft ``<=`` — kosteten auf diesem Baum 59,5 s Rechenzeit, 10.001 Eintraege wurden
in 0,002 s abgewiesen. Der Durchlauf fuehrt den Hash-Zustand jetzt inkrementell mit
(``_PraefixDeckung``) und ist linear.

WAS HIER GEPRUEFT WIRD, UND WAS NICHT. Diese Datei prueft NICHT die Laufzeit — das tut
``test_budget_kostenkurve.py``. Sie prueft das ERGEBNIS gegen ein unabhaengiges Orakel: die naiven
Funktionen ``_cover_data`` / ``_cover_prior_and_data`` sind unveraendert geblieben (``renew_hashtree``
benutzt sie weiter), also rechnet der Referenz-Durchlauf hier mit ANDEREM Code dieselbe Wahrheit aus.
Waeren die Bytes auch nur an einer Stelle andere, wuerde jede existierende Sequenz aufhoeren zu
verifizieren — ein schneller Verifizierer, der etwas anderes verifiziert, ist kein Fortschritt.

KORPUS STATT PUNKTVORLAGE. Verglichen wird nicht eine Sequenz, sondern eine erzeugte Menge: echte
Erneuerungsketten (Zeitstempel- und Hashbaum-Erneuerung, signiert und unsigniert, ueber mehrere
Algorithmen) UND die kaputten Formen, an denen sich Fehlerreihenfolgen unterscheiden koennten —
leere Datendigests, ungueltige Datendigests, ein Token das wirft, ein unbekannter und ein
veralteter Algorithmus, eine unhashbare Algorithmus-Kennung. Verglichen wird die VOLLSTAENDIGE
Checkliste (Name, ok, Text), nicht nur ``.ok``: ein Text, der einen anderen Grund nennt, ist ein
anderes Ergebnis.

DIE ARBEITSZAEHLUNG IST DETERMINISTISCH. Der Beweis der Linearitaet steht hier nicht als Sekunden,
sondern als Zaehlung: ``token()``-Aufrufe je ATS. Vorher n*(n-1)/2 + n, nachher genau n. Diese Zahl
haengt nicht von der Maschine, der Last oder dem Wetter ab.
"""
from __future__ import annotations

import pytest

from proofbundle.errors import ProofBundleError, VerificationResult
from proofbundle.hashalg import HashAlgError, compute_digest
from proofbundle.renewal import (
    _HEXRE,
    ArchiveTimeStamp,
    RenewalError,
    _cover_data,
    _cover_prior_and_data,
    _PraefixDeckung,
    build_initial_sequence,
    renew_hashtree,
    renew_timestamp,
    verify_sequence,
)

NULL = "aa" * 32


# --------------------------------------------------------------------------- das unabhaengige Orakel
def _referenz_cover_checks(sequence, data_digests) -> list:
    """Der Deckungs-Durchlauf in seiner NAIVEN Form — Wort fuer Wort die Fassung von vor L2-600-01.

    Sie ruft ``_cover_data`` / ``_cover_prior_and_data`` auf, also den Code, den der Fix NICHT
    angefasst hat. Damit ist das hier ein unabhaengiges Orakel und keine Wiederholung derselben
    Rechnung mit denselben Zeilen.
    """
    seen_before: list = []
    ausgabe: list = []
    covering_ok = True
    for ci, chain in enumerate(sequence):
        for ai, a in enumerate(chain):
            try:
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
            except ProofBundleError as exc:
                covering_ok = False
                ausgabe.append((f"renewal:cover:c{ci}a{ai}", False,
                                f"covered digest not verifiable: {exc}"))
                seen_before.append(a)
                continue
            if a.covered_digest != expect:
                covering_ok = False
                ausgabe.append((f"renewal:cover:c{ci}a{ai}", False,
                                "covered digest does not recompute (a break in the sequence or "
                                "tampered data)"))
            seen_before.append(a)
    if covering_ok:
        ausgabe.append(("renewal:cover", True,
                        "every ATS covers its prior objects; data recomputes"))
    return ausgabe


def _cover_checks(ergebnis: VerificationResult) -> list:
    return [(c.name, c.ok, c.detail) for c in ergebnis.checks if c.name.startswith("renewal:cover")]


# --------------------------------------------------------------------------- der Korpus
def _echte_kette(sig_alg: str = "", signers=None):
    seq = build_initial_sequence([NULL], hash_alg="sha256", time=1000,
                                 sig_alg=sig_alg, signers=signers)
    seq = renew_timestamp(seq, time=2000, sig_alg=sig_alg or None, signers=signers)
    seq = renew_hashtree(seq, [NULL], new_hash_alg="sha512", time=3000,
                         sig_alg=sig_alg or None, signers=signers)
    seq = renew_timestamp(seq, time=4000, sig_alg=sig_alg or None, signers=signers)
    seq = renew_hashtree(seq, [NULL], new_hash_alg="sha3-256", time=5000,
                         sig_alg=sig_alg or None, signers=signers)
    return seq


def _signer():
    from proofbundle.emit import generate_signer
    return generate_signer()


def _korpus() -> list:
    """(name, sequence, data_digests). Jeder neue Fund haertet DIESE Liste, nicht eine Einzelvorlage."""
    sk = _signer()
    mehrere = sorted(["%064x" % i for i in range(3)])
    faelle = [
        ("echte kette unsigniert", _echte_kette(), [NULL]),
        ("echte kette signiert", _echte_kette("ed25519", {"ed25519": sk}), [NULL]),
        ("echte kette, andere datendigests", _echte_kette(), ["bb" * 32]),
        ("initial allein", build_initial_sequence([NULL], hash_alg="sha256", time=7), [NULL]),
        ("initial mit drei digests",
         build_initial_sequence(mehrere, hash_alg="sha256", time=7), mehrere),
        ("leere datendigests", [[ArchiveTimeStamp("sha256", NULL, 1)],
                                [ArchiveTimeStamp("sha256", NULL, 2)]], []),
        ("ungueltige datendigests", [[ArchiveTimeStamp("sha256", NULL, 1)],
                                     [ArchiveTimeStamp("sha256", NULL, 2)]], ["nicht-hex!"]),
        # unsortierte Datendigests: die Deckung sortiert sie, und ein Weg, der das vergisst, faellt
        # nur auf, wenn der Korpus eine unsortierte Menge enthaelt (Generator-Haertung, nicht Punktfall)
        ("mehrere datendigests, unsortiert uebergeben",
         [[ArchiveTimeStamp("sha256", NULL, i + 1)] for i in range(4)],
         ["ff" * 32, "00" * 32, "aa" * 32, "77" * 32]),
        ("mehrere datendigests, unsortiert, echte kette",
         _echte_kette(), ["ff" * 32, "00" * 32, "aa" * 32]),
        ("nur kettenanfaenge, nichts deckt",
         [[ArchiveTimeStamp("sha256", NULL, i + 1)] for i in range(6)], [NULL]),
        ("gemischte algorithmen an kettenanfaengen",
         [[ArchiveTimeStamp(a, NULL, i + 1)]
          for i, a in enumerate(["sha256", "sha512", "sha3-512", "sha384", "sha3-256"])], [NULL]),
        ("veralteter algorithmus am kettenanfang",
         [[ArchiveTimeStamp("sha1", NULL, 1)], [ArchiveTimeStamp("sha256", NULL, 2)]], [NULL]),
        ("unbekannter algorithmus am kettenanfang",
         [[ArchiveTimeStamp("sha999", NULL, 1)], [ArchiveTimeStamp("sha256", NULL, 2)]], [NULL]),
        ("unhashbare algorithmus-kennung",
         [[ArchiveTimeStamp(["sha256"], NULL, 1)], [ArchiveTimeStamp("sha256", NULL, 2)]], [NULL]),
        ("covered_digest nicht klein-hex",
         [[ArchiveTimeStamp("sha256", "AA" * 32, 1)], [ArchiveTimeStamp("sha256", NULL, 2)]], [NULL]),
        # token() wirft: der Praefix ist ab hier vergiftet, JEDER spaetere Kettenanfang muss
        # denselben Fehler melden wie der naive Weg, der die Liste jedes Mal neu baut.
        ("token wirft: time ist keine zahl",
         [[ArchiveTimeStamp("sha256", NULL, 1)], [ArchiveTimeStamp("sha256", NULL, "zwei")],
          [ArchiveTimeStamp("sha256", NULL, 3)], [ArchiveTimeStamp("sha256", NULL, 4)]], [NULL]),
        ("token wirft: sig_alg ist keine zeichenkette",
         [[ArchiveTimeStamp("sha256", NULL, 1)],
          [ArchiveTimeStamp("sha256", NULL, 2, "confirmed", 123)],
          [ArchiveTimeStamp("sha256", NULL, 3)]], [NULL]),
        ("token wirft: signaturen sind keine paare",
         [[ArchiveTimeStamp("sha256", NULL, 1)],
          [ArchiveTimeStamp("sha256", NULL, 2, "confirmed", "ed25519", [("a",)])],
          [ArchiveTimeStamp("sha256", NULL, 3)]], [NULL]),
        # eine LEERE Kette vorne: der erste ATS ueberhaupt steht dann in Kette 1, nicht in Kette 0 —
        # der alte Weg nahm dafuer _cover_prior_and_data([]), der neue den leeren Praefix
        ("leere kette am anfang",
         [[], [ArchiveTimeStamp("sha256", NULL, 1)], [ArchiveTimeStamp("sha512", NULL, 2)]], [NULL]),
        ("ketten mit mehreren gliedern",
         [[ArchiveTimeStamp("sha256", NULL, 1), ArchiveTimeStamp("sha256", NULL, 2)],
          [ArchiveTimeStamp("sha512", NULL, 3), ArchiveTimeStamp("sha512", NULL, 4)]], [NULL]),
    ]
    return faelle


KORPUS = _korpus()


class TestErgebnisOrakel:
    """B2, erste Haelfte: stimmt das ERGEBNIS — nicht die Laufzeit."""

    @pytest.mark.parametrize("name,seq,daten", KORPUS, ids=[f[0] for f in KORPUS])
    def test_die_checkliste_ist_dieselbe_wie_beim_naiven_weg(self, name, seq, daten):
        ist = _cover_checks(verify_sequence(seq, daten, allow_unauthenticated_anchor=True))
        soll = _referenz_cover_checks(seq, daten)
        assert ist == soll, (
            f"{name}: die inkrementelle Deckung kommt zu einem anderen Ergebnis als der naive Weg.\n"
            f"  inkrementell: {ist}\n  naiv:         {soll}")

    @pytest.mark.parametrize("name,seq,daten", KORPUS, ids=[f[0] for f in KORPUS])
    def test_deckung_ist_byteidentisch_an_jeder_praefixlaenge(self, name, seq, daten):
        """Nicht nur am Ende gleich, sondern an JEDER Stelle des Durchlaufs.

        Ein Fehler, der sich erst ab dem dritten Kettenanfang zeigt, faende ein Vergleich nur am
        Schluss nicht.
        """
        flach = [a for kette in seq for a in kette]
        algs = {a.hash_alg for a in flach if isinstance(a.hash_alg, str)}
        if not algs:
            pytest.skip("kein aufloesbarer Algorithmus in dieser Sequenz")
        deckung = _PraefixDeckung(daten, algs, allow_deprecated=True)
        for i in range(len(flach) + 1):
            for alg in sorted(algs):
                naiv_wert = naiv_fehler = None
                try:
                    naiv_wert = _cover_prior_and_data(flach[:i], daten, alg, allow_deprecated=True)
                except ProofBundleError as exc:
                    naiv_fehler = f"{type(exc).__name__}: {exc}"
                neu_wert = neu_fehler = None
                try:
                    neu_wert = deckung.deckung(alg)
                except ProofBundleError as exc:
                    neu_fehler = f"{type(exc).__name__}: {exc}"
                assert (neu_wert, neu_fehler) == (naiv_wert, naiv_fehler), (
                    f"{name}: Praefixlaenge {i}, Algorithmus {alg}")
            if i < len(flach):
                deckung.aufnehmen(flach[i])

    def test_leerer_praefix_ist_genau_cover_data(self):
        """``_cover_data(d, a)`` und ``_cover_prior_and_data([], d, a)`` sind derselbe Wert — darauf
        stuetzt sich, dass der Durchlauf den Sonderfall 'erster ATS ueberhaupt' nicht mehr braucht."""
        for daten in ([NULL], ["bb" * 32, "aa" * 32], []):
            for alg in ("sha256", "sha512", "sha3-256"):
                deckung = _PraefixDeckung(daten, [alg])
                assert deckung.deckung(alg) == _cover_data(daten, alg) \
                    == _cover_prior_and_data([], daten, alg)


class TestArbeitszaehlung:
    """B2, zweite Haelfte: der Beweis der Linearitaet ist eine ZAEHLUNG, keine Uhrzeit."""

    class _ZaehlATS(ArchiveTimeStamp):
        """``isinstance(x, ArchiveTimeStamp)`` bleibt wahr, der Shape-Guard laesst sie also durch."""
        zaehler = 0

        def token(self) -> str:
            type(self).zaehler += 1
            return super().token()

    def _zaehle(self, n: int) -> int:
        typ = TestArbeitszaehlung._ZaehlATS
        typ.zaehler = 0
        seq = [[typ("sha256", NULL, i + 1)] for i in range(n)]
        verify_sequence(seq, [NULL], allow_unauthenticated_anchor=True)
        return typ.zaehler

    @pytest.mark.parametrize("n", [50, 100, 200, 400])
    def test_genau_ein_token_je_ats(self, n):
        """Der naive Weg brauchte n*(n-1)/2 Aufrufe fuer dieselbe Antwort. Diese Zahl ist
        deterministisch: sie haengt nicht von Maschine, Last oder Messfehler ab."""
        assert self._zaehle(n) == n, "die Tokenliste wird wieder je Kettenanfang neu gebaut"

    def test_die_zaehlung_waechst_linear_nicht_quadratisch(self):
        klein, gross = self._zaehle(100), self._zaehle(800)
        assert gross == 8 * klein, (
            f"achtfache Eingabe, {gross / klein:.1f}-fache Arbeit — bei quadratischem Verhalten "
            "waeren es 64")


class TestNichtEinDauerNein:
    """ANTI-PARITAET. Ein Durchlauf, der jede Sequenz ablehnt, bestuende jede Zeitmessung und jeden
    Vergleich mit einem ebenso kaputten Orakel. Echte Erneuerungen muessen weiter verifizieren."""

    def test_eine_echte_erneuerungskette_verifiziert_weiter(self):
        seq = _echte_kette()
        res = verify_sequence(seq, [NULL], allow_unauthenticated_anchor=True)
        assert res.ok, [str(c) for c in res.checks if not c.ok]

    def test_eine_signierte_kette_verifiziert_gegen_ihren_schluessel(self):
        sk = _signer()
        seq = _echte_kette("ed25519", {"ed25519": sk})
        res = verify_sequence(seq, [NULL],
                              authority_keys={"ed25519": sk.public_key().public_bytes_raw()})
        assert res.ok, [str(c) for c in res.checks if not c.ok]

    def test_ein_gebrochenes_glied_faellt_weiterhin_auf(self):
        seq = _echte_kette()
        seq[1][0] = ArchiveTimeStamp(seq[1][0].hash_alg, "cc" * 32, seq[1][0].time)
        res = verify_sequence(seq, [NULL], allow_unauthenticated_anchor=True)
        assert not res.ok
        assert any(c.name.startswith("renewal:cover:") and not c.ok for c in res.checks)


class TestAngemeldeteAlgorithmen:
    """Der Zustand kann nur vorwaerts wachsen, also muessen die Kennungen vorher feststehen. Wer eine
    nicht angemeldete anfragt, bekommt eine typisierte Absage statt eines Digests ueber einen
    unvollstaendigen Praefix."""

    def test_nicht_angemeldeter_algorithmus_wird_typisiert_abgelehnt(self):
        deckung = _PraefixDeckung([NULL], ["sha256"])
        deckung.aufnehmen(ArchiveTimeStamp("sha256", NULL, 1))
        with pytest.raises(RenewalError, match="no prefix state"):
            deckung.deckung("sha512")

    def test_der_durchlauf_meldet_jede_kettenanfangs_kennung_an(self):
        """Die Gegenrichtung: durch ``verify_sequence`` darf diese Absage NIE entstehen, weil die
        Menge dort aus genau denselben Ausdruecken gebaut wird, die sie spaeter anfragen."""
        seq = [[ArchiveTimeStamp(a, NULL, i + 1)]
               for i, a in enumerate(sorted({"sha256", "sha512", "sha3-256", "sha384", "sha3-512",
                                             "sha1", "md5"}))]
        res = verify_sequence(seq, [NULL], allow_unauthenticated_anchor=True)
        assert not any("no prefix state" in c.detail for c in res.checks), \
            [str(c) for c in res.checks]
