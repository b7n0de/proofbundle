"""Eine Schranke gegen die LAENGE begrenzt nichts, solange der geschuetzte Durchlauf ueberlinear ist.

DIE KLASSE (deep gate 6.0.0, L2-600-01, P2 — die Instanz war ``renewal.verify_sequence``). Jede
Budget-Dimension existiert, um Kosten zu begrenzen. Sie begrenzt aber nur eine ZAHL an der Eingabe:
Eintraege, Knoten, Schritte, Bits. Was diese Zahl KOSTET, sagt sie nicht. Ist der geschuetzte
Durchlauf ueberlinear, dann liegt der teuerste zugelassene Fall beliebig weit ueber dem, was die
Schranke zu verhindern scheint — und der erste ABGEWIESENE Fall ist billig. Gemessen auf diesem Baum
vor dem Fix: ``renewal_ats_chain`` = 10.000 (die Pruefung ist ``value <= limit``, der groesste
ZUGELASSENE Wert ist also 10.000, nicht 9.999) kostete am Limit **59,5 s Rechenzeit** aus 1,26 MB
Eingabe, waehrend 10.001 Eintraege in **0,002 s** abgewiesen wurden. Die Schranke feuerte korrekt und
begrenzte nichts.

DIE ZUSICHERUNG, und sie gilt fuer JEDE Dimension, nicht fuer die eine, an der es auffiel:

1. Der groesste ZUGELASSENE Wert kostet weniger als die erklaerte Obergrenze (``GRENZE_S``).
2. Die drei Punkte um das Limit — L-1, L, L+1 — verhalten sich wie angekuendigt: L-1 und L
   zugelassen, L+1 abgewiesen. Genau dort sass der Sprung von 0,002 s auf 59,5 s.
3. Die Kostenkurve ueber die Verdopplungsreihe L/8, L/4, L/2, L ist nicht ueberlinear
   (Exponent <= ``EXPONENT_MAX``).
4. Auch KOMBINIERTE Achsen, jede an ihrem Limit, bleiben unter der Summe ihrer Obergrenzen.

WARUM RECHENZEIT UND NICHT UHRZEIT. ``resource.getrusage`` misst die Rechenzeit DIESES Prozesses.
Die Uhrzeit misst mit, was 23 andere Kerne gerade tun; auf einer Maschine unter Last waeren die
Zahlen unbrauchbar, und eine unbrauchbare Zahl in einer Zusicherung ist schlimmer als keine.

WARUM ZUSAETZLICH EINE ARBEITSZAEHLUNG. Auch Rechenzeit haengt an der Maschine. Wo der Durchlauf in
Python liegt, wird deshalb zusaetzlich die Zahl der Python-Aufrufe gezaehlt (``sys.setprofile``,
GC aus): eine deterministische, maschinenunabhaengige Groesse. Sie ist nicht ueberall aussagekraeftig
— wo die Arbeit in C liegt (JSON-Parser, Hash-Kern), bleibt sie flach. Genau das wird GEPRUEFT statt
angenommen: waechst die Zaehlung ueber die Reihe nicht mindestens um das Doppelte, gilt sie fuer diese
Dimension als UNEMPFINDLICH und wird nicht als Beleg benutzt. Der dritte Zustand wird berichtet, nicht
verschwiegen.

WARUM EINE RESERVE. Unter ``RESERVE_S`` liegt die Messung im Rauschen (Cache, Zuteilung, Last), und
ein Exponent aus Rauschen ist eine Fehlmeldung. Unterhalb der Reserve wird der Exponent deshalb
BERICHTET, aber er entscheidet nicht — die Obergrenze entscheidet immer. Beispiel aus der eigenen
Messung: ``int_bits`` hat eine quadratische Kurve (der Schiebe-Loop in ``root_from_inclusion``), kostet
am groessten zugelassenen Wert aber 0,0045 s. Bei rund 1/200 der Obergrenze kann die Form der Kurve
keine Ueberlastung mehr erzeugen; sie als Fund zu melden waere ein Fehlbefund.

WARUM DIE GRENZE 1,2 UND NICHT 1,05 IST — GEMESSEN, NICHT GESCHAETZT. Am 2026-09-05 wurde auf dieser
Maschine (Lastmittel 27 bei 24 Kernen, also unter voller Konkurrenz) der Zeit-Exponent der beiden
teuersten LINEAREN Dimensionen je 9 mal erhoben: ``renewal_ats_chain`` 0,960 bis 1,132,
``json_nodes`` 0,975 bis 1,097. Der schlechteste von 18 Werten war 1,132. 1,2 laesst diesem Rauschen
Platz und trennt trotzdem sauber von der gemessenen Kurve VOR dem Fix (1,99). Damit der Abstand
nicht von der Tagesform abhaengt, ist jeder Punkt zusaetzlich das MINIMUM aus mehreren Laeufen
(siehe ``_zeit_min``) — Rauschen addiert nur, also ist das Minimum der beste Schaetzer der wahren
Kosten.

EHRLICHE GRENZE, ZWEI STUECK. (a) Gemessen wird EINE Maschine (Farmer, 24 Kerne, Python 3.10). Die
Zahlen sind Obergrenzen mit Reserve, kein Benchmark. Eine schnellere Maschine macht jede Zusicherung
hier nur sicherer; eine langsamere verschiebt alle Werte gleichmaessig, und die Obergrenze hat
ueberall mindestens Faktor 10 Luft — ausser im teuersten kombinierten Fall, der eigens benannt ist.
(b) Die Zusicherung ist EINDIMENSIONAL und kann es nicht anders sein: sie spricht ueber den groessten
ZUGELASSENEN Wert, und den gibt es nur, wo ein Limit steht. Eine Achse OHNE Limit faellt durch — und
genau so eine multipliziert hier eine begrenzte: ``verify_sequence``s ``data_digests`` hat keine
Dimension, und 10.000 ATS (am Limit) mal 50.000 Datendigests kosten gemessen 15,9 s. Das ist als
eigener Befund festgehalten (RENEWAL-DATA-DIGESTS-OHNE-DIMENSION-MULTIPLIZIERT-DIE-ATS-SCHRANKE-01)
und wird von dieser Datei ausdruecklich NICHT gedeckt. Wer das hier fuer eine Gesamtaussage haelt,
liest mehr, als gemessen wurde.
"""
from __future__ import annotations

import base64
import dataclasses
import gc
import json
import math
import resource
import sys

import pytest

import proofbundle as pb
from proofbundle import dsse, merkle, sdjwt
from proofbundle._strict_json import loads_strict
from proofbundle.budget import DEFAULT_BUDGET as B
from proofbundle.budget import VerificationBudget
from proofbundle.emit import generate_signer
from proofbundle.errors import ProofBundleError
from proofbundle.renewal import ArchiveTimeStamp
from proofbundle.trust_pack import validate_trust_pack_predicate

# Die erklaerte Obergrenze: eine Sekunde Rechenzeit am groessten zugelassenen Wert EINER Dimension.
GRENZE_S = 1.0
# Der hoechste Exponent, den eine Kostenkurve haben darf. 1,0 ist linear; 1,2 laesst Messrauschen und
# einen log-Faktor zu. Vor dem Fix mass renewal_ats_chain 1,99.
EXPONENT_MAX = 1.2
# Unterhalb dieser Kosten entscheidet der Exponent nicht mehr (siehe Kopf). 1/50 der Obergrenze.
RESERVE_S = GRENZE_S / 50.0
# So viel muss die Arbeitszaehlung ueber die 8-fache Eingabe wachsen, um als empfindlich zu gelten.
ARBEIT_EMPFINDLICH = 2.0

HEX32 = "aa" * 32
# So oft wird ein billiger Punkt wiederholt; genommen wird das MINIMUM. Ein teurer Punkt braucht das
# nicht — bei 60 s Messwert aendert ein Cache-Miss nichts, und die Wiederholung kostete dort Minuten.
WIEDERHOLUNGEN = 3
WIEDERHOLEN_UNTER_S = 0.2


def _cpu() -> float:
    r = resource.getrusage(resource.RUSAGE_SELF)
    return r.ru_utime + r.ru_stime


def _zeit(ruf):
    """(Rechenzeit, Ergebnis-oder-Ausnahme). Eine Ausnahme ist hier ein ERGEBNIS: die Schranke, die
    ueber dem Limit zuschlaegt, meldet sich bei den Parser-Flaechen genau so."""
    t = _cpu()
    try:
        r = ruf()
    except ProofBundleError as exc:
        return _cpu() - t, exc
    return _cpu() - t, r


def _zeit_min(ruf):
    """Der beste Schaetzer der wahren Kosten: das MINIMUM mehrerer Laeufe.

    Messrauschen (Cache, Zuteilung, fremde Last auf den anderen Kernen) kann Rechenzeit nur
    HINZUFUEGEN, nie abziehen. Ein Mittelwert traegt das Rauschen mit, das Minimum nicht. Wiederholt
    wird nur unterhalb von ``WIEDERHOLEN_UNTER_S``: wo die Messung gross ist, ist das Rauschen relativ
    klein, und die Wiederholung kostete dort Minuten statt Millisekunden.
    """
    dauer, erg = _zeit(ruf)
    if dauer >= WIEDERHOLEN_UNTER_S:
        return dauer, erg
    for _ in range(WIEDERHOLUNGEN - 1):
        d2, erg = _zeit(ruf)
        dauer = min(dauer, d2)
    return dauer, erg


def _arbeit(ruf) -> int:
    """Deterministische Arbeitszaehlung: Python-Aufrufe. Haengt nicht an der Maschine."""
    n = 0

    def zaehle(*_):
        nonlocal n
        n += 1

    war_an = gc.isenabled()
    gc.disable()
    sys.setprofile(zaehle)
    try:
        ruf()
    except ProofBundleError:
        pass
    finally:
        sys.setprofile(None)
        if war_an:
            gc.enable()
    return n


def _exponent(punkte) -> float:
    """Exponent aus einer Verdopplungsreihe: Median der einzelnen log-Steigungen.

    Der Median statt einer Ausgleichsgeraden, weil ein einzelner verrauschter Punkt (eine
    Zuteilung, ein Cache-Miss) die Gerade kippt, den Median aber nicht.
    """
    steigungen = []
    for (n0, k0), (n1, k1) in zip(punkte, punkte[1:]):
        if k0 <= 0 or k1 <= 0 or n1 <= n0:
            continue
        steigungen.append(math.log(k1 / k0) / math.log(n1 / n0))
    if not steigungen:
        return float("nan")
    steigungen.sort()
    return steigungen[len(steigungen) // 2]


# --------------------------------------------------------------------------- die Lasten
def _json_mit_genau(n: int) -> str:
    """Ein JSON-Dokument von EXAKT n Bytes, auf jeder anderen Achse zulaessig.

    Exakt, weil die Punkte L-1, L, L+1 sonst keine Punkte an der Grenze waeren, sondern in ihrer
    Naehe — und die Grenze ist genau das, was hier gemessen wird.
    """
    k = max(1, -(-n // 900_000))                      # Aufrunden: jede Zeichenkette bleibt < string_len
    summe = n - 3 * k - 1                             # ["a...","a..."] = sum(len) + 3k + 1
    assert summe >= k, f"n={n} ist zu klein fuer {k} Stuecke"
    q, rest = divmod(summe, k)
    laengen = [q + (1 if i < rest else 0) for i in range(k)]
    txt = "[" + ",".join('"' + "a" * m + '"' for m in laengen) + "]"
    assert len(txt) == n, (len(txt), n)
    return txt


def _last_input_bytes(n):
    txt = _json_mit_genau(n)
    return (lambda: loads_strict(txt)), len(txt)


def _last_json_nodes(n):
    txt = "[" + ",".join("1" for _ in range(n)) + "]"
    return (lambda: loads_strict(txt)), n


def _last_json_depth(n):
    txt = "[" * n + "]" * n
    return (lambda: loads_strict(txt)), n


def _last_string_len(n):
    txt = '["' + "a" * n + '"]'
    return (lambda: loads_strict(txt)), n


_SK = generate_signer()
_PUB = _SK.public_key().public_bytes_raw()


def _last_signatures(n):
    echt = dsse.sign_envelope(b'{"x":1}', _SK, payload_type="application/x.pb-kostenkurve")
    env = dict(echt)
    # die echte Signatur ans ENDE: sonst bricht die Schleife beim ersten Eintrag ab und misst nichts
    env["signatures"] = [{"sig": "AA=="} for _ in range(n - 1)] + list(echt["signatures"])
    return (lambda: dsse.verify_envelope(env, _PUB)), len(env["signatures"])


def _last_merkle_path(n):
    beweis = [bytes([i % 251]) * 32 for i in range(n)]
    wurzel = merkle.root_from_inclusion(0, 2 ** n, merkle.leaf_hash(b"x"), beweis)
    return (lambda: pb.verify_inclusion(b"x", 0, 2 ** n, beweis, wurzel)), len(beweis)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _last_disclosures(n):
    disc = [_b64u(json.dumps([f"salt{i}", f"feld{i}", i], separators=(",", ":")).encode())
            for i in range(n)]
    nutz = {"_sd": [sdjwt._digest(d, "sha-256") for d in disc], "_sd_alg": "sha-256"}
    kopf = _b64u(json.dumps({"alg": "EdDSA", "typ": "example+sd-jwt"}).encode())
    kompakt = "~".join([f"{kopf}.{_b64u(json.dumps(nutz).encode())}.{_b64u(b'x' * 64)}"] + disc) + "~"
    return (lambda: sdjwt.verify_sd_jwt(kompakt)), n


def _last_renewal_ats_chain(n):
    seq = [[ArchiveTimeStamp("sha256", HEX32, i + 1)] for i in range(n)]
    return (lambda: pb.verify_sequence(seq, [HEX32], allow_unauthenticated_anchor=True)), n


def _last_witnesses(n):
    keys = {f"k-{i}": {"publicKey": base64.b64encode(
        generate_signer().public_key().public_bytes_raw()).decode()} for i in range(n)}
    pred = {"schemaVersion": "0.1.0", "trustPackId": "t", "version": 1,
            "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
            "roles": {"root": {"keyIds": [f"k-{i}" for i in range(2)], "threshold": 1}},
            "keys": keys, "nonClaims": ["x"]}
    return (lambda: validate_trust_pack_predicate(pred)), n


def _last_int_bits(n):
    """Der groesste zugelassene Betrag ist eine Zahl MIT n Bits, also 2**(n-1) — nicht 2**n."""
    idx = 2 ** (n - 1)
    groesse = idx + 1
    beweis = [b"\x11" * 32]
    wurzel = merkle.root_from_inclusion(idx, groesse, merkle.leaf_hash(b"x"), beweis)
    return (lambda: pb.verify_inclusion(b"x", idx, groesse, beweis, wurzel)), idx.bit_length()


def _kein_fehler(r):
    return not isinstance(r, BaseException)


@dataclasses.dataclass(frozen=True)
class Dimension:
    name: str
    was: str
    baue: object
    zugelassen: object


DIMENSIONEN = [
    Dimension("input_bytes", "_strict_json.loads_strict", _last_input_bytes, _kein_fehler),
    Dimension("json_nodes", "_strict_json.loads_strict", _last_json_nodes, _kein_fehler),
    Dimension("json_depth", "_strict_json.loads_strict", _last_json_depth, _kein_fehler),
    Dimension("string_len", "_strict_json.loads_strict", _last_string_len, _kein_fehler),
    Dimension("signatures", "dsse.verify_envelope", _last_signatures, lambda r: r is True),
    Dimension("merkle_path", "merkle.verify_inclusion", _last_merkle_path, lambda r: r is True),
    Dimension("disclosures", "sdjwt.verify_sd_jwt", _last_disclosures,
              lambda r: isinstance(r, dict) and "too many disclosures" not in r["detail"]),
    Dimension("renewal_ats_chain", "renewal.verify_sequence", _last_renewal_ats_chain,
              lambda r: not any(c.name == "renewal:budget" for c in r.checks)),
    Dimension("witnesses", "trust_pack.validate_trust_pack_predicate", _last_witnesses,
              lambda r: not any("budget.witnesses" in e for e in r)),
    Dimension("int_bits", "merkle.verify_inclusion", _last_int_bits, lambda r: r is True),
]

_MESSUNGEN: dict = {}


def _messung(dim: Dimension) -> dict:
    """Einmal messen, mehrfach zusichern — sonst kostet jede Zusicherung die Reihe erneut."""
    if dim.name in _MESSUNGEN:
        return _MESSUNGEN[dim.name]
    limit = getattr(B, dim.name)
    reihe, arbeit = [], []
    for n in (limit // 8, limit // 4, limit // 2, limit):
        ruf, ist = dim.baue(n)
        dauer, erg = _zeit_min(ruf)
        reihe.append((ist, dauer, erg))
        arbeit.append((ist, _arbeit(ruf)))
    rand = {}
    for n in (limit - 1, limit, limit + 1):
        ruf, ist = dim.baue(n)
        dauer, erg = _zeit_min(ruf)
        rand[n] = (ist, dauer, dim.zugelassen(erg))
    m = {
        "limit": limit,
        "reihe": reihe,
        "arbeit": arbeit,
        "rand": rand,
        "kosten_am_limit": reihe[-1][1],
        "exponent_zeit": _exponent([(n, k) for n, k, _ in reihe]),
        "exponent_arbeit": _exponent(arbeit),
        "arbeit_empfindlich": (arbeit[-1][1] >= ARBEIT_EMPFINDLICH * max(arbeit[0][1], 1)),
    }
    _MESSUNGEN[dim.name] = m
    return m


IDS = [d.name for d in DIMENSIONEN]


class TestJedeDimensionIstAbgedeckt:
    def test_keine_dimension_ohne_last(self):
        """ABGELEITET, nicht aufgezaehlt: die Menge kommt aus ``VerificationBudget`` selbst. Eine
        neue Dimension ohne Last faellt hier auf, statt still ungemessen zu bleiben."""
        felder = {f.name for f in dataclasses.fields(VerificationBudget)}
        gemessen = {d.name for d in DIMENSIONEN}
        assert felder == gemessen, (
            f"ohne Kostenkurve: {sorted(felder - gemessen)} | "
            f"gemessen, aber keine Budget-Dimension: {sorted(gemessen - felder)}")


class TestObergrenzeAmGroesstenZugelassenenWert:
    @pytest.mark.parametrize("dim", DIMENSIONEN, ids=IDS)
    def test_die_last_erreicht_das_limit_wirklich(self, dim):
        """Eine Last, die das Limit gar nicht erreicht, bestuende jede Obergrenze und pruefte nichts."""
        m = _messung(dim)
        ist = m["reihe"][-1][0]
        assert ist >= 0.95 * m["limit"], (
            f"{dim.name}: die Last erreicht nur {ist} von {m['limit']} — sie misst nicht den "
            "teuersten zugelassenen Fall")

    @pytest.mark.parametrize("dim", DIMENSIONEN, ids=IDS)
    def test_l_minus_eins_l_und_l_plus_eins(self, dim):
        """Die drei Punkte um das Limit. Dort sass der Sprung von 0,002 s auf 59,5 s."""
        m = _messung(dim)
        limit = m["limit"]
        assert m["rand"][limit - 1][2], f"{dim.name}: L-1 wird abgewiesen"
        assert m["rand"][limit][2], (
            f"{dim.name}: L selbst wird abgewiesen — dann ist L-1 der groesste zugelassene Wert und "
            "die Schranke ist anders dokumentiert als sie wirkt")
        assert not m["rand"][limit + 1][2], f"{dim.name}: L+1 wird NICHT abgewiesen"

    @pytest.mark.parametrize("dim", DIMENSIONEN, ids=IDS)
    def test_kosten_am_limit_unter_der_obergrenze(self, dim):
        m = _messung(dim)
        limit = m["limit"]
        k = m["rand"][limit][1]
        drei = " | ".join(f"n={n}: {m['rand'][n][1]:.4f} s "
                          f"({'zugelassen' if m['rand'][n][2] else 'abgewiesen'})"
                          for n in (limit - 1, limit, limit + 1))
        assert k <= GRENZE_S, (
            f"{dim.name}: {k:.3f} s Rechenzeit am groessten zugelassenen Wert ({limit}), "
            f"Obergrenze {GRENZE_S:.1f} s. Die Schranke laesst mehr zu, als sie zu begrenzen "
            f"behauptet — genau der Fund L2-600-01.\n  die drei Punkte um das Limit: {drei}")


class TestKostenkurve:
    @pytest.mark.parametrize("dim", DIMENSIONEN, ids=IDS)
    def test_die_kurve_ist_nicht_ueberlinear(self, dim):
        m = _messung(dim)
        if m["arbeit_empfindlich"]:
            # maschinenunabhaengiger Beleg: die Arbeitszaehlung waechst mit der Eingabe, also ist ihr
            # Exponent aussagekraeftig und haengt nicht an Takt oder Last
            assert m["exponent_arbeit"] <= EXPONENT_MAX, (
                f"{dim.name}: Arbeits-Exponent {m['exponent_arbeit']:.2f} > {EXPONENT_MAX} "
                f"(Zaehlung {[a for _, a in m['arbeit']]})")
        if m["kosten_am_limit"] > RESERVE_S:
            assert m["exponent_zeit"] <= EXPONENT_MAX, (
                f"{dim.name}: Zeit-Exponent {m['exponent_zeit']:.2f} > {EXPONENT_MAX} bei "
                f"{m['kosten_am_limit']:.3f} s am Limit — ueberlinear INNERHALB der eigenen Schranke")

    def test_der_schaetzer_erkennt_eine_gepflanzte_quadratische_kurve(self):
        """GATE-META-TEST. Ein Schaetzer, der nie ausschlaegt, ist von einem funktionierenden nicht
        zu unterscheiden. Also wird ihm eine Kurve bekannter Form vorgelegt."""
        linear = [(n, 0.001 * n) for n in (1000, 2000, 4000, 8000)]
        quadratisch = [(n, 1e-8 * n * n) for n in (1000, 2000, 4000, 8000)]
        vor_dem_fix = [(1000, 0.691), (2000, 2.745), (4000, 9.344), (8000, 43.240)]
        assert abs(_exponent(linear) - 1.0) < 0.01
        assert abs(_exponent(quadratisch) - 2.0) < 0.01
        assert _exponent(quadratisch) > EXPONENT_MAX
        # die echte Messung von renewal_ats_chain VOR dem Fix, auf diesem Baum am 2026-09-05
        assert _exponent(vor_dem_fix) > EXPONENT_MAX, (
            "die gemessene Kurve vor dem Fix muesste dieser Schaetzer als Fund melden")

    def test_die_arbeitszaehlung_ist_mindestens_einmal_empfindlich(self):
        """Sonst waere der maschinenunabhaengige Teil dieser Datei ueberall unentschieden — und ein
        Beleg, der nie greift, ist kein Beleg."""
        empfindlich = [d.name for d in DIMENSIONEN if _messung(d)["arbeit_empfindlich"]]
        assert empfindlich, "keine einzige Dimension hat eine empfindliche Arbeitszaehlung"


# --------------------------------------------------------------------------- kombinierte Achsen
def _kombi_renewal_x_int_bits():
    gross = 2 ** (B.int_bits - 1)
    seq = [[ArchiveTimeStamp("sha256", HEX32, gross + i)] for i in range(B.renewal_ats_chain)]
    return lambda: pb.verify_sequence(seq, [HEX32], allow_unauthenticated_anchor=True)


def _kombi_renewal_x_algorithmen():
    algs = ["sha256", "sha512", "sha3-256", "sha3-512", "sha384"]
    seq = [[ArchiveTimeStamp(algs[i % len(algs)], HEX32, i + 1)]
           for i in range(B.renewal_ats_chain)]
    return lambda: pb.verify_sequence(seq, [HEX32], allow_unauthenticated_anchor=True)


def _kombi_merkle_x_int_bits():
    n = B.merkle_path
    idx = 2 ** (B.int_bits - 1)
    beweis = [bytes([i % 251]) * 32 for i in range(n)]
    groesse = idx + 1
    wurzel = merkle.root_from_inclusion(idx, groesse, merkle.leaf_hash(b"x"), beweis[:1])
    return lambda: pb.verify_inclusion(b"x", idx, groesse, beweis[:1], wurzel)


def _kombi_signatures_x_input_bytes():
    nutz = json.dumps({"x": "a" * 900_000}).encode()
    echt = dsse.sign_envelope(nutz, _SK, payload_type="application/x.pb-kostenkurve")
    env = dict(echt)
    env["signatures"] = [{"sig": "AA=="} for _ in range(B.signatures - 1)] + list(echt["signatures"])
    return lambda: dsse.verify_envelope(env, _PUB)


def _kombi_parser_alle_achsen():
    tief = B.json_depth
    kern = json.dumps(["a" * 500_000] * 15)
    txt = "[" * (tief - 1) + kern + "]" * (tief - 1)
    return lambda: loads_strict(txt)


KOMBIS = [
    ("renewal_ats_chain x int_bits", 2, _kombi_renewal_x_int_bits),
    ("renewal_ats_chain x 5 hash-algorithmen", 2, _kombi_renewal_x_algorithmen),
    ("merkle_path x int_bits", 2, _kombi_merkle_x_int_bits),
    ("signatures x input_bytes", 2, _kombi_signatures_x_input_bytes),
    ("input_bytes x json_depth x string_len", 3, _kombi_parser_alle_achsen),
]


class TestKombinierteAchsen:
    """Eine Dimension allein ist nicht der teuerste zugelassene Fall. Zwei Achsen, jede an ihrem
    Limit, sind zwei Budgets — die Obergrenze ist deshalb ihre SUMME, nicht ihr Maximum. Das ist eine
    Regel, keine an das Ergebnis angepasste Zahl.

    Der teuerste hier gemessene Fall ist ``renewal_ats_chain x int_bits``: 10.000 ATS mit einer
    8192-Bit-``time``. Sein Anteil ist zu ~0,61 s das einmalige Rendern dieser Zahlen nach dezimal
    (CPython ist dort ueberlinear), und das ist nicht wegzuoptimieren: die dezimale Form IST das
    gedeckte Material. Vor dem Fix wurde sie n mal je ATS gerendert statt einmal.
    """

    @pytest.mark.parametrize("name,achsen,bau", KOMBIS, ids=[k[0] for k in KOMBIS])
    def test_kombi_bleibt_unter_der_summe_der_obergrenzen(self, name, achsen, bau):
        dauer, _ = _zeit_min(bau())
        assert dauer <= achsen * GRENZE_S, (
            f"{name}: {dauer:.3f} s Rechenzeit, Obergrenze {achsen * GRENZE_S:.1f} s "
            f"({achsen} Achsen an ihrem Limit)")


class TestBericht:
    def test_zahlen_ausgeben(self, capsys):
        """Kein Urteil, nur die Zahlen — sichtbar mit ``pytest -s``. Ein Riegel, dessen Messwerte
        niemand sehen kann, wird beim naechsten Zweifel neu erfunden statt nachgelesen."""
        zeilen = ["", f"{'Dimension':<20}{'Limit':>10}{'CPU@L':>9}{'Exp(Zeit)':>11}"
                      f"{'Exp(Arbeit)':>13}{'Arbeit empf.':>14}  Flaeche"]
        for d in DIMENSIONEN:
            m = _messung(d)
            zeilen.append(
                f"{d.name:<20}{m['limit']:>10}{m['rand'][m['limit']][1]:>9.4f}"
                f"{m['exponent_zeit']:>11.2f}{m['exponent_arbeit']:>13.2f}"
                f"{str(m['arbeit_empfindlich']):>14}  {d.was}")
        with capsys.disabled():
            print("\n".join(zeilen))
        assert len(zeilen) == len(DIMENSIONEN) + 2
