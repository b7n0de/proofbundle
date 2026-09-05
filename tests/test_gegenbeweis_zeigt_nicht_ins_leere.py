"""Ein Gegenbeweis muss aus SEINEM erklaerten Grund fallen, nicht nebenbei.

DIE KLASSE, und ich bin ihr am 01.09.2026 zweimal an einem Vormittag selbst aufgesessen:

  1. Ein v0.2-Test schickte ein v0.1-Envelope in `verify_agent_review_v02`. Dort ist
     `predicate_type_ok` dann `False`, der gepruefte Block wird NIE BETRETEN, und die Zusicherungen
     hielten gegen die Vorbelegung aus `_empty_result` statt gegen eine Messung. Der eingepflanzte
     Defekt liess den Test gruen.
  2. Eine Gate-Meta-Mutation setzte einen Kommentar in ein mehrzeiliges Dict-Literal und erzeugte
     einen `SyntaxError`. Der Lauf war rot — aber aus dem falschen Grund, und ein roter Lauf aus
     dem falschen Grund belegt ueber die Tests genau nichts.

Beides ist dieselbe Klasse: die Pruefung zeigt ins Leere und sieht trotzdem aus wie eine Pruefung.
Auf Korpus-Ebene hat sie eine praezise Form. Ein `counter_proof`, der `classification: invalid`
erwartet, behauptet: „dieses Receipt ist kryptografisch einwandfrei und faellt trotzdem, weil die
benannte Regel greift." Traegt sein Umschlag eine kaputte Signatur oder unparsbare Bytes, faellt er
schon vorher — die benannte Regel wird nie erreicht, und der Fall belegt sie nicht.

GEMESSEN am 01.09.2026 gegen den lebenden Korpus: beide `invalid`-Faelle erfuellen die Eigenschaft
bereits. Dieser Test aendert also heute nichts am Ergebnis — er haelt fest, dass es so bleibt.
Genau das ist der Punkt: eine Eigenschaft, die nur zufaellig gilt, ist keine Eigenschaft.

ABGRENZUNG, damit der Test nicht mehr behauptet als er misst: `refused`-Faelle tragen bewusst KEIN
Envelope (sie werden vom Validator vor jeder Signaturfrage abgewiesen), und `bodyCoreStable`-Faelle
pruefen eine Digest-Eigenschaft ohne Envelope. Beide sind hier ausdruecklich nicht betroffen.
"""
from __future__ import annotations

import base64
import json
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from proofbundle import dsse  # noqa: E402

KORPUS = REPO / "conformance" / "agent_review"


def _faelle():
    if not KORPUS.is_dir():
        return []
    aus = []
    for d in sorted(KORPUS.iterdir()):
        cj = d / "case.json"
        if cj.is_file():
            aus.append((d, json.loads(cj.read_text(encoding="utf-8"))))
    return aus


def test_der_korpus_wird_ueberhaupt_gefunden():
    """OHNE DIESE ZUSICHERUNG WAERE ALLES DARUNTER WERTLOS. Ein leerer Korpus laesst jede
    Schleife darunter still durchlaufen — und ein Test, der ueber nichts iteriert, ist gruen."""
    faelle = _faelle()
    assert len(faelle) >= 10, f"nur {len(faelle)} Faelle gefunden — der Test misst fast nichts"
    rollen = {c.get("role") for _, c in faelle}
    assert "counter_proof" in rollen and "positive_control" in rollen, rollen


def test_ein_invalid_gegenbeweis_traegt_einen_gueltigen_umschlag():
    """DIE EIGENSCHAFT. `invalid` heisst: die Signatur traegt, die REGEL faellt."""
    pk_datei = KORPUS / "publickey.hex"
    if not pk_datei.is_file():
        pytest.skip("kein publickey.hex im Korpus — nicht messbar, ausdruecklich keine Freigabe")
    pk = bytes.fromhex(pk_datei.read_text(encoding="utf-8").strip())

    geprueft = 0
    for d, c in _faelle():
        if c.get("role") != "counter_proof":
            continue
        if (c.get("expected") or {}).get("classification") != "invalid":
            continue
        env_p = d / c.get("input", "envelope.json")
        assert env_p.is_file(), f"{d.name}: nennt {env_p.name}, die Datei fehlt"
        env = json.loads(env_p.read_text(encoding="utf-8"))
        assert "payload" in env, f"{d.name}: erwartet invalid, traegt aber gar kein DSSE-Envelope"

        # 1. Die Signatur MUSS tragen — sonst faellt der Fall vor der benannten Regel.
        dsse.verify_envelope(env, pk)
        # 2. Die Nutzlast MUSS parsen — sonst erreicht die Regel die Daten nie.
        json.loads(base64.b64decode(env["payload"]))
        # 3. Der Fall MUSS die Regel benennen, gegen die er zeigt.
        assert str(c.get("rule") or "").strip(), f"{d.name}: kein `rule` — der Fall zeigt auf nichts"
        assert len(str(c.get("rationale") or "")) > 40, (
            f"{d.name}: `rationale` zu duenn, um den erklaerten Grund zu pruefen")
        geprueft += 1

    assert geprueft >= 2, (
        f"nur {geprueft} invalid-Gegenbeweise geprueft — bei weniger als zwei misst dieser Test "
        "eine Einzelfall-Eigenschaft und keine Korpus-Eigenschaft")


# DIE EINE Quelle der Standard-Policy ist das Paket (siehe standard_policy_path); die Kopie im
# Korpus ist byte-gleich und wird von tests/test_standard_policy_liegt_im_paket.py gehalten.
_STANDARD_POLICY = Path(str(__import__("proofbundle.agent_review", fromlist=["x"]).standard_policy_path()))


_PARAM_ZUGRIFF = re.compile(r"""params(?:\.get\(|\[)\s*["']([A-Za-z_][A-Za-z0-9_]*)["']""")


def _gelesene_params() -> frozenset[str]:
    """Welche `params.<name>` der Konformitaetslaeufer wirklich liest — aus seinem Quelltext."""
    quelle = (Path(__file__).resolve().parents[1] / "conformance" / "run_conformance.py").read_text(
        encoding="utf-8")
    return frozenset(_PARAM_ZUGRIFF.findall(quelle))


def _eingabe_schluessel(d: Path, c: dict) -> str | None:
    """ALLES, was der Fall dem Pruefer gibt — nicht nur die Receipt-Datei.

    GEMESSEN am 04.09.2026 (Teil A5, Policy-Achse): drei Faelle teilen dasselbe `predicate.json`
    und unterscheiden sich NUR in der Policy — Standard-Policy, keine Policy, sperrende Policy im
    Fallordner. Eine Policy ist Eingabe des Verifizierers, kein Zufall: dasselbe Receipt faellt
    unter der einen und steht unter der anderen, deterministisch und aus genau dem erklaerten
    Grund. Der Schluessel ist deshalb das Tupel (Eingabedatei, Parameter), und eine Policy, die
    eine Datei nennt, geht mit ihren BYTES ein — zwei Faelle mit verschiedenen Dateinamen und
    gleichem Inhalt sind dieselbe Eingabe.

    Was der Schluessel NICHT aufweicht: zwei Faelle, die dem Pruefer in NICHTS verschieden
    gegenuebertreten, bleiben dieselbe Eingabe (siehe den Meta-Test darunter).
    """
    env_p = d / c.get("input", "envelope.json")
    if not env_p.is_file():
        return None
    # NUR DIE PARAMETER, DIE DER LAEUFER LIEST (Linse 2 auf PR 185, FUND-2): das ganze
    # params-Dict roh zu serialisieren macht zwei fuer den Verifizierer identische Faelle zu
    # "verschiedenen" Schluesseln, sobald einer einen nie gelesenen Zusatzschluessel traegt —
    # und entzieht das Paar dem Duplikat-Fang. Die Menge kommt aus dem Laeufer-Quelltext, nicht
    # aus einer zweiten Liste; der Meta-Test darunter haelt beide Richtungen zusammen.
    params = {k: v for k, v in (c.get("params") or {}).items() if k in _gelesene_params()}
    pol = params.get("policy")
    if isinstance(pol, str) and pol not in ("none", "default"):
        pf = d / pol
        params["policy"] = "bytes:" + (pf.read_text(encoding="utf-8") if pf.is_file() else "<fehlt>")
    elif pol == "default" and _STANDARD_POLICY.is_file():
        params["policy"] = "bytes:" + _STANDARD_POLICY.read_text(encoding="utf-8")
    return env_p.read_text(encoding="utf-8") + "\n\x00params=" + json.dumps(params, sort_keys=True)


def _gleiche_eingabe_in_beiden_rollen(faelle) -> list[list[str]]:
    inhalte: dict[str, list[str]] = {}
    for d, c in faelle:
        key = _eingabe_schluessel(d, c)
        if key is None:
            continue
        inhalte.setdefault(key, []).append(f"{c.get('role')}:{d.name}")
    return [namen for namen in inhalte.values()
            if {"counter_proof", "positive_control"} <= {n.split(":", 1)[0] for n in namen}]


def test_jeder_gegenbeweis_unterscheidet_sich_von_der_positiven_kontrolle():
    """Ein Gegenbeweis, dessen Eingabe mit einer positiven Kontrolle IDENTISCH ist, kann nicht aus
    einem anderen Grund fallen als sie — er misst dann die Regel nicht, sondern den Zufall.
    Eingabe heisst: alles, was der Pruefer sieht (`_eingabe_schluessel`)."""
    doppelt = _gleiche_eingabe_in_beiden_rollen(_faelle())
    assert not doppelt, (
        f"dieselbe Eingabe wird als Gegenbeweis UND als positive Kontrolle gefuehrt: {doppelt}")


def _fall_anlegen(wurzel: Path, name: str, role: str, inhalt: str, params: dict | None = None,
                  extra: dict | None = None) -> tuple[Path, dict]:
    d = wurzel / name
    d.mkdir()
    (d / "predicate.json").write_text(inhalt, encoding="utf-8")
    for fn, txt in (extra or {}).items():
        (d / fn).write_text(txt, encoding="utf-8")
    c = {"caseId": name, "role": role, "input": "predicate.json",
         **({"params": params} if params is not None else {})}
    return d, c


def test_meta_gleiche_datei_und_gleiche_parameter_werden_weiter_gefangen(tmp_path):
    """Der Schluessel darf die Regel nicht aufweichen: nichts verschieden -> dieselbe Eingabe."""
    faelle = [_fall_anlegen(tmp_path, "a-positive", "positive_control", "{}", {"policy": "default"}),
              _fall_anlegen(tmp_path, "b-counter", "counter_proof", "{}", {"policy": "default"})]
    assert _gleiche_eingabe_in_beiden_rollen(faelle), "identische Eingabe wurde nicht gefangen"


def test_meta_nur_die_policy_verschieden_ist_eine_andere_eingabe(tmp_path):
    """Dieselbe Datei, andere Policy: das ist die Policy-Achse, kein Zufall — kein Fang. Und eine
    Datei-Policy zaehlt nach Bytes: gleicher Inhalt unter anderem Namen bleibt dieselbe Eingabe."""
    faelle = [_fall_anlegen(tmp_path, "a-positive", "positive_control", "{}", {"policy": "default"}),
              _fall_anlegen(tmp_path, "b-counter", "counter_proof", "{}", {"policy": "none"}),
              _fall_anlegen(tmp_path, "c-counter", "counter_proof", "{}", {"policy": "p.json"},
                            {"p.json": '{"blocking": ["IDENTITY_UNBOUND"]}'})]
    assert not _gleiche_eingabe_in_beiden_rollen(faelle)
    gleich = [_fall_anlegen(tmp_path, "d-positive", "positive_control", "{}", {"policy": "x.json"},
                            {"x.json": "{}"}),
              _fall_anlegen(tmp_path, "e-counter", "counter_proof", "{}", {"policy": "y.json"},
                            {"y.json": "{}"})]
    assert _gleiche_eingabe_in_beiden_rollen(gleich), "gleiche Policy-Bytes unter anderem Namen"


def test_jeder_param_schluessel_des_korpus_wird_vom_laeufer_gelesen():
    """DIE GEGENRICHTUNG des Eingabeschluessels: ein Parameter, den ein Fall traegt und der
    Laeufer nie liest, ist ein Autorenfehler des Falls — er sieht aus wie eine Eingabe und
    aendert nichts. Ohne diesen Test koennte ein solcher Schluessel still hinzukommen und den
    Duplikat-Fang genau so aushebeln, wie es Linse 2 gemessen hat."""
    gelesen = _gelesene_params()
    assert {"expectedSubjectDigest", "policy"} <= gelesen, gelesen
    fremd = {}
    for d in sorted(x for x in KORPUS.iterdir() if x.is_dir()):
        cj = d / "case.json"
        if not cj.is_file():
            continue
        c = json.loads(cj.read_text(encoding="utf-8"))
        for k in (c.get("params") or {}):
            if k not in gelesen:
                fremd.setdefault(k, []).append(d.name)
    assert not fremd, f"params-Schluessel, die der Laeufer nie liest: {fremd}"
