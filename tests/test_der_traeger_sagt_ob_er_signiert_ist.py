"""NICHT ANWENDBAR war das falsche Wort — der Traeger ist unsigniert, nicht signaturfrei.

FUND, Codex 3999796576 (P2). Der Traeger fuehrte `signature.state: NOT APPLICABLE` mit der
Begruendung, er werde ueber den emit-und-assemble-Weg signiert. GEMESSEN: der `--v2`-Lauf schreibt
Traeger und Ansichten und endet mit 0, ohne `emit` oder `assemble` je zu rufen. Ein Leser konnte
den Aussteller damit nicht pruefen — und las im selben Feld, das sei bauartbedingt so.

DIE KLASSE: ein Lueckenwort, das die FALSCHE Luecke benennt. "Nicht anwendbar" heisst "hier ohne
Bedeutung"; richtig ist das Gegenteil, der Traeger IST fuer den Signierweg gebaut und nur noch
nicht durch ihn gegangen. Wer die Art der Luecke verwechselt, macht aus einer offenen Aufgabe eine
Eigenschaft.

SIGNIEREN BLEIBT EINE OWNER-TUER. Der private Schluesselteil liegt beim Owner; diese Sitzung kann
den Traeger nicht signieren und behauptet das auch nicht. Was in ihrer Macht steht, ist die
ehrliche Auskunft: was fehlt, was es braeuchte, und was das fuer den Leser bedeutet — und dass die
Auskunft den Leser ERREICHT, also in beiden Ansichten steht und nicht nur im Rohdokument.
"""
from __future__ import annotations

import base64
import copy
import importlib.util
import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
TRAEGER = REPO / "audit_artifacts" / "600" / "findings_register_v2.json"
MD = REPO / "audit_artifacts" / "600" / "views" / "uebersicht.md"
HTML = REPO / "audit_artifacts" / "600" / "views" / "uebersicht.html"


def _gen():
    p = REPO / "scripts" / "gen_findings_register.py"
    if not p.is_file():
        pytest.skip(f"NICHT MESSBAR: {p} fehlt")
    s = importlib.util.spec_from_file_location("_gfr8", p)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def _doc():
    if not TRAEGER.is_file():
        pytest.skip(f"NICHT MESSBAR: {TRAEGER} fehlt")
    return json.loads(TRAEGER.read_text(encoding="utf-8"))


def test_der_zustand_heisst_UNSIGNED_und_nicht_NICHT_ANWENDBAR():
    """[ZAEHLT] Der Fund selbst: das Lueckenwort benannte die falsche Luecke."""
    s = _doc().get("signature") or {}
    assert s.get("state") == "UNSIGNED", s
    assert s.get("reason") and s.get("what_would_change_it"), s
    assert s.get("consequence_for_the_reader"), (
        "die Einschraenkung ohne ihre Folge zu nennen heisst, sie nicht zu veroeffentlichen")


def test_beide_ansichten_sagen_es_dem_leser():
    """[ZAEHLT] Eine Auskunft, die nur im Rohdokument steht, erreicht den Leser nicht."""
    for p in (MD, HTML):
        if not p.is_file():
            pytest.skip(f"NICHT MESSBAR: {p} fehlt")
        t = p.read_text(encoding="utf-8")
        assert "UNSIGNED" in t, f"{p.name} nennt den Signaturzustand nicht"
        assert "unauthenticated" in t, f"{p.name} nennt die Folge fuer den Leser nicht"


def test_FANG_ein_zustand_OHNE_grund_wird_gemeldet():
    """[ZAEHLT] Gegenrichtung am Pruefer."""
    g, doc = _gen(), _doc()
    k = copy.deepcopy(doc)
    k["signature"] = {"state": "UNSIGNED"}
    f = g.pruefe_v2(k, REPO)
    assert any("leere Marke" in x for x in f), f[:2]


def test_FANG_UNSIGNED_ohne_die_folge_wird_gemeldet():
    """[ZAEHLT] Die Folge ist das, was den Leser schuetzt — sie darf nicht wegfallen."""
    g, doc = _gen(), _doc()
    k = copy.deepcopy(doc)
    k["signature"] = {"state": "UNSIGNED", "reason": "weil"}
    assert any("Folge fuer den Leser" in x for x in g.pruefe_v2(k, REPO))


def test_FANG_eine_behauptete_signatur_ohne_ihre_teile_wird_gemeldet():
    """[ZAEHLT] Eine Signatur, die man nicht pruefen kann, ist keine."""
    g, doc = _gen(), _doc()
    k = copy.deepcopy(doc)
    k["signature"] = {"sig_b64": "AAAA"}
    assert any("nicht pruefbar" in x for x in g.pruefe_v2(k, REPO))


def test_FANG_ein_traeger_ganz_OHNE_signaturblock_wird_gemeldet():
    """[ZAEHLT] Schweigen ueber die Echtheit ist die schlechteste Auskunft."""
    g, doc = _gen(), _doc()
    k = copy.deepcopy(doc)
    k.pop("signature", None)
    assert any("gar nichts" in x for x in g.pruefe_v2(k, REPO))


def test_ANTI_ein_SIGNIERTER_traeger_geht_durch():
    """[ZAEHLT] A tightened check must not block the path it points at.

    (English because it is new; the German around it is the untranslated existing body, by the
    owner's language rule of 2026-09-19.)

    THE DUMMY WAS A COIN FLIP, measured 2026-09-20. What stood here were 32 and 64 ZERO BYTES,
    justified by the comment "nothing is verified at this point, only the shape is checked". That
    was true on the 14th and stopped being true with `_signatur_lage`, which verifies
    cryptographically over the canonical body. And 32 zero bytes, read as a curve point, are NOT
    the identity: they are a point of ORDER 4, so with a zero signature the equation holds exactly
    when the body's hash falls favourably. MEASURED over 200 bodies differing only in a timestamp:
    44 verified, 22 per cent. The order is not INFERRED from that rate, it is computed: the 32
    zero bytes decompress to (x != 0, y = 0), and four self-additions of the point reach the
    identity (0, 1), so the order is exactly 4 and it is not the identity, which would have let
    every message through. The rate agrees with the computation but does not establish it; a hit
    rate is a hint, the arithmetic is the evidence. On `main` the coin landed well, this case was
    green, and every change to the carrier threw it again. SPEC section 4a names this very
    assumption as documented behaviour of the profile ("small-/mixed-order components are
    accepted"), so the checker is right and the dummy never was.

    An anti-case that is green with probability 22 per cent does not measure whether a SIGNED
    carrier passes. It needs a real signature, and that costs three lines.

    WHAT IS DELIBERATELY NOT FIXED HERE, because it is a decision and not an oversight. A first
    attempt added a catch case demanding that the zero dummy NEVER verify. It fails, on this tree
    and on `main`, because `_signatur_lage` delegates to `cryptography` and this profile ACCEPTS
    small-order components, which SPEC section 4a states explicitly and pins byte-exact against
    the "Taming the Many EdDSAs" vectors. A test asserting the opposite would fix a property the
    verifier does not have and, by its own promise, is not meant to have. Refusing a small-order
    key at the carrier's signature block is a CODE change to `_signatur_lage`; it belongs in its
    own branch with its own catch proof, not in a documentation cut. Carried as
    SMALL-ORDER-KEY-AT-CARRIER-SIGNATURE-01, target 6.2.0, so the finding does not vanish with
    this comment.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    g, doc = _gen(), _doc()
    k = copy.deepcopy(doc)
    schluessel = Ed25519PrivateKey.generate()
    oeffentlich = schluessel.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    k["signature"] = {"alg": "ed25519",
                      "public_key_b64": base64.b64encode(oeffentlich).decode("ascii"),
                      "sig_b64": ""}
    rumpf = g.canonical_bytes(k)
    k["signature"]["sig_b64"] = base64.b64encode(schluessel.sign(rumpf)).decode("ascii")
    # THE ASSUMPTION THIS CASE RESTS ON, asserted rather than relied upon. An adversarial reading
    # of this very change asked whether the case is circular: the bytes are canonicalised while
    # `sig_b64` is empty, and the block is MUTATED afterwards, so if `canonical_bytes` covered the
    # signature wrapper the verifier would hash something else and this case would pass or fail
    # for a reason that has nothing to do with the signature. It does not cover it
    # (`gen_findings_register.canonical_bytes` drops the `signature` key), and that is the only
    # reason the mutation is allowed. If someone ever includes the wrapper, this line fails first
    # and says why, instead of leaving a confusing InvalidSignature two frames down.
    assert g.canonical_bytes(k) == rumpf, (
        "canonical_bytes no longer ignores the signature wrapper, so the bytes signed here are "
        "not the bytes the checker verifies — this case would be measuring nothing")
    assert g._signatur_lage(k)[0] == "VERIFIZIERT", (
        f"eine echte Signatur ueber den kanonischen Rumpf muss verifizieren, gemessen: "
        f"{g._signatur_lage(k)}")
    assert not [x for x in g.pruefe_v2(k, REPO) if x.startswith("Signatur")]


def test_ANTI_der_echte_traeger_bleibt_fehlerfrei():
    """[GETRENNT] Ein Riegel, der alles meldet, misst nichts."""
    g, doc = _gen(), _doc()
    assert g.pruefe_v2(doc, REPO) == []
