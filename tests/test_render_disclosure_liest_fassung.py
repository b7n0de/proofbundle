"""Der Renderer liest die Fassung aus dem Predicate — gemessen am ersten echten v0.2-Receipt.

WAS PASSIERT IST (04.09.2026, PR 185). Das erste v0.2-Receipt, das nicht aus dem Korpus kam,
sondern eine wirkliche Pull Request beschrieb, trug `declaration.timeClaims` — und
`render_disclosure_block` wies es ab: der Renderer rief den v0.1-Pruefer, und der kennt das Feld
nicht. Emitter und Verifizierer waren laengst versioniert; die Darstellung war es nicht. Dieselbe
Kopplung, die Teil A5 in vier Schichten gefunden hatte, in der fuenften.

WARUM DIE TESTS HIER `timeClaims` SETZEN. Der Korpus traegt in keinem v0.2-Fall `timeClaims`, und
`limitationCodes` ist auch in v0.1 zulaessig. Ein Test auf dem blossen Korpusfall waere auf dem
alten Code GRUEN gewesen und haette den Defekt nicht gesehen — er prueft den Fall, den man im
Kopf hat, nicht den, der aufgetreten ist.
"""
from __future__ import annotations

import base64
import json
import pathlib

import pytest

from proofbundle import agent_review as ar

KORPUS = pathlib.Path(__file__).resolve().parents[1] / "conformance" / "agent_review"


def _predicate(case_dir: str) -> dict:
    env = json.loads((KORPUS / case_dir / "envelope.json").read_text(encoding="utf-8"))
    return json.loads(base64.b64decode(env["payload"], validate=True))["predicate"]


def _v02_mit_timeclaims() -> dict:
    p = _predicate("agent-review-v02-positive-control-current-v02-is-marked-current")
    p["declaration"]["timeClaims"] = [{"kind": "reviewCompleted", "value": "2026-09-04T12:47:25Z",
                                       "assertedBy": "test", "assurance": "selfDeclared"}]
    # Vorbedingung, kein Prueflauf: der Fall ist nach v0.2 strikt gueltig, sonst misst der Test
    # unten den Fixture-Fehler statt den Renderer.
    assert ar.validate_agent_review_v02_predicate(p, strict=True) == []
    return p


def test_block_eines_v02_predicates_mit_timeclaims_wird_gerendert():
    block = ar.render_disclosure_block(_v02_mit_timeclaims(), receipt_digest="0" * 64)
    assert block.startswith(ar.DISCLOSURE_BEGIN) and block.endswith(ar.DISCLOSURE_END)
    for label in ar._HUMAN_LINE_ORDER:
        assert f"- **{label}:**" in block
    assert f"`sha256:{'0' * 64}`" in block


def test_zeile_eines_v02_predicates_mit_timeclaims_wird_gerendert():
    line = ar.render_disclosure_line(_v02_mit_timeclaims(), receipt_digest="0" * 64,
                                     receipt_url="https://example.invalid/r.json")
    assert "assurance selfDeclared" in line


def test_v01_predicate_rendert_wie_bisher():
    p = _predicate("agent-review-v02-positive-control-legacy-v01-is-marked-legacy")
    assert "timeClaims" not in p["declaration"]
    assert not ar._traegt_v02_felder(p)
    assert "- **Assurance:**" in ar.render_disclosure_block(p)


def test_v02_wird_strenger_geprueft_nicht_nachsichtiger():
    # Gate-Meta in die Gegenrichtung: die Weiche darf die Pruefung nicht aufweichen. Ohne
    # `limitationCodes` ist ein v0.2-Predicate ungueltig, und der Renderer muss das sagen.
    p = _v02_mit_timeclaims()
    del p["limitationCodes"]
    with pytest.raises(ar.AgentReviewError, match="limitationCodes"):
        ar.render_disclosure_block(p)


def test_fangnachweis_ohne_die_weiche_kommt_der_gemessene_fehler_zurueck(monkeypatch):
    # Der Mutant ist der alte Code: die Weiche sagt immer "v0.1". Dann faellt genau die
    # Fehlermeldung wieder, die PR 185 gemessen hat.
    monkeypatch.setattr(ar, "_traegt_v02_felder", lambda predicate: False)
    with pytest.raises(ar.AgentReviewError, match="timeClaims"):
        ar.render_disclosure_block(_v02_mit_timeclaims())
