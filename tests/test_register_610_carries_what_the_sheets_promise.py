"""The producer of the signed register and the shipped risk sheets are bound in BOTH directions.

WHY A SECOND GUARD BESIDE `tests/test_a_register_entry_promised_in_prose_exists.py`. That file
asks whether a promised identifier exists in ANY register file, and the unsigned v2 carrier of
line 610 satisfied it from 2026-09-20 on. The release-deciding artefact is a different one:
`C12.2` reads `audit_artifacts/findings_register_361.json`, the v1 register that the owner signs,
and that register is built from `FINDINGS` in `scripts/gen_findings_register.py`. A promise that
only the unsigned carrier keeps is kept where nothing decides. Measured at `1283954` before this
file: five promised identifiers, none of them in `FINDINGS`.

THE OTHER DIRECTION IS THE ONE THAT AGES QUIETLY. An entry in `FINDINGS` with no find site in any
shipped sheet is a finding nobody can read up on: it decides the release (if P0/P1) or fills the
count (otherwise) on the producer's word alone. Every carried entry of line 600 has a table row
`| N<n> |` in `RESTRISIKO_600.md`; every promised entry has its `Register entry` sentence. A new
entry has to have one of the two, or say in a named exception why not.

AND THE VERSION IS READ, NOT REMEMBERED. The producer's `VERSION` must equal the version the tree
ships (`pyproject.toml`), because `findings_register._version_binding_error` refuses everything
else fail-closed and a producer that emits the wrong version produces a register that decides
nothing. The 6.0.0 round found exactly this one level down (a valid 3.6.1 register deciding 6.0.0).

WHAT THIS DOES NOT CLAIM: that the signed artefact in the tree matches the producer. That is
`tests/test_register_gegen_erzeuger.py`, a separate assurance, and it is red between the moment
the producer moves and the moment the owner signs — on purpose.
"""
from __future__ import annotations

import importlib.util
import pathlib
import re
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
ERZEUGER = REPO / "scripts" / "gen_findings_register.py"
PYPROJECT = REPO / "pyproject.toml"

#: The prose form of a promise, the same pattern the neighbouring guard uses (measured there: the
#: sentence wraps across lines, so the pattern allows any whitespace between the words and the
#: token). Read from the sheets, not from the evidence copies under `audit_artifacts/`.
_ZUSAGE = re.compile(r"Register entry[:\s]+`([^`\s]+)`")
#: A carried finding of line 600 is DECLARED as a table row at the start of a line; an `N12` in
#: running text is a reference, not a declaration.
_TABELLENZEILE = re.compile(r"^\|\s*(N\d+)\s*\|", re.M)
_NICHT_BLATT = ("audit_artifacts/",)


def _im_checkout() -> bool:
    try:
        from conftest import running_in_repo_checkout  # noqa: PLC0415
    except Exception:                                  # noqa: BLE001
        return any((REPO / m).exists() for m in ("RESTRISIKO_600.md", "audit_artifacts"))
    return running_in_repo_checkout()


if not _im_checkout():
    pytest.skip("not shipped: this module reads the risk sheets and the producer, and the "
                "distribution carries neither — N/A outside a git checkout",
                allow_module_level=True)


def _erzeuger():
    if not ERZEUGER.is_file():
        pytest.skip("scripts/gen_findings_register.py is not in this tree")
    spec = importlib.util.spec_from_file_location("_gfr_zusagen", str(ERZEUGER))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_gfr_zusagen"] = mod
    spec.loader.exec_module(mod)
    return mod


def _blaetter(wurzel: pathlib.Path) -> list[pathlib.Path]:
    return sorted(p for p in wurzel.glob("**/*.md") if p.is_file()
                  and not any(str(p.relative_to(wurzel)).startswith(x) for x in _NICHT_BLATT))


def zusagen(wurzel: pathlib.Path) -> dict[str, str]:
    """identifier -> first sheet that promises it, over every shipped Markdown document."""
    raus: dict[str, str] = {}
    for b in _blaetter(wurzel):
        for k in _ZUSAGE.findall(b.read_text(encoding="utf-8", errors="replace")):
            raus.setdefault(k, str(b.relative_to(wurzel)))
    return raus


def fundstellen(wurzel: pathlib.Path) -> dict[str, str]:
    """identifier -> where a reader finds it: a `| N<n> |` row of a sheet, or a promise."""
    raus = dict(zusagen(wurzel))
    for b in _blaetter(wurzel):
        for k in _TABELLENZEILE.findall(b.read_text(encoding="utf-8", errors="replace")):
            raus.setdefault(k, str(b.relative_to(wurzel)))
    return raus


def ohne_traeger(findings: list[dict], wurzel: pathlib.Path) -> list[str]:
    """Promised identifiers that `findings` does not carry."""
    ids = {str(f.get("id")) for f in findings}
    return sorted(k for k in zusagen(wurzel) if k not in ids)


def ohne_fundstelle(findings: list[dict], wurzel: pathlib.Path) -> list[str]:
    """Entries of `findings` that no shipped sheet declares or promises."""
    stellen = fundstellen(wurzel)
    return sorted(str(f.get("id")) for f in findings if str(f.get("id")) not in stellen)


def test_jede_zusage_der_blaetter_steht_im_erzeuger():
    """[ZAEHLT] Red at `1283954`: five promises, none in FINDINGS."""
    m = _erzeuger()
    fehlend = ohne_traeger(m.FINDINGS, REPO)
    assert not fehlend, (
        f"{len(fehlend)} identifier(s) are promised as a register entry in a shipped sheet and "
        f"missing from scripts/gen_findings_register.py::FINDINGS, so the SIGNED register cannot "
        f"carry them: {fehlend}")


def test_jeder_eintrag_des_erzeugers_hat_eine_fundstelle():
    """[GETRENNT] The direction that ages quietly: an entry nobody can read up on.

    Green at `1283954` as well, because every carried entry had its table row already; the case
    could not be red against that head and says so. Its planted-defect case below is the one that
    shows it can fall."""
    m = _erzeuger()
    fremd = ohne_fundstelle(m.FINDINGS, REPO)
    assert not fremd, (
        f"{len(fremd)} entry/entries of FINDINGS have no find site in any shipped sheet, neither "
        f"a `| N<n> |` row nor a `Register entry` promise: {fremd}. A finding that only the "
        f"producer knows decides or fills the count on its word alone")


def test_die_fassung_des_erzeugers_ist_die_des_baums():
    """[ZAEHLT] A producer emitting another version produces a register that decides nothing."""
    m = _erzeuger()
    roh = PYPROJECT.read_text(encoding="utf-8")
    t = re.search(r'(?m)^\s*version\s*=\s*["\']([^"\']+)["\']', roh)
    assert t, "pyproject.toml names no version, so nothing can be bound"
    assert m.VERSION == t.group(1), (
        f"the producer speaks about {m.VERSION!r}, the tree ships {t.group(1)!r}; "
        f"findings_register._version_binding_error refuses that register fail-closed")


def test_KONTROLLE_die_muster_finden_die_ausgelieferten_stellen():
    """A guard whose patterns match nothing is green for the wrong reason."""
    assert len(zusagen(REPO)) >= 5, f"the promise pattern sees {len(zusagen(REPO))} promise(s)"
    n_zeilen = sum(1 for k in fundstellen(REPO) if _TABELLENZEILE.match(f"| {k} |"))
    assert n_zeilen >= 21, f"the table-row pattern sees {n_zeilen} row(s); line 600 has 21"


def test_FANG_eine_zusage_ohne_eintrag_wird_gemeldet(tmp_path):
    """[ZAEHLT] The planted defect of the first direction, on given data rather than the tree."""
    (tmp_path / "RESTRISIKO_PROBE.md").write_text(
        "Register entry `NUR-VERSPROCHEN-NIE-GETRAGEN-01`, target 9.9.9.\n", encoding="utf-8")
    assert ohne_traeger([{"id": "N1"}], tmp_path) == ["NUR-VERSPROCHEN-NIE-GETRAGEN-01"]
    # and the same promise with its entry is not reported — otherwise the guard reports everything
    assert ohne_traeger([{"id": "NUR-VERSPROCHEN-NIE-GETRAGEN-01"}], tmp_path) == []


def test_FANG_ein_eintrag_ohne_fundstelle_wird_gemeldet(tmp_path):
    """[ZAEHLT] The planted defect of the second direction."""
    (tmp_path / "RESTRISIKO_PROBE.md").write_text(
        "| N1 | a carried finding |\n\nRegister entry `VERSPROCHEN-01`.\n", encoding="utf-8")
    assert ohne_fundstelle([{"id": "N1"}, {"id": "VERSPROCHEN-01"}, {"id": "N77"}], tmp_path) \
        == ["N77"]
    # a reference in running text is not a declaration
    (tmp_path / "RESTRISIKO_PROBE.md").write_text("as N77 shows in passing\n", encoding="utf-8")
    assert ohne_fundstelle([{"id": "N77"}], tmp_path) == ["N77"]


def test_FANG_eine_kopie_unter_audit_artifacts_zaehlt_nicht(tmp_path):
    """[ZAEHLT] Evidence copies are byte copies of the promise paragraphs; counting them would let
    a promise back itself from its own copy."""
    (tmp_path / "audit_artifacts" / "x").mkdir(parents=True)
    (tmp_path / "audit_artifacts" / "x" / "ev.md").write_text(
        "Register entry `NUR-IN-DER-KOPIE-01`.\n", encoding="utf-8")
    assert zusagen(tmp_path) == {}
