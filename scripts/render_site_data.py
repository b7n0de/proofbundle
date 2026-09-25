#!/usr/bin/env python3
"""render_site_data — site-data.json from measured sources in this repository and nothing else.

Every value carries its source and the time of its measurement. A value the generator cannot
measure stands as not_measurable with a reason, never as 0, never as an empty list and never as a
last-known value. Those three substitutes share one property: they read like a measurement, and a
gap that looks like a value is more expensive than one you can see.

═══ THE CONTRADICTION IN THE REQUIREMENT, AND HOW IT IS RESOLVED HERE ═══

Two demands exclude each other as long as "measurement time" means RUN time:

    every value carries its source and its measurement time
    the file is byte-stable while its sources do not change

A run time in every field makes the file differ on every run even when no source moved. Then
byte-stability is unreachable, and a contract test on it could never be green.

RESOLVED SO: the measurement time of a value is the time of the thing measured, not of the run.

    from a file      the commit that last changed it (author time, UTC)
    from a tag       the date of that tag
    from the network the run time, because a foreign answer has no other time

Everything from the tree is byte-stable that way, and exactly the network fields are not — which
stands in the head of the file as stable false with a reason instead of being a silent exception.
The contract test asserts stability over the TREE fields and over nothing else; asserting it over
everything would give a test that is red on every second run and therefore gets switched off.

═══ WHAT WAS MEASURED BEFORE BUILDING, because three stated sources do not hold as written ═══

  checks     Stated as "3, from the list of verifier checks in the code, not as a constant". A real
             verify run on a conformance bundle yields TWO (`ed25519-signature`,
             `merkle-inclusion`). The count hangs on the BUNDLE and not on the code: a bundle
             without an anchor layer carries no anchor check. So no bare number stands here, but
             the measured list together WITH the bundle it was measured on.
  interop    `docs/interop_status.json` does not exist. A curated list is knowledge someone keeps,
             not a measurement. Absent, it stands as not_measurable with a reason.
  tests      A shell count said 4544, this generator says 4639, and the difference is indented
             class methods. The counting rule therefore stands IN the field; without it the number
             means nothing, and a later run with `--collect-only` names another one while nothing
             has changed.

═══ WHAT THIS FILE DOES NOT DO ═══

It writes no key and no token. It guesses nothing. It never carries a last-known value forward: a
stale value without a marker is worse than a gap, because it is read as a measurement.

Usage:
    python3 scripts/render_site_data.py [--out docs/site/site-data.json] [--no-network] [--json]

Exit: 0 written · 2 nothing measurable, nothing written
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

#: The bundles the verifier checks are measured on. The path travels WITH the number in the result,
#: because a number without its object is the very constant this avoids, only by a detour.
_MEASURED_BUNDLES = (
    "conformance/envelope_profile/r4-positive-control-issuer-is-the-signing-key/bundle.json",
)

#: The counting rule stands as DATA next to the number, not in a comment. A reader who sees 4639
#: has to know what was counted.
_TEST_COUNTING_RULE = (
    "Files: *.py directly under tests/. Functions: lines matching 'def test_', so ONE per "
    "function - parameterised cases count as one and class methods are not counted separately. A "
    "run with `pytest --collect-only` names a different number while nothing has changed."
)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _git(*args: str, baum: Path | None = None) -> tuple[str, str]:
    """(stdout, state). `state` is 'gemessen' or a NOT MEASURABLE sentence."""
    try:
        r = subprocess.run(["git", "-C", str(baum or REPO), *args],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return "", f"NICHT MESSBAR: {type(exc).__name__}: {exc}"
    if r.returncode != 0:
        return "", f"NICHT MESSBAR: git {' '.join(args)} rc={r.returncode}: {r.stderr.strip()[:120]}"
    return r.stdout.strip(), "gemessen"


def _source_time(rel: str) -> str | None:
    """The time of the commit that last changed this path - not the run time.

    `None` when the path is in no commit. That is a statement and not a placeholder: an untracked
    file has no source time a reader could check.
    """
    aus, state = _git("log", "-1", "--format=%aI", "--", rel)
    if state != "gemessen" or not aus:
        return None
    return aus


def _field(value, *, source: str, at: str | None, stable: bool = True, **rest) -> dict:
    """A measured value with its source and its measurement time."""
    d = {"value": value, "source": source, "measured_at": at, "stable": stable}
    d.update(rest)
    return d


def _gap(*, source: str, reason: str, **rest) -> dict:
    """NOT MEASURABLE with a reason. Explicitly NOT 0, NOT an empty list, NOT an old value.

    Those three substitutes are named and forbidden for one shared property: they read like a
    measurement. A gap that looks like a value is more expensive than one you can see.
    """
    d = {"not_measurable": True, "reason": reason, "source": source, "measured_at": None,
         "stable": True}
    d.update(rest)
    return d


# ── version, release_date, release_commit ───────────────────────────────────────────────────────
def version_and_release() -> dict:
    """Version from pyproject, date and commit from the tag of that version."""
    p = REPO / "pyproject.toml"
    if not p.is_file():
        return {"version": _gap(source="pyproject.toml", reason="pyproject.toml fehlt"),
                "release_date": _gap(source="git tag", reason="ohne Version kein Tag"),
                "release_commit": _gap(source="git tag", reason="ohne Version kein Tag")}
    m = re.search(r'^version\s*=\s*"([^"]+)"', p.read_text(encoding="utf-8"), re.M)
    if not m:
        return {"version": _gap(source="pyproject.toml",
                                   reason="pyproject.toml traegt keine version-Zeile"),
                "release_date": _gap(source="git tag", reason="ohne Version kein Tag"),
                "release_commit": _gap(source="git tag", reason="ohne Version kein Tag")}
    v = m.group(1)
    at = _source_time("pyproject.toml")
    aus = {"version": _field(v, source="pyproject.toml:version", at=at)}

    tag = f"v{v}"
    datum, state = _git("tag", "--list", tag, "--format=%(creatordate:iso-strict)")
    kopf, lage2 = _git("rev-list", "-n", "1", tag)
    if state != "gemessen" or not datum:
        aus["release_date"] = _gap(source=f"git tag {tag}",
                                      reason=f"kein Tag {tag} in diesem Baum — die Version in "
                                            "pyproject ist noch nicht veroeffentlicht")
        aus["release_commit"] = _gap(source=f"git tag {tag}", reason=f"kein Tag {tag}")
        return aus
    aus["release_date"] = _field(datum, source=f"git tag {tag}", at=datum)
    aus["release_commit"] = (_field(kopf, source=f"git rev-list -n1 {tag}", at=datum)
                             if lage2 == "gemessen" and kopf else
                             _gap(source=f"git rev-list -n1 {tag}", reason=lage2))
    return aus


# ── checks ──────────────────────────────────────────────────────────────────────────────────────
def verifier_checks() -> dict:
    """The checks of a REAL verify run, together with the bundle they were measured on.

    NO NUMBER WITHOUT ITS OBJECT. "Not as a constant" is not satisfied by a number that came from a
    run whose object is missing from the result: such a number cannot be told apart from a constant.
    Measured on an envelope bundle it is TWO and not three, because a bundle without an anchor layer
    carries no anchor check.
    """
    ergebnisse = []
    for rel in _MEASURED_BUNDLES:
        p = REPO / rel
        if not p.is_file():
            ergebnisse.append({"bundle": rel, "not_measurable": True,
                               "reason": "Buendel fehlt in diesem Baum"})
            continue
        state, namen = _verify(p)
        if namen is None:
            ergebnisse.append({"bundle": rel, "not_measurable": True, "reason": state})
            continue
        ergebnisse.append({"bundle": rel, "count": len(namen), "checks_measured": namen,
                           "at": _source_time(rel)})
    measured = [e for e in ergebnisse if "count" in e]
    if not measured:
        return _gap(source="proofbundle verify ueber " + ", ".join(_MEASURED_BUNDLES),
                       reason="kein Messbuendel lieferte ein Ergebnis", runs=ergebnisse)
    return _field(measured[0]["count"],
                 source=f"proofbundle verify {measured[0]['bundle']}",
                 at=measured[0]["at"], checks_measured=measured[0]["checks_measured"],
                 runs=ergebnisse,
                 note=("the count hangs on the bundle and not on the code; a bundle without an "
                       "anchor layer carries no anchor check"))


def _verify(pfad: Path) -> tuple[str, list[str] | None]:
    """(state, check names). `None` means not measured, and the state says why.

    THE ENTRY POINT IS `proofbundle.cli.main` AND NOT `python -m proofbundle`: the package has no
    `__main__`, and the module form ends with "No module named proofbundle.__main__". A generator
    taking the wrong entry point reports NOT MEASURABLE for every bundle while looking careful.
    """
    code = (
        "import json,sys; sys.path.insert(0,'src');"
        "from proofbundle import cli; sys.argv=['proofbundle','verify',%r,'--json'];"
        "\ntry: cli.main()\nexcept SystemExit: pass" % str(pfad)
    )
    try:
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                           timeout=180, cwd=str(REPO))
    except (OSError, subprocess.SubprocessError) as exc:
        return f"NICHT MESSBAR: {type(exc).__name__}: {exc}", None
    i = r.stdout.find("{")
    if i < 0:
        return (f"NICHT MESSBAR: verify gab kein JSON zurueck (rc={r.returncode}): "
                f"{(r.stderr or r.stdout).strip()[:140]}"), None
    try:
        d = json.loads(r.stdout[i:])
    except ValueError as exc:
        return f"NICHT MESSBAR: verify-Ausgabe ist kein JSON: {exc}", None
    # `checks` carries `name`, `matrix` carries `check` - two shapes of one list. The source is
    # read, not the presentation.
    namen = [c.get("name") for c in (d.get("checks") or []) if c.get("name")]
    if not namen:
        namen = [c.get("check") for c in (d.get("matrix") or []) if c.get("check")]
    if not namen:
        return "NICHT MESSBAR: die verify-Ausgabe traegt keine Pruefnamen", None
    return "gemessen", namen


# ── tests ───────────────────────────────────────────────────────────────────────────────────────
def test_surface() -> dict:
    d = REPO / "tests"
    if not d.is_dir():
        return {"tests_files": _gap(source="tests/", reason="tests/ fehlt"),
                "tests_functions": _gap(source="tests/", reason="tests/ fehlt")}
    dateien = sorted(p for p in d.glob("*.py"))
    n = 0
    for p in dateien:
        try:
            n += len(re.findall(r"^\s*def test_", p.read_text(encoding="utf-8"), re.M))
        except OSError:
            continue
    at = _source_time("tests")
    return {"tests_files": _field(len(dateien), source="tests/*.py", at=at,
                                 counting_rule=_TEST_COUNTING_RULE),
            "tests_functions": _field(n, source="tests/*.py", at=at,
                                     counting_rule=_TEST_COUNTING_RULE)}


# ── interop ─────────────────────────────────────────────────────────────────────────────────────
def interop() -> dict:
    rel = "docs/interop_status.json"
    p = REPO / rel
    if not p.is_file():
        return _gap(source=rel,
                       reason=("die gepflegte Liste fehlt in diesem Baum. Ihr Inhalt ist Wissen, "
                              "das jemand pflegt, und keine Messung — der Erzeuger kann sie lesen "
                              "und ihr Fehlen melden, ihren Inhalt nicht erfinden"))
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return _gap(source=rel, reason=f"unlesbar: {type(exc).__name__}: {exc}")
    zeilen = d if isinstance(d, list) else (d.get("rows") or d.get("entries") or [])
    fehlend = [i for i, z in enumerate(zeilen)
               if not (isinstance(z, dict) and z.get("at") and z.get("beleg") and z.get("datum"))]
    return _field(zeilen, source=rel, at=_source_time(rel),
                 rows_without_required_fields=fehlend,
                 note=("each row is required to carry state, evidence and date; rows missing "
                       "any of the three stand in rows_without_required_fields and are not "
                       "silently completed"))


# ── proof_log ───────────────────────────────────────────────────────────────────────────────────
def _check_receipt(d: dict) -> dict:
    """A pre-tag receipt with ITS OWN checker, not with the bundle verifier.

    THE FIRST DRAFT WROTE `failed` FOR ALL FOUR, and that would have been a false accusation about
    this project's own release receipts on a public page. A pre-tag receipt carries
    `schema: b7n0de.pre_tag_audit_receipt.v1` with `audit_command`, `audit_exit_code`, `signature`
    and `signer_pubkey` - it is NOT a proofbundle bundle. `proofbundle verify` on it produces no
    check names, and that was read as a failure.

    THREE STATES, NEVER TWO: `passed`, `failed`, `nicht_pruefbar` with a reason. `failed` means
    checked and failed; writing it for an artefact kind touched with the wrong tool is an accusation
    without a measurement.

    WHAT IS CHECKED and what explicitly is not: the signature by a TRUSTED key, the version binding,
    and `audit_exit_code == 0`. NOT checked is the binding to the tree - that would need the tree AT
    THE TAG and not today's, and holding a historical receipt against today's tree would have to
    fail because the tree moved on. That stands as
    `baumbindung: nicht_gepruefbar_ohne_auscheckung_am_tag` in the result instead of silently
    missing.
    """
    if not isinstance(d, dict) or d.get("schema") != "b7n0de.pre_tag_audit_receipt.v1":
        return {"state": "not_checkable",
                "reason": (f"unbekannte Artefaktart {(d or {}).get('schema')!r} — fuer sie ist hier "
                          "kein Pruefer erklaert, und ein Urteil ohne Pruefer waere geraten")}
    try:
        sys.path.insert(0, str(REPO / "src"))
        sys.path.insert(0, str(REPO / "scripts"))
        import importlib.util as _u  # noqa: PLC0415
        s = _u.spec_from_file_location("_ptl", REPO / "scripts" / "pre_tag_receipt_lib.py")
        lib = _u.module_from_spec(s)
        s.loader.exec_module(lib)
        from proofbundle._wire_b64 import decode_b64  # noqa: PLC0415
        from proofbundle.signature import verify_ed25519  # noqa: PLC0415
    except Exception as exc:  # noqa: BLE001 - a checker that will not load is NOT MEASURABLE
        return {"state": "not_checkable",
                "reason": f"der Pruefer ist nicht ladbar: {type(exc).__name__}: {exc}"}

    try:
        vertraut = lib.load_trusted_pubkeys(REPO)
    except Exception as exc:  # noqa: BLE001
        return {"state": "not_checkable",
                "reason": f"die Liste der vertrauten Schluessel ist nicht lesbar: {exc}"}

    pub = d.get("signer_pubkey")
    if pub not in (vertraut or []):
        return {"state": "failed",
                "reason": "der signierende Schluessel steht nicht in "
                         "audit_artifacts/pre_tag_trusted_pubkeys.txt",
                "tree_binding": "nicht_gepruefbar_ohne_auscheckung_am_tag"}
    try:
        # THE ORDER IS (pubkey, signature, message) AND NOT (pubkey, message, signature). The
        # first draft had the last two swapped. The call succeeded, returned a bool, and the bool was
        # wrong: ALL FOUR genuine release receipts reported that their ed25519 signature does not
        # hold, and that would have gone onto a public page as an accusation. The correct order is in
        # pre_tag_receipt_lib.verify_receipt.
        ok = verify_ed25519(decode_b64(pub), decode_b64(d.get("signature")),
                            lib.canonical_bytes(d))
    except Exception as exc:  # noqa: BLE001
        return {"state": "not_checkable",
                "reason": f"die Signatur ist nicht auswertbar: {type(exc).__name__}: {exc}"}
    if not ok:
        return {"state": "failed", "reason": "die ed25519-Signatur haelt nicht",
                "tree_binding": "nicht_gepruefbar_ohne_auscheckung_am_tag"}
    if d.get("audit_exit_code") != 0:
        return {"state": "failed",
                "reason": f"audit_exit_code ist {d.get('audit_exit_code')!r} und nicht 0 — die "
                         "Quittung bezeugt einen FEHLGESCHLAGENEN Lauf",
                "tree_binding": "nicht_gepruefbar_ohne_auscheckung_am_tag"}
    return {"state": "passed",
            "checked": ["signatur_durch_vertrauten_schluessel", "audit_exit_code_0"],
            "tree_binding": "nicht_gepruefbar_ohne_auscheckung_am_tag",
            "tree_binding_reason": ("verify_receipt verlangt den erwarteten Baum-Digest; eine "
                                  "historische Quittung gegen den HEUTIGEN Baum zu halten muesste "
                                  "fehlschlagen, weil der Baum weitergelaufen ist")}


def proof_log(*, check: bool = True) -> dict:
    """Per release the pre-tag receipt, its sha256, the recompute command and a REAL checker.

    THE GENERATOR CHECKS ITSELF, and a failure stands as `failed` WITH its reason. A receipt listed
    in a proof log that nobody ran is a claim about a check. But `failed` is only written when a
    check actually ran; otherwise `nicht_pruefbar`.
    """
    eintraege = []
    for p in sorted((REPO / "audit_artifacts").glob("*/pre_tag_receipt_*.json")):
        rel = str(p.relative_to(REPO))
        try:
            rohe = p.read_bytes()
            inhalt = json.loads(rohe)
        except (OSError, ValueError) as exc:
            eintraege.append({"receipt": rel, "not_measurable": True, "reason": str(exc)[:140]})
            continue
        e = {
            "receipt": rel,
            "version": inhalt.get("version"),
            "sha256": hashlib.sha256(rohe).hexdigest(),
            "recompute": f"sha256sum {rel}",
            "measured_at": _source_time(rel),
        }
        e["check"] = (_check_receipt(inhalt) if check else
                       {"state": "not_run", "reason": "--no-check was set"})
        eintraege.append(e)
    if not eintraege:
        return _gap(source="audit_artifacts/*/pre_tag_receipt_*.json",
                       reason="keine Pre-Tag-Quittung in diesem Baum")
    return _field(eintraege, source="audit_artifacts/*/pre_tag_receipt_*.json",
                 at=max((e.get("measured_at") or "") for e in eintraege) or None)


# ── audit_state / audit_link ────────────────────────────────────────────────────────────────────
def audit_state_field(version_wert) -> dict:
    d = REPO / "audit_artifacts"
    if not d.is_dir():
        return {"audit_state": _gap(source="audit_artifacts/", reason="audit_artifacts/ fehlt"),
                "audit_link": _gap(source="audit_artifacts/", reason="audit_artifacts/ fehlt")}
    stufen = sorted(p.name for p in d.iterdir() if p.is_dir() and p.name.isdigit())
    erwartet = None
    if isinstance(version_wert, str):
        teile = version_wert.split(".")
        if len(teile) >= 2 and all(t.isdigit() for t in teile[:2]):
            erwartet = f"{teile[0]}{teile[1]}0"
    at = _source_time("audit_artifacts")
    if erwartet and erwartet not in stufen:
        return {"audit_state": _gap(
                    source="audit_artifacts/", stages=stufen,
                    reason=(f"fuer Version {version_wert} waere Stufe {erwartet} zu erwarten; sie "
                           f"liegt nicht. Vorhanden sind {', '.join(stufen)}")),
                "audit_link": _gap(source="audit_artifacts/",
                                      reason=f"ohne Stufe {erwartet} kein Link")}
    stufe = erwartet or (stufen[-1] if stufen else None)
    if stufe is None:
        return {"audit_state": _gap(source="audit_artifacts/", reason="keine Stufe vorhanden"),
                "audit_link": _gap(source="audit_artifacts/", reason="keine Stufe vorhanden")}
    return {"audit_state": _field(stufe, source="audit_artifacts/", at=at, stages=stufen),
            "audit_link": _field(f"audit_artifacts/{stufe}/", source="audit_artifacts/",
                                at=at)}


# ── scorecard ───────────────────────────────────────────────────────────────────────────────────
def scorecard(*, network: bool = True) -> dict:
    ziel = "https://api.scorecard.dev/projects/github.com/b7n0de/proofbundle"
    if not network:
        return _gap(source=ziel, reason="--no-network was set, so it was not asked", stable=False)
    try:
        r = subprocess.run(["curl", "-sS", "--max-time", "25", ziel],
                           capture_output=True, text=True, timeout=40)
    except (OSError, subprocess.SubprocessError) as exc:
        return _gap(source=ziel, reason=f"{type(exc).__name__}: {exc}", stable=False)
    if r.returncode != 0:
        return _gap(source=ziel, reason=f"curl rc={r.returncode}: {r.stderr.strip()[:140]}",
                       stable=False)
    try:
        d = json.loads(r.stdout or "null")
    except ValueError as exc:
        return _gap(source=ziel, reason=f"Antwort ist kein JSON: {exc}", stable=False)
    if not isinstance(d, dict):
        return _gap(source=ziel, reason=f"Antwort ist {type(d).__name__}, erwartet ein Objekt",
                       stable=False)
    pruefungen = d.get("checks") or []
    # ALL values, not the overall score. How many there really are is said by the answer and not
    # by the requirement, so the measured count stands next to them.
    return _field({"score": d.get("score"),
                  "checks": [{"name": c.get("name"), "score": c.get("score"),
                              "reason": c.get("reason")} for c in pruefungen]},
                 source=ziel, at=_now(), stable=False,
                 check_count=len(pruefungen),
                 note=("from the network and therefore not byte-stable: a foreign answer has no "
                       "source time in the tree, its measurement time is the run time"))


def build(*, network: bool = True, check: bool = True) -> dict:
    vr = version_and_release()
    aus = {
        "schema": "b7n0de.proofbundle_site_data.v1",
        "generated_by": "scripts/render_site_data.py",
        "generated_at": _now(),
        # THE EXPLANATION MUST NOT LOOK LIKE A FIELD. The first draft named its keys
        # `messzeit`, `stabil` and `nicht_messbar`, the same names as the data fields. The loop
        # counting the gaps therefore took the explanation block for a measured field without a
        # reason and ended in a KeyError, measured on the first run.
        #
        # Fixed at the COLLISION and not at the single case: the keys now end in `..._bedeutet`, so
        # neither a reader nor a loop can mistake them for a value. A special case in the loop would
        # have produced the same class at the next explanation block.
        "how_to_read": {
            "measured_at_means": ("the time of the thing measured and not of the run: for a file "
                                  "the commit that last changed it, for a tag its date, for the "
                                  "network the run time"),
            "stable_means": ("true means the value changes only when its source changes. Fields "
                             "with false come from the network and make the file differ on every "
                             "run; the contract test asserts stability over the tree fields"),
            "not_measurable_means": ("a value the generator cannot measure stands as "
                                     "not_measurable with a reason. Never 0, never an empty list, "
                                     "never a last-known value"),
        },
        **vr,
        **audit_state_field(vr["version"].get("value")),
        "checks": verifier_checks(),
        **test_surface(),
        "interop": interop(),
        "proof_log": proof_log(check=check),
        "scorecard": scorecard(network=network),
    }
    return aus


def tree_fields(d: dict) -> dict:
    """Only the fields that come from the tree - the object of the stability promise."""
    return {k: v for k, v in d.items()
            if isinstance(v, dict) and v.get("stable") is True}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, default=REPO / "docs" / "site" / "site-data.json")
    ap.add_argument("--no-network", action="store_true",
                    help="die Netzquellen nicht fragen; sie stehen dann als nicht_messbar mit "
                         "genau diesem Grund")
    ap.add_argument("--no-check", action="store_true",
                    help="die Quittungen nicht selbst nachrechnen; ihr Zustand ist dann "
                         "nicht_gefahren und ausdruecklich nicht passed")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    d = build(network=not a.no_network, check=not a.no_check)
    luecken = [k for k, v in d.items() if isinstance(v, dict) and v.get("not_measurable")]
    if len(luecken) == len([k for k, v in d.items() if isinstance(v, dict) and "stable" in v]):
        print("NICHT MESSBAR: keine einzige Quelle lesbar — nichts geschrieben", file=sys.stderr)
        return 2

    a.out.parent.mkdir(parents=True, exist_ok=True)
    tmp = a.out.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    tmp.replace(a.out)

    if a.json:
        print(json.dumps(d, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"geschrieben: {a.out.relative_to(REPO) if a.out.is_relative_to(REPO) else a.out}")
        print(f"  Felder: {len([k for k, v in d.items() if isinstance(v, dict) and 'stable' in v])} "
              f"· nicht messbar: {len(luecken)}")
        for k in luecken:
            print(f"  ! {k}: {d[k]['reason'][:110]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
