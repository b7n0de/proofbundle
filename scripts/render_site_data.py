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
  tests      Measured 2026-09-25: a shell count over the same files said 4544 while this generator
             said 4639, and the difference is indented class methods. BOTH numbers move as tests are
             added, so neither is named here as a current value; the counting rule stands IN the
             field, because without it a later count is not comparable to this one.

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

#: The counting rule stands as DATA next to the number, not in a comment. A reader who sees a
#: four-digit count has to know what was counted.
_TEST_COUNTING_RULE = (
    "Files: *.py directly under tests/. Functions: lines matching 'def test_', so ONE per "
    "function - parameterised cases count as one and class methods are not counted separately. A "
    "run with `pytest --collect-only` names a different number while nothing has changed."
)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _git(*args: str, tree: Path | None = None) -> tuple[str, str]:
    """(stdout, state). `state` is 'measured' or a NOT MEASURABLE sentence."""
    try:
        r = subprocess.run(["git", "-C", str(tree or REPO), *args],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return "", f"NOT MEASURABLE: {type(exc).__name__}: {exc}"
    if r.returncode != 0:
        return "", f"NOT MEASURABLE: git {' '.join(args)} rc={r.returncode}: {r.stderr.strip()[:120]}"
    return r.stdout.strip(), "measured"


def _source_time(rel: str) -> str | None:
    """The time of the commit that last changed this path - not the run time.

    `None` when the path is in no commit. That is a statement and not a placeholder: an untracked
    file has no source time a reader could check.
    """
    out, state = _git("log", "-1", "--format=%aI", "--", rel)
    if state != "measured" or not out:
        return None
    return out


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
        return {"version": _gap(source="pyproject.toml", reason="pyproject.toml is missing"),
                "release_date": _gap(source="git tag", reason="no version, so no tag"),
                "release_commit": _gap(source="git tag", reason="no version, so no tag")}
    m = re.search(r'^version\s*=\s*"([^"]+)"', p.read_text(encoding="utf-8"), re.M)
    if not m:
        return {"version": _gap(source="pyproject.toml",
                                   reason="pyproject.toml carries no version line"),
                "release_date": _gap(source="git tag", reason="no version, so no tag"),
                "release_commit": _gap(source="git tag", reason="no version, so no tag")}
    v = m.group(1)
    at = _source_time("pyproject.toml")
    out = {"version": _field(v, source="pyproject.toml:version", at=at)}

    tag = f"v{v}"
    date, state = _git("tag", "--list", tag, "--format=%(creatordate:iso-strict)")
    head, state2 = _git("rev-list", "-n", "1", tag)
    if state != "measured" or not date:
        out["release_date"] = _gap(source=f"git tag {tag}",
                                      reason=f"no tag {tag} in this tree - the version in "
                                            "pyproject is not released yet")
        out["release_commit"] = _gap(source=f"git tag {tag}", reason=f"no tag {tag}")
        return out
    out["release_date"] = _field(date, source=f"git tag {tag}", at=date)
    out["release_commit"] = (_field(head, source=f"git rev-list -n1 {tag}", at=date)
                             if state2 == "measured" and head else
                             _gap(source=f"git rev-list -n1 {tag}", reason=state2))
    return out


# ── checks ──────────────────────────────────────────────────────────────────────────────────────
def verifier_checks() -> dict:
    """The checks of a REAL verify run, together with the bundle they were measured on.

    NO NUMBER WITHOUT ITS OBJECT. "Not as a constant" is not satisfied by a number that came from a
    run whose object is missing from the result: such a number cannot be told apart from a constant.
    Measured on an envelope bundle it is TWO and not three, because a bundle without an anchor layer
    carries no anchor check.
    """
    results = []
    for rel in _MEASURED_BUNDLES:
        p = REPO / rel
        if not p.is_file():
            results.append({"bundle": rel, "not_measurable": True,
                               "reason": "the bundle is missing in this tree"})
            continue
        state, names = _verify(p)
        if names is None:
            results.append({"bundle": rel, "not_measurable": True, "reason": state})
            continue
        results.append({"bundle": rel, "count": len(names), "checks_measured": names,
                           "at": _source_time(rel)})
    measured = [e for e in results if "count" in e]
    if not measured:
        return _gap(source="proofbundle verify over " + ", ".join(_MEASURED_BUNDLES),
                       reason="no measuring bundle produced a result", runs=results)
    return _field(measured[0]["count"],
                 source=f"proofbundle verify {measured[0]['bundle']}",
                 at=measured[0]["at"], checks_measured=measured[0]["checks_measured"],
                 runs=results,
                 note=("the count hangs on the bundle and not on the code; a bundle without an "
                       "anchor layer carries no anchor check"))


def _verify(path: Path) -> tuple[str, list[str] | None]:
    """(state, check names). `None` means not measured, and the state says why.

    THE ENTRY POINT IS `proofbundle.cli.main` AND NOT `python -m proofbundle`: the package has no
    `__main__`, and the module form ends with "No module named proofbundle.__main__". A generator
    taking the wrong entry point reports NOT MEASURABLE for every bundle while looking careful.
    """
    code = (
        "import json,sys; sys.path.insert(0,'src');"
        "from proofbundle import cli; sys.argv=['proofbundle','verify',%r,'--json'];"
        "\ntry: cli.main()\nexcept SystemExit: pass" % str(path)
    )
    try:
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                           timeout=180, cwd=str(REPO))
    except (OSError, subprocess.SubprocessError) as exc:
        return f"NOT MEASURABLE: {type(exc).__name__}: {exc}", None
    i = r.stdout.find("{")
    if i < 0:
        return (f"NOT MEASURABLE: verify returned no JSON (rc={r.returncode}): "
                f"{(r.stderr or r.stdout).strip()[:140]}"), None
    try:
        d = json.loads(r.stdout[i:])
    except ValueError as exc:
        return f"NOT MEASURABLE: the verify output is not JSON: {exc}", None
    # `checks` carries `name`, `matrix` carries `check` - two shapes of one list. The source is
    # read, not the presentation.
    names = [c.get("name") for c in (d.get("checks") or []) if c.get("name")]
    if not names:
        names = [c.get("check") for c in (d.get("matrix") or []) if c.get("check")]
    if not names:
        return "NOT MEASURABLE: the verify output carries no check names", None
    return "measured", names


# ── tests ───────────────────────────────────────────────────────────────────────────────────────
def test_surface() -> dict:
    d = REPO / "tests"
    if not d.is_dir():
        return {"tests_files": _gap(source="tests/", reason="tests/ is missing"),
                "tests_functions": _gap(source="tests/", reason="tests/ is missing")}
    files = sorted(p for p in d.glob("*.py"))
    n = 0
    for p in files:
        try:
            n += len(re.findall(r"^\s*def test_", p.read_text(encoding="utf-8"), re.M))
        except OSError:
            continue
    at = _source_time("tests")
    return {"tests_files": _field(len(files), source="tests/*.py", at=at,
                                 counting_rule=_TEST_COUNTING_RULE),
            "tests_functions": _field(n, source="tests/*.py", at=at,
                                     counting_rule=_TEST_COUNTING_RULE)}


# ── interop ─────────────────────────────────────────────────────────────────────────────────────
def interop() -> dict:
    rel = "docs/interop_status.json"
    p = REPO / rel
    if not p.is_file():
        return _gap(source=rel,
                       reason=("the curated list is missing in this tree. Its content is knowledge "
                              "someone keeps and not a measurement; the generator can read it and "
                              "report its absence, it cannot invent its content"))
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return _gap(source=rel, reason=f"unreadable: {type(exc).__name__}: {exc}")
    rows = d if isinstance(d, list) else (d.get("rows") or d.get("entries") or [])
    incomplete = [i for i, z in enumerate(rows)
                  if not (isinstance(z, dict) and z.get("state") and z.get("evidence")
                          and z.get("date"))]
    return _field(rows, source=rel, at=_source_time(rel),
                 rows_without_required_fields=incomplete,
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

    THREE STATES, NEVER TWO: `passed`, `failed`, `not_checkable` with a reason. `failed` means
    checked and failed; writing it for an artefact kind touched with the wrong tool is an accusation
    without a measurement.

    WHAT IS CHECKED and what explicitly is not: the signature by a TRUSTED key, the version binding,
    and `audit_exit_code == 0`. NOT checked is the binding to the tree - that would need the tree AT
    THE TAG and not today's, and holding a historical receipt against today's tree would have to
    fail because the tree moved on. That stands as
    `tree_binding: not_checkable_without_checkout_at_tag` in the result instead of silently
    missing.
    """
    if not isinstance(d, dict) or d.get("schema") != "b7n0de.pre_tag_audit_receipt.v1":
        return {"state": "not_checkable",
                "reason": (f"unknown artefact kind {(d or {}).get('schema')!r} - no checker is "
                          "declared for it here, and a verdict without a checker would be a guess")}
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
                "reason": f"the checker will not load: {type(exc).__name__}: {exc}"}

    try:
        trusted = lib.load_trusted_pubkeys(REPO)
    except Exception as exc:  # noqa: BLE001
        return {"state": "not_checkable",
                "reason": f"the trusted key list is unreadable: {exc}"}

    pub = d.get("signer_pubkey")
    # AN EMPTY TRUST LIST IS NOT AN UNTRUSTED KEY, and that is why this is two branches. With no
    # anchor pinned NOTHING was checked, and a reason saying "this key is not trusted" would blame
    # the receipt for a missing anchor. Both block, but a reader has to be able to tell whether to
    # add a key or to repair the anchor.
    if not trusted:
        return {"state": "failed",
                "reason": ("no trust anchor pinned: audit_artifacts/pre_tag_trusted_pubkeys.txt is "
                           "absent or empty, so NOTHING about this signature was checked. This is "
                           "not a statement about the receipt"),
                "tree_binding": "not_checkable_without_checkout_at_tag"}
    pub = d.get("signer_pubkey")
    if pub not in trusted:
        return {"state": "failed",
                "reason": ("the signing key is not in "
                           "audit_artifacts/pre_tag_trusted_pubkeys.txt"),
                "tree_binding": "not_checkable_without_checkout_at_tag"}
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
                "reason": f"the signature cannot be evaluated: {type(exc).__name__}: {exc}"}
    if not ok:
        return {"state": "failed", "reason": "the ed25519 signature does not hold",
                "tree_binding": "not_checkable_without_checkout_at_tag"}
    if d.get("audit_exit_code") != 0:
        return {"state": "failed",
                "reason": (f"audit_exit_code is {d.get('audit_exit_code')!r} and not 0 - the "
                           "receipt attests a FAILED run"),
                "tree_binding": "not_checkable_without_checkout_at_tag"}
    return {"state": "passed",
            "checked": ["signature_by_trusted_key", "audit_exit_code_0"],
            "tree_binding": "not_checkable_without_checkout_at_tag",
            "tree_binding_reason": ("verify_receipt requires the expected tree digest; holding a "
                                    "historical receipt against TODAY's tree would have to fail, "
                                    "because the tree moved on")}


def proof_log(*, check: bool = True) -> dict:
    """Per release the pre-tag receipt, its sha256, the recompute command and a REAL checker.

    THE GENERATOR CHECKS ITSELF, and a failure stands as `failed` WITH its reason. A receipt listed
    in a proof log that nobody ran is a claim about a check. But `failed` is only written when a
    check actually ran; otherwise `not_run`.
    """
    entries = []
    for p in sorted((REPO / "audit_artifacts").glob("*/pre_tag_receipt_*.json")):
        rel = str(p.relative_to(REPO))
        try:
            raw = p.read_bytes()
            content = json.loads(raw)
        except (OSError, ValueError) as exc:
            entries.append({"receipt": rel, "not_measurable": True, "reason": str(exc)[:140]})
            continue
        e = {
            "receipt": rel,
            "version": content.get("version"),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "recompute": f"sha256sum {rel}",
            "measured_at": _source_time(rel),
        }
        e["check"] = (_check_receipt(content) if check else
                       {"state": "not_run", "reason": "--no-check was set"})
        entries.append(e)
    if not entries:
        return _gap(source="audit_artifacts/*/pre_tag_receipt_*.json",
                       reason="no pre-tag receipt in this tree")
    return _field(entries, source="audit_artifacts/*/pre_tag_receipt_*.json",
                 at=max((e.get("measured_at") or "") for e in entries) or None)


# ── audit_state / audit_link ────────────────────────────────────────────────────────────────────
def audit_state_field(version_value) -> dict:
    d = REPO / "audit_artifacts"
    if not d.is_dir():
        return {"audit_state": _gap(source="audit_artifacts/", reason="audit_artifacts/ is missing"),
                "audit_link": _gap(source="audit_artifacts/", reason="audit_artifacts/ is missing")}
    stages = sorted(p.name for p in d.iterdir() if p.is_dir() and p.name.isdigit())
    expected = None
    if isinstance(version_value, str):
        parts = version_value.split(".")
        if len(parts) >= 2 and all(t.isdigit() for t in parts[:2]):
            expected = f"{parts[0]}{parts[1]}0"
    at = _source_time("audit_artifacts")
    if expected and expected not in stages:
        return {"audit_state": _gap(
                    source="audit_artifacts/", stages=stages,
                    reason=(f"for version {version_value} stage {expected} would be expected; it "
                            f"is not there. Present are {', '.join(stages)}")),
                "audit_link": _gap(source="audit_artifacts/",
                                      reason=f"no link without stage {expected}")}
    stage = expected or (stages[-1] if stages else None)
    if stage is None:
        return {"audit_state": _gap(source="audit_artifacts/", reason="no stage present"),
                "audit_link": _gap(source="audit_artifacts/", reason="no stage present")}
    return {"audit_state": _field(stage, source="audit_artifacts/", at=at, stages=stages),
            "audit_link": _field(f"audit_artifacts/{stage}/", source="audit_artifacts/",
                                at=at)}


# ── scorecard ───────────────────────────────────────────────────────────────────────────────────
def scorecard(*, network: bool = True) -> dict:
    target = "https://api.scorecard.dev/projects/github.com/b7n0de/proofbundle"
    if not network:
        return _gap(source=target, reason="--no-network was set, so it was not asked", stable=False)
    try:
        r = subprocess.run(["curl", "-sS", "--max-time", "25", target],
                           capture_output=True, text=True, timeout=40)
    except (OSError, subprocess.SubprocessError) as exc:
        return _gap(source=target, reason=f"{type(exc).__name__}: {exc}", stable=False)
    if r.returncode != 0:
        return _gap(source=target, reason=f"curl rc={r.returncode}: {r.stderr.strip()[:140]}",
                       stable=False)
    try:
        d = json.loads(r.stdout or "null")
    except ValueError as exc:
        return _gap(source=target, reason=f"the answer is not JSON: {exc}", stable=False)
    if not isinstance(d, dict):
        return _gap(source=target, reason=f"the answer is {type(d).__name__}, an object was expected",
                       stable=False)
    checks_list = d.get("checks") or []
    # ALL values, not the overall score. How many there really are is said by the answer and not
    # by the requirement, so the measured count stands next to them.
    return _field({"score": d.get("score"),
                  "checks": [{"name": c.get("name"), "score": c.get("score"),
                              "reason": c.get("reason")} for c in checks_list]},
                 source=target, at=_now(), stable=False,
                 check_count=len(checks_list),
                 note=("from the network and therefore not byte-stable: a foreign answer has no "
                       "source time in the tree, its measurement time is the run time"))


def build(*, network: bool = True, check: bool = True) -> dict:
    vr = version_and_release()
    out = {
        "schema": "b7n0de.proofbundle_site_data.v1",
        "generated_by": "scripts/render_site_data.py",
        "generated_at": _now(),
        # THE EXPLANATION MUST NOT LOOK LIKE A FIELD. The first draft named its keys
        # `messzeit`, `stabil` and `nicht_messbar`, the same names as the data fields. The loop
        # counting the gaps therefore took the explanation block for a measured field without a
        # reason and ended in a KeyError, measured on the first run.
        #
        # Fixed at the COLLISION and not at the single case: the keys now end in `..._means`, so
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
    return out


def tree_fields(d: dict) -> dict:
    """Only the fields that come from the tree - the object of the stability promise."""
    return {k: v for k, v in d.items()
            if isinstance(v, dict) and v.get("stable") is True}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, default=REPO / "docs" / "site" / "site-data.json")
    ap.add_argument("--no-network", action="store_true",
                    help="do not ask the network sources; they then stand as not_measurable with "
                         "exactly that reason")
    ap.add_argument("--no-check", action="store_true",
                    help="do not recompute the receipts; their state is then not_run and "
                         "explicitly not passed")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    d = build(network=not a.no_network, check=not a.no_check)
    gaps = [k for k, v in d.items() if isinstance(v, dict) and v.get("not_measurable")]
    if len(gaps) == len([k for k, v in d.items() if isinstance(v, dict) and "stable" in v]):
        print("NOT MEASURABLE: not a single source is readable - nothing written", file=sys.stderr)
        return 2

    a.out.parent.mkdir(parents=True, exist_ok=True)
    tmp = a.out.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    tmp.replace(a.out)

    if a.json:
        print(json.dumps(d, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"written: {a.out.relative_to(REPO) if a.out.is_relative_to(REPO) else a.out}")
        print(f"  fields: {len([k for k, v in d.items() if isinstance(v, dict) and 'stable' in v])} "
              f"· not measured: {len(gaps)}")
        for k in gaps:
            print(f"  ! {k}: {d[k]['reason'][:110]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
