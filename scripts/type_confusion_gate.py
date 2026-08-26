#!/usr/bin/env python3
"""Fundament F4 — property-based JSON type-confusion matrix over the AST-discovered verify_* set.

The 3.6.0 acceptance "every public verifier survives the type-confusion matrix without a raw
exception" was going to be a STATIC list — one that silently rots the moment a new verifier
(relation-statement, 3.5.0) is added and nobody remembers to append it. Front-Loading builds the
generator ONCE so the property is STRUCTURAL, not point-wise:

  1. Re-use the SAME AST ground-truth inventory the Rust-parity gate holds itself to
     (``rust_parity_gate.discover_python_verify_functions``) — every module-level ``def verify_*``,
     re-discovered fresh each run, nothing hand-copied.

  2. Classify each by INTROSPECTION, not a hand list:
       * JSON-object primary (dict / Union[dict,str] / Any / list / a json-shaped param name)
         -> IN SCOPE for the JSON type-confusion matrix.
       * bytes / compact-string / file-path / int primary -> a DIFFERENT parser class
         (covered by the byte/string fuzz tests, tests/test_fuzz_parsers.py) -> honestly
         NON_JSON, recorded, not silently dropped.
     Extra required arguments are satisfied from a name-keyed table of BENIGN fixtures
     (``public_key`` -> a real Ed25519 pubkey, ``canonical_root`` -> 32 bytes, ...), so a new
     verifier that reuses those parameter names is covered with ZERO new config.

  3. Run the type-confusion matrix against every IN SCOPE verifier and assert the DEFINING property:
     it RETURNS or raises a ``ProofBundleError`` — never a raw, uncaught exception. A raw crash is a
     real robustness bug (a DoS / parser-differential vector), so it FAILS the gate (this axis is a
     correctness property, not advisory). The matrix has TWO passes, and the second one is the reason
     this gate reported a clean run through 3.6.0 while four surfaces were crashing:
       * WHOLE ARGUMENT — None / int / float / bool / str / list / nested dict / large / control chars.
         Catches "the verifier assumes it got a dict at all".
       * NESTED LEAF (added 2026-08-26) — a form-VALID outer object with exactly one corrupted leaf,
         list/dict/set/tuple, at AST-derived field names, at two depths. Catches "the outer shape check
         passed and an inner field validator then hashed attacker data". Pass one cannot reach this
         class at all: its payloads never survive the outer shape check.

  4. Accountability (mirrors the Rust-parity honesty gate): a new verify_* whose extra required
     args CANNOT be satisfied from the benign-fixture table is NEEDS_FIXTURE (a decision is owed,
     never silently skipped). ``--strict`` exits non-zero on any NEEDS_FIXTURE, exactly so a new
     surface cannot slip through uncovered.

CLI:
  python scripts/type_confusion_gate.py [--json] [--strict]

Exit code: non-zero if any IN SCOPE verifier RAW-crashes on a type-confused input (always), or if
``--strict`` and a NEEDS_FIXTURE surface exists. A NON_JSON classification never fails anything.
"""
from __future__ import annotations

import argparse
import ast
import base64
import importlib
import inspect
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
sys.path.insert(0, str(REPO / "scripts"))

from rust_parity_gate import discover_python_verify_functions, resolve_surface  # noqa: E402
from proofbundle.errors import ProofBundleError  # noqa: E402

# --- the type-confusion matrix: JSON-representable values in the WRONG shape for any verifier ---
_ZERO32 = bytes(32)
# Bare strings are kept SEPARATE: for a Union[dict, str] verifier (e.g. verify_bundle) a str is a
# LEGITIMATE input class (a file path / compact token), not a type confusion — a bad path raising
# OSError is correct API behaviour, not a robustness bug. String payloads are therefore only run
# against verifiers whose primary is dict/list-only.
_STR_PAYLOADS: list[object] = ["", "str", "🙈", "\x00\x01\x02", "0" * 4096]
_NONSTR_PAYLOADS: list[object] = [
    None, True, False, 0, -1, 2 ** 63, 3.14, float("nan"),
    [], [1, "a", None], [[[[]]]],
    {}, {"a": 1}, {"payload": None}, {"payload": 123}, {"payload": [], "signatures": {}},
    {"signatures": "not-a-list"}, {"predicate": None}, {"predicate": []},
    {"schemaVersion": 1}, {"schemaVersion": None},
    {"nested": {"deep": {"deeper": {"deepest": {}}}}},
    {str(i): i for i in range(64)},
    {"": ""}, {"\x00": "\x00"}, {"payload": "not-base64!!", "signatures": [{"sig": None}]},
]
TYPE_CONFUSION_PAYLOADS: list[object] = _NONSTR_PAYLOADS + _STR_PAYLOADS

# --- benign fixtures for extra required params, keyed by PARAMETER NAME (generalises across new
# verifiers that reuse the same parameter vocabulary — the point of the front-loaded generator) ---


def _benign_public_key() -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.generate().public_key().public_bytes_raw()


def _benign_fixtures() -> dict[str, object]:
    return {
        "public_key": _benign_public_key(),
        "canonical_root": _ZERO32,
        "target_roots": {},
        "root_b64": base64.b64encode(_ZERO32).decode(),
        "n": 1,
        "data_digests": [],
        "policy": {},
        "frozen": {},
    }


# A json-object-shaped primary param even when the annotation is missing/ambiguous, recognised by
# name (kept small and explicit — an unknown name falls through to annotation-based classification).
_JSON_PRIMARY_NAMES = {
    "bundle", "envelope", "pack", "entry", "anchor", "anchors", "opening", "sequence",
    "relationships", "proof_obj", "predicate", "statement", "receipt",
}


def _deferral_targets(module: str, fname: str) -> list[str]:
    """Tests under ``tests/`` that actually REFERENCE this surface — the only valid basis for a deferral.

    Resolved against the tree instead of asserted, because the asserted form was wrong: the note cited
    tests/test_fuzz_parsers.py for every non-JSON primary, and that file mentions neither evalcard nor
    prereg. A citation nobody resolves is indistinguishable from real coverage.
    """
    import pathlib as _pl  # noqa: PLC0415

    tests = _pl.Path(__file__).resolve().parents[1] / "tests"
    if not tests.is_dir():
        return []
    treffer = []
    for f in sorted(tests.glob("test_*.py")):
        try:
            quelle = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        # BEIDES muss vorkommen: der Funktionsname UND das Modul. Die erste Fassung liess
        # `"proofbundle" in quelle` als Ersatz zu — das trifft fast jede Testdatei, und damit meldete
        # die Pruefung fuer alle 26 Flaechen eine belegte Deckung. Eine Aufloesung, die immer faendig
        # wird, ist keine Aufloesung; sie ist die Behauptung in Prueferform.
        # Der letzte Modul-Abschnitt und der reine Funktionsname: seit die Population Unterpakete und
        # Klassenmethoden kennt, kommen hier `experimental.enclave` und `Klasse.methode` an, und die
        # stehen so in keiner Testdatei. Wer den vollen Punktnamen suchte, faende NIE etwas — und eine
        # Suche, die nie faendig wird, meldet fuer jede Flaeche eine unbelegte Deckung.
        kurz_modul = module.rsplit(".", 1)[-1]
        kurz_fn = fname.rsplit(".", 1)[-1]
        if kurz_fn in quelle and kurz_modul in quelle:
            treffer.append(f"tests/{f.name}")
    return treffer


def _is_json_primary(param: inspect.Parameter) -> bool:
    """Is the primary (attacker-controlled parsed) argument a JSON OBJECT/array, i.e. in scope for
    the JSON type-confusion matrix?  bytes / compact-str / path / int primaries are a different
    parser class and out of scope here."""
    ann = param.annotation
    if ann is not inspect.Parameter.empty:
        # Resolve string annotations best-effort via typing.get_type_hints-style text match.
        text = str(ann)
        if "bytes" in text or text == "int" or "float" in text:
            return False
        if "dict" in text or "Dict" in text or "Mapping" in text or "list" in text or \
           "List" in text or "Any" in text or "Union[dict" in text:
            return True
        if ann is str or text == "str":
            return False
    return param.name in _JSON_PRIMARY_NAMES


def _classify(qname: str, info: dict | None = None) -> dict:
    # NOT `qname.split(".")[1]`/`[2]` any more. That two-segment assumption silently mis-resolved every
    # subpackage module and every class method — i.e. exactly the surfaces the population was widened to
    # include on 2026-08-26 — and turned them into IMPORT_ERROR, a status this gate counted nowhere and
    # failed on never. Resolution now lives once, next to the population (rust_parity_gate.py).
    module = (info or {}).get("module") or ".".join(qname.split(".")[1:-1])
    fname = (info or {}).get("function") or qname.split(".")[-1]
    try:
        fn = resolve_surface(qname)
        sig = inspect.signature(fn)
    except Exception as e:  # pragma: no cover - defensive
        return {"python_ref": qname, "status": "IMPORT_ERROR", "notes": str(e)}
    params = list(sig.parameters.values())
    if not params:
        return {"python_ref": qname, "status": "NON_JSON", "notes": "no positional input"}
    first = params[0]
    if not _is_json_primary(first):
        # A DEFERRAL IS ONLY WORTH THE TEST IT NAMES (deep gate wf_cfe249d0-ee8, finding L1-03, P2).
        #
        # This note said "covered by tests/test_fuzz_parsers.py" for every non-JSON primary. Measured:
        # that file mentions neither evalcard nor prereg — it names a coverage that does not exist, and a
        # named coverage reads exactly like a real one. So the deferral is now RESOLVED against the tree:
        # only a test that actually references the surface may be cited; otherwise the entry says so.
        gedeckt = _deferral_targets(module, fname)
        if gedeckt:
            hinweis = f"byte/string/path parser class — covered by {', '.join(gedeckt)}"
        else:
            hinweis = ("byte/string/path parser class — NO test in tests/ references this surface; "
                       "the deferral is unbacked and this surface is UNCOVERED here")
        return {"python_ref": qname, "status": "NON_JSON",
                "notes": f"primary {first.name!r} is not a JSON object ({hinweis})",
                "deferral_backed": bool(gedeckt)}
    fixtures = _benign_fixtures()
    extra_kwargs: dict[str, object] = {}
    unsatisfiable: list[str] = []
    for p in params[1:]:
        if p.default is not inspect.Parameter.empty or p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
            continue
        if p.name in fixtures:
            extra_kwargs[p.name] = fixtures[p.name]
        else:
            unsatisfiable.append(p.name)
    if unsatisfiable:
        return {"python_ref": qname, "status": "NEEDS_FIXTURE",
                "notes": f"extra required arg(s) {unsatisfiable} have no benign fixture — a "
                         "type-confusion coverage decision is owed"}
    # A Union[dict, str] primary legitimately accepts a str (path/token); bare strings are not a
    # type confusion for it, so they are excluded from ITS matrix (dict/list-only verifiers get them).
    union_str = "str" in str(first.annotation)
    payloads = _NONSTR_PAYLOADS if union_str else TYPE_CONFUSION_PAYLOADS
    return {"python_ref": qname, "status": "IN_SCOPE", "fn": fn, "extra_kwargs": extra_kwargs,
            "payloads": payloads, "str_excluded": union_str}


# --- NESTED-LEAF MATRIX (fix for deep-gate iteration 8, finding L3-05) -------------------------
#
# WHY THE WHOLE-ARGUMENT MATRIX IS NOT ENOUGH, measured rather than assumed: `_exercise` replaced the
# ENTIRE primary argument with the confusion value. `[]`, `0`, `None` are not dicts, so every verifier's
# OUTER shape check rejected them immediately and no INNER field validator ever ran. The gate therefore
# reported `never_raise_ok=true` while four surfaces raised raw TypeErrors on a nested value — they all
# do `x not in <set|dict>`, which HASHES x, and an unhashable leaf crashes before any typed rejection.
#
# TWO DEPTHS ARE MEASURED-NECESSARY, not precautionary. `outcome` falls at depth 1; `run_ledger` only at
# depth 2, because its membership test sits in a per-entry validator under `runs`. A fixed depth misses
# the next surface SILENTLY — the very failure mode this fix exists to remove, one level down. (The
# author of this fix hit exactly that with the first prototype.)
#
# FIELD NAMES COME FROM THE AST, never from a maintained list: a maintained list ages without a symptom,
# which is how the population above went stale for four narrowings at once.
_LEAF_CONFUSIONS: list[object] = [
    [], [1],            # list
    {}, {"a": 1},       # dict
    set(), {1, 2},      # set        — unhashable, the class that produced all four P1 findings
    (), (1, 2),         # tuple      — hashable, so it passes a membership test and confuses LATER
]
_FIELD_CACHE: dict[str, list[str]] = {}
# A pathological module must not be able to blow the runtime up, so there is a budget — but it caps the
# PRODUCT and truncates by an even STRIDE, never by a sorted prefix.
#
# WHY THAT DISTINCTION IS THE WHOLE POINT: the first version of this fix capped at `sorted(fields)[:40]`.
# That silently dropped everything alphabetically after `predicate_type_ok` — including `status`, which
# is the single field all four of the findings this fix exists for crash on. A sorted prefix is not a
# sample; it is a systematic bias toward the start of the alphabet, and it reproduced the exact defect
# class (a surface excluded without a symptom) one level below the one being fixed.
#
# Measured on the real tree: 341712 payloads across 30 in-scope surfaces in 5.6s. The budget does not
# bite today (largest single surface ~38.6k) and exists only as a guard against future growth.
_MAX_NESTED_PER_SURFACE = 100_000


def _field_names(fn) -> list[str]:
    """Every string the module ``fn`` lives in uses as a dict key: ``.get("x")``, ``obj["x"]``, ``"x" in obj``.

    Read out of the AST, never from a maintained list — a maintained list ages without a symptom, which
    is how the population above went stale for four narrowings at once.
    A module whose source cannot be read yields []: less coverage, never a false result."""
    mod = getattr(fn, "__module__", "") or ""
    if mod in _FIELD_CACHE:
        return _FIELD_CACHE[mod]
    # `mod == "proofbundle" or mod.startswith("proofbundle.")`, NOT `startswith("proofbundle")`:
    # a bare prefix also matches `proofbundle_something_else`. Substring-instead-of-token is the exact
    # bug class this release already paid for once (`"import decode_b64" in text` matched
    # `import decode_b64url` and skipped a genuinely missing import — 133 tests went red).
    if not (mod == "proofbundle" or mod.startswith("proofbundle.")):
        return []
    try:
        baum = ast.parse(Path(importlib.import_module(mod).__file__).read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - an unreadable source means less coverage, never an error
        _FIELD_CACHE[mod] = []
        return []
    felder: set[str] = set()
    for k in ast.walk(baum):
        if (isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute) and k.func.attr == "get"
                and k.args and isinstance(k.args[0], ast.Constant)
                and isinstance(k.args[0].value, str)):
            felder.add(k.args[0].value)
        elif (isinstance(k, ast.Subscript) and isinstance(k.slice, ast.Constant)
                and isinstance(k.slice.value, str)):
            felder.add(k.slice.value)
        elif (isinstance(k, ast.Compare) and isinstance(k.left, ast.Constant)
                and isinstance(k.left.value, str) and any(isinstance(o, ast.In) for o in k.ops)):
            felder.add(k.left.value)
    _FIELD_CACHE[mod] = sorted(felder)
    return _FIELD_CACHE[mod]


def _nested_payloads(fn) -> tuple[list[tuple[object, str]], bool]:
    """([(payload, path)], truncated?) — form-valid dicts with EXACTLY ONE corrupted leaf.

    EVERY field is also a CONTAINER candidate, deliberately. The precise version tried to detect
    containers syntactically (``for … in obj.get("x")``) and missed ``run_ledger``, which writes
    ``runs = predicate.get("runs")`` and then ``for i, run in enumerate(runs)`` — a matched FORM instead
    of a matched ROLE, the same mistake as matching a name prefix instead of a security role. Here the
    asymmetry is decisive: over-inclusion only costs payloads that get rejected normally, while
    under-inclusion is the defect itself. Being generous is measured cheap (5.6s) and strictly finds
    more — the generous form is what surfaced verification_summary, which the precise form missed."""
    felder = _field_names(fn)
    aus: list[tuple[object, str]] = []
    for wert in _LEAF_CONFUSIONS:
        for f in felder:
            aus.append(({f: wert}, f))
            for b in felder:
                aus.append(({b: [{f: wert}]}, f"{b}[0].{f}"))
    if len(aus) <= _MAX_NESTED_PER_SURFACE:
        return aus, False
    schritt = len(aus) // _MAX_NESTED_PER_SURFACE + 1
    return aus[::schritt], True


def _depth1_payloads(fn) -> list[tuple[object, str]]:
    return [({f: wert}, f) for wert in _LEAF_CONFUSIONS for f in _field_names(fn)]


def _depth2_payloads(fn, skip_container: set) -> tuple[list[tuple[object, str]], bool]:
    """Depth-2 payloads, SKIPPING containers already proven broken at depth 1.

    If ``{"status": []}`` already crashes, then ``{"status": [{anything: []}]}`` crashes for the exact
    same reason — the container itself is the unhashable value. Emitting both turns one defect into 69
    identical-looking violations and buries the real signal (outcome alone produced 556). What is
    reported must be the MINIMAL witness, or the gate's own output becomes the next thing nobody reads."""
    felder = _field_names(fn)
    behaelter = [b for b in felder if b not in skip_container]
    aus = [({b: [{f: wert}]}, f"{b}[0].{f}")
           for wert in _LEAF_CONFUSIONS for f in felder for b in behaelter]
    if len(aus) <= _MAX_NESTED_PER_SURFACE:
        return aus, False
    schritt = len(aus) // _MAX_NESTED_PER_SURFACE + 1
    return aus[::schritt], True


def _exercise(fn, extra_kwargs: dict, payloads: list[object]) -> list[str]:
    """Run the matrix against one verifier; return the list of RAW-crash violations."""
    violations: list[str] = []
    for payload in payloads:
        try:
            fn(payload, **extra_kwargs)
        except ProofBundleError:
            pass  # a typed rejection is the correct, defended behaviour
        except (KeyboardInterrupt, SystemExit):
            raise
        except RecursionError:
            # A verifier walking attacker-nested JSON may hit the interpreter limit; that is a raw
            # crash class and MUST be defended (bounded depth) — count it as a violation.
            violations.append(f"RecursionError on payload {_short(payload)}")
        except Exception as e:  # noqa: BLE001 - the whole point is to catch the raw class
            violations.append(f"{type(e).__name__} on payload {_short(payload)}: {e}")
    return violations


def _run_leaf_payloads(fn, extra_kwargs: dict, nutzlasten) -> tuple[list[str], set]:
    """(violations, fields that crashed) for one batch of leaf payloads."""
    violations: list[str] = []
    kaputt: set = set()
    for nutzlast, pfad in nutzlasten:
        try:
            fn(nutzlast, **extra_kwargs)
        except ProofBundleError:
            pass  # a typed rejection is the correct, defended behaviour
        except (KeyboardInterrupt, SystemExit):
            raise
        except RecursionError:
            violations.append(f"RecursionError on nested leaf {pfad}")
            kaputt.add(pfad)
        except TypeError as e:
            # A TypeError from the CALL ITSELF (wrong signature) is a finding about the PROBE, not
            # about the surface. The distinction lives in the message, not in the type — skipping it
            # produced 252 non-findings during this fix's own preparatory work.
            if any(m in str(e) for m in ("argument", "positional", "keyword")):
                break
            violations.append(f"TypeError on nested leaf {pfad}: {e}")
            kaputt.add(pfad)
        except Exception as e:  # noqa: BLE001
            violations.append(f"{type(e).__name__} on nested leaf {pfad}: {e}")
            kaputt.add(pfad)
    return violations, kaputt


def _exercise_nested(fn, extra_kwargs: dict) -> tuple[list[str], int, bool]:
    """Second pass: a form-VALID outer object with one corrupted leaf inside (see the block above).

    Depth 1 first, then depth 2 only through containers depth 1 did NOT already break — so what the
    gate reports is the minimal witness for each defect, not the same defect once per sibling field."""
    d1 = _depth1_payloads(fn)
    v1, kaputt = _run_leaf_payloads(fn, extra_kwargs, d1)
    d2, gekuerzt = _depth2_payloads(fn, kaputt)
    v2, _ = _run_leaf_payloads(fn, extra_kwargs, d2)
    return v1 + v2, len(d1) + len(d2), gekuerzt


def _short(payload: object) -> str:
    s = repr(payload)
    return s if len(s) <= 60 else s[:57] + "..."


def evaluate() -> dict:
    ground_truth = discover_python_verify_functions()
    items: list[dict] = []
    in_scope = non_json = needs_fixture = import_error = 0
    violations: list[dict] = []
    for qname in sorted(ground_truth):
        info = _classify(qname, ground_truth.get(qname))
        status = info["status"]
        if status == "IN_SCOPE":
            in_scope += 1
            viol = _exercise(info["fn"], info["extra_kwargs"], info["payloads"])
            nested, n_nested, gekuerzt = _exercise_nested(info["fn"], info["extra_kwargs"])
            viol = viol + nested
            rec = {"python_ref": qname, "status": "IN_SCOPE",
                   "matrix_size": len(info["payloads"]), "str_excluded": info["str_excluded"],
                   "nested_matrix_size": n_nested, "nested_truncated": gekuerzt,
                   "violations": viol}
            if viol:
                violations.append({"python_ref": qname, "violations": viol})
            items.append(rec)
        elif status == "NON_JSON":
            non_json += 1
            items.append(info)
        elif status == "NEEDS_FIXTURE":
            needs_fixture += 1
            items.append(info)
        else:
            # IMPORT_ERROR used to land here uncounted and un-failable: a surface the gate could not
            # even resolve looked exactly like a surface it had cleared. That is the same vacuity the
            # population fix removed, one layer up, so it is now counted and --strict-failing.
            if status == "IMPORT_ERROR":
                import_error += 1
            items.append(info)
    return {
        "schema": "proofbundle.type_confusion_gate.v1",
        "total_verify_surfaces": len(ground_truth),
        "in_scope": in_scope,
        "non_json": non_json,
        "needs_fixture": needs_fixture,
        "import_error": import_error,
        "matrix_size": len(TYPE_CONFUSION_PAYLOADS),
        "never_raise_ok": not violations,
        "violations": violations,
        "items": items,
    }


def _format_human(result: dict) -> str:
    lines = [
        f"[type-confusion] {result['total_verify_surfaces']} verify_* surface(s): "
        f"{result['in_scope']} IN SCOPE (× {result['matrix_size']} payloads), "
        f"{result['non_json']} NON_JSON (byte/string parser class), "
        f"{result['needs_fixture']} NEEDS_FIXTURE, "
        f"{result.get('import_error', 0)} IMPORT_ERROR",
        f"  never_raise_ok={result['never_raise_ok']}",
    ]
    for item in result["items"]:
        if item["status"] in ("NEEDS_FIXTURE", "IMPORT_ERROR"):
            lines.append(f"  {item['status']} {item['python_ref']} — {item['notes']}")
        elif item["status"] == "IN_SCOPE" and item.get("violations"):
            for v in item["violations"]:
                lines.append(f"  VIOLATION {item['python_ref']}: {v}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--json", action="store_true")
    p.add_argument("--strict", action="store_true",
                   help="also exit non-zero if a NEEDS_FIXTURE surface exists (a coverage decision "
                        "is owed for a new verifier)")
    args = p.parse_args(argv)
    result = evaluate()
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str) if args.json
          else _format_human(result))
    if not result["never_raise_ok"]:
        return 1
    if args.strict and (result["needs_fixture"] or result.get("import_error")):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
