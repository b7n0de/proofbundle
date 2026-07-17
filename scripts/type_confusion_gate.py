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

  3. Run the type-confusion matrix (None / int / float / bool / str / list / nested dict /
     wrong-typed fields / deeply nested / large / control chars) against every IN SCOPE verifier
     and assert the DEFINING property: it RETURNS or raises a ``ProofBundleError`` — never a raw,
     uncaught exception. A raw crash is a real robustness bug (a DoS / parser-differential vector),
     so it FAILS the gate (this axis is a correctness property, not advisory).

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

from rust_parity_gate import discover_python_verify_functions  # noqa: E402
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


def _classify(qname: str) -> dict:
    module = qname.split(".")[1]
    fname = qname.split(".")[2]
    try:
        mod = importlib.import_module(f"proofbundle.{module}")
        fn = getattr(mod, fname)
        sig = inspect.signature(fn)
    except Exception as e:  # pragma: no cover - defensive
        return {"python_ref": qname, "status": "IMPORT_ERROR", "notes": str(e)}
    params = list(sig.parameters.values())
    if not params:
        return {"python_ref": qname, "status": "NON_JSON", "notes": "no positional input"}
    first = params[0]
    if not _is_json_primary(first):
        return {"python_ref": qname, "status": "NON_JSON",
                "notes": f"primary {first.name!r} is not a JSON object (byte/string/path parser "
                         "class — covered by tests/test_fuzz_parsers.py)"}
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


def _short(payload: object) -> str:
    s = repr(payload)
    return s if len(s) <= 60 else s[:57] + "..."


def evaluate() -> dict:
    ground_truth = discover_python_verify_functions()
    items: list[dict] = []
    in_scope = non_json = needs_fixture = 0
    violations: list[dict] = []
    for qname in sorted(ground_truth):
        info = _classify(qname)
        status = info["status"]
        if status == "IN_SCOPE":
            in_scope += 1
            viol = _exercise(info["fn"], info["extra_kwargs"], info["payloads"])
            rec = {"python_ref": qname, "status": "IN_SCOPE",
                   "matrix_size": len(info["payloads"]), "str_excluded": info["str_excluded"],
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
            items.append(info)
    return {
        "schema": "proofbundle.type_confusion_gate.v1",
        "total_verify_surfaces": len(ground_truth),
        "in_scope": in_scope,
        "non_json": non_json,
        "needs_fixture": needs_fixture,
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
        f"{result['needs_fixture']} NEEDS_FIXTURE",
        f"  never_raise_ok={result['never_raise_ok']}",
    ]
    for item in result["items"]:
        if item["status"] == "NEEDS_FIXTURE":
            lines.append(f"  NEEDS_FIXTURE {item['python_ref']} — {item['notes']}")
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
    if args.strict and result["needs_fixture"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
