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
         -> IN_SCOPE for the JSON type-confusion matrix (whole-argument + nested-leaf + a string matrix
         for a Union[dict,str] primary — F5, strings are no longer excluded).
       * bytes / compact-string / file-path / int primary -> NON_JSON, and NOW EXERCISED with a
         type-appropriate never-raise matrix (makellose-500 Phase 2, reviewer F3): the previous
         "covered by tests/test_fuzz_parsers.py" was a comment, not a run, and 27 of 57 surfaces went
         untested. A NON_JSON surface must give a VERDICT or a typed ProofBundleError on any malformed
         primary, whatever its declared type — a raw OSError/TypeError is a bug, not "correct API".
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

Exit code: FAIL-CLOSED by default (makellose-500 / reviewer F1). Non-zero if ANY surface (IN_SCOPE or
NON_JSON) raw-crashes, OR the population is not complete — that is: an empty population, a surface left
un-evaluated (NEEDS_FIXTURE / IMPORT_ERROR), a source file the AST cannot parse (a vanished surface), or
a disagreement between the two independent inventories (AST vs runtime introspection). ``--strict`` is
retained but is no longer the only thing that reddens an unmeasured surface. The gate binds its verdict
to ``subject_tree_digest`` + ``gate_source_digest`` + ``inventory_source_digests`` in its receipt.
"""
from __future__ import annotations

import argparse
import ast
import base64
import copy
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
    pub = _benign_public_key()
    b64pub = base64.b64encode(pub).decode()
    return {
        "public_key": pub,
        "canonical_root": _ZERO32,
        "target_roots": {},
        "root_b64": base64.b64encode(_ZERO32).decode(),
        "n": 1,
        "data_digests": [],
        "policy": {},
        "frozen": {},
        # makellose-500 Phase 2: benign extras for the 17 NON_JSON verify surfaces, so they can be
        # EXERCISED instead of counted-and-skipped. Each is a type-valid value that lets the call reach
        # the FUZZED primary; an invalid value is fine because the never-raise property is about the
        # primary, and an early typed rejection is a verdict, not a crash. A new verifier reusing any of
        # these parameter names is covered with zero new config (the front-loaded-generator discipline).
        "message": b"benign message", "signature": b"\x00" * 64, "salt": b"benign-salt",
        "commitment": "", "expected_binding": "", "expected_uri": "",
        "verifier_pubkey": pub, "issuer_pubkey": pub, "pq_pub": pub,
        "first_root": _ZERO32, "second_root": _ZERO32, "expected_root": _ZERO32,
        "classical_sig": b"\x00" * 64, "pq_sig": b"\x00" * 64, "leaf_data": b"leaf",
        "second_size": 1, "leaf_index": 0, "tree_size": 1, "index": 0,
        "claim": {}, "digests": {}, "proof": [], "witness_vkeys": [],
        "log_vkey": b64pub, "vkey_str": b64pub, "witness_vkey": b64pub,
    }


# A json-object-shaped primary param even when the annotation is missing/ambiguous, recognised by
# name (kept small and explicit — an unknown name falls through to annotation-based classification).
_JSON_PRIMARY_NAMES = {
    "bundle", "envelope", "pack", "entry", "anchor", "anchors", "opening", "sequence",
    "relationships", "proof_obj", "predicate", "statement", "receipt",
}

# --- NON_JSON never-raise matrices (makellose-500 Phase 2, reviewer F3/F5) --------------------------
#
# WARUM DAS HIER STEHT: der Gegenleser mass, dass 27 von 57 Flaechen als NON_JSON klassifiziert und
# danach GAR NICHT geuebt wurden — die Delegation an tests/test_fuzz_parsers.py war ein Kommentar, kein
# Lauf (P3/P4). Und fuer eine Union[dict,str]-Flaeche schloss der Gate alle String-Nutzlasten aus und
# nannte einen rohen OSError auf einem schlechten Pfad "korrektes API-Verhalten" (P10/F5). Beide sind
# Loecher im never-raise-Instrument: eine oeffentliche Verify-Flaeche muss fuer JEDE fehlerhafte
# Primaereingabe — egal welchen deklarierten Typs — ein VERDIKT oder einen typisierten ProofBundleError
# liefern, nie eine rohe Ausnahme. Jeder NON_JSON-Primaer bekommt darum jetzt eine typ-passende
# never-raise-Matrix, die WIRKLICH laeuft. Hausstandard, nicht der externe Vorschlag: ein roher OSError
# ist ein Fehler, keine korrekte API-Antwort.
_BYTES_PAYLOADS: list[object] = [
    b"", b"\x00", b"\xff" * 64, b"not a real proof at all", bytes(range(256)),
    None, 0, 123, "a string where bytes are due", [], {}, [1, 2], {"a": 1}, True, 3.14,
    b"\x00" * (1 << 20),  # 1 MiB — a pre-decode size guard must fail typed, never raw-crash
]
_COMPACT_STR_PAYLOADS: list[object] = [
    "", "x", "a.b.c", "~!@#$%^&*", "🙈", "\x00\x01\x02", "not.base64url~", "a" * 100_000,
    None, 0, 123, b"bytes where str is due", [], {}, {"a": 1}, True, 3.14,
]
_PATH_PAYLOADS: list[object] = [
    "/nonexistent/proof/path/xyz", "", ".", "/dev/null", "\x00badpath",
    None, 0, 123, [], {}, True,
]
_INT_PAYLOADS: list[object] = [None, "str", [], {}, {"a": 1}, True, 3.14, 2 ** 64, -1, float("nan")]


def _primary_kind(param: inspect.Parameter) -> str:
    """The parser class of a NON_JSON primary: ``bytes`` | ``compact_str`` | ``path`` | ``int`` | ``other``.

    Drives which never-raise matrix a surface gets. ``other`` (an unannotated, unnamed primary) gets the
    union of the byte and compact-string matrices — more coverage, never less."""
    text = str(param.annotation)
    name = param.name.lower()
    if "bytes" in text:
        return "bytes"
    if param.annotation is int or text == "int":
        return "int"
    if any(k in name for k in ("path", "file", "dir")) or "Path" in text:
        return "path"
    if param.annotation is str or text == "str" or "str" in text:
        return "compact_str"
    return "other"


def _nonjson_payloads(kind: str) -> list[object]:
    return {
        "bytes": _BYTES_PAYLOADS,
        "compact_str": _COMPACT_STR_PAYLOADS,
        "path": _PATH_PAYLOADS,
        "int": _INT_PAYLOADS,
    }.get(kind, _BYTES_PAYLOADS + _COMPACT_STR_PAYLOADS)


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
    try:
        fn = resolve_surface(qname)
        sig = inspect.signature(fn)
    except Exception as e:  # pragma: no cover - defensive
        return {"python_ref": qname, "status": "IMPORT_ERROR", "notes": str(e)}
    params = list(sig.parameters.values())
    if not params:
        return {"python_ref": qname, "status": "NON_JSON", "notes": "no positional input", "no_input": True}
    first = params[0]
    # Extra required args are resolved for BOTH the JSON and the NON_JSON path now. The old code resolved
    # them only on the JSON branch and returned NON_JSON early — which is exactly why 27 surfaces were
    # counted and never exercised. A NON_JSON surface whose extra args cannot be satisfied owes the same
    # NEEDS_FIXTURE decision as a JSON one.
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
                         "never-raise coverage decision is owed"}
    if _is_json_primary(first):
        union_str = "str" in str(first.annotation)
        # F5 CLOSED: a Union[dict,str] primary is no longer given a pass on strings. The dict/list
        # confusion set runs as the JSON matrix; the string class runs as its OWN never-raise matrix
        # (``str_matrix``) — a raw crash on a string input is a robustness bug on a public verify surface,
        # NOT "correct API behaviour" (Hausstandard over the external note). Nothing is excluded any more.
        return {"python_ref": qname, "status": "IN_SCOPE", "fn": fn, "extra_kwargs": extra_kwargs,
                "primary_name": first.name, "primary_kwonly": first.kind == inspect.Parameter.KEYWORD_ONLY,
                "payloads": _NONSTR_PAYLOADS if union_str else TYPE_CONFUSION_PAYLOADS,
                "str_matrix": _COMPACT_STR_PAYLOADS if union_str else [],
                "str_excluded": False}
    # F3 CLOSED: a NON_JSON primary is now EXERCISED with a type-appropriate never-raise matrix, run for
    # real — no more delegation-by-comment to a test that may not even reference the surface. The
    # ``_deferral_targets`` mechanism is gone: a surface is either covered by an executed matrix here, or
    # it is NEEDS_FIXTURE; a comment can no longer stand in for a run.
    kind = _primary_kind(first)
    return {"python_ref": qname, "status": "NON_JSON", "fn": fn, "extra_kwargs": extra_kwargs,
            "primary_name": first.name, "primary_kwonly": first.kind == inspect.Parameter.KEYWORD_ONLY,
            "primary_kind": kind, "payloads": _nonjson_payloads(kind),
            "notes": f"primary {first.name!r} parser class = {kind}; exercised with a {kind} never-raise matrix"}


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


def _call(fn, payload, primary_name: str, kwonly: bool, extra_kwargs: dict) -> None:
    """Invoke the verifier with a fresh deep copy, passing the primary positionally OR by keyword —
    a keyword-only primary (e.g. verify_hybrid's ``classical_pub``) must not be handed positionally,
    which would raise a signature TypeError that is a PROBE error, not a surface finding."""
    p = copy.deepcopy(payload)
    e = copy.deepcopy(extra_kwargs)
    if kwonly:
        fn(**{primary_name: p}, **e)
    else:
        fn(p, **e)


def _is_signature_error(exc: Exception) -> bool:
    """A TypeError from the CALL SIGNATURE (wrong arity / keyword) is about the PROBE, not the surface."""
    return isinstance(exc, TypeError) and any(
        m in str(exc) for m in ("positional argument", "keyword argument", "keyword-only",
                                 "required argument", "unexpected keyword", "takes"))


def _exercise(fn, extra_kwargs: dict, payloads: list[object], primary_name: str = "",
              primary_kwonly: bool = False) -> tuple[list[str], int]:
    """Run the matrix against one verifier; return (RAW-crash violations, count that RETURNED a verdict).

    The second value is the positive-control signal at surface granularity: a surface that returned at
    least once (a verdict, even ok=False) is not a constant typed-reject. The AUTHORITATIVE positive
    control stays the harness clean-tree run (a valid input must PASS), but this cheap per-surface count
    surfaces a guard that only ever rejects."""
    violations: list[str] = []
    returned = 0
    for payload in payloads:
        try:
            # F4 CLOSED: a fresh deep copy per call (inside _call), so a verifier that mutates its input
            # cannot corrupt the shared payload/fixtures and mask a LATER verifier's raw crash (P9).
            _call(fn, payload, primary_name, primary_kwonly, extra_kwargs)
            returned += 1
        except ProofBundleError:
            pass  # a typed rejection is the correct, defended behaviour
        except (KeyboardInterrupt, SystemExit):
            raise
        except RecursionError:
            # A verifier walking attacker-nested JSON may hit the interpreter limit; that is a raw
            # crash class and MUST be defended (bounded depth) — count it as a violation.
            violations.append(f"RecursionError on payload {_short(payload)}")
        except TypeError as e:
            if _is_signature_error(e):
                # the PROBE's call shape is wrong for this surface (not a finding); the same shape will
                # fail identically for every payload, so stop rather than spam one non-finding per row.
                violations.append(f"PROBE_SIGNATURE_ERROR (not a surface finding): {e}")
                break
            violations.append(f"TypeError on payload {_short(payload)}: {e}")
        except Exception as e:  # noqa: BLE001 - the whole point is to catch the raw class
            violations.append(f"{type(e).__name__} on payload {_short(payload)}: {e}")
    return violations, returned


def _run_leaf_payloads(fn, extra_kwargs: dict, nutzlasten, primary_name: str = "",
                       primary_kwonly: bool = False) -> tuple[list[str], set]:
    """(violations, fields that crashed) for one batch of leaf payloads."""
    violations: list[str] = []
    kaputt: set = set()
    for nutzlast, pfad in nutzlasten:
        try:
            _call(fn, nutzlast, primary_name, primary_kwonly, extra_kwargs)
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


def _exercise_nested(fn, extra_kwargs: dict, primary_name: str = "",
                     primary_kwonly: bool = False) -> tuple[list[str], int, bool]:
    """Second pass: a form-VALID outer object with one corrupted leaf inside (see the block above).

    Depth 1 first, then depth 2 only through containers depth 1 did NOT already break — so what the
    gate reports is the minimal witness for each defect, not the same defect once per sibling field."""
    d1 = _depth1_payloads(fn)
    v1, kaputt = _run_leaf_payloads(fn, extra_kwargs, d1, primary_name, primary_kwonly)
    d2, gekuerzt = _depth2_payloads(fn, kaputt)
    v2, _ = _run_leaf_payloads(fn, extra_kwargs, d2, primary_name, primary_kwonly)
    return v1 + v2, len(d1) + len(d2), gekuerzt


def _short(payload: object) -> str:
    s = repr(payload)
    return s if len(s) <= 60 else s[:57] + "..."


def _parse_skips() -> list[str]:
    """Source .py files under src/ the AST discovery CANNOT parse. discover_python_verify_functions
    silently skips a SyntaxError/OSError file (rust_parity_gate.py:124), so its verify_* VANISH with no
    symptom (reviewer F1). Any unparseable file is a coverage gap: the gate fails, it does not skip."""
    skips: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        try:
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (SyntaxError, OSError) as e:
            skips.append(f"{path.relative_to(SRC)}: {type(e).__name__}: {e}")
    return skips


def _runtime_inventory() -> tuple[set[str], list[str]]:
    """A SECOND, independent inventory of public verify_*/validate_* surfaces via RUNTIME introspection
    (import + dir scan of every submodule + class). The reviewer requires two independent inventories with
    equality enforced, so the AST inventory cannot silently disagree with what actually imports. Returns
    (qualified_names, import_errors)."""
    import pkgutil  # noqa: PLC0415
    names: set[str] = set()
    errors: list[str] = []
    try:
        import proofbundle  # noqa: PLC0415
    except Exception as e:  # noqa: BLE001
        return set(), [f"proofbundle: {type(e).__name__}: {e}"]
    mods = [proofbundle]
    for m in pkgutil.walk_packages(proofbundle.__path__, "proofbundle."):
        try:
            mods.append(importlib.import_module(m.name))
        except Exception as e:  # noqa: BLE001
            errors.append(f"{m.name}: {type(e).__name__}")
    for mod in mods:
        mn = mod.__name__
        for a in dir(mod):
            obj = getattr(mod, a, None)
            if isinstance(obj, type) and getattr(obj, "__module__", "") == mn:
                for m2 in dir(obj):
                    if m2.startswith(("verify_", "validate_")) and callable(getattr(obj, m2, None)):
                        names.add(f"{mn}.{a}.{m2}")
            elif callable(obj) and (a.startswith("verify_") or a.startswith("validate_")) \
                    and getattr(obj, "__module__", "") == mn:
                names.add(f"{mn}.{a}")
    return names, errors


def _inv_digest(names) -> str:
    import hashlib  # noqa: PLC0415
    return hashlib.sha256("\n".join(sorted(names)).encode()).hexdigest()


def _tree_digest() -> str:
    """The git tree digest of the subject the gate ran against — binds every receipt to a subject."""
    import subprocess  # noqa: PLC0415
    try:
        r = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD^{tree}"],
                           capture_output=True, text=True, timeout=10)
        return r.stdout.strip() or "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"


def _sha256_file(path: Path) -> str:
    import hashlib  # noqa: PLC0415
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return "unreadable"


def evaluate() -> dict:
    ground_truth = discover_python_verify_functions()
    population_size = len(ground_truth)
    ast_inv = set(ground_truth)
    runtime_inv, runtime_import_errors = _runtime_inventory()
    parse_skips = _parse_skips()
    only_ast = sorted(ast_inv - runtime_inv)
    only_runtime = sorted(runtime_inv - ast_inv)
    inventories_agree = not only_ast and not only_runtime and not runtime_import_errors
    items: list[dict] = []
    in_scope = non_json = needs_fixture = import_error = no_input = 0
    evaluated = 0
    mutation_cases = 0
    positive_controls = 0
    violations: list[dict] = []
    for qname in sorted(ground_truth):
        info = _classify(qname, ground_truth.get(qname))
        status = info["status"]
        if status == "IN_SCOPE":
            in_scope += 1
            evaluated += 1
            viol, ret_a = _exercise(info["fn"], info["extra_kwargs"], info["payloads"], info["primary_name"], info["primary_kwonly"])
            str_matrix = info.get("str_matrix") or []
            str_viol, ret_s = _exercise(info["fn"], info["extra_kwargs"], str_matrix, info["primary_name"], info["primary_kwonly"]) if str_matrix else ([], 0)
            nested, n_nested, gekuerzt = _exercise_nested(info["fn"], info["extra_kwargs"], info["primary_name"], info["primary_kwonly"])
            viol = viol + str_viol + nested
            mutation_cases += len(info["payloads"]) + len(str_matrix) + n_nested
            if ret_a + ret_s > 0:
                positive_controls += 1
            rec = {"python_ref": qname, "status": "IN_SCOPE",
                   "matrix_size": len(info["payloads"]), "str_matrix_size": len(str_matrix),
                   "nested_matrix_size": n_nested, "nested_truncated": gekuerzt,
                   "returned_verdict": ret_a + ret_s > 0, "violations": viol}
            if viol:
                violations.append({"python_ref": qname, "violations": viol})
            items.append(rec)
        elif status == "NON_JSON" and "fn" in info:
            # F3 CLOSED: NON_JSON surfaces are now EXERCISED with a type-appropriate never-raise matrix.
            non_json += 1
            evaluated += 1
            viol, ret = _exercise(info["fn"], info["extra_kwargs"], info["payloads"], info["primary_name"], info["primary_kwonly"])
            mutation_cases += len(info["payloads"])
            if ret > 0:
                positive_controls += 1
            rec = {"python_ref": qname, "status": "NON_JSON", "primary_kind": info["primary_kind"],
                   "matrix_size": len(info["payloads"]), "returned_verdict": ret > 0,
                   "notes": info["notes"], "violations": viol}
            if viol:
                violations.append({"python_ref": qname, "violations": viol})
            items.append(rec)
        elif status == "NON_JSON":
            # a surface with no positional input at all — nothing to fuzz, honestly unevaluated
            no_input += 1
            items.append({"python_ref": qname, "status": "NON_JSON", "notes": info.get("notes", "no input")})
        elif status == "NEEDS_FIXTURE":
            needs_fixture += 1
            items.append(info)
        else:
            if status == "IMPORT_ERROR":
                import_error += 1
            items.append(info)
    unresolved = needs_fixture + import_error + no_input
    # F1 CLOSED: the population must be non-empty AND every surface must be EVALUATED. An empty population,
    # an IMPORT_ERROR, or an un-fixturable surface leaves evaluated_count < population_size and is a
    # coverage gap, not a clean run — fail-closed, never a vacuous green.
    # F1 CLOSED, fully: complete requires a non-empty population, EVERY surface evaluated, no import
    # error, NO unparseable source file (a vanished surface), and the two independent inventories AGREE.
    population_complete = (population_size > 0 and evaluated == population_size and import_error == 0
                           and not parse_skips and inventories_agree)
    raw_exception_count = sum(len(v["violations"]) for v in violations)
    return {
        "schema": "proofbundle.type_confusion_gate.v2",
        "subject_tree_digest": _tree_digest(),
        "gate_source_digest": _sha256_file(Path(__file__).resolve()),
        "inventory_source_digests": {"ast": _inv_digest(ast_inv), "runtime": _inv_digest(runtime_inv)},
        "inventory_ast_count": len(ast_inv),
        "inventory_runtime_count": len(runtime_inv),
        "inventory_only_ast": only_ast,
        "inventory_only_runtime": only_runtime,
        "inventory_runtime_import_errors": runtime_import_errors,
        "inventories_agree": inventories_agree,
        "parse_skips": parse_skips,
        "total_verify_surfaces": population_size,
        "population_size": population_size,
        "evaluated_count": evaluated,
        "unresolved_count": unresolved,
        "in_scope": in_scope,
        "non_json": non_json,
        "needs_fixture": needs_fixture,
        "import_error": import_error,
        "no_input": no_input,
        "matrix_size": len(TYPE_CONFUSION_PAYLOADS),
        "mutation_case_count": mutation_cases,
        "raw_exception_count": raw_exception_count,
        "positive_control_count": positive_controls,
        "population_complete": population_complete,
        "never_raise_ok": not violations,
        "violations": violations,
        "items": items,
    }


def _format_human(result: dict) -> str:
    lines = [
        f"[type-confusion] {result['population_size']} surface(s): {result['in_scope']} IN_SCOPE, "
        f"{result['non_json']} NON_JSON (now exercised), {result['needs_fixture']} NEEDS_FIXTURE, "
        f"{result['import_error']} IMPORT_ERROR, {result.get('no_input', 0)} NO_INPUT",
        f"  evaluated={result['evaluated_count']}/{result['population_size']} "
        f"complete={result['population_complete']} mutation_cases={result['mutation_case_count']} "
        f"raw_exceptions={result['raw_exception_count']} positive_controls={result['positive_control_count']}",
        f"  never_raise_ok={result['never_raise_ok']} "
        f"subject_tree={result['subject_tree_digest'][:12]} gate_source={result['gate_source_digest'][:12]}",
    ]
    for item in result["items"]:
        if item["status"] in ("NEEDS_FIXTURE", "IMPORT_ERROR"):
            lines.append(f"  {item['status']} {item['python_ref']} — {item.get('notes', '')}")
        elif item.get("violations"):
            for v in item["violations"]:
                lines.append(f"  VIOLATION {item['python_ref']}: {v}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--json", action="store_true")
    p.add_argument("--strict", action="store_true",
                   help="retained for compatibility; the gate is now FAIL-CLOSED by default — an "
                        "incomplete population, an import error, or an un-fixturable surface fails "
                        "the exit code WITHOUT --strict (reviewer F1)")
    args = p.parse_args(argv)
    result = evaluate()
    print(json.dumps(result, indent=2, ensure_ascii=False, default=str) if args.json
          else _format_human(result))
    # Fail-closed by default (reviewer F1/makellose-500): a raw crash OR an incomplete population
    # (evaluated_count < population_size, an empty population, or an IMPORT_ERROR) is a coverage gap, not
    # a clean run. --strict is retained but is no longer the ONLY thing that reddens an unmeasured surface.
    if not result["never_raise_ok"]:
        return 1
    if not result["population_complete"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
