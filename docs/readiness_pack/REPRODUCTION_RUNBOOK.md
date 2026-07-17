# Reproduction runbook — verify the verifiability

An external reviewer runs this command set to reproduce every internal assurance gate from the pack,
without repo insider knowledge. Each step is self-contained and read-only (writes only under
`audit_artifacts/`). The point is that the reviewer confirms the instruments run, not that they trust a
green screenshot.

## 0. Environment freeze

```
python3 --version           # project floor: 3.10
python3 -c "import cryptography, hypothesis; print(cryptography.__version__)"
cargo --version && rustc --version   # for the Rust differential leg (WP-C)
export PYTHONPATH=src
```

The differential matrix and reproducible-build steps record their own tool versions into their output
artifacts, so a re-run on a different box is comparable.

## 1. Repository gate (full, digest-pinned checkout)

```
python3 -m pytest -q                              # full suite (floor locked, see step 3)
python3 scripts/audit_candidate_matrix.py         # the 33-check acceptance matrix (§9 minus external)
```

`audit_candidate_matrix.py` orchestrates every gate below and prints one line per acceptance
obligation with an honest verdict (PASS / PENDING_JUSTIFIED / DATA_BLOCKED / EXTERNAL_PENDING / FAIL).
`audit_candidate_ready=True` means no internal obligation is broken; `fully_verified_here=True`
additionally means this box had the full toolchain (cargo + build backend + a recorded 24h soak).

## 2. Published-artifact gate (hermetic cleanroom)

```
# CI runs this on every PR (.github/workflows/published-artifact-gate.yml):
#   build the normalised sdist, install it into a FRESH venv, run the demo + an
#   emit/verify/tamper round-trip using only the published bytes, and prove two
#   independent sdist builds are byte-identical.
python3 scripts/build_reproducible.py --check-determinism   # two sdists byte-identical (needs `build`)
```

## 3. Test manifest (no silent test shrink)

```
python3 scripts/test_manifest_gate.py             # collected >= locked floor, 0 collection errors
```

## 4. Type-confusion never-raise matrix (F4)

```
python3 scripts/type_confusion_gate.py --strict   # every public verifier, never a raw exception
```

## 5. Python <-> Rust differential conformance (WP-C)

```
( cd tools/pb_verify_rs && cargo build )          # build the independent second verifier
python3 tools/pb_verify_rs/crosscheck.py --matrix audit_artifacts/360/rust_differential_matrix.json
python3 scripts/rust_parity_gate.py --strict --json   # registry integrity; PENDING is honest, see rust_parity_scope.md
```

## 6. Fuzz soak (WP-D)

```
python3 scripts/fuzz_soak.py --duration-seconds 30          # bounded smoke, runnable here
# the full 24h operational soak (a soak box, not CI):
# python3 scripts/fuzz_soak.py --duration-seconds 86400 --out audit_artifacts/360/fuzz_soak_latest.json
```

The continuous coverage-guided leg is `.clusterfuzzlite/` + `fuzz/fuzz_verifiers.py` (Atheris), an
operational CI artifact.

## 7. Formal model (F3)

```
python3 formal/model.py --json                    # O1-O4 proven; O5/O6/O7 honestly reserved
```

## 8. Claims hygiene (status boundary held)

```
python3 scripts/claims_hygiene_check.py           # 0 un-negated overclaim; no stable/audited/prod-ready
```

## 9. Pack self-integrity + self-receipt

```
python3 scripts/readiness_pack_manifest.py --check           # every listed evidence file hashes as recorded
```

A green run of 1..9 is the machine-checkable half. The other half is the reviewer's own judgement of
the cryptographic constructions and protocol semantics, itemised in `AUDITOR_OPEN_POINTS.md`.
