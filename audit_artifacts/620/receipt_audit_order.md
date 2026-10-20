# The audit command of the 6.2.0 pre-tag receipt

The pre-tag receipt of 6.2.0 runs the full test suite with `-p no:randomly`, which keeps the file
order the CI runs. The receipt of 6.1.0 ran the same suite without that flag, and its
`audit_command` shows it.

## Why the order is fixed

The environment that runs the audit, `~/proofbundle/.venv`, has `pytest-randomly` installed, and
that plugin shuffles the suite on every run. Neither the CI workflow nor `pyproject.toml` installs
it, so the CI runs the suite in file order. In a shuffled order one pair of tests depends on which
runs first, for a reason inside the tests, not inside the package.

- `tests/test_one_reading_reaches_every_argument.py::TheNeighboursTheVerifyLaneFound::test_a_token_in_the_instance_dict`
  sets `token`, an attribute the class does not declare, on one `ArchiveTimeStamp` instance with
  `object.__setattr__`.
- On CPython 3.10 the instances of that class stop sharing the keys of their `__dict__` after that,
  so every later instance takes more memory.
- `tests/test_lauf11_l3_testlast_ist_gedeckelt.py::TestKeineUngedeckelteTestlast::test_die_kostentabelle_ist_gemessen_nicht_geschaetzt`
  measures that size with `tracemalloc` against a table entry of 384 bytes per element. Run after
  the first test it measured 572.7 bytes, and in the reverse order both passed, measured on
  2026-09-29 with a fixed order.
- Over 20 seeds of `pytest-randomly`, 10 collected the first test before the second.

## What this does not change

The flag fixes the order and nothing else. It selects no test and skips none, and every test the
shuffled suite runs, the ordered suite runs too. The dependence between the two tests is a defect
of the tests and is repaired after the tag in a pull request of its own.
