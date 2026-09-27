**A shipped tool verdict is quoted but not re-run.** `pyproject.toml` states that eight mypy
versions and six ruff versions exit 0 over this tree. `tests/test_shipped_comment_numbers.py` binds
the number of FILES each claim ranges over; it does not re-run the tools, because that means eight
interpreter-bound toolchains and minutes per run. The split is stated in the case's docstring
rather than blurred: bound is the size of the set, unbound is the verdict over it. Register entry
`SHIPPED-TOOL-VERDICT-NOT-RE-RUN-01`, target 6.2.0.