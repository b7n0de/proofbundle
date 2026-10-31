# done-claims.json, examples (D118)

A repository may say what a completion message needs: the file `.proofbundle/done-claims.json` at its root. The Stop
hook reads it where it is committed (HEAD), where the remote origin holds it (its default branch) and in the work tree,
and takes the union of the three. For a message that reports the work done, the tests passing, a checked set green, a
state that holds or a status OK, each entry needs a run after the last change in the session's transcript whose program
and first words are as declared, that exits 0 with its own exit code (no pipe without pipefail after it, no list, no
`||`) and whose output names a checked count above zero.

The form, exactly:

```json
{"schema": "proofbundle-plugin/done-claims/v0.1",
 "evidence": [{"id": "<name>", "program": ["<program>", "<word>", "..."]}]}
```

`id` is a name of lowercase letters, digits, `-` and `_` (at most 32); `program` holds 1 to 8 words. The program is
compared by the last part of its path; any `python` (python3, python3.12, .venv/bin/python) stands for `python`, and its
switches before `-m` are read over. At most 16 entries. A file that is there but does not hold this form holds every
completion message, with one line that names it.

- `proofbundle.json`: the suite as AGENTS.md names it, `python -m pytest tests/`; pytest names its count (`N passed`).
- the owner's work repository, a proposal only and therefore no file here: its commands are not measured from this session (the
  repository is not reachable here); known from audit_artifacts/600 is a pytest suite under `tests/`, so the proposal
  is the same entry as for proofbundle. Further entries, for example a script under `scripts/` that prints its
  numbers, are the owner's to add once measured there.

  ```json
  {"schema": "proofbundle-plugin/done-claims/v0.1",
   "evidence": [{"id": "tests", "program": ["python", "-m", "pytest"]}]}
  ```

Neither file is checked in at the root of a repository by this change; where one goes is an owner question.
