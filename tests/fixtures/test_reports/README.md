# Test report vectors: JUnit XML and CTRF JSON

`vectors.json` lists every file in `junit/` and `ctrf/` with the expected outcome of
`proofbundle.adapters.junit_ctrf`: accepted with the five counts (tests, passed, failed, errors,
skipped) and the verdict, or refused with a reason code. `tests/test_junit_ctrf_adapter.py` reads the
manifest and fails when a file is missing from it.

## Real reports

Produced on 2026-10-16 by running the tools, not written by hand.

| Files | Producer | Changes |
|---|---|---|
| `junit/pytest-9.1.1_*.xml` | pytest 9.1.1 `--junitxml` on CPython 3.10.12 | local path prefix replaced by `/work`, host name replaced by `ci-host` |
| `junit/jest-junit-17.0.0_*.xml` | jest 29.7.0 with jest-junit 17.0.0 | local path prefix replaced by `/work` |
| `ctrf/jest-ctrf-json-reporter-0.2.0_*.json` | jest 29.7.0 with jest-ctrf-json-reporter 0.2.0 (`specVersion` 0.2.0) | local path prefix replaced by `/work` |
| `junit/surefire-fixture_*.xml` | test resources of `apache/maven-surefire`, `surefire-report-parser/src/test/resources/fixture/testsuitexmlparser/`, commit `f18d70cd8b0b4847316ead34b4dada545f6b9843` | none, byte-identical; Apache-2.0, license text in `junit/surefire-fixtures.LICENSE` |

Vendored Surefire files, renamed, with their SHA-256:

| Here | Upstream name | SHA-256 |
|---|---|---|
| `surefire-fixture_MyTest.xml` | `TEST-surefire.MyTest.xml` | `1a6b45e824076fafe0e11791ce64b93f1dc4b2c458c5676f9cbf48433ad30ee2` |
| `surefire-fixture_FailingTest.xml` | `TEST-org.apache.maven.surefire.test.FailingTest.xml` | `d4fe7e2e89262db30c9112a7085bbbc153fe81c288ac2c3fb6aa2aa2316c9549` |
| `surefire-fixture_FlakyTest_old_writer.xml` | `TEST-org.acme.FlakyTest.xml` | `e709b82fb7e34c3f7d995a9626ccba249061439b74cfacc21536ce84e703c1c6` |

Two real reports contradict themselves and are refused:

- `jest-junit-17.0.0_todo_contradiction.xml`: jest-junit writes a `test.todo` as a `<testcase>`
  without a child element, which reads as passed, and leaves it out of `tests="3"`. The file holds
  four testcases.
- `surefire-fixture_FlakyTest_old_writer.xml`: two `<testcase>` elements under `tests="1"`. The
  current Surefire writer (`StatelessXmlReporter` at the commit above) counts one per test method.

The mixed jest run also had a test file that failed to load. jest-junit and the CTRF reporter both
left it out of their report. Nothing in either file shows that it existed.

## CTRF version

The CTRF reader follows the normative specification `spec/ctrf.md` of `ctrf-io/ctrf`, version 0.2.0
dated 2026-10-10, retrieved 2026-10-16T07:19:01Z (SHA-256
`38b7e51733c12488bad08ccaf88f1398940083863542107914c652e8564e95e8`).

## Synthetic vectors

Files starting with `syn_` are written by hand, one rule each. They are the negative cases
(document type declarations, entities, external references, processing instructions, duplicate
attributes and keys, encodings, contradictions between counts and elements, unknown fields,
unsupported versions) and the positive cases no real run above produced (a flaky Surefire test,
nested suites, an empty CTRF run, a CTRF status `other`).
