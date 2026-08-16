# Finding — a typo in the verifier's own command line reads exactly like a broken artifact

**Pre-existing (`main`). Reported first, then CLOSED IN THIS RELEASE** under the Owner's
instruction that all gaps be closed inside 3.8.0. Its subject exists at `v3.7.0`, so it stays an
Altbefund in the index count; only its state changed. `verify-proof`, `--threshold` and
`--log-vkey` all predate 3.8.0. Recorded because a lens on the candidate surfaced it and because it
is the same legibility family as the other findings.

**RE-MEASURED WHILE CLOSING, and the number moved:** this file reported three colliding causes.
Today it is two — `--threshold -1` now separates, because this release put `threshold` into the
JSON for a different finding. That is not a correction of the count as it stood; it is an effect of
work done in between, and it is written out so the difference is not later read as a contradiction.

**Nothing in this file asserts that a pre-tag audit ran.**

## Measured

Positive control first, so an always-collapsing output would be visible: the good run returns
`rc=0, ok=true`. Then four failure causes, hashing the full stdout:

| Cause | exit | sha256(stdout)[:16] |
|---|---|---|
| empty proof file — *the artifact is not a proof* | 1 | `6f5177382070a08a` |
| `--threshold -1` — **the verifier's own typo** | 1 | `6f5177382070a08a` |
| unparseable `--log-vkey` — **the verifier's own typo** | 1 | `6f5177382070a08a` |
| garbage bytes | 2 | `0e35e243f9e23c02` (distinguishable, carries an `error` field) |

**Three of the four are byte-identical.** The count is worth stating precisely: the lens that
surfaced this reported four, and re-measuring gives three — the garbage-bytes case does separate,
with its own exit code and its own field. The finding is narrower than first reported and, in one
respect, worse than the count suggests.

## Why the narrower finding is the more serious one

Of the three that collide, **two are mistakes in the verifier's own invocation**, not properties of
the artifact under test. The output for "you passed a negative threshold" and "your verifier key is
malformed" is indistinguishable from "this file is not a proof". So the relying party reads a verdict
about the artifact, and starts investigating the artifact, while the fault is on their own command
line.

The text path makes it concrete: `--threshold -1` prints `[FAIL] log-signature: None`. Nothing was
ever checked — the threshold guard fires before parsing — but the line names the log signature, which
is the one thing the operator will now go and look at.

## The class

This is the sibling of `FINDING_json_trennt_die_drei_ursachen_nicht.md`, and the difference is worth
keeping. There, three genuine *verification results* collide — all three really are "this proof did
not verify". Here, **"not measurable" collides with "measured no"**, which is a different kind of
error: one of the two states is not a verdict at all.

- **class_id:** `unmeasurable_input_reported_in_the_same_shape_as_a_measured_negative`
- **invariant:** a surface that cannot evaluate its input must say so in a form distinct from the
  form it uses to report a completed evaluation that came out negative. Three states, not two.
- **surface_family_query:** every command that returns a structured verdict and can fail before
  reaching its evaluation (argument validation, file parsing, key parsing).
- **oracle_predicate:** produce one input error and one genuine negative; if the outputs are
  byte-identical, the surface reports its own inability as the artifact's fault.
- **outcome:** `class_closed` — the surface now says WHICH question failed.

## How it is closed

`detail` is copied into the `--json` output (always present, `null` on the green path, so its
absence never has to be interpreted) and printed as a `reason:` line on the text path. Nothing was
invented: the library already carried a precise cause for each case — *no empty-line separator
before the checkpoint* for the empty file, *vkey must have 3 '+'-separated parts* for the malformed
key — and the information was dropped one layer before the output. All four causes now produce
pairwise distinct stdout, with the good run as the control.

The text line goes through `_safe_line`, and the honest wording for that is **precautionary**:
two of the four causes interpolate `{exc}`, whose text this file does not determine and whose forms
cannot be enumerated. Three probes — ESC, newline injection, NUL — produced **no** control character
in the detail, because the parse errors are library-authored. So this is not a measured leak; the
wrapping costs nothing and covers the forms nobody has enumerated. The JSON path is safe through
`json.dumps` either way.

Rollback probes: removing the JSON key turns two guards red, removing the text line turns one red,
and wiring the key to a constant string — which *looks* filled — turns two red.

`_tlog_failclosed` builds the collapsed shape, and the library does carry a precise `detail` for each
of these causes — `cli.py` lists the keys to copy into the JSON and `detail` is not among them. The
information exists and is dropped one layer before the output.

## Why it was not fixed here — the reasoning at the time, overtaken

Adding `detail` to the JSON output is a change to the output shape, which this release has already
had to correct its CHANGELOG about twice. `verify-proof`'s error path is outside the shipped delta
(`git diff v3.7.0..HEAD -- src/` is `cli.py` and `__init__.py`, and the change there is the origin
flag, its JSON field and the display filter). Under the rule this run follows, that makes it a `main`
finding: reported, not folded in.

## Honest boundary

Measured is that the three outputs are byte-identical and that two of the three causes originate in
the caller's command line. **Not** measured is how often a relying party hits this, or whether anyone
has actually been sent looking at the wrong thing — that is outside what a repository measurement can
see. The exit codes do carry one bit the JSON does not: the garbage-bytes case exits 2 while the
other three exit 1, so a caller who checks the exit code has strictly more to go on than one who
parses only the document.
