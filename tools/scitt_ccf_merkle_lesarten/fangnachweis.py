#!/usr/bin/env python3
"""Catch proof for zwei_lesarten.py — plants defects and measures what shows up.

WHY THIS IS NEEDED: zwei_lesarten.py reports "5 of 6 cases differ". A measuring tool that always
says the same thing would look exactly like that. This proof plants defects in the checker and
measures whether they change the result.

PREDICTION BEFORE THE RUN (derived from the measured baseline, not guessed):
  FIRST RUN, predicted 4 COUNTS / 2 AGAINST — MEASURED 3 / 3. The prediction did NOT hold.
  A2 slipped through because only the NUMBER of deviations was measured.
  AFTER THE HARDENING (the roots belong to the measuring surface): PREDICTED 6 COUNTS / 0 AGAINST.
  COUNTS  = the defect changes WHAT THE SCRIPT REPORTS (verdict line, counter-probe OR a root).
  AGAINST = the defect stays invisible in the measured surface. After the hardening there should be
            no such case left; if one remains, THAT is the finding.

PLANTING PROOF: every mutation asserts `neu != orig` to show it took effect at all. Without that
line, str.replace() silently reports success when the pattern does not match — which is exactly how
an earlier proof in this session reported "1 of 8" instead of "3 of 9".

A NOTE ON THE COUPLING, because a translation exposed it: `kennzahlen` parses the PROSE of the
sibling script's output. Translating that script from German to English broke three of its patterns
at once, and this proof did the right thing — it refused to report a number without a baseline
instead of reporting zero. The roots came through unharmed because their pattern reads hex rather
than words, which is the same hardening the paragraph above describes: a second measure that does
not hang on wording.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys
import tempfile

QUELLE = pathlib.Path(__file__).resolve().parent / "zwei_lesarten.py"

# (name, old, new, predicted class, why)
DEFEKTE = [
    (
        "A1 leaf preimages made equal",
        "    serialisiert = CBOR.schreibe([",
        "    return blatt_hash_b(b)\n    serialisiert = CBOR.schreibe([",
        "COUNTS",
        "Reading 2.1 then computes the same as 3.2, so the deviation must fall to 0.",
    ),
    (
        "A2 inner HASH removed from reading 3.2",
        '+ H(b["internal_evidence"].encode("utf-8"))',
        '+ b["internal_evidence"].encode("utf-8")',
        "COUNTS",
        "3.2 demands HASH(internal-evidence) verbatim. Without that hash it is a different "
        "reading: the roots change but the deviation count stays 5. Predicted COUNTS only if the "
        "script REPORTS it; otherwise the case falls back to AGAINST.",
    ),
    (
        "A3 k boundary shifted",
        "    while k * 2 < n:",
        "    while k * 2 <= n:",
        "COUNTS",
        "The tree shape tips over (k must be the largest power of two with k < n). At n=2 and "
        "n=4 the split becomes empty, and that has to become visible.",
    ),
    (
        "A4 counter-probe defused",
        '    return True, "equal case, unequal case and positive control all correct", hx(H(spur))[:16]',
        '    return True, "always green", hx(H(spur))[:16]',
        "COUNTS",
        "The counter-probe is the only protection against 'differs' becoming meaningless. Its "
        "reason line is part of the output; if that becomes arbitrary, it is visible.",
    ),
    (
        "A5 RFC 6962 prefixes in BOTH readings",
        "    return H(mth(blatt_hashes[:k]) + mth(blatt_hashes[k:]))",
        '    return H(b"\\x01" + mth(blatt_hashes[:k]) + mth(blatt_hashes[k:]))',
        "COUNTS",
        "Changes EVERY root from n=2 on, but symmetrically in both readings, so the deviation "
        "count stays 5. The checker cannot see it because it COMPARES readings instead of checking "
        "against fixed expected values. A named blind spot.",
    ),
    (
        "A8 comparison results removed from the measure",
        "        spur += roh + bytes([gleich, ungleich])",
        "        spur += roh",
        "COUNTS",
        "The refutation from the FIRST FOREIGN model family, in its present form. Back then the "
        "defect was 'delete both if blocks' and it slipped through: the trace fell out of the "
        "computed INTERMEDIATE VALUES rather than the comparison results and stayed byte-identical "
        "(0a87e1a7611f53dd before and after). Since the findings go into the trace themselves, "
        "removing that binding is the equivalent defect, and it MUST show up, or the hardening is "
        "merely claimed again.",
    ),
    (
        "A9 mechanics disarmed (the pass reports fixed findings)",
        "    return links == rechts, anders != links, links + anders",
        "    return True, True, links + anders",
        "COUNTS",
        "The case that did NOT exist before: in a run where the property holds, a disarmed "
        "comparison is invisible in principle, because every measure is identical. It becomes "
        "visible only through a case that MUST fail. That is what the deaf reading is for: if the "
        "mechanics report it as discriminating, they are lying. If this defect is not caught, the "
        "positive control has no value.",
    ),
    (
        "A7 counter-probe silenced (dead code)",
        '    blaetter = [blatt(i) for i in range(4)]\n    gleichwertig =',
        '    return True, "equal case, unequal case and positive control all correct", ""\n'
        '    blaetter = [blatt(i) for i in range(4)]\n    gleichwertig =',
        "COUNTS",
        "The defect a cross-reading used to refute this proof: an early return turns the whole "
        "check into dead code. Before the trace existed that stayed invisible, because the "
        "measuring surface read only the REPORTED RESULT. With the trace it MUST show up.",
    ),
    (
        "A6 concatenation order reversed",
        "    return H(mth(blatt_hashes[:k]) + mth(blatt_hashes[k:]))",
        "    return H(mth(blatt_hashes[k:]) + mth(blatt_hashes[:k]))",
        "COUNTS",
        "The same class as A5: both readings share the tree rule, so a defect in it hits both "
        "equally and cancels out in the comparison.",
    ),
]


def lauf(quelltext: str) -> tuple[int, str]:
    """Run one mutated candidate and return (return code, output).

    THE CANDIDATE LIVES IN THE SOURCE'S OWN DIRECTORY, and the reason is the whole point of this
    function. `zwei_lesarten.py` derives everything it needs from the location of its own file: the
    repository root by walking up for `.git`, and `cbor_min.py` as a sibling of its own directory. A
    candidate placed anywhere else answers those questions differently, dies on a load error instead
    of on the planted defect, and measures nothing.

    THE FIRST VERSION KNEW THAT AND STILL GOT IT WRONG, which is why the reasoning stays here. It used
    `TemporaryDirectory(dir=QUELLE.parent)`, a SUBDIRECTORY of the source directory, so the candidate
    sat one level too deep: its sibling lookup resolved to
    `scitt_ccf_merkle_lesarten/scitt_ccf_datahash_vector/cbor_min.py`, which does not exist. In this
    repository the `.git` walk covered for it and everything looked fine. In a tree WITHOUT `.git` --
    an exported `git archive`, an sdist, a downloaded zip -- both routes failed at once. Measured in a
    clean export of this branch: `zwei_lesarten.py` exits 0, this proof exits 2 before planting
    anything, with the baseline reporting every field as None. The comment above the old line named
    the class correctly and the code below it was off by one directory, which is the more useful half
    of this story: a correct comment is not a correct implementation. Found by the review lane, not by
    re-reading, and confirmed by running the export.

    SO THE FIX IS NOT A DEEPER PATH BUT NO PATH REASONING AT ALL: same directory as the source, unique
    name, removed afterwards. Then the candidate resolves every lookup exactly as the original does,
    and it keeps doing so if `_lade_cbor_min` is ever rewritten.
    """
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".py", prefix="kandidat_",
                                     dir=str(QUELLE.parent), delete=False) as f:
        f.write(quelltext)
        p = pathlib.Path(f.name)
    try:
        r = subprocess.run([sys.executable, str(p)], capture_output=True, text=True, timeout=120)
        return r.returncode, r.stdout + r.stderr
    finally:
        p.unlink(missing_ok=True)


def kennzahlen(ausgabe: str) -> dict:
    """The things the script REPORTS — that is what is measured, not its internals.

    THE ROOTS BELONG TO IT, and that is a hardening from this proof's first run: it measured only
    the NUMBER of deviations, and three of six defects (A2, A5, A6) left that number at 5. A checker
    that holds two readings AGAINST EACH OTHER is blind to a defect that hits BOTH equally; that is
    owed to its construction and cannot be repaired by looking harder. The second, INDEPENDENT check
    is therefore the root value itself: it binds the result to fixed bytes rather than to a
    comparison.
    """
    m = re.search(r"RESULT: (\d+) of (\d+) cases differ", ausgabe)
    g = re.search(r"COUNTER-PROBE: (\w+) -- (.*?)(?: \[trace [0-9a-f]*\])?$", ausgabe, re.M)
    # TRACE: the value falls out of the counter-probe's own computation. Without it the
    # counter-probe could be silenced without any measured quantity reacting (cross-reading,
    # finding 1).
    s = re.search(r"\[trace ([0-9a-f]*)\]", ausgabe)
    # PROVENANCE: which path supplied the CBOR serialization. It was in no pattern before, so a
    # forged provenance line was invisible (cross-reading, finding 4).
    h = re.search(r"^CBOR\s*:\s*(.+)$", ausgabe, re.M)
    # per table row: n, root A, root B
    wurzeln = tuple(
        (int(a), b, c)
        for a, b, c in re.findall(r"^\s*(\d+)\s+([0-9a-f]{64})\s+([0-9a-f]{64})", ausgabe, re.M)
    )
    return {
        "abweichend": int(m.group(1)) if m else None,
        "gesamt": int(m.group(2)) if m else None,
        "gegenprobe": g.group(1) if g else None,
        "gegenprobe_grund": g.group(2).strip() if g else None,
        "gegenprobe_spur": s.group(1) if s else None,
        "cbor_herkunft": h.group(1).strip() if h else None,
        "wurzeln": wurzeln,
    }


def main() -> int:
    orig = QUELLE.read_text(encoding="utf-8")
    rc0, aus0 = lauf(orig)
    grund = kennzahlen(aus0)
    print("BASELINE, measured (not predicted):")
    print(f"  RC={rc0}  {grund}")
    if grund["abweichend"] is None:
        print("STOPPING: the baseline reports no result line — without a baseline every mutation "
              "count is meaningless.")
        return 2

    # TRANSPORT CONTROL: the baseline above is the source text run through the CANDIDATE transport --
    # written to a temporary file and executed from there. Every number below is compared against it,
    # so if the transport changes what the source reports, every comparison is against a baseline that
    # is nobody's behaviour. Running the source AT ITS OWN PLACE is the only way to see that, and the
    # two measurands must be identical.
    #
    # STATED REACH, MEASURED, and it does NOT include the defect that prompted it. The candidate used
    # to be written one directory BELOW the source, so it resolved its dependencies by a different
    # route. Measured with that old transport restored in THIS repository: this control PASSES, because
    # the `.git` walk produced the identical measurand by the other route. It fires only when the
    # transport changes WHAT IS REPORTED, not when it merely takes a different path to the same report.
    #
    # So the pair is the protection, not this control alone. What catches a route difference that is
    # invisible here is running the proof in a tree WITHOUT `.git`, where the second route does not
    # exist -- and that run is recorded in RUNS.txt as its own case for exactly this reason. Writing
    # this limit down rather than letting the control look complete is the point: a control whose reach
    # is assumed instead of measured is the shape this whole tool exists against.
    rc_direkt = subprocess.run([sys.executable, str(QUELLE)], capture_output=True, text=True,
                               timeout=120)
    direkt = kennzahlen(rc_direkt.stdout + rc_direkt.stderr)
    if direkt != grund or rc_direkt.returncode != rc0:
        print("STOPPING: the transport changes the measurement. The source run IN PLACE and the same "
              "source run as a candidate do not agree, so the baseline every mutation is compared "
              "against is not the source's behaviour.")
        print(f"  in place  RC={rc_direkt.returncode}  {direkt}")
        print(f"  as candidate RC={rc0}  {grund}")
        return 2
    print("  transport control: the source measures the same in place as it does as a candidate.")
    print()

    angesagt_zaehlt = sum(1 for d in DEFEKTE if d[3] == "COUNTS")
    print(f"PREDICTED: {angesagt_zaehlt} COUNTS of {len(DEFEKTE)} planted defects.")
    print()

    zaehlt = gegen = ungepflanzt = nur_absturz = angehalten_n = 0
    for name, alt, neu, klasse, warum in DEFEKTE:
        if alt not in orig:
            print(f"  {name:42s} NOT PLANTED — pattern not in the source")
            ungepflanzt += 1
            continue
        # UNIQUENESS FIRST (cross-reading, finding 5): `assert kandidat != orig` only shows that
        # SOMETHING changed, never that the INTENDED place was hit. If the pattern occurs more than
        # once, replace(..., 1) silently hits the first occurrence.
        anzahl = orig.count(alt)
        if anzahl != 1:
            print(f"  {name:42s} AMBIGUOUS — pattern occurs {anzahl}x, not planted")
            ungepflanzt += 1
            continue
        kandidat = orig.replace(alt, neu, 1)
        # PLANTING PROOF: without this assertion replace() silently reports success
        assert kandidat != orig, f"{name}: the mutation did not take effect"

        rc, aus = lauf(kandidat)
        k = kennzahlen(aus)
        # WHAT THE CATCH HANGS ON, kept apart (cross-reading, finding 3): a crash is caught by
        # any rc test and does NOT show that the measuring surface saw anything. The marker is
        # NOT `k == grund` — in a crash every field is None and therefore different. The marker
        # is that the result line never appeared: then the surface saw only ABSENCE, not a
        # measured difference.
        # THREE causes, not two. The first version had ONE field for two of them and called A9
        # "crash only" -- but there the counter-probe had correctly FAILED and stopped the run.
        # That is the STRONGEST form of catching, not the weakest, and a shared label would have
        # counted it as the weakest.
        # "FAILED" AND NOT "GEFALLEN", and this line was DEAD for one commit. The sibling tool
        # prints its counter-probe verdict, this one parses it, and translating the sibling
        # changed the token from GEFALLEN to FAILED while this comparison stayed behind. The
        # effect was silent and precisely the one the comment above warns about: `angehalten`
        # was always False, so a case where the counter-probe correctly FAILED got labelled
        # "run aborted" -- the weakest form of catching, for what is the strongest.
        angehalten = k["gegenprobe"] == "FAILED"
        nur_rc = k["abweichend"] is None and not angehalten
        sichtbar = (rc != rc0) or (k != grund)
        urteil = ("CAUGHT (counter-probe fails)" if angehalten
                  else "CAUGHT (run aborted)" if nur_rc
                  else "CAUGHT" if sichtbar else "slipped through")
        ist = "COUNTS" if sichtbar else "AGAINST"
        treffer = "ok" if ist == klasse else "DIFFERS FROM PREDICTION"
        if sichtbar:
            zaehlt += 1
        else:
            gegen += 1
        if nur_rc:
            nur_absturz += 1
        if angehalten:
            angehalten_n += 1
        print(f"  {name:54s} {urteil:28s} predicted={klasse:7s} measured={ist:7s} {treffer}")
        if k != grund:
            print(f"      {grund}  ->  {k}")

    print()
    print(f"MEASURED: {zaehlt} COUNTS · {gegen} AGAINST · {ungepflanzt} not planted "
          f"(of {len(DEFEKTE)})")
    print(f"of those, caught ONLY through the return code (the run aborted, the surface saw "
          f"nothing but absence): {nur_absturz}")
    print(f"of those, stopped by the counter-probe itself (it REPORTS the defect): {angehalten_n}")
    print(f"PREDICTED was: {angesagt_zaehlt} COUNTS.")
    if zaehlt == angesagt_zaehlt:
        print("The prediction held.")
    else:
        print("THE PREDICTION DID NOT HOLD -- that is the finding, not the defects' outcome.")
    print()
    print("WHAT THIS PROOF LEARNED, and it stands here because it REFUTED the prediction: "
          "the first run predicted 4 COUNTS and measured 3. A2 slipped through because the "
          "measuring surface was only the NUMBER of deviations -- and A2, A5 and A6 all leave "
          "that number at 5. A checker that holds two readings AGAINST EACH OTHER is blind to "
          "every defect that hits BOTH equally; that is owed to its construction, not to a lack "
          "of care. The hardening is therefore not a stricter rule but a SECOND, independent "
          "quantity: the root values themselves. They bind the result to fixed bytes instead of "
          "to a comparison. After that: 6 of 6 -- which was every defect there was THEN. The "
          "table has since grown to 9, so read that 6 as a date and not as the current count.")
    print()
    print("WHAT REMAINS NOT MEASURABLE, with the reason: whether our roots are the RIGHT "
          "ones. The draft names no test vectors, and no independent implementation is "
          "available here. This proof shows that the checker reacts to changes -- not that it "
          "reads the document correctly.")
    return 0 if zaehlt == angesagt_zaehlt else 1


if __name__ == "__main__":
    sys.exit(main())
