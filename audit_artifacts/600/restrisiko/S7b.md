### S7b · The first version of the S7 fix was itself refuted — by three lenses, on three different grounds

The fix recorded in S7 measured the reference load on every call but **appended** the measurements
and took the median over the whole run. Three independent lenses attacked that, and two of the three
attacks landed with arithmetic behind them.

**DRIFT (first lens, executed).** `_maschinenfaktor()` runs once per dimension, twelve times in a
run. With accumulation the first dimension sees 9 values and the twelfth sees 108 — axes of the SAME
run measured against different ceilings, decided by their position in a list.

**MASKING, the worse one (first lens, re-computed independently here).** A median only follows once
more than half the values are new; a slowdown starting at call *k* becomes visible around call
*2k-1*. For a real fivefold slowdown starting at call 11 of 12: the accumulated series reports factor
**1.000** for both affected dimensions, while a per-call series reports **5.000** immediately. The
ceiling would stay tight while the machine really is slow — the false red that `OA-0646ecdf70` exists
to prevent, hidden one level deeper.

**And the accumulation was not bound at all.** The same lens found the mutation that leaves all eight
cases green: a `clear()` at the start of the function. Every case cleared the series itself before
its own scenario, so none of them ever observed the behaviour across calls.

**The fix now measures a fresh series on every call and REPLACES the previous one.** Factor and
measured cost then describe the same time window — they are paired. Against the other danger, a
single restless series, the protection is no longer smoothing but `_faktor_spanne` (S7c).

**A second lens found a leak, executed rather than argued.** The test helper patched two module
globals in two separate statements, and every caller obtained the restore function only after the
call returned. The lens injected a failure between the two assignments and watched a case in a
DIFFERENT class inherit the fake clock and report a fabricated *"machine factor 20.00"* as a
clean-looking skip. Both globals are now set in a single `globals().update(...)` as the function's
last statement: either nothing is patched, or the function returned.

**The same lens showed the counter binds calls, not effect.** One extra unpaired call to the fake
clock desynchronises its start/stop alternation permanently, every measured delta collapses to 0.0 —
and `max(1.0, 0/reference)` yields exactly the 1.0 the median case expects. The case would stay green
on a completely corrupt measurement. The cases now assert that every measured value is positive and
that the outlier really is forty times the others.

**One deviation of my own, found by my own matrix and worth recording.** The case binding "the span
describes the SAME series as the median" measured that by the series' LENGTH. When the design changed
from appending to replacing, the length stopped growing — and the case went from catching that
mutation to catching nothing (announced 1, measured 0). It is now bound to the measurement COUNTER.
A riegel whose measured quantity turns under it is silent, and nothing says so.

**And a flaky assertion of my own.** The same case evaluated its last assertion AFTER restoring the
real clock, so it took a LIVE measurement of the machine inside a case that judges a faked series.
The same mutated state produced 2 failures in one run and 3 in the next. Moved inside the patched
window; ten runs of the mutated state now give ten identical results, and ten runs of the clean state
give ten times eleven green.

Register keys: `ANGEHAEUFTE-REFERENZREIHE-MASKIERT-DIE-SPAETE-VERLANGSAMUNG-01`,
`ZWEI-GLOBALE-IN-ZWEI-SCHRITTEN-GEPATCHT-LECKT-IN-FREMDE-KLASSEN-01`,
`EIN-ZAEHLER-ZAEHLT-AUFRUFE-UND-BINDET-KEINE-WIRKUNG-01`,
`RIEGEL-AN-EINER-MESSGROESSE-DIE-SICH-UNTER-IHM-WEGDREHT-01`.

