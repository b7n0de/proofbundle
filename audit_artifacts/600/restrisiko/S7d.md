### S7d · Three mutants survived the entire class, and a fourth defect was in the test harness itself — CLOSED

The third lens ran mutations the class had never been asked about, and three of them left **all eight
cases green** while a real property was broken:

* **The axis-count multiplier was unreachable.** `_faktor_deckel` computes headroom as
  `(d.achsen * GRENZE_S) / k`. Removing the multiplier changed nothing, because every call in the
  class passed `ausser="renewal_work"` — and `renewal_work` is the ONLY dimension with `achsen != 1`.
  The one axis whose multiplier matters was always the excluded one. The new case excludes a
  single-axis dimension instead, so `renewal_work` enters the computation with its three axes.
* **The `k <= 0` guard was never exercised.** No fixture ever set a cost of zero. It becomes real as
  soon as an axis is cheap enough to fall under the clock's resolution; without the guard the cap
  dies on a division by zero, and a riegel that dies on an exception reports nothing at all.
* **The boundary `faktor > deckel` versus `>=` was undecided.** No fixture constructed equality. The
  boundary is a statement: the cap is the stretch at which the NEXT axis breaks, so exactly on it
  nothing has broken yet and the case is still measurable. Shifting it silently converts a measurable
  case into a NICHT MESSBAR, and a silent riegel is indistinguishable from a passing one.

**Building the third case exposed a defect in the harness rather than in the subject.** The fake
clock accumulated (`t += cost`), so the difference of two large floats was no longer exactly the
requested value; the drift pushed the factor just above the cap and the case went red for a reason
that had nothing to do with the boundary. Each measurement now starts at 0.0. A measuring instrument
whose own imprecision moves the quantity under test measures itself along with it.

Three mutations, three announced numbers, three hits. Register keys:
`DIE-EINZIGE-ACHSE-DEREN-MULTIPLIKATOR-ZAEHLT-WAR-IMMER-DIE-AUSGESCHLOSSENE-01`,
`EIN-SCHUTZ-DEN-KEINE-FIXTURE-ANSTEUERT-IST-UNGEBUNDEN-01`,
`DIE-GRENZE-EINES-RIEGELS-IST-EINE-AUSSAGE-KEINE-GESCHMACKSFRAGE-01`,
`EINE-AUFSUMMIERENDE-TESTUHR-VERSCHIEBT-DIE-GEPRUEFTE-GROESSE-01`.

