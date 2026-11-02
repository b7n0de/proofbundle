---
type: regex
target: trace
pattern: '^(?:(?!proofbundle done check)[\s\S])*$'
---
A passed end prints nothing since DECISIONS.md D53: the trace holds no line of the done check, neither a block nor an end
without a done verdict. The verdict and its reason id `done` stand in the gate log (D21).
