# Herkunft der Inspect-Fixtures

## `safety_refusal_demo.eval`

| Feld | Wert | woher |
|---|---|---|
| aufgezeichnet mit | `inspect_ai 0.3.217` | aus der Datei selbst: `log.eval.packages` |
| aufgezeichnet am | 2026-07-01T17:08:08+00:00 | `log.eval.created` |
| Log-Format | Version 2 | `log.version` |
| Modell | `mockllm/model` | `log.eval.model` |

**Die Angabe stand nie daneben — aber sie stand IN der Datei.** Der Nachtrag `20260826T213824Z`
nahm an, die Version sei nicht festgehalten. Gemessen ist sie es: Inspect schreibt `packages` in
den Kopf jedes `.eval`. Was fehlte, war nicht die Herkunft, sondern ihre Sichtbarkeit — man musste
die Datei oeffnen, um sie zu erfahren. Deshalb steht sie jetzt hier, mit dem Feld, aus dem sie
kommt, damit ein Leser sie nachrechnen kann statt sie zu glauben.

## Schreibt die aktuelle Version noch dasselbe Format?

**Ja, gemessen am 29.08.2026** gegen `inspect_ai 0.3.260` (die Version, die der Pin
`>=0.3.112,<0.4` heute zieht), in einer frischen Umgebung mit einem echten
`inspect eval … --model mockllm/model`:

```
frisch aufgezeichnet   log.version 2 · packages {'inspect_ai': '0.3.260'}
alte Fixture gelesen   log.version 2 · status success · results vorhanden
```

Beide Seiten tragen Format **Version 2**, und die alte Fixture liest sich unter 0.3.260
unveraendert. Damit ist die Bedingung des Nachtrags fuer eine ZWEITE Fixture nicht erfuellt —
sie wird ausdruecklich nur aufgezeichnet, *falls* sich das Format geaendert hat. Es hat sich nicht
geaendert.

**Die alte Fixture wird nicht geloescht.** Sie ist der Nachweis der Rueckwaertsvertraeglichkeit:
ohne sie waere „0.3.260 liest 0.3.217" eine Erinnerung statt einer Messung.

**EHRLICHE GRENZE:** gemessen ist die Format-VERSION und dass der Kopf lesbar bleibt — nicht, dass
jedes Feld dieselbe Bedeutung traegt. Eine Semantik-Aenderung innerhalb derselben Formatversion
(wie sie fuer die Scorer in 0.3.258 berichtet wurde) faengt diese Messung nicht.
