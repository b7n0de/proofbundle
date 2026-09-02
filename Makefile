.PHONY: test lint typecheck demo tamper-demo persample-demo full-demo mutation examples conformance conformance-crossimpl all coverage

PYTHON ?= python3

# EIN ZIEL, DAS IM AUSGELIEFERTEN ZUSTAND NICHT LAUFEN KANN, MUSS DAS SAGEN — nicht scheitern.
#
# GEMESSEN am 02.09.2026 (adversariale as-shipped-Linse): `include Makefile` machte alle 13 Ziele
# zu ausgelieferten Versprechen. Sieben laufen aus dem sdist nicht, und `conformance-crossimpl`
# scheiterte an einem fehlenden Verzeichnis, waehrend sein Kommentar "needs cargo" sagte — die
# falsche Vorbedingung. `prune tools` ist richtig; die MELDUNG war es nicht.
#
# Der Wachtposten ist EINE Zeile je Ziel und nennt die Vorbedingung im Klartext, statt eine
# Shell-Fehlermeldung ueber ein fehlendes Verzeichnis zu produzieren.
# EIN SHELL-AUFRUF, kein zweizeiliger Wachtposten.
#
# Die erste Fassung war eine EIGENE Rezeptzeile mit `|| { echo …; exit 0; }`. Gemessen aus dem
# entpackten sdist: sie meldete die Vorbedingung KORREKT — und make fuhr die naechste Zeile
# trotzdem, weil jede Rezeptzeile ihre eigene Shell hat und `exit 0` nur diese verlaesst. Das Ziel
# scheiterte danach genau wie vorher, jetzt nur mit einer beruhigenden Zeile davor. Ein Riegel,
# der ankuendigt und dann durchlaesst, ist schlimmer als keiner. Deshalb umschliesst die Bedingung
# den GANZEN Rumpf in EINER Zeile.
CHECKOUT_FEHLT = echo "== $@: skipped — needs a source checkout, not the shipped package."; \
	echo "   Why:  tools/ and .github/ are deliberately pruned from the sdist (MANIFEST.in)."; \
	echo "   How:  run this target from a source checkout of the repository."

test:  ## needs pytest (in the [test] extra) — it is the only runner that sees this suite
	$(PYTHON) -m pytest -q

lint:  ## needs `pip install ruff` — deliberately NOT in the [test] extra
	ruff check .

typecheck:  ## needs `pip install mypy` — deliberately NOT in the [test] extra
	$(PYTHON) -m mypy src

demo:  ## pip-only, offline: honest receipt verifies, tampers fail, sample swap caught (in memory)
	PYTHONPATH=src $(PYTHON) -m proofbundle.cli demo

tamper-demo:  ## the demo with an exit-code contract (fails if any guarantee breaks)
	bash scripts/demo_tamper.sh

persample-demo:  ## offline forced-random-sample audit walkthrough
	$(PYTHON) examples/persample_audit.py

full-demo:  ## real eval logs -> signed receipts -> verified OK (needs [eval,inspect] extras)
	bash scripts/demo.sh

mutation:  ## anti-Goodhart gate: the tests must KILL broken implementations (needs a source checkout: it walks the tracked file list)
	@if [ -d tools ] && [ -d .github ]; then $(PYTHON) scripts/mutation_check.py; \
	else $(CHECKOUT_FEHLT); fi

coverage:  ## line coverage of the core over the test suite (needs `pip install coverage`)
	$(PYTHON) -m coverage run -m pytest -q
	$(PYTHON) -m coverage report -m --include="src/proofbundle/*"

examples:  ## run every offline example (those without optional extras)
	@for f in examples/make_example.py examples/lm_eval_receipt.py examples/eee_receipt.py \
	          examples/intoto_dsse_export.py examples/checkpoint_example.py \
	          examples/tlog_proof_example.py examples/rekor_interop.py \
	          examples/persample_audit.py; do \
		echo "== $$f =="; PYTHONPATH=src $(PYTHON) $$f || exit 1; done

conformance:  ## offline conformance corpus (anchor sub-checks need the [anchors] extra)
	PYTHONPATH=src $(PYTHON) conformance/run_conformance.py

conformance-crossimpl:  ## cross-impl acceptance gate: the independent Rust second-verifier must AGREE with Python over the verifier core (needs a source checkout AND cargo; #55 S2)
	@if [ -d tools ] && [ -d .github ]; then \
		( cd tools/pb_verify_rs && cargo build --release ) && \
		PYTHONPATH=src $(PYTHON) tools/pb_verify_rs/crosscheck.py; \
	else $(CHECKOUT_FEHLT); fi

all: lint typecheck test  ## needs ruff + mypy; from the shipped package run `make test` alone
