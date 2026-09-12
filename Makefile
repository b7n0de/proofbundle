.PHONY: test lint typecheck demo tamper-demo persample-demo full-demo mutation examples conformance conformance-crossimpl all coverage restrisiko restrisiko-deckung restrisiko-render

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

# THE INVOCATION, NAMED — because a generator nobody calls is a generator nobody can trust.
#
# GEMESSEN 12.09.2026: `restrisiko_render.py` had ZERO callers. No make target, no CI step, no
# document naming the command. Its three surfaces (KNOWN_ISSUES_610.md, RESTRISIKO_610.md,
# openvex_610.json) existed from a hand-run, so they could drift from the register with nothing
# to notice — the register is the source, and a rendering that nobody re-derives is a copy.
#
# The identifier list lives OUTSIDE the repository on purpose (a list of names that must not ship
# cannot itself ship), so it is a variable and not a path. Without it the identifier state is
# NOT_MEASURED and the run says so — that is the honest state, not a failure.
IDENTIFIER_LIST ?=
REGISTER ?= audit_artifacts/findings_register_610.json
#
# COVER is EMPTY by default, and that is a statement, not a convenience. Handing it
# `RESTRISIKO_600.md` makes the run refuse with 119 lines of `appears in the prose with no
# carrier entry` — which is finding N26 verbatim, not a broken target. So the prose-coverage run
# has its own name below: it is the finish line of the migration, and it is SUPPOSED to be red
# until the migration is done. A gate that is red by design does not belong in the default path,
# and a gate that would be green only because nobody points it at the prose does not belong
# anywhere.
COVER ?=
RESTRISIKO_ARGS = --register $(REGISTER) \
	--also-check audit_artifacts/600/restrisiko \
	$(if $(COVER),--also-cover $(COVER),) \
	$(if $(IDENTIFIER_LIST),--identifier-list $(IDENTIFIER_LIST),)

restrisiko:  ## validate the findings register and report which areas are exempt (writes nothing)
	$(PYTHON) scripts/restrisiko_render.py $(RESTRISIKO_ARGS) --check-only

restrisiko-deckung:  ## N26 finish line: every identifier in the published prose must have a carrier entry (RED until the migration is done)
	$(PYTHON) scripts/restrisiko_render.py $(RESTRISIKO_ARGS) --check-only \
		--also-cover RESTRISIKO_600.md

restrisiko-render:  ## re-derive the three outward surfaces FROM the register (overwrites them)
	$(PYTHON) scripts/restrisiko_render.py $(RESTRISIKO_ARGS) \
		--out-summary KNOWN_ISSUES_610.md \
		--out-full RESTRISIKO_610.md \
		--out-openvex audit_artifacts/restrisiko_610/openvex_610.json

all: lint typecheck test  ## needs ruff + mypy; from the shipped package run `make test` alone
