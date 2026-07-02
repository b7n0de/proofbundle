.PHONY: test lint typecheck demo tamper-demo persample-demo full-demo mutation examples all

PYTHON ?= python3

test:
	$(PYTHON) -m unittest discover -s tests -v

lint:
	ruff check .

typecheck:
	$(PYTHON) -m mypy src

demo:  ## pip-only, offline: honest receipt verifies, tampers fail, sample swap caught (in memory)
	PYTHONPATH=src $(PYTHON) -m proofbundle.cli demo

tamper-demo:  ## the demo with an exit-code contract (fails if any guarantee breaks)
	bash scripts/demo_tamper.sh

persample-demo:  ## offline forced-random-sample audit walkthrough
	$(PYTHON) examples/persample_audit.py

full-demo:  ## real eval logs -> signed receipts -> verified OK (needs [eval,inspect] extras)
	bash scripts/demo.sh

mutation:  ## anti-Goodhart gate: the tests must KILL broken implementations
	$(PYTHON) scripts/mutation_check.py

coverage:  ## line coverage of the core over the test suite (needs `pip install coverage`)
	$(PYTHON) -m coverage run -m unittest discover -s tests
	$(PYTHON) -m coverage report -m --include="src/proofbundle/*"

examples:  ## run every offline example (those without optional extras)
	@for f in examples/make_example.py examples/lm_eval_receipt.py examples/eee_receipt.py \
	          examples/intoto_dsse_export.py examples/checkpoint_example.py \
	          examples/tlog_proof_example.py examples/rekor_interop.py \
	          examples/persample_audit.py; do \
		echo "== $$f =="; PYTHONPATH=src $(PYTHON) $$f || exit 1; done

all: lint typecheck test
