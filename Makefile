.PHONY: test lint typecheck demo all

PYTHON ?= python3

test:
	$(PYTHON) -m unittest discover -s tests -v

lint:
	ruff check .

typecheck:
	$(PYTHON) -m mypy src

demo:  ## offline: real eval logs -> signed receipts -> verified OK
	bash scripts/demo.sh

all: lint typecheck test
