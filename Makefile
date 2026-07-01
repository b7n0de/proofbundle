.PHONY: test lint typecheck demo all

test:
	python -m unittest discover -s tests -v

lint:
	ruff check .

typecheck:
	mypy src

demo:  ## offline: real eval logs -> signed receipts -> verified OK
	bash scripts/demo.sh

all: lint typecheck test
