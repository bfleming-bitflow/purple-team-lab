PYTHON ?= python3
VENV   ?= .venv
BIN     = $(VENV)/bin

.PHONY: help venv lint validate test attack-check coverage-check check clean

help:
	@echo "venv             create .venv and install development dependencies"
	@echo "lint             ruff, yamllint and pymarkdown"
	@echo "validate         validate emulation plans"
	@echo "test             run the test suite"
	@echo "attack-check     regenerate ATT&CK reference data from a STIX bundle and compare (BUNDLE=path)"
	@echo "coverage-check   fail if docs/coverage.md is stale"
	@echo "check            lint, validate, coverage-check and test (what CI runs)"

venv:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -r requirements-dev.txt

lint:
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .
	$(BIN)/yamllint -s .
	$(BIN)/pymarkdown --config .pymarkdown.json scan -r --exclude .venv --exclude .github .

validate:
	$(BIN)/python tools/validate_plans.py

coverage-check:
	$(BIN)/python tools/render_coverage.py --check

test:
	$(BIN)/pytest

attack-check:
	$(BIN)/python tools/attack_data.py --bundle $(BUNDLE) --check

check: lint validate coverage-check test

clean:
	rm -rf .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
