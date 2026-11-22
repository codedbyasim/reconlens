PYTHON ?= python3
BIN ?= .venv/bin

.PHONY: venv install lint format typecheck test coverage ci

venv:
	$(PYTHON) -m venv .venv
	$(BIN)/python -m pip install --upgrade pip

install: venv
	$(BIN)/python -m pip install -e ".[dev]"

lint:
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .

format:
	$(BIN)/ruff check --fix .
	$(BIN)/ruff format .

typecheck:
	$(BIN)/mypy src

test:
	$(BIN)/pytest

coverage:
	$(BIN)/pytest --cov=reconlens --cov-report=term-missing --cov-fail-under=80

ci: lint typecheck coverage
