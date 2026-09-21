.PHONY: setup test lint train scan

PY := py -3.11

setup:
	$(PY) -m venv .venv
	.venv/Scripts/pip install --upgrade pip
	.venv/Scripts/pip install -e ".[dev]"
	.venv/Scripts/pre-commit install

test:
	.venv/Scripts/pytest

lint:
	.venv/Scripts/ruff check .
	.venv/Scripts/black --check .
	.venv/Scripts/mypy voxa training

train:
	.venv/Scripts/python -m training.models.train_xgboost

scan:
	.venv/Scripts/voxa scan
