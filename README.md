# VOXA

Pre-execution ransomware detection for Windows PE files (`.exe`, `.dll`), using 23
statically-extracted PE features and an XGBoost + TabNet ensemble with feature-level
explanation. Offline, standalone, no sample is ever executed.

See [`VOXA — Development Roadmap.md`](<VOXA — Development Roadmap.md>) for the full
project plan, architecture and phase-by-phase task breakdown.

## Setup

Requires Python 3.11 and the `py` launcher (Windows).

```
make setup
make test
```

`make setup` creates a `.venv`, installs the project in editable mode with dev
dependencies, and installs pre-commit hooks. `make test` runs the test suite.

Copy `.env.example` to `.env` and adjust paths if needed.

## Layout

- `voxa/` — the application: feature extraction, inference, ensemble, explainability,
  database, CLI and GUI. Nothing here executes an analyzed file.
- `training/` — dataset preparation, model training, evaluation. Imports
  `voxa/core/features/` so training and inference share one extractor.
- `tests/` — unit and integration tests.
- `docs/` — feature spec, ADRs, dataset provenance, evaluation reports.
- `data/`, `models/` — gitignored; never committed.

## Commands

- `make setup` — create venv, install deps, install pre-commit hooks
- `make test` — run pytest
- `make lint` — ruff, black --check, mypy
- `make train` — run the training entry point
- `make scan` — run the CLI scan entry point
