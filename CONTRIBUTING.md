# Contributing

This is an internal capstone project for a small skincare business. External contributions are not accepted.

## Local Setup

```bash
python -m venv .venv-windows
pip install -r requirements-dev.txt
export SECRET_KEY="replace-with-a-local-secret"
flask --app shyne.py init-db
flask --app shyne.py create-admin --email owner@shynebeauty.com
python shyne.py   # starts on http://localhost:8000
```

## Running Tests

```bash
python -m pytest -q -m "not a11y_smoke"
```

## Branching

Create a feature branch from `main`, open a PR, and merge after CI passes.
