# ShyneBeauty

ShyneBeauty is a Flask application for running the internal
operations of a small skincare business. The current app centralizes customer,
order, inventory, batch, shipment, and order-status data models while exposing
protected admin screens plus a live Flask-Admin surface for internal use.

## Current App State

- `shyne.py` contains the Flask app setup, SQLAlchemy models, Flask-Login auth
  flow, Flask-Admin registration, routes, and CLI commands.
- `/login` is a live admin sign-in flow with safe redirect handling, generic
  credential failure messaging, remember-me support, and account lockout after
  repeated failed attempts.
- `/`, `/orders`, and `/tasks` are protected admin pages rendered with Jinja
  templates. They currently show prototype/sample content rather than live
  query-backed business data.
- `/admin/` is protected behind admin authentication and exposes registered
  business tables through Flask-Admin for local/internal development work.
- CI runs pytest on Python 3.10 and 3.12 and also runs CodeQL analysis.

## Local Setup

1. Create and activate a virtual environment.
2. Install dependencies with `pip install -r requirements.txt`.
3. Set `SECRET_KEY` before starting the app. The runtime will also load values
   from `.env`, `.env/local.env`, or `.env/.env` when present.
4. Initialize the databases with `flask --app shyne.py init-db`.
5. Create an admin account with
   `flask --app shyne.py create-admin --email owner@shynebeauty.com`.
6. Start the dev server with `python shyne.py`.
7. Open `http://localhost:8000/login` and sign in.

Example setup:

```powershell
python -m venv .venv-windows
.\.venv-windows\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SECRET_KEY = "replace-with-a-local-secret"
flask --app shyne.py init-db
flask --app shyne.py create-admin --email owner@shynebeauty.com
python shyne.py
```

Optional variables:

- `DATABASE_URL`
- `AUTH_DATABASE_URL`
- `FLASK_DEBUG=true` for debugging
- `SESSION_COOKIE_SECURE=true` for HTTPS

## Testing And CI

Run the local test suite with one of these commands:

```powershell
.\.venv-windows\Scripts\python.exe -m pytest -q
```

```bash
python -m pytest -q
```

GitHub Actions workflows:

- `.github/workflows/pytest.yml` runs pytest on Python 3.10 and 3.12
- `.github/workflows/codeql.yml` runs CodeQL security analysis

## Repository Layout

- `shyne.py`: application setup, models, auth flow, routes, admin registration,
  and CLI commands
- `templates/`: Jinja templates for the current UI surfaces
- `static/`: shared frontend assets such as `shyneIcon.png`
- `tests/`: pytest coverage for auth, protected routes, CLI commands, and model
  behavior
- `schema.sql`: reference schema for the business tables
- `SECURITY.md`: tracked summary of the current security posture and known auth
  risks
- `requirements.txt`: runtime and test dependencies
- `.github/workflows/`: CI and code-scanning workflows
