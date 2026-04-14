# ShyneBeauty

ShyneBeauty is a Flask application for running the internal
operations of a small skincare business. The current app centralizes customer,
order, inventory, batch, shipment, and order-status data models while exposing
protected admin screens plus a live Flask-Admin surface for internal use.

## Current App State

- `shyne.py` contains the Flask app setup, SQLAlchemy models, Flask-Login auth
  flow, Flask-Admin registration, routes, and CLI commands.
- `/login` is a live admin sign-in flow with safe redirect handling, generic
  credential failure messaging, remember-me support, account lockout after
  repeated failed attempts, and CSRF protection on POST routes.
- `/`, `/orders`, `/customers`, and `/inventory` are protected admin pages
  rendered with Jinja templates and backed by live database queries.
- `/add-customer`, `/add-order`, `/add-inventory`, and `/add-product` are live
  create workflows gated by business permissions and backed by saved database
  writes.
- `/tasks` remains a protected prototype workflow page and is not backed by a
  persisted task model yet.
- `/admin/` is protected behind admin authentication and exposes registered
  business tables through Flask-Admin for local/internal development work.
- CI runs pytest on Python 3.10 and 3.12, CodeQL analysis, dependency review
  on pull requests, and a Gitleaks secret scan on pushes and pull requests.
- Dependabot is configured to open weekly update PRs for Python dependencies
  and GitHub Actions workflow dependencies.

## Local Setup

1. Create and activate a virtual environment.
2. Install dependencies with `pip install -r requirements.txt`.
3. Set `SECRET_KEY` before starting the app. The runtime will also load values
   from `.env`, `.env/local.env`, or `.env/.env` when present.
4. Initialize the databases with `flask --app shyne.py init-db`.
5. Create an admin account with
   `flask --app shyne.py create-admin --email owner@shynebeauty.com`.
6. Optional local-only shortcut: set `ENABLE_DEV_TEST_ADMIN=true` and run
   `flask --app shyne.py --debug seed-dev-admin` to seed a development login of
   `admin` / `admin`. The login page only shows the credentials after that
   seeding step has run.
7. Start the dev server with `python shyne.py`.
8. Open `http://localhost:8000/login` and sign in.

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
- `ENABLE_DEV_TEST_ADMIN=true` for the local-only `seed-dev-admin` shortcut
- `SESSION_COOKIE_SECURE=true` for HTTPS

## Password Hashing

- Admin passwords are created with Werkzeug PBKDF2 using
  `pbkdf2:sha256:1000000`.
- This hash method was chosen for cross-platform compatibility across macOS,
  Windows, and Linux.

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
- `.github/workflows/dependency-review.yml` blocks pull requests that introduce
  new high-severity vulnerable dependencies
- `.github/workflows/gitleaks.yml` scans pushes and pull requests for committed
  secrets
- `.github/dependabot.yml` schedules weekly update PRs for `pip` and GitHub
  Actions dependencies

If GitHub Secret Scanning is enabled for the repository, that native feature can
coexist with the Gitleaks workflow or replace it later.

## Repository Layout

- `shyne.py`: application setup, models, auth flow, routes, admin registration,
  and CLI commands
- `templates/`: Jinja templates for the current UI surfaces
- `static/`: shared frontend assets such as `shyneIcon.png`
- `tests/`: pytest coverage for auth, CSRF, protected routes, create workflows,
  CLI commands, and model behavior
- `schema.sql`: reference schema for the business tables
- `requirements.txt`: runtime and test dependencies
- `.github/workflows/`: CI and code-scanning workflows
