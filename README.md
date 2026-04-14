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
4. Initialize demo data with `flask --app shyne.py init-db` if you want the
   seeded sample dataset, or initialize empty schema with
   `flask --app shyne.py init-live-db` for real staff use.
5. Start the dev server with `python shyne.py`.
6. Open `http://localhost:8000/login`.

Example setup:

```powershell
python -m venv .venv-windows
.\.venv-windows\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SECRET_KEY = "replace-with-a-local-secret"
flask --app shyne.py init-db
python shyne.py
```

## Seeded Demo Accounts

`flask --app shyne.py init-db` seeds these deterministic example users:

- `olivia.mercer@shynebeauty.com` / `ShyneDemoSuper1!` — `Superadmin`
- `maya.brooks@shynebeauty.com` / `ShyneDemoStaff1!` — `Staff Operator`
- `noah.kim@shynebeauty.com` / `ShyneDemoInventory1!` — `Inventory / Production`
- `devops@shynebeauty.com` / `ShyneDemoDev1!` — `Dev Admin`

Use these accounts for local demo and development only. `Dev Admin` remains
hidden from the `Users & Access` table and is the only seeded role that can
open `/admin/`.

Optional variables:

- `DATABASE_URL`
- `AUTH_DATABASE_URL`
- `FLASK_DEBUG=true` for debugging only
- `SESSION_COOKIE_SECURE=true` for HTTPS

## Internal Launch Guidance

For restricted internal staff use, prefer the schema-only bootstrap path and a
WSGI server instead of the Flask development server.

Recommended bootstrap:

1. Set a non-demo `SECRET_KEY` outside git.
2. Run `flask --app shyne.py init-live-db`.
3. Create the first business admin with
   `flask --app shyne.py create-admin --email owner@shynebeauty.com`.
4. Create a hidden technical admin only if you need Flask-Admin access:
   `flask --app shyne.py create-dev-admin --email tech@shynebeauty.com`.
5. Launch the app with Waitress:

```bash
python -m waitress --listen=127.0.0.1:8000 shyne:app
```

Notes:

- `python shyne.py` remains the development server path only.
- `init-db` is destructive and reseeds demo data; do not run it against live
  operator data.
- When `DATABASE_URL` and `AUTH_DATABASE_URL` are not overridden, the default
  SQLite files live under `instance/`.
- Set `SESSION_COOKIE_SECURE=true` when the app is served over HTTPS.

## Backup And Restore

- Stop the app before copying SQLite files.
- Back up both databases together:
  - `instance/shynebeauty.db`
  - `instance/shynebeauty_auth.db`
- Restore by replacing both files as a pair, then restarting the app.
- If `DATABASE_URL` or `AUTH_DATABASE_URL` are overridden, back up those custom
  paths instead of the defaults above.

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
