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
  repeated failed attempts, IP-aware throttling, optional TOTP MFA challenge
  for any enrolled account, and CSRF protection on POST routes.
- `/`, `/orders`, `/customers`, and `/inventory` are protected admin pages
  rendered with Jinja templates and backed by live database queries.
- `/add-customer`, `/add-order`, `/add-inventory`, and `/add-product` are live
  create workflows gated by business permissions and backed by saved database
  writes.
- `/admin/` is protected behind admin authentication and exposes registered
  business tables through Flask-Admin for local/internal development work.
- CI runs pytest on Python 3.10 and 3.12, CodeQL analysis, dependency review
  on pull requests, an accessibility smoke check in Chromium, and a Gitleaks
  secret scan on pushes and pull requests.
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
$env:APP_RUNTIME = "demo-dev"
flask --app shyne.py init-db
python shyne.py
```

## Seeded Demo Accounts

`flask --app shyne.py init-db` seeds these deterministic example users:

- `superadmin@demo.com` / `demo` — `Superadmin`
- `staffoperator@demo.com` / `demo` — `Staff Operator`
- `inventoryproduction@demo.com` / `demo` — `Inventory / Production`
- `devadmin@demo.com` / `demo` — `Dev Admin`

Use these accounts for local demo and development only. `Dev Admin` remains
hidden from the `Users & Access` table and is the only seeded role that can
open `/admin/`.

Optional variables:

- `APP_RUNTIME=demo-dev|live-prod`
- `DATABASE_URL`
- `AUTH_DATABASE_URL`
- `SHYNE_LOG_DIR` to override the default `instance/logs` directory
- `DISABLE_FILE_LOGGING=true` to disable the rotating file logger
- `FLASK_DEBUG=true` for debugging only
- `SESSION_COOKIE_SECURE=true` for HTTPS
- `TRUST_PROXY_HEADERS=true` only when the app is behind a trusted reverse proxy

Unset runtime means demo. Live requires explicit `APP_RUNTIME=live-prod`.

## Internal Launch Guidance

For restricted internal staff use, prefer the schema-only bootstrap path and a
Linux WSGI server behind a reverse proxy instead of the Flask development server.

Recommended bootstrap:

1. Set a non-demo `SECRET_KEY` outside git.
2. Set `APP_RUNTIME=live-prod`.
3. Run `flask --app shyne.py init-live-db`.
4. Create the first business admin with
   `flask --app shyne.py create-admin --email owner@shynebeauty.com`.
5. Create a hidden technical admin only if you need Flask-Admin access:
   `flask --app shyne.py create-dev-admin --email tech@shynebeauty.com`.
6. Launch the app with Gunicorn behind nginx or Caddy:

```bash
APP_RUNTIME=live-prod gunicorn --bind 127.0.0.1:8000 shyne:app
```

Notes:

- `python shyne.py` remains the development server path only and defaults to
  `APP_RUNTIME=demo-dev` when `APP_RUNTIME` is unset.
- Unset runtime means demo. Live requires explicit `APP_RUNTIME=live-prod`.
- `init-db` is destructive and reseeds demo data; do not run it against live
  operator data.
- When `DATABASE_URL` and `AUTH_DATABASE_URL` are not overridden, runtime mode
  selects the default SQLite files under `instance/`:
  - `demo-dev` -> `instance/shynebeauty_demo.db`,
    `instance/shynebeauty_demo_auth.db`
  - `live-prod` -> `instance/shynebeauty_live.db`,
    `instance/shynebeauty_live_auth.db`
- Set `SESSION_COOKIE_SECURE=true` when the app is served over HTTPS.
- Runtime-sensitive defaults:
  - `demo-dev` defaults `SESSION_COOKIE_SECURE=False`
  - `live-prod` defaults `SESSION_COOKIE_SECURE=True`
  - `TRUST_PROXY_HEADERS` defaults `False` in both modes unless explicitly set
  - `ENABLE_DEV_TEST_ADMIN` is forced off in `live-prod`
  - `FLASK_DEBUG` must not be enabled in `live-prod`
- `create-admin` and `create-dev-admin` enforce the password policy used by the
  web flows: minimum 12 characters, no email-address fragments, and no demo or
  common fallback credentials.
- MFA is optional for all accounts. Temporary-password onboarding can opt into
  MFA during the first `/change-password` flow, and authenticated users can
  manage password changes and MFA from `/account/settings`.

## Backup And Restore

- Primary owner: business `Superadmin`
- Secondary owner: `Dev Admin` / technical maintainer
- Cadence:
  - weekly paired backup of both SQLite files
  - extra backup before schema, auth, or admin-access changes
  - monthly restore drill against a non-live copy
- Pre-backup checks:
  - confirm which database paths are active
  - stop the app or place it in a maintenance window before copying files
- Back up both databases together:
  - `instance/shynebeauty.db`
  - `instance/shynebeauty_auth.db`
- Restore steps:
  - stop the app
  - copy the current live pair aside as a rollback snapshot
  - replace both database files as a matched pair
  - restart the app
- Post-restore verification:
  - confirm `/login` loads
  - confirm a known admin account can sign in
  - confirm `/orders` and `/users` render without schema errors
  - confirm the auth database still contains `admin_users`, `admin_access_events`,
    and `admin_login_throttles`
- If restore validation fails, roll back to the pre-restore snapshot and
  escalate to the technical maintainer before further writes occur.
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
APP_RUNTIME=demo-dev ./.venv/bin/python -m pytest -q -m "not a11y_smoke"
```

Run the Playwright accessibility smoke suite separately:

```bash
APP_RUNTIME=demo-dev ./.venv/bin/python -m pytest -q tests/test_accessibility_smoke.py
```

GitHub Actions workflows:

- `.github/workflows/pytest.yml` runs pytest on Python 3.10 and 3.12
- the generic pytest matrix excludes the `a11y_smoke` marker so browser-only
  checks do not run without Playwright Chromium installed
- `.github/workflows/pytest.yml` runs Playwright-based accessibility smoke
  coverage for `/login`, `/`, `/orders`, and `/account/settings` in
  the dedicated `a11y-smoke` job after installing Chromium
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

- `shyne.py`: compatibility facade that preserves the public app/module entrypoints
- `shyne_app/`: internal package containing config, models, auth, access,
  admin, routes, and CLI modules
- `templates/`: Jinja templates for the current UI surfaces
- `static/`: shared frontend assets such as `shyneIcon.png`
- `tests/`: pytest coverage for auth, CSRF, protected routes, create workflows,
  CLI commands, and model behavior
- `schema.sql`: reference schema for the business tables
- `requirements.txt`: runtime and test dependencies
- `.github/workflows/`: CI and code-scanning workflows
