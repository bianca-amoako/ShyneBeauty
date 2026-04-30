# Security Policy

## Supported Versions

ShyneBeauty is an internal Flask operations app. Only the latest code on `main` is supported.

## Implemented Controls

### Authentication

- Admin authentication is handled by `shyne_app.routes.login()` against `shyne_app.models.AdminUser` on the auth bind (`AUTH_BIND_KEY = "auth"`).
- Passwords are hashed with Werkzeug using `PASSWORD_HASH_METHOD = "pbkdf2:sha256:1000000"` in `shyne_app/config.py`.
- Password policy is enforced by `shyne_app.config.password_policy_errors()`:
  - minimum 12 characters
  - must not contain email-address fragments
  - must not match common or demo fallback credentials
  - must differ from the current temporary password when applicable
- Account lockout is enforced in `shyne_app.models.AdminUser.register_failed_login()` using `FAILED_LOGIN_THRESHOLD = 5` and `ACCOUNT_LOCK_DURATION = timedelta(minutes=15)` from `shyne_app/config.py`.
- IP-based login throttling is also enforced through `shyne_app.models.AdminLoginThrottle`.

### Session management

- Flask-Login session handling is initialized in `shyne_app/extensions.py` and configured in `shyne_app/app.py`.
- Cookie settings in `shyne_app/app.py`:
  - `SESSION_COOKIE_HTTPONLY = True`
  - `SESSION_COOKIE_SAMESITE = "Lax"`
  - `SESSION_COOKIE_SECURE` defaults to `False` in `demo-dev` and `True` in `live-prod`
  - `REMEMBER_COOKIE_HTTPONLY = True`
  - `REMEMBER_COOKIE_SAMESITE = "Lax"`
  - `REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE`
- Revoked or incompatible sessions are cleared in `shyne_app.auth.invalidate_revoked_authenticated_session()` and `shyne_app.auth.revoke_authenticated_session()`.
- Forced first-login password rotation is enforced by `shyne_app.auth.enforce_password_change()` and `AdminUser.must_change_password`.
- HTTPS upgrades are enforced by `shyne_app.auth.enforce_https()` when `APP_RUNTIME` is `live-prod` and `TRUST_PROXY_HEADERS` is enabled.

### CSRF

- Global CSRF protection is enabled with `flask_wtf.csrf.CSRFProtect` in `shyne_app/extensions.py` via `csrf = CSRFProtect()` and `csrf.init_app(flask_app)`.
- `shyne_app/app.py` sets `WTF_CSRF_ENABLED = True`.
- The login form includes a CSRF token via `templates/_form_helpers.html` and `templates/login.html`:
  - `_form_helpers.html` defines `csrf_input()`
  - `login.html` calls `{{ csrf_input() }}`
- Authenticated POST forms such as `templates/change_password.html`, `templates/users.html`, `templates/account_settings.html`, `templates/mfa_challenge.html`, and `templates/mfa_enroll.html` also use the same helper.

### Rate limiting

- Request throttling is implemented in-memory in `shyne_app/rate_limit.py`.
- Enforcement happens in `shyne_app.auth.enforce_rate_limits()` before route execution.
- Sensitive POST paths covered by `_SENSITIVE_POST_PATHS`:
  - `/change-password`
  - `/account/settings`
  - `/login`
  - `/users/invite`
- Additional sensitive POST patterns covered by `_SENSITIVE_POST_PATH_PATTERNS`:
  - `/users/<id>/temporary-password`
  - `/users/<id>/resend-invite`
- `/admin` traffic is separately rate-limited by prefix match in `check_rate_limit()`.
- Current limiter characteristics:
  - 30 requests per minute for sensitive POST buckets
  - 60 requests per minute for `/admin` buckets
  - per-process memory storage using `_RateLimiter`

### RBAC and audit

- Role-to-permission mapping is defined in `shyne_app.config.ROLE_PERMISSION_MAP`.
- Permission checks are evaluated by `shyne_app.access.has_permission()`.
- Route-level enforcement is performed by `shyne_app.access.require_permission()`.
- Technical console access at `/admin/` is gated by `PERMISSION_ADMIN_CONSOLE_ACCESS` in `shyne_app/admin.py`.
- Business user management routes are gated by `PERMISSION_USERS_MANAGE` in `shyne_app/routes.py`.
- Persistent access and lifecycle audit rows are stored in the auth database:
  - `shyne_app.models.AdminAccessEvent`
  - table name: `admin_access_events`
- `AdminAccessEvent` is used for permission denials and user lifecycle actions such as invite creation, invite resend, invite cancellation, activation, account creation, temporary-password reset, password change, role change, and status change.
- Persistent login audit rows are stored in `shyne_app.models.AdminLoginEvent`:
  - table name: `admin_login_events`
  - recorded columns include `email`, `ip`, `success`, `failure_reason`, `user_agent`, and `created_at`
- Login events are written from `shyne_app.routes._record_login_event()` for successful logins, bad credentials, account lockouts, IP throttle lockouts, and MFA-pending logins.

### Security headers

- Baseline headers are defined in `shyne_app.config.SECURITY_HEADERS` and applied in `shyne_app.auth.add_security_headers()`.
- Current baseline includes:
  - `Content-Security-Policy`
  - `Referrer-Policy: same-origin`
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: SAMEORIGIN`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains` is added only when `APP_RUNTIME` is `live-prod`.
- Authenticated and selected auth endpoints are marked `Cache-Control: no-store` and `Pragma: no-cache` via `NO_STORE_ENDPOINTS` and `add_security_headers()`.

### MFA

- Optional TOTP MFA is implemented with `pyotp` in `shyne_app.models.AdminUser` and the `/mfa/challenge` and `/mfa/enroll` flows in `shyne_app/routes.py`.
- Elevated roles are defined by `shyne_app.access.MFA_REQUIRED_ROLES`:
  - `Superadmin`
  - `Dev Admin`
- Users in those roles are nudged to enroll when `user_should_be_nudged_to_enroll_mfa()` returns true, which currently means:
  - the role is in `MFA_REQUIRED_ROLES`
  - MFA is not enabled
  - `mfa_enroll_dismissed_at` is still `NULL`
- The enrollment page explicitly allows deferral. The `Skip for now` action in `templates/mfa_enroll.html` sets `AdminUser.mfa_enroll_dismissed_at` in `shyne_app.routes.mfa_enroll()`.
- MFA is encouraged for elevated access but is not mandatory in v1.

## Known Limitations / Post-v1 Roadmap

- Flask-Admin CRUD and export actions in `shyne_app/admin.py` do not emit `AdminAccessEvent` rows for every action.
- Schema evolution is still handled with ad hoc compatibility helpers such as `ensure_admin_user_access_columns()`, `ensure_customer_source_column()`, and `ensure_runtime_auth_schema_compatibility()` in `shyne_app/models.py`. There is no migration framework such as Alembic yet.
- Some permission keys are defined but not currently used to gate any route:
  - `shipping.view`
  - `shipping.edit`
  - `reports.view`
  - `users.view`
- `shyne_app/rate_limit.py` uses in-memory per-process buckets. Multi-worker or multi-instance production deployments should move to a shared backend such as Redis.

## Environment Hardening Checklist

- Set a strong `SECRET_KEY` outside git. `shyne_app/app.py` expects it to be present and recommends generating one with `python -c "import secrets; print(secrets.token_hex(32))"`.
- Use a unique `SECRET_KEY` per environment.
- Run production with `APP_RUNTIME=live-prod`.
- Set `SESSION_COOKIE_SECURE=true` in production and serve the app only over HTTPS.
- If the app is behind a TLS-terminating proxy, set `TRUST_PROXY_HEADERS=true` so `shyne_app.auth.enforce_https()` can trust `X-Forwarded-Proto`.
- Confirm `ENABLE_DEV_TEST_ADMIN` is never enabled in production. `shyne_app/app.py` forces it off in `live-prod`, but operators should still verify the environment.
- Back up both active database files together:
  - default `demo-dev`: `instance/shynebeauty_demo.db` and `instance/shynebeauty_demo_auth.db`
  - default `live-prod`: `instance/shynebeauty_live.db` and `instance/shynebeauty_live_auth.db`
  - if `DATABASE_URL` or `AUTH_DATABASE_URL` overrides are used, back up those paths instead
- Review `admin_login_events` and `admin_access_events` on a fixed cadence for failed logins, permission denials, and unexpected account lifecycle changes.
