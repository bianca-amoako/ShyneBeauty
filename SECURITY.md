# Security Review

This document captures the current security posture of the ShyneBeauty admin
login flow and the highest-priority follow-up risks for the tracked repository
state.

## Scope

- Admin login and logout routes in `shyne.py`
- Protected admin pages: `/`, `/orders`, `/tasks`, `/admin/`
- The `AdminUser` identity model and `create-admin` CLI workflow
- The tracked login UI and related pytest coverage

## Controls Currently In Place

- Admin identities are stored separately from the main business tables by using
  a dedicated auth database bind.
- Passwords are hashed with Werkzeug helpers and never stored in plain text.
- Email addresses are normalized before lookup and persisted uniquely.
- Login failures use a generic error message to reduce account enumeration.
- Safe redirect validation rejects non-local `next` targets.
- Account lockout activates after repeated failed logins.
- Session and remember cookies are configured as `HttpOnly` and `SameSite=Lax`.
- Authenticated pages and the login route now send a small header baseline:
  `Cache-Control: no-store`, `Referrer-Policy: same-origin`,
  `X-Content-Type-Options: nosniff`, and `X-Frame-Options: SAMEORIGIN`.
- `python shyne.py` no longer enables debug mode or runs schema bootstrap
  automatically; local debugging now requires `FLASK_DEBUG=true` explicitly.

## Findings

### High

- CSRF protection is not implemented for `/login`, `/logout`, or other admin
  form posts. This leaves authenticated browser sessions exposed to cross-site
  request forgery.
- Authorization is still coarse-grained. Any active admin account can access
  the full Flask-Admin surface and its data export capabilities.

### Medium

- `SESSION_COOKIE_SECURE` remains deployment-controlled. If HTTPS deployments
  are misconfigured and the flag is left off, session and remember cookies can
  travel over insecure transport.
- The current brute-force control is account-based only. There is no IP-aware
  or device-aware throttling.
- MFA, audit logging, and self-service recovery flows are not implemented.
- Authenticated pages still depend on third-party CDN assets, and the app does
  not yet send a Content Security Policy.
- Session lifetime and remember-me duration still rely on framework defaults
  instead of an explicit deployment policy.
- Password strength requirements are not enforced during admin creation.

### Low

- The current Flask-Login dependency still emits a remember-cookie deprecation
  warning under pytest. This did not block the auth review, but the dependency
  should be upgraded or patched in a future maintenance pass.

## Changes Made In This Pass

- Added tracked security documentation to the repository.
- Added a response-header baseline for auth and admin responses.
- Removed implicit debug startup and automatic schema creation from the normal
  `python shyne.py` path.
- Expanded pytest coverage for inactive admins, remember-cookie behavior,
  expired lockout recovery, and security headers.

## Verification

- Local auth regression suite: `.\.venv-windows\Scripts\python.exe -m pytest -q`
- GitHub Actions workflows present:
  - `.github/workflows/pytest.yml`
  - `.github/workflows/codeql.yml`

## Recommended Next Steps

1. Add CSRF protection for all auth and admin mutation forms.
2. Introduce admin roles or scoped permissions for Flask-Admin access.
3. Enforce HTTPS cookie settings in deployed environments and document the
   expected runtime configuration.
4. Replace CDN-hosted authenticated-page assets or add a CSP once asset loading
   is finalized.
5. Add audit logging, stronger password rules, and a defined MFA plan before
   broader internal rollout.
