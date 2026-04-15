import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright
from werkzeug.serving import make_server

from shyne import (
    ACCOUNT_STATUS_ACTIVE,
    ROLE_SUPERADMIN,
    AdminUser,
    app as flask_app,
    db,
    utc_now,
)

A11Y_ADMIN_EMAIL = "a11y-admin@shynebeauty.com"
A11Y_ADMIN_PASSWORD = "ValidPassw0rd!"


def configure_test_database_uris(primary_uri, auth_uri):
    flask_app.config["SQLALCHEMY_DATABASE_URI"] = primary_uri
    flask_app.config["SQLALCHEMY_BINDS"] = {"auth": auth_uri}

    engines = db._app_engines[flask_app]
    for engine in engines.values():
        engine.dispose()
    engines.clear()

    echo = flask_app.config.get("SQLALCHEMY_ECHO", False)
    for bind_key, uri in ((None, primary_uri), ("auth", auth_uri)):
        options = {"url": uri, "echo": echo, "echo_pool": echo}
        db._make_metadata(bind_key)
        db._apply_driver_defaults(options, flask_app)
        engines[bind_key] = db._make_engine(bind_key, options, flask_app)


@contextmanager
def live_server():
    original_primary_uri = flask_app.config["SQLALCHEMY_DATABASE_URI"]
    original_auth_uri = flask_app.config["SQLALCHEMY_BINDS"]["auth"]
    server = None
    thread = None

    with tempfile.TemporaryDirectory(prefix="shynebeauty-a11y-") as tmp_dir:
        tmp_path = Path(tmp_dir)
        primary_uri = f"sqlite:///{(tmp_path / 'primary.db').as_posix()}"
        auth_uri = f"sqlite:///{(tmp_path / 'auth.db').as_posix()}"

        flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        configure_test_database_uris(primary_uri, auth_uri)

        with flask_app.app_context():
            db.session.remove()
            db.drop_all(bind_key="__all__")
            db.create_all(bind_key="__all__")
            admin_user = AdminUser(
                email=A11Y_ADMIN_EMAIL,
                full_name="Accessibility Admin",
            )
            admin_user.set_password(A11Y_ADMIN_PASSWORD)
            admin_user.set_role(ROLE_SUPERADMIN, now=utc_now())
            admin_user.set_account_status(ACCOUNT_STATUS_ACTIVE, now=utc_now())
            db.session.add(admin_user)
            db.session.commit()

        server = make_server("127.0.0.1", 0, flask_app)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}"
        finally:
            if server is not None:
                server.shutdown()
            if thread is not None:
                thread.join(timeout=5)
            with flask_app.app_context():
                db.session.remove()
                db.drop_all(bind_key="__all__")
            configure_test_database_uris(original_primary_uri, original_auth_uri)


def collect_accessibility_findings(page):
    return page.evaluate(
        """
        () => {
          const findings = [];

          if (!document.querySelector("main")) {
            findings.push("missing-main");
          }
          if (!document.querySelector("h1")) {
            findings.push("missing-h1");
          }

          const unlabeledFields = [...document.querySelectorAll("input, select, textarea")]
            .filter((field) => {
              if (field.type === "hidden") return false;
              const id = field.getAttribute("id");
              const ariaLabel = field.getAttribute("aria-label");
              const ariaLabelledBy = field.getAttribute("aria-labelledby");
              const wrappedByLabel = !!field.closest("label");
              const explicitLabel = id
                ? !!document.querySelector(`label[for="${id}"]`)
                : false;
              return !(wrappedByLabel || explicitLabel || ariaLabel || ariaLabelledBy);
            })
            .map((field) => field.getAttribute("name") || field.getAttribute("id") || field.tagName);

          findings.push(...unlabeledFields.map((name) => `unlabeled-field:${name}`));

          const imageWithoutAlt = [...document.querySelectorAll("img")]
            .filter((image) => !image.hasAttribute("alt"))
            .map((image) => image.getAttribute("src") || "img");

          findings.push(...imageWithoutAlt.map((name) => `img-missing-alt:${name}`));

          return findings;
        }
        """
    )


@pytest.mark.a11y_smoke
@pytest.mark.parametrize(
    ("path", "requires_login"),
    [
        ("/login", False),
        ("/", True),
        ("/orders", True),
        ("/tasks", True),
        ("/account/settings", True),
    ],
)
def test_accessibility_smoke(path, requires_login):
    with live_server() as base_url:
        with sync_playwright() as playwright:
            try:
                browser = playwright.chromium.launch()
            except PlaywrightError as exc:
                if (
                    "Executable doesn't exist" in str(exc)
                    or "Please run the following command to download new browsers" in str(exc)
                    or "libasound.so.2" in str(exc)
                ):
                    pytest.skip(
                        "Playwright Chromium is unavailable locally; install browsers or rely on the dedicated CI a11y-smoke job."
                    )
                raise
            page = browser.new_page()

            if requires_login:
                page.goto(f"{base_url}/login", wait_until="networkidle")
                page.fill('input[name="email"]', A11Y_ADMIN_EMAIL)
                page.fill('input[name="password"]', A11Y_ADMIN_PASSWORD)
                page.click('button[type="submit"]')
                page.wait_for_load_state("networkidle")

            page.goto(f"{base_url}{path}", wait_until="networkidle")

            findings = collect_accessibility_findings(page)
            assert findings == []

            if requires_login:
                assert page.locator('a[href="#main-content"]').count() == 1

            browser.close()
