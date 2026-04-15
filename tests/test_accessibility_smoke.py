import threading
from contextlib import contextmanager

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


@contextmanager
def live_server():
    flask_app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)

    with flask_app.app_context():
        db.drop_all(bind_key="__all__")
        db.create_all(bind_key="__all__")
        admin_user = AdminUser(
            email="a11y-admin@shynebeauty.com",
            full_name="Accessibility Admin",
        )
        admin_user.set_password("ValidPassw0rd!")
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
        server.shutdown()
        thread.join(timeout=5)
        with flask_app.app_context():
            db.session.remove()
            db.drop_all(bind_key="__all__")


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
                if "libasound.so.2" in str(exc):
                    pytest.skip(
                        "Playwright Chromium runtime deps are unavailable locally; CI installs them with --with-deps."
                    )
                raise
            page = browser.new_page()

            if requires_login:
                page.goto(f"{base_url}/login", wait_until="networkidle")
                page.fill('input[name="email"]', "a11y-admin@shynebeauty.com")
                page.fill('input[name="password"]', "ValidPassw0rd!")
                page.click('button[type="submit"]')
                page.wait_for_load_state("networkidle")

            page.goto(f"{base_url}{path}", wait_until="networkidle")

            findings = collect_accessibility_findings(page)
            assert findings == []

            if requires_login:
                assert page.locator('a[href="#main-content"]').count() == 1

            browser.close()
