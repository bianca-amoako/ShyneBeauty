from datetime import datetime, timedelta, timezone

import pyotp
import pytest
from sqlalchemy import inspect, select, text

from shyne import (
    AUTH_BIND_KEY,
    ACCOUNT_STATUS_ACTIVE,
    ACCOUNT_STATUS_SUSPENDED,
    AdminLoginThrottle,
    AdminUser,
    HTML_CONTENT_SECURITY_POLICY,
    IP_LOGIN_FAILURE_THRESHOLD,
    ROLE_STAFF_OPERATOR,
    ROLE_SUPERADMIN,
    db,
    utc_now,
)


@pytest.mark.parametrize(
    "route", ["/", "/orders", "/tasks", "/customers", "/inventory", "/users", "/admin/"]
)
def test_anonymous_access_to_protected_routes_redirects_to_login(client, route):
    response = client.get(route)

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/login?next={route}")


def test_login_route_sets_security_headers(client):
    response = client.get("/login")

    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["Content-Security-Policy"] == HTML_CONTENT_SECURITY_POLICY
    assert response.headers["Referrer-Policy"] == "same-origin"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN"


def test_login_and_authenticated_shell_use_local_font_assets(client, admin_user, login):
    login_response = client.get("/login")

    assert b"fonts.googleapis.com" not in login_response.data
    assert b"fonts.gstatic.com" not in login_response.data
    assert b"/static/css/fonts.css" in login_response.data

    login(client)
    shell_response = client.get("/orders")

    assert b"fonts.googleapis.com" not in shell_response.data
    assert b"fonts.gstatic.com" not in shell_response.data
    assert b"/static/css/fonts.css" in shell_response.data


def test_login_rejects_missing_csrf_token(csrf_client, admin_user):
    response = csrf_client.post(
        "/login",
        data={
            "email": "admin@shynebeauty.com",
            "password": "correct-horse-battery-staple",
        },
    )

    assert response.status_code == 400
    assert b"CSRF" in response.data


def test_login_route_rejects_missing_credentials_with_feedback(client):
    response = client.post("/login", data={"email": "", "password": ""})

    assert response.status_code == 200
    assert b"Email is required." in response.data
    assert b"Password is required." in response.data


def test_valid_login_succeeds_and_resets_login_state(client, admin_user, app, login):
    client.post(
        "/login",
        data={
            "email": "admin@shynebeauty.com",
            "password": "wrong-password",
        },
    )
    client.post(
        "/login",
        data={
            "email": "admin@shynebeauty.com",
            "password": "wrong-password",
        },
    )

    with client.session_transaction() as session_data:
        session_data["pre_auth_marker"] = "clear-me"

    response = login(client, remember_me=True, next_url="/orders")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/orders")

    with client.session_transaction() as session_data:
        assert "pre_auth_marker" not in session_data
        assert session_data.get("_user_id") == str(admin_user)

    with app.app_context():
        row = db.session.execute(
            select(
                AdminUser.failed_login_count,
                AdminUser.locked_until,
                AdminUser.last_login_at,
            ).where(AdminUser.id == admin_user)
        ).one()
        assert row.failed_login_count == 0
        assert row.locked_until is None
        assert row.last_login_at is not None


def test_login_with_remember_me_sets_cookie_flags(client, admin_user, login):
    response = login(client, remember_me=True)

    remember_cookie = next(
        header
        for header in response.headers.getlist("Set-Cookie")
        if header.startswith("remember_token=")
    )

    assert "HttpOnly" in remember_cookie
    assert "SameSite=Lax" in remember_cookie


@pytest.mark.parametrize(
    ("email", "password"),
    [
        ("admin@shynebeauty.com", "wrong-password"),
        ("missing@shynebeauty.com", "wrong-password"),
    ],
)
def test_invalid_credentials_show_generic_error(client, admin_user, email, password):
    response = client.post("/login", data={"email": email, "password": password})

    assert response.status_code == 200
    assert b"Invalid email or password." in response.data


def test_unknown_credentials_are_rejected(client):
    response = client.post("/login", data={"email": "admin", "password": "admin"})

    assert response.status_code == 200
    assert b"Invalid email or password." in response.data


def test_authenticated_shell_includes_skip_link_and_live_region(
    client, admin_user, login
):
    login(client)

    response = client.get("/orders")

    assert response.status_code == 200
    assert b'href="#main-content"' in response.data
    assert b'<main class="sb-main" id="main-content">' in response.data
    assert b'<nav class="sb-sidebar"' in response.data


def test_inactive_admin_cannot_log_in(client, app, login):
    with app.app_context():
        user = AdminUser(
            email="inactive@shynebeauty.com",
            full_name="Inactive Admin",
            is_active=False,
        )
        user.set_password("correct-horse-battery-staple")
        db.session.add(user)
        db.session.commit()
        db.session.remove()

    response = login(client, email="inactive@shynebeauty.com")

    assert response.status_code == 200
    assert b"Invalid email or password." in response.data

    with client.session_transaction() as session_data:
        assert "_user_id" not in session_data


def test_open_redirect_attempts_are_ignored(client, admin_user, login):
    response = login(client, next_url="https://evil.example/phish")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")


@pytest.mark.parametrize(
    "next_url",
    [
        "//evil.example/phish",
        "/\\evil.example/phish",
        "https:/evil.example/phish",
        "https:///evil.example/phish",
    ],
)
def test_malformed_next_targets_are_ignored(client, admin_user, login, next_url):
    response = login(client, next_url=next_url)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")


def test_internal_next_targets_with_query_params_are_allowed(client, admin_user, login):
    response = login(client, next_url="/orders?status=open")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/orders?status=open")


def test_backslash_next_targets_are_normalized_when_safe(client, admin_user, login):
    response = login(client, next_url="\\orders?status=open")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/orders?status=open")


def test_authenticated_users_are_redirected_away_from_login(
    client, admin_user, login
):
    login(client)

    response = client.get("/login")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")


def test_logout_requires_post(client):
    response = client.get("/logout")

    assert response.status_code == 405


def test_logout_clears_authentication(client, admin_user, login):
    login(client, remember_me=True)

    response = client.post("/logout")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")

    with client.session_transaction() as session_data:
        assert "_user_id" not in session_data

    protected_response = client.get("/")
    assert protected_response.status_code == 302
    assert "/login?next=" in protected_response.headers["Location"]

    remember_cookie = next(
        header
        for header in response.headers.getlist("Set-Cookie")
        if header.startswith("remember_token=")
    )
    assert "Expires=Thu, 01 Jan 1970" in remember_cookie


def test_logout_rejects_missing_csrf_token(csrf_client, admin_user, login):
    login(csrf_client)

    response = csrf_client.post("/logout", follow_redirects=False)

    assert response.status_code == 302

    protected_response = csrf_client.get("/")
    assert protected_response.status_code == 200


def test_logout_missing_csrf_redirects_to_same_origin_referrer(
    csrf_client, admin_user, login
):
    login(csrf_client)

    response = csrf_client.post(
        "/logout",
        headers={"Referer": "http://localhost/orders?status=open"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/orders?status=open")

    protected_response = csrf_client.get("/")
    assert protected_response.status_code == 200


def test_logout_missing_csrf_rejects_external_referrer(
    csrf_client, admin_user, login
):
    login(csrf_client)

    response = csrf_client.post(
        "/logout",
        headers={"Referer": "https://evil.example/phish"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")

    protected_response = csrf_client.get("/")
    assert protected_response.status_code == 200


@pytest.mark.parametrize(
    "referer",
    [
        "//evil.example/phish",
        "http://localhost\\orders?status=open",
        "https:///evil.example/phish",
    ],
)
def test_logout_missing_csrf_rejects_malformed_referrers(
    csrf_client, admin_user, login, referer
):
    login(csrf_client)

    response = csrf_client.post(
        "/logout",
        headers={"Referer": referer},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")

    protected_response = csrf_client.get("/")
    assert protected_response.status_code == 200


def test_lockout_triggers_after_repeated_failed_attempts(client, admin_user, app, login):
    for _ in range(5):
        response = client.post(
            "/login",
            data={
                "email": "admin@shynebeauty.com",
                "password": "wrong-password",
            },
        )
        assert response.status_code == 200
        assert b"Invalid email or password." in response.data

    with app.app_context():
        refreshed_user = db.session.get(AdminUser, admin_user)
        assert refreshed_user.failed_login_count == 5
        assert refreshed_user.locked_until is not None

    locked_response = login(client)

    assert locked_response.status_code == 200
    assert b"Invalid email or password." in locked_response.data


def test_expired_lockout_allows_login_again(client, admin_user, app, login):
    user_id = admin_user

    with app.app_context():
        user = db.session.get(AdminUser, user_id)
        user.failed_login_count = 5
        user.locked_until = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.session.commit()

    response = login(client)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")

    with app.app_context():
        row = db.session.execute(
            select(
                AdminUser.failed_login_count,
                AdminUser.locked_until,
            ).where(AdminUser.id == user_id)
        ).one()
        assert row.failed_login_count == 0
        assert row.locked_until is None


def test_seeded_superadmin_can_log_in_after_init_db(client, app):
    runner = app.test_cli_runner()
    result = runner.invoke(args=["init-db"])

    assert result.exit_code == 0

    response = client.post(
        "/login",
        data={
            "email": "olivia.mercer@shynebeauty.com",
            "password": "ShyneDemoSuper1!",
            "next": "/users",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/users")

    with app.app_context():
        user = AdminUser.query.filter_by(email="olivia.mercer@shynebeauty.com").one()
        user_id = user.id
        assert user.last_login_at is not None

    with client.session_transaction() as session_data:
        assert session_data.get("_user_id") == str(user_id)

    protected_response = client.get("/users")
    assert protected_response.status_code == 200
    assert b"Users & Access" in protected_response.data


def test_seeded_dev_admin_can_access_admin_console_after_init_db(client, app):
    runner = app.test_cli_runner()
    result = runner.invoke(args=["init-db"])

    assert result.exit_code == 0

    response = client.post(
        "/login",
        data={
            "email": "devops@shynebeauty.com",
            "password": "ShyneDemoDev1!",
            "next": "/admin/",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/admin/")

    admin_response = client.get("/admin/")
    assert admin_response.status_code == 200
    assert b"ShyneBeauty Admin" in admin_response.data


def test_business_role_seeded_by_init_db_cannot_access_admin_console(client, app):
    runner = app.test_cli_runner()
    result = runner.invoke(args=["init-db"])

    assert result.exit_code == 0

    login_response = client.post(
        "/login",
        data={
            "email": "maya.brooks@shynebeauty.com",
            "password": "ShyneDemoStaff1!",
        },
    )
    assert login_response.status_code == 302

    admin_response = client.get("/admin/")
    assert admin_response.status_code == 403
    assert b"Admin console access denied" in admin_response.data


def test_seeded_demo_user_still_locks_after_repeated_failed_attempts(client, app):
    runner = app.test_cli_runner()
    result = runner.invoke(args=["init-db"])

    assert result.exit_code == 0

    for _ in range(5):
        response = client.post(
            "/login",
            data={
                "email": "devops@shynebeauty.com",
                "password": "wrong-password",
            },
        )
        assert response.status_code == 200
        assert b"Invalid email or password." in response.data

    with app.app_context():
        user = AdminUser.query.filter_by(email="devops@shynebeauty.com").one()
        assert user.failed_login_count == 5
        assert user.locked_until is not None

    locked_response = client.post(
        "/login",
        data={
            "email": "devops@shynebeauty.com",
            "password": "ShyneDemoDev1!",
        },
    )

    assert locked_response.status_code == 200
    assert b"Invalid email or password." in locked_response.data


@pytest.mark.parametrize(
    ("route", "expected_text"),
    [
        ("/", b"Dashboard"),
        ("/orders", b"Manage Orders"),
        ("/tasks", b"Tasks"),
        ("/customers", b"Customer Database"),
        ("/inventory", b"Inventory"),
        ("/users", b"Users & Access"),
    ],
)
def test_authenticated_users_can_reach_protected_routes(
    client, admin_user, login, route, expected_text
):
    login(client)

    response = client.get(route)

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.content_type.startswith("text/html")
    assert expected_text in response.data


def test_temporary_password_login_redirects_to_forced_password_change(
    client, admin_factory, login
):
    admin_factory(
        email="temp-user@shynebeauty.com",
        full_name="Temp User",
        role=ROLE_STAFF_OPERATOR,
        account_status=ACCOUNT_STATUS_ACTIVE,
        must_change_password=True,
        password="TempPassw0rd!",
    )

    response = login(
        client,
        email="temp-user@shynebeauty.com",
        password="TempPassw0rd!",
        next_url="/orders",
    )

    assert response.status_code == 302
    assert "/change-password" in response.headers["Location"]
    assert "next=/orders" in response.headers["Location"]


@pytest.mark.parametrize("route", ["/", "/orders", "/customers", "/tasks", "/inventory", "/users", "/admin/"])
def test_users_with_temporary_password_are_redirected_until_password_changes(
    client, admin_factory, login, route
):
    admin_factory(
        email="temp-lock@shynebeauty.com",
        full_name="Temp Lock",
        role=ROLE_SUPERADMIN,
        account_status=ACCOUNT_STATUS_ACTIVE,
        must_change_password=True,
        password="TempPassw0rd!",
    )
    login(
        client,
        email="temp-lock@shynebeauty.com",
        password="TempPassw0rd!",
    )

    response = client.get(route)

    assert response.status_code == 302
    assert "/change-password" in response.headers["Location"]


def test_forced_password_change_clears_requirement_and_restores_access(
    client, admin_factory, app, login
):
    user = admin_factory(
        email="temp-clear@shynebeauty.com",
        full_name="Temp Clear",
        role=ROLE_STAFF_OPERATOR,
        account_status=ACCOUNT_STATUS_ACTIVE,
        must_change_password=True,
        password="TempPassw0rd!",
    )

    login(
        client,
        email="temp-clear@shynebeauty.com",
        password="TempPassw0rd!",
    )

    response = client.post(
        "/change-password?next=/orders",
        data={
            "password": "BrandNewPassw0rd!",
            "password_confirmation": "BrandNewPassw0rd!",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/orders")

    with app.app_context():
        refreshed_user = db.session.get(AdminUser, user.id)
        assert refreshed_user.requires_password_change() is False
        assert refreshed_user.check_password("BrandNewPassw0rd!") is True


def test_suspended_user_with_temporary_password_is_logged_out_before_password_change(
    client, admin_factory, app, login
):
    user = admin_factory(
        email="temp-suspended@shynebeauty.com",
        full_name="Temp Suspended",
        role=ROLE_STAFF_OPERATOR,
        account_status=ACCOUNT_STATUS_ACTIVE,
        must_change_password=True,
        password="TempPassw0rd!",
    )

    login(
        client,
        email="temp-suspended@shynebeauty.com",
        password="TempPassw0rd!",
    )

    with app.app_context():
        refreshed_user = db.session.get(AdminUser, user.id)
        refreshed_user.set_account_status(ACCOUNT_STATUS_SUSPENDED, now=utc_now())
        db.session.commit()

    response = client.post(
        "/change-password?next=/orders",
        data={
            "password": "BrandNewPassw0rd!",
            "password_confirmation": "BrandNewPassw0rd!",
        },
    )

    assert response.status_code == 302
    assert "/login" in response.headers["Location"]

    with app.app_context():
        refreshed_user = db.session.get(AdminUser, user.id)
        assert refreshed_user.requires_password_change() is True
        assert refreshed_user.check_password("BrandNewPassw0rd!") is False


def test_forced_password_change_rejects_missing_csrf_token(
    csrf_client, admin_factory, app, login
):
    user = admin_factory(
        email="temp-csrf@shynebeauty.com",
        full_name="Temp Csrf",
        role=ROLE_STAFF_OPERATOR,
        account_status=ACCOUNT_STATUS_ACTIVE,
        must_change_password=True,
        password="TempPassw0rd!",
    )

    login(
        csrf_client,
        email="temp-csrf@shynebeauty.com",
        password="TempPassw0rd!",
    )

    response = csrf_client.post(
        "/change-password?next=/orders",
        data={
            "password": "BrandNewPassw0rd!",
            "password_confirmation": "BrandNewPassw0rd!",
        },
    )

    assert response.status_code == 400
    assert b"CSRF" in response.data

    with app.app_context():
        refreshed_user = db.session.get(AdminUser, user.id)
        assert refreshed_user.requires_password_change() is True


@pytest.mark.parametrize(
    "next_url",
    [
        "//evil.example/phish",
        "https://evil.example/phish",
        "\\\\evil.example/phish",
    ],
)
def test_forced_password_change_rejects_unsafe_next_targets(
    client, admin_factory, login, next_url
):
    admin_factory(
        email="temp-unsafe@shynebeauty.com",
        full_name="Temp Unsafe",
        role=ROLE_STAFF_OPERATOR,
        account_status=ACCOUNT_STATUS_ACTIVE,
        must_change_password=True,
        password="TempPassw0rd!",
    )

    login(
        client,
        email="temp-unsafe@shynebeauty.com",
        password="TempPassw0rd!",
    )

    response = client.post(
        f"/change-password?next={next_url}",
        data={
            "next": next_url,
            "password": "BrandNewPassw0rd!",
            "password_confirmation": "BrandNewPassw0rd!",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")


def test_forced_password_change_normalizes_safe_backslash_next_targets(
    client, admin_factory, login
):
    admin_factory(
        email="temp-safe@shynebeauty.com",
        full_name="Temp Safe",
        role=ROLE_STAFF_OPERATOR,
        account_status=ACCOUNT_STATUS_ACTIVE,
        must_change_password=True,
        password="TempPassw0rd!",
    )

    login(
        client,
        email="temp-safe@shynebeauty.com",
        password="TempPassw0rd!",
    )

    response = client.post(
        "/change-password?next=\\orders?status=open",
        data={
            "next": "\\orders?status=open",
            "password": "BrandNewPassw0rd!",
            "password_confirmation": "BrandNewPassw0rd!",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/orders?status=open")


def test_forced_password_change_rejects_short_password(client, admin_factory, login):
    admin_factory(
        email="temp-short@shynebeauty.com",
        role=ROLE_STAFF_OPERATOR,
        account_status=ACCOUNT_STATUS_ACTIVE,
        must_change_password=True,
        password="TempPassw0rd!",
    )

    login(client, email="temp-short@shynebeauty.com", password="TempPassw0rd!")
    response = client.post(
        "/change-password",
        data={
            "password": "shortpass1!",
            "password_confirmation": "shortpass1!",
        },
    )

    assert response.status_code == 200
    assert b"Password must be at least 12 characters." in response.data


def test_forced_password_change_rejects_password_containing_email(client, admin_factory, login):
    admin_factory(
        email="olivia@shynebeauty.com",
        role=ROLE_STAFF_OPERATOR,
        account_status=ACCOUNT_STATUS_ACTIVE,
        must_change_password=True,
        password="TempPassw0rd!",
    )

    login(client, email="olivia@shynebeauty.com", password="TempPassw0rd!")
    response = client.post(
        "/change-password",
        data={
            "password": "OliviaSecure123!",
            "password_confirmation": "OliviaSecure123!",
        },
    )

    assert response.status_code == 200
    assert b"Password cannot contain your email address." in response.data


def test_ip_throttle_triggers_after_repeated_failures(client, app):
    for _ in range(IP_LOGIN_FAILURE_THRESHOLD):
        response = client.post(
            "/login",
            data={
                "email": "missing@shynebeauty.com",
                "password": "wrong-password",
            },
            environ_base={"REMOTE_ADDR": "10.0.0.8"},
        )
        assert response.status_code == 200
        assert b"Invalid email or password." in response.data

    with app.app_context():
        throttle = AdminLoginThrottle.query.filter_by(ip_address="10.0.0.8").one()
        assert throttle.failed_login_count == IP_LOGIN_FAILURE_THRESHOLD
        assert throttle.locked_until is not None


def test_ip_throttle_blocks_login_for_valid_account(client, admin_user):
    for _ in range(IP_LOGIN_FAILURE_THRESHOLD):
        client.post(
            "/login",
            data={
                "email": "missing@shynebeauty.com",
                "password": "wrong-password",
            },
            environ_base={"REMOTE_ADDR": "10.0.0.9"},
        )

    response = client.post(
        "/login",
        data={
            "email": "admin@shynebeauty.com",
            "password": "correct-horse-battery-staple",
        },
        environ_base={"REMOTE_ADDR": "10.0.0.9"},
    )

    assert response.status_code == 200
    assert b"Invalid email or password." in response.data


def test_ip_throttle_isolated_by_client_ip(client, admin_user, login):
    for _ in range(IP_LOGIN_FAILURE_THRESHOLD):
        client.post(
            "/login",
            data={
                "email": "missing@shynebeauty.com",
                "password": "wrong-password",
            },
            environ_base={"REMOTE_ADDR": "10.0.0.10"},
        )

    response = login(client, next_url="/orders")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/orders")


def test_expired_ip_throttle_allows_login_again(client, admin_user, app, login):
    with app.app_context():
        throttle = AdminLoginThrottle(ip_address="10.0.0.11")
        throttle.failed_login_count = IP_LOGIN_FAILURE_THRESHOLD
        throttle.locked_until = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.session.add(throttle)
        db.session.commit()

    response = client.post(
        "/login",
        data={
            "email": "admin@shynebeauty.com",
            "password": "correct-horse-battery-staple",
        },
        environ_base={"REMOTE_ADDR": "10.0.0.11"},
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")

    with app.app_context():
        throttle = AdminLoginThrottle.query.filter_by(ip_address="10.0.0.11").one()
        assert throttle.failed_login_count == 0
        assert throttle.locked_until is None


def test_first_login_password_change_allows_skipping_optional_mfa(
    client, admin_factory, app, login
):
    user = admin_factory(
        email="first-login@shynebeauty.com",
        role=ROLE_SUPERADMIN,
        account_status=ACCOUNT_STATUS_ACTIVE,
        password="ValidPassw0rd!",
        must_change_password=True,
    )

    response = login(client, email="first-login@shynebeauty.com", password="ValidPassw0rd!")

    assert response.status_code == 302
    assert "/change-password" in response.headers["Location"]

    change_password_page = client.get("/change-password")

    assert change_password_page.status_code == 200
    assert b"Enable MFA for this account now" in change_password_page.data

    completion_response = client.post(
        "/change-password",
        data={
            "password": "FirstLoginPass123",
            "password_confirmation": "FirstLoginPass123",
        },
        follow_redirects=True,
    )

    assert completion_response.status_code == 200
    assert b"Password updated." in completion_response.data

    with app.app_context():
        refreshed_user = db.session.get(AdminUser, user.id)
        assert refreshed_user.requires_password_change() is False
        assert refreshed_user.check_password("FirstLoginPass123") is True
        assert refreshed_user.has_mfa_enabled() is False


def test_first_login_password_change_can_enable_mfa(client, admin_factory, app, login):
    user = admin_factory(
        email="mfa-setup@shynebeauty.com",
        role=ROLE_SUPERADMIN,
        account_status=ACCOUNT_STATUS_ACTIVE,
        password="ValidPassw0rd!",
        must_change_password=True,
    )

    login(client, email="mfa-setup@shynebeauty.com", password="ValidPassw0rd!")
    change_password_page = client.get("/change-password")

    assert change_password_page.status_code == 200
    assert b"Manual Setup Key" in change_password_page.data

    with client.session_transaction() as session_data:
        enrollment_secret = session_data["mfa_enrollment_secret"]

    code = pyotp.TOTP(enrollment_secret).now()
    response = client.post(
        "/change-password",
        data={
            "password": "FirstLoginPass123",
            "password_confirmation": "FirstLoginPass123",
            "enable_mfa": "on",
            "mfa_code": code,
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Password updated." in response.data
    assert b"Multi-factor authentication enabled." in response.data

    with app.app_context():
        refreshed_user = db.session.get(AdminUser, user.id)
        assert refreshed_user.has_mfa_enabled() is True
        assert refreshed_user.must_enroll_mfa is False
        assert refreshed_user.requires_password_change() is False


def test_mfa_challenge_completes_login_for_enabled_account(
    client, admin_factory, app, login, totp_code_for
):
    user = admin_factory(
        email="mfa-user@shynebeauty.com",
        role=ROLE_STAFF_OPERATOR,
        account_status=ACCOUNT_STATUS_ACTIVE,
        password="ValidPassw0rd!",
        mfa_enabled=True,
    )

    first_response = login(
        client,
        email="mfa-user@shynebeauty.com",
        password="ValidPassw0rd!",
    )

    assert first_response.status_code == 302
    assert first_response.headers["Location"].endswith("/mfa/challenge")

    challenge_response = login(
        client,
        email="mfa-user@shynebeauty.com",
        password="ValidPassw0rd!",
        mfa_code=totp_code_for(user.id),
    )

    assert challenge_response.status_code == 302
    assert challenge_response.headers["Location"].endswith("/")

    with app.app_context():
        refreshed_user = db.session.get(AdminUser, user.id)
        assert refreshed_user.last_mfa_verified_at is not None


def test_invalid_mfa_code_does_not_authenticate(client, admin_factory, login):
    admin_factory(
        email="mfa-bad@shynebeauty.com",
        role=ROLE_STAFF_OPERATOR,
        account_status=ACCOUNT_STATUS_ACTIVE,
        password="ValidPassw0rd!",
        mfa_enabled=True,
    )

    response = login(
        client,
        email="mfa-bad@shynebeauty.com",
        password="ValidPassw0rd!",
        mfa_code="000000",
    )

    assert response.status_code == 200
    assert b"Enter a valid authentication code." in response.data

    with client.session_transaction() as session_data:
        assert session_data.get("_user_id") is None


def test_mfa_disabled_user_logs_in_without_challenge(client, admin_factory, login):
    admin_factory(
        email="staff-mfa@shynebeauty.com",
        role=ROLE_STAFF_OPERATOR,
        account_status=ACCOUNT_STATUS_ACTIVE,
        password="ValidPassw0rd!",
    )

    response = login(
        client,
        email="staff-mfa@shynebeauty.com",
        password="ValidPassw0rd!",
        next_url="/orders",
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/orders")


def test_authenticated_user_can_view_account_settings(client, admin_user, login):
    login(client)

    response = client.get("/account/settings")

    assert response.status_code == 200
    assert b"Account Settings" in response.data
    assert b"Change Password" in response.data


def test_account_settings_password_change_succeeds_without_mfa_when_disabled(
    client, admin_factory, app, login
):
    user = admin_factory(
        email="settings-no-mfa@shynebeauty.com",
        role=ROLE_STAFF_OPERATOR,
        account_status=ACCOUNT_STATUS_ACTIVE,
        password="ValidPassw0rd!",
    )

    login(client, email="settings-no-mfa@shynebeauty.com", password="ValidPassw0rd!")

    response = client.post(
        "/account/settings",
        data={
            "action": "change_password",
            "current_password": "ValidPassw0rd!",
            "new_password": "SettingsPass123",
            "password_confirmation": "SettingsPass123",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Password updated." in response.data

    with app.app_context():
        refreshed_user = db.session.get(AdminUser, user.id)
        assert refreshed_user.check_password("SettingsPass123") is True


def test_account_settings_password_change_requires_valid_mfa_code_when_enabled(
    client, admin_factory, app, login, totp_code_for
):
    user = admin_factory(
        email="settings-mfa@shynebeauty.com",
        role=ROLE_STAFF_OPERATOR,
        account_status=ACCOUNT_STATUS_ACTIVE,
        password="ValidPassw0rd!",
        mfa_enabled=True,
    )

    login(
        client,
        email="settings-mfa@shynebeauty.com",
        password="ValidPassw0rd!",
        mfa_code=totp_code_for(user.id),
    )

    missing_code_response = client.post(
        "/account/settings",
        data={
            "action": "change_password",
            "current_password": "ValidPassw0rd!",
            "new_password": "SettingsPass123",
            "password_confirmation": "SettingsPass123",
        },
        follow_redirects=True,
    )

    assert missing_code_response.status_code == 200
    assert (
        b"Authentication code is required to change your password."
        in missing_code_response.data
    )

    invalid_code_response = client.post(
        "/account/settings",
        data={
            "action": "change_password",
            "current_password": "ValidPassw0rd!",
            "new_password": "SettingsPass123",
            "password_confirmation": "SettingsPass123",
            "password_mfa_code": "000000",
        },
        follow_redirects=True,
    )

    assert invalid_code_response.status_code == 200
    assert b"Enter a valid authentication code." in invalid_code_response.data

    success_response = client.post(
        "/account/settings",
        data={
            "action": "change_password",
            "current_password": "ValidPassw0rd!",
            "new_password": "SettingsPass123",
            "password_confirmation": "SettingsPass123",
            "password_mfa_code": totp_code_for(user.id),
        },
        follow_redirects=True,
    )

    assert success_response.status_code == 200
    assert b"Password updated." in success_response.data

    with app.app_context():
        refreshed_user = db.session.get(AdminUser, user.id)
        assert refreshed_user.check_password("SettingsPass123") is True


def test_account_settings_can_enable_mfa(client, admin_factory, app, login):
    user = admin_factory(
        email="enable-mfa@shynebeauty.com",
        role=ROLE_STAFF_OPERATOR,
        account_status=ACCOUNT_STATUS_ACTIVE,
        password="ValidPassw0rd!",
    )

    login(client, email="enable-mfa@shynebeauty.com", password="ValidPassw0rd!")
    settings_page = client.get("/account/settings")

    assert settings_page.status_code == 200
    assert b"Enable MFA" in settings_page.data

    with client.session_transaction() as session_data:
        enrollment_secret = session_data["mfa_enrollment_secret"]

    response = client.post(
        "/account/settings",
        data={
            "action": "enable_mfa",
            "mfa_code": pyotp.TOTP(enrollment_secret).now(),
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Multi-factor authentication enabled." in response.data

    with app.app_context():
        refreshed_user = db.session.get(AdminUser, user.id)
        assert refreshed_user.has_mfa_enabled() is True


def test_account_settings_disable_mfa_requires_valid_code(
    client, admin_factory, app, login, totp_code_for
):
    user = admin_factory(
        email="disable-mfa@shynebeauty.com",
        role=ROLE_STAFF_OPERATOR,
        account_status=ACCOUNT_STATUS_ACTIVE,
        password="ValidPassw0rd!",
        mfa_enabled=True,
    )

    login(
        client,
        email="disable-mfa@shynebeauty.com",
        password="ValidPassw0rd!",
        mfa_code=totp_code_for(user.id),
    )

    invalid_response = client.post(
        "/account/settings",
        data={
            "action": "disable_mfa",
            "disable_mfa_code": "000000",
        },
        follow_redirects=True,
    )

    assert invalid_response.status_code == 200
    assert b"Enter a valid authentication code." in invalid_response.data

    success_response = client.post(
        "/account/settings",
        data={
            "action": "disable_mfa",
            "disable_mfa_code": totp_code_for(user.id),
        },
        follow_redirects=True,
    )

    assert success_response.status_code == 200
    assert b"Multi-factor authentication disabled." in success_response.data

    with app.app_context():
        refreshed_user = db.session.get(AdminUser, user.id)
        assert refreshed_user.has_mfa_enabled() is False


def test_superadmin_is_denied_admin_console_access(client, admin_user, login):
    login(client)

    response = client.get("/admin/")

    assert response.status_code == 403
    assert b"Admin console access denied" in response.data


def test_staff_operator_is_denied_users_access(client, staff_user, login):
    response = login(
        client,
        email="staff@shynebeauty.com",
        password="correct-horse-battery-staple",
    )

    assert response.status_code == 302

    denied_response = client.get("/users")

    assert denied_response.status_code == 403
    assert b"Users &amp; Access denied" in denied_response.data


def test_dev_admin_can_access_admin_console_but_not_users(client, dev_admin_user, login):
    response = login(
        client,
        email="devadmin@shynebeauty.com",
        password="correct-horse-battery-staple",
    )

    assert response.status_code == 302

    admin_response = client.get("/admin/")
    users_response = client.get("/users")

    assert admin_response.status_code == 200
    assert b"ShyneBeauty Admin" in admin_response.data
    assert users_response.status_code == 403
    assert b"Users &amp; Access denied" in users_response.data


def test_runtime_auth_schema_compatibility_upgrades_legacy_admin_table_before_user_load(
    client, app
):
    try:
        with app.app_context():
            db.session.remove()
            db.drop_all(bind_key=AUTH_BIND_KEY)
            auth_engine = db.engines[AUTH_BIND_KEY]
            with auth_engine.begin() as connection:
                connection.execute(
                    text(
                        """
                        CREATE TABLE admin_users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            email VARCHAR(255) NOT NULL UNIQUE,
                            password_hash VARCHAR(255),
                            full_name VARCHAR(255),
                            is_active BOOLEAN NOT NULL DEFAULT 1,
                            failed_login_count INTEGER NOT NULL DEFAULT 0,
                            locked_until DATETIME,
                            last_login_at DATETIME,
                            created_at DATETIME NOT NULL
                        )
                        """
                    )
                )
                connection.execute(
                    text(
                        """
                        INSERT INTO admin_users (
                            id,
                            email,
                            password_hash,
                            full_name,
                            is_active,
                            failed_login_count,
                            locked_until,
                            last_login_at,
                            created_at
                        ) VALUES (
                            :id,
                            :email,
                            :password_hash,
                            :full_name,
                            :is_active,
                            :failed_login_count,
                            :locked_until,
                            :last_login_at,
                            :created_at
                        )
                        """
                    ),
                    {
                        "id": 1,
                        "email": "legacy@shynebeauty.com",
                        "password_hash": "legacy-hash",
                        "full_name": "Legacy Admin",
                        "is_active": True,
                        "failed_login_count": 0,
                        "locked_until": None,
                        "last_login_at": None,
                        "created_at": datetime.now(timezone.utc),
                    },
                )

        with client.session_transaction() as session_data:
            session_data["_user_id"] = "1"
            session_data["_fresh"] = True

        response = client.get("/")

        assert response.status_code == 200
        assert b"Home Dashboard / Analytics" in response.data

        with app.app_context():
            auth_inspector = inspect(db.engines[AUTH_BIND_KEY])
            assert "admin_access_events" in set(auth_inspector.get_table_names())
            assert {
                column["name"] for column in auth_inspector.get_columns("admin_users")
            } >= {
                "role",
                "account_status",
                "must_change_password",
                "permission_overrides_json",
            }
            user = db.session.get(AdminUser, 1)
            assert user.get_role() == "Staff Operator"
            assert user.get_account_status() == "active"
    finally:
        with app.app_context():
            db.session.remove()
            db.drop_all(bind_key=AUTH_BIND_KEY)
            db.create_all(bind_key=AUTH_BIND_KEY)


def test_login_path_is_rate_limited():
    from shyne_app.rate_limit import check_rate_limit, _SENSITIVE_POST_LIMIT
    ip = "192.0.2.10"
    for _ in range(_SENSITIVE_POST_LIMIT):
        check_rate_limit(ip, "/login", "POST")
    assert check_rate_limit(ip, "/login", "POST") is False


def test_invite_path_is_rate_limited():
    from shyne_app.rate_limit import check_rate_limit, _SENSITIVE_POST_LIMIT
    ip = "192.0.2.11"
    for _ in range(_SENSITIVE_POST_LIMIT):
        check_rate_limit(ip, "/users/invite", "POST")
    assert check_rate_limit(ip, "/users/invite", "POST") is False


def test_temporary_password_path_is_rate_limited():
    from shyne_app.rate_limit import check_rate_limit, _SENSITIVE_POST_LIMIT
    ip = "192.0.2.12"
    for _ in range(_SENSITIVE_POST_LIMIT):
        check_rate_limit(ip, "/users/42/temporary-password", "POST")
    assert check_rate_limit(ip, "/users/42/temporary-password", "POST") is False


def test_resend_invite_path_is_rate_limited():
    from shyne_app.rate_limit import check_rate_limit, _SENSITIVE_POST_LIMIT
    ip = "192.0.2.13"
    for _ in range(_SENSITIVE_POST_LIMIT):
        check_rate_limit(ip, "/users/99/resend-invite", "POST")
    assert check_rate_limit(ip, "/users/99/resend-invite", "POST") is False
