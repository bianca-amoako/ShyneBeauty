from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import inspect, select, text

from shyne import AUTH_BIND_KEY, ACCOUNT_STATUS_ACTIVE, AdminUser, ROLE_STAFF_OPERATOR, ROLE_SUPERADMIN, db


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
    assert response.headers["Referrer-Policy"] == "same-origin"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN"


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


def test_default_config_rejects_dev_test_admin_credentials(client):
    response = client.post("/login", data={"email": "admin", "password": "admin"})

    assert response.status_code == 200
    assert b"Invalid email or password." in response.data


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


def test_seeded_dev_test_admin_can_log_in_and_access_protected_routes(client, app):
    app.config["ENABLE_DEV_TEST_ADMIN"] = True
    runner = app.test_cli_runner()
    result = runner.invoke(args=["seed-dev-admin"])

    assert result.exit_code == 0

    response = client.post(
        "/login",
        data={"email": "admin", "password": "admin", "next": "/orders"},
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/orders")

    with app.app_context():
        user = AdminUser.query.filter_by(email="admin").one()
        user_id = user.id
        assert user.last_login_at is not None

    with client.session_transaction() as session_data:
        assert session_data.get("_user_id") == str(user_id)

    protected_response = client.get("/orders")
    assert protected_response.status_code == 200
    assert b"Manage Orders" in protected_response.data


def test_seeded_dev_test_admin_is_rejected_when_dev_mode_is_disabled(client, app):
    app.config["ENABLE_DEV_TEST_ADMIN"] = True
    runner = app.test_cli_runner()
    result = runner.invoke(args=["seed-dev-admin"])

    assert result.exit_code == 0

    app.config["ENABLE_DEV_TEST_ADMIN"] = False

    response = client.post(
        "/login",
        data={"email": "admin", "password": "admin"},
    )

    assert response.status_code == 200
    assert b"Invalid email or password." in response.data

    with client.session_transaction() as session_data:
        assert "_user_id" not in session_data


def test_seeded_dev_test_admin_still_locks_after_repeated_failed_attempts(client, app):
    app.config["ENABLE_DEV_TEST_ADMIN"] = True
    runner = app.test_cli_runner()
    result = runner.invoke(args=["seed-dev-admin"])

    assert result.exit_code == 0

    for _ in range(5):
        response = client.post(
            "/login",
            data={"email": "admin", "password": "wrong-password"},
        )
        assert response.status_code == 200
        assert b"Invalid email or password." in response.data

    with app.app_context():
        user = AdminUser.query.filter_by(email="admin").one()
        assert user.failed_login_count == 5
        assert user.locked_until is not None

    locked_response = client.post(
        "/login",
        data={"email": "admin", "password": "admin"},
    )

    assert locked_response.status_code == 200
    assert b"Invalid email or password." in locked_response.data


@pytest.mark.parametrize(
    ("route", "expected_text"),
    [
        ("/", b"Home Dashboard / Analytics"),
        ("/orders", b"Manage Orders"),
        ("/tasks", b"Task List"),
        ("/customers", b"Customer Database"),
        ("/inventory", b"Inventory Page"),
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
