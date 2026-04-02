from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from shyne import AdminUser, db


@pytest.mark.parametrize("route", ["/", "/orders", "/tasks", "/admin/"])
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


@pytest.mark.parametrize(
    ("route", "expected_text"),
    [
        ("/", b"Home Dashboard / Analytics"),
        ("/orders", b"Manage Orders"),
        ("/tasks", b"Task List"),
        ("/admin/", b"ShyneBeauty Admin"),
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
