import pytest

from shyne import (
    ACCOUNT_STATUS_ACTIVE,
    ACCOUNT_STATUS_INVITED,
    PERMISSION_ADMIN_CONSOLE_ACCESS,
    ROLE_DEV_ADMIN,
    ROLE_STAFF_OPERATOR,
    ROLE_SUPERADMIN,
    AdminUser,
    db,
)


def test_superadmin_can_view_users_page(client, admin_user, login):
    login(client)

    response = client.get("/users")

    assert response.status_code == 200
    assert b"Users & Access" in response.data
    assert b"Create user" in response.data


def test_dev_admin_is_hidden_from_users_table(client, admin_user, dev_admin_user, login):
    login(client)

    response = client.get("/users")

    assert response.status_code == 200
    assert b"devadmin@shynebeauty.com" not in response.data


def test_create_user_with_manual_temporary_password(
    client, admin_user, app, login
):
    login(client)

    invite_response = client.post(
        "/users/invite",
        data={
            "full_name": "Taylor Temp",
            "email": "taylor@shynebeauty.com",
            "role": ROLE_STAFF_OPERATOR,
            "password_mode": "manual",
            "password": "TempPassw0rd!",
            "password_confirmation": "TempPassw0rd!",
        },
    )

    assert invite_response.status_code == 302

    with app.app_context():
        created_user = AdminUser.query.filter_by(email="taylor@shynebeauty.com").one()
        assert created_user.get_account_status() == ACCOUNT_STATUS_ACTIVE
        assert created_user.get_role() == ROLE_STAFF_OPERATOR
        assert created_user.check_password("TempPassw0rd!") is True
        assert created_user.requires_password_change() is True

    client.post("/logout")
    login_response = login(
        client,
        email="taylor@shynebeauty.com",
        password="TempPassw0rd!",
    )

    assert login_response.status_code == 302
    assert "/change-password" in login_response.headers["Location"]


def test_create_user_with_generated_temporary_password_shows_password_once(
    client, admin_user, app, login
):
    login(client)

    response = client.post(
        "/users/invite",
        data={
            "full_name": "Jordan Generated",
            "email": "jordan@shynebeauty.com",
            "role": ROLE_STAFF_OPERATOR,
            "password_mode": "generated",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Temporary password (shown once):" in response.data

    with app.app_context():
        created_user = AdminUser.query.filter_by(email="jordan@shynebeauty.com").one()
        assert created_user.get_account_status() == ACCOUNT_STATUS_ACTIVE
        assert created_user.requires_password_change() is True


def test_last_active_superadmin_cannot_be_demoted(client, admin_user, app, login):
    login(client)

    response = client.post(
        f"/users/{admin_user}/role",
        data={"role": ROLE_STAFF_OPERATOR},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"last active superadmin" in response.data

    with app.app_context():
        user = db.session.get(AdminUser, admin_user)
        assert user.get_role() == ROLE_SUPERADMIN


def test_last_active_superadmin_cannot_be_suspended(client, admin_user, app, login):
    login(client)

    response = client.post(
        f"/users/{admin_user}/suspend",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"last active superadmin" in response.data

    with app.app_context():
        user = db.session.get(AdminUser, admin_user)
        assert user.get_account_status() == ACCOUNT_STATUS_ACTIVE


def test_superadmin_can_demote_another_superadmin_when_not_last(
    client, admin_user, admin_factory, app, login
):
    with app.app_context():
        second_superadmin = admin_factory(
            email="second-super@shynebeauty.com",
            full_name="Second Superadmin",
            role=ROLE_SUPERADMIN,
            account_status=ACCOUNT_STATUS_ACTIVE,
        )
        second_superadmin_id = second_superadmin.id

    login(client)

    response = client.post(
        f"/users/{second_superadmin_id}/role",
        data={"role": ROLE_STAFF_OPERATOR},
    )

    assert response.status_code == 302

    with app.app_context():
        user = db.session.get(AdminUser, second_superadmin_id)
        assert user.get_role() == ROLE_STAFF_OPERATOR


def test_superadmin_can_set_temporary_password_for_active_business_user(
    client, admin_user, staff_user, app, login
):
    login(client)

    response = client.post(
        f"/users/{staff_user}/temporary-password",
        data={
            "password": "NewTempPassw0rd!",
            "password_confirmation": "NewTempPassw0rd!",
        },
    )

    assert response.status_code == 302

    with app.app_context():
        user = db.session.get(AdminUser, staff_user)
        assert user.check_password("NewTempPassw0rd!") is True
        assert user.requires_password_change() is True


def test_legacy_pending_invite_can_still_be_activated_with_temporary_password(
    client, admin_user, admin_factory, app, login
):
    with app.app_context():
        invited_user = admin_factory(
            email="legacy-invite@shynebeauty.com",
            full_name="Legacy Invite",
            password=None,
            role=ROLE_STAFF_OPERATOR,
            account_status=ACCOUNT_STATUS_INVITED,
        )
        invited_user_id = invited_user.id

    login(client)

    response = client.post(
        f"/users/{invited_user_id}/activate",
        data={
            "password": "LegacyTempPassw0rd!",
            "password_confirmation": "LegacyTempPassw0rd!",
        },
    )

    assert response.status_code == 302

    with app.app_context():
        activated_user = db.session.get(AdminUser, invited_user_id)
        assert activated_user.get_account_status() == ACCOUNT_STATUS_ACTIVE
        assert activated_user.requires_password_change() is True
        assert activated_user.check_password("LegacyTempPassw0rd!") is True


def test_users_page_can_filter_pending_invites(
    client, admin_user, admin_factory, app, login
):
    with app.app_context():
        admin_factory(
            email="pending@shynebeauty.com",
            full_name="Pending Invite",
            password=None,
            role=ROLE_STAFF_OPERATOR,
            account_status=ACCOUNT_STATUS_INVITED,
        )

    login(client)

    response = client.get("/users?status_filter=invited")

    assert response.status_code == 200
    assert b"pending@shynebeauty.com" in response.data


def test_users_page_never_shows_admin_console_role_option(client, admin_user, login):
    login(client)

    response = client.get("/users")

    assert response.status_code == 200
    assert f'value="{ROLE_DEV_ADMIN}"'.encode() not in response.data


def test_permission_override_allowlist_rejects_admin_console_access(app):
    with app.app_context():
        user = AdminUser(email="override@shynebeauty.com")
        user.set_password("StrongPassw0rd!")
        user.set_role(ROLE_STAFF_OPERATOR)
        user.set_account_status(ACCOUNT_STATUS_ACTIVE)

        with pytest.raises(ValueError):
            user.set_permission_overrides([PERMISSION_ADMIN_CONSOLE_ACCESS])
