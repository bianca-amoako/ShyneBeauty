from datetime import datetime, timedelta, timezone

import pytest

from shyne import (
    ACCOUNT_STATUS_ACTIVE,
    ACCOUNT_STATUS_INVITED,
    ACCOUNT_STATUS_SUSPENDED,
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


def test_users_page_marks_selected_row_for_assistive_tech(client, admin_user, login):
    login(client)

    response = client.get("/users")

    assert response.status_code == 200
    assert b'aria-selected="true"' in response.data


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

    first_login_page = client.get("/change-password")

    assert first_login_page.status_code == 200
    assert b"Enable MFA for this account now" in first_login_page.data
    assert b"optional" in first_login_page.data.lower()


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


def test_create_user_rejects_weak_manual_temporary_password(client, admin_user, app, login):
    login(client)

    response = client.post(
        "/users/invite",
        data={
            "full_name": "Weak Temp",
            "email": "weak@shynebeauty.com",
            "role": ROLE_STAFF_OPERATOR,
            "password_mode": "manual",
            "password": "weak-pass1!",
            "password_confirmation": "weak-pass1!",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Password must be at least 12 characters." in response.data

    with app.app_context():
        assert AdminUser.query.filter_by(email="weak@shynebeauty.com").first() is None


def test_users_invite_rejects_missing_csrf_token(
    csrf_client, admin_user, app, login
):
    login(csrf_client)

    response = csrf_client.post(
        "/users/invite",
        data={
            "full_name": "Taylor Temp",
            "email": "taylor@shynebeauty.com",
            "role": ROLE_STAFF_OPERATOR,
            "password_mode": "manual",
            "password": "TempPassw0rd!",
            "password_confirmation": "TempPassw0rd!",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302

    with app.app_context():
        created_user = AdminUser.query.filter_by(email="taylor@shynebeauty.com").first()
        assert created_user is None


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


def test_temporary_password_reset_routes_back_to_optional_first_login_flow(
    client, admin_user, app, login
):
    login(client)

    create_response = client.post(
        "/users/invite",
        data={
            "full_name": "Resettable Super",
            "email": "resettable-super@shynebeauty.com",
            "role": ROLE_SUPERADMIN,
            "password_mode": "manual",
            "password": "TempResetPass12",
            "password_confirmation": "TempResetPass12",
        },
    )

    assert create_response.status_code == 302

    with app.app_context():
        created_user = AdminUser.query.filter_by(
            email="resettable-super@shynebeauty.com"
        ).one()
        created_user_id = created_user.id

    reset_response = client.post(
        f"/users/{created_user_id}/temporary-password",
        data={
            "password": "AnotherTempPass12",
            "password_confirmation": "AnotherTempPass12",
        },
    )

    assert reset_response.status_code == 302

    client.post("/logout")
    login_response = login(
        client,
        email="resettable-super@shynebeauty.com",
        password="AnotherTempPass12",
    )

    assert login_response.status_code == 302
    assert "/change-password" in login_response.headers["Location"]

    first_login_page = client.get("/change-password")

    assert first_login_page.status_code == 200
    assert b"Enable MFA for this account now" in first_login_page.data
    assert b"Manual Setup Key" in first_login_page.data


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


def test_superadmin_can_resend_pending_invite(client, admin_user, admin_factory, app, login):
    with app.app_context():
        invited_user = admin_factory(
            email="pending-resend@shynebeauty.com",
            full_name="Pending Resend",
            password=None,
            role=ROLE_STAFF_OPERATOR,
            account_status=ACCOUNT_STATUS_INVITED,
        )
        invited_user.invited_at = datetime.now(timezone.utc) - timedelta(days=3)
        db.session.commit()
        invited_user_id = invited_user.id
        original_invited_at = invited_user.invited_at

    login(client)

    response = client.post(f"/users/{invited_user_id}/resend-invite")

    assert response.status_code == 302

    with app.app_context():
        refreshed_user = db.session.get(AdminUser, invited_user_id)
        assert refreshed_user.get_account_status() == ACCOUNT_STATUS_INVITED
        assert refreshed_user.invited_at > original_invited_at
        assert refreshed_user.invited_by_user_id == admin_user


def test_superadmin_can_cancel_pending_invite(client, admin_user, admin_factory, app, login):
    with app.app_context():
        invited_user = admin_factory(
            email="pending-cancel@shynebeauty.com",
            full_name="Pending Cancel",
            password=None,
            role=ROLE_STAFF_OPERATOR,
            account_status=ACCOUNT_STATUS_INVITED,
        )
        invited_user_id = invited_user.id

    login(client)

    response = client.post(f"/users/{invited_user_id}/cancel-invite")

    assert response.status_code == 302

    with app.app_context():
        assert db.session.get(AdminUser, invited_user_id) is None


def test_superadmin_can_reactivate_suspended_user(client, admin_user, admin_factory, app, login):
    with app.app_context():
        suspended_user = admin_factory(
            email="reactivate@shynebeauty.com",
            full_name="Reactivate User",
            role=ROLE_STAFF_OPERATOR,
            account_status=ACCOUNT_STATUS_SUSPENDED,
            failed_login_count=4,
            locked_until=datetime.now(timezone.utc) + timedelta(minutes=5),
        )
        suspended_user_id = suspended_user.id

    login(client)

    response = client.post(f"/users/{suspended_user_id}/reactivate")

    assert response.status_code == 302

    with app.app_context():
        refreshed_user = db.session.get(AdminUser, suspended_user_id)
        assert refreshed_user.get_account_status() == ACCOUNT_STATUS_ACTIVE
        assert refreshed_user.failed_login_count == 0
        assert refreshed_user.locked_until is None


def test_activate_user_rejects_non_invited_account(client, admin_user, staff_user, app, login):
    login(client)

    response = client.post(
        f"/users/{staff_user}/activate",
        data={
            "password": "LegacyTempPassw0rd!",
            "password_confirmation": "LegacyTempPassw0rd!",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Only pending invites can be activated." in response.data

    with app.app_context():
        active_user = db.session.get(AdminUser, staff_user)
        assert active_user.get_account_status() == ACCOUNT_STATUS_ACTIVE
        assert active_user.check_password("LegacyTempPassw0rd!") is False


def test_temporary_password_rejects_non_active_account(
    client, admin_user, admin_factory, app, login
):
    with app.app_context():
        suspended_user = admin_factory(
            email="suspended-reset@shynebeauty.com",
            full_name="Suspended Reset",
            role=ROLE_STAFF_OPERATOR,
            account_status=ACCOUNT_STATUS_SUSPENDED,
        )
        suspended_user_id = suspended_user.id

    login(client)

    response = client.post(
        f"/users/{suspended_user_id}/temporary-password",
        data={
            "password": "NewTempPassw0rd!",
            "password_confirmation": "NewTempPassw0rd!",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Only active accounts can receive a temporary password." in response.data

    with app.app_context():
        refreshed_user = db.session.get(AdminUser, suspended_user_id)
        assert refreshed_user.get_account_status() == ACCOUNT_STATUS_SUSPENDED
        assert refreshed_user.check_password("NewTempPassw0rd!") is False


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
