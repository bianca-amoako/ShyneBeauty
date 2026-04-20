import os
import re
import sys
import tempfile
import uuid
from pathlib import Path

import pyotp
import pytest

# tests can import the app module if pytest is run from repo root or different working directory.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

os.environ.setdefault("SECRET_KEY", "test-secret-key")
TEST_DB_DIR = Path(tempfile.gettempdir()) / f"shynebeauty-pytest-{os.getpid()}-{uuid.uuid4().hex}"
TEST_DB_DIR.mkdir(parents=True, exist_ok=True)
PRIMARY_TEST_DB = TEST_DB_DIR / "test_shynebeauty.db"
AUTH_TEST_DB = TEST_DB_DIR / "test_shynebeauty_auth.db"
os.environ.setdefault(
    "DATABASE_URL",
    f"sqlite:///{PRIMARY_TEST_DB.as_posix()}",
)
os.environ.setdefault(
    "AUTH_DATABASE_URL",
    f"sqlite:///{AUTH_TEST_DB.as_posix()}",
)

from shyne import AdminUser
from shyne import ACCOUNT_STATUS_ACTIVE
from shyne import ACCOUNT_STATUS_INVITED
from shyne import ACCOUNT_STATUS_SUSPENDED
from shyne import ROLE_DEV_ADMIN
from shyne import ROLE_STAFF_OPERATOR
from shyne import ROLE_SUPERADMIN
from shyne import app as flask_app
from shyne import db
from shyne import utc_now

_UNSET = object()

BASE_SQLALCHEMY_DATABASE_URI = flask_app.config["SQLALCHEMY_DATABASE_URI"]
BASE_SQLALCHEMY_BINDS = dict(flask_app.config["SQLALCHEMY_BINDS"])
BASE_APP_RUNTIME = flask_app.config["APP_RUNTIME"]
BASE_RUNTIME_DEFAULT_DATABASES = dict(flask_app.config["RUNTIME_DEFAULT_DATABASES"])


def reset_database_schema():
    db.session.remove()
    db.drop_all(bind_key="__all__")
    db.create_all(bind_key="__all__")


@pytest.fixture()
def app():
    flask_app.config.update(
        TESTING=True,
        DEBUG=False,
        SECRET_KEY="test-secret-key",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        APP_RUNTIME=BASE_APP_RUNTIME,
        SQLALCHEMY_DATABASE_URI=BASE_SQLALCHEMY_DATABASE_URI,
        SQLALCHEMY_BINDS=dict(BASE_SQLALCHEMY_BINDS),
        RUNTIME_DEFAULT_DATABASES=dict(BASE_RUNTIME_DEFAULT_DATABASES),
        ENABLE_DEV_TEST_ADMIN=False,
        TRUST_PROXY_HEADERS=False,
        WTF_CSRF_ENABLED=False,
    )

    with flask_app.app_context():
        reset_database_schema()
        yield flask_app
        reset_database_schema()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def csrf_client(app):
    original_value = app.config["WTF_CSRF_ENABLED"]
    app.config["WTF_CSRF_ENABLED"] = True
    try:
        yield app.test_client()
    finally:
        app.config["WTF_CSRF_ENABLED"] = original_value


def extract_csrf_token(response_data):
    html = response_data.decode("utf-8")
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    assert match, "Expected a CSRF token in the response body."
    return match.group(1)


@pytest.fixture()
def csrf_token_for():
    def _csrf_token_for(client, path):
        response = client.get(path)
        assert response.status_code == 200
        return extract_csrf_token(response.data)

    return _csrf_token_for


@pytest.fixture()
def login():
    def _login(
        client,
        *,
        email="admin@shynebeauty.com",
        password="correct-horse-battery-staple",
        remember_me=False,
        next_url=None,
        mfa_code=None,
    ):
        data = {
            "email": email,
            "password": password,
        }
        if client.application.config.get("WTF_CSRF_ENABLED"):
            data["csrf_token"] = extract_csrf_token(client.get("/login").data)
        if remember_me:
            data["remember_me"] = "on"
        if next_url is not None:
            data["next"] = next_url

        response = client.post(
            "/login",
            data=data,
            query_string={"next": next_url} if next_url is not None else None,
        )

        if mfa_code is not None:
            challenge_data = {"code": mfa_code}
            if client.application.config.get("WTF_CSRF_ENABLED"):
                challenge_data["csrf_token"] = extract_csrf_token(
                    client.get("/mfa/challenge").data
                )
            return client.post("/mfa/challenge", data=challenge_data)
        return response

    return _login


@pytest.fixture()
def admin_user(app):
    with app.app_context():
        user = AdminUser(
            email="admin@shynebeauty.com",
            full_name="Shyne Admin",
        )
        user.set_password("correct-horse-battery-staple")
        user.set_role(ROLE_SUPERADMIN, now=utc_now())
        user.set_account_status(ACCOUNT_STATUS_ACTIVE, now=utc_now())
        user.mfa_enroll_dismissed_at = utc_now()
        db.session.add(user)
        db.session.commit()
        return user.id


@pytest.fixture()
def admin_factory(app):
    with app.app_context():
        created_count = {"value": 0}

        def _create_admin(
            *,
            email=None,
            full_name="Shyne Admin",
            password="correct-horse-battery-staple",
            role=ROLE_STAFF_OPERATOR,
            account_status=ACCOUNT_STATUS_ACTIVE,
            must_change_password=False,
            failed_login_count=0,
            locked_until=None,
            last_login_at=None,
            permission_overrides=None,
            must_enroll_mfa=False,
            mfa_enabled=False,
            mfa_totp_secret=None,
            mfa_enroll_dismissed_at=_UNSET,
        ):
            created_count["value"] += 1
            comparison_time = utc_now()
            user = AdminUser(
                email=email or f"admin{created_count['value']}@shynebeauty.com",
                full_name=full_name,
                failed_login_count=failed_login_count,
                locked_until=locked_until,
                last_login_at=last_login_at,
            )
            if password is not None:
                user.set_password(password)
            else:
                user.password_hash = ""
            if role is not None:
                user.set_role(role, now=comparison_time)
            if account_status is not None:
                user.set_account_status(account_status, now=comparison_time)
            else:
                user.account_status = None
                user.is_active = True
            if account_status == ACCOUNT_STATUS_INVITED:
                user.invited_by_user_id = 1
            user.must_change_password = must_change_password
            user.must_enroll_mfa = must_enroll_mfa
            if mfa_enroll_dismissed_at is _UNSET:
                if role in {ROLE_SUPERADMIN, ROLE_DEV_ADMIN} and not mfa_enabled:
                    user.mfa_enroll_dismissed_at = comparison_time
                else:
                    user.mfa_enroll_dismissed_at = None
            else:
                user.mfa_enroll_dismissed_at = mfa_enroll_dismissed_at
            if mfa_enabled:
                user.mfa_enabled = True
                user.mfa_totp_secret = mfa_totp_secret or pyotp.random_base32()
                user.mfa_enrolled_at = comparison_time
            if permission_overrides is not None:
                user.set_permission_overrides(permission_overrides)
            db.session.add(user)
            db.session.commit()
            return user

        yield _create_admin


@pytest.fixture()
def staff_user(app, admin_factory):
    with app.app_context():
        user = admin_factory(
            email="staff@shynebeauty.com",
            full_name="Staff User",
            role=ROLE_STAFF_OPERATOR,
            account_status=ACCOUNT_STATUS_ACTIVE,
        )
        return user.id


@pytest.fixture()
def dev_admin_user(app, admin_factory):
    with app.app_context():
        user = admin_factory(
            email="devadmin@shynebeauty.com",
            full_name="Dev Admin",
            role=ROLE_DEV_ADMIN,
            account_status=ACCOUNT_STATUS_ACTIVE,
        )
        return user.id


@pytest.fixture()
def totp_code_for(app):
    def _totp_code_for(user_id):
        with app.app_context():
            user = db.session.get(AdminUser, user_id)
            assert user is not None
            assert user.mfa_totp_secret
            return pyotp.TOTP(user.mfa_totp_secret).now()

    return _totp_code_for


@pytest.fixture()
def suspended_user(app, admin_factory):
    with app.app_context():
        user = admin_factory(
            email="suspended@shynebeauty.com",
            full_name="Suspended User",
            role=ROLE_STAFF_OPERATOR,
            account_status=ACCOUNT_STATUS_SUSPENDED,
        )
        return user.id
