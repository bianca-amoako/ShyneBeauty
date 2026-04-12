import os
import sys
import tempfile
from pathlib import Path

import pytest

# tests can import the app module if pytest is run from repo root or different working directory.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

os.environ.setdefault("SECRET_KEY", "test-secret-key")
TEST_DB_DIR = Path(tempfile.gettempdir()) / "shynebeauty-pytest"
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


@pytest.fixture()
def app():
    flask_app.config.update(
        TESTING=True,
        DEBUG=False,
        SECRET_KEY="test-secret-key",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        ENABLE_DEV_TEST_ADMIN=False,
    )

    with flask_app.app_context():
        db.drop_all(bind_key="__all__")
        db.create_all(bind_key="__all__")
        yield flask_app
        db.session.remove()
        db.drop_all(bind_key="__all__")


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def login():
    def _login(
        client,
        *,
        email="admin@shynebeauty.com",
        password="correct-horse-battery-staple",
        remember_me=False,
        next_url=None,
    ):
        data = {
            "email": email,
            "password": password,
        }
        if remember_me:
            data["remember_me"] = "on"
        if next_url is not None:
            data["next"] = next_url

        return client.post(
            "/login",
            data=data,
            query_string={"next": next_url} if next_url is not None else None,
        )

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
def suspended_user(app, admin_factory):
    with app.app_context():
        user = admin_factory(
            email="suspended@shynebeauty.com",
            full_name="Suspended User",
            role=ROLE_STAFF_OPERATOR,
            account_status=ACCOUNT_STATUS_SUSPENDED,
        )
        return user.id
