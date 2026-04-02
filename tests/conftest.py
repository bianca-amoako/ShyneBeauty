import os
import pytest
import sys
import tempfile
from pathlib import Path
from sqlalchemy import inspect as sa_inspect

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
from shyne import app as flask_app
from shyne import db


def clear_test_data():
    db.session.remove()
    for bind_key, metadata in db.metadatas.items():
        engine = db.engine if bind_key is None else db.engines[bind_key]
        existing_tables = set(sa_inspect(engine).get_table_names())
        with engine.begin() as connection:
            for table in reversed(metadata.sorted_tables):
                if table.name in existing_tables:
                    connection.execute(table.delete())


@pytest.fixture()
def app():
    flask_app.config.update(
        TESTING=True,
        SECRET_KEY="test-secret-key",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )

    with flask_app.app_context():
        db.create_all(bind_key="__all__")
        clear_test_data()
        yield flask_app
        clear_test_data()
        db.session.remove()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def admin_user(app):
    with app.app_context():
        user = AdminUser(
            email="admin@shynebeauty.com",
            full_name="Shyne Admin",
        )
        user.set_password("correct-horse-battery-staple")
        db.session.add(user)
        db.session.commit()
        return user.id
