from .config import *
from .extensions import app, init_extensions

load_project_env()
app.config["SECRET_KEY"] = require_env("SECRET_KEY")
runtime_database_config = resolve_runtime_database_config(BASE_DIR.parent)
app.config["APP_RUNTIME"] = runtime_database_config["runtime"]
app.config["RUNTIME_DEFAULT_DATABASES"] = runtime_database_config["runtime_defaults"]
app.config["SQLALCHEMY_DATABASE_URI"] = runtime_database_config["primary_uri"]
app.config["SQLALCHEMY_BINDS"] = {
    AUTH_BIND_KEY: runtime_database_config["auth_uri"]
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["ENABLE_DEV_TEST_ADMIN"] = (
    False
    if app.config["APP_RUNTIME"] == APP_RUNTIME_LIVE_PROD
    else env_flag("ENABLE_DEV_TEST_ADMIN", default=False)
)
app.config["TRUST_PROXY_HEADERS"] = env_flag("TRUST_PROXY_HEADERS", default=False)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = env_flag(
    "SESSION_COOKIE_SECURE",
    default=runtime_default_flag(
        app.config["APP_RUNTIME"],
        demo_default=False,
        live_default=True,
    ),
)
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
app.config["REMEMBER_COOKIE_SECURE"] = app.config["SESSION_COOKIE_SECURE"]
app.config["WTF_CSRF_ENABLED"] = True

if app.config["APP_RUNTIME"] == APP_RUNTIME_LIVE_PROD and env_flag(
    "FLASK_DEBUG", default=False
):
    raise RuntimeError("FLASK_DEBUG must not be enabled in live-prod.")

init_extensions(app)

from . import models as _models  # noqa: E402,F401
from . import access as _access  # noqa: E402,F401
from . import auth as _auth  # noqa: E402,F401
from . import admin as _admin  # noqa: E402,F401
from . import routes as _routes  # noqa: E402,F401
from . import cli as _cli  # noqa: E402,F401

_admin.register_admin_views()
