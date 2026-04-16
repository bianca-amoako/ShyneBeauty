import logging
import logging.handlers

from .config import *
from .extensions import app, init_extensions


def _configure_logging(runtime: str, log_dir) -> None:
    log_dir = log_dir if hasattr(log_dir, "mkdir") else __import__("pathlib").Path(log_dir)
    log_dir.mkdir(exist_ok=True)

    level = logging.DEBUG if runtime == APP_RUNTIME_DEMO_DEV else logging.INFO
    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.handlers.TimedRotatingFileHandler(
        log_dir / "shynebeauty.log",
        when="midnight",
        backupCount=30,
        encoding="utf-8",
    )
    file_handler.setFormatter(fmt)
    file_handler.setLevel(level)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt)
    console_handler.setLevel(logging.WARNING)

    logger = logging.getLogger("shynebeauty")
    logger.setLevel(level)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    logger.propagate = False


# Config docs and local setup store dotenv files at project root
load_project_env(BASE_DIR.parent)
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

_configure_logging(app.config["APP_RUNTIME"], BASE_DIR.parent / "logs")

_logger = logging.getLogger("shynebeauty.startup")
_logger.info(
    "ShyneBeauty starting | runtime=%s | debug=%s",
    app.config["APP_RUNTIME"],
    app.debug,
)

if app.config["APP_RUNTIME"] == APP_RUNTIME_LIVE_PROD and not app.config.get("SESSION_COOKIE_SECURE"):
    import warnings
    warnings.warn(
        "SESSION_COOKIE_SECURE is False in live-prod — session cookies will be sent over HTTP. "
        "Set SESSION_COOKIE_SECURE=true and deploy behind HTTPS.",
        stacklevel=1,
    )

init_extensions(app)

from . import models as _models  # noqa: E402,F401
from . import access as _access  # noqa: E402,F401
from . import auth as _auth  # noqa: E402,F401
from . import admin as _admin  # noqa: E402,F401
from . import routes as _routes  # noqa: E402,F401
from . import cli as _cli  # noqa: E402,F401
from . import rate_limit as _rate_limit  # noqa: E402,F401

_admin.register_admin_views()
