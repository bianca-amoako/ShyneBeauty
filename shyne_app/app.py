import logging
import logging.handlers
import os
import time
from pathlib import Path

from .config import *
from .extensions import app, init_extensions


class SafeTimedRotatingFileHandler(logging.handlers.TimedRotatingFileHandler):
    def doRollover(self):
        try:
            super().doRollover()
        except PermissionError:
            current_time = int(time.time())
            next_rollover = self.computeRollover(current_time)
            while next_rollover <= current_time:
                next_rollover += self.interval
            self.rolloverAt = next_rollover

            if self.stream:
                try:
                    self.stream.close()
                except OSError:
                    pass
                self.stream = None
            self.stream = self._open()


def _resolve_log_dir(project_root, environ=None) -> Path:
    environ = environ or os.environ
    configured_log_dir = (environ.get("SHYNE_LOG_DIR") or "").strip()
    if configured_log_dir:
        return Path(configured_log_dir)
    return Path(project_root) / "instance" / "logs"


def _configure_logging(
    runtime: str,
    log_dir,
    *,
    enable_file_logging: bool = True,
    logger_name: str = "shynebeauty",
) -> logging.Logger:
    log_dir = log_dir if hasattr(log_dir, "mkdir") else Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    level = logging.DEBUG if runtime == APP_RUNTIME_DEMO_DEV else logging.INFO
    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    logger = logging.getLogger(logger_name)
    if getattr(logger, "_shyne_logging_configured", False):
        return logger

    logger.setLevel(level)
    logger.propagate = False
    logger._shyne_logging_configured = True

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt)
    console_handler.setLevel(logging.WARNING)
    logger.addHandler(console_handler)

    if not enable_file_logging:
        return logger

    try:
        file_handler = SafeTimedRotatingFileHandler(
            log_dir / "shynebeauty.log",
            when="midnight",
            backupCount=30,
            encoding="utf-8",
            delay=True,
        )
        file_handler.setFormatter(fmt)
        file_handler.setLevel(level)
        logger.addHandler(file_handler)
    except OSError as exc:
        logger.warning("File logging disabled: %s", exc)

    return logger


# Config docs and local setup store dotenv files at project root
load_project_env(BASE_DIR.parent)
_secret_key = require_env("SECRET_KEY")
if not _secret_key or not _secret_key.strip():
    raise RuntimeError(
        "SECRET_KEY environment variable is missing or empty. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )
app.config["SECRET_KEY"] = _secret_key
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

_configure_logging(
    app.config["APP_RUNTIME"],
    _resolve_log_dir(BASE_DIR.parent),
    enable_file_logging=not env_flag("DISABLE_FILE_LOGGING", default=False),
)

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
