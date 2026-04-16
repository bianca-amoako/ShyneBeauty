import json
import os
import secrets
import string
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse
from decimal import Decimal

import click
from dotenv import dotenv_values
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
try:
    from flask_admin.theme import Bootstrap4Theme
except ImportError:
    Bootstrap4Theme = None
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFError, CSRFProtect
from sqlalchemy.orm import validates
from sqlalchemy.orm.exc import ObjectDeletedError
from sqlalchemy import func, inspect, or_, text
from sqlalchemy.exc import InvalidRequestError, OperationalError
from werkzeug.security import check_password_hash, generate_password_hash
from .extensions import app

FAILED_LOGIN_THRESHOLD = 5
ACCOUNT_LOCK_DURATION = timedelta(minutes=15)
INVITE_EXPIRY_DURATION = timedelta(days=7)
BASE_DIR = Path(__file__).resolve().parent
AUTH_BIND_KEY = "auth"
PASSWORD_HASH_METHOD = "pbkdf2:sha256:1000000"
APP_RUNTIME_DEMO_DEV = "demo-dev"
APP_RUNTIME_LIVE_PROD = "live-prod"
APP_RUNTIME_CHOICES = (APP_RUNTIME_DEMO_DEV, APP_RUNTIME_LIVE_PROD)
DEV_TEST_ADMIN_EMAIL = "admin"
DEV_TEST_ADMIN_PASSWORD = "admin"
DEV_TEST_ADMIN_FULL_NAME = "Dev Admin"
ROLE_STAFF_OPERATOR = "Staff Operator"
ROLE_INVENTORY_PRODUCTION = "Inventory / Production"
ROLE_SUPERADMIN = "Superadmin"
ROLE_DEV_ADMIN = "Dev Admin"
BUSINESS_ROLE_CHOICES = (
    ROLE_STAFF_OPERATOR,
    ROLE_INVENTORY_PRODUCTION,
    ROLE_SUPERADMIN,
)
ALL_ROLE_CHOICES = BUSINESS_ROLE_CHOICES + (ROLE_DEV_ADMIN,)
ROLE_SLUG_MAP = {
    "staff-operator": ROLE_STAFF_OPERATOR,
    "inventory-production": ROLE_INVENTORY_PRODUCTION,
    "superadmin": ROLE_SUPERADMIN,
}
ROLE_LABEL_TO_SLUG = {label: slug for slug, label in ROLE_SLUG_MAP.items()}
ACCOUNT_STATUS_INVITED = "invited"
ACCOUNT_STATUS_ACTIVE = "active"
ACCOUNT_STATUS_SUSPENDED = "suspended"
ACCOUNT_STATUS_CHOICES = (
    ACCOUNT_STATUS_INVITED,
    ACCOUNT_STATUS_ACTIVE,
    ACCOUNT_STATUS_SUSPENDED,
)
PERMISSION_DASHBOARD_VIEW = "dashboard.view"
PERMISSION_ORDERS_VIEW = "orders.view"
PERMISSION_ORDERS_EDIT = "orders.edit"
PERMISSION_CUSTOMERS_VIEW = "customers.view"
PERMISSION_CUSTOMERS_EDIT = "customers.edit"
PERMISSION_SHIPPING_VIEW = "shipping.view"
PERMISSION_SHIPPING_EDIT = "shipping.edit"
PERMISSION_INVENTORY_VIEW = "inventory.view"
PERMISSION_INVENTORY_EDIT = "inventory.edit"
PERMISSION_PRODUCTION_VIEW = "production.view"
PERMISSION_PRODUCTION_EDIT = "production.edit"
PERMISSION_TASKS_VIEW = "tasks.view"
PERMISSION_TASKS_EDIT = "tasks.edit"
PERMISSION_REPORTS_VIEW = "reports.view"
PERMISSION_USERS_VIEW = "users.view"
PERMISSION_USERS_MANAGE = "users.manage"
PERMISSION_ADMIN_CONSOLE_ACCESS = "admin_console.access"
ALL_PERMISSION_KEYS = (
    PERMISSION_DASHBOARD_VIEW,
    PERMISSION_ORDERS_VIEW,
    PERMISSION_ORDERS_EDIT,
    PERMISSION_CUSTOMERS_VIEW,
    PERMISSION_CUSTOMERS_EDIT,
    PERMISSION_SHIPPING_VIEW,
    PERMISSION_SHIPPING_EDIT,
    PERMISSION_INVENTORY_VIEW,
    PERMISSION_INVENTORY_EDIT,
    PERMISSION_PRODUCTION_VIEW,
    PERMISSION_PRODUCTION_EDIT,
    PERMISSION_TASKS_VIEW,
    PERMISSION_TASKS_EDIT,
    PERMISSION_REPORTS_VIEW,
    PERMISSION_USERS_VIEW,
    PERMISSION_USERS_MANAGE,
    PERMISSION_ADMIN_CONSOLE_ACCESS,
)
PERMISSION_LABELS = {
    PERMISSION_DASHBOARD_VIEW: "Dashboard",
    PERMISSION_ORDERS_VIEW: "Orders",
    PERMISSION_ORDERS_EDIT: "Orders",
    PERMISSION_CUSTOMERS_VIEW: "Customers",
    PERMISSION_CUSTOMERS_EDIT: "Customers",
    PERMISSION_SHIPPING_VIEW: "Shipping",
    PERMISSION_SHIPPING_EDIT: "Shipping",
    PERMISSION_INVENTORY_VIEW: "Inventory",
    PERMISSION_INVENTORY_EDIT: "Inventory",
    PERMISSION_PRODUCTION_VIEW: "Production",
    PERMISSION_PRODUCTION_EDIT: "Production",
    PERMISSION_TASKS_VIEW: "Tasks",
    PERMISSION_TASKS_EDIT: "Tasks",
    PERMISSION_REPORTS_VIEW: "Reports",
    PERMISSION_USERS_VIEW: "Users & Access",
    PERMISSION_USERS_MANAGE: "Users & Access",
    PERMISSION_ADMIN_CONSOLE_ACCESS: "Admin Console",
}
OVERRIDE_ALLOWLIST = frozenset(
    permission
    for permission in ALL_PERMISSION_KEYS
    if permission != PERMISSION_ADMIN_CONSOLE_ACCESS
)
ROLE_PERMISSION_MAP = {
    ROLE_STAFF_OPERATOR: frozenset(
        {
            PERMISSION_DASHBOARD_VIEW,
            PERMISSION_ORDERS_VIEW,
            PERMISSION_ORDERS_EDIT,
            PERMISSION_CUSTOMERS_VIEW,
            PERMISSION_CUSTOMERS_EDIT,
            PERMISSION_SHIPPING_VIEW,
            PERMISSION_SHIPPING_EDIT,
            PERMISSION_INVENTORY_VIEW,
            PERMISSION_PRODUCTION_VIEW,
            PERMISSION_TASKS_VIEW,
            PERMISSION_TASKS_EDIT,
            PERMISSION_REPORTS_VIEW,
        }
    ),
    ROLE_INVENTORY_PRODUCTION: frozenset(
        {
            PERMISSION_DASHBOARD_VIEW,
            PERMISSION_ORDERS_VIEW,
            PERMISSION_CUSTOMERS_VIEW,
            PERMISSION_SHIPPING_VIEW,
            PERMISSION_INVENTORY_VIEW,
            PERMISSION_INVENTORY_EDIT,
            PERMISSION_PRODUCTION_VIEW,
            PERMISSION_PRODUCTION_EDIT,
            PERMISSION_TASKS_VIEW,
            PERMISSION_REPORTS_VIEW,
        }
    ),
    ROLE_SUPERADMIN: frozenset(
        {
            PERMISSION_DASHBOARD_VIEW,
            PERMISSION_ORDERS_VIEW,
            PERMISSION_ORDERS_EDIT,
            PERMISSION_CUSTOMERS_VIEW,
            PERMISSION_CUSTOMERS_EDIT,
            PERMISSION_SHIPPING_VIEW,
            PERMISSION_SHIPPING_EDIT,
            PERMISSION_INVENTORY_VIEW,
            PERMISSION_INVENTORY_EDIT,
            PERMISSION_PRODUCTION_VIEW,
            PERMISSION_PRODUCTION_EDIT,
            PERMISSION_TASKS_VIEW,
            PERMISSION_TASKS_EDIT,
            PERMISSION_REPORTS_VIEW,
            PERMISSION_USERS_VIEW,
            PERMISSION_USERS_MANAGE,
        }
    ),
    ROLE_DEV_ADMIN: frozenset(
        {
            PERMISSION_DASHBOARD_VIEW,
            PERMISSION_ORDERS_VIEW,
            PERMISSION_CUSTOMERS_VIEW,
            PERMISSION_SHIPPING_VIEW,
            PERMISSION_INVENTORY_VIEW,
            PERMISSION_PRODUCTION_VIEW,
            PERMISSION_TASKS_VIEW,
            PERMISSION_REPORTS_VIEW,
            PERMISSION_ADMIN_CONSOLE_ACCESS,
        }
    ),
}
ADMIN_ACCESS_EVENT_OUTCOME_SUCCESS = "success"
ADMIN_ACCESS_EVENT_OUTCOME_DENIED = "denied"
ADMIN_ACCESS_EVENT_OUTCOME_CANCELLED = "cancelled"
ADMIN_ACCESS_EVENT_INVITE_CREATED = "invite.created"
ADMIN_ACCESS_EVENT_INVITE_RESENT = "invite.resent"
ADMIN_ACCESS_EVENT_INVITE_CANCELLED = "invite.cancelled"
ADMIN_ACCESS_EVENT_ACCOUNT_ACTIVATED = "account.activated"
ADMIN_ACCESS_EVENT_ACCOUNT_CREATED = "account.created"
ADMIN_ACCESS_EVENT_PASSWORD_RESET = "account.password_reset"
ADMIN_ACCESS_EVENT_PASSWORD_CHANGED = "account.password_changed"
ADMIN_ACCESS_EVENT_ROLE_CHANGED = "account.role_changed"
ADMIN_ACCESS_EVENT_STATUS_CHANGED = "account.status_changed"
ADMIN_ACCESS_EVENT_ACCESS_DENIED = "access.denied"
CUSTOMER_SOURCE_OPTIONS = ("Fiverr", "Square", "Manual Entry")
GOOGLE_SHEETS_ORDER_SOURCE = "Google Sheets"
ORDER_PLATFORM_OPTIONS = ("Fiverr", "Square", GOOGLE_SHEETS_ORDER_SOURCE, "Direct")
ORDER_STATUS_OPTIONS = ("Placed", "Ready", "Completed")
IP_LOGIN_FAILURE_THRESHOLD = 5
IP_LOGIN_LOCK_DURATION = timedelta(minutes=15)
HTML_CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "style-src 'self' 'unsafe-inline'; "
    "script-src 'self' 'unsafe-inline'; "
    "font-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'self'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": HTML_CONTENT_SECURITY_POLICY,
    "Referrer-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
}
NO_STORE_ENDPOINTS = {
    "index",
    "change_password",
    "login",
    "logout",
    "orders",
    "tasks",
    "customers",
    "inventory",
    "users",
}
DEMO_USER_ACCOUNTS = (
    {
        "email": "Superadmin@demo.com",
        "full_name": "Demo Superadmin",
        "role": ROLE_SUPERADMIN,
        "password": "demo",
        "last_login_at": datetime(2026, 4, 14, 8, 45, tzinfo=timezone.utc),
    },
    {
        "email": "StaffOperator@demo.com",
        "full_name": "Demo Staff Operator",
        "role": ROLE_STAFF_OPERATOR,
        "password": "demo",
        "last_login_at": datetime(2026, 4, 13, 16, 20, tzinfo=timezone.utc),
    },
    {
        "email": "InventoryProduction@demo.com",
        "full_name": "Demo Inventory / Production",
        "role": ROLE_INVENTORY_PRODUCTION,
        "password": "demo",
        "last_login_at": None,
    },
    {
        "email": "DevAdmin@demo.com",
        "full_name": "Demo Dev Admin",
        "role": ROLE_DEV_ADMIN,
        "password": "demo",
        "last_login_at": datetime(2026, 4, 14, 7, 55, tzinfo=timezone.utc),
    },
)


def require_env(name):
    value = os.getenv(name)
    if value:
        return value
    raise RuntimeError(f"{name} environment variable must be set.")


def env_flag(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def dotenv_candidates(base_dir=BASE_DIR):
    base_path = Path(base_dir)
    return (
        base_path / ".env",
        base_path / ".env" / "local.env",
        base_path / ".env" / ".env",
    )


def load_project_env(base_dir=BASE_DIR):
    for candidate in dotenv_candidates(base_dir):
        if not candidate.is_file():
            continue

        for key, value in dotenv_values(candidate).items():
            if value is not None and key not in os.environ:
                os.environ[key] = value
        return candidate

    return None


def default_runtime_for_process(invoked_as_main=False):
    del invoked_as_main
    return APP_RUNTIME_DEMO_DEV


def runtime_default_flag(runtime, *, demo_default, live_default):
    return live_default if runtime == APP_RUNTIME_LIVE_PROD else demo_default


def instance_database_uris(base_dir):
    instance_dir = Path(base_dir) / "instance"
    return {
        APP_RUNTIME_DEMO_DEV: {
            "primary": f"sqlite:///{(instance_dir / 'shynebeauty_demo.db').as_posix()}",
            "auth": f"sqlite:///{(instance_dir / 'shynebeauty_demo_auth.db').as_posix()}",
        },
        APP_RUNTIME_LIVE_PROD: {
            "primary": f"sqlite:///{(instance_dir / 'shynebeauty_live.db').as_posix()}",
            "auth": f"sqlite:///{(instance_dir / 'shynebeauty_live_auth.db').as_posix()}",
        },
    }


def resolve_runtime_database_config(base_dir=BASE_DIR, environ=None):
    environ = os.environ if environ is None else environ
    runtime = (environ.get("APP_RUNTIME") or "").strip() or default_runtime_for_process()
    if runtime not in APP_RUNTIME_CHOICES:
        raise RuntimeError(
            "APP_RUNTIME must be one of: " + ", ".join(APP_RUNTIME_CHOICES)
        )

    defaults = instance_database_uris(base_dir)[runtime]
    primary_uri = (environ.get("DATABASE_URL") or "").strip() or defaults["primary"]
    auth_uri = (environ.get("AUTH_DATABASE_URL") or "").strip() or defaults["auth"]
    return {
        "runtime": runtime,
        "primary_uri": primary_uri,
        "auth_uri": auth_uri,
        "database_override": bool((environ.get("DATABASE_URL") or "").strip()),
        "auth_database_override": bool((environ.get("AUTH_DATABASE_URL") or "").strip()),
        "defaults": defaults,
        "runtime_defaults": instance_database_uris(base_dir),
    }


def runtime_init_command_hint(runtime=None):
    target_runtime = runtime or app.config.get("APP_RUNTIME") or default_runtime_for_process()
    if target_runtime == APP_RUNTIME_LIVE_PROD:
        return "flask --app shyne.py init-live-db"
    return "flask --app shyne.py init-db"


def utc_now():
    return datetime.now(timezone.utc)


def ensure_utc(value):
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


def normalize_email(value):
    return (value or "").strip().lower()


def password_policy_errors(password, *, email=None, current_password=None):
    normalized_password = password or ""
    errors = []
    if len(normalized_password) < 12:
        errors.append("Password must be at least 12 characters.")

    normalized_email = normalize_email(email)
    if normalized_email:
        email_fragments = {
            fragment
            for fragment in normalized_email.replace("@", ".").split(".")
            if len(fragment) >= 3
        }
        lower_password = normalized_password.lower()
        if any(fragment in lower_password for fragment in email_fragments):
            errors.append("Password cannot contain your email address.")

    disallowed_passwords = {
        "admin",
        "password",
        "changeme",
        DEV_TEST_ADMIN_PASSWORD.lower(),
        "correct-horse-battery-staple",
        "shynedemosuper1!",
        "shynedemostaff1!",
        "shynedemoinventory1!",
        "shynedemodev1!",
    }
    if normalized_password.lower() in disallowed_passwords:
        errors.append("Password must not use a common or demo fallback credential.")

    if current_password and normalized_password == current_password:
        errors.append("Choose a password different from the temporary password.")

    return errors


def parse_non_negative_decimal(raw_value, *, field_label):
    normalized = (raw_value or "").strip()
    if not normalized:
        raise ValueError(f"{field_label} is required.")
    try:
        value = Decimal(normalized)
    except InvalidOperation as exc:
        raise ValueError(f"{field_label} must be a valid number.") from exc
    if value < 0:
        raise ValueError(f"{field_label} cannot be negative.")
    return value


def read_line_items_form_data(form):
    product_ids = form.getlist("product_id")
    quantities = form.getlist("quantity")
    unit_prices = form.getlist("unit_price")
    lengths_match = len({len(product_ids), len(quantities), len(unit_prices)}) == 1
    max_length = max(len(product_ids), len(quantities), len(unit_prices), 1)

    line_items = []
    for index in range(max_length):
        line_items.append(
            {
                "product_id": (
                    product_ids[index].strip() if index < len(product_ids) else ""
                ),
                "quantity": (
                    quantities[index].strip() if index < len(quantities) else ""
                ),
                "unit_price": (
                    unit_prices[index].strip() if index < len(unit_prices) else ""
                ),
            }
        )

    return line_items, lengths_match


def is_safe_next_target(target):
    if not target:
        return False

    candidate = target.strip()
    normalized_candidate = candidate.replace("\\", "/")

    if not normalized_candidate.startswith("/") or normalized_candidate.startswith("//"):
        return False

    parts = urlparse(normalized_candidate)
    return not parts.scheme and not parts.netloc


def get_safe_next_target(target):
    if not target:
        return ""

    candidate = target.strip()
    normalized_candidate = candidate.replace("\\", "/")
    parsed = urlparse(normalized_candidate)
    if (
        normalized_candidate.startswith("/")
        and not normalized_candidate.startswith("//")
        and not parsed.scheme
        and not parsed.netloc
    ):
        return normalized_candidate
    return ""


def get_safe_referrer_target(target):
    if not target:
        return ""

    candidate = target.strip()
    if "\\" in candidate:
        return ""

    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"}:
        return ""
    if parsed.netloc != request.host:
        return ""
    if not parsed.path:
        return ""

    local_target = parsed.path
    if parsed.query:
        local_target = f"{local_target}?{parsed.query}"
    return get_safe_next_target(local_target)


def redirect_to_safe_next(target, *, fallback_endpoint="index"):
    safe_target = get_safe_next_target(target)
    if safe_target:
        return redirect(safe_target)
    return redirect(url_for(fallback_endpoint))


@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    flash(error.description or "Invalid CSRF token.", "error")

    if request.endpoint == "login":
        return render_template(
            "login.html",
            form_data={"email": "", "remember_me": False},
            next_url=get_safe_next_target(request.args.get("next")),
        ), 400

    if request.endpoint == "change_password":
        return render_template(
            "change_password.html",
            next_url=get_safe_next_target(request.args.get("next")),
        ), 400

    safe_referrer = get_safe_referrer_target(request.referrer)
    if safe_referrer:
        return redirect(safe_referrer)
    return redirect(url_for("index"))


def current_request_next_target():
    if request.query_string:
        return f"{request.path}?{request.query_string.decode('utf-8')}"
    return request.path


def revoke_authenticated_session(*, redirect_to_login=True):
    session.clear()
    logout_user()
    flash(
        "Your session is no longer active. Sign in again or contact a superadmin.",
        "error",
    )
    if not redirect_to_login:
        return None

    safe_next = get_safe_next_target(current_request_next_target())
    if safe_next:
        return redirect(url_for("login", next=safe_next))
    return redirect(url_for("login"))


def generate_temporary_password(length=16):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def slug_to_role_label(value):
    if value not in ROLE_SLUG_MAP:
        raise click.ClickException(
            "Role must be one of: "
            + ", ".join(sorted(ROLE_SLUG_MAP))
            + "."
        )
    return ROLE_SLUG_MAP[value]


def serialize_state(value):
    if value is None:
        return None
    return json.dumps(value, sort_keys=True)


def deserialize_state(value, default=None):
    if not value:
        return [] if default is None else default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return [] if default is None else default


def unique_strings(values):
    return sorted({value for value in values if value})
