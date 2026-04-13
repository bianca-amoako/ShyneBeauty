import json
import os
import secrets
import string
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

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
except ImportError:  # Flask-Admin < 2.0
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
from sqlalchemy.orm import validates
from sqlalchemy import inspect, or_, text
from sqlalchemy.exc import OperationalError
from werkzeug.security import check_password_hash, generate_password_hash

FAILED_LOGIN_THRESHOLD = 5
ACCOUNT_LOCK_DURATION = timedelta(minutes=15)
INVITE_EXPIRY_DURATION = timedelta(days=7)
BASE_DIR = Path(__file__).resolve().parent
AUTH_BIND_KEY = "auth"
PASSWORD_HASH_METHOD = "pbkdf2:sha256:1000000"
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
SECURITY_HEADERS = {
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


load_project_env()

app = Flask(__name__)
app.config["SECRET_KEY"] = require_env("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL", "sqlite:///shynebeauty.db"
)
app.config["SQLALCHEMY_BINDS"] = {
    AUTH_BIND_KEY: os.getenv("AUTH_DATABASE_URL", "sqlite:///shynebeauty_auth.db")
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["ENABLE_DEV_TEST_ADMIN"] = env_flag("ENABLE_DEV_TEST_ADMIN", default=False)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = env_flag("SESSION_COOKIE_SECURE", default=False)
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
app.config["REMEMBER_COOKIE_SECURE"] = app.config["SESSION_COOKIE_SECURE"]

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please sign in to continue."
login_manager.login_message_category = "info"


def utc_now():
    return datetime.now(timezone.utc)


def ensure_utc(value):
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


def normalize_email(value):
    return (value or "").strip().lower()


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


def redirect_to_safe_next(target, *, fallback_endpoint="index"):
    safe_target = get_safe_next_target(target)
    if safe_target:
        return redirect(safe_target)
    return redirect(url_for(fallback_endpoint))


def current_request_next_target():
    if request.query_string:
        return f"{request.path}?{request.query_string.decode('utf-8')}"
    return request.path


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


def dev_test_admin_enabled(flask_app=None):
    target_app = flask_app or app
    return bool(target_app.config.get("ENABLE_DEV_TEST_ADMIN")) and (
        target_app.testing or target_app.debug
    )


def is_dev_test_admin_email(email):
    return normalize_email(email) == DEV_TEST_ADMIN_EMAIL


def is_dev_test_admin_account(admin_user):
    return admin_user is not None and is_dev_test_admin_email(admin_user.email)


def dev_test_admin_seeded():
    if not dev_test_admin_enabled():
        return False
    return (
        db.session.query(AdminUser.id)
        .filter_by(email=DEV_TEST_ADMIN_EMAIL)
        .first()
        is not None
    )


def require_dev_test_admin_mode(flask_app=None):
    if dev_test_admin_enabled(flask_app):
        return

    raise click.ClickException(
        "seed-dev-admin is only available when ENABLE_DEV_TEST_ADMIN=true "
        "and the app is running in debug or testing mode."
    )


def ensure_customer_source_column():
    inspector = inspect(db.engine)
    if "customers" not in inspector.get_table_names():
        return

    customer_columns = {
        column["name"] for column in inspector.get_columns("customers")
    }
    if "source" in customer_columns:
        return

    with db.engine.begin() as connection:
        connection.execute(
            text("ALTER TABLE customers ADD COLUMN source VARCHAR(120)")
        )
        connection.execute(
            text("CREATE INDEX IF NOT EXISTS idx_customers_source ON customers (source)")
        )


def ensure_admin_user_access_columns():
    auth_engine = db.engines[AUTH_BIND_KEY]
    inspector = inspect(auth_engine)
    if "admin_users" not in inspector.get_table_names():
        return

    def read_admin_user_columns():
        return {
            column["name"] for column in inspect(auth_engine).get_columns("admin_users")
        }

    admin_user_columns = read_admin_user_columns()
    missing_columns = {
        "role": "ALTER TABLE admin_users ADD COLUMN role VARCHAR(64)",
        "account_status": "ALTER TABLE admin_users ADD COLUMN account_status VARCHAR(32)",
        "invited_at": "ALTER TABLE admin_users ADD COLUMN invited_at DATETIME",
        "invited_by_user_id": "ALTER TABLE admin_users ADD COLUMN invited_by_user_id INTEGER",
        "activated_at": "ALTER TABLE admin_users ADD COLUMN activated_at DATETIME",
        "suspended_at": "ALTER TABLE admin_users ADD COLUMN suspended_at DATETIME",
        "suspended_by_user_id": "ALTER TABLE admin_users ADD COLUMN suspended_by_user_id INTEGER",
        "access_granted_by_user_id": "ALTER TABLE admin_users ADD COLUMN access_granted_by_user_id INTEGER",
        "last_role_changed_at": "ALTER TABLE admin_users ADD COLUMN last_role_changed_at DATETIME",
        "last_role_changed_by_user_id": "ALTER TABLE admin_users ADD COLUMN last_role_changed_by_user_id INTEGER",
        "permission_overrides_json": "ALTER TABLE admin_users ADD COLUMN permission_overrides_json TEXT",
        "must_change_password": (
            "ALTER TABLE admin_users "
            "ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT 0"
        ),
    }

    with auth_engine.begin() as connection:
        for column_name, statement in missing_columns.items():
            if column_name not in admin_user_columns:
                try:
                    connection.execute(text(statement))
                except OperationalError as exc:
                    if "duplicate column name" not in str(exc).lower():
                        raise
                admin_user_columns = read_admin_user_columns()

        if "role" in admin_user_columns:
            connection.execute(
                text("CREATE INDEX IF NOT EXISTS idx_admin_users_role ON admin_users (role)")
            )
        if "account_status" in admin_user_columns:
            connection.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS idx_admin_users_account_status "
                    "ON admin_users (account_status)"
                )
            )


def ensure_runtime_auth_schema_compatibility():
    auth_engine = db.engines[AUTH_BIND_KEY]
    inspector = inspect(auth_engine)
    if "admin_users" not in inspector.get_table_names():
        return

    # Keep older auth databases readable by adding the shipped access columns
    # and audit table before request-time queries hit the ORM.
    AdminAccessEvent.__table__.create(bind=auth_engine, checkfirst=True)
    ensure_admin_user_access_columns()


class AdminUser(UserMixin, db.Model):
    __bind_key__ = AUTH_BIND_KEY
    __tablename__ = "admin_users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255))
    full_name = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    role = db.Column(db.String(64), index=True)
    account_status = db.Column(db.String(32), index=True)
    invited_at = db.Column(db.DateTime(timezone=True))
    invited_by_user_id = db.Column(db.Integer)
    activated_at = db.Column(db.DateTime(timezone=True))
    suspended_at = db.Column(db.DateTime(timezone=True))
    suspended_by_user_id = db.Column(db.Integer)
    access_granted_by_user_id = db.Column(db.Integer)
    last_role_changed_at = db.Column(db.DateTime(timezone=True))
    last_role_changed_by_user_id = db.Column(db.Integer)
    permission_overrides_json = db.Column(db.Text)
    must_change_password = db.Column(db.Boolean, nullable=False, default=False)
    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime(timezone=True))
    last_login_at = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(
        db.DateTime(timezone=True), default=utc_now, nullable=False
    )

    @validates("email")
    def validate_email(self, _key, value):
        normalized = normalize_email(value)
        if not normalized:
            raise ValueError("Email is required.")
        return normalized

    @validates("role")
    def validate_role(self, _key, value):
        if value in {None, ""}:
            return None
        if value not in ALL_ROLE_CHOICES:
            raise ValueError("Role must use one of the fixed v1 role labels.")
        return value

    @validates("account_status")
    def validate_account_status(self, _key, value):
        if value in {None, ""}:
            return None
        if value not in ACCOUNT_STATUS_CHOICES:
            raise ValueError("Account status must be invited, active, or suspended.")
        return value

    def set_password(self, password):
        if not password:
            raise ValueError("Password is required.")
        self.password_hash = generate_password_hash(
            password, method=PASSWORD_HASH_METHOD
        )

    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def get_role(self):
        return self.role or ROLE_STAFF_OPERATOR

    def get_account_status(self):
        if self.account_status in ACCOUNT_STATUS_CHOICES:
            return self.account_status
        return ACCOUNT_STATUS_ACTIVE if self.is_active else ACCOUNT_STATUS_SUSPENDED

    def sync_legacy_state(self):
        self.is_active = self.get_account_status() == ACCOUNT_STATUS_ACTIVE
        if self.role is None:
            self.role = self.get_role()

    def set_account_status(self, status, *, actor=None, now=None):
        comparison_time = now or utc_now()
        self.account_status = status
        self.is_active = status == ACCOUNT_STATUS_ACTIVE
        if status == ACCOUNT_STATUS_ACTIVE:
            self.suspended_at = None
            self.suspended_by_user_id = None
            if self.activated_at is None:
                self.activated_at = comparison_time
            if actor is not None:
                self.access_granted_by_user_id = actor.id
        elif status == ACCOUNT_STATUS_INVITED:
            self.invited_at = comparison_time
            self.activated_at = None
            self.suspended_at = None
            self.suspended_by_user_id = None
            self.access_granted_by_user_id = None if actor is None else actor.id
        elif status == ACCOUNT_STATUS_SUSPENDED:
            self.suspended_at = comparison_time
            self.suspended_by_user_id = None if actor is None else actor.id

    def set_role(self, role, *, actor=None, now=None):
        comparison_time = now or utc_now()
        self.role = role
        self.last_role_changed_at = comparison_time
        self.last_role_changed_by_user_id = None if actor is None else actor.id

    def set_permission_overrides(self, permission_keys):
        permission_keys = unique_strings(permission_keys)
        unknown_keys = set(permission_keys) - OVERRIDE_ALLOWLIST
        if unknown_keys:
            raise ValueError(
                "Permission overrides must use the allowlisted bundle keys only."
            )
        self.permission_overrides_json = serialize_state(permission_keys)

    def get_permission_overrides(self):
        overrides = deserialize_state(self.permission_overrides_json, default=[])
        if not isinstance(overrides, list):
            return []
        return unique_strings(
            value for value in overrides if isinstance(value, str) and value in OVERRIDE_ALLOWLIST
        )

    def is_locked(self, now=None):
        if self.locked_until is None:
            return False
        comparison_time = now or utc_now()
        return ensure_utc(self.locked_until) > comparison_time

    def is_invite_expired(self, now=None):
        if self.get_account_status() != ACCOUNT_STATUS_INVITED or self.invited_at is None:
            return False
        comparison_time = now or utc_now()
        return ensure_utc(self.invited_at) + INVITE_EXPIRY_DURATION <= comparison_time

    def register_failed_login(self, now=None):
        comparison_time = now or utc_now()

        if self.locked_until and not self.is_locked(comparison_time):
            self.failed_login_count = 0
            self.locked_until = None

        self.failed_login_count += 1
        if self.failed_login_count >= FAILED_LOGIN_THRESHOLD:
            self.locked_until = comparison_time + ACCOUNT_LOCK_DURATION

    def reset_login_state(self):
        self.failed_login_count = 0
        self.locked_until = None

    def requires_password_change(self):
        return bool(self.must_change_password)

    def display_status(self, now=None):
        if self.is_locked(now):
            return "Locked"
        if self.is_invite_expired(now):
            return "Expired invite"
        status = self.get_account_status()
        if status == ACCOUNT_STATUS_INVITED:
            return "Pending invite"
        if status == ACCOUNT_STATUS_ACTIVE:
            return "Active"
        if status == ACCOUNT_STATUS_SUSPENDED:
            return "Suspended"
        return "Unknown"

    def role_slug(self):
        return ROLE_LABEL_TO_SLUG.get(self.get_role(), "")


class AdminAccessEvent(db.Model):
    __bind_key__ = AUTH_BIND_KEY
    __tablename__ = "admin_access_events"

    id = db.Column(db.Integer, primary_key=True)
    actor_user_id = db.Column(db.Integer, index=True)
    target_user_id = db.Column(db.Integer, index=True)
    event_type = db.Column(db.String(80), nullable=False, index=True)
    outcome = db.Column(db.String(32), nullable=False, index=True)
    before_state_json = db.Column(db.Text)
    after_state_json = db.Column(db.Text)
    note = db.Column(db.Text)
    created_at = db.Column(
        db.DateTime(timezone=True), default=utc_now, nullable=False, index=True
    )


class Customer(db.Model):
    __tablename__ = "customers"

    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(40))
    street_address = db.Column(db.String(255))
    city = db.Column(db.String(120))
    state = db.Column(db.String(120))
    postal_code = db.Column(db.String(30))
    country = db.Column(db.String(120), default="USA")
    source = db.Column(db.String(120), index=True)
    created_at = db.Column(
        db.DateTime(timezone=True), default=utc_now, nullable=False
    )

    orders = db.relationship("Order", back_populates="customer", lazy=True)

    @validates("source")
    def validate_source(self, _key, value):
        normalized = (value or "").strip()
        if not normalized:
            return None
        if normalized not in CUSTOMER_SOURCE_OPTIONS:
            raise ValueError(
                "Customer source must be one of: "
                + ", ".join(CUSTOMER_SOURCE_OPTIONS)
                + "."
            )
        return normalized


class Product(db.Model):
    __tablename__ = "products"

    id = db.Column(db.Integer, primary_key=True)
    sku = db.Column(db.String(80), unique=True, nullable=False, index=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    reorder_threshold = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(
        db.DateTime(timezone=True), default=utc_now, nullable=False
    )

    order_items = db.relationship("OrderItem", back_populates="product", lazy=True)
    product_batches = db.relationship("ProductBatch", back_populates="product", lazy=True)


class Ingredient(db.Model):
    __tablename__ = "ingredients"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True, nullable=False, index=True)
    stock_quantity = db.Column(db.Numeric(10, 3), nullable=False, default=0)
    unit = db.Column(db.String(30), nullable=False, default="g")
    supplier_name = db.Column(db.String(200))
    supplier_contact = db.Column(db.String(255))
    reorder_threshold = db.Column(db.Numeric(10, 3), nullable=False, default=0)
    created_at = db.Column(
        db.DateTime(timezone=True), default=utc_now, nullable=False
    )

    batch_ingredients = db.relationship(
        "BatchIngredient", back_populates="ingredient", lazy=True
    )


class Batch(db.Model):
    __tablename__ = "batches"

    id = db.Column(db.Integer, primary_key=True)
    batch_code = db.Column(db.String(80), unique=True, nullable=False, index=True)
    status = db.Column(db.String(50), nullable=False, default="Open")
    started_at = db.Column(
        db.DateTime(timezone=True), default=utc_now, nullable=False
    )
    ended_at = db.Column(db.DateTime(timezone=True))
    notes = db.Column(db.Text)

    batch_ingredients = db.relationship(
        "BatchIngredient", back_populates="batch", lazy=True, cascade="all, delete-orphan"
    )
    product_batches = db.relationship(
        "ProductBatch", back_populates="batch", lazy=True, cascade="all, delete-orphan"
    )


class ProductBatch(db.Model):
    __tablename__ = "product_batches"

    id = db.Column(db.Integer, primary_key=True)
    batch_id = db.Column(db.Integer, db.ForeignKey("batches.id"), nullable=False, index=True)
    product_id = db.Column(
        db.Integer, db.ForeignKey("products.id"), nullable=False, index=True
    )
    lot_number = db.Column(db.String(120), unique=True, nullable=False, index=True)
    units_produced = db.Column(db.Integer, nullable=False, default=0)
    units_available = db.Column(db.Integer, nullable=False, default=0)
    expiry_date = db.Column(db.Date)
    created_at = db.Column(
        db.DateTime(timezone=True), default=utc_now, nullable=False
    )

    batch = db.relationship("Batch", back_populates="product_batches")
    product = db.relationship("Product", back_populates="product_batches")
    order_items = db.relationship("OrderItem", back_populates="product_batch", lazy=True)


class Order(db.Model):
    __tablename__ = "orders"

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(
        db.Integer, db.ForeignKey("customers.id"), nullable=False, index=True
    )
    order_number = db.Column(db.String(100), unique=True, nullable=False, index=True)
    platform = db.Column(db.String(120), nullable=False, default="Direct")
    total_amount = db.Column(db.Numeric(10, 2), nullable=False, default=0)
    status = db.Column(db.String(50), nullable=False, default="Placed", index=True)
    placed_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    customer = db.relationship("Customer", back_populates="orders")
    order_items = db.relationship(
        "OrderItem", back_populates="order", lazy=True, cascade="all, delete-orphan"
    )
    status_events = db.relationship(
        "OrderStatusEvent",
        back_populates="order",
        lazy=True,
        cascade="all, delete-orphan",
    )
    shipment = db.relationship(
        "Shipment",
        back_populates="order",
        uselist=False,
        cascade="all, delete-orphan",
    )


class OrderItem(db.Model):
    __tablename__ = "order_items"

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=False, index=True)
    product_id = db.Column(
        db.Integer, db.ForeignKey("products.id"), nullable=False, index=True
    )
    product_batch_id = db.Column(db.Integer, db.ForeignKey("product_batches.id"), index=True)
    quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.Numeric(10, 2), nullable=False)

    order = db.relationship("Order", back_populates="order_items")
    product = db.relationship("Product", back_populates="order_items")
    product_batch = db.relationship("ProductBatch", back_populates="order_items")


class BatchIngredient(db.Model):
    __tablename__ = "batch_ingredients"

    id = db.Column(db.Integer, primary_key=True)
    batch_id = db.Column(db.Integer, db.ForeignKey("batches.id"), nullable=False, index=True)
    ingredient_id = db.Column(
        db.Integer, db.ForeignKey("ingredients.id"), nullable=False, index=True
    )
    quantity_used = db.Column(db.Numeric(10, 3), nullable=False)
    unit = db.Column(db.String(30), nullable=False, default="g")

    batch = db.relationship("Batch", back_populates="batch_ingredients")
    ingredient = db.relationship("Ingredient", back_populates="batch_ingredients")


class OrderStatusEvent(db.Model):
    __tablename__ = "order_status_events"

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=False, index=True)
    event_status = db.Column(db.String(60), nullable=False, index=True)
    message = db.Column(db.Text)
    created_at = db.Column(
        db.DateTime(timezone=True), default=utc_now, nullable=False
    )

    order = db.relationship("Order", back_populates="status_events")


class Shipment(db.Model):
    __tablename__ = "shipments"

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=False, unique=True)
    carrier = db.Column(db.String(120))
    tracking_number = db.Column(db.String(120), unique=True, index=True)
    tracking_url = db.Column(db.String(500))
    shipped_at = db.Column(db.DateTime(timezone=True))
    delivered_at = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(
        db.DateTime(timezone=True), default=utc_now, nullable=False
    )

    order = db.relationship("Order", back_populates="shipment")


def summarize_permissions(permission_keys):
    labels = []
    for permission_key in permission_keys:
        label = PERMISSION_LABELS.get(permission_key)
        if label and label not in labels:
            labels.append(label)
    return labels


def serialize_admin_user_snapshot(admin_user, *, now=None):
    comparison_time = now or utc_now()
    return {
        "email": admin_user.email,
        "full_name": admin_user.full_name,
        "role": admin_user.get_role(),
        "account_status": admin_user.get_account_status(),
        "display_status": admin_user.display_status(comparison_time),
        "is_active": bool(admin_user.is_active),
        "is_locked": admin_user.is_locked(comparison_time),
        "must_change_password": admin_user.requires_password_change(),
        "permission_overrides": admin_user.get_permission_overrides(),
    }


def log_admin_access_event(
    *,
    actor=None,
    target=None,
    event_type,
    outcome,
    before_state=None,
    after_state=None,
    note=None,
):
    db.session.add(
        AdminAccessEvent(
            actor_user_id=None if actor is None else actor.id,
            target_user_id=None if target is None else target.id,
            event_type=event_type,
            outcome=outcome,
            before_state_json=serialize_state(before_state),
            after_state_json=serialize_state(after_state),
            note=note,
        )
    )


def get_effective_permissions(admin_user):
    if admin_user is None:
        return frozenset()
    role_permissions = ROLE_PERMISSION_MAP.get(admin_user.get_role(), frozenset())
    override_permissions = frozenset(admin_user.get_permission_overrides())
    return frozenset(role_permissions.union(override_permissions))


def has_permission(permission_key, admin_user=None, *, now=None):
    target_user = admin_user or current_user
    if not getattr(target_user, "is_authenticated", False):
        return False
    if target_user.get_account_status() != ACCOUNT_STATUS_ACTIVE:
        return False
    if target_user.is_locked(now):
        return False
    return permission_key in get_effective_permissions(target_user)


def is_superadmin(admin_user=None):
    target_user = admin_user or current_user
    return getattr(target_user, "is_authenticated", False) and (
        target_user.get_role() == ROLE_SUPERADMIN
    )


def is_dev_admin(admin_user=None):
    target_user = admin_user or current_user
    return getattr(target_user, "is_authenticated", False) and (
        target_user.get_role() == ROLE_DEV_ADMIN
    )


def is_last_active_superadmin(admin_user, *, now=None):
    if admin_user is None or admin_user.get_role() != ROLE_SUPERADMIN:
        return False
    comparison_time = now or utc_now()
    active_superadmins = (
        AdminUser.query.filter(
            AdminUser.role == ROLE_SUPERADMIN,
            AdminUser.account_status == ACCOUNT_STATUS_ACTIVE,
        )
        .all()
    )
    return len(
        [user for user in active_superadmins if not user.is_locked(comparison_time)]
    ) <= 1


def role_scope_summary(role_label):
    return {
        ROLE_STAFF_OPERATOR: "Orders, customers, shipping, tasks",
        ROLE_INVENTORY_PRODUCTION: "Inventory, production, stock",
        ROLE_SUPERADMIN: "Business admin and users",
        ROLE_DEV_ADMIN: "Technical console access",
    }.get(role_label, "Operational access")


def password_state_label(admin_user):
    return (
        "Temporary password; must change at next login"
        if admin_user.requires_password_change()
        else "Ready for normal sign-in"
    )


def resolve_actor_name(user_id):
    if not user_id:
        return "System"
    admin_user = db.session.get(AdminUser, user_id)
    if admin_user is None:
        return "Unknown user"
    return admin_user.full_name or admin_user.email


def force_password_change_allowed_endpoint(endpoint):
    if endpoint is None:
        return True
    return endpoint in {"change_password", "logout", "static"}


def parse_last_login_state(admin_user, *, now=None):
    comparison_time = now or utc_now()
    if admin_user.is_locked(comparison_time):
        return "locked"
    if admin_user.last_login_at is None:
        return "never"
    if ensure_utc(admin_user.last_login_at) >= comparison_time - timedelta(days=14):
        return "recent"
    return "stale"


def visible_users_query():
    return AdminUser.query.filter(
        or_(AdminUser.role.is_(None), AdminUser.role != ROLE_DEV_ADMIN)
    )


def users_redirect_response(
    *,
    selected_user_id=None,
    show_invite=False,
    search="",
    role_filter="",
    status_filter="",
    last_login_filter="",
):
    query_params = {}
    if search:
        query_params["search"] = search
    if role_filter:
        query_params["role_filter"] = role_filter
    if status_filter:
        query_params["status_filter"] = status_filter
    if last_login_filter:
        query_params["last_login_filter"] = last_login_filter
    if selected_user_id is not None:
        query_params["selected_user"] = selected_user_id
    if show_invite:
        query_params["show_invite"] = "1"
    return redirect(url_for("users", **query_params))


def read_users_filter_state(source=None):
    source = source or request.values
    return {
        "search": (source.get("search") or "").strip(),
        "role_filter": (source.get("role_filter") or "").strip(),
        "status_filter": (source.get("status_filter") or "").strip(),
        "last_login_filter": (source.get("last_login_filter") or "").strip(),
    }


def get_visible_user_or_none(user_id):
    if not user_id:
        return None
    return visible_users_query().filter(AdminUser.id == user_id).first()


def deny_sensitive_users_action(target_user, *, note):
    flash(note, "error")
    log_admin_access_event(
        actor=current_user,
        target=target_user,
        event_type=ADMIN_ACCESS_EVENT_ACCESS_DENIED,
        outcome=ADMIN_ACCESS_EVENT_OUTCOME_DENIED,
        note=note,
    )
    db.session.commit()


def sort_visible_users(users, *, now=None):
    comparison_time = now or utc_now()
    status_priority = {
        "Active": 0,
        "Locked": 1,
        "Pending invite": 2,
        "Expired invite": 3,
        "Suspended": 4,
    }
    return sorted(
        users,
        key=lambda user: (
            status_priority.get(user.display_status(comparison_time), 99),
            (user.full_name or "").lower(),
            user.email.lower(),
        ),
    )


def require_permission(permission_key, *, denial_title="Access denied", denial_message=None):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if has_permission(permission_key):
                return view_func(*args, **kwargs)

            log_admin_access_event(
                actor=current_user,
                target=current_user,
                event_type=ADMIN_ACCESS_EVENT_ACCESS_DENIED,
                outcome=ADMIN_ACCESS_EVENT_OUTCOME_DENIED,
                note=f"{request.method} {request.path}",
            )
            db.session.commit()
            return (
                render_template(
                    "access_denied.html",
                    page_title=denial_title,
                    denial_message=denial_message
                    or "You do not have permission to access this page.",
                ),
                403,
            )

        return wrapped

    return decorator


class SecureAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return has_permission(PERMISSION_ADMIN_CONSOLE_ACCESS)

    def inaccessible_callback(self, name, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("login", next=current_request_next_target()))
        log_admin_access_event(
            actor=current_user,
            target=current_user,
            event_type=ADMIN_ACCESS_EVENT_ACCESS_DENIED,
            outcome=ADMIN_ACCESS_EVENT_OUTCOME_DENIED,
            note=f"GET {request.path}",
        )
        db.session.commit()
        return (
            render_template(
                "access_denied.html",
                page_title="Admin console access denied",
                denial_message="Dev Admin access is required to use the technical admin console.",
            ),
            403,
        )


class LiveDataModelView(ModelView):
    # Internal admin UI for live table browsing/editing during development.
    can_view_details = True
    can_export = True
    page_size = 50
    column_display_pk = True

    def is_accessible(self):
        return has_permission(PERMISSION_ADMIN_CONSOLE_ACCESS)

    def inaccessible_callback(self, name, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("login", next=current_request_next_target()))
        log_admin_access_event(
            actor=current_user,
            target=current_user,
            event_type=ADMIN_ACCESS_EVENT_ACCESS_DENIED,
            outcome=ADMIN_ACCESS_EVENT_OUTCOME_DENIED,
            note=f"GET {request.path}",
        )
        db.session.commit()
        return (
            render_template(
                "access_denied.html",
                page_title="Admin console access denied",
                denial_message="Dev Admin access is required to use the technical admin console.",
            ),
            403,
        )


# Model map used to register all SQLAlchemy tables in Flask-Admin.
MODEL_REGISTRY = {
    Customer.__tablename__: Customer,
    Product.__tablename__: Product,
    Ingredient.__tablename__: Ingredient,
    Batch.__tablename__: Batch,
    ProductBatch.__tablename__: ProductBatch,
    Order.__tablename__: Order,
    OrderItem.__tablename__: OrderItem,
    BatchIngredient.__tablename__: BatchIngredient,
    OrderStatusEvent.__tablename__: OrderStatusEvent,
    Shipment.__tablename__: Shipment,
}


admin = Admin(
    app,
    name="ShyneBeauty Admin",
    index_view=SecureAdminIndexView(url="/admin/"),
    **({"theme": Bootstrap4Theme()} if Bootstrap4Theme is not None else {}),
)
_admin_views_registered = False


def register_admin_views():
    global _admin_views_registered
    if _admin_views_registered:
        return

    for table_name, model in MODEL_REGISTRY.items():
        admin.add_view(LiveDataModelView(model, db.session, name=table_name))

    _admin_views_registered = True


register_admin_views()


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(AdminUser, int(user_id))
    except (TypeError, ValueError):
        return None


@login_manager.unauthorized_handler
def handle_unauthorized():
    return redirect(url_for("login", next=current_request_next_target()))


@app.before_request
def ensure_request_auth_schema_compatibility():
    if request.endpoint == "static":
        return None
    ensure_runtime_auth_schema_compatibility()
    return None


@app.before_request
def enforce_password_change():
    if not current_user.is_authenticated:
        return None
    if not current_user.requires_password_change():
        return None
    if force_password_change_allowed_endpoint(request.endpoint):
        return None

    next_target = current_request_next_target()
    safe_next = get_safe_next_target(next_target)
    if safe_next:
        return redirect(url_for("change_password", next=safe_next))
    return redirect(url_for("change_password"))


@app.after_request
def add_security_headers(response):
    for header_name, header_value in SECURITY_HEADERS.items():
        response.headers.setdefault(header_name, header_value)

    should_disable_caching = request.endpoint != "static" and (
        request.endpoint in NO_STORE_ENDPOINTS or current_user.is_authenticated
    )
    if should_disable_caching:
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"

    return response


@app.context_processor
def inject_current_admin_label():
    label = None
    role_label = None
    nav_items = []
    if current_user.is_authenticated:
        label = current_user.full_name or current_user.email
        role_label = current_user.get_role()
        nav_items = [
            {
                "endpoint": "index",
                "label": "Home Dashboard",
                "visible": has_permission(PERMISSION_DASHBOARD_VIEW),
            },
            {
                "endpoint": "orders",
                "label": "Manage Orders",
                "visible": has_permission(PERMISSION_ORDERS_VIEW),
            },
            {
                "endpoint": "inventory",
                "label": "Inventory",
                "visible": has_permission(PERMISSION_INVENTORY_VIEW),
            },
            {
                "endpoint": "customers",
                "label": "Customers",
                "visible": has_permission(PERMISSION_CUSTOMERS_VIEW),
            },
            {
                "endpoint": "tasks",
                "label": "Tasks",
                "visible": has_permission(PERMISSION_TASKS_VIEW),
            },
            {
                "endpoint": "users",
                "label": "Users & Access",
                "visible": has_permission(PERMISSION_USERS_MANAGE),
            },
        ]
    return {
        "current_admin_label": label,
        "current_admin_role_label": role_label,
        "authenticated_nav_items": [item for item in nav_items if item["visible"]],
    }


@app.route("/")
@require_permission(PERMISSION_DASHBOARD_VIEW)
def index():
    total_orders = db.session.query(Order).count()
    ready_to_ship_count = db.session.query(Order).filter(Order.status == "Ready").count()
    completed_orders = db.session.query(Order).filter(Order.status == "Completed").count()
    fiverr_orders = db.session.query(Order).filter(Order.platform == "Fiverr").count()
    square_orders = db.session.query(Order).filter(Order.platform == "Square").count()
    google_orders = db.session.query(Order).filter(
        Order.platform == GOOGLE_SHEETS_ORDER_SOURCE
    ).count()
    recent_orders = Order.query.order_by(Order.placed_at.desc()).limit(3).all()
    return render_template(
        "index.html",
        total_orders=total_orders,
        ready_to_ship_count=ready_to_ship_count,
        fiverr_orders=fiverr_orders,
        square_orders=square_orders,
        google_orders=google_orders,
        recent_orders=recent_orders,
        completed_orders=completed_orders,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        if current_user.requires_password_change():
            return redirect(url_for("change_password"))
        return redirect(url_for("index"))

    form_data = {"email": "", "remember_me": False}
    next_url = get_safe_next_target(request.args.get("next"))

    if request.method == "POST":
        email = normalize_email(request.form.get("email"))
        password = request.form.get("password") or ""
        remember_me = request.form.get("remember_me") in {"on", "true", "1", "yes"}
        next_url = get_safe_next_target(
            request.form.get("next") or request.args.get("next")
        )

        form_data["email"] = email
        form_data["remember_me"] = remember_me

        if not email:
            flash("Email is required.", "error")
        if not password:
            flash("Password is required.", "error")

        if email and password:
            admin_user = AdminUser.query.filter_by(email=email).first()
            now = utc_now()

            if admin_user and is_dev_test_admin_account(admin_user) and not dev_test_admin_enabled():
                flash("Invalid email or password.", "error")
            elif admin_user and admin_user.is_locked(now):
                flash("Invalid email or password.", "error")
            elif (
                admin_user
                and admin_user.get_account_status() == ACCOUNT_STATUS_ACTIVE
                and admin_user.check_password(password)
            ):
                admin_user.reset_login_state()
                admin_user.last_login_at = now
                admin_user.sync_legacy_state()
                db.session.commit()

                session.clear()
                login_user(admin_user, remember=remember_me)
                if admin_user.requires_password_change():
                    if next_url:
                        return redirect(url_for("change_password", next=next_url))
                    return redirect(url_for("change_password"))
                return redirect_to_safe_next(
                    request.form.get("next") or request.args.get("next"),
                    fallback_endpoint="index",
                )
            else:
                if admin_user:
                    admin_user.register_failed_login(now)
                    db.session.commit()
                flash("Invalid email or password.", "error")

    return render_template(
        "login.html",
        form_data=form_data,
        next_url=next_url,
        show_dev_test_admin_hint=dev_test_admin_enabled(),
        dev_test_admin_seeded=dev_test_admin_seeded(),
    )


@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if not current_user.is_authenticated:
        return login_manager.unauthorized()
    if not current_user.requires_password_change():
        return redirect(url_for("index"))

    next_url = get_safe_next_target(request.args.get("next"))
    if request.method == "POST":
        next_url = get_safe_next_target(
            request.form.get("next") or request.args.get("next")
        )
        password = request.form.get("password") or ""
        password_confirmation = request.form.get("password_confirmation") or ""

        if not password:
            flash("New password is required.", "error")
        elif password != password_confirmation:
            flash("Passwords must match.", "error")
        elif current_user.check_password(password):
            flash("Choose a password different from the temporary password.", "error")
        else:
            comparison_time = utc_now()
            before_state = serialize_admin_user_snapshot(
                current_user, now=comparison_time
            )
            current_user.set_password(password)
            current_user.must_change_password = False
            current_user.reset_login_state()
            log_admin_access_event(
                actor=current_user,
                target=current_user,
                event_type=ADMIN_ACCESS_EVENT_PASSWORD_CHANGED,
                outcome=ADMIN_ACCESS_EVENT_OUTCOME_SUCCESS,
                before_state=before_state,
                after_state=serialize_admin_user_snapshot(
                    current_user, now=comparison_time
                ),
                note="Forced password change completed.",
            )
            db.session.commit()
            flash("Password updated.", "success")
            return redirect_to_safe_next(
                request.form.get("next") or request.args.get("next"),
                fallback_endpoint="index",
            )

    return render_template("change_password.html", next_url=next_url)


@app.route("/orders")
@require_permission(PERMISSION_ORDERS_VIEW)
def orders():
    search_query = request.args.get("search", "").strip()
    source = request.args.get("source", "")
    status = request.args.get("status", "")

    query = Order.query

    if search_query:
        query = query.filter(
            or_(
                Order.order_number.ilike(f"%{search_query}%"),
                Order.customer.has(Customer.first_name.ilike(f"%{search_query}%")),
                Order.customer.has(Customer.last_name.ilike(f"%{search_query}%")),
            )
        )

    if source:
        query = query.filter(Order.platform == source)

    if status:
        query = query.filter(Order.status == status)

    all_orders = query.options(
        db.joinedload(Order.customer),
        db.joinedload(Order.order_items).joinedload(OrderItem.product),
        db.joinedload(Order.shipment),
    ).order_by(Order.placed_at.desc()).all()

    return render_template(
        "manageOrders.html",
        all_orders=all_orders,
        search_query=search_query,
        selected_source=source,
        selected_status=status,
    )


@app.route("/tasks")
@require_permission(PERMISSION_TASKS_VIEW)
def tasks():
    return render_template("tasks.html")


@app.route("/customers")
@require_permission(PERMISSION_CUSTOMERS_VIEW)
def customers():
    search_query = request.args.get("search", "").strip()
    source = request.args.get("source", "")

    query = Customer.query
    if search_query:
        query = query.filter(
            (Customer.first_name.ilike(f"%{search_query}%"))
            | (Customer.last_name.ilike(f"%{search_query}%"))
            | (Customer.email.ilike(f"%{search_query}%"))
        )

    if source:
        query = query.filter(Customer.source == source)

    all_customers = query.order_by(Customer.created_at.desc()).all()

    return render_template(
        "customerDatabase.html",
        all_customers=all_customers,
        search_query=search_query,
        selected_source=source,
    )

@app.route("/inventory")
@require_permission(PERMISSION_INVENTORY_VIEW)
def inventory():
    search_query = request.args.get('search', '').strip()
    category = request.args.get('category', '')
    stock_status = request.args.get('stock_status', '')

    query = Ingredient.query
    

    if search_query:
        query = query.filter(Ingredient.name.ilike(f'%{search_query}%'))

    if category:
        query = query.filter(Ingredient.category == category)
    

    if stock_status:
        if stock_status == 'in_stock':
            query = query.filter(Ingredient.stock_quantity > Ingredient.reorder_threshold)
        elif stock_status == 'low_stock':
            query = query.filter(
                Ingredient.stock_quantity <= Ingredient.reorder_threshold,
                Ingredient.stock_quantity > 0
            )
        elif stock_status == 'out_of_stock':
            query = query.filter(Ingredient.stock_quantity == 0)
    
    all_items = query.order_by(Ingredient.name).all()
    
    return render_template("inventory.html", 
                         all_items=all_items,
                         search_query=search_query,
                         selected_category=category,
                         selected_stock_status=stock_status)
    
    @app.route("/add-new")
@login_required
def add_new():
    return render_template("addNew.html")

@app.route("/add-customer")
@login_required
def add_customer():
    return render_template("addCustomer.html")

@app.route("/users")
@require_permission(
    PERMISSION_USERS_MANAGE,
    denial_title="Users & Access denied",
    denial_message="Superadmin access is required to manage internal staff accounts.",
)
def users():
    filter_state = read_users_filter_state(request.args)
    selected_user_id = request.args.get("selected_user", type=int)
    show_invite = request.args.get("show_invite") == "1"
    comparison_time = utc_now()
    users_list = visible_users_query().order_by(AdminUser.created_at.desc()).all()
    filtered_users = []

    for admin_user in users_list:
        full_name = (admin_user.full_name or "").strip()
        if filter_state["search"]:
            search_value = filter_state["search"].lower()
            if search_value not in full_name.lower() and search_value not in admin_user.email.lower():
                continue
        if filter_state["role_filter"] and admin_user.get_role() != filter_state["role_filter"]:
            continue

        derived_status = admin_user.display_status(comparison_time)
        status_matches = {
            "active": derived_status == "Active",
            "invited": derived_status == "Pending invite",
            "expired": derived_status == "Expired invite",
            "suspended": derived_status == "Suspended",
            "locked": derived_status == "Locked",
        }
        if filter_state["status_filter"] and not status_matches.get(
            filter_state["status_filter"],
            False,
        ):
            continue
        if filter_state["last_login_filter"] and parse_last_login_state(
            admin_user, now=comparison_time
        ) != filter_state["last_login_filter"]:
            continue
        filtered_users.append(admin_user)

    filtered_users = sort_visible_users(filtered_users, now=comparison_time)
    filtered_ids = {admin_user.id for admin_user in filtered_users}
    selected_user = None if show_invite else get_visible_user_or_none(selected_user_id)
    if selected_user and selected_user.id not in filtered_ids:
        selected_user = None
    if selected_user is None and filtered_users and not show_invite:
        selected_user = filtered_users[0]

    selected_user_events = []
    if selected_user is not None:
        selected_user_events = (
            AdminAccessEvent.query.filter_by(target_user_id=selected_user.id)
            .order_by(AdminAccessEvent.created_at.desc())
            .limit(5)
            .all()
        )

    return render_template(
        "users.html",
        users_list=filtered_users,
        selected_user=selected_user,
        selected_user_events=selected_user_events,
        filter_state=filter_state,
        show_invite=show_invite,
        role_options=BUSINESS_ROLE_CHOICES,
        status_options=(
            ("active", "Active"),
            ("invited", "Pending invite"),
            ("expired", "Expired invite"),
            ("suspended", "Suspended"),
            ("locked", "Locked"),
        ),
        last_login_options=(
            ("never", "Never logged in"),
            ("recent", "Recent"),
            ("stale", "Stale"),
            ("locked", "Locked"),
        ),
        comparison_time=comparison_time,
        permission_labels=summarize_permissions,
        password_state_label=password_state_label,
        role_scope_summary=role_scope_summary,
        parse_last_login_state=parse_last_login_state,
        resolve_actor_name=resolve_actor_name,
        get_effective_permissions=get_effective_permissions,
    )


@app.route("/users/invite", methods=["POST"])
@require_permission(PERMISSION_USERS_MANAGE)
def invite_user():
    filter_state = read_users_filter_state(request.form)
    email = normalize_email(request.form.get("email"))
    full_name = (request.form.get("full_name") or "").strip()
    role = request.form.get("role")
    password_mode = (request.form.get("password_mode") or "generated").strip()
    password = request.form.get("password") or ""
    password_confirmation = request.form.get("password_confirmation") or ""
    if not email:
        flash("Email is required.", "error")
        return users_redirect_response(show_invite=True, **filter_state)
    if role not in BUSINESS_ROLE_CHOICES:
        flash("Select one of the fixed business roles.", "error")
        return users_redirect_response(show_invite=True, **filter_state)
    if password_mode not in {"generated", "manual"}:
        flash("Select a temporary password mode.", "error")
        return users_redirect_response(show_invite=True, **filter_state)
    if password_mode == "manual":
        if not password:
            flash("Temporary password is required.", "error")
            return users_redirect_response(show_invite=True, **filter_state)
        if password != password_confirmation:
            flash("Passwords must match.", "error")
            return users_redirect_response(show_invite=True, **filter_state)
    existing_user = AdminUser.query.filter_by(email=email).first()
    if existing_user is not None:
        flash("An account with that email already exists.", "error")
        return users_redirect_response(show_invite=True, **filter_state)

    comparison_time = utc_now()
    created_user = AdminUser(
        email=email,
        full_name=full_name or None,
    )
    temporary_password = (
        generate_temporary_password() if password_mode == "generated" else password
    )
    created_user.set_password(temporary_password)
    created_user.must_change_password = True
    created_user.set_role(role, actor=current_user, now=comparison_time)
    created_user.set_account_status(
        ACCOUNT_STATUS_ACTIVE, actor=current_user, now=comparison_time
    )
    created_user.reset_login_state()
    db.session.add(created_user)
    db.session.flush()
    log_admin_access_event(
        actor=current_user,
        target=created_user,
        event_type=ADMIN_ACCESS_EVENT_ACCOUNT_CREATED,
        outcome=ADMIN_ACCESS_EVENT_OUTCOME_SUCCESS,
        after_state=serialize_admin_user_snapshot(created_user, now=comparison_time),
        note=f"Temporary password mode: {password_mode}.",
    )
    db.session.commit()
    flash("User created with a temporary password.", "success")
    if password_mode == "generated":
        flash(
            f"Temporary password (shown once): {temporary_password}",
            "info",
        )
    return users_redirect_response(
        selected_user_id=created_user.id,
        show_invite=False,
        **filter_state,
    )


@app.route("/users/<int:user_id>/activate", methods=["POST"])
@require_permission(PERMISSION_USERS_MANAGE)
def activate_user(user_id):
    filter_state = read_users_filter_state(request.form)
    target_user = get_visible_user_or_none(user_id)
    if target_user is None:
        flash("User not found.", "error")
        return users_redirect_response(show_invite=True, **filter_state)
    password = request.form.get("password") or ""
    password_confirmation = request.form.get("password_confirmation") or ""
    if not password:
        flash("Initial password is required.", "error")
        return users_redirect_response(selected_user_id=user_id, **filter_state)
    if password != password_confirmation:
        flash("Passwords must match.", "error")
        return users_redirect_response(selected_user_id=user_id, **filter_state)
    if target_user.get_account_status() != ACCOUNT_STATUS_INVITED:
        flash("Only pending invites can be activated.", "error")
        return users_redirect_response(selected_user_id=user_id, **filter_state)

    comparison_time = utc_now()
    before_state = serialize_admin_user_snapshot(target_user, now=comparison_time)
    target_user.set_password(password)
    target_user.must_change_password = True
    target_user.set_account_status(
        ACCOUNT_STATUS_ACTIVE, actor=current_user, now=comparison_time
    )
    target_user.reset_login_state()
    log_admin_access_event(
        actor=current_user,
        target=target_user,
        event_type=ADMIN_ACCESS_EVENT_ACCOUNT_ACTIVATED,
        outcome=ADMIN_ACCESS_EVENT_OUTCOME_SUCCESS,
        before_state=before_state,
        after_state=serialize_admin_user_snapshot(target_user, now=comparison_time),
    )
    db.session.commit()
    flash("Account activated with a temporary password.", "success")
    return users_redirect_response(selected_user_id=user_id, **filter_state)


@app.route("/users/<int:user_id>/resend-invite", methods=["POST"])
@require_permission(PERMISSION_USERS_MANAGE)
def resend_invite(user_id):
    filter_state = read_users_filter_state(request.form)
    target_user = get_visible_user_or_none(user_id)
    if target_user is None:
        flash("User not found.", "error")
        return users_redirect_response(show_invite=True, **filter_state)
    if target_user.get_account_status() != ACCOUNT_STATUS_INVITED:
        flash("Only pending invites can be resent.", "error")
        return users_redirect_response(selected_user_id=user_id, **filter_state)

    comparison_time = utc_now()
    before_state = serialize_admin_user_snapshot(target_user, now=comparison_time)
    target_user.invited_at = comparison_time
    target_user.invited_by_user_id = current_user.id
    log_admin_access_event(
        actor=current_user,
        target=target_user,
        event_type=ADMIN_ACCESS_EVENT_INVITE_RESENT,
        outcome=ADMIN_ACCESS_EVENT_OUTCOME_SUCCESS,
        before_state=before_state,
        after_state=serialize_admin_user_snapshot(target_user, now=comparison_time),
    )
    db.session.commit()
    flash("Invite resent.", "success")
    return users_redirect_response(selected_user_id=user_id, **filter_state)


@app.route("/users/<int:user_id>/cancel-invite", methods=["POST"])
@require_permission(PERMISSION_USERS_MANAGE)
def cancel_invite(user_id):
    filter_state = read_users_filter_state(request.form)
    target_user = get_visible_user_or_none(user_id)
    if target_user is None:
        flash("User not found.", "error")
        return users_redirect_response(show_invite=True, **filter_state)
    if target_user.get_account_status() != ACCOUNT_STATUS_INVITED:
        flash("Only pending invites can be cancelled.", "error")
        return users_redirect_response(selected_user_id=user_id, **filter_state)

    before_state = serialize_admin_user_snapshot(target_user)
    log_admin_access_event(
        actor=current_user,
        target=target_user,
        event_type=ADMIN_ACCESS_EVENT_INVITE_CANCELLED,
        outcome=ADMIN_ACCESS_EVENT_OUTCOME_CANCELLED,
        before_state=before_state,
        note="Pending invite removed.",
    )
    db.session.delete(target_user)
    db.session.commit()
    flash("Invite cancelled.", "success")
    return users_redirect_response(show_invite=True, **filter_state)


@app.route("/users/<int:user_id>/role", methods=["POST"])
@require_permission(PERMISSION_USERS_MANAGE)
def update_user_role(user_id):
    filter_state = read_users_filter_state(request.form)
    target_user = get_visible_user_or_none(user_id)
    if target_user is None:
        flash("User not found.", "error")
        return users_redirect_response(show_invite=True, **filter_state)
    new_role = request.form.get("role")
    if new_role not in BUSINESS_ROLE_CHOICES:
        flash("Select one of the fixed business roles.", "error")
        return users_redirect_response(selected_user_id=user_id, **filter_state)
    if target_user.get_role() == ROLE_SUPERADMIN and new_role != ROLE_SUPERADMIN:
        if is_last_active_superadmin(target_user):
            deny_sensitive_users_action(
                target_user,
                note="You cannot demote the last active superadmin.",
            )
            return users_redirect_response(selected_user_id=user_id, **filter_state)
    if target_user.get_role() == new_role:
        flash("Role is already assigned.", "info")
        return users_redirect_response(selected_user_id=user_id, **filter_state)

    comparison_time = utc_now()
    before_state = serialize_admin_user_snapshot(target_user, now=comparison_time)
    target_user.set_role(new_role, actor=current_user, now=comparison_time)
    log_admin_access_event(
        actor=current_user,
        target=target_user,
        event_type=ADMIN_ACCESS_EVENT_ROLE_CHANGED,
        outcome=ADMIN_ACCESS_EVENT_OUTCOME_SUCCESS,
        before_state=before_state,
        after_state=serialize_admin_user_snapshot(target_user, now=comparison_time),
    )
    db.session.commit()
    flash("Role updated.", "success")
    return users_redirect_response(selected_user_id=user_id, **filter_state)


@app.route("/users/<int:user_id>/suspend", methods=["POST"])
@require_permission(PERMISSION_USERS_MANAGE)
def suspend_user(user_id):
    filter_state = read_users_filter_state(request.form)
    target_user = get_visible_user_or_none(user_id)
    if target_user is None:
        flash("User not found.", "error")
        return users_redirect_response(show_invite=True, **filter_state)
    if target_user.get_account_status() == ACCOUNT_STATUS_SUSPENDED:
        flash("Account is already suspended.", "info")
        return users_redirect_response(selected_user_id=user_id, **filter_state)
    if target_user.get_role() == ROLE_SUPERADMIN and is_last_active_superadmin(target_user):
        deny_sensitive_users_action(
            target_user,
            note="You cannot suspend the last active superadmin.",
        )
        return users_redirect_response(selected_user_id=user_id, **filter_state)

    comparison_time = utc_now()
    before_state = serialize_admin_user_snapshot(target_user, now=comparison_time)
    target_user.set_account_status(
        ACCOUNT_STATUS_SUSPENDED, actor=current_user, now=comparison_time
    )
    log_admin_access_event(
        actor=current_user,
        target=target_user,
        event_type=ADMIN_ACCESS_EVENT_STATUS_CHANGED,
        outcome=ADMIN_ACCESS_EVENT_OUTCOME_SUCCESS,
        before_state=before_state,
        after_state=serialize_admin_user_snapshot(target_user, now=comparison_time),
        note="Account suspended.",
    )
    db.session.commit()
    flash("Account suspended.", "success")
    return users_redirect_response(selected_user_id=user_id, **filter_state)


@app.route("/users/<int:user_id>/reactivate", methods=["POST"])
@require_permission(PERMISSION_USERS_MANAGE)
def reactivate_user(user_id):
    filter_state = read_users_filter_state(request.form)
    target_user = get_visible_user_or_none(user_id)
    if target_user is None:
        flash("User not found.", "error")
        return users_redirect_response(show_invite=True, **filter_state)
    if target_user.get_account_status() == ACCOUNT_STATUS_ACTIVE:
        flash("Account is already active.", "info")
        return users_redirect_response(selected_user_id=user_id, **filter_state)

    comparison_time = utc_now()
    before_state = serialize_admin_user_snapshot(target_user, now=comparison_time)
    target_user.set_account_status(
        ACCOUNT_STATUS_ACTIVE, actor=current_user, now=comparison_time
    )
    target_user.reset_login_state()
    log_admin_access_event(
        actor=current_user,
        target=target_user,
        event_type=ADMIN_ACCESS_EVENT_STATUS_CHANGED,
        outcome=ADMIN_ACCESS_EVENT_OUTCOME_SUCCESS,
        before_state=before_state,
        after_state=serialize_admin_user_snapshot(target_user, now=comparison_time),
        note="Account reactivated.",
    )
    db.session.commit()
    flash("Account reactivated.", "success")
    return users_redirect_response(selected_user_id=user_id, **filter_state)


@app.route("/users/<int:user_id>/temporary-password", methods=["POST"])
@require_permission(PERMISSION_USERS_MANAGE)
def set_temporary_password(user_id):
    filter_state = read_users_filter_state(request.form)
    target_user = get_visible_user_or_none(user_id)
    if target_user is None:
        flash("User not found.", "error")
        return users_redirect_response(show_invite=True, **filter_state)
    if target_user.get_account_status() != ACCOUNT_STATUS_ACTIVE:
        flash("Only active accounts can receive a temporary password.", "error")
        return users_redirect_response(selected_user_id=user_id, **filter_state)
    password = request.form.get("password") or ""
    password_confirmation = request.form.get("password_confirmation") or ""
    if not password:
        flash("Temporary password is required.", "error")
        return users_redirect_response(selected_user_id=user_id, **filter_state)
    if password != password_confirmation:
        flash("Passwords must match.", "error")
        return users_redirect_response(selected_user_id=user_id, **filter_state)

    comparison_time = utc_now()
    before_state = serialize_admin_user_snapshot(target_user, now=comparison_time)
    target_user.set_password(password)
    target_user.must_change_password = True
    target_user.reset_login_state()
    log_admin_access_event(
        actor=current_user,
        target=target_user,
        event_type=ADMIN_ACCESS_EVENT_PASSWORD_RESET,
        outcome=ADMIN_ACCESS_EVENT_OUTCOME_SUCCESS,
        before_state=before_state,
        after_state=serialize_admin_user_snapshot(target_user, now=comparison_time),
    )
    db.session.commit()
    flash("Temporary password set. The user must change it at next login.", "success")
    return users_redirect_response(selected_user_id=user_id, **filter_state)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    logout_user()
    return redirect(url_for("login"))


@app.cli.command("init-db")
def init_db_command():
    db.create_all(bind_key="__all__")
    ensure_customer_source_column()
    ensure_admin_user_access_columns()
    print("Database initialized.")


def choose_default_business_role():
    has_business_admin = (
        AdminUser.query.filter(
            AdminUser.role == ROLE_SUPERADMIN,
            AdminUser.account_status == ACCOUNT_STATUS_ACTIVE,
        ).first()
        is not None
    )
    return ROLE_STAFF_OPERATOR if has_business_admin else ROLE_SUPERADMIN


@app.cli.command("create-admin")
@click.option("--email", required=True, help="Admin email address.")
@click.option("--full-name", default=None, help="Optional admin display name.")
@click.option(
    "--role",
    type=click.Choice(sorted(ROLE_SLUG_MAP)),
    default=None,
    help="Fixed business role for the account.",
)
@click.option(
    "--update",
    is_flag=True,
    help="Update an existing admin user instead of failing if the email already exists.",
)
def create_admin_command(email, full_name, role, update):
    normalized_email = normalize_email(email)
    if not normalized_email:
        raise click.ClickException("A valid email address is required.")
    if is_dev_test_admin_email(normalized_email):
        raise click.ClickException(
            "The 'admin' identifier is reserved for the dev-only seed-dev-admin command."
        )

    password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
    if not password:
        raise click.ClickException("Password cannot be empty.")

    db.create_all(bind_key=AUTH_BIND_KEY)
    ensure_admin_user_access_columns()
    admin_user = AdminUser.query.filter_by(email=normalized_email).first()
    role_label = None if role is None else slug_to_role_label(role)

    if admin_user and not update:
        raise click.ClickException(
            "Admin user already exists. Re-run with --update to replace the password."
        )

    if admin_user is None:
        admin_user = AdminUser(email=normalized_email)
        db.session.add(admin_user)
        action = "created"
    else:
        action = "updated"

    if full_name is not None:
        admin_user.full_name = full_name.strip() or None

    comparison_time = utc_now()
    if role_label is None:
        role_label = admin_user.role or choose_default_business_role()
    admin_user.set_role(role_label, now=comparison_time)
    admin_user.set_account_status(
        ACCOUNT_STATUS_ACTIVE, actor=None, now=comparison_time
    )
    admin_user.reset_login_state()
    admin_user.set_password(password)
    admin_user.sync_legacy_state()
    db.session.commit()

    click.echo(f"Admin user {action}: {normalized_email} ({admin_user.get_role()})")


@app.cli.command("create-dev-admin")
@click.option("--email", required=True, help="Dev Admin email address.")
@click.option("--full-name", default=DEV_TEST_ADMIN_FULL_NAME, help="Optional display name.")
@click.option(
    "--update",
    is_flag=True,
    help="Update an existing Dev Admin instead of failing if the email already exists.",
)
def create_dev_admin_command(email, full_name, update):
    normalized_email = normalize_email(email)
    if not normalized_email:
        raise click.ClickException("A valid email address is required.")
    password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
    if not password:
        raise click.ClickException("Password cannot be empty.")

    db.create_all(bind_key=AUTH_BIND_KEY)
    ensure_admin_user_access_columns()
    admin_user = AdminUser.query.filter_by(email=normalized_email).first()
    if admin_user and not update:
        raise click.ClickException(
            "Dev Admin already exists. Re-run with --update to replace the password."
        )

    if admin_user is None:
        admin_user = AdminUser(email=normalized_email)
        db.session.add(admin_user)
        action = "created"
    else:
        action = "updated"

    comparison_time = utc_now()
    admin_user.full_name = (full_name or "").strip() or None
    admin_user.set_role(ROLE_DEV_ADMIN, now=comparison_time)
    admin_user.set_account_status(ACCOUNT_STATUS_ACTIVE, now=comparison_time)
    admin_user.reset_login_state()
    admin_user.set_password(password)
    admin_user.sync_legacy_state()
    db.session.commit()

    click.echo(f"Dev Admin {action}: {normalized_email}")


@app.cli.command("backfill-admin-access")
@click.option(
    "--first-superadmin-email",
    default=None,
    help="Email address to assign the first Superadmin role during backfill.",
)
@click.option(
    "--dev-admin-email",
    "dev_admin_emails",
    multiple=True,
    help="Email addresses to mark as hidden Dev Admin accounts during backfill.",
)
def backfill_admin_access_command(first_superadmin_email, dev_admin_emails):
    db.create_all(bind_key=AUTH_BIND_KEY)
    ensure_admin_user_access_columns()
    selected_superadmin_email = normalize_email(first_superadmin_email)
    selected_dev_admin_emails = {normalize_email(email) for email in dev_admin_emails}
    comparison_time = utc_now()
    admin_users = AdminUser.query.order_by(AdminUser.created_at.asc()).all()

    for admin_user in admin_users:
        if admin_user.email in selected_dev_admin_emails:
            admin_user.set_role(ROLE_DEV_ADMIN, now=comparison_time)
            admin_user.set_account_status(
                ACCOUNT_STATUS_ACTIVE if admin_user.is_active else ACCOUNT_STATUS_SUSPENDED,
                now=comparison_time,
            )
        else:
            admin_user.set_role(
                ROLE_SUPERADMIN
                if selected_superadmin_email and admin_user.email == selected_superadmin_email
                else admin_user.role
                or ROLE_STAFF_OPERATOR,
                now=comparison_time,
            )
            admin_user.set_account_status(
                ACCOUNT_STATUS_ACTIVE if admin_user.is_active else ACCOUNT_STATUS_SUSPENDED,
                now=comparison_time,
            )
        admin_user.sync_legacy_state()

    active_superadmin_count = AdminUser.query.filter(
        AdminUser.role == ROLE_SUPERADMIN,
        AdminUser.account_status == ACCOUNT_STATUS_ACTIVE,
    ).count()
    if active_superadmin_count == 0:
        raise click.ClickException(
            "Backfill would leave zero active superadmins. Re-run with --first-superadmin-email."
        )

    db.session.commit()
    click.echo("Admin access backfill completed.")


@app.cli.command("seed-dev-admin")
def seed_dev_admin_command():
    require_dev_test_admin_mode()

    db.create_all(bind_key=AUTH_BIND_KEY)
    ensure_admin_user_access_columns()
    admin_user = AdminUser.query.filter_by(email=DEV_TEST_ADMIN_EMAIL).first()

    if admin_user is None:
        admin_user = AdminUser(email=DEV_TEST_ADMIN_EMAIL)
        db.session.add(admin_user)
        action = "created"
    else:
        action = "updated"

    comparison_time = utc_now()
    admin_user.full_name = DEV_TEST_ADMIN_FULL_NAME
    admin_user.set_role(ROLE_DEV_ADMIN, now=comparison_time)
    admin_user.set_account_status(ACCOUNT_STATUS_ACTIVE, now=comparison_time)
    admin_user.reset_login_state()
    admin_user.set_password(DEV_TEST_ADMIN_PASSWORD)
    admin_user.sync_legacy_state()
    db.session.commit()

    click.echo(f"Dev test admin {action}: {DEV_TEST_ADMIN_EMAIL}")


if __name__ == "__main__":
    app.run(host="localhost", port=8000, debug=env_flag("FLASK_DEBUG", default=False))
