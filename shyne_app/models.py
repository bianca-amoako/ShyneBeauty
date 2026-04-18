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
import pyotp
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
from .config import *
from .extensions import db

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
        "must_enroll_mfa": (
            "ALTER TABLE admin_users "
            "ADD COLUMN must_enroll_mfa BOOLEAN NOT NULL DEFAULT 0"
        ),
        "mfa_enabled": (
            "ALTER TABLE admin_users "
            "ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT 0"
        ),
        "mfa_totp_secret": "ALTER TABLE admin_users ADD COLUMN mfa_totp_secret VARCHAR(64)",
        "mfa_enrolled_at": "ALTER TABLE admin_users ADD COLUMN mfa_enrolled_at DATETIME",
        "last_mfa_verified_at": (
            "ALTER TABLE admin_users ADD COLUMN last_mfa_verified_at DATETIME"
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
    AdminLoginThrottle.__table__.create(bind=auth_engine, checkfirst=True)
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
    must_enroll_mfa = db.Column(db.Boolean, nullable=False, default=False)
    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)
    mfa_totp_secret = db.Column(db.String(64))
    mfa_enrolled_at = db.Column(db.DateTime(timezone=True))
    last_mfa_verified_at = db.Column(db.DateTime(timezone=True))
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

        self.failed_login_count = self.failed_login_count or 0
        self.failed_login_count += 1
        if self.failed_login_count >= FAILED_LOGIN_THRESHOLD:
            self.locked_until = comparison_time + ACCOUNT_LOCK_DURATION

    def reset_login_state(self):
        self.failed_login_count = 0
        self.locked_until = None

    def requires_password_change(self):
        return bool(self.must_change_password)

    def has_mfa_enabled(self):
        return bool(self.mfa_enabled and self.mfa_totp_secret)

    def ensure_mfa_secret(self):
        if not self.mfa_totp_secret:
            self.mfa_totp_secret = pyotp.random_base32()
        return self.mfa_totp_secret

    def verify_mfa_code(self, code):
        if not self.has_mfa_enabled():
            return False
        if not code:
            return False
        try:
            return pyotp.TOTP(self.mfa_totp_secret).verify((code or "").strip(), valid_window=1)
        except Exception:
            return False

    def enable_mfa(self, *, secret=None, now=None):
        comparison_time = now or utc_now()
        self.mfa_totp_secret = secret or self.ensure_mfa_secret()
        self.mfa_enabled = True
        self.must_enroll_mfa = False
        self.mfa_enrolled_at = comparison_time
        self.last_mfa_verified_at = comparison_time

    def disable_mfa(self):
        self.mfa_enabled = False
        self.must_enroll_mfa = False
        self.mfa_totp_secret = None
        self.mfa_enrolled_at = None
        self.last_mfa_verified_at = None

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


class AdminLoginThrottle(db.Model):
    __bind_key__ = AUTH_BIND_KEY
    __tablename__ = "admin_login_throttles"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(64), nullable=False, unique=True, index=True)
    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime(timezone=True))
    last_failed_at = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utc_now)

    def is_locked(self, now=None):
        if self.locked_until is None:
            return False
        comparison_time = now or utc_now()
        return ensure_utc(self.locked_until) > comparison_time

    def register_failed_login(self, now=None):
        comparison_time = now or utc_now()
        if self.locked_until and not self.is_locked(comparison_time):
            self.failed_login_count = 0
            self.locked_until = None
        self.failed_login_count = self.failed_login_count or 0
        self.failed_login_count += 1
        self.last_failed_at = comparison_time
        if self.failed_login_count >= IP_LOGIN_FAILURE_THRESHOLD:
            self.locked_until = comparison_time + IP_LOGIN_LOCK_DURATION

    def reset_state(self):
        self.failed_login_count = 0
        self.locked_until = None
        self.last_failed_at = None


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
