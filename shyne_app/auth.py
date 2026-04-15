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
from .config import *
from .extensions import app, db, login_manager
from .models import *
from .access import *

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

    if request.endpoint == "mfa_challenge":
        pending_user = None
        pending_user_id = session.get("pending_mfa_user_id")
        if pending_user_id:
            pending_user = db.session.get(AdminUser, pending_user_id)
        return render_template(
            "mfa_challenge.html",
            pending_user=pending_user,
            next_url=get_safe_next_target(request.args.get("next") or request.form.get("next")),
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


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(AdminUser, int(user_id), populate_existing=True)
    except (TypeError, ValueError, OperationalError):
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
def invalidate_revoked_authenticated_session():
    if request.endpoint == "static" or not current_user.is_authenticated:
        return None

    try:
        db.session.refresh(current_user._get_current_object())
    except (InvalidRequestError, ObjectDeletedError):
        return revoke_authenticated_session(redirect_to_login=request.endpoint != "login")

    comparison_time = utc_now()
    if (
        current_user.get_account_status() == ACCOUNT_STATUS_ACTIVE
        and not current_user.is_locked(comparison_time)
    ):
        return None

    return revoke_authenticated_session(redirect_to_login=request.endpoint != "login")


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
        add_flow_items = build_add_flow_items(current_user)
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
                "endpoint": "add_new",
                "label": "Add New",
                "visible": any(item["visible"] for item in add_flow_items),
            },
            {
                "endpoint": "add_product",
                "label": "Add Product",
                "visible": has_permission(PERMISSION_PRODUCTION_EDIT),
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
        "account_settings_available": current_user.is_authenticated
        and not current_user.requires_password_change(),
        "runtime_banner_label": (
            "Demo environment"
            if app.config.get("APP_RUNTIME") == APP_RUNTIME_DEMO_DEV
            else None
        ),
        "authenticated_nav_items": [item for item in nav_items if item["visible"]],
        "add_flow_items": [item for item in build_add_flow_items() if item["visible"]]
        if current_user.is_authenticated
        else [],
    }
