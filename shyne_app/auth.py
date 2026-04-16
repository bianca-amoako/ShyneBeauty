import json
import logging
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
    abort,
    flash,
    got_request_exception,
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
from .rate_limit import check_rate_limit


def _rate_limit_client_ip():
    if app.config.get("TRUST_PROXY_HEADERS"):
        forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if forwarded:
            return forwarded
    return request.remote_addr or "unknown"


@app.before_request
def enforce_rate_limits():
    if app.config.get("TESTING"):
        return None
    if request.endpoint == "static":
        return None
    if not check_rate_limit(_rate_limit_client_ip(), request.path, request.method):
        abort(429)
    return None


@app.errorhandler(429)
def handle_429(error):
    flash("Too many requests. Please wait a moment and try again.", "error")
    referrer = request.referrer
    if referrer:
        parsed = urlparse(referrer)
        if parsed.netloc == request.host and parsed.path:
            safe_url = url_for("login") if parsed.path == "/" else parsed.path
            return redirect(safe_url), 429
    return redirect(url_for("login")), 429


_logger = logging.getLogger("shynebeauty.errors")

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


@app.errorhandler(404)
def handle_404(error):
    return render_template(
        "error.html",
        error_code=404,
        error_title="Page not found",
        error_message="The page you're looking for doesn't exist or has been moved.",
    ), 404


@app.errorhandler(500)
def handle_500(error):
    return render_template(
        "error.html",
        error_code=500,
        error_title="Something went wrong",
        error_message="An unexpected error occurred. Please try again or contact a Dev Admin.",
    ), 500


@app.errorhandler(OperationalError)
def handle_db_error(error):
    return render_template(
        "error.html",
        error_code=503,
        error_title="Database unavailable",
        error_message="The database is temporarily unavailable. Please try again in a moment.",
    ), 503


def _log_exception(sender, exception, **extra):
    _logger.error(
        "unhandled exception | path=%s | %s: %s",
        request.path,
        type(exception).__name__,
        exception,
        exc_info=True,
    )

got_request_exception.connect(_log_exception, app)


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


@app.before_request
def enforce_https():
    if app.config.get("APP_RUNTIME") != APP_RUNTIME_LIVE_PROD:
        return None
    if not app.config.get("TRUST_PROXY_HEADERS"):
        return None
    proto = request.headers.get("X-Forwarded-Proto", "https")
    if proto == "http":
        https_url = request.url
        if https_url.startswith("http://"):
            https_url = "https://" + https_url[7:]
        parsed = urlparse(https_url)
        if parsed.scheme == "https" and parsed.netloc == request.host:
            return redirect(parsed.geturl(), code=301)
    return None


@app.after_request
def add_security_headers(response):
    for header_name, header_value in SECURITY_HEADERS.items():
        response.headers.setdefault(header_name, header_value)

    if app.config.get("APP_RUNTIME") == APP_RUNTIME_LIVE_PROD:
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )

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
