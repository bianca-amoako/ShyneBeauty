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
from .extensions import db, login_manager
from .models import *

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


def has_any_permission(*permission_keys, admin_user=None, now=None):
    return any(
        has_permission(permission_key, admin_user=admin_user, now=now)
        for permission_key in permission_keys
    )


def build_add_flow_items(admin_user=None):
    target_user = admin_user or current_user
    return [
        {
            "endpoint": "add_customer",
            "label": "Add Customer",
            "description": "Create a customer record with contact and address details.",
            "visible": has_permission(PERMISSION_CUSTOMERS_EDIT, admin_user=target_user),
        },
        {
            "endpoint": "add_order",
            "label": "Add Order",
            "description": "Create an order for an existing customer with line items and an initial status.",
            "visible": has_permission(PERMISSION_ORDERS_EDIT, admin_user=target_user),
        },
        {
            "endpoint": "add_inventory",
            "label": "Add Inventory Item",
            "description": "Create an ingredient or supply record for stock and reorder tracking.",
            "visible": has_permission(PERMISSION_INVENTORY_EDIT, admin_user=target_user),
        },
        {
            "endpoint": "add_product",
            "label": "Add Product",
            "description": "Create a product so it can be used in future order entry.",
            "visible": has_permission(PERMISSION_PRODUCTION_EDIT, admin_user=target_user),
        },
        {
            "endpoint": "add_product_batch",
            "label": "Add Product Batch",
            "description": "Record a new production lot for an existing product to track batch inventory.",
            "visible": has_permission(PERMISSION_PRODUCTION_EDIT, admin_user=target_user),
        },
    ]


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
        ROLE_STAFF_OPERATOR: "Orders, customers, shipping",
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
