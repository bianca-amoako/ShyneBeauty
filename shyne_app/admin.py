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
from .extensions import app, db
from .models import *
from .access import *
from .auth import current_request_next_target

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
        admin.add_view(LiveDataModelView(model, db, name=table_name))

    _admin_views_registered = True


register_admin_views()
