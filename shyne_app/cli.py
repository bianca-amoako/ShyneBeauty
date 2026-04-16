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
from .auth import *

def init_db_targets_live_data():
    runtime = app.config.get("APP_RUNTIME")
    if runtime == APP_RUNTIME_LIVE_PROD:
        return True
    live_defaults = app.config.get("RUNTIME_DEFAULT_DATABASES", {}).get(APP_RUNTIME_LIVE_PROD, {})
    return (
        app.config.get("SQLALCHEMY_DATABASE_URI") == live_defaults.get("primary")
        or app.config.get("SQLALCHEMY_BINDS", {}).get(AUTH_BIND_KEY) == live_defaults.get("auth")
    )


def reset_auth_demo_data():
    db.session.query(AdminAccessEvent).delete()
    db.session.query(AdminUser).delete()

    for account in DEMO_USER_ACCOUNTS:
        comparison_time = utc_now()
        admin_user = AdminUser(
            email=account["email"],
            full_name=account["full_name"],
            last_login_at=account["last_login_at"],
        )
        admin_user.set_role(account["role"], now=comparison_time)
        admin_user.set_account_status(ACCOUNT_STATUS_ACTIVE, now=comparison_time)
        admin_user.set_password(account["password"])
        admin_user.must_change_password = False
        admin_user.reset_login_state()
        admin_user.sync_legacy_state()
        db.session.add(admin_user)
        db.session.flush()
        log_admin_access_event(
            event_type=ADMIN_ACCESS_EVENT_ACCOUNT_CREATED,
            outcome=ADMIN_ACCESS_EVENT_OUTCOME_SUCCESS,
            target=admin_user,
            after_state=serialize_admin_user_snapshot(admin_user, now=comparison_time),
            note="Seeded by init-db demo reset.",
        )


def reset_business_demo_data():
    db.session.query(Shipment).delete()
    db.session.query(OrderStatusEvent).delete()
    db.session.query(OrderItem).delete()
    db.session.query(ProductBatch).delete()
    db.session.query(BatchIngredient).delete()
    db.session.query(Order).delete()
    db.session.query(Batch).delete()
    db.session.query(Product).delete()
    db.session.query(Ingredient).delete()
    db.session.query(Customer).delete()

    customers = {
        "imani": Customer(
            first_name="Imani",
            last_name="Reed",
            email="imani.reed@example.com",
            phone="404-555-0146",
            street_address="412 Peachtree St NE",
            city="Atlanta",
            state="GA",
            postal_code="30308",
            country="USA",
            source="Fiverr",
            created_at=datetime(2026, 4, 5, 13, 15, tzinfo=timezone.utc),
        ),
        "sophia": Customer(
            first_name="Sophia",
            last_name="Patel",
            email="sophia.patel@example.com",
            phone="312-555-0198",
            street_address="81 W Wacker Dr",
            city="Chicago",
            state="IL",
            postal_code="60601",
            country="USA",
            source="Square",
            created_at=datetime(2026, 4, 7, 10, 0, tzinfo=timezone.utc),
        ),
        "leah": Customer(
            first_name="Leah",
            last_name="Nguyen",
            email="leah.nguyen@example.com",
            phone="713-555-0114",
            street_address="208 Main St",
            city="Houston",
            state="TX",
            postal_code="77002",
            country="USA",
            source="Manual Entry",
            created_at=datetime(2026, 4, 9, 15, 30, tzinfo=timezone.utc),
        ),
        "zoe": Customer(
            first_name="Zoe",
            last_name="Turner",
            email="zoe.turner@example.com",
            phone="615-555-0109",
            street_address="900 Woodland St",
            city="Nashville",
            state="TN",
            postal_code="37206",
            country="USA",
            source="Manual Entry",
            created_at=datetime(2026, 4, 11, 9, 5, tzinfo=timezone.utc),
        ),
    }
    db.session.add_all(customers.values())

    products = {
        "serum": Product(
            sku="SER-101",
            name="Radiance Serum",
            description="Daily brightening serum with niacinamide and rosehip oil.",
            price=Decimal("28.00"),
            active=True,
            reorder_threshold=8,
            created_at=datetime(2026, 4, 1, 9, 0, tzinfo=timezone.utc),
        ),
        "butter": Product(
            sku="BB-205",
            name="Velvet Body Butter",
            description="Rich shea butter blend for overnight moisture repair.",
            price=Decimal("22.50"),
            active=True,
            reorder_threshold=6,
            created_at=datetime(2026, 4, 2, 11, 0, tzinfo=timezone.utc),
        ),
        "oil": Product(
            sku="LO-330",
            name="Glossed Lip Oil",
            description="Conditioning lip oil with vitamin E and jojoba.",
            price=Decimal("14.00"),
            active=True,
            reorder_threshold=12,
            created_at=datetime(2026, 4, 3, 14, 0, tzinfo=timezone.utc),
        ),
        "sampler": Product(
            sku="KIT-404",
            name="Glow Sample Set",
            description="Inactive sample bundle kept for historical demo data.",
            price=Decimal("36.00"),
            active=False,
            reorder_threshold=0,
            created_at=datetime(2026, 4, 4, 16, 0, tzinfo=timezone.utc),
        ),
    }
    db.session.add_all(products.values())

    ingredients = {
        "niacinamide": Ingredient(
            name="Niacinamide",
            stock_quantity=Decimal("18.000"),
            unit="g",
            supplier_name="Actives Lab",
            supplier_contact="purchasing@activeslab.example",
            reorder_threshold=Decimal("8.000"),
            created_at=datetime(2026, 4, 1, 8, 0, tzinfo=timezone.utc),
        ),
        "shea": Ingredient(
            name="Shea Butter",
            stock_quantity=Decimal("4.500"),
            unit="kg",
            supplier_name="Pure Butter Co.",
            supplier_contact="orders@purebutter.example",
            reorder_threshold=Decimal("5.000"),
            created_at=datetime(2026, 4, 1, 8, 15, tzinfo=timezone.utc),
        ),
        "rosehip": Ingredient(
            name="Rosehip Oil",
            stock_quantity=Decimal("0.000"),
            unit="L",
            supplier_name="Botanical Source",
            supplier_contact="sales@botanicals.example",
            reorder_threshold=Decimal("2.000"),
            created_at=datetime(2026, 4, 1, 8, 30, tzinfo=timezone.utc),
        ),
        "vitamin_e": Ingredient(
            name="Vitamin E",
            stock_quantity=Decimal("12.000"),
            unit="g",
            supplier_name="Actives Lab",
            supplier_contact="purchasing@activeslab.example",
            reorder_threshold=Decimal("3.000"),
            created_at=datetime(2026, 4, 1, 8, 45, tzinfo=timezone.utc),
        ),
        "bottles": Ingredient(
            name="Amber Dropper Bottles",
            stock_quantity=Decimal("15.000"),
            unit="units",
            supplier_name="PackRight",
            supplier_contact="support@packright.example",
            reorder_threshold=Decimal("15.000"),
            created_at=datetime(2026, 4, 1, 9, 0, tzinfo=timezone.utc),
        ),
    }
    db.session.add_all(ingredients.values())

    batches = {
        "serum_batch": Batch(
            batch_code="B-2026-0412-A",
            status="Open",
            started_at=datetime(2026, 4, 12, 8, 0, tzinfo=timezone.utc),
            notes="Current serum production run for marketplace replenishment.",
        ),
        "butter_batch": Batch(
            batch_code="B-2026-0408-B",
            status="Closed",
            started_at=datetime(2026, 4, 8, 7, 30, tzinfo=timezone.utc),
            ended_at=datetime(2026, 4, 8, 14, 45, tzinfo=timezone.utc),
            notes="Completed body butter batch used to fulfill Square orders.",
        ),
    }
    db.session.add_all(batches.values())
    db.session.flush()

    db.session.add_all(
        [
            BatchIngredient(
                batch=batches["serum_batch"],
                ingredient=ingredients["niacinamide"],
                quantity_used=Decimal("2.250"),
                unit="g",
            ),
            BatchIngredient(
                batch=batches["serum_batch"],
                ingredient=ingredients["rosehip"],
                quantity_used=Decimal("1.100"),
                unit="L",
            ),
            BatchIngredient(
                batch=batches["butter_batch"],
                ingredient=ingredients["shea"],
                quantity_used=Decimal("3.500"),
                unit="kg",
            ),
            BatchIngredient(
                batch=batches["butter_batch"],
                ingredient=ingredients["vitamin_e"],
                quantity_used=Decimal("0.600"),
                unit="g",
            ),
        ]
    )

    product_batches = {
        "serum_lot": ProductBatch(
            batch=batches["serum_batch"],
            product=products["serum"],
            lot_number="LOT-SER-0412",
            units_produced=48,
            units_available=36,
            expiry_date=datetime(2027, 4, 12, tzinfo=timezone.utc).date(),
            created_at=datetime(2026, 4, 12, 12, 15, tzinfo=timezone.utc),
        ),
        "butter_lot": ProductBatch(
            batch=batches["butter_batch"],
            product=products["butter"],
            lot_number="LOT-BB-0408",
            units_produced=32,
            units_available=18,
            expiry_date=datetime(2027, 1, 8, tzinfo=timezone.utc).date(),
            created_at=datetime(2026, 4, 8, 15, 0, tzinfo=timezone.utc),
        ),
        "oil_lot": ProductBatch(
            batch=batches["serum_batch"],
            product=products["oil"],
            lot_number="LOT-LO-0412",
            units_produced=60,
            units_available=52,
            expiry_date=datetime(2027, 4, 12, tzinfo=timezone.utc).date(),
            created_at=datetime(2026, 4, 12, 13, 0, tzinfo=timezone.utc),
        ),
    }
    db.session.add_all(product_batches.values())
    db.session.flush()

    orders = {
        "fiverr_ready": Order(
            customer=customers["imani"],
            order_number="SB-2048",
            platform="Fiverr",
            total_amount=Decimal("42.00"),
            status="Ready",
            placed_at=datetime(2026, 4, 14, 10, 30, tzinfo=timezone.utc),
        ),
        "square_completed": Order(
            customer=customers["sophia"],
            order_number="SB-2047",
            platform="Square",
            total_amount=Decimal("22.50"),
            status="Completed",
            placed_at=datetime(2026, 4, 13, 14, 20, tzinfo=timezone.utc),
        ),
        "sheets_placed": Order(
            customer=customers["leah"],
            order_number="SB-2046",
            platform=GOOGLE_SHEETS_ORDER_SOURCE,
            total_amount=Decimal("28.00"),
            status="Placed",
            placed_at=datetime(2026, 4, 12, 11, 10, tzinfo=timezone.utc),
        ),
        "direct_placed": Order(
            customer=customers["imani"],
            order_number="SB-2045",
            platform="Direct",
            total_amount=Decimal("50.50"),
            status="Placed",
            placed_at=datetime(2026, 4, 11, 17, 5, tzinfo=timezone.utc),
        ),
    }
    db.session.add_all(orders.values())
    db.session.flush()

    db.session.add_all(
        [
            OrderItem(
                order=orders["fiverr_ready"],
                product=products["serum"],
                product_batch=product_batches["serum_lot"],
                quantity=1,
                unit_price=Decimal("28.00"),
            ),
            OrderItem(
                order=orders["fiverr_ready"],
                product=products["oil"],
                product_batch=product_batches["oil_lot"],
                quantity=1,
                unit_price=Decimal("14.00"),
            ),
            OrderItem(
                order=orders["square_completed"],
                product=products["butter"],
                product_batch=product_batches["butter_lot"],
                quantity=1,
                unit_price=Decimal("22.50"),
            ),
            OrderItem(
                order=orders["sheets_placed"],
                product=products["serum"],
                quantity=1,
                unit_price=Decimal("28.00"),
            ),
            OrderItem(
                order=orders["direct_placed"],
                product=products["serum"],
                product_batch=product_batches["serum_lot"],
                quantity=1,
                unit_price=Decimal("28.00"),
            ),
            OrderItem(
                order=orders["direct_placed"],
                product=products["butter"],
                product_batch=product_batches["butter_lot"],
                quantity=1,
                unit_price=Decimal("22.50"),
            ),
        ]
    )

    db.session.add_all(
        [
            OrderStatusEvent(
                order=orders["fiverr_ready"],
                event_status="Ready",
                message="Packed and queued for USPS pickup.",
                created_at=datetime(2026, 4, 14, 11, 0, tzinfo=timezone.utc),
            ),
            OrderStatusEvent(
                order=orders["square_completed"],
                event_status="Completed",
                message="Delivered to customer and closed out.",
                created_at=datetime(2026, 4, 13, 18, 45, tzinfo=timezone.utc),
            ),
            OrderStatusEvent(
                order=orders["sheets_placed"],
                event_status="Placed",
                message="Imported from Google Sheets intake queue.",
                created_at=datetime(2026, 4, 12, 11, 15, tzinfo=timezone.utc),
            ),
            OrderStatusEvent(
                order=orders["direct_placed"],
                event_status="Placed",
                message="Manual direct order awaiting fulfillment review.",
                created_at=datetime(2026, 4, 11, 17, 10, tzinfo=timezone.utc),
            ),
        ]
    )

    db.session.add_all(
        [
            Shipment(
                order=orders["fiverr_ready"],
                carrier="USPS",
                tracking_number="9400111206210582048001",
                tracking_url="https://tools.usps.com/go/TrackConfirmAction?tLabels=9400111206210582048001",
                shipped_at=datetime(2026, 4, 14, 12, 15, tzinfo=timezone.utc),
                created_at=datetime(2026, 4, 14, 12, 15, tzinfo=timezone.utc),
            ),
            Shipment(
                order=orders["square_completed"],
                carrier="UPS",
                tracking_number="1Z999AA10123456784",
                tracking_url="https://www.ups.com/track?tracknum=1Z999AA10123456784",
                shipped_at=datetime(2026, 4, 13, 15, 0, tzinfo=timezone.utc),
                delivered_at=datetime(2026, 4, 14, 9, 10, tzinfo=timezone.utc),
                created_at=datetime(2026, 4, 13, 15, 0, tzinfo=timezone.utc),
            ),
        ]
    )
@app.cli.command("init-db")
def init_db_command():
    if init_db_targets_live_data():
        raise click.ClickException("init-db only supports demo-dev targets.")
    db.create_all(bind_key="__all__")
    ensure_customer_source_column()
    ensure_admin_user_access_columns()
    reset_auth_demo_data()
    reset_business_demo_data()
    db.session.commit()
    print("Database initialized and demo data reset.")


@app.cli.command("init-live-db")
def init_live_db_command():
    db.create_all(bind_key="__all__")
    ensure_customer_source_column()
    ensure_admin_user_access_columns()
    db.session.commit()
    click.echo("Database schema initialized without demo data.")


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

    password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
    if not password:
        raise click.ClickException("Password cannot be empty.")
    password_errors = password_policy_errors(password, email=normalized_email)
    if password_errors:
        raise click.ClickException(password_errors[0])

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
    password_errors = password_policy_errors(password, email=normalized_email)
    if password_errors:
        raise click.ClickException(password_errors[0])

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


@app.cli.command("export-data")
@click.option("--output-dir", default=".", help="Directory to write the backup archive.")
def export_data_command(output_dir):
    """Dump both SQLite databases to a timestamped tar.gz with a SHA-256 integrity hash."""
    import hashlib
    import tarfile
    from pathlib import Path
    from urllib.parse import urlparse

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    output_path = Path(output_dir).resolve()
    output_path.mkdir(parents=True, exist_ok=True)
    archive_name = f"shynebeauty-backup-{timestamp}.tar.gz"
    archive_path = output_path / archive_name

    def _db_file(uri):
        if uri and uri.startswith("sqlite:///"):
            p = Path(uri[len("sqlite:///"):])
            return p if p.exists() else None
        return None

    primary_path = _db_file(app.config.get("SQLALCHEMY_DATABASE_URI", ""))
    auth_path = _db_file(
        (app.config.get("SQLALCHEMY_BINDS") or {}).get(AUTH_BIND_KEY, "")
    )

    files_to_archive = [p for p in [primary_path, auth_path] if p]
    if not files_to_archive:
        raise click.ClickException("No SQLite database files found to back up.")

    with tarfile.open(archive_path, "w:gz") as tar:
        for f in files_to_archive:
            tar.add(f, arcname=f.name)

    sha256 = hashlib.sha256()
    with open(archive_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)

    hash_path = archive_path.with_suffix(".tar.gz.sha256")
    hash_path.write_text(f"{sha256.hexdigest()}  {archive_name}\n", encoding="utf-8")

    click.echo(f"Backup written: {archive_path}")
    click.echo(f"SHA-256:        {hash_path}")
