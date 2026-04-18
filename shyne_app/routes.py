import io
import json
import logging
import os
import secrets
import string
from datetime import datetime, timedelta, timezone, date
from decimal import Decimal, InvalidOperation
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse
from decimal import Decimal

import click
from dotenv import dotenv_values
import pyotp
import qrcode
import qrcode.image.svg
from flask import (
    Flask,
    flash,
    jsonify,
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
from .auth import *

_logger = logging.getLogger("shynebeauty.auth")


def _request_client_ip():
    if app.config.get("TRUST_PROXY_HEADERS"):
        forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if forwarded:
            return forwarded
    return request.remote_addr or "unknown"


def _login_setup_error_response():
    flash("The authentication database is not initialized yet.", "error")
    flash(f"Run `{runtime_init_command_hint()}` to initialize it.", "info")
    return render_template(
        "login.html",
        form_data={"email": "", "remember_me": False},
        next_url=get_safe_next_target(request.args.get("next")),
    )


def _find_or_create_ip_throttle(ip_address):
    throttle = AdminLoginThrottle.query.filter_by(ip_address=ip_address).first()
    if throttle is None:
        throttle = AdminLoginThrottle(ip_address=ip_address)
        db.session.add(throttle)
    return throttle


def _mfa_provisioning_context(admin_user, *, session_key="mfa_enrollment_secret"):
    secret = session.get(session_key)
    if not secret:
        secret = pyotp.random_base32()
        session[session_key] = secret
    provisioning_uri = pyotp.TOTP(secret).provisioning_uri(
        name=admin_user.email,
        issuer_name="ShyneBeauty",
    )
    qr = qrcode.make(provisioning_uri, image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    qr.save(buf)
    raw_svg = buf.getvalue().decode("utf-8")
    # Strip XML declaration so the SVG can be safely inlined in HTML
    qr_svg_markup = raw_svg.split("?>", 1)[-1].strip() if "?>" in raw_svg else raw_svg
    return {
        "manual_secret": secret,
        "provisioning_uri": provisioning_uri,
        "qr_svg_markup": qr_svg_markup,
    }

@app.route("/health")
def health():
    try:
        db.session.execute(text("SELECT 1"))
        return jsonify(status="ok"), 200
    except Exception:
        return jsonify(status="error"), 503


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
            try:
                admin_user = AdminUser.query.filter_by(email=email).first()
                throttle = _find_or_create_ip_throttle(_request_client_ip())
            except OperationalError:
                db.session.rollback()
                return _login_setup_error_response()

            now = utc_now()

            client_ip = _request_client_ip()
            if throttle.is_locked(now):
                _logger.warning("login blocked — IP throttle active | ip=%s email=%s", client_ip, email)
                flash("Invalid email or password.", "error")
            elif admin_user and admin_user.is_locked(now):
                _logger.warning("login blocked — account locked | ip=%s email=%s", client_ip, email)
                flash("Invalid email or password.", "error")
            elif (
                admin_user
                and admin_user.get_account_status() == ACCOUNT_STATUS_ACTIVE
                and admin_user.check_password(password)
            ):
                admin_user.reset_login_state()
                admin_user.sync_legacy_state()
                throttle.reset_state()

                if admin_user.has_mfa_enabled():
                    session.clear()
                    session["pending_mfa_user_id"] = admin_user.id
                    session["pending_mfa_remember_me"] = remember_me
                    if next_url:
                        session["pending_mfa_next"] = next_url
                    db.session.commit()
                    _logger.info("login: MFA challenge started | ip=%s email=%s", client_ip, email)
                    return redirect(url_for("mfa_challenge"))

                admin_user.last_login_at = now
                db.session.commit()

                session.clear()
                login_user(admin_user, remember=remember_me)
                _logger.info("login success | ip=%s email=%s role=%s", client_ip, email, admin_user.get_role())
                if admin_user.requires_password_change():
                    if next_url:
                        return redirect(url_for("change_password", next=next_url))
                    return redirect(url_for("change_password"))
                return redirect_to_safe_next(
                    request.form.get("next") or request.args.get("next"),
                    fallback_endpoint="index",
                )
            else:
                throttle.register_failed_login(now)
                if admin_user:
                    admin_user.register_failed_login(now)
                db.session.commit()
                _logger.warning("login failed — bad credentials | ip=%s email=%s", client_ip, email)
                flash("Invalid email or password.", "error")

    return render_template(
        "login.html",
        form_data=form_data,
        next_url=next_url,
    )


@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if not current_user.is_authenticated:
        return login_manager.unauthorized()
    if not current_user.requires_password_change():
        return redirect(url_for("index"))

    next_url = get_safe_next_target(request.args.get("next"))
    enable_mfa_now = request.method == "POST" and request.form.get("enable_mfa") in {
        "on",
        "true",
        "1",
        "yes",
    }
    mfa_context = _mfa_provisioning_context(current_user)
    if request.method == "POST":
        next_url = get_safe_next_target(
            request.form.get("next") or request.args.get("next")
        )
        password = request.form.get("password") or ""
        password_confirmation = request.form.get("password_confirmation") or ""
        enable_mfa_now = request.form.get("enable_mfa") in {"on", "true", "1", "yes"}
        mfa_code = (request.form.get("mfa_code") or "").strip()
        errors = []

        if not password:
            errors.append("New password is required.")
        elif password != password_confirmation:
            errors.append("Passwords must match.")
        else:
            errors.extend(
                password_policy_errors(
                password,
                email=current_user.email,
                current_password=password if current_user.check_password(password) else None,
                )
            )

        if enable_mfa_now and not mfa_code:
            errors.append("Authentication code is required to enable MFA.")
        elif enable_mfa_now and not pyotp.TOTP(session["mfa_enrollment_secret"]).verify(
            mfa_code, valid_window=1
        ):
            errors.append("Enter a valid authentication code.")

        if errors:
            for error in errors:
                flash(error, "error")
        else:
            comparison_time = utc_now()
            before_state = serialize_admin_user_snapshot(
                current_user, now=comparison_time
            )
            current_user.set_password(password)
            current_user.must_change_password = False
            current_user.reset_login_state()
            if enable_mfa_now:
                current_user.enable_mfa(
                    secret=session.get("mfa_enrollment_secret"),
                    now=comparison_time,
                )
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
            if enable_mfa_now:
                session.pop("mfa_enrollment_secret", None)
                flash("Multi-factor authentication enabled.", "success")
            return redirect_to_safe_next(
                request.form.get("next") or request.args.get("next"),
                fallback_endpoint="index",
            )

    return render_template(
        "change_password.html",
        next_url=next_url,
        enable_mfa_now=enable_mfa_now,
        **mfa_context,
    )


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
        order_platform_options=ORDER_PLATFORM_OPTIONS,
        order_status_options=ORDER_STATUS_OPTIONS,
    )


@app.route("/tasks")
@require_permission(PERMISSION_TASKS_VIEW)
def tasks():
    intake_orders = (
        Order.query.options(
            db.joinedload(Order.customer),
            db.joinedload(Order.order_items).joinedload(OrderItem.product),
        )
        .filter(Order.status == "Placed")
        .order_by(Order.placed_at.desc())
        .all()
    )
    shipping_orders = (
        Order.query.options(
            db.joinedload(Order.customer),
            db.joinedload(Order.order_items).joinedload(OrderItem.product),
            db.joinedload(Order.shipment),
        )
        .filter(Order.status == "Ready")
        .order_by(Order.placed_at.desc())
        .all()
    )
    inventory_attention_items = (
        Ingredient.query.filter(
            Ingredient.stock_quantity <= Ingredient.reorder_threshold
        )
        .order_by(Ingredient.stock_quantity.asc(), Ingredient.name.asc())
        .all()
    )
    return render_template(
        "tasks.html",
        intake_orders=intake_orders,
        intake_count=len(intake_orders),
        shipping_orders=shipping_orders,
        shipping_count=len(shipping_orders),
        inventory_attention_items=inventory_attention_items,
        inventory_attention_count=len(inventory_attention_items),
    )


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
    search_query = request.args.get("search", "").strip()
    stock_status = request.args.get("stock_status", "")

    query = Ingredient.query

    if search_query:
        query = query.filter(Ingredient.name.ilike(f"%{search_query}%"))

    if stock_status:
        if stock_status == "in_stock":
            query = query.filter(Ingredient.stock_quantity > Ingredient.reorder_threshold)
        elif stock_status == "low_stock":
            query = query.filter(
                Ingredient.stock_quantity <= Ingredient.reorder_threshold,
                Ingredient.stock_quantity > 0,
            )
        elif stock_status == "out_of_stock":
            query = query.filter(Ingredient.stock_quantity == 0)

    all_items = query.order_by(Ingredient.name).all()

    return render_template(
        "inventory.html",
        all_items=all_items,
        search_query=search_query,
        selected_stock_status=stock_status,
    )


@app.route("/add-new")
@login_required
def add_new():
    if not has_any_permission(
        PERMISSION_CUSTOMERS_EDIT,
        PERMISSION_ORDERS_EDIT,
        PERMISSION_INVENTORY_EDIT,
        PERMISSION_PRODUCTION_EDIT,
    ):
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
                page_title="Add workflows denied",
                denial_message="You do not have permission to create business records from this menu.",
            ),
            403,
        )

    return render_template("AddNew.html")

@app.route("/add-customer", methods=["GET", "POST"])
@require_permission(PERMISSION_CUSTOMERS_EDIT)
def add_customer():
    form_data = {
        "first_name": "",
        "last_name": "",
        "email": "",
        "phone": "",
        "source": "",
        "street_address": "",
        "city": "",
        "state": "",
        "postal_code": "",
        "country": "USA",
    }
    
    if request.method == "POST":
        form_data = {
            "first_name": (request.form.get("first_name") or "").strip(),
            "last_name": (request.form.get("last_name") or "").strip(),
            "email": (request.form.get("email") or "").strip().lower(),
            "phone": (request.form.get("phone") or "").strip(),
            "source": (request.form.get("source") or "").strip(),
            "street_address": (request.form.get("street_address") or "").strip(),
            "city": (request.form.get("city") or "").strip(),
            "state": (request.form.get("state") or "").strip(),
            "postal_code": (request.form.get("postal_code") or "").strip(),
            "country": (request.form.get("country") or "").strip() or "USA",
        }
        
        errors = []
        
        if not form_data["first_name"]:
            errors.append("First name is required.")
        if not form_data["last_name"]:
            errors.append("Last name is required.")
        if not form_data["email"]:
            errors.append("Email is required.")
        
        if form_data["email"]:
            existing = Customer.query.filter_by(email=form_data["email"]).first()
            if existing:
                errors.append("A customer with that email already exists.")
        
        if not errors:
            try:
                customer = Customer(
                    first_name=form_data["first_name"],
                    last_name=form_data["last_name"],
                    email=form_data["email"],
                    phone=form_data["phone"] or None,
                    source=form_data["source"] or None,
                    street_address=form_data["street_address"] or None,
                    city=form_data["city"] or None,
                    state=form_data["state"] or None,
                    postal_code=form_data["postal_code"] or None,
                    country=form_data["country"],
                )
                db.session.add(customer)
                db.session.commit()
                flash("Customer created successfully!", "success")
                return redirect(url_for("customers"))
            except Exception as e:
                db.session.rollback()
                flash(f"Error creating customer: {str(e)}", "error")
        
        for error in errors:
            flash(error, "error")
    
    return render_template(
        "addCustomer.html",
        form_data=form_data,
        source_options=CUSTOMER_SOURCE_OPTIONS,
        is_edit=False
    )

@app.route("/edit-customer/<int:customer_id>", methods=["GET", "POST"])
@require_permission(PERMISSION_CUSTOMERS_EDIT)
def edit_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)
    
    if request.method == "POST":
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        phone = request.form.get('phone')
        street_address = request.form.get('street_address')
        city = request.form.get('city')
        state = request.form.get('state')
        postal_code = request.form.get('postal_code')
        country = request.form.get('country')
        
        errors = []
        
        if not first_name:
            errors.append("First name is required.")
        if not last_name:
            errors.append("Last name is required.")
        
        if errors:
            for error in errors:
                flash(error, "error")
            return redirect(url_for('edit_customer', customer_id=customer.id))
        
        try:

            customer.first_name = first_name
            customer.last_name = last_name
            customer.phone = phone
            customer.street_address = street_address
            customer.city = city
            customer.state = state
            customer.postal_code = postal_code
            customer.country = country or "USA"
            
            db.session.commit()
            flash(f"Customer {customer.first_name} {customer.last_name} updated successfully!", "success")
            return redirect(url_for('customers'))
            
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating customer: {str(e)}", "error")
            return redirect(url_for('edit_customer', customer_id=customer.id))
    

    form_data = {
        "first_name": customer.first_name,
        "last_name": customer.last_name,
        "email": customer.email,
        "phone": customer.phone or "",
        "source": customer.source or "",
        "street_address": customer.street_address or "",
        "city": customer.city or "",
        "state": customer.state or "",
        "postal_code": customer.postal_code or "",
        "country": customer.country or "USA",
    }
    
    return render_template(
        "addCustomer.html",
        form_data=form_data,
        source_options=CUSTOMER_SOURCE_OPTIONS,
        is_edit=True,
        edit_customer_id=customer.id
    )

#help funcion for getting order number
def generate_order_number():
    """Generate a unique order number"""
    year = datetime.now().year
    last_order = Order.query.order_by(Order.id.desc()).first()
    
    if last_order and last_order.order_number:

        try:
            last_num = int(last_order.order_number.split('-')[-1])
            new_num = last_num + 1
        except (ValueError, AttributeError):
            new_num = 1
    else:
        new_num = 1
    
    return f"ORD-{year}-{new_num:04d}"

def check_and_update_product_stock(product_id, quantity_used):
    product = Product.query.get(product_id)
    if not product:
        raise ValueError(f"Product ID {product_id} not found")
    
    if operation == "subtract":
        if product.quantity < quantity_used:
            raise ValueError(f"Not enough stock for {product.name}. Available: {product.stock_quantity}, Requested: {quantity_used}")
        product.quantity -= quantity_used
    
    return product


@app.route("/add-order", methods=["GET", "POST"])
@require_permission(PERMISSION_ORDERS_EDIT)
def add_order():
    customers = Customer.query.order_by(Customer.last_name, Customer.first_name).all()
    products = Product.query.filter_by(active=True).order_by(Product.name).all()

    form_data = {
        "customer_id": "",
        "platform": "Direct",
        "status": "Placed",
        "placed_at": datetime.now(timezone.utc).date().isoformat(),
    }
    line_items = [{"product_id": "", "quantity": "1", "unit_price": ""}]

    if request.method == "POST":
        form_data = {
            "customer_id": (request.form.get("customer_id") or "").strip(),
            "platform": (request.form.get("platform") or "").strip(),
            "status": (request.form.get("status") or "").strip(),
            "placed_at": (request.form.get("placed_at") or "").strip(),
        }
        line_items, line_item_lengths_match = read_line_items_form_data(request.form)

        errors = []
        customer = None
        placed_at = None
        parsed_line_items = []
        total_amount = Decimal("0.00")

        if not line_item_lengths_match:
            errors.append("Each line item must include a product, quantity, and price.")

        if not form_data["customer_id"]:
            errors.append("Customer is required.")
        else:
            try:
                customer = db.session.get(Customer, int(form_data["customer_id"]))
            except ValueError:
                customer = None
            if customer is None:
                errors.append("Select a valid customer.")

        if form_data["platform"] not in ORDER_PLATFORM_OPTIONS:
            errors.append("Order source must be a supported platform.")

        if form_data["status"] not in ORDER_STATUS_OPTIONS:
            errors.append("Status must be Placed, Ready, or Completed.")

        if not form_data["placed_at"]:
            errors.append("Order date is required.")
        else:
            try:
                placed_at = datetime.strptime(
                    form_data["placed_at"], "%Y-%m-%d"
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                errors.append("Order date must be a valid date.")

        active_line_items = [
            item
            for item in line_items
            if item["product_id"] or item["quantity"] or item["unit_price"]
        ]
        if not active_line_items:
            errors.append("Add at least one line item.")

        product_lookup = {product.id: product for product in products}
        for index, item in enumerate(active_line_items, start=1):
            product = None
            quantity = None
            unit_price = None

            try:
                product = product_lookup.get(int(item["product_id"]))
            except ValueError:
                product = None
            if product is None:
                errors.append(f"Line item {index} must use a valid product.")

            try:
                quantity = int(item["quantity"])
                if quantity <= 0:
                    raise ValueError
            except ValueError:
                errors.append(f"Line item {index} quantity must be a positive whole number.")

            try:
                unit_price = Decimal(item["unit_price"])
                if unit_price < 0:
                    raise ValueError
            except Exception:
                errors.append(f"Line item {index} price must be a valid non-negative amount.")

            if product is not None and quantity is not None and unit_price is not None:
                parsed_line_items.append(
                    {
                        "product": product,
                        "quantity": quantity,
                        "unit_price": unit_price,
                    }
                )
                total_amount += unit_price * quantity

        if not errors:
            order = Order(
                customer=customer,
                order_number=generate_order_number(),
                platform=form_data["platform"],
                total_amount=total_amount,
                status=form_data["status"],
                placed_at=placed_at,
            )
            db.session.add(order)
            db.session.flush()

            for item in parsed_line_items:
                db.session.add(
                    OrderItem(
                        order=order,
                        product=item["product"],
                        quantity=item["quantity"],
                        unit_price=item["unit_price"],
                    )
                )

            db.session.add(
                OrderStatusEvent(
                    order=order,
                    event_status=form_data["status"],
                    message="Initial status recorded on order creation.",
                )
            )
            db.session.commit()
            flash(f"Order {order.order_number} created successfully!", "success")
            return redirect(url_for("orders", search=order.order_number))
        

        for error in errors:
            flash(error, "error")
    

    return render_template("addOrder.html", 
                         customers=customers, 
                         products=products,
                         form_data=form_data,
                         line_items=line_items,
                         order_platform_options=ORDER_PLATFORM_OPTIONS,
                         order_status_options=ORDER_STATUS_OPTIONS)

@app.route("/edit-order/<int:order_id>", methods=["GET", "POST"])
@require_permission(PERMISSION_ORDERS_EDIT)
def edit_order(order_id):
    order = Order.query.get_or_404(order_id)
    
    if request.method == "POST":

        platform = request.form.get('platform')
        status = request.form.get('status')
        placed_at_str = request.form.get('placed_at')
        product_ids = request.form.getlist('product_id')
        quantities = request.form.getlist('quantity')
        unit_prices = request.form.getlist('unit_price')
        
        errors = []
        
        if not platform:
            errors.append("Platform is required.")
        
        if not product_ids or not product_ids[0]:
            errors.append("At least one product is required.")
        
        if errors:
            for error in errors:
                flash(error, "error")
            return redirect(url_for('edit_order', order_id=order.id))
        
        try:

            order.platform = platform
            order.status = status
            if placed_at_str:
                order.placed_at = datetime.strptime(placed_at_str, '%Y-%m-%d').replace(tzinfo=timezone.utc)
            order.updated_at = utc_now()
            

            OrderItem.query.filter_by(order_id=order.id).delete()
            

            total_amount = Decimal('0.00')
            for i, product_id in enumerate(product_ids):
                if product_id:
                    quantity = int(quantities[i]) if i < len(quantities) else 1
                    unit_price = Decimal(unit_prices[i]) if i < len(unit_prices) else 0
                    item_total = unit_price * quantity
                    total_amount += item_total
                    
                    order_item = OrderItem(
                        order_id=order.id,
                        product_id=int(product_id),
                        quantity=quantity,
                        unit_price=unit_price
                    )
                    db.session.add(order_item)
            
            order.total_amount = total_amount
            

            db.session.add(OrderStatusEvent(
                order_id=order.id,
                event_status=status,
                message=f"Order updated via edit form"
            ))
            
            db.session.commit()
            flash(f"Order {order.order_number} updated successfully!", "success")
            return redirect(url_for('orders'))
            
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating order: {str(e)}", "error")
            return redirect(url_for('edit_order', order_id=order.id))
    

    form_data = {
        "customer_id": str(order.customer_id),
        "platform": order.platform,
        "status": order.status,
        "placed_at": order.placed_at.strftime('%Y-%m-%d') if order.placed_at else '',
    }
    

    line_items = []
    for item in order.order_items:
        line_items.append({
            "product_id": str(item.product_id),
            "quantity": str(item.quantity),
            "unit_price": str(item.unit_price)
        })
    
    customers = Customer.query.order_by(Customer.last_name, Customer.first_name).all()
    products = Product.query.filter_by(active=True).order_by(Product.name).all()
    
    return render_template(
        "addOrder.html", 
        form_data=form_data,
        line_items=line_items,
        customers=customers,
        products=products,
        order_platform_options=ORDER_PLATFORM_OPTIONS,
        order_status_options=ORDER_STATUS_OPTIONS,
        is_edit=True,  
        edit_order_id=order.id 
    )


@app.route("/add-inventory", methods=["GET", "POST"])
@require_permission(PERMISSION_INVENTORY_EDIT)
def add_inventory():
    form_data = {
        "name": "",
        "unit": "g",
        "stock_quantity": "0",
        "reorder_threshold": "0",
        "supplier_name": "",
        "supplier_contact": "",
    }

    if request.method == "POST":
        form_data = {
            "name": (request.form.get("name") or "").strip(),
            "unit": (request.form.get("unit") or "").strip() or "g",
            "stock_quantity": (request.form.get("stock_quantity") or "").strip(),
            "reorder_threshold": (request.form.get("reorder_threshold") or "").strip(),
            "supplier_name": (request.form.get("supplier_name") or "").strip(),
            "supplier_contact": (request.form.get("supplier_contact") or "").strip(),
        }

        errors = []
        stock_quantity = None
        reorder_threshold = None

        if not form_data["name"]:
            errors.append("Item name is required.")

        existing_item = (
            Ingredient.query.filter(
                func.lower(Ingredient.name) == form_data["name"].lower()
            ).first()
            if form_data["name"]
            else None
        )
        if existing_item:
            errors.append("An inventory item with that name already exists.")

        try:
            stock_quantity = parse_non_negative_decimal(
                form_data["stock_quantity"],
                field_label="Current stock",
            )
        except ValueError as exc:
            errors.append(str(exc))

        try:
            reorder_threshold = parse_non_negative_decimal(
                form_data["reorder_threshold"],
                field_label="Reorder threshold",
            )
        except ValueError as exc:
            errors.append(str(exc))

        if not errors:
            ingredient = Ingredient(
                name=form_data["name"],
                unit=form_data["unit"],
                stock_quantity=stock_quantity,
                reorder_threshold=reorder_threshold,
                supplier_name=form_data["supplier_name"] or None,
                supplier_contact=form_data["supplier_contact"] or None,
            )
            db.session.add(ingredient)
            db.session.commit()
            flash("Inventory item created.", "success")
            return redirect(url_for("inventory", search=form_data["name"]))

        if errors:
            for error in errors:
                flash(error, "error")
    return render_template("addInventoryItem.html", form_data=form_data, is_edit=False)

@app.route("/edit-inventory/<int:item_id>", methods=["GET", "POST"])
@require_permission(PERMISSION_INVENTORY_EDIT)
def edit_inventory(item_id):
    item = Ingredient.query.get_or_404(item_id)
    
    if request.method == "POST":
        stock_quantity = request.form.get('stock_quantity')
        unit = request.form.get('unit')
        supplier_name = request.form.get('supplier_name')
        supplier_contact = request.form.get('supplier_contact')
        reorder_threshold = request.form.get('reorder_threshold')
        
        errors = []
        
        try:
            stock_quantity_val = parse_non_negative_decimal(
                stock_quantity,
                field_label="Current stock",
            )
        except ValueError as exc:
            errors.append(str(exc))
            stock_quantity_val = None
        
        try:
            reorder_threshold_val = parse_non_negative_decimal(
                reorder_threshold,
                field_label="Reorder threshold",
            )
        except ValueError as exc:
            errors.append(str(exc))
            reorder_threshold_val = None
        
        if not unit:
            errors.append("Unit is required.")
        
        if errors:
            for error in errors:
                flash(error, "error")
            return redirect(url_for('edit_inventory', item_id=item.id))
        
        try:

            item.stock_quantity = stock_quantity_val
            item.unit = unit
            item.supplier_name = supplier_name if supplier_name else None
            item.supplier_contact = supplier_contact if supplier_contact else None
            item.reorder_threshold = reorder_threshold_val
            
            db.session.commit()
            flash(f"Inventory item '{item.name}' updated successfully!", "success")
            return redirect(url_for('inventory'))
            
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating inventory item: {str(e)}", "error")
            return redirect(url_for('edit_inventory', item_id=item.id))
    

    form_data = {
        "name": item.name,
        "stock_quantity": str(item.stock_quantity),
        "unit": item.unit,
        "supplier_name": item.supplier_name or "",
        "supplier_contact": item.supplier_contact or "",
        "reorder_threshold": str(item.reorder_threshold),
    }
    
    return render_template(
        "addInventoryItem.html",
        form_data=form_data,
        is_edit=True,
        edit_item_id=item.id
    )

    
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
        password_errors = password_policy_errors(password, email=email)
        if password_errors:
            for error in password_errors:
                flash(error, "error")
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
    password_errors = password_policy_errors(password, email=target_user.email)
    if password_errors:
        for error in password_errors:
            flash(error, "error")
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
    password_errors = password_policy_errors(password, email=target_user.email)
    if password_errors:
        for error in password_errors:
            flash(error, "error")
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


@app.route("/mfa/challenge", methods=["GET", "POST"])
def mfa_challenge():
    pending_user_id = session.get("pending_mfa_user_id")
    if not pending_user_id:
        return redirect(url_for("login"))

    pending_user = db.session.get(AdminUser, pending_user_id)
    if pending_user is None or not pending_user.has_mfa_enabled():
        session.pop("pending_mfa_user_id", None)
        session.pop("pending_mfa_remember_me", None)
        session.pop("pending_mfa_next", None)
        flash("Sign in again.", "error")
        return redirect(url_for("login"))

    next_url = get_safe_next_target(
        request.form.get("next") or session.get("pending_mfa_next") or request.args.get("next")
    )
    if request.method == "POST":
        code = (request.form.get("code") or "").strip()
        if not pending_user.verify_mfa_code(code):
            flash("Enter a valid authentication code.", "error")
            return render_template(
                "mfa_challenge.html",
                pending_user=pending_user,
                next_url=next_url,
            )

        comparison_time = utc_now()
        pending_user.last_login_at = comparison_time
        pending_user.last_mfa_verified_at = comparison_time
        pending_user.reset_login_state()
        db.session.commit()

        remember_me = bool(session.get("pending_mfa_remember_me"))
        redirect_target = session.get("pending_mfa_next")
        session.clear()
        login_user(pending_user, remember=remember_me)
        if pending_user.requires_password_change():
            if redirect_target:
                return redirect(url_for("change_password", next=redirect_target))
            return redirect(url_for("change_password"))
        return redirect_to_safe_next(redirect_target, fallback_endpoint="index")

    return render_template(
        "mfa_challenge.html",
        pending_user=pending_user,
        next_url=next_url,
    )


@app.route("/account/settings", methods=["GET", "POST"])
@login_required
def account_settings():
    mfa_context = _mfa_provisioning_context(current_user)

    if request.method == "POST":
        action = (request.form.get("action") or "").strip()
        comparison_time = utc_now()
        if action == "change_password":
            current_password = request.form.get("current_password") or ""
            new_password = request.form.get("new_password") or ""
            password_confirmation = request.form.get("password_confirmation") or ""
            password_mfa_code = (request.form.get("password_mfa_code") or "").strip()
            errors = []

            if not current_user.check_password(current_password):
                errors.append("Current password is incorrect.")
            elif new_password != password_confirmation:
                errors.append("Passwords must match.")
            else:
                errors.extend(
                    password_policy_errors(
                    new_password,
                    email=current_user.email,
                    current_password=current_password if new_password == current_password else None,
                    )
                )

            if current_user.has_mfa_enabled():
                if not password_mfa_code:
                    errors.append("Authentication code is required to change your password.")
                elif not current_user.verify_mfa_code(password_mfa_code):
                    errors.append("Enter a valid authentication code.")

            if errors:
                for error in errors:
                    flash(error, "error")
            else:
                before_state = serialize_admin_user_snapshot(current_user, now=comparison_time)
                current_user.set_password(new_password)
                log_admin_access_event(
                    actor=current_user,
                    target=current_user,
                    event_type=ADMIN_ACCESS_EVENT_PASSWORD_CHANGED,
                    outcome=ADMIN_ACCESS_EVENT_OUTCOME_SUCCESS,
                    before_state=before_state,
                    after_state=serialize_admin_user_snapshot(current_user, now=comparison_time),
                    note="Password updated from account settings.",
                )
                db.session.commit()
                flash("Password updated.", "success")
                return redirect(url_for("account_settings"))

        elif action == "enable_mfa":
            mfa_code = (request.form.get("mfa_code") or "").strip()
            enrollment_secret = session.get("mfa_enrollment_secret")
            if not mfa_code:
                flash("Authentication code is required to enable MFA.", "error")
            elif not pyotp.TOTP(enrollment_secret).verify(mfa_code, valid_window=1):
                flash("Enter a valid authentication code.", "error")
            else:
                current_user.enable_mfa(secret=enrollment_secret, now=comparison_time)
                db.session.commit()
                session.pop("mfa_enrollment_secret", None)
                flash("Multi-factor authentication enabled.", "success")
                return redirect(url_for("account_settings"))

        elif action == "disable_mfa":
            disable_code = (request.form.get("disable_mfa_code") or "").strip()
            if not current_user.verify_mfa_code(disable_code):
                flash("Enter a valid authentication code.", "error")
            else:
                current_user.disable_mfa()
                db.session.commit()
                flash("Multi-factor authentication disabled.", "success")
                return redirect(url_for("account_settings"))

    elevated_roles = {ROLE_INVENTORY_PRODUCTION, ROLE_SUPERADMIN, ROLE_DEV_ADMIN}
    show_mfa_warning = (
        current_user.get_role() in elevated_roles
        and not current_user.has_mfa_enabled()
    )
    return render_template(
        "account_settings.html",
        mfa_enabled=current_user.has_mfa_enabled(),
        show_mfa_warning=show_mfa_warning,
        **mfa_context,
    )


import random
from datetime import datetime

def generate_batch_code():
    """Generate a unique batch code like BATCH-2024-001"""
    year = datetime.now().year
    # Get the last batch to determine the next number
    last_batch = Batch.query.order_by(Batch.id.desc()).first()
    
    if last_batch and last_batch.batch_code:
        try:
            # Extract number from format BATCH-2024-001
            parts = last_batch.batch_code.split('-')
            if len(parts) >= 3:
                last_num = int(parts[-1])
                new_num = last_num + 1
            else:
                new_num = 1
        except:
            new_num = 1
    else:
        new_num = 1
    
    return f"BATCH-{year}-{new_num:03d}"

def generate_lot_number(product_sku):
    """Generate a lot number based on product SKU, e.g., LOT-LIP001-2024-001"""
    year = datetime.now().year
    # Get the last product batch for this product to determine sequence
    last_batch = ProductBatch.query.order_by(ProductBatch.id.desc()).first()
    
    if last_batch and last_batch.lot_number:
        try:
            # Extract sequence number from format LOT-SKU-2024-001
            parts = last_batch.lot_number.split('-')
            if len(parts) >= 4:
                last_num = int(parts[-1])
                new_num = last_num + 1
            else:
                new_num = 1
        except:
            new_num = 1
    else:
        new_num = 1
    
    # Create SKU without hyphens for lot number
    clean_sku = product_sku.replace('-', '')
    return f"LOT-{clean_sku}-{year}-{new_num:03d}"


@app.route("/product-batches")
@require_permission(PERMISSION_INVENTORY_VIEW)
def product_batches():
    search_query = request.args.get("search", "").strip()
    product_id = request.args.get("product_id", "").strip()
    stock_status = request.args.get("stock_status", "")

    query = ProductBatch.query

    if search_query:
        query = query.filter(
            (ProductBatch.lot_number.ilike(f"%{search_query}%")) |
            (ProductBatch.product.has(Product.name.ilike(f"%{search_query}%"))) |
            (ProductBatch.product.has(Product.sku.ilike(f"%{search_query}%")))
        )

    if product_id:
        query = query.filter(ProductBatch.product_id == int(product_id))

    if stock_status:
        if stock_status == "in_stock":
            query = query.filter(ProductBatch.units_available > 0)
        elif stock_status == "low_stock":
            query = query.filter(ProductBatch.units_available <= 10, ProductBatch.units_available > 0)
        elif stock_status == "out_of_stock":
            query = query.filter(ProductBatch.units_available == 0)
        elif stock_status == "expired":
            query = query.filter(ProductBatch.expiry_date < date.today())

    all_batches = query.options(
        db.joinedload(ProductBatch.product),
        db.joinedload(ProductBatch.batch)
    ).order_by(ProductBatch.created_at.desc()).all()

    products = Product.query.filter_by(active=True).order_by(Product.name).all()

    return render_template(
        "manageProducts.html",
        all_batches=all_batches,
        products=products,
        search_query=search_query,
        selected_product_id=product_id,
        selected_stock_status=stock_status,
        today=date.today()
    )

@app.route("/manage-products")
@require_permission(PERMISSION_PRODUCTION_VIEW)
def manage_products():
    search_query = request.args.get("search", "").strip()
    status_filter = request.args.get("status", "").strip()
    stock_status = request.args.get("stock_status", "").strip()

    query = Product.query

    if search_query:
        query = query.filter(
            (Product.name.ilike(f"%{search_query}%")) |
            (Product.sku.ilike(f"%{search_query}%")) |
            (Product.description.ilike(f"%{search_query}%"))
        )

    if status_filter == "active":
        query = query.filter(Product.active == True)
    elif status_filter == "inactive":
        query = query.filter(Product.active == False)

    all_products = query.order_by(Product.name).all()

    # Filter by stock status (requires checking batches)
    if stock_status:
        filtered_products = []
        for product in all_products:
            total_stock = sum(batch.units_available for batch in product.product_batches)
            if stock_status == "in_stock" and total_stock > 0:
                filtered_products.append(product)
            elif stock_status == "low_stock" and 0 < total_stock <= product.reorder_threshold:
                filtered_products.append(product)
            elif stock_status == "out_of_stock" and total_stock == 0:
                filtered_products.append(product)
        all_products = filtered_products

    return render_template(
        "viewProducts.html",
        all_products=all_products,
        search_query=search_query,
        selected_status=status_filter,
        selected_stock_status=stock_status
    )


@app.route("/add-product", methods=["GET", "POST"])
@require_permission(PERMISSION_PRODUCTION_EDIT)
def add_product():
    form_data = {
        "name": "",
        "sku": "",

        "price": "",
        "reorder_threshold": "0",
        "units_produced": "",  # User only needs to enter this
    }

    if request.method == "POST":
        form_data = {
            "name": (request.form.get("name") or "").strip(),
            "sku": (request.form.get("sku") or "").strip(),

            "price": (request.form.get("price") or "").strip(),
            "reorder_threshold": (request.form.get("reorder_threshold") or "").strip() or "0",
            "units_produced": (request.form.get("units_produced") or "").strip(),
        }

        errors = []
        price = None
        reorder_threshold = None
        units_produced = None

        # Product validation
        if not form_data["name"]:
            errors.append("Product name is required.")
        if not form_data["sku"]:
            errors.append("SKU is required.")

        if form_data["sku"]:
            existing_product = Product.query.filter(
                func.lower(Product.sku) == form_data["sku"].lower()
            ).first()
            if existing_product:
                errors.append("A product with that SKU already exists.")

        try:
            price = Decimal(form_data["price"])
            if price < 0:
                raise ValueError
        except (InvalidOperation, ValueError):
            errors.append("Price must be a valid non-negative amount.")

        try:
            reorder_threshold = int(form_data["reorder_threshold"])
            if reorder_threshold < 0:
                raise ValueError
        except ValueError:
            errors.append("Reorder threshold must be a non-negative whole number.")

        # Batch validation - only units produced needed
        if not form_data["units_produced"]:
            errors.append("Units produced (initial stock) is required.")

        try:
            units_produced = int(form_data["units_produced"])
            if units_produced < 0:
                raise ValueError
        except ValueError:
            errors.append("Units produced must be a non-negative whole number.")

        if not errors:
            try:
                # Auto-generate batch code and lot number
                batch_code = generate_batch_code()
                lot_number = generate_lot_number(form_data["sku"])
                
                # Create the product
                product = Product(
                    name=form_data["name"],
                    sku=form_data["sku"],
                    price=price,
                    active=True,
                    reorder_threshold=reorder_threshold,
                )
                db.session.add(product)
                db.session.flush()  # Get the product ID

                # Create a production batch
                production_batch = Batch(
                    batch_code=batch_code,
                    status="Completed",
                    started_at=utc_now(),
                    ended_at=utc_now(),
                    notes=f"Initial batch for product {form_data['name']}"
                )
                db.session.add(production_batch)
                db.session.flush()  # Get the batch ID

                # Create the product batch (lot)
                product_batch = ProductBatch(
                    batch_id=production_batch.id,
                    product_id=product.id,
                    lot_number=lot_number,
                    units_produced=units_produced,
                    units_available=units_produced,  # Initially, all produced units are available
                    expiry_date=None,  # Can be set later via edit
                )
                db.session.add(product_batch)

                db.session.commit()
                flash(f"Product {form_data['name']} created! Batch: {batch_code}, Lot: {lot_number}", "success")
                return redirect(url_for("inventory"))

            except Exception as e:
                db.session.rollback()
                flash(f"Error creating product: {str(e)}", "error")

        for error in errors:
            flash(error, "error")

    return render_template(
        "addProduct.html",
        form_data=form_data,
        is_edit=False
    )

def generate_lot_number_for_product(product_id, product_sku):
    """Generate lot number for an existing product"""
    year = datetime.now().year
    # Count existing batches for this product
    batch_count = ProductBatch.query.filter_by(product_id=product_id).count()
    new_num = batch_count + 1
    
    clean_sku = product_sku.replace('-', '')
    return f"LOT-{clean_sku}-{year}-{new_num:03d}"


@app.route("/edit-product-batch/<int:batch_id>", methods=["GET", "POST"])
@require_permission(PERMISSION_INVENTORY_EDIT)
def edit_product_batch(batch_id):
    product_batch = ProductBatch.query.get_or_404(batch_id)
    
    if request.method == "POST":
        units_available = request.form.get("units_available")
        units_produced = request.form.get("units_produced")
        expiry_date_str = request.form.get("expiry_date")
        
        errors = []
        
        if not units_available:
            errors.append("Units available is required.")
        
        if errors:
            for error in errors:
                flash(error, "error")
            return redirect(url_for("edit_product_batch", batch_id=product_batch.id))
        
        try:
            if units_available:
                product_batch.units_available = int(units_available)
            if units_produced:
                product_batch.units_produced = int(units_produced)
            if expiry_date_str:
                product_batch.expiry_date = datetime.strptime(expiry_date_str, "%Y-%m-%d").date()
            else:
                product_batch.expiry_date = None
            
            db.session.commit()
            flash(f"Stock updated for batch {product_batch.lot_number}!", "success")
            return redirect(url_for("product_batches"))
            
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating batch: {str(e)}", "error")
            return redirect(url_for("edit_product_batch", batch_id=product_batch.id))
    
    # GET request - show form with existing data
    form_data = {
        "product_id": str(product_batch.product_id),
        "batch_id": str(product_batch.batch_id),
        "product_name": product_batch.product.name,  # Add this for display
        "lot_number": product_batch.lot_number,
        "units_produced": str(product_batch.units_produced),
        "units_available": str(product_batch.units_available),
        "expiry_date": product_batch.expiry_date.strftime("%Y-%m-%d") if product_batch.expiry_date else "",
    }
    
    products = Product.query.filter_by(active=True).order_by(Product.name).all()
    production_batches = Batch.query.order_by(Batch.started_at.desc()).all()
    
    return render_template(
        "addProductBatch.html",
        form_data=form_data,
        products=products,
        production_batches=production_batches,
        is_edit=True,
        edit_batch_id=product_batch.id
    )

@app.route("/edit-product/<int:product_id>", methods=["GET", "POST"])
@require_permission(PERMISSION_PRODUCTION_EDIT)
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    if request.method == "POST":
        name = request.form.get("name")

        price = request.form.get("price")
        reorder_threshold = request.form.get("reorder_threshold")
        
        errors = []
        
        if not name:
            errors.append("Product name is required.")
        
        try:
            price_val = Decimal(price)
            if price_val < 0:
                raise ValueError
        except (InvalidOperation, ValueError):
            errors.append("Price must be a valid non-negative amount.")
        
        if errors:
            for error in errors:
                flash(error, "error")
            return redirect(url_for("edit_product", product_id=product.id))
        
        try:
            product.name = name
            product.price = price_val
            product.reorder_threshold = int(reorder_threshold) if reorder_threshold else 0
            
            db.session.commit()
            flash(f"Product {product.name} updated successfully!", "success")
            return redirect(url_for("inventory"))
            
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating product: {str(e)}", "error")
    
    form_data = {
        "name": product.name,
        "sku": product.sku,
        "price": str(product.price),
        "reorder_threshold": str(product.reorder_threshold),
    }
    
    return render_template("addProduct.html", form_data=form_data, is_edit=True, edit_product_id=product.id)

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    logout_user()
    return redirect(url_for("login"))
