import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

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
from sqlalchemy import or_
from werkzeug.security import check_password_hash, generate_password_hash

FAILED_LOGIN_THRESHOLD = 5
ACCOUNT_LOCK_DURATION = timedelta(minutes=15)
BASE_DIR = Path(__file__).resolve().parent
AUTH_BIND_KEY = "auth"
SECURITY_HEADERS = {
    "Referrer-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
}
NO_STORE_ENDPOINTS = {"index", "login", "logout", "orders", "tasks"}


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
    if not candidate.startswith("/") or candidate.startswith("//") or candidate.startswith("/\\"):
        return False

    parts = urlsplit(candidate)
    return not parts.scheme and not parts.netloc


def get_safe_next_target(target):
    if is_safe_next_target(target):
        return target.strip()
    return ""


def current_request_next_target():
    if request.query_string:
        return f"{request.path}?{request.query_string.decode('utf-8')}"
    return request.path


class AdminUser(UserMixin, db.Model):
    __bind_key__ = AUTH_BIND_KEY
    __tablename__ = "admin_users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, nullable=False, default=True)
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

    def set_password(self, password):
        if not password:
            raise ValueError("Password is required.")
        self.password_hash = generate_password_hash(password, method='pbkdf2')

    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

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

        self.failed_login_count += 1
        if self.failed_login_count >= FAILED_LOGIN_THRESHOLD:
            self.locked_until = comparison_time + ACCOUNT_LOCK_DURATION

    def reset_login_state(self):
        self.failed_login_count = 0
        self.locked_until = None


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
    created_at = db.Column(
        db.DateTime(timezone=True), default=utc_now, nullable=False
    )

    orders = db.relationship("Order", back_populates="customer", lazy=True)


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


class SecureAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_active

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for("login", next=current_request_next_target()))


class LiveDataModelView(ModelView):
    # Internal admin UI for live table browsing/editing during development.
    can_view_details = True
    can_export = True
    page_size = 50
    column_display_pk = True

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_active

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for("login", next=current_request_next_target()))


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
    template_mode="bootstrap4",
    index_view=SecureAdminIndexView(url="/admin/"),
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
    if current_user.is_authenticated:
        label = current_user.full_name or current_user.email
    return {"current_admin_label": label}


@app.route("/")
@login_required
def index():
    total_orders = db.session.query(Order).count()
    ready_to_ship_count = db.session.query(Order).filter(Order.status == 'Ready').count()
    completed_orders = db.session.query(Order).filter(Order.status == "Completed").count()
    fiverr_orders = db.session.query(Order).filter(Order.platform == "Fiverr").count()
    square_orders = db.session.query(Order).filter(Order.platform == "Square").count()
    google_orders = db.session.query(Order).filter(Order.platform == "Sheets").count()
    recent_orders = Order.query.order_by(Order.placed_at.desc()).limit(3).all()
    return render_template("index.html", total_orders=total_orders, ready_to_ship_count=ready_to_ship_count, fiverr_orders=fiverr_orders, square_orders=square_orders, google_orders=google_orders, recent_orders=recent_orders, completed_orders=completed_orders)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
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

            if admin_user and admin_user.is_locked(now):
                flash("Invalid email or password.", "error")
            elif admin_user and admin_user.is_active and admin_user.check_password(password):
                admin_user.reset_login_state()
                admin_user.last_login_at = now
                db.session.commit()

                session.clear()
                login_user(admin_user, remember=remember_me)
                return redirect(next_url or url_for("index"))
            else:
                if admin_user:
                    admin_user.register_failed_login(now)
                    db.session.commit()
                flash("Invalid email or password.", "error")

    return render_template("login.html", form_data=form_data, next_url=next_url)


@app.route("/orders")
@login_required
def orders():
    search_query = request.args.get('search', '').strip()
    source = request.args.get('source', '')
    status = request.args.get('status', '')

    query = Order.query
    
    if search_query:
        query = query.filter(
            or_(
                Order.order_number.ilike(f'%{search_query}%'),
                Order.customer.has(Customer.first_name.ilike(f'%{search_query}%')),
                Order.customer.has(Customer.last_name.ilike(f'%{search_query}%'))
            )
        )
    
    if source:
        query = query.filter(Order.platform == source)
    
    if status:
        query = query.filter(Order.status == status)
    
    all_orders = query.options(
        db.joinedload(Order.customer),
        db.joinedload(Order.order_items).joinedload(OrderItem.product),
        db.joinedload(Order.shipment)
    ).order_by(Order.placed_at.desc()).all()
    
    return render_template("manageOrders.html", 
                         all_orders=all_orders,
                         search_query=search_query,
                         selected_source=source,
                         selected_status=status)


@app.route("/tasks")
@login_required
def tasks():
    return render_template("tasks.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    logout_user()
    return redirect(url_for("login"))


@app.cli.command("init-db")
def init_db_command():
    db.create_all(bind_key="__all__")
    print("Database initialized.")


@app.cli.command("create-admin")
@click.option("--email", required=True, help="Admin email address.")
@click.option("--full-name", default=None, help="Optional admin display name.")
@click.option(
    "--update",
    is_flag=True,
    help="Update an existing admin user instead of failing if the email already exists.",
)
def create_admin_command(email, full_name, update):
    normalized_email = normalize_email(email)
    if not normalized_email:
        raise click.ClickException("A valid email address is required.")

    password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
    if not password:
        raise click.ClickException("Password cannot be empty.")

    db.create_all(bind_key=[AUTH_BIND_KEY])
    admin_user = AdminUser.query.filter_by(email=normalized_email).first()

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

    admin_user.is_active = True
    admin_user.reset_login_state()
    admin_user.set_password(password)
    db.session.commit()

    click.echo(f"Admin user {action}: {normalized_email}")


if __name__ == "__main__":
    app.run(host="localhost", port=8000, debug=env_flag("FLASK_DEBUG", default=False))
