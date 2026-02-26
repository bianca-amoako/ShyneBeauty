import os
from datetime import datetime

from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL", "sqlite:///shynebeauty.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


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
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    batch_ingredients = db.relationship(
        "BatchIngredient", back_populates="ingredient", lazy=True
    )


class Batch(db.Model):
    __tablename__ = "batches"

    id = db.Column(db.Integer, primary_key=True)
    batch_code = db.Column(db.String(80), unique=True, nullable=False, index=True)
    status = db.Column(db.String(50), nullable=False, default="Open")
    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ended_at = db.Column(db.DateTime)
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

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
    placed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
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
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    order = db.relationship("Order", back_populates="status_events")


class Shipment(db.Model):
    __tablename__ = "shipments"

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=False, unique=True)
    carrier = db.Column(db.String(120))
    tracking_number = db.Column(db.String(120), unique=True, index=True)
    tracking_url = db.Column(db.String(500))
    shipped_at = db.Column(db.DateTime)
    delivered_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    order = db.relationship("Order", back_populates="shipment")


@app.route("/")
def index():
    return render_template("index.html")


@app.cli.command("init-db")
def init_db_command():
    db.create_all()
    print("Database initialized.")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="localhost", port=8000, debug=True)
