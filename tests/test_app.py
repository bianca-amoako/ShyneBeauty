from datetime import date, datetime, timezone
from decimal import Decimal

from sqlalchemy import inspect

from shyne import (
    Batch,
    BatchIngredient,
    Customer,
    Ingredient,
    MODEL_REGISTRY,
    Order,
    OrderItem,
    OrderStatusEvent,
    Product,
    ProductBatch,
    Shipment,
    db,
)

# loads html
def test_home_route_renders(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.content_type.startswith("text/html")

# loads admin html page
def test_admin_route_renders(client):
    response = client.get("/admin/")
    assert response.status_code == 200
    assert response.content_type.startswith("text/html")

# check that model registry includes all core tables 
def test_model_registry_has_core_tables():
    expected_tables = {
        "customers",
        "products",
        "ingredients",
        "batches",
        "product_batches",
        "orders",
        "order_items",
        "batch_ingredients",
        "order_status_events",
        "shipments",
    }
    assert expected_tables.issubset(MODEL_REGISTRY.keys())


def test_index_route_renders_expected_dashboard(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.content_type.startswith("text/html")
    assert b"Home Dashboard / Analytics" in response.data


def test_orders_route_renders(client):
    response = client.get("/orders")
    assert response.status_code == 200
    assert response.content_type.startswith("text/html")


def test_orders_route_renders_expected_manage_orders_content(client):
    response = client.get("/orders")
    assert response.status_code == 200
    assert b"Manage Orders" in response.data
    assert b"Track customer orders from Fiverr, Square, Google Sheets, and manual entries." in response.data
    assert b"Order List" in response.data
    assert b"SB-1001" in response.data


def test_tasks_route_renders_expected_task_content(client):
    response = client.get("/tasks")
    assert response.status_code == 200
    assert b"Task List" in response.data
    assert b"Track tasks for each order." in response.data
    assert b"ANITA NJIWAH" in response.data
    assert b"+ Add Task" in response.data


def test_index_route_links_to_orders_page(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b'href="/orders"' in response.data
    assert b"Manage Orders" in response.data


def test_orders_route_links_back_to_dashboard(client):
    response = client.get("/orders")
    assert response.status_code == 200
    assert b'href="/"' in response.data or b'href="index.html"' in response.data
    assert b"Home Dashboard" in response.data


def test_shyne_icon_is_served_from_static(client):
    response = client.get("/static/shyneIcon.png")
    assert response.status_code == 200
    assert response.content_type == "image/png"


def test_orders_route_is_registered(app):
    routes = {rule.rule for rule in app.url_map.iter_rules()}
    assert "/" in routes
    assert "/orders" in routes
    assert "/tasks" in routes


def test_admin_route_renders_admin_shell(client):
    response = client.get("/admin/")
    assert response.status_code == 200
    assert response.content_type.startswith("text/html")
    assert b"ShyneBeauty Admin" in response.data


def test_init_db_cli_command_creates_tables_and_reports_success(app):
    runner = app.test_cli_runner()
    result = runner.invoke(args=["init-db"])

    assert result.exit_code == 0
    assert "Database initialized." in result.output

    inspector = inspect(db.engine)
    assert {
        "customers",
        "products",
        "ingredients",
        "batches",
        "product_batches",
        "orders",
        "order_items",
        "batch_ingredients",
        "order_status_events",
        "shipments",
    }.issubset(set(inspector.get_table_names()))


def test_init_db_cli_command_is_idempotent(app):
    runner = app.test_cli_runner()

    first_result = runner.invoke(args=["init-db"])
    second_result = runner.invoke(args=["init-db"])

    assert first_result.exit_code == 0
    assert second_result.exit_code == 0
    assert "Database initialized." in first_result.output
    assert "Database initialized." in second_result.output



def test_model_defaults_and_relationships_round_trip(app):
    with app.app_context():
        customer = Customer(
            first_name="Mia",
            last_name="Lopez",
            email="mia@example.com",
        )
        product = Product(
            sku="SKU-001",
            name="Glow Serum",
            price=Decimal("24.99"),
        )
        ingredient = Ingredient(
            name="Hyaluronic Acid",
            stock_quantity=Decimal("12.500"),
        )
        batch = Batch(batch_code="B-100")
        order = Order(
            customer=customer,
            order_number="ORD-100",
            total_amount=Decimal("24.99"),
        )
        order_item = OrderItem(
            order=order,
            product=product,
            quantity=1,
            unit_price=Decimal("24.99"),
        )
        batch_ingredient = BatchIngredient(
            batch=batch,
            ingredient=ingredient,
            quantity_used=Decimal("1.250"),
        )
        product_batch = ProductBatch(
            batch=batch,
            product=product,
            lot_number="LOT-100",
            units_produced=10,
            units_available=10,
            expiry_date=date(2026, 12, 31),
        )
        status_event = OrderStatusEvent(
            order=order,
            event_status="Packed",
            message="Ready for shipping",
            created_at=datetime(2026, 3, 19, 10, 30, tzinfo=timezone.utc),
        )
        shipment = Shipment(
            order=order,
            carrier="USPS",
            tracking_number="9400110898825022579493",
            tracking_url="https://tools.usps.com/go/TrackConfirmAction?tLabels=9400110898825022579493",
        )

        db.session.add_all(
            [
                customer,
                product,
                ingredient,
                batch,
                order,
                order_item,
                batch_ingredient,
                product_batch,
                status_event,
                shipment,
            ]
        )
        db.session.commit()

        db.session.expire_all()

        loaded_customer = Customer.query.filter_by(email="mia@example.com").one()
        loaded_order = Order.query.filter_by(order_number="ORD-100").one()
        loaded_product = Product.query.filter_by(sku="SKU-001").one()
        loaded_batch = Batch.query.filter_by(batch_code="B-100").one()
        loaded_ingredient = Ingredient.query.filter_by(name="Hyaluronic Acid").one()

        assert loaded_customer.country == "USA"
        assert loaded_product.active is True
        assert loaded_product.reorder_threshold == 0
        assert loaded_ingredient.unit == "g"
        assert loaded_ingredient.reorder_threshold == 0
        assert loaded_batch.status == "Open"
        assert loaded_order.platform == "Direct"
        assert loaded_order.status == "Placed"
        assert loaded_order.customer is loaded_customer
        assert loaded_customer.orders[0] is loaded_order
        assert loaded_order.order_items[0].product is loaded_product
        assert loaded_product.order_items[0].order is loaded_order
        assert loaded_order.status_events[0].event_status == "Packed"
        assert loaded_order.shipment.tracking_number == "9400110898825022579493"
        assert loaded_batch.batch_ingredients[0].ingredient is loaded_ingredient
        assert loaded_batch.product_batches[0].product is loaded_product
        assert loaded_product.product_batches[0].batch is loaded_batch
