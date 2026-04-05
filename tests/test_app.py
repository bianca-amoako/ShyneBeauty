import os
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path

from sqlalchemy import inspect

from shyne import (
    AdminUser,
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
    load_project_env,
)


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
    assert "admin_users" not in MODEL_REGISTRY


def test_load_project_env_reads_local_env_file(monkeypatch, tmp_path):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.delenv("SESSION_COOKIE_SECURE", raising=False)

    env_dir = tmp_path / ".env"
    env_dir.mkdir()
    env_file = env_dir / "local.env"
    env_file.write_text(
        "SECRET_KEY=dotenv-secret\nSESSION_COOKIE_SECURE=true\n",
        encoding="utf-8",
    )

    loaded_path = load_project_env(tmp_path)

    assert loaded_path == env_file
    assert os.environ["SECRET_KEY"] == "dotenv-secret"
    assert os.environ["SESSION_COOKIE_SECURE"] == "true"


def test_load_project_env_does_not_override_existing_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("SECRET_KEY", "shell-secret")

    env_dir = tmp_path / ".env"
    env_dir.mkdir()
    (env_dir / "local.env").write_text(
        "SECRET_KEY=dotenv-secret\n",
        encoding="utf-8",
    )

    load_project_env(Path(tmp_path))

    assert os.environ["SECRET_KEY"] == "shell-secret"


def test_login_route_renders_expected_content(client):
    response = client.get("/login")

    assert response.status_code == 200
    assert response.content_type.startswith("text/html")
    assert b"Sign in to ShyneBeauty" in response.data
    assert b"Admin dashboard access" in response.data
    assert b"Forgot password?" in response.data
    assert b"trusted internal admin workflow" in response.data


def test_index_route_links_to_orders_page(client, admin_user, login):
    login(client)

    response = client.get("/")

    assert response.status_code == 200
    assert b'href="/orders"' in response.data
    assert b'href="/customers"' in response.data
    assert b"Manage Orders" in response.data


def test_orders_route_links_back_to_dashboard(client, admin_user, login):
    login(client)

    response = client.get("/orders")

    assert response.status_code == 200
    assert b'href="/"' in response.data or b'href="index.html"' in response.data
    assert b"Home Dashboard" in response.data


def test_shyne_icon_is_served_from_static(client):
    response = client.get("/static/shyneIcon.png")

    assert response.status_code == 200
    assert response.content_type == "image/png"


def test_routes_are_registered(app):
    routes = {rule.rule for rule in app.url_map.iter_rules()}

    assert "/" in routes
    assert "/login" in routes
    assert "/orders" in routes
    assert "/customers" in routes
    assert "/tasks" in routes
    assert "/logout" in routes


def test_init_db_cli_command_creates_tables_and_reports_success(app):
    runner = app.test_cli_runner()
    result = runner.invoke(args=["init-db"])

    assert result.exit_code == 0
    assert "Database initialized." in result.output

    primary_inspector = inspect(db.engine)
    auth_inspector = inspect(db.engines["auth"])
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
    }.issubset(set(primary_inspector.get_table_names()))
    assert "admin_users" not in set(primary_inspector.get_table_names())
    assert "admin_users" in set(auth_inspector.get_table_names())


def test_init_db_cli_command_is_idempotent(app):
    runner = app.test_cli_runner()

    first_result = runner.invoke(args=["init-db"])
    second_result = runner.invoke(args=["init-db"])

    assert first_result.exit_code == 0
    assert second_result.exit_code == 0
    assert "Database initialized." in first_result.output
    assert "Database initialized." in second_result.output


def test_create_admin_cli_command_creates_hashed_password(app):
    runner = app.test_cli_runner()
    password = "StrongPassw0rd!"

    result = runner.invoke(
        args=["create-admin", "--email", "owner@shynebeauty.com"],
        input=f"{password}\n{password}\n",
    )

    assert result.exit_code == 0
    assert "Admin user created: owner@shynebeauty.com" in result.output

    with app.app_context():
        user = AdminUser.query.filter_by(email="owner@shynebeauty.com").one()
        assert user.password_hash != password
        assert user.check_password(password) is True
        assert "admin_users" not in set(inspect(db.engine).get_table_names())
        assert "admin_users" in set(inspect(db.engines["auth"]).get_table_names())


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
