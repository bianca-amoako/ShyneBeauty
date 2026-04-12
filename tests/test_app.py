import os
import re
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path

from sqlalchemy import inspect, text

from shyne import (
    ACCOUNT_STATUS_ACTIVE,
    AdminUser,
    Batch,
    AdminAccessEvent,
    BatchIngredient,
    Customer,
    Ingredient,
    MODEL_REGISTRY,
    Order,
    OrderItem,
    OrderStatusEvent,
    PASSWORD_HASH_METHOD,
    Product,
    ProductBatch,
    ROLE_DEV_ADMIN,
    ROLE_SUPERADMIN,
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
    assert b"Local development shortcut" not in response.data


def test_login_route_shows_dev_test_admin_hint_when_enabled(app, client):
    app.config["ENABLE_DEV_TEST_ADMIN"] = True

    response = client.get("/login")

    assert response.status_code == 200
    assert b"Local development setup" in response.data
    assert b"seed-dev-admin" in response.data
    assert b"sign in with <code>admin</code> / <code>admin</code>" in response.data


def test_login_route_shows_dev_test_admin_credentials_after_seeding(app, client):
    app.config["ENABLE_DEV_TEST_ADMIN"] = True
    runner = app.test_cli_runner()

    result = runner.invoke(args=["seed-dev-admin"])

    assert result.exit_code == 0

    response = client.get("/login")

    assert response.status_code == 200
    assert b"Local development shortcut" in response.data
    assert b"email field" in response.data
    assert b"admin</code> as the password" in response.data


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
    assert "/inventory" in routes
    assert "/users" in routes
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
    assert {
        column["name"] for column in primary_inspector.get_columns("customers")
    } >= {
        "source",
    }
    assert "admin_users" not in set(primary_inspector.get_table_names())
    assert "admin_users" in set(auth_inspector.get_table_names())
    assert "admin_access_events" in set(auth_inspector.get_table_names())
    assert {
        column["name"] for column in auth_inspector.get_columns("admin_users")
    } >= {
        "role",
        "account_status",
        "invited_at",
        "invited_by_user_id",
        "activated_at",
        "permission_overrides_json",
    }


def test_init_db_cli_command_is_idempotent(app):
    runner = app.test_cli_runner()

    first_result = runner.invoke(args=["init-db"])
    second_result = runner.invoke(args=["init-db"])

    assert first_result.exit_code == 0
    assert second_result.exit_code == 0
    assert "Database initialized." in first_result.output
    assert "Database initialized." in second_result.output


def test_init_db_cli_command_adds_customer_source_column_to_existing_table(app):
    with app.app_context():
        db.drop_all(bind_key="__all__")
        with db.engine.begin() as connection:
            connection.execute(
                text(
                    """
                    CREATE TABLE customers (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        first_name TEXT NOT NULL,
                        last_name TEXT NOT NULL,
                        email TEXT NOT NULL UNIQUE,
                        phone TEXT,
                        street_address TEXT,
                        city TEXT,
                        state TEXT,
                        postal_code TEXT,
                        country TEXT DEFAULT 'USA',
                        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """
                )
            )

    runner = app.test_cli_runner()
    result = runner.invoke(args=["init-db"])

    assert result.exit_code == 0

    with app.app_context():
        customer_columns = {
            column["name"] for column in inspect(db.engine).get_columns("customers")
        }
        assert "source" in customer_columns


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
        assert user.password_hash.startswith(f"{PASSWORD_HASH_METHOD}$")
        assert user.check_password(password) is True
        assert user.get_role() == ROLE_SUPERADMIN
        assert user.get_account_status() == ACCOUNT_STATUS_ACTIVE
        assert "admin_users" not in set(inspect(db.engine).get_table_names())
        assert "admin_users" in set(inspect(db.engines["auth"]).get_table_names())


def test_create_admin_cli_command_rejects_reserved_dev_admin_identifier(app):
    runner = app.test_cli_runner()

    result = runner.invoke(
        args=["create-admin", "--email", "admin"],
        input="admin\nadmin\n",
    )

    assert result.exit_code != 0
    assert "reserved for the dev-only seed-dev-admin command" in result.output


def test_seed_dev_admin_cli_command_requires_enable_flag(app):
    runner = app.test_cli_runner()

    result = runner.invoke(args=["seed-dev-admin"])

    assert result.exit_code != 0
    assert "ENABLE_DEV_TEST_ADMIN=true" in result.output


def test_seed_dev_admin_cli_command_requires_debug_or_testing_mode(app):
    app.config.update(
        ENABLE_DEV_TEST_ADMIN=True,
        TESTING=False,
        DEBUG=False,
    )
    runner = app.test_cli_runner()

    result = runner.invoke(args=["seed-dev-admin"])

    assert result.exit_code != 0
    assert "debug or testing mode" in result.output


def test_seed_dev_admin_cli_command_upserts_dev_admin(app):
    app.config["ENABLE_DEV_TEST_ADMIN"] = True
    runner = app.test_cli_runner()

    first_result = runner.invoke(args=["seed-dev-admin"])

    assert first_result.exit_code == 0
    assert "Dev test admin created: admin" in first_result.output

    with app.app_context():
        user = AdminUser.query.filter_by(email="admin").one()
        user.full_name = None
        user.is_active = False
        user.failed_login_count = 5
        user.locked_until = datetime.now(timezone.utc)
        db.session.commit()

    second_result = runner.invoke(args=["seed-dev-admin"])

    assert second_result.exit_code == 0
    assert "Dev test admin updated: admin" in second_result.output

    with app.app_context():
        user = AdminUser.query.filter_by(email="admin").one()
        assert user.full_name == "Dev Admin"
        assert user.is_active is True
        assert user.get_role() == ROLE_DEV_ADMIN
        assert user.failed_login_count == 0
        assert user.locked_until is None
        assert user.password_hash != "admin"
        assert user.password_hash.startswith(f"{PASSWORD_HASH_METHOD}$")
        assert user.check_password("admin") is True
        assert AdminUser.query.filter_by(email="admin").count() == 1


def test_create_dev_admin_cli_command_creates_hidden_dev_admin(app):
    runner = app.test_cli_runner()
    password = "StrongPassw0rd!"

    result = runner.invoke(
        args=["create-dev-admin", "--email", "tech@shynebeauty.com"],
        input=f"{password}\n{password}\n",
    )

    assert result.exit_code == 0
    assert "Dev Admin created: tech@shynebeauty.com" in result.output

    with app.app_context():
        user = AdminUser.query.filter_by(email="tech@shynebeauty.com").one()
        assert user.get_role() == ROLE_DEV_ADMIN
        assert user.get_account_status() == ACCOUNT_STATUS_ACTIVE


def test_backfill_admin_access_requires_explicit_superadmin_assignment(app, admin_factory):
    with app.app_context():
        admin_factory(
            email="legacy@shynebeauty.com",
            full_name="Legacy Admin",
            role=None,
            account_status=None,
        )

    runner = app.test_cli_runner()
    failure = runner.invoke(args=["backfill-admin-access"])
    success = runner.invoke(
        args=[
            "backfill-admin-access",
            "--first-superadmin-email",
            "legacy@shynebeauty.com",
        ]
    )

    assert failure.exit_code != 0
    assert "zero active superadmins" in failure.output
    assert success.exit_code == 0

    with app.app_context():
        user = AdminUser.query.filter_by(email="legacy@shynebeauty.com").one()
        assert user.get_role() == ROLE_SUPERADMIN


def test_model_defaults_and_relationships_round_trip(app):
    with app.app_context():
        customer = Customer(
            first_name="Mia",
            last_name="Lopez",
            email="mia@example.com",
            source="Fiverr",
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
        assert loaded_customer.source == "Fiverr"
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


def test_customer_source_defaults_to_none(app):
    with app.app_context():
        customer = Customer(
            first_name="Ava",
            last_name="Cole",
            email="ava@example.com",
        )

        db.session.add(customer)
        db.session.commit()
        db.session.expire_all()

        loaded_customer = Customer.query.filter_by(email="ava@example.com").one()

        assert loaded_customer.source is None


def test_customers_route_filters_by_source(client, admin_user, login, app):
    with app.app_context():
        fiverr_customer = Customer(
            first_name="Avery",
            last_name="Stone",
            email="avery@example.com",
            source="Fiverr",
        )
        square_customer = Customer(
            first_name="Bianca",
            last_name="Jones",
            email="bianca@example.com",
            source="Square",
        )
        db.session.add_all([fiverr_customer, square_customer])
        db.session.commit()

    login(client)

    response = client.get("/customers?source=Fiverr")

    assert response.status_code == 200
    assert b"Avery Stone" in response.data
    assert b"Bianca Jones" not in response.data


def test_dashboard_and_orders_render_google_sheets_order_source(
    client, admin_user, login, app
):
    with app.app_context():
        customer = Customer(
            first_name="Gia",
            last_name="Sheets",
            email="gia@example.com",
        )
        order = Order(
            customer=customer,
            order_number="ORD-GS-1",
            platform="Google Sheets",
            total_amount=Decimal("19.99"),
        )
        db.session.add_all([customer, order])
        db.session.commit()

    login(client)

    dashboard_response = client.get("/")
    orders_response = client.get("/orders")

    dashboard_text = dashboard_response.get_data(as_text=True)
    orders_text = orders_response.get_data(as_text=True)

    assert dashboard_response.status_code == 200
    assert orders_response.status_code == 200
    assert re.search(r"Gia Sheets</td>\s*<td>Google Sheets</td>", dashboard_text)
    assert re.search(r"Gia Sheets</td>\s*<td>Google Sheets</td>", orders_text)


def test_google_sheets_source_filter_and_dashboard_count_use_canonical_value(
    client, admin_user, login, app
):
    with app.app_context():
        canonical_customer = Customer(
            first_name="Cora",
            last_name="Canonical",
            email="cora@example.com",
        )
        legacy_customer = Customer(
            first_name="Lena",
            last_name="Legacy",
            email="lena@example.com",
        )
        canonical_order = Order(
            customer=canonical_customer,
            order_number="ORD-GOOGLE-1",
            platform="Google Sheets",
            total_amount=Decimal("18.00"),
        )
        legacy_order = Order(
            customer=legacy_customer,
            order_number="ORD-SHEETS-1",
            platform="Sheets",
            total_amount=Decimal("11.00"),
        )
        db.session.add_all(
            [canonical_customer, legacy_customer, canonical_order, legacy_order]
        )
        db.session.commit()

    login(client)

    filtered_response = client.get("/orders?source=Google+Sheets")
    dashboard_response = client.get("/")

    filtered_text = filtered_response.get_data(as_text=True)
    dashboard_text = dashboard_response.get_data(as_text=True)

    assert filtered_response.status_code == 200
    assert dashboard_response.status_code == 200
    assert "Cora Canonical" in filtered_text
    assert "Lena Legacy" not in filtered_text
    assert re.search(r"Google Sheets</td>\s*<td>1</td>", dashboard_text)
