import os
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pytest
from sqlalchemy import inspect, select

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


def login(
    client,
    *,
    email="admin@shynebeauty.com",
    password="correct-horse-battery-staple",
    remember_me=False,
    next_url=None,
):
    data = {
        "email": email,
        "password": password,
    }
    if remember_me:
        data["remember_me"] = "on"
    if next_url is not None:
        data["next"] = next_url

    return client.post(
        "/login",
        data=data,
        query_string={"next": next_url} if next_url is not None else None,
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


@pytest.mark.parametrize("route", ["/", "/orders", "/tasks", "/admin/"])
def test_anonymous_access_to_protected_routes_redirects_to_login(client, route):
    response = client.get(route)

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/login?next={route}")


def test_login_route_renders_expected_content(client):
    response = client.get("/login")

    assert response.status_code == 200
    assert response.content_type.startswith("text/html")
    assert b"Sign in to ShyneBeauty" in response.data
    assert b"Admin dashboard access" in response.data
    assert b"Forgot password?" in response.data
    assert b"trusted internal admin workflow" in response.data


def test_login_route_sets_security_headers(client):
    response = client.get("/login")

    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["Referrer-Policy"] == "same-origin"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN"


def test_login_route_rejects_missing_credentials_with_feedback(client):
    response = client.post("/login", data={"email": "", "password": ""})

    assert response.status_code == 200
    assert b"Email is required." in response.data
    assert b"Password is required." in response.data


def test_valid_login_succeeds_and_resets_login_state(client, admin_user, app):
    client.post(
        "/login",
        data={
            "email": "admin@shynebeauty.com",
            "password": "wrong-password",
        },
    )
    client.post(
        "/login",
        data={
            "email": "admin@shynebeauty.com",
            "password": "wrong-password",
        },
    )

    with client.session_transaction() as session_data:
        session_data["pre_auth_marker"] = "clear-me"

    response = login(client, remember_me=True, next_url="/orders")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/orders")

    with client.session_transaction() as session_data:
        assert "pre_auth_marker" not in session_data
        assert session_data.get("_user_id") == str(admin_user)

    with app.app_context():
        row = db.session.execute(
            select(
                AdminUser.failed_login_count,
                AdminUser.locked_until,
                AdminUser.last_login_at,
            ).where(AdminUser.id == admin_user)
        ).one()
        assert row.failed_login_count == 0
        assert row.locked_until is None
        assert row.last_login_at is not None


def test_login_with_remember_me_sets_cookie_flags(client, admin_user):
    response = login(client, remember_me=True)

    remember_cookie = next(
        header
        for header in response.headers.getlist("Set-Cookie")
        if header.startswith("remember_token=")
    )

    assert "HttpOnly" in remember_cookie
    assert "SameSite=Lax" in remember_cookie


@pytest.mark.parametrize(
    ("email", "password"),
    [
        ("admin@shynebeauty.com", "wrong-password"),
        ("missing@shynebeauty.com", "wrong-password"),
    ],
)
def test_invalid_credentials_show_generic_error(client, admin_user, email, password):
    response = client.post("/login", data={"email": email, "password": password})

    assert response.status_code == 200
    assert b"Invalid email or password." in response.data


def test_inactive_admin_cannot_log_in(client, app):
    with app.app_context():
        user = AdminUser(
            email="inactive@shynebeauty.com",
            full_name="Inactive Admin",
            is_active=False,
        )
        user.set_password("correct-horse-battery-staple")
        db.session.add(user)
        db.session.commit()
        db.session.remove()

    response = login(client, email="inactive@shynebeauty.com")

    assert response.status_code == 200
    assert b"Invalid email or password." in response.data

    with client.session_transaction() as session_data:
        assert "_user_id" not in session_data


def test_open_redirect_attempts_are_ignored(client, admin_user):
    response = login(client, next_url="https://evil.example/phish")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")


def test_authenticated_users_are_redirected_away_from_login(client, admin_user):
    login(client)

    response = client.get("/login")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")


def test_logout_requires_post(client):
    response = client.get("/logout")

    assert response.status_code == 405


def test_logout_clears_authentication(client, admin_user):
    login(client, remember_me=True)

    response = client.post("/logout")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")

    with client.session_transaction() as session_data:
        assert "_user_id" not in session_data

    protected_response = client.get("/")
    assert protected_response.status_code == 302
    assert "/login?next=" in protected_response.headers["Location"]

    remember_cookie = next(
        header
        for header in response.headers.getlist("Set-Cookie")
        if header.startswith("remember_token=")
    )
    assert "Expires=Thu, 01 Jan 1970" in remember_cookie


def test_lockout_triggers_after_repeated_failed_attempts(client, admin_user, app):
    for _ in range(5):
        response = client.post(
            "/login",
            data={
                "email": "admin@shynebeauty.com",
                "password": "wrong-password",
            },
        )
        assert response.status_code == 200
        assert b"Invalid email or password." in response.data

    with app.app_context():
        refreshed_user = db.session.get(AdminUser, admin_user)
        assert refreshed_user.failed_login_count == 5
        assert refreshed_user.locked_until is not None

    locked_response = login(client)

    assert locked_response.status_code == 200
    assert b"Invalid email or password." in locked_response.data


def test_expired_lockout_allows_login_again(client, admin_user, app):
    user_id = admin_user

    with app.app_context():
        user = db.session.get(AdminUser, user_id)
        user.failed_login_count = 5
        user.locked_until = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.session.commit()

    response = login(client)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")

    with app.app_context():
        row = db.session.execute(
            select(
                AdminUser.failed_login_count,
                AdminUser.locked_until,
            ).where(AdminUser.id == user_id)
        ).one()
        assert row.failed_login_count == 0
        assert row.locked_until is None


@pytest.mark.parametrize(
    ("route", "expected_text"),
    [
        ("/", b"Home Dashboard / Analytics"),
        ("/orders", b"Manage Orders"),
        ("/tasks", b"Task List"),
        ("/admin/", b"ShyneBeauty Admin"),
    ],
)
def test_authenticated_users_can_reach_protected_routes(
    client, admin_user, route, expected_text
):
    login(client)

    response = client.get(route)

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.content_type.startswith("text/html")
    assert expected_text in response.data


def test_index_route_links_to_orders_page(client, admin_user):
    login(client)

    response = client.get("/")

    assert response.status_code == 200
    assert b'href="/orders"' in response.data
    assert b"Manage Orders" in response.data


def test_orders_route_links_back_to_dashboard(client, admin_user):
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
