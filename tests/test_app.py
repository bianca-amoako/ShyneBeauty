import os
import re
import logging
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path

from sqlalchemy import inspect, text

from shyne import (
    APP_RUNTIME_CHOICES,
    APP_RUNTIME_DEMO_DEV,
    APP_RUNTIME_LIVE_PROD,
    AUTH_BIND_KEY,
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
    ROLE_INVENTORY_PRODUCTION,
    ROLE_DEV_ADMIN,
    ROLE_STAFF_OPERATOR,
    ROLE_SUPERADMIN,
    Shipment,
    default_runtime_for_process,
    db,
    init_db_targets_live_data,
    instance_database_uris,
    load_project_env,
    load_user,
    runtime_init_command_hint,
    runtime_default_flag,
    resolve_runtime_database_config,
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


def test_default_runtime_for_process_uses_demo_defaults():
    assert default_runtime_for_process(invoked_as_main=True) == APP_RUNTIME_DEMO_DEV
    assert default_runtime_for_process(invoked_as_main=False) == APP_RUNTIME_DEMO_DEV


def test_runtime_default_flag_switches_between_demo_and_live_defaults():
    assert runtime_default_flag(APP_RUNTIME_DEMO_DEV, demo_default=False, live_default=True) is False
    assert runtime_default_flag(APP_RUNTIME_LIVE_PROD, demo_default=False, live_default=True) is True


def test_instance_database_uris_returns_demo_and_live_defaults(tmp_path):
    uris = instance_database_uris(tmp_path)

    assert set(uris) == {APP_RUNTIME_DEMO_DEV, APP_RUNTIME_LIVE_PROD}
    assert "shynebeauty_demo.db" in uris[APP_RUNTIME_DEMO_DEV]["primary"]
    assert "shynebeauty_demo_auth.db" in uris[APP_RUNTIME_DEMO_DEV]["auth"]
    assert "shynebeauty_live.db" in uris[APP_RUNTIME_LIVE_PROD]["primary"]
    assert "shynebeauty_live_auth.db" in uris[APP_RUNTIME_LIVE_PROD]["auth"]


def test_resolve_runtime_database_config_uses_demo_defaults_when_runtime_unset(tmp_path):
    config = resolve_runtime_database_config(base_dir=tmp_path, environ={})

    assert config["runtime"] == APP_RUNTIME_DEMO_DEV
    assert "shynebeauty_demo.db" in config["primary_uri"]
    assert "shynebeauty_demo_auth.db" in config["auth_uri"]
    assert config["database_override"] is False
    assert config["auth_database_override"] is False


def test_resolve_runtime_database_config_uses_live_defaults_when_runtime_is_live(tmp_path):
    config = resolve_runtime_database_config(
        base_dir=tmp_path,
        environ={"APP_RUNTIME": APP_RUNTIME_LIVE_PROD},
    )

    assert config["runtime"] == APP_RUNTIME_LIVE_PROD
    assert "shynebeauty_live.db" in config["primary_uri"]
    assert "shynebeauty_live_auth.db" in config["auth_uri"]


def test_resolve_runtime_database_config_prefers_explicit_database_overrides(tmp_path):
    config = resolve_runtime_database_config(
        base_dir=tmp_path,
        environ={
            "APP_RUNTIME": APP_RUNTIME_LIVE_PROD,
            "DATABASE_URL": "sqlite:////tmp/custom-primary.db",
            "AUTH_DATABASE_URL": "sqlite:////tmp/custom-auth.db",
        },
    )

    assert config["runtime"] == APP_RUNTIME_LIVE_PROD
    assert config["primary_uri"] == "sqlite:////tmp/custom-primary.db"
    assert config["auth_uri"] == "sqlite:////tmp/custom-auth.db"
    assert config["database_override"] is True
    assert config["auth_database_override"] is True


def test_resolve_runtime_database_config_rejects_invalid_runtime(tmp_path):
    try:
        resolve_runtime_database_config(
            base_dir=tmp_path,
            environ={"APP_RUNTIME": "staging"},
        )
    except RuntimeError as exc:
        assert "APP_RUNTIME must be one of" in str(exc)
        for runtime in APP_RUNTIME_CHOICES:
            assert runtime in str(exc)
    else:
        raise AssertionError("Expected invalid APP_RUNTIME to raise RuntimeError")


def test_readme_documents_demo_runtime_for_local_dev():
    readme = Path("README.md").read_text(encoding="utf-8")

    assert "APP_RUNTIME = \"demo-dev\"" in readme or "APP_RUNTIME=demo-dev" in readme
    assert "python shyne.py" in readme
    assert "Unset runtime means demo" in readme


def test_readme_documents_gunicorn_as_linux_production_default():
    readme = Path("README.md").read_text(encoding="utf-8")

    assert 'gunicorn -w 1 --threads 4 --bind 127.0.0.1:8000 "shyne_app.app:app"' in readme
    assert "Live requires explicit `APP_RUNTIME=live-prod`" in readme


def test_resolve_log_dir_defaults_to_instance_logs():
    from shyne_app.app import _resolve_log_dir

    log_dir = _resolve_log_dir(Path("/tmp/shynebeauty-project"), environ={})

    assert log_dir == Path("/tmp/shynebeauty-project/instance/logs")


def test_resolve_log_dir_honors_environment_override():
    from shyne_app.app import _resolve_log_dir

    log_dir = _resolve_log_dir(
        Path("/tmp/shynebeauty-project"),
        environ={"SHYNE_LOG_DIR": "/var/log/shynebeauty"},
    )

    assert log_dir == Path("/var/log/shynebeauty")


def test_configure_logging_is_idempotent(tmp_path):
    from shyne_app.app import _configure_logging

    logger_name = "shynebeauty.test.idempotent"
    logger = logging.getLogger(logger_name)
    logger.handlers.clear()
    logger._shyne_logging_configured = False

    try:
        _configure_logging(
            APP_RUNTIME_DEMO_DEV,
            tmp_path,
            logger_name=logger_name,
        )
        _configure_logging(
            APP_RUNTIME_DEMO_DEV,
            tmp_path,
            logger_name=logger_name,
        )

        assert len(logger.handlers) == 2
        assert sum(
            isinstance(handler, logging.StreamHandler)
            and not isinstance(handler, logging.handlers.TimedRotatingFileHandler)
            for handler in logger.handlers
        ) == 1
        assert sum(
            isinstance(handler, logging.handlers.TimedRotatingFileHandler)
            for handler in logger.handlers
        ) == 1
    finally:
        for handler in list(logger.handlers):
            handler.close()
            logger.removeHandler(handler)
        logger._shyne_logging_configured = False


def test_safe_timed_rotating_file_handler_recovers_from_permission_error(
    monkeypatch, tmp_path
):
    from shyne_app.app import SafeTimedRotatingFileHandler

    original_rollover = logging.handlers.TimedRotatingFileHandler.doRollover

    def _raise_permission_error(self):
        raise PermissionError("rename denied")

    monkeypatch.setattr(
        logging.handlers.TimedRotatingFileHandler,
        "doRollover",
        _raise_permission_error,
    )

    handler = SafeTimedRotatingFileHandler(
        tmp_path / "shynebeauty.log",
        when="midnight",
        backupCount=1,
        encoding="utf-8",
        delay=True,
    )

    try:
        handler.rolloverAt = 0
        handler.doRollover()
        assert handler.rolloverAt > 0

        record = logging.LogRecord(
            name="shynebeauty.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="after rollover fallback",
            args=(),
            exc_info=None,
        )
        handler.emit(record)

        assert "after rollover fallback" in (
            tmp_path / "shynebeauty.log"
        ).read_text(encoding="utf-8")
    finally:
        handler.close()
        monkeypatch.setattr(
            logging.handlers.TimedRotatingFileHandler,
            "doRollover",
            original_rollover,
        )


def test_app_runtime_sensitive_defaults_are_applied():
    from shyne import app

    assert app.config["APP_RUNTIME"] in {APP_RUNTIME_DEMO_DEV, APP_RUNTIME_LIVE_PROD}
    if app.config["APP_RUNTIME"] == APP_RUNTIME_DEMO_DEV:
        assert app.config["SESSION_COOKIE_SECURE"] is False
        assert app.config["ENABLE_DEV_TEST_ADMIN"] is False
        assert app.config["TRUST_PROXY_HEADERS"] is False
    else:
        assert app.config["SESSION_COOKIE_SECURE"] is True
        assert app.config["ENABLE_DEV_TEST_ADMIN"] is False
        assert app.config["TRUST_PROXY_HEADERS"] is False


def test_login_route_renders_expected_content(client):
    response = client.get("/login")

    assert response.status_code == 200
    assert response.content_type.startswith("text/html")
    assert b"Sign in to ShyneBeauty" in response.data
    assert b"Admin dashboard access" in response.data
    assert b"trusted internal admin workflow" in response.data
    assert b"Local development shortcut" not in response.data
    assert b"seed-dev-admin" not in response.data


def test_login_shows_setup_error_when_auth_schema_is_missing(app, client):
    with app.app_context():
        AdminUser.__table__.drop(bind=db.engines["auth"], checkfirst=True)

    response = client.post(
        "/login",
        data={
            "email": "olivia.mercer@shynebeauty.com",
            "password": "ShyneDemoSuper1!",
        },
    )

    assert response.status_code == 200
    assert b"The authentication database is not initialized yet." in response.data
    assert runtime_init_command_hint().encode("utf-8") in response.data


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
    assert "/add-new" in routes
    assert "/add-customer" in routes
    assert "/add-order" in routes
    assert "/add-inventory" in routes
    assert "/add-product" in routes
    assert "/users" in routes
    assert "/change-password" in routes
    assert "/account/settings" in routes
    assert "/logout" in routes


def test_load_user_returns_none_when_auth_table_is_unavailable(app):
    with app.app_context():
        auth_engine = db.engines["auth"]
        AdminUser.__table__.drop(bind=auth_engine, checkfirst=True)

        assert load_user("1") is None


def test_index_renders_operational_sections(client, admin_user, login):
    login(client)

    response = client.get("/")

    assert response.status_code == 200
    assert b"Order Intake Review" in response.data
    assert b"Shipping Handoff" in response.data
    assert b"Inventory Attention" in response.data
    assert b"Orders awaiting intake review" in response.data
    assert b"Orders ready for shipping handoff" in response.data
    assert b"Inventory items needing attention" in response.data


def test_index_surfaces_live_and_empty_operational_states(
    client, admin_user, app, login
):
    login(client)

    empty_response = client.get("/")

    assert empty_response.status_code == 200
    assert b"No orders are currently waiting for intake review." in empty_response.data
    assert b"No orders are currently ready for shipping handoff." in empty_response.data
    assert b"No inventory items currently need attention." in empty_response.data

    with app.app_context():
        customer = Customer(
            first_name="Taylor",
            last_name="Customer",
            email="taylor.tasks@shynebeauty.com",
            country="USA",
        )
        placed_product = Product(
            name="Glow Balm",
            sku="GB-TASKS-001",
            price=Decimal("24.50"),
            active=True,
            reorder_threshold=5,
        )
        ready_product = Product(
            name="Body Butter",
            sku="BB-TASKS-001",
            price=Decimal("18.00"),
            active=True,
            reorder_threshold=4,
        )
        low_stock_item = Ingredient(
            name="Shea Butter Tasks",
            stock_quantity=Decimal("3.000"),
            reorder_threshold=Decimal("5.000"),
            unit="lb",
            supplier_name="Butter Supply Co.",
        )
        out_of_stock_item = Ingredient(
            name="Fragrance Oil Tasks",
            stock_quantity=Decimal("0.000"),
            reorder_threshold=Decimal("2.000"),
            unit="oz",
            supplier_name="Aroma House",
        )
        db.session.add_all(
            [customer, placed_product, ready_product, low_stock_item, out_of_stock_item]
        )
        db.session.flush()

        placed_order = Order(
            customer_id=customer.id,
            order_number="ORD-TASKS-PLACED",
            platform="Direct",
            total_amount=Decimal("24.50"),
            status="Placed",
            placed_at=datetime(2026, 4, 14, tzinfo=timezone.utc),
        )
        ready_order = Order(
            customer_id=customer.id,
            order_number="ORD-TASKS-READY",
            platform="Square",
            total_amount=Decimal("18.00"),
            status="Ready",
            placed_at=datetime(2026, 4, 15, tzinfo=timezone.utc),
        )
        db.session.add_all([placed_order, ready_order])
        db.session.flush()

        db.session.add_all(
            [
                OrderItem(
                    order_id=placed_order.id,
                    product_id=placed_product.id,
                    quantity=1,
                    unit_price=Decimal("24.50"),
                ),
                OrderItem(
                    order_id=ready_order.id,
                    product_id=ready_product.id,
                    quantity=1,
                    unit_price=Decimal("18.00"),
                ),
                Shipment(
                    order_id=ready_order.id,
                    carrier="USPS",
                    tracking_number="9400111206210582999999",
                ),
            ]
        )
        db.session.commit()

    response = client.get("/")

    assert response.status_code == 200
    assert b"ORD-TASKS-PLACED" in response.data
    assert b"ORD-TASKS-READY" in response.data
    assert b"Glow Balm" in response.data
    assert b"Body Butter" in response.data
    assert b"USPS: 9400111206210582999999" in response.data
    assert b"Fragrance Oil Tasks" in response.data
    assert b"Shea Butter Tasks" in response.data
    assert b"Out of stock" in response.data
    assert b"Low stock" in response.data


def test_init_db_cli_command_creates_tables_and_reports_success(app):
    runner = app.test_cli_runner()
    result = runner.invoke(args=["init-db"])

    assert result.exit_code == 0
    assert "Database initialized and demo data reset." in result.output

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
        "must_change_password",
        "permission_overrides_json",
    }

    with app.app_context():
        seeded_users = {
            user.email: user for user in AdminUser.query.order_by(AdminUser.email).all()
        }
        assert set(seeded_users) == {
            "devadmin@demo.com",
            "inventoryproduction@demo.com",
            "staffoperator@demo.com",
            "superadmin@demo.com",
        }
        assert seeded_users["superadmin@demo.com"].get_role() == ROLE_SUPERADMIN
        assert seeded_users["staffoperator@demo.com"].get_role() == ROLE_STAFF_OPERATOR
        assert (
            seeded_users["inventoryproduction@demo.com"].get_role()
            == ROLE_INVENTORY_PRODUCTION
        )
        assert seeded_users["devadmin@demo.com"].get_role() == ROLE_DEV_ADMIN
        assert (
            seeded_users["superadmin@demo.com"].check_password("demo")
            is True
        )
        assert Customer.query.count() == 4
        assert Product.query.count() == 4
        assert Ingredient.query.count() == 5
        assert Batch.query.count() == 2
        assert ProductBatch.query.count() == 3
        assert Order.query.count() == 4
        assert OrderItem.query.count() == 6
        assert OrderStatusEvent.query.count() == 4
        assert Shipment.query.count() == 2
        assert AdminAccessEvent.query.count() == 4


def test_init_db_cli_command_is_idempotent(app):
    runner = app.test_cli_runner()

    first_result = runner.invoke(args=["init-db"])
    second_result = runner.invoke(args=["init-db"])

    assert first_result.exit_code == 0
    assert second_result.exit_code == 0
    assert "Database initialized and demo data reset." in first_result.output
    assert "Database initialized and demo data reset." in second_result.output

    with app.app_context():
        assert AdminUser.query.count() == 4
        assert Customer.query.count() == 4
        assert Order.query.count() == 4


def test_init_db_cli_command_replaces_existing_auth_and_business_data(app):
    with app.app_context():
        legacy_user = AdminUser(
            email="legacy@shynebeauty.com",
            full_name="Legacy User",
        )
        legacy_user.set_password("legacy-password")
        legacy_user.set_role(ROLE_SUPERADMIN, now=datetime.now(timezone.utc))
        legacy_user.set_account_status(ACCOUNT_STATUS_ACTIVE, now=datetime.now(timezone.utc))
        legacy_customer = Customer(
            first_name="Legacy",
            last_name="Customer",
            email="legacy.customer@example.com",
        )
        db.session.add_all([legacy_user, legacy_customer])
        db.session.commit()

    runner = app.test_cli_runner()
    result = runner.invoke(args=["init-db"])

    assert result.exit_code == 0

    with app.app_context():
        assert AdminUser.query.filter_by(email="legacy@shynebeauty.com").count() == 0
        assert Customer.query.filter_by(email="legacy.customer@example.com").count() == 0
        assert AdminUser.query.count() == 4
        assert Customer.query.count() == 4


def test_init_live_db_cli_command_creates_schema_without_demo_data(app):
    runner = app.test_cli_runner()

    result = runner.invoke(args=["init-live-db"])

    assert result.exit_code == 0
    assert "without demo data" in result.output

    with app.app_context():
        assert AdminUser.query.count() == 0
        assert Customer.query.count() == 0
        inspector = inspect(db.engines["auth"])
        assert "admin_users" in inspector.get_table_names()
        assert "admin_login_throttles" in inspector.get_table_names()


def test_init_db_cli_command_refuses_live_runtime_targets(app):
    runner = app.test_cli_runner()
    live_defaults = app.config["RUNTIME_DEFAULT_DATABASES"][APP_RUNTIME_LIVE_PROD]
    app.config["APP_RUNTIME"] = APP_RUNTIME_LIVE_PROD
    app.config["SQLALCHEMY_DATABASE_URI"] = live_defaults["primary"]
    app.config["SQLALCHEMY_BINDS"][AUTH_BIND_KEY] = live_defaults["auth"]

    result = runner.invoke(args=["init-db"])

    assert result.exit_code != 0
    assert "init-db only supports demo-dev targets" in result.output


def test_init_db_targets_live_data_detects_live_runtime_or_live_defaults(app):
    original_runtime = app.config["APP_RUNTIME"]
    original_primary = app.config["SQLALCHEMY_DATABASE_URI"]
    original_auth = app.config["SQLALCHEMY_BINDS"][AUTH_BIND_KEY]
    live_defaults = app.config["RUNTIME_DEFAULT_DATABASES"][APP_RUNTIME_LIVE_PROD]

    try:
        app.config["APP_RUNTIME"] = APP_RUNTIME_LIVE_PROD
        assert init_db_targets_live_data() is True

        app.config["APP_RUNTIME"] = APP_RUNTIME_DEMO_DEV
        app.config["SQLALCHEMY_DATABASE_URI"] = live_defaults["primary"]
        app.config["SQLALCHEMY_BINDS"][AUTH_BIND_KEY] = live_defaults["auth"]
        assert init_db_targets_live_data() is True
    finally:
        app.config["APP_RUNTIME"] = original_runtime
        app.config["SQLALCHEMY_DATABASE_URI"] = original_primary
        app.config["SQLALCHEMY_BINDS"][AUTH_BIND_KEY] = original_auth


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


def test_create_admin_cli_command_allows_admin_identifier_now(app):
    runner = app.test_cli_runner()

    result = runner.invoke(
        args=["create-admin", "--email", "admin"],
        input="RootPassw0rd!\nRootPassw0rd!\n",
    )

    assert result.exit_code == 0
    assert "Admin user created: admin" in result.output

    with app.app_context():
        user = AdminUser.query.filter_by(email="admin").one()
        assert user.get_role() == ROLE_SUPERADMIN
        assert user.check_password("RootPassw0rd!") is True


def test_create_admin_cli_command_rejects_password_containing_email(app):
    runner = app.test_cli_runner()

    result = runner.invoke(
        args=["create-admin", "--email", "owner@shynebeauty.com"],
        input="OwnerSecure123!\nOwnerSecure123!\n",
    )

    assert result.exit_code != 0
    assert "cannot contain your email address" in result.output


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


def test_health_returns_ok(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ok"


def test_health_requires_no_authentication(client):
    # unauthenticated request must not redirect to login
    response = client.get("/health")
    assert response.status_code == 200


def test_export_data_command_creates_archive(app):
    import hashlib
    import tarfile
    import tempfile
    from pathlib import Path
    from click.testing import CliRunner
    from shyne_app.cli import export_data_command

    with tempfile.TemporaryDirectory() as tmpdir:
        runner = CliRunner()
        with app.app_context():
            result = runner.invoke(export_data_command, ["--output-dir", tmpdir])
        assert result.exit_code == 0, result.output
        archives = list(Path(tmpdir).glob("shynebeauty-backup-*.tar.gz"))
        assert len(archives) == 1, f"Expected one archive, got: {archives}"
        hashes = list(Path(tmpdir).glob("*.sha256"))
        assert len(hashes) == 1, f"Expected one hash file, got: {hashes}"
        sha256 = hashlib.sha256()
        with open(archives[0], "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        hash_line = hashes[0].read_text(encoding="utf-8").strip()
        assert hash_line.startswith(sha256.hexdigest())
