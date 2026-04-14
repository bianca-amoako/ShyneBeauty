from decimal import Decimal

from shyne import (
    ACCOUNT_STATUS_ACTIVE,
    Product,
    ROLE_INVENTORY_PRODUCTION,
    ROLE_STAFF_OPERATOR,
    db,
)


def test_add_product_requires_production_edit_permission(
    client, admin_factory, login
):
    admin_factory(
        email="staff-operator@shynebeauty.com",
        full_name="Staff Operator",
        role=ROLE_STAFF_OPERATOR,
        account_status=ACCOUNT_STATUS_ACTIVE,
    )

    login(
        client,
        email="staff-operator@shynebeauty.com",
        password="correct-horse-battery-staple",
    )

    response = client.get("/add-product")

    assert response.status_code == 403
    assert b"Access denied" in response.data


def test_add_product_creates_product_and_redirects_to_confirmation(
    client, admin_factory, app, login
):
    admin_factory(
        email="inventory@shynebeauty.com",
        full_name="Inventory User",
        role=ROLE_INVENTORY_PRODUCTION,
        account_status=ACCOUNT_STATUS_ACTIVE,
    )

    login(
        client,
        email="inventory@shynebeauty.com",
        password="correct-horse-battery-staple",
    )

    response = client.post(
        "/add-product",
        data={
            "name": "Glow Balm",
            "sku": "GB-001",
            "status": "Active",
            "price": "24.50",
            "reorder_threshold": "5",
            "description": "Night repair balm",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/add-product?created=GB-001")

    with app.app_context():
        product = Product.query.filter_by(sku="GB-001").one()
        assert product.name == "Glow Balm"
        assert product.price == Decimal("24.50")
        assert product.active is True


def test_add_product_rejects_duplicate_sku(client, admin_factory, app, login):
    with app.app_context():
        db.session.add(
            Product(
                name="Glow Balm",
                sku="GB-001",
                price=Decimal("24.50"),
                active=True,
                reorder_threshold=5,
            )
        )
        db.session.commit()

    admin_factory(
        email="inventory@shynebeauty.com",
        full_name="Inventory User",
        role=ROLE_INVENTORY_PRODUCTION,
        account_status=ACCOUNT_STATUS_ACTIVE,
    )

    login(
        client,
        email="inventory@shynebeauty.com",
        password="correct-horse-battery-staple",
    )

    response = client.post(
        "/add-product",
        data={
            "name": "Glow Balm Copy",
            "sku": "gb-001",
            "status": "Active",
            "price": "24.50",
            "reorder_threshold": "5",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"A product with that SKU already exists." in response.data

    with app.app_context():
        assert Product.query.filter_by(sku="GB-001").count() == 1


def test_add_product_validates_numeric_fields(client, admin_factory, app, login):
    admin_factory(
        email="inventory@shynebeauty.com",
        full_name="Inventory User",
        role=ROLE_INVENTORY_PRODUCTION,
        account_status=ACCOUNT_STATUS_ACTIVE,
    )

    login(
        client,
        email="inventory@shynebeauty.com",
        password="correct-horse-battery-staple",
    )

    response = client.post(
        "/add-product",
        data={
            "name": "Glow Balm",
            "sku": "GB-001",
            "status": "Active",
            "price": "abc",
            "reorder_threshold": "-1",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Price must be a valid non-negative amount." in response.data
    assert b"Reorder threshold must be a non-negative whole number." in response.data

    with app.app_context():
        assert Product.query.count() == 0
