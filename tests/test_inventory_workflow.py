from decimal import Decimal

from sqlalchemy import func

from shyne import (
    ACCOUNT_STATUS_ACTIVE,
    Ingredient,
    ROLE_INVENTORY_PRODUCTION,
    ROLE_STAFF_OPERATOR,
    db,
)


def test_add_inventory_requires_inventory_edit_permission(
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

    response = client.get("/add-inventory")

    assert response.status_code == 403
    assert b"Access denied" in response.data


def test_add_inventory_creates_ingredient_record(client, admin_factory, app, login):
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
        "/add-inventory",
        data={
            "name": "Shea Butter",
            "unit": "g",
            "stock_quantity": "125.500",
            "reorder_threshold": "25.000",
            "supplier_name": "Glow Supplier",
            "supplier_contact": "glow@example.com",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/inventory?search=Shea+Butter")

    with app.app_context():
        ingredient = Ingredient.query.filter_by(name="Shea Butter").one()
        assert ingredient.stock_quantity == Decimal("125.500")
        assert ingredient.reorder_threshold == Decimal("25.000")
        assert ingredient.supplier_name == "Glow Supplier"


def test_add_inventory_rejects_duplicate_name(client, admin_factory, app, login):
    with app.app_context():
        db.session.add(
            Ingredient(
                name="Shea Butter",
                unit="g",
                stock_quantity=Decimal("10.000"),
                reorder_threshold=Decimal("2.000"),
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
        "/add-inventory",
        data={
            "name": "shea butter",
            "unit": "g",
            "stock_quantity": "5",
            "reorder_threshold": "1",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"An inventory item with that name already exists." in response.data

    with app.app_context():
        assert Ingredient.query.filter(func.lower(Ingredient.name) == "shea butter").count() == 1


def test_add_inventory_rejects_invalid_numeric_values(
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
        "/add-inventory",
        data={
            "name": "Shea Butter",
            "unit": "g",
            "stock_quantity": "-1",
            "reorder_threshold": "abc",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Current stock cannot be negative." in response.data
    assert b"Reorder threshold must be a valid number." in response.data

    with app.app_context():
        assert Ingredient.query.count() == 0


def test_inventory_page_no_longer_exposes_category_filter(client, admin_user, login):
    login(client)

    response = client.get("/inventory")

    assert response.status_code == 200
    assert b"inventory-category" not in response.data
    assert b"Category" not in response.data
