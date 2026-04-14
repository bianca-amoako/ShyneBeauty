from shyne import (
    ACCOUNT_STATUS_ACTIVE,
    ROLE_INVENTORY_PRODUCTION,
    ROLE_STAFF_OPERATOR,
)


def test_staff_operator_sees_only_allowed_add_cards(
    client, admin_factory, login
):
    admin_factory(
        email="staff@shynebeauty.com",
        full_name="Staff Operator",
        role=ROLE_STAFF_OPERATOR,
        account_status=ACCOUNT_STATUS_ACTIVE,
    )

    login(
        client,
        email="staff@shynebeauty.com",
        password="correct-horse-battery-staple",
    )

    response = client.get("/add-new")

    assert response.status_code == 200
    assert b"Add Customer" in response.data
    assert b"Add Order" in response.data
    assert b"Add Inventory Item" not in response.data
    assert b"Add Product" not in response.data


def test_inventory_production_sees_inventory_and_product_add_cards(
    client, admin_factory, login
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

    response = client.get("/add-new")

    assert response.status_code == 200
    assert b"Add Inventory Item" in response.data
    assert b"Add Product" in response.data
    assert b"Add Customer" not in response.data
    assert b"Add Order" not in response.data


def test_dev_admin_cannot_access_add_new_menu(client, dev_admin_user, login):
    login(
        client,
        email="devadmin@shynebeauty.com",
        password="correct-horse-battery-staple",
    )

    response = client.get("/add-new")

    assert response.status_code == 403
    assert b"Add workflows denied" in response.data


def test_dev_admin_sidebar_hides_add_workflows(client, dev_admin_user, login):
    login(
        client,
        email="devadmin@shynebeauty.com",
        password="correct-horse-battery-staple",
    )

    response = client.get("/")

    assert response.status_code == 200
    assert b"Add New" not in response.data
    assert b"Add Product" not in response.data
