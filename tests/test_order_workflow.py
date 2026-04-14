from decimal import Decimal

from shyne import (
    ACCOUNT_STATUS_ACTIVE,
    Customer,
    Order,
    OrderItem,
    OrderStatusEvent,
    Product,
    ROLE_INVENTORY_PRODUCTION,
    Shipment,
    db,
)


def test_add_order_requires_order_edit_permission(client, admin_factory, login):
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

    response = client.get("/add-order")

    assert response.status_code == 403
    assert b"Access denied" in response.data


def test_add_order_creates_order_items_and_status_event(
    client, admin_user, app, login
):
    with app.app_context():
        customer = Customer(
            first_name="Taylor",
            last_name="Customer",
            email="taylor@shynebeauty.com",
            country="USA",
        )
        product = Product(
            name="Glow Balm",
            sku="GB-001",
            price=Decimal("24.50"),
            active=True,
            reorder_threshold=5,
        )
        db.session.add_all([customer, product])
        db.session.commit()
        customer_id = customer.id
        product_id = product.id

    login(client)

    response = client.post(
        "/add-order",
        data={
            "order_number": "ORD-1001",
            "customer_id": str(customer_id),
            "platform": "Direct",
            "status": "Placed",
            "placed_at": "2026-04-13",
            "product_id": [str(product_id)],
            "quantity": ["2"],
            "unit_price": ["24.50"],
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/orders?search=ORD-1001")

    with app.app_context():
        order = Order.query.filter_by(order_number="ORD-1001").one()
        assert order.customer_id == customer_id
        assert order.total_amount == Decimal("49.00")
        assert order.platform == "Direct"
        assert order.status == "Placed"

        order_items = OrderItem.query.filter_by(order_id=order.id).all()
        assert len(order_items) == 1
        assert order_items[0].product_id == product_id
        assert order_items[0].quantity == 2
        assert order_items[0].unit_price == Decimal("24.50")

        status_event = OrderStatusEvent.query.filter_by(order_id=order.id).one()
        assert status_event.event_status == "Placed"
        assert Shipment.query.filter_by(order_id=order.id).count() == 0


def test_add_order_rejects_duplicate_order_number(client, admin_user, app, login):
    with app.app_context():
        customer = Customer(
            first_name="Taylor",
            last_name="Customer",
            email="taylor@shynebeauty.com",
            country="USA",
        )
        product = Product(
            name="Glow Balm",
            sku="GB-001",
            price=Decimal("24.50"),
            active=True,
            reorder_threshold=5,
        )
        order = Order(
            customer=customer,
            order_number="ORD-1001",
            platform="Direct",
            total_amount=Decimal("24.50"),
            status="Placed",
        )
        db.session.add_all([customer, product, order])
        db.session.commit()
        customer_id = customer.id
        product_id = product.id

    login(client)

    response = client.post(
        "/add-order",
        data={
            "order_number": "ord-1001",
            "customer_id": str(customer_id),
            "platform": "Direct",
            "status": "Placed",
            "placed_at": "2026-04-13",
            "product_id": [str(product_id)],
            "quantity": ["1"],
            "unit_price": ["24.50"],
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"An order with that number already exists." in response.data


def test_add_order_requires_at_least_one_valid_line_item(
    client, admin_user, app, login
):
    with app.app_context():
        customer = Customer(
            first_name="Taylor",
            last_name="Customer",
            email="taylor@shynebeauty.com",
            country="USA",
        )
        db.session.add(customer)
        db.session.commit()
        customer_id = customer.id

    login(client)

    response = client.post(
        "/add-order",
        data={
            "order_number": "ORD-1001",
            "customer_id": str(customer_id),
            "platform": "Direct",
            "status": "Placed",
            "placed_at": "2026-04-13",
            "product_id": [""],
            "quantity": [""],
            "unit_price": [""],
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Add at least one line item." in response.data


def test_add_order_validates_line_item_values(client, admin_user, app, login):
    with app.app_context():
        customer = Customer(
            first_name="Taylor",
            last_name="Customer",
            email="taylor@shynebeauty.com",
            country="USA",
        )
        product = Product(
            name="Glow Balm",
            sku="GB-001",
            price=Decimal("24.50"),
            active=True,
            reorder_threshold=5,
        )
        db.session.add_all([customer, product])
        db.session.commit()
        customer_id = customer.id
        product_id = product.id

    login(client)

    response = client.post(
        "/add-order",
        data={
            "order_number": "ORD-1001",
            "customer_id": str(customer_id),
            "platform": "Direct",
            "status": "Placed",
            "placed_at": "2026-04-13",
            "product_id": [str(product_id)],
            "quantity": ["0"],
            "unit_price": ["abc"],
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Line item 1 quantity must be a positive whole number." in response.data
    assert b"Line item 1 price must be a valid non-negative amount." in response.data
