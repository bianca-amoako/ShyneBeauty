from shyne import ACCOUNT_STATUS_ACTIVE, ROLE_INVENTORY_PRODUCTION, Customer, db


def test_add_customer_requires_customer_edit_permission(
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

    response = client.get("/add-customer")

    assert response.status_code == 403
    assert b"Access denied" in response.data


def test_add_customer_creates_customer_record(client, admin_user, app, login):
    login(client)

    response = client.post(
        "/add-customer",
        data={
            "first_name": "Taylor",
            "last_name": "Customer",
            "source": "Manual Entry",
            "email": "taylor@shynebeauty.com",
            "phone": "555-111-2222",
            "country": "USA",
            "street_address": "123 Glow Ave",
            "city": "Atlanta",
            "state": "GA",
            "postal_code": "30303",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith(
        "/customers?search=taylor@shynebeauty.com"
    )

    with app.app_context():
        customer = Customer.query.filter_by(email="taylor@shynebeauty.com").one()
        assert customer.first_name == "Taylor"
        assert customer.last_name == "Customer"
        assert customer.source == "Manual Entry"
        assert customer.city == "Atlanta"


def test_add_customer_rejects_duplicate_email(client, admin_user, app, login):
    with app.app_context():
        existing_customer = Customer(
            first_name="Existing",
            last_name="Customer",
            email="existing@shynebeauty.com",
            country="USA",
        )
        db.session.add(existing_customer)
        db.session.commit()

    login(client)

    response = client.post(
        "/add-customer",
        data={
            "first_name": "Taylor",
            "last_name": "Customer",
            "source": "Manual Entry",
            "email": "Existing@ShyneBeauty.com",
            "country": "USA",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"A customer with that email already exists." in response.data
    assert b'value="existing@shynebeauty.com"' in response.data

    with app.app_context():
        assert Customer.query.filter_by(email="existing@shynebeauty.com").count() == 1


def test_add_customer_validates_required_fields(client, admin_user, app, login):
    login(client)

    response = client.post(
        "/add-customer",
        data={
            "first_name": "",
            "last_name": "",
            "email": "",
            "country": "USA",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"First name is required." in response.data
    assert b"Last name is required." in response.data
    assert b"Email is required." in response.data

    with app.app_context():
        assert Customer.query.count() == 0
