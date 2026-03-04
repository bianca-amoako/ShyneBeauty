from shyne import MODEL_REGISTRY

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
