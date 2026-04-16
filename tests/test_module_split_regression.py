from shyne import AdminUser, app, db


def test_shyne_facade_exports_core_objects():
    assert app is not None
    assert db is not None
    assert AdminUser.__name__ == "AdminUser"


def test_shyne_facade_keeps_core_routes_and_cli_commands():
    routes = {rule.rule for rule in app.url_map.iter_rules()}

    assert "/" in routes
    assert "/login" in routes
    assert "/orders" in routes
    assert "/users" in routes

    assert "init-db" in app.cli.commands
    assert "init-live-db" in app.cli.commands
    assert "create-admin" in app.cli.commands
    assert "create-dev-admin" in app.cli.commands
    assert "backfill-admin-access" in app.cli.commands
    assert "export-data" in app.cli.commands
