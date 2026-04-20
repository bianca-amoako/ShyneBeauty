"""Smoke test: every GET-only, non-parametric authenticated route returns 200.

Guards against silently-orphaned templates and broken `url_for` references
that the registration test (test_app.py::test_routes_are_registered) does
not catch — a route may be registered but still 500 on render.
"""

import pytest


AUTHENTICATED_GET_ROUTES = [
    "/",
    "/account/settings",
    "/orders",
    "/add-order",
    "/customers",
    "/add-customer",
    "/inventory",
    "/add-inventory",
    "/add-new",
    "/manage-products",
    "/add-product",
    "/product-batches",
    "/add-product-batch",
    "/users",
]


PUBLIC_GET_ROUTES = [
    "/login",
    "/health",
]


@pytest.mark.parametrize("path", PUBLIC_GET_ROUTES)
def test_public_routes_return_200(client, path):
    response = client.get(path)
    assert response.status_code == 200, (
        f"GET {path} returned {response.status_code}"
    )


@pytest.mark.parametrize("path", AUTHENTICATED_GET_ROUTES)
def test_authenticated_routes_return_200(client, admin_user, login, path):
    login(client)
    response = client.get(path)
    assert response.status_code == 200, (
        f"GET {path} returned {response.status_code} for authenticated admin"
    )


def test_all_template_files_are_rendered_somewhere(app):
    """Every .html template should be render_template()-ed by some route,
    OR be a layout/partial (base_*, _form_helpers) or an error page.
    """
    import re
    from pathlib import Path

    templates_dir = Path(app.root_path).parent / "templates"
    if not templates_dir.exists():
        templates_dir = Path(app.root_path) / "templates"
    all_templates = {p.name for p in templates_dir.glob("*.html")}

    # Partials, layouts, and error pages don't need a direct route.
    excluded = {
        "base_authenticated.html",
        "_form_helpers.html",
        "error.html",
        "access_denied.html",
    }

    source_files = [
        Path(app.root_path) / "routes.py",
        Path(app.root_path) / "auth.py",
        Path(app.root_path) / "admin.py",
        Path(app.root_path) / "access.py",
        Path(app.root_path) / "config.py",
    ]
    rendered = set()
    pattern = re.compile(r'render_template\(\s*["\']([A-Za-z0-9_./-]+\.html)["\']')
    for src in source_files:
        if src.exists():
            rendered.update(pattern.findall(src.read_text(encoding="utf-8")))

    unrendered = all_templates - rendered - excluded
    assert not unrendered, (
        f"Template files are never render_template()-ed: {sorted(unrendered)}. "
        "Either wire them up to a route, add to the excluded partials set, "
        "or delete them."
    )
