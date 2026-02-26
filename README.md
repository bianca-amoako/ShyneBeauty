# ShyneBeauty

ShyneBeauty is a Flask-based web application for managing a small skincare business.  
The project goal is to replace fragmented spreadsheet/marketplace workflows with one system for customer data, order lifecycle, inventory, and production batches.

## Current Status

- Current runnable code is an early Flask scaffold (`shyne.py`) with a rendered dashboard template.
- Most business functionality is defined in the project documentation and is still being implemented.


## Project Goals

- Centralize customer, order, and inventory data.
- Track ingredient usage and production batches.
- Give customers simple order-status visibility.
- Reduce manual errors in a single-owner workflow.
- Keep the admin workflow straightforward and fast.

## Planned Functional Areas

- Product catalog management
- Ingredient inventory tracking
- Batch production and finished-goods tracking
- Order fulfillment and shipment tracking
- Order status timeline events for customers
- Reporting for sales, inventory, and production

## Technical Requirements

### Python

- Python `3.10+` recommended

### Flask Requirements

Flask is the web framework for routing and template rendering.

- Route handlers for admin and customer-facing pages
- Jinja template rendering (`render_template`)
- Environment-based config for development/production
- Form/API validation and error handling

### SQL Requirements

A relational SQL database is required to keep business data consistent and queryable.

- Core entities: `Customer`, `Order`, `OrderItem`, `Product`, `Ingredient`, `Batch`, `BatchIngredient`, `ProductBatch`, `Shipment`, `OrderStatusEvent`
- Primary and foreign keys for traceability across ordering and production
- Indexed lookup paths for common queries (orders, status, inventory levels)
- Transaction-safe updates when fulfillment changes order + inventory together
- Backup and restore procedures for reliability

### SQLAlchemy Requirements

SQLAlchemy is the planned data access layer.

- ORM models for each core table
- Explicit relationships (for example: `Customer -> Order -> OrderItem`)
- Session/transaction handling for atomic updates
- Schema migration workflow (Alembic/Flask-Migrate recommended)

## Local Setup

1. Create and activate a virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the app:

```bash
python shyne.py
```

4. Open: `http://localhost:8000`

## Repository Layout

- `shyne.py` - Flask application entry point
- `templates/index.html` - current dashboard template
