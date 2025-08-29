# Admin Service

Comprehensive admin, analytics, compliance, and configuration API for the Event Booking Platform. This service exposes admin-focused endpoints for managing users/events/venues, system configuration, analytics dashboards, compliance, and audit logs.

Highlights:
- FastAPI with OpenAPI/Swagger docs at /docs when running
- RBAC placeholder: require 'admin' role via headers (demo)
- In-memory demo stores (no database yet)
- OpenAPI generation helper script included

Run (development):
- Install: pip install -r requirements.txt
- Start: uvicorn src.api.main:app --host 0.0.0.0 --port 8000
- Docs: http://localhost:8000/docs

Security / RBAC (placeholder):
- For demo, include headers to simulate an authenticated admin:
  - x-user-id: "u1"
  - x-user-roles: "admin"
- In production, integrate with API Gateway / UserService JWT and enforce roles centrally.

OpenAPI:
- Generate OpenAPI JSON file: python -m src.api.generate_openapi
- Output will be written to interfaces/openapi.json

Environment variables:
- See .env.example for available configuration.
