import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Path, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from starlette.responses import JSONResponse

# -----------------------------------------------------------------------------
# App metadata and OpenAPI tags
# -----------------------------------------------------------------------------

openapi_tags = [
    {"name": "health", "description": "Service health and metadata"},
    {"name": "admin-dashboard", "description": "Admin dashboard overview and platform health"},
    {"name": "admin-users", "description": "Administrative endpoints for user management"},
    {"name": "admin-events", "description": "Administrative endpoints for event management"},
    {"name": "admin-venues", "description": "Administrative endpoints for venue management"},
    {"name": "admin-config", "description": "System configuration management"},
    {"name": "admin-analytics", "description": "Platform analytics and reports"},
    {"name": "admin-compliance", "description": "Compliance checks and reports"},
    {"name": "admin-audit", "description": "Audit logs and administrative activity"},
]

app = FastAPI(
    title="Admin Service",
    description=(
        "Comprehensive admin, analytics, compliance, and configuration API for the Event Platform. "
        "This demo implements in-memory stubs and RBAC placeholders suitable for integration via API Gateway."
    ),
    version="0.1.0",
    openapi_tags=openapi_tags,
)

# -----------------------------------------------------------------------------
# CORS
# -----------------------------------------------------------------------------

allowed_origins = os.getenv("CORS_ALLOW_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------------------------------
# Security and RBAC placeholders
# -----------------------------------------------------------------------------

class AdminIdentity(BaseModel):
    user_id: str = Field(..., description="Admin user ID")
    roles: List[str] = Field(default_factory=list, description="Assigned roles")

# PUBLIC_INTERFACE
def require_admin(
    x_user_id: Optional[str] = Header(default=None, alias="x-user-id"),
    x_user_roles: Optional[str] = Header(default=None, alias="x-user-roles"),
) -> AdminIdentity:
    """
    This is a public function.
    RBAC dependency placeholder. In production, this would verify a JWT or session via the API Gateway,
    then enforce that the caller has an 'admin' role (or equivalent permission).
    """
    # Minimal placeholder logic using headers for role assertion.
    # Expected format: x-user-roles: "admin,organizer"
    roles = [r.strip() for r in (x_user_roles or "").split(",") if r.strip()]
    if "admin" not in roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    if not x_user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing user identity")
    return AdminIdentity(user_id=x_user_id, roles=roles)

# -----------------------------------------------------------------------------
# Pydantic models for public API
# -----------------------------------------------------------------------------

class Profile(BaseModel):
    first_name: str = Field("", description="First name")
    last_name: str = Field("", description="Last name")
    bio: str = Field("", description="Short biography or description")
    avatar_url: str = Field("", description="URL to profile avatar")
    phone: str = Field("", description="Phone number in E.164 if possible")

class UserPublic(BaseModel):
    id: str = Field(..., description="User ID")
    email: str = Field(..., description="User email")
    roles: List[str] = Field(default_factory=list, description="Assigned roles")
    is_active: bool = Field(..., description="Is the user active")
    is_verified: bool = Field(..., description="Has the user's email been verified")
    profile: Optional[Profile] = Field(default=None, description="User profile")

class RoleUpdate(BaseModel):
    roles: List[Literal["attendee", "organizer", "admin"]] = Field(..., description="List of roles to assign")

class SystemSetting(BaseModel):
    key: str = Field(..., description="Setting key")
    value: Any = Field(..., description="Setting value")
    description: Optional[str] = Field(default=None, description="Optional description")

class SystemSettingsUpsert(BaseModel):
    settings: List[SystemSetting] = Field(..., description="List of settings to upsert")

class EventPublic(BaseModel):
    id: str = Field(..., description="Event ID")
    title: str = Field(..., description="Event title")
    status: Literal["draft", "published", "archived"] = Field(..., description="Event status")
    organizer_id: str = Field(..., description="Organizer user id")
    starts_at: Optional[datetime] = Field(default=None, description="Start datetime")
    ends_at: Optional[datetime] = Field(default=None, description="End datetime")

class VenuePublic(BaseModel):
    id: str = Field(..., description="Venue ID")
    name: str = Field(..., description="Venue name")
    city: str = Field(..., description="City")
    country: str = Field(..., description="Country")
    capacity: int = Field(..., description="Capacity")

class DashboardSummary(BaseModel):
    users_total: int = Field(..., description="Total registered users")
    events_total: int = Field(..., description="Total events")
    venues_total: int = Field(..., description="Total venues")
    bookings_total: int = Field(..., description="Total bookings")
    revenue_total: float = Field(..., description="Total revenue (stub)")

class PlatformHealth(BaseModel):
    status: Literal["healthy", "degraded", "down"] = Field(..., description="Overall platform status")
    components: Dict[str, Literal["healthy", "degraded", "down"]] = Field(..., description="Component status map")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Status timestamp")

class AnalyticsSummary(BaseModel):
    period: Literal["24h", "7d", "30d"] = Field(..., description="Aggregation period")
    new_users: int = Field(..., description="New registered users in period")
    tickets_sold: int = Field(..., description="Tickets sold")
    revenue: float = Field(..., description="Revenue for the period")

class ComplianceReport(BaseModel):
    report_id: str = Field(..., description="Report id")
    generated_at: datetime = Field(..., description="Report generation time")
    scope: Literal["gdpr", "pci", "soc2"] = Field(..., description="Compliance scope")
    passed: bool = Field(..., description="Overall compliance result")
    findings: List[str] = Field(default_factory=list, description="List of notable findings")

class AuditLogEntry(BaseModel):
    id: str = Field(..., description="Audit entry id")
    actor_id: str = Field(..., description="Admin/user id who performed the action")
    action: str = Field(..., description="Action performed")
    target: str = Field(..., description="Target entity, e.g., user:123")
    timestamp: datetime = Field(..., description="When the action happened")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional details")

# -----------------------------------------------------------------------------
# In-memory demo stores (stubs for demo purposes)
# -----------------------------------------------------------------------------

_FAKE_USERS: Dict[str, UserPublic] = {
    "u1": UserPublic(
        id="u1",
        email="admin@example.com",
        roles=["admin"],
        is_active=True,
        is_verified=True,
        profile=Profile(first_name="Ada", last_name="Admin"),
    ),
    "u2": UserPublic(
        id="u2",
        email="org@example.com",
        roles=["organizer"],
        is_active=True,
        is_verified=True,
        profile=Profile(first_name="Owen", last_name="Organizer"),
    ),
    "u3": UserPublic(
        id="u3",
        email="attendee@example.com",
        roles=["attendee"],
        is_active=True,
        is_verified=False,
        profile=Profile(first_name="Allie", last_name="Attendee"),
    ),
}

_FAKE_EVENTS: Dict[str, EventPublic] = {
    "e1": EventPublic(id="e1", title="Tech Conf 2025", status="published", organizer_id="u2"),
    "e2": EventPublic(id="e2", title="Music Fest", status="draft", organizer_id="u2"),
}

_FAKE_VENUES: Dict[str, VenuePublic] = {
    "v1": VenuePublic(id="v1", name="Grand Hall", city="Berlin", country="DE", capacity=5000),
    "v2": VenuePublic(id="v2", name="Open Arena", city="Austin", country="US", capacity=12000),
}

_FAKE_SETTINGS: Dict[str, SystemSetting] = {
    "booking.maxSeatsPerOrder": SystemSetting(
        key="booking.maxSeatsPerOrder", value=10, description="Max seats per booking"
    ),
    "security.passwordMinLength": SystemSetting(
        key="security.passwordMinLength", value=8, description="Minimum password length"
    ),
}

_FAKE_AUDIT: List[AuditLogEntry] = []

# Helper to add audit entries
def _audit(actor_id: str, action: str, target: str, metadata: Optional[Dict[str, Any]] = None) -> None:
    entry = AuditLogEntry(
        id=f"a{len(_FAKE_AUDIT)+1}",
        actor_id=actor_id,
        action=action,
        target=target,
        timestamp=datetime.utcnow(),
        metadata=metadata or {},
    )
    _FAKE_AUDIT.append(entry)

# -----------------------------------------------------------------------------
# Health and Docs
# -----------------------------------------------------------------------------

@app.get("/", tags=["health"], summary="Health check", description="Simple health check endpoint.")
def health_check() -> Dict[str, str]:
    """
    Health check endpoint for Admin Service.
    Returns {"message": "Healthy"} when service is running.
    """
    return {"message": "Healthy"}

# PUBLIC_INTERFACE
@app.get(
    "/docs/websocket-usage",
    tags=["health"],
    summary="WebSocket usage notes",
    description="This service currently does not expose WebSockets. This endpoint documents future real-time features.",
)
def websocket_usage_note() -> Dict[str, str]:
    """This is a public function.
    Returns a short note indicating no current WebSocket endpoints are exposed for the AdminService.
    """
    return {
        "message": "AdminService does not expose WebSockets in this demo. Reserved for future real-time admin monitoring."
    }

# -----------------------------------------------------------------------------
# Admin Dashboard and Platform Health
# -----------------------------------------------------------------------------

# PUBLIC_INTERFACE
@app.get(
    "/admin/dashboard/summary",
    tags=["admin-dashboard"],
    summary="Dashboard summary",
    description="Returns high-level totals for entities in the platform for admin overview.",
    response_model=DashboardSummary,
    responses={200: {"description": "Summary totals for dashboard"}},
)
def admin_dashboard_summary(_: AdminIdentity = Depends(require_admin)) -> DashboardSummary:
    """This is a public function.
    Provides a summarized view for admins. Values are stubbed from in-memory stores.
    """
    # These totals would normally be fetched from respective services or a data warehouse.
    return DashboardSummary(
        users_total=len(_FAKE_USERS),
        events_total=len(_FAKE_EVENTS),
        venues_total=len(_FAKE_VENUES),
        bookings_total=1234,  # stub
        revenue_total=98765.43,  # stub
    )

# PUBLIC_INTERFACE
@app.get(
    "/admin/dashboard/health",
    tags=["admin-dashboard"],
    summary="Platform health",
    description="Overall platform/component health snapshot suitable for an admin dashboard.",
    response_model=PlatformHealth,
)
def platform_health(_: AdminIdentity = Depends(require_admin)) -> PlatformHealth:
    """This is a public function.
    Returns a basic health snapshot. In production, aggregate health from all services.
    """
    components = {
        "UserService": "healthy",
        "EventService": "healthy",
        "VenueService": "healthy",
        "BookingService": "healthy",
        "NotificationService": "degraded",
        "AdminService": "healthy",
    }
    status_overall: Literal["healthy", "degraded", "down"] = "healthy"
    if "down" in components.values():
        status_overall = "down"
    elif "degraded" in components.values():
        status_overall = "degraded"
    return PlatformHealth(status=status_overall, components=components)

# -----------------------------------------------------------------------------
# Admin: Manage Users
# -----------------------------------------------------------------------------

# PUBLIC_INTERFACE
@app.get(
    "/admin/users",
    tags=["admin-users"],
    summary="List users",
    description="List all users (admin only).",
    response_model=List[UserPublic],
)
def admin_list_users(_: AdminIdentity = Depends(require_admin)) -> List[UserPublic]:
    """This is a public function.
    Returns list of users from the in-memory store.
    """
    return list(_FAKE_USERS.values())

# PUBLIC_INTERFACE
@app.get(
    "/admin/users/{user_id}",
    tags=["admin-users"],
    summary="Get a user",
    description="Retrieve a user by ID (admin only).",
    response_model=UserPublic,
)
def admin_get_user(
    user_id: str = Path(..., description="User ID"),
    _: AdminIdentity = Depends(require_admin),
) -> UserPublic:
    """This is a public function."""
    user = _FAKE_USERS.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# PUBLIC_INTERFACE
@app.put(
    "/admin/users/{user_id}/roles",
    tags=["admin-users"],
    summary="Update user roles",
    description="Assign roles to a user (admin only). Allowed roles: attendee, organizer, admin.",
    response_model=UserPublic,
)
def admin_update_roles(
    user_id: str = Path(..., description="User ID"),
    body: RoleUpdate = ...,
    admin: AdminIdentity = Depends(require_admin),
) -> UserPublic:
    """This is a public function."""
    user = _FAKE_USERS.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    updated = user.model_copy(update={"roles": body.roles})
    _FAKE_USERS[user_id] = updated
    _audit(actor_id=admin.user_id, action="update_roles", target=f"user:{user_id}", metadata={"roles": body.roles})
    return updated

# PUBLIC_INTERFACE
@app.delete(
    "/admin/users/{user_id}",
    tags=["admin-users"],
    summary="Delete user",
    description="Delete a user account (admin only).",
)
def admin_delete_user(
    user_id: str = Path(..., description="User ID"),
    admin: AdminIdentity = Depends(require_admin),
) -> JSONResponse:
    """This is a public function."""
    if user_id not in _FAKE_USERS:
        raise HTTPException(status_code=404, detail="User not found")
    del _FAKE_USERS[user_id]
    _audit(actor_id=admin.user_id, action="delete_user", target=f"user:{user_id}")
    return JSONResponse({"status": "deleted"}, status_code=200)

# -----------------------------------------------------------------------------
# Admin: Manage Events
# -----------------------------------------------------------------------------

class EventUpdate(BaseModel):
    title: Optional[str] = Field(default=None, description="Event title")
    status: Optional[Literal["draft", "published", "archived"]] = Field(default=None, description="Status")

# PUBLIC_INTERFACE
@app.get(
    "/admin/events",
    tags=["admin-events"],
    summary="List events",
    description="List all events (admin only).",
    response_model=List[EventPublic],
)
def admin_list_events(_: AdminIdentity = Depends(require_admin)) -> List[EventPublic]:
    """This is a public function."""
    return list(_FAKE_EVENTS.values())

# PUBLIC_INTERFACE
@app.get(
    "/admin/events/{event_id}",
    tags=["admin-events"],
    summary="Get event",
    description="Retrieve a single event.",
    response_model=EventPublic,
)
def admin_get_event(
    event_id: str = Path(..., description="Event ID"),
    _: AdminIdentity = Depends(require_admin),
) -> EventPublic:
    """This is a public function."""
    ev = _FAKE_EVENTS.get(event_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Event not found")
    return ev

# PUBLIC_INTERFACE
@app.put(
    "/admin/events/{event_id}",
    tags=["admin-events"],
    summary="Update event",
    description="Update event fields.",
    response_model=EventPublic,
)
def admin_update_event(
    event_id: str = Path(..., description="Event ID"),
    body: EventUpdate = ...,
    admin: AdminIdentity = Depends(require_admin),
) -> EventPublic:
    """This is a public function."""
    ev = _FAKE_EVENTS.get(event_id)
    if not ev:
        raise HTTPException(status_code=404, detail="Event not found")
    updated = ev.model_copy(update=body.model_dump(exclude_unset=True))
    _FAKE_EVENTS[event_id] = updated
    _audit(actor_id=admin.user_id, action="update_event", target=f"event:{event_id}", metadata=body.model_dump())
    return updated

# PUBLIC_INTERFACE
@app.delete(
    "/admin/events/{event_id}",
    tags=["admin-events"],
    summary="Delete event",
    description="Delete an event.",
)
def admin_delete_event(
    event_id: str = Path(..., description="Event ID"),
    admin: AdminIdentity = Depends(require_admin),
) -> JSONResponse:
    """This is a public function."""
    if event_id not in _FAKE_EVENTS:
        raise HTTPException(status_code=404, detail="Event not found")
    del _FAKE_EVENTS[event_id]
    _audit(actor_id=admin.user_id, action="delete_event", target=f"event:{event_id}")
    return JSONResponse({"status": "deleted"}, status_code=200)

# -----------------------------------------------------------------------------
# Admin: Manage Venues
# -----------------------------------------------------------------------------

class VenueUpdate(BaseModel):
    name: Optional[str] = Field(default=None, description="Venue name")
    city: Optional[str] = Field(default=None, description="City")
    country: Optional[str] = Field(default=None, description="Country")
    capacity: Optional[int] = Field(default=None, description="Capacity")

# PUBLIC_INTERFACE
@app.get(
    "/admin/venues",
    tags=["admin-venues"],
    summary="List venues",
    description="List all venues.",
    response_model=List[VenuePublic],
)
def admin_list_venues(_: AdminIdentity = Depends(require_admin)) -> List[VenuePublic]:
    """This is a public function."""
    return list(_FAKE_VENUES.values())

# PUBLIC_INTERFACE
@app.get(
    "/admin/venues/{venue_id}",
    tags=["admin-venues"],
    summary="Get venue",
    description="Retrieve a venue.",
    response_model=VenuePublic,
)
def admin_get_venue(
    venue_id: str = Path(..., description="Venue ID"),
    _: AdminIdentity = Depends(require_admin),
) -> VenuePublic:
    """This is a public function."""
    vn = _FAKE_VENUES.get(venue_id)
    if not vn:
        raise HTTPException(status_code=404, detail="Venue not found")
    return vn

# PUBLIC_INTERFACE
@app.put(
    "/admin/venues/{venue_id}",
    tags=["admin-venues"],
    summary="Update venue",
    description="Update venue details.",
    response_model=VenuePublic,
)
def admin_update_venue(
    venue_id: str = Path(..., description="Venue ID"),
    body: VenueUpdate = ...,
    admin: AdminIdentity = Depends(require_admin),
) -> VenuePublic:
    """This is a public function."""
    vn = _FAKE_VENUES.get(venue_id)
    if not vn:
        raise HTTPException(status_code=404, detail="Venue not found")
    updated = vn.model_copy(update=body.model_dump(exclude_unset=True))
    _FAKE_VENUES[venue_id] = updated
    _audit(actor_id=admin.user_id, action="update_venue", target=f"venue:{venue_id}", metadata=body.model_dump())
    return updated

# PUBLIC_INTERFACE
@app.delete(
    "/admin/venues/{venue_id}",
    tags=["admin-venues"],
    summary="Delete venue",
    description="Delete a venue.",
)
def admin_delete_venue(
    venue_id: str = Path(..., description="Venue ID"),
    admin: AdminIdentity = Depends(require_admin),
) -> JSONResponse:
    """This is a public function."""
    if venue_id not in _FAKE_VENUES:
        raise HTTPException(status_code=404, detail="Venue not found")
    del _FAKE_VENUES[venue_id]
    _audit(actor_id=admin.user_id, action="delete_venue", target=f"venue:{venue_id}")
    return JSONResponse({"status": "deleted"}, status_code=200)

# -----------------------------------------------------------------------------
# System Configuration
# -----------------------------------------------------------------------------

# PUBLIC_INTERFACE
@app.get(
    "/admin/config",
    tags=["admin-config"],
    summary="List system settings",
    description="Retrieve all system settings.",
    response_model=List[SystemSetting],
)
def list_system_settings(_: AdminIdentity = Depends(require_admin)) -> List[SystemSetting]:
    """This is a public function."""
    return list(_FAKE_SETTINGS.values())

# PUBLIC_INTERFACE
@app.put(
    "/admin/config",
    tags=["admin-config"],
    summary="Upsert system settings",
    description="Create or update multiple system settings.",
    response_model=List[SystemSetting],
)
def upsert_system_settings(
    body: SystemSettingsUpsert,
    admin: AdminIdentity = Depends(require_admin),
) -> List[SystemSetting]:
    """This is a public function."""
    for s in body.settings:
        _FAKE_SETTINGS[s.key] = s
        _audit(actor_id=admin.user_id, action="upsert_setting", target=f"setting:{s.key}", metadata={"value": s.value})
    return list(_FAKE_SETTINGS.values())

# PUBLIC_INTERFACE
@app.delete(
    "/admin/config/{key}",
    tags=["admin-config"],
    summary="Delete system setting",
    description="Delete a single system setting by key.",
)
def delete_system_setting(
    key: str = Path(..., description="Setting key"),
    admin: AdminIdentity = Depends(require_admin),
) -> JSONResponse:
    """This is a public function."""
    if key not in _FAKE_SETTINGS:
        raise HTTPException(status_code=404, detail="Setting not found")
    del _FAKE_SETTINGS[key]
    _audit(actor_id=admin.user_id, action="delete_setting", target=f"setting:{key}")
    return JSONResponse({"status": "deleted"}, status_code=200)

# -----------------------------------------------------------------------------
# Admin Analytics
# -----------------------------------------------------------------------------

# PUBLIC_INTERFACE
@app.get(
    "/admin/analytics/summary",
    tags=["admin-analytics"],
    summary="Analytics summary",
    description="High level analytics for a period.",
    response_model=AnalyticsSummary,
)
def analytics_summary(
    period: Literal["24h", "7d", "30d"] = Query("7d", description="Aggregation period"),
    _: AdminIdentity = Depends(require_admin),
) -> AnalyticsSummary:
    """This is a public function.
    Returns synthetic analytics. Replace with real aggregation from services/warehouse.
    """
    stub = {
        "24h": dict(new_users=12, tickets_sold=340, revenue=12345.67),
        "7d": dict(new_users=88, tickets_sold=2134, revenue=234567.89),
        "30d": dict(new_users=322, tickets_sold=9134, revenue=934567.12),
    }[period]
    return AnalyticsSummary(period=period, **stub)

# PUBLIC_INTERFACE
@app.get(
    "/admin/analytics/events/{event_id}",
    tags=["admin-analytics"],
    summary="Event analytics",
    description="Basic stats for a specific event.",
)
def event_analytics(
    event_id: str = Path(..., description="Event ID"),
    _: AdminIdentity = Depends(require_admin),
) -> Dict[str, Any]:
    """This is a public function."""
    if event_id not in _FAKE_EVENTS:
        raise HTTPException(status_code=404, detail="Event not found")
    # synthetic
    return {
        "event_id": event_id,
        "tickets_sold": 452,
        "revenue": 18954.25,
        "conversion_rate": 0.064,
        "updated_at": datetime.utcnow().isoformat(),
    }

# -----------------------------------------------------------------------------
# Compliance
# -----------------------------------------------------------------------------

# PUBLIC_INTERFACE
@app.post(
    "/admin/compliance/reports",
    tags=["admin-compliance"],
    summary="Generate compliance report",
    description="Generate a compliance report for gdpr, pci, or soc2 scopes.",
    response_model=ComplianceReport,
)
def generate_compliance_report(
    scope: Literal["gdpr", "pci", "soc2"] = Query(..., description="Compliance scope"),
    _: AdminIdentity = Depends(require_admin),
) -> ComplianceReport:
    """This is a public function.
    Returns a synthetic compliance report for demo purposes.
    """
    # basic synthetic signal
    passed = scope != "pci"
    findings = [] if passed else ["Weak cipher suites detected on legacy endpoint", "Missing quarterly ASV scan"]
    return ComplianceReport(
        report_id=f"r-{scope}-{int(datetime.utcnow().timestamp())}",
        generated_at=datetime.utcnow(),
        scope=scope,
        passed=passed,
        findings=findings,
    )

# PUBLIC_INTERFACE
@app.get(
    "/admin/compliance/policies",
    tags=["admin-compliance"],
    summary="List compliance policies",
    description="List platform compliance policies and versions.",
)
def list_policies(_: AdminIdentity = Depends(require_admin)) -> Dict[str, Any]:
    """This is a public function."""
    return {
        "policies": [
            {"name": "Privacy Policy", "version": "2025-01", "url": "https://example.com/privacy"},
            {"name": "Terms of Service", "version": "2025-01", "url": "https://example.com/terms"},
            {"name": "Data Retention", "version": "2024-10", "url": "https://example.com/retention"},
        ]
    }

# -----------------------------------------------------------------------------
# Audit Logs
# -----------------------------------------------------------------------------

# PUBLIC_INTERFACE
@app.get(
    "/admin/audit/logs",
    tags=["admin-audit"],
    summary="List audit logs",
    description="Paginated list of audit logs.",
    response_model=List[AuditLogEntry],
)
def list_audit_logs(
    limit: int = Query(50, ge=1, le=500, description="Max logs to return"),
    since_seconds: Optional[int] = Query(None, ge=1, description="Return entries since N seconds ago"),
    _: AdminIdentity = Depends(require_admin),
) -> List[AuditLogEntry]:
    """This is a public function."""
    entries = _FAKE_AUDIT[-limit:]
    if since_seconds:
        boundary = datetime.utcnow() - timedelta(seconds=since_seconds)
        entries = [e for e in entries if e.timestamp >= boundary]
    return entries
