"""API routers, grouped by resource."""

from app.api.routers import admin, analytics, health, jobs, logs, reports

__all__ = ["admin", "analytics", "health", "jobs", "logs", "reports"]
