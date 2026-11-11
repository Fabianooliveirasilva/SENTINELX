"""Aggregates all v1 routers under the /api/v1 prefix."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.endpoints import audit_logs, auth, health, projects, users

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(projects.router)
api_router.include_router(audit_logs.router)
