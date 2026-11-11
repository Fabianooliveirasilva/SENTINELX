"""Aggregates all v1 routers under the /api/v1 prefix."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.endpoints import health

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
