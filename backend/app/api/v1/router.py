"""Aggregates all v1 routers under a single APIRouter."""
from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import (
    ai,
    assets,
    auth,
    detection,
    findings,
    governance,
    insights,
    organizations,
    projects,
    scans,
    users,
)

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(organizations.router)
api_router.include_router(projects.router)
api_router.include_router(assets.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(detection.router)
api_router.include_router(insights.router)
api_router.include_router(governance.router)
api_router.include_router(ai.router)
