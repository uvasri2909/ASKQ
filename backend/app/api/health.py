"""Liveness endpoint. Does not touch the database (DB checks arrive in Phase 3)."""

from fastapi import APIRouter
from pydantic import BaseModel

from app import __version__
from app.config import get_settings

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    environment: str


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        service="askq-backend",
        version=__version__,
        environment=get_settings().app_env,
    )
