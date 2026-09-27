"""Health endpoints (no authentication).

/health     liveness; never touches the database.
/health/db  runs SELECT 1 through each account's engine. Reports only ok /
            unavailable per connection: no host, user, version or error text.
"""

import logging
from collections.abc import Callable
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import Engine, text
from sqlalchemy.exc import SQLAlchemyError

from app import __version__
from app.config import ConfigurationError
from app.db.session import Database, get_database

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])

CheckStatus = Literal["ok", "unavailable"]


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    environment: str


class DatabaseChecks(BaseModel):
    app: CheckStatus
    reader: CheckStatus


class DatabaseHealthResponse(BaseModel):
    status: CheckStatus
    checks: DatabaseChecks


@router.get("/health", response_model=HealthResponse)
def health(request: Request) -> HealthResponse:
    return HealthResponse(
        status="ok",
        service="askq-backend",
        version=__version__,
        environment=request.app.state.settings.app_env,
    )


def _ping(name: str, get_engine: Callable[[], Engine]) -> CheckStatus:
    """SELECT 1 on one engine. get_engine may raise ConfigurationError (password not set)."""
    try:
        with get_engine().connect() as connection:
            connection.execute(text("SELECT 1")).scalar_one()
        return "ok"
    except (ConfigurationError, SQLAlchemyError, OSError) as exc:
        logger.warning("database health check failed for %s: %s", name, type(exc).__name__)
        return "unavailable"


@router.get(
    "/health/db",
    response_model=DatabaseHealthResponse,
    responses={503: {"model": DatabaseHealthResponse}},
)
def health_db(database: Annotated[Database, Depends(get_database)]) -> JSONResponse:
    checks = DatabaseChecks(
        app=_ping("app", lambda: database.app_engine),
        reader=_ping("reader", lambda: database.reader_engine),
    )
    ok = checks.app == "ok" and checks.reader == "ok"
    body = DatabaseHealthResponse(status="ok" if ok else "unavailable", checks=checks)
    return JSONResponse(body.model_dump(), status_code=200 if ok else 503)
