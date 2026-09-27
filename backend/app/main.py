"""FastAPI application entry point.

Run from the backend/ directory:
    .venv\\Scripts\\python -m uvicorn app.main:app --reload

create_app() takes explicit Settings and a Database so tests can build an app
without the real .env or MySQL. Database engines are created lazily and
never connect at startup; they are disposed on shutdown.
"""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api import health
from app.api.router import api_router
from app.config import Settings, get_settings
from app.db.session import Database
from app.errors import install_error_handlers

logger = logging.getLogger(__name__)


def create_app(settings: Settings | None = None, database: Database | None = None) -> FastAPI:
    settings = settings or get_settings()
    database = database or Database(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if not settings.is_configured("jwt_secret"):
            logger.warning("JWT_SECRET is not configured: login and /me will answer 503")
        yield
        database.dispose()

    # Interactive docs are for development; production serves the API only.
    docs = not settings.is_production
    app = FastAPI(
        title="ASKQ API",
        description="Ask Questions to your Data - secure NL-to-SQL with CAIR",
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
    )
    app.state.settings = settings
    app.state.database = database

    # Tokens travel in the Authorization header, not cookies, so credentials
    # mode is off; origins are an explicit list (config rejects "*").
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )
    install_error_handlers(app)
    app.include_router(health.router)
    app.include_router(api_router)
    return app


app = create_app()
