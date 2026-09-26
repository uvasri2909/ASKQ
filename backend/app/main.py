"""FastAPI application entry point.

Run from the backend/ directory:
    .venv\\Scripts\\python -m uvicorn app.main:app --reload
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api import health
from app.config import get_settings


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="ASKQ API",
        description="Ask Questions to your Data - secure NL-to-SQL with CAIR",
        version=__version__,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )
    app.include_router(health.router)
    return app


app = create_app()
