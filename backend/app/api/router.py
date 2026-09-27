"""The versioned API: everything under /api/v1."""

from fastapi import APIRouter

from app.api import auth, query

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(auth.router)
api_router.include_router(query.router)
