"""Uniform, safe error responses.

Every error body has the shape {"error": {"code", "message", ...}}. Clients
never see exception text, SQL, connection details or stack traces:
* validation errors list only field locations and messages, never the input
  (which may be a password);
* database and configuration failures become a generic 503;
* anything unexpected becomes a generic 500 with an error_id that is also
  written to the server log next to the traceback.
"""

import logging
import uuid
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import ConfigurationError

logger = logging.getLogger("app.errors")

_CODES = {
    400: "bad_request",
    401: "unauthenticated",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "payload_too_large",
    415: "unsupported_media_type",
    422: "validation_error",
    429: "too_many_requests",
    500: "internal_error",
    503: "service_unavailable",
}


class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorDetail


def _error(
    status_code: int,
    message: str,
    headers: dict[str, str] | None = None,
    **extra: Any,
) -> JSONResponse:
    body = {"error": {"code": _CODES.get(status_code, "error"), "message": message, **extra}}
    return JSONResponse(body, status_code=status_code, headers=headers)


async def _http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    message = exc.detail if isinstance(exc.detail, str) else "Request failed."
    return _error(exc.status_code, message, headers=getattr(exc, "headers", None))


async def _validation_exception(request: Request, exc: RequestValidationError) -> JSONResponse:
    # Only location, message and type: pydantic's "input" and "ctx" could echo a password.
    fields = [
        {
            "loc": [str(part) for part in err.get("loc", ())],
            "msg": err.get("msg"),
            "type": err.get("type"),
        }
        for err in exc.errors()
    ]
    return _error(status.HTTP_422_UNPROCESSABLE_CONTENT, "Invalid request.", fields=fields)


async def _configuration_exception(request: Request, exc: ConfigurationError) -> JSONResponse:
    logger.error("configuration error on %s %s: %s", request.method, request.url.path, exc)
    return _error(status.HTTP_503_SERVICE_UNAVAILABLE, "Service temporarily unavailable.")


async def _database_exception(request: Request, exc: SQLAlchemyError) -> JSONResponse:
    # The class name only: statement text is not needed to triage, and parameters
    # are hidden by the engine (hide_parameters=True) in any case.
    logger.error(
        "database error on %s %s: %s", request.method, request.url.path, type(exc).__name__
    )
    return _error(status.HTTP_503_SERVICE_UNAVAILABLE, "Service temporarily unavailable.")


async def _unexpected_exception(request: Request, exc: Exception) -> JSONResponse:
    error_id = uuid.uuid4().hex
    logger.exception("unhandled error %s on %s %s", error_id, request.method, request.url.path)
    return _error(
        status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal server error.", error_id=error_id
    )


def install_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(StarletteHTTPException, _http_exception)
    app.add_exception_handler(RequestValidationError, _validation_exception)
    app.add_exception_handler(ConfigurationError, _configuration_exception)
    app.add_exception_handler(SQLAlchemyError, _database_exception)
    app.add_exception_handler(Exception, _unexpected_exception)
