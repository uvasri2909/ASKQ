"""Uniform, safe error responses and CORS."""

import secrets

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from app.main import create_app

LEAKY_SECRET = secrets.token_hex(12)
LEAKY = f"mysql+pymysql://askq_app:{LEAKY_SECRET}@127.0.0.1/askq_system"

boom = APIRouter(prefix="/boom")


@boom.get("/unexpected")
def unexpected():
    raise RuntimeError(f"failed to connect with {LEAKY}")


@boom.get("/database")
def database_down():
    raise OperationalError("SELECT secret FROM x WHERE p = %s", {"p": LEAKY}, Exception(LEAKY))


@pytest.fixture
def boom_client(settings, database):
    app = create_app(settings, database)
    app.include_router(boom)
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


def test_unexpected_error_is_generic(boom_client, caplog):
    response = boom_client.get("/boom/unexpected")
    assert response.status_code == 500
    body = response.json()
    assert body["error"]["code"] == "internal_error"
    assert body["error"]["message"] == "Internal server error."
    assert len(body["error"]["error_id"]) == 32
    assert LEAKY_SECRET not in response.text and "Traceback" not in response.text
    # The id links the response to the server-side log entry.
    assert body["error"]["error_id"] in caplog.text


def test_database_error_is_503_without_sql(boom_client):
    response = boom_client.get("/boom/database")
    assert response.status_code == 503
    assert response.json() == {
        "error": {"code": "service_unavailable", "message": "Service temporarily unavailable."}
    }


def test_not_found_and_method_not_allowed_use_the_same_shape(client):
    assert client.get("/nope").json() == {"error": {"code": "not_found", "message": "Not Found"}}
    response = client.get("/api/v1/auth/login")
    assert response.status_code == 405
    assert response.json()["error"]["code"] == "method_not_allowed"


def test_malformed_json_is_a_validation_error(client):
    response = client.post(
        "/api/v1/auth/login", content="{not json", headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


# ---------- CORS ----------


def _preflight(client, origin):
    return client.options(
        "/api/v1/auth/login",
        headers={"Origin": origin, "Access-Control-Request-Method": "POST"},
    )


def test_cors_allows_configured_origin_without_credentials(client):
    response = _preflight(client, "http://localhost:5173")
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "access-control-allow-credentials" not in response.headers


def test_cors_ignores_other_origins(client):
    response = _preflight(client, "https://evil.example")
    assert "access-control-allow-origin" not in response.headers


def test_docs_disabled_in_production(database):
    from tests.conftest import make_settings

    settings = make_settings(app_env="production", cors_origins="https://askq.example")
    with TestClient(create_app(settings, database)) as client:
        assert client.get("/docs").status_code == 404
        assert client.get("/openapi.json").status_code == 404
        assert client.get("/health").status_code == 200
