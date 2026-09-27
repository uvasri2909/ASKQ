def test_health_returns_ok(client):
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "askq-backend"
    assert body["version"]
    assert body["environment"] == "test"


def test_unknown_route_returns_404(client):
    assert client.get("/does-not-exist").status_code == 404


def test_cors_allows_frontend_origin(client):
    response = client.options(
        "/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_docs_available_outside_production(client):
    assert client.get("/docs").status_code == 200
    paths = client.get("/openapi.json").json()["paths"]
    assert set(paths) == {
        "/health",
        "/health/db",
        "/api/v1/auth/login",
        "/api/v1/auth/me",
        "/api/v1/query",
    }
