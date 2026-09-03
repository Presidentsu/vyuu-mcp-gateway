from fastapi.testclient import TestClient


def test_health_returns_gateway_status(client: TestClient) -> None:
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "Vyuu MCP Gateway",
        "version": "test-version",
        "environment": "test",
    }


def test_unknown_route_returns_not_found(client: TestClient) -> None:
    response = client.get("/mcp")

    assert response.status_code == 404
