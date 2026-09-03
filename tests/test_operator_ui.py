from fastapi.testclient import TestClient

from vyuu_gateway.config import Settings
from vyuu_gateway.main import create_app


def test_operator_console_serves_static_shell() -> None:
    app = create_app(
        Settings(
            app_name="Vyuu MCP Gateway",
            environment="test",
            log_level="CRITICAL",
            version="test-version",
            operator_auth_signing_secret="ignored",
        )
    )

    with TestClient(app) as client:
        response = client.get("/operator")

    assert response.status_code == 200
    assert "Operator Console" in response.text
    assert "/operator/app.js" in response.text
    assert response.headers["content-security-policy"].startswith("default-src 'self'")
    assert response.headers["x-content-type-options"] == "nosniff"


def test_operator_console_assets_are_served_with_security_headers() -> None:
    app = create_app(
        Settings(
            app_name="Vyuu MCP Gateway",
            environment="test",
            log_level="CRITICAL",
            version="test-version",
            operator_auth_signing_secret="ignored",
        )
    )

    with TestClient(app) as client:
        css_response = client.get("/operator/app.css")
        js_response = client.get("/operator/app.js")

    assert css_response.status_code == 200
    assert "text/css" in css_response.headers["content-type"]
    assert "Operator Console" not in css_response.text
    assert js_response.status_code == 200
    assert "text/javascript" in js_response.headers["content-type"]
    assert "sessionStorage" in js_response.text
    assert js_response.headers["referrer-policy"] == "no-referrer"
