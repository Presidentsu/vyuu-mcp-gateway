import os

# When `VYUU_TEST_DATABASE_URL` is set (used by integration tests that
# need a real Postgres), promote it to `VYUU_DATABASE_URL` so the
# gateway's module-time `SessionLocal` binds to the test cluster
# instead of the production-default URL. Must run BEFORE any
# `vyuu_gateway` import in any test file. Conftest is the only
# pytest-supplied hook that fires that early.
_TEST_DB = os.environ.get("VYUU_TEST_DATABASE_URL")
if _TEST_DB and not os.environ.get("VYUU_DATABASE_URL"):
    os.environ["VYUU_DATABASE_URL"] = _TEST_DB

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from vyuu_gateway.config import Settings  # noqa: E402
from vyuu_gateway.main import create_app  # noqa: E402


@pytest.fixture
def client() -> TestClient:
    app = create_app(
        Settings(
            app_name="Vyuu MCP Gateway",
            environment="test",
            log_level="CRITICAL",
            version="test-version",
        )
    )
    return TestClient(app)
