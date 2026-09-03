import pytest

from vyuu_gateway.config import Settings
from vyuu_gateway.main import create_app


def test_settings_loads_vyuu_prefixed_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VYUU_ENVIRONMENT", "production")
    monkeypatch.setenv("VYUU_LOG_LEVEL", "WARNING")

    settings = Settings()

    assert settings.environment == "production"
    assert settings.log_level == "WARNING"


def test_create_app_requires_redis_url_outside_local_or_test() -> None:
    with pytest.raises(RuntimeError, match="VYUU_REDIS_URL is required"):
        create_app(Settings(environment="production", log_level="CRITICAL", redis_url=None))


def test_create_app_requires_management_plane_url_for_management_policy_backend() -> None:
    with pytest.raises(RuntimeError, match="VYUU_MANAGEMENT_PLANE_POLICY_BASE_URL"):
        create_app(
            Settings(
                environment="test",
                log_level="CRITICAL",
                policy_provider_backend="management_plane",
                management_plane_policy_base_url=None,
            )
        )


def test_create_app_rejects_unknown_policy_backend() -> None:
    with pytest.raises(RuntimeError, match="VYUU_POLICY_PROVIDER_BACKEND"):
        create_app(
            Settings(
                environment="test",
                log_level="CRITICAL",
                policy_provider_backend="unknown",
            )
        )
