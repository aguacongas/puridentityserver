"""Tests du support CORS (clients publics SPA, Authorization Code + PKCE sans secret)."""

import pytest
from fastapi.testclient import TestClient

from puridentityserver.infrastructure.settings import Settings
from puridentityserver.server import create_app

_ISSUER = "https://id.example"
_ORIGIN = "http://127.0.0.1:5173"


def test_settings_parses_and_normalises_cors_origins() -> None:
    settings = Settings(cors_origins="http://a.example, http://b.example/")

    assert settings.cors_origins == ("http://a.example", "http://b.example")


def test_cors_is_disabled_when_no_origin_configured() -> None:
    settings = Settings(issuer=_ISSUER, cors_origins=())
    with TestClient(create_app(settings)) as client:
        response = client.get("/.well-known/openid-configuration", headers={"Origin": _ORIGIN})

    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


def test_cors_allows_configured_origin_on_get() -> None:
    settings = Settings(issuer=_ISSUER, cors_origins=(_ORIGIN,))
    with TestClient(create_app(settings)) as client:
        response = client.get("/.well-known/openid-configuration", headers={"Origin": _ORIGIN})

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == _ORIGIN
    exposed = response.headers["access-control-expose-headers"].lower()
    assert "location" in exposed
    assert "www-authenticate" in exposed


def test_cors_rejects_unlisted_origin() -> None:
    settings = Settings(issuer=_ISSUER, cors_origins=(_ORIGIN,))
    with TestClient(create_app(settings)) as client:
        response = client.get(
            "/.well-known/openid-configuration", headers={"Origin": "http://evil.example"}
        )

    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


def test_cors_preflight_on_token_endpoint() -> None:
    settings = Settings(issuer=_ISSUER, cors_origins=(_ORIGIN,))
    with TestClient(create_app(settings)) as client:
        response = client.options(
            "/token",
            headers={
                "Origin": _ORIGIN,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type, authorization",
            },
        )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == _ORIGIN
    allowed_headers = response.headers["access-control-allow-headers"].lower()
    assert "content-type" in allowed_headers
    assert "authorization" in allowed_headers


def test_cors_reads_origins_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PURIDENTITYSERVER_CORS_ORIGINS", _ORIGIN)
    settings = Settings(_env_file=None)

    assert settings.cors_origins == (_ORIGIN,)
