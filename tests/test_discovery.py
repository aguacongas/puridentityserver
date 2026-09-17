"""Tests de la feature Discovery (OIDC Discovery 1.0)."""

from fastapi.testclient import TestClient

from puridentityserver.application.discovery import DiscoveryConfig, DiscoveryUseCase
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.server import create_app

_ISSUER = "https://id.example"
_BASE_URL = "https://id.example"
_ALL_ALGOS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"]


def test_discovery_usecase_builds_document_from_base_url() -> None:
    usecase = DiscoveryUseCase(DiscoveryConfig(issuer=_ISSUER, base_url=_BASE_URL))
    document = usecase.execute()

    assert document["issuer"] == _ISSUER
    assert document["authorization_endpoint"] == f"{_BASE_URL}/authorize"
    assert document["token_endpoint"] == f"{_BASE_URL}/token"
    assert document["userinfo_endpoint"] == f"{_BASE_URL}/userinfo"
    assert document["jwks_uri"] == f"{_BASE_URL}/.well-known/jwks.json"
    assert document["introspection_endpoint"] == f"{_BASE_URL}/introspect"
    assert document["revocation_endpoint"] == f"{_BASE_URL}/revoke"
    assert document["end_session_endpoint"] == f"{_BASE_URL}/end_session"
    assert document["device_authorization_endpoint"] == f"{_BASE_URL}/device_authorization"
    assert document["id_token_signing_alg_values_supported"] == _ALL_ALGOS


def test_discovery_usecase_falls_back_to_issuer_as_base_url() -> None:
    usecase = DiscoveryUseCase(DiscoveryConfig(issuer=_ISSUER))
    document = usecase.execute()

    assert document["authorization_endpoint"] == f"{_ISSUER}/authorize"
    assert document["jwks_uri"] == f"{_ISSUER}/.well-known/jwks.json"


def test_discovery_endpoint_returns_oidc_metadata() -> None:
    settings = Settings(issuer=_ISSUER, base_url=_BASE_URL)
    with TestClient(create_app(settings)) as client:
        response = client.get("/.well-known/openid-configuration")

    assert response.status_code == 200
    metadata = response.json()
    assert metadata["issuer"] == _ISSUER
    assert metadata["authorization_endpoint"] == f"{_BASE_URL}/authorize"
    assert metadata["token_endpoint"] == f"{_BASE_URL}/token"
    assert metadata["jwks_uri"] == f"{_BASE_URL}/.well-known/jwks.json"
    assert metadata["response_types_supported"] == ["code"]
    assert metadata["subject_types_supported"] == ["public"]
    assert metadata["device_authorization_endpoint"] == f"{_BASE_URL}/device_authorization"
    assert "urn:ietf:params:oauth:grant-type:device_code" in metadata["grant_types_supported"]
    assert metadata["id_token_signing_alg_values_supported"] == _ALL_ALGOS


def test_discovery_advertises_configured_signing_algorithms() -> None:
    settings = Settings(
        issuer=_ISSUER,
        base_url=_BASE_URL,
        jwks_algorithms=("RS256", "ES256", "ES512"),
    )
    with TestClient(create_app(settings)) as client:
        response = client.get("/.well-known/openid-configuration")

    assert response.status_code == 200
    metadata = response.json()
    assert metadata["id_token_signing_alg_values_supported"] == ["RS256", "ES256", "ES512"]
