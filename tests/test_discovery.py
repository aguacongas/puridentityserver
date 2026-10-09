"""Tests de la feature Discovery (OIDC Discovery 1.0)."""

import asyncio
from collections.abc import Awaitable
from typing import TypeVar

from fastapi.testclient import TestClient

from puridentityserver.application.discovery import DiscoveryConfig, DiscoveryUseCase
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"
_BASE_URL = "https://id.example"
_ALL_ALGOS = [
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "HS256",
    "HS384",
    "HS512",
    # ``none`` complète toujours la liste : l'OP émet un id_token non signé
    # pour un client qui l'enregistre ainsi (OIDC Core 1.0 §3.1.3.7).
    "none",
]


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone (tests sans event loop externe)."""
    return asyncio.run(awaitable)


def test_discovery_usecase_builds_document_from_base_url() -> None:
    usecase = DiscoveryUseCase(DiscoveryConfig(issuer=_ISSUER, base_url=_BASE_URL))
    document = run(usecase.execute())

    assert document["issuer"] == _ISSUER
    assert document["authorization_endpoint"] == f"{_BASE_URL}/authorize"
    assert document["token_endpoint"] == f"{_BASE_URL}/token"
    assert document["userinfo_endpoint"] == f"{_BASE_URL}/userinfo"
    assert document["jwks_uri"] == f"{_BASE_URL}/.well-known/jwks.json"
    assert document["introspection_endpoint"] == f"{_BASE_URL}/introspect"
    assert document["revocation_endpoint"] == f"{_BASE_URL}/revoke"
    assert document["end_session_endpoint"] == f"{_BASE_URL}/end_session"
    assert document["frontchannel_logout_supported"] is True
    assert document["frontchannel_logout_session_supported"] is True
    assert document["backchannel_logout_supported"] is True
    assert document["backchannel_logout_session_supported"] is True
    assert document["device_authorization_endpoint"] == f"{_BASE_URL}/device_authorization"
    assert document["id_token_signing_alg_values_supported"] == _ALL_ALGOS


def test_discovery_usecase_falls_back_to_issuer_as_base_url() -> None:
    usecase = DiscoveryUseCase(DiscoveryConfig(issuer=_ISSUER))
    document = run(usecase.execute())

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
    assert metadata["end_session_endpoint"] is not None
    assert metadata["frontchannel_logout_supported"] is True
    assert metadata["frontchannel_logout_session_supported"] is True
    assert metadata["backchannel_logout_supported"] is True
    assert metadata["backchannel_logout_session_supported"] is True
    assert metadata["response_types_supported"] == [
        "code",
        "id_token",
        "token",
        "id_token token",
        "code id_token",
        "code token",
        "code id_token token",
    ]
    assert metadata["subject_types_supported"] == ["public"]
    assert metadata["device_authorization_endpoint"] == f"{_BASE_URL}/device_authorization"
    assert "urn:ietf:params:oauth:grant-type:device_code" in metadata["grant_types_supported"]
    assert "implicit" in metadata["grant_types_supported"]
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
    assert metadata["id_token_signing_alg_values_supported"] == ["RS256", "ES256", "ES512", "none"]


def test_discovery_advertises_request_object_signing_algorithms() -> None:
    usecase = DiscoveryUseCase(DiscoveryConfig(issuer=_ISSUER))
    document = run(usecase.execute())

    # RFC 9101 §5.2 : ``alg=none`` pour les clients standards, ``PS256``/
    # ``ES256`` pour le profil FAPI1 Advanced (FAPI1-ADV-5.2.2-1) ; les
    # deux indicateurs restent vrais — la suite de certification émet un
    # avertissement dès qu'un d'eux vaut ``false``.
    assert document["request_object_signing_alg_values_supported"] == [
        "none",
        "PS256",
        "ES256",
    ]
    assert document["request_parameter_supported"] is True
    assert document["request_uri_parameter_supported"] is True


def test_discovery_advertises_fapi1_client_assertion_algorithms() -> None:
    usecase = DiscoveryUseCase(DiscoveryConfig(issuer=_ISSUER, base_url=_BASE_URL))
    document = run(usecase.execute())

    assert document["token_endpoint_auth_signing_alg_values_supported"] == ["PS256", "ES256"]


def test_discovery_advertises_pkce_methods() -> None:
    usecase = DiscoveryUseCase(DiscoveryConfig(issuer=_ISSUER, base_url=_BASE_URL))
    document = run(usecase.execute())

    assert document["code_challenge_methods_supported"] == ["S256", "plain"]


def test_discovery_advertises_certificate_bound_access_tokens() -> None:
    usecase = DiscoveryUseCase(DiscoveryConfig(issuer=_ISSUER, base_url=_BASE_URL))
    document = run(usecase.execute())

    assert document["tls_client_certificate_bound_access_tokens"] is True


def test_discovery_omits_require_pushed_authorization_requests() -> None:
    usecase = DiscoveryUseCase(DiscoveryConfig(issuer=_ISSUER, base_url=_BASE_URL))
    document = run(usecase.execute())

    assert "require_pushed_authorization_requests" not in document


def test_discovery_endpoint_exposes_fapi1_fields() -> None:
    settings = Settings(issuer=_ISSUER, base_url=_BASE_URL, jwks_algorithms=("RS256",))
    with TestClient(create_app(settings)) as client:
        metadata = client.get("/.well-known/openid-configuration").json()

    assert metadata["token_endpoint_auth_signing_alg_values_supported"] == ["PS256", "ES256"]
    assert metadata["code_challenge_methods_supported"] == ["S256", "plain"]
    assert metadata["tls_client_certificate_bound_access_tokens"] is True
    assert "require_pushed_authorization_requests" not in metadata
