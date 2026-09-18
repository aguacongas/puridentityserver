"""Tests du CORS dynamique — origines déduites des URIs des clients.

Les origines autorisées sont déduites des ``redirect_uris`` des clients
actifs et complétées de leurs ``web_origins`` (OAuth 2.0 for Browser-Based
Apps) : aucune liste statique n'est configurée, un client enregistré
dynamiquement (RFC 7591) est couvert immédiatement.
"""

import asyncio
from typing import Any, cast

from fastapi.testclient import TestClient

from puridentityserver.domain.authorization import Client, origin_of_uri
from puridentityserver.infrastructure.persistence.memory.clients import InMemoryClientRepository
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.interfaces.api.cors import DynamicCORSMiddleware
from puridentityserver.server import create_app

_ISSUER = "https://id.example"
_ORIGIN = "http://127.0.0.1:5177"
_ALIAS = "http://localhost:5177"
_EVIL = "http://evil.example"

_SPA_CLIENT: tuple[dict[str, object], ...] = (
    {
        "client_id": "sample-spa-client",
        "redirect_uris": ["http://127.0.0.1:5177/"],
        "web_origins": ["http://localhost:5177"],
        "client_type": "public",
    },
)

_CORS_HEADER = "access-control-allow-origin"


def _settings(clients: tuple[dict[str, object], ...] = _SPA_CLIENT) -> Settings:
    """Réglages du serveur de test avec les clients seed fournis."""
    return Settings(issuer=_ISSUER, jwks_algorithms=("RS256",), clients_seed=clients)


class TestOriginOfUri:
    """Normalisation URI → origine (OAuth BCP §8)."""

    def test_elides_default_ports(self) -> None:
        assert origin_of_uri("https://app.example:443/callback") == "https://app.example"
        assert origin_of_uri("http://app.example:80/callback") == "http://app.example"

    def test_preserves_non_default_port(self) -> None:
        assert origin_of_uri("http://127.0.0.1:5177/") == _ORIGIN
        assert origin_of_uri("http://localhost:8080/cb") == "http://localhost:8080"

    def test_rejects_non_http_uris(self) -> None:
        assert origin_of_uri("ftp://app.example/cb") is None
        assert origin_of_uri("relative/uri") is None


class TestClientCorsOrigins:
    """Déduction des origines CORS d'un client (redirect_uris + web_origins)."""

    def test_derives_origin_from_redirect_uris(self) -> None:
        client = Client(client_id="c", redirect_uris=frozenset({"https://app.example/cb"}))

        assert client.cors_allowed_origins() == frozenset({"https://app.example"})

    def test_merges_declared_web_origins(self) -> None:
        client = Client(
            client_id="c",
            redirect_uris=frozenset({"https://app.example/cb"}),
            web_origins=frozenset({"https://alias.example"}),
        )

        assert client.cors_allowed_origins() == frozenset(
            {"https://app.example", "https://alias.example"}
        )

    def test_ignores_non_http_origins(self) -> None:
        client = Client(client_id="c", redirect_uris=frozenset({"ftp://app.example/cb"}))

        assert client.cors_allowed_origins() == frozenset()


class TestRepositoryCors:
    """Contrat ``is_cors_origin_allowed`` du registre clients."""

    def _repo(self, client: Client) -> InMemoryClientRepository:
        repo = InMemoryClientRepository()
        asyncio.run(repo.save(client))
        return repo

    def test_allows_origin_of_active_client(self) -> None:
        repo = self._repo(
            Client(
                client_id="c",
                redirect_uris=frozenset({"https://app.example/cb"}),
                is_active=True,
            )
        )

        assert asyncio.run(repo.is_cors_origin_allowed("https://app.example")) is True

    def test_denies_origin_of_inactive_client(self) -> None:
        repo = self._repo(
            Client(
                client_id="c",
                redirect_uris=frozenset({"https://app.example/cb"}),
                is_active=False,
            )
        )

        assert asyncio.run(repo.is_cors_origin_allowed("https://app.example")) is False

    def test_denies_unregistered_origin(self) -> None:
        repo = self._repo(
            Client(client_id="c", redirect_uris=frozenset({"https://app.example/cb"}))
        )

        assert asyncio.run(repo.is_cors_origin_allowed(_EVIL)) is False


class TestMiddlewarePassThrough:
    """Comportement ASGI de base du middleware (hors requêtes HTTP)."""

    def test_forwards_non_http_scopes(self) -> None:
        seen: list[str] = []

        async def app(scope: dict[str, str], receive: object, send: object) -> None:
            seen.append(scope["type"])
            await asyncio.sleep(0)

        middleware = DynamicCORSMiddleware(cast(Any, app), InMemoryClientRepository())
        asyncio.run(
            middleware(
                cast(Any, {"type": "websocket"}),
                cast(Any, None),
                cast(Any, None),
            )
        )

        assert seen == ["websocket"]


class TestDynamicCorsHttp:
    """End-to-end : origine acceptée si un client actif l'autorise."""

    def test_allows_origin_of_client_redirect_uri(self) -> None:
        with TestClient(create_app(_settings())) as client:
            response = client.get("/.well-known/openid-configuration", headers={"Origin": _ORIGIN})

        assert response.status_code == 200
        assert response.headers[_CORS_HEADER] == _ORIGIN
        assert response.headers.get("vary") == "Origin"

    def test_allows_origin_from_web_origins(self) -> None:
        with TestClient(create_app(_settings())) as client:
            response = client.get("/.well-known/openid-configuration", headers={"Origin": _ALIAS})

        assert response.status_code == 200
        assert response.headers[_CORS_HEADER] == _ALIAS

    def test_exposes_location_and_www_authenticate(self) -> None:
        with TestClient(create_app(_settings())) as client:
            response = client.get("/.well-known/openid-configuration", headers={"Origin": _ORIGIN})

        exposed = response.headers["access-control-expose-headers"].lower()
        assert "location" in exposed
        assert "www-authenticate" in exposed

    def test_rejects_unregistered_origin(self) -> None:
        with TestClient(create_app(_settings())) as client:
            response = client.get("/.well-known/openid-configuration", headers={"Origin": _EVIL})

        assert response.status_code == 200
        assert _CORS_HEADER not in response.headers

    def test_denies_all_origins_without_clients(self) -> None:
        with TestClient(create_app(_settings(clients=()))) as client:
            response = client.get("/.well-known/openid-configuration", headers={"Origin": _ORIGIN})

        assert response.status_code == 200
        assert _CORS_HEADER not in response.headers

    def test_no_origin_header_means_no_cors_headers(self) -> None:
        with TestClient(create_app(_settings())) as client:
            response = client.get("/.well-known/openid-configuration")

        assert response.status_code == 200
        assert _CORS_HEADER not in response.headers


class TestDynamicCorsPreflight:
    """Preludes OPTIONS (Access-Control-Request-Method)."""

    def test_allows_preflight_for_registered_origin(self) -> None:
        with TestClient(create_app(_settings())) as client:
            response = client.options(
                "/token",
                headers={
                    "Origin": _ORIGIN,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "content-type, authorization",
                },
            )

        assert response.status_code == 200
        assert response.headers[_CORS_HEADER] == _ORIGIN
        methods = response.headers["access-control-allow-methods"].upper()
        assert "POST" in methods
        assert "GET" in methods
        headers = response.headers["access-control-allow-headers"].lower()
        assert "content-type" in headers
        assert "authorization" in headers

    def test_rejects_preflight_for_unregistered_origin(self) -> None:
        with TestClient(create_app(_settings())) as client:
            response = client.options(
                "/token",
                headers={
                    "Origin": _EVIL,
                    "Access-Control-Request-Method": "POST",
                },
            )

        assert response.status_code == 400
        assert _CORS_HEADER not in response.headers

    def test_options_without_request_method_is_not_preflight(self) -> None:
        with TestClient(create_app(_settings())) as client:
            response = client.options(
                "/.well-known/openid-configuration", headers={"Origin": _ORIGIN}
            )

        assert response.status_code in (200, 405)
        assert _CORS_HEADER in response.headers


def test_settings_seed_clients_expose_web_origins() -> None:
    settings = _settings()

    client = settings.seed_clients[0]

    assert client.web_origins == frozenset({_ALIAS})
    assert client.cors_allowed_origins() == frozenset({_ORIGIN, _ALIAS})
