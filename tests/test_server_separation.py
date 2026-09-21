"""Tests de la séparation physique des serveurs et des ports de lecture.

Couvre la frontière définie pour la refonte des packages :
- les **adapters readers** (``readers.py``) délèguent en lecture seule aux
  stores partagés et ne reflètent aucune opération d'écriture ;
- le serveur ``full`` partage **les mêmes instances de ``Stores``** entre
  ``ProtocolDependencies`` et ``AdminDependencies`` : une écriture de
  l'administration est immédiatement visible du protocole ;
- les trois points d'entrée (``puridentityprotocol.server:app``,
  ``puridentityadmin.server:app``, ``puridentityfull.server:app``)
  montent la surface attendue, sans fuite entre les rôles ;
- la façade ``puridentityserver.server`` dispatche sur le ``role`` configuré.
"""

import asyncio
from collections.abc import Awaitable
from typing import TypeVar

from fastapi import FastAPI
from fastapi.testclient import TestClient

import puridentityadmin
import puridentityfull
import puridentityprotocol
import puridentityserver.server as facade
from puridentityadmin.server import AdminDependencies
from puridentityprotocol.server import ProtocolDependencies
from puridentityserver.application.identity_resource import (
    IdentityResourceData,
    IdentityResourceRequest,
)
from puridentityserver.domain.api_resource import ApiResource
from puridentityserver.domain.authorization import Client, ClientType, Scope
from puridentityserver.domain.identity_resource import IdentityResource
from puridentityserver.domain.userinfo import UserClaims
from puridentityserver.infrastructure.persistence.memory.api_resources import (
    InMemoryApiResourceRepository,
)
from puridentityserver.infrastructure.persistence.memory.clients import (
    InMemoryClientRepository,
)
from puridentityserver.infrastructure.persistence.memory.identity_resources import (
    InMemoryIdentityResourceRepository,
)
from puridentityserver.infrastructure.persistence.memory.users import (
    InMemoryUserRepository,
)
from puridentityserver.infrastructure.persistence.readers import (
    ApiResourceReaderAdapter,
    ClientReaderAdapter,
    IdentityResourceReaderAdapter,
    Readers,
    UserReaderAdapter,
    build_readers_from_stores,
)
from puridentityserver.infrastructure.persistence.stores import build_stores
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"

_ORIGIN = "https://app.example"


def run(awaitable: Awaitable[_T]) -> _T:
    """Exécute une coroutine de manière synchrone (tests sans event loop externe)."""
    return asyncio.run(awaitable)


def _settings(**overrides: object) -> Settings:
    """Settings d'administration minimaux pour les tests de composition."""
    return Settings(
        issuer=_ISSUER,
        jwks_algorithms=("RS256",),
        **overrides,
    )


def _client(*, session_lifetime_seconds: int | None = None) -> Client:
    """Client confidentiel de test avec origine CORS déclarée."""
    return Client(
        client_id="web-app",
        client_secret_hash="hash",
        redirect_uris=frozenset({f"{_ORIGIN}/callback"}),
        web_origins=frozenset({f"{_ORIGIN}/"}),
        scopes=frozenset({Scope.OPENID, Scope("api.read")}),
        client_type=ClientType.CONFIDENTIAL,
        session_lifetime_seconds=session_lifetime_seconds,
    )


class TestReaderAdapters:
    """Couvre la délégation en lecture seule des quatre adapters."""

    def test_client_reader_delegates_reads(self) -> None:
        repository = InMemoryClientRepository()
        reader = ClientReaderAdapter(repository)
        client = _client()
        run(repository.save(client))

        assert run(reader.find_by_id("web-app")) is client
        assert run(reader.find_by_id("missing")) is None
        assert run(reader.find_all()) == [client]
        assert run(reader.is_cors_origin_allowed(_ORIGIN)) is True
        assert run(reader.is_cors_origin_allowed("https://evil.example")) is False

    def test_client_reader_exposes_no_write_method(self) -> None:
        reader = ClientReaderAdapter(InMemoryClientRepository())

        assert not hasattr(reader, "save")
        assert not hasattr(reader, "delete")

    def test_user_reader_delegates_reads(self) -> None:
        repository = InMemoryUserRepository()
        reader = UserReaderAdapter(repository)
        alice = UserClaims(subject="alice", claims={"name": "Alice Martin"})
        run(repository.save(alice))

        assert run(reader.find_by_subject("alice")) is alice
        assert run(reader.find_by_subject("missing")) is None
        assert run(reader.find_all()) == [alice]

    def test_identity_resource_reader_delegates_reads(self) -> None:
        repository = InMemoryIdentityResourceRepository()
        reader = IdentityResourceReaderAdapter(repository)
        resource = IdentityResource(name="profile", display_name="Profil")
        run(repository.save(resource))

        assert run(reader.find_by_name("profile")) is resource
        assert run(reader.find_by_name("missing")) is None
        assert run(reader.find_all()) == [resource]

    def test_api_resource_reader_delegates_reads(self) -> None:
        repository = InMemoryApiResourceRepository()
        reader = ApiResourceReaderAdapter(repository)
        resource = ApiResource(name="billing", scopes=frozenset({"api.read"}))
        run(repository.save(resource))

        assert run(reader.find_by_name("billing")) is resource
        assert run(reader.find_by_name("missing")) is None
        assert run(reader.find_all()) == [resource]


class TestReadersFromStores:
    """Couvre ``build_readers_from_stores`` et la cohérence des stores partagés."""

    def test_readers_expose_admin_writes_on_shared_stores(self) -> None:
        stores = build_stores(_settings())
        readers = build_readers_from_stores(
            client=stores.client,
            user=stores.user,
            identity_resource=stores.identity_resource,
            api_resource=stores.api_resource,
        )
        alice = UserClaims(subject="alice", claims={"name": "Alice Martin"})
        identity = IdentityResource(name="custom", display_name="Sur mesure")
        api = ApiResource(name="billing", scopes=frozenset({"api.read"}))
        run(stores.client.save(_client()))
        run(stores.user.save(alice))
        run(stores.identity_resource.save(identity))
        run(stores.api_resource.save(api))

        assert isinstance(readers, Readers)
        assert isinstance(readers.client, ClientReaderAdapter)
        assert isinstance(readers.user, UserReaderAdapter)
        assert isinstance(readers.identity_resource, IdentityResourceReaderAdapter)
        assert isinstance(readers.api_resource, ApiResourceReaderAdapter)
        assert run(readers.client.find_by_id("web-app")) is not None
        assert run(readers.user.find_by_subject("alice")) is alice
        assert run(readers.identity_resource.find_by_name("custom")) is identity
        assert run(readers.api_resource.find_by_name("billing")) is api


class TestServerPackages:
    """Couvre les points d'entrée des trois serveurs (titre + surface HTTP)."""

    def test_protocol_app_exposes_only_protocol(self) -> None:
        with TestClient(puridentityprotocol.server.create_app(_settings())) as client:
            assert client.app.title == "PurIdentityServer — protocole"
            assert client.get("/.well-known/openid-configuration").status_code == 200
            assert client.get("/.well-known/jwks.json").status_code == 200
            assert client.get("/api-resources").status_code == 404
            assert client.get("/identity-resources").status_code == 404

    def test_admin_app_exposes_only_administration(self) -> None:
        settings = _settings(admin_required_claim_values=())
        with TestClient(puridentityadmin.server.create_app(settings)) as client:
            assert client.app.title == "PurIdentityServer — administration"
            assert client.get("/api-resources").status_code == 200
            assert client.get("/identity-resources").status_code == 200
            assert client.get("/.well-known/openid-configuration").status_code == 404
            assert client.get("/authorize").status_code == 404

    def test_full_app_exposes_protocol_and_administration(self) -> None:
        settings = _settings(admin_required_claim_values=())
        with TestClient(puridentityfull.server.create_app(settings)) as client:
            assert client.app.title == "PurIdentityServer"
            assert client.get("/.well-known/openid-configuration").status_code == 200
            assert client.get("/api-resources").status_code == 200
            assert client.get("/identity-resources").status_code == 200

    def test_module_level_app_objects_are_composed(self) -> None:
        assert puridentityprotocol.app.title == "PurIdentityServer — protocole"
        assert puridentityadmin.app.title == "PurIdentityServer — administration"
        assert puridentityfull.app.title == "PurIdentityServer"


class TestSharedStores:
    """Couvre le partage des instances entre les deux compositions roots."""

    def test_full_composition_shares_store_instances(self) -> None:
        settings = _settings()
        stores = build_stores(settings)

        protocol = ProtocolDependencies(settings, stores)
        admin = AdminDependencies(settings, stores)

        assert protocol.stores is stores
        assert admin.stores is stores

    def test_admin_write_is_visible_through_protocol_readers(self) -> None:
        settings = _settings()
        stores = build_stores(settings)
        protocol = ProtocolDependencies(settings, stores)
        admin = AdminDependencies(settings, stores)
        result = run(
            admin.identity_resources_usecase.create(
                IdentityResourceRequest(name="admin-added", user_claims=frozenset({"name"}))
            )
        )
        assert isinstance(result, IdentityResourceData)
        stored = run(protocol.readers.identity_resource.find_by_name("admin-added"))
        assert stored is not None
        assert stored.user_claims == frozenset({"name"})

    def test_resolve_session_lifetime_reads_client_setting(self) -> None:
        protocol = ProtocolDependencies(_settings(), build_stores(_settings()))
        run(protocol.stores.client.save(_client(session_lifetime_seconds=600)))

        assert run(protocol.resolve_session_lifetime("web-app")) == 600
        assert run(protocol.resolve_session_lifetime("missing")) is None


class TestFacadeDispatch:
    """Couvre le dispatch de la façade historique selon le ``role`` configuré."""

    def _app(self, **overrides: object) -> FastAPI:
        return create_app(_settings(**overrides))

    def test_default_role_resolves_to_full(self) -> None:
        assert self._app().title == "PurIdentityServer"

    def test_protocol_role_dispatches_to_protocol_server(self) -> None:
        assert self._app(role="protocol").title == "PurIdentityServer — protocole"

    def test_admin_role_dispatches_to_admin_server(self) -> None:
        assert self._app(role="admin").title == "PurIdentityServer — administration"

    def test_facade_module_app_uses_default_role(self) -> None:
        assert facade.app.title == "PurIdentityServer"
