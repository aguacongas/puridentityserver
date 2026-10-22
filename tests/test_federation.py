"""Tests de la Fédération (OpenID Federation 1.1).

Couvre l'entity statement (structure §3.2), la chaîne de confiance
(§4, §10) et l'endpoint de configuration de l'OP (§9).
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Coroutine
from datetime import UTC, datetime
from typing import Any, TypeVar

import jwt as pyjwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.application.federated_client import TrustChainClientResolver
from puridentityserver.application.federation import (
    ENTITY_CONFIGURATION_PATH,
    DiscoveryFederationMetadataProvider,
    FederationConfig,
    FederationUseCase,
)
from puridentityserver.domain.authorization import (
    Client,
    ClientType,
    Scope,
    TokenEndpointAuthMethod,
)
from puridentityserver.domain.federation import (
    ENTITY_STATEMENT_MEDIA_TYPE,
    EntityStatement,
    FederationError,
    TrustChain,
    parse_entity_statement,
)
from puridentityserver.domain.jwks import JWTAlgorithm, KeyUse
from puridentityserver.infrastructure.federated_client import FederatedClientReader
from puridentityserver.infrastructure.federation import (
    HTTPFederationEntityFetcher,
    KeyManagerFederationKeyProvider,
    PyJWTFederationTokenManager,
)
from puridentityserver.infrastructure.jwks import DefaultKeyManager
from puridentityserver.infrastructure.persistence.memory.keys import (
    InMemoryKeyPairRepository,
)
from puridentityserver.infrastructure.settings import Settings
from puridentityserver.interfaces.domain.federation import FederationEntityFetcher
from puridentityserver.interfaces.repositories.readers import ClientReader
from puridentityserver.server import create_app

_T = TypeVar("_T")

_ISSUER = "https://id.example"


def _now() -> int:
    """Horodatage courant (secondes) : les statements doivent être valides."""
    return int(time.time())


def run(awaitable: Coroutine[Any, Any, _T]) -> _T:
    """Exécute une coroutine de façon synchrone (pattern du dépôt)."""
    return asyncio.run(awaitable)


def _key_manager() -> DefaultKeyManager:
    """Gestionnaire de clés de la fédération (ES256), clé générée."""
    manager = DefaultKeyManager(InMemoryKeyPairRepository(), use=KeyUse.FEDERATION)
    run(manager.ensure_active_key(2048, JWTAlgorithm.ES256))
    return manager


def _usecase(
    *,
    entity_identifier: str = _ISSUER,
    trust_anchors: tuple[str, ...] = (),
    fetcher: FederationEntityFetcher | None = None,
) -> FederationUseCase:
    """Cas d'usage de la fédération pour les tests."""
    key_manager = _key_manager()
    return FederationUseCase(
        config=FederationConfig(
            entity_identifier=entity_identifier,
            trust_anchors=trust_anchors,
            statement_ttl_seconds=3600,
            algorithm=JWTAlgorithm.ES256,
        ),
        token_manager=PyJWTFederationTokenManager(key_manager, JWTAlgorithm.ES256),
        key_provider=KeyManagerFederationKeyProvider(key_manager),
        fetcher=fetcher or HTTPFederationEntityFetcher(allow_local_targets=True),
    )


class _StaticFetcher:
    """Fetcher renvoyant des statements pré-construits (par URL)."""

    def __init__(self, statements: dict[str, str]) -> None:
        self._statements = statements

    async def fetch_entity_statement(self, url: str) -> str | None:
        return self._statements.get(url)


def test_entity_statement_is_self_signed_and_typed() -> None:
    """L'entity statement est auto-signé et typé (spec §3, §9.2)."""
    usecase = _usecase()
    statement = run(usecase.entity_statement())

    header = pyjwt.get_unverified_header(statement)
    assert header["typ"] == ENTITY_STATEMENT_MEDIA_TYPE
    assert header["kid"]
    claims = pyjwt.decode(statement, options={"verify_signature": False})
    assert claims["iss"] == _ISSUER
    assert claims["sub"] == _ISSUER
    assert claims["exp"] > claims["iat"]
    assert claims["jwks"]["keys"]


def test_entity_statement_is_verifiable_with_its_own_jwks() -> None:
    """La signature se vérifie avec le `jwks` porté par le statement (spec §3.2)."""
    usecase = _usecase()
    statement = run(usecase.entity_statement())

    claims = pyjwt.decode(statement, options={"verify_signature": False})
    verified = usecase.token_manager.verify_entity_statement(
        token=statement,
        jwks=claims["jwks"],
        issuer=_ISSUER,
        subject=_ISSUER,
    )

    assert verified is not None
    assert verified["sub"] == _ISSUER


def test_entity_statement_declares_the_trust_anchors() -> None:
    """Les ancres de confiance configurées sont annoncées en `authority_hints`."""
    usecase = _usecase(trust_anchors=("https://ta.example",))
    statement = run(usecase.entity_statement())

    claims = pyjwt.decode(statement, options={"verify_signature": False})
    assert claims["authority_hints"] == ["https://ta.example"]


def _parse_without(claims: dict[str, Any], missing: str) -> None:
    """Lève l'erreur attendue quand un claim obligatoire manque."""
    incomplete = {key: value for key, value in claims.items() if key != missing}
    with pytest.raises(FederationError):
        parse_entity_statement(incomplete)


def test_parse_entity_statement_requires_the_mandatory_claims() -> None:
    """`iss`, `sub`, `iat`, `exp` et `jwks` sont obligatoires (spec §3.1.1)."""
    base = {
        "iss": _ISSUER,
        "sub": _ISSUER,
        "iat": _now(),
        "exp": _now() + 3600,
        "jwks": {"keys": []},
    }
    for missing in ("iss", "sub", "iat", "exp", "jwks"):
        _parse_without(base, missing)

    assert parse_entity_statement(base).issuer == _ISSUER


def test_parse_entity_statement_rejects_non_standard_entity_types() -> None:
    """Les types d'entité doivent être standard (spec §5.1)."""
    claims = {
        "iss": _ISSUER,
        "sub": _ISSUER,
        "iat": _now(),
        "exp": _now() + 3600,
        "jwks": {"keys": []},
        "metadata": {"inconnu": {}},
    }
    with pytest.raises(FederationError):
        parse_entity_statement(claims)


def test_parse_entity_statement_rejects_an_inverted_expiration() -> None:
    """`exp` doit être postérieur à `iat` (spec §3.1.1)."""
    with pytest.raises(FederationError):
        parse_entity_statement(
            {
                "iss": _ISSUER,
                "sub": _ISSUER,
                "iat": 1700003600,
                "exp": 1700000000,
                "jwks": {"keys": []},
            }
        )


def test_resolve_trust_chain_rejects_an_unknown_subject() -> None:
    """Un sujet sans entity statement accessible ne donne aucune chaîne."""
    usecase = _usecase(fetcher=_StaticFetcher({}))

    assert run(usecase.resolve_trust_chain("https://rp.example", "")) is None


def test_resolve_trust_chain_follows_the_authority_hints() -> None:
    """La résolution remonte les `authority_hints` jusqu'à l'ancre (spec §10.1)."""
    key_manager = _key_manager()
    token_manager = PyJWTFederationTokenManager(key_manager, JWTAlgorithm.ES256)
    anchor = "https://ta.example"

    anchor_claims = {
        "iss": anchor,
        "sub": anchor,
        "iat": _now(),
        "exp": _now() + 3600,
        "jwks": run(KeyManagerFederationKeyProvider(key_manager).public_jwks()),
        "metadata": {"federation_entity": {"federation_fetch_endpoint": f"{anchor}/fetch"}},
    }
    anchor_statement = run(
        token_manager.sign_entity_statement(
            algorithm=JWTAlgorithm.ES256, claims=anchor_claims, key_id=""
        )
    )

    subject_claims = {
        "iss": "https://rp.example",
        "sub": "https://rp.example",
        "iat": _now(),
        "exp": _now() + 3600,
        "jwks": run(KeyManagerFederationKeyProvider(key_manager).public_jwks()),
        "authority_hints": [anchor],
    }
    subject_statement = run(
        token_manager.sign_entity_statement(
            algorithm=JWTAlgorithm.ES256, claims=subject_claims, key_id=""
        )
    )

    subordinate_claims = {
        "iss": anchor,
        "sub": "https://rp.example",
        "iat": _now(),
        "exp": _now() + 3600,
        "jwks": anchor_claims["jwks"],
    }
    subordinate_statement = run(
        token_manager.sign_entity_statement(
            algorithm=JWTAlgorithm.ES256, claims=subordinate_claims, key_id=""
        )
    )

    fetcher = _StaticFetcher(
        {
            "https://rp.example/.well-known/openid-federation": subject_statement,
            f"{anchor}/.well-known/openid-federation": anchor_statement,
            f"{anchor}/fetch?sub=https://rp.example": subordinate_statement,
        }
    )
    usecase = FederationUseCase(
        config=FederationConfig(
            entity_identifier=_ISSUER, trust_anchors=(anchor,), algorithm=JWTAlgorithm.ES256
        ),
        token_manager=token_manager,
        key_provider=KeyManagerFederationKeyProvider(key_manager),
        fetcher=fetcher,
    )

    chain = run(usecase.resolve_trust_chain("https://rp.example", anchor))

    assert chain is not None
    assert chain.subject.subject == "https://rp.example"
    assert chain.trust_anchor.issuer == anchor
    assert len(chain.statements) == 3


def _app(*, enabled: bool) -> FastAPI:
    """Application de test, avec ou sans le support de la Fédération."""
    return create_app(
        Settings(
            issuer=_ISSUER,
            base_url=_ISSUER,
            jwks_algorithms=("RS256", "ES256"),
            federation_enabled=enabled,
            federation_entity_identifier=_ISSUER,
        )
    )


def test_federation_endpoint_is_absent_by_default() -> None:
    """Sans le drapeau, aucune route de Fédération n'est exposée (404)."""
    with TestClient(_app(enabled=False)) as client:
        response = client.get("/.well-known/openid-federation")

    assert response.status_code == 404


def test_federation_endpoint_publishes_the_entity_statement() -> None:
    """L'entity statement est publié au type MIME dédié (spec §15.1)."""
    with TestClient(_app(enabled=True)) as client:
        response = client.get("/.well-known/openid-federation")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(ENTITY_STATEMENT_MEDIA_TYPE)
    claims = pyjwt.decode(response.text, options={"verify_signature": False})
    assert claims["iss"] == _ISSUER
    assert claims["sub"] == _ISSUER
    assert "openid_provider" in claims["metadata"]
    assert json.loads(json.dumps(claims))["metadata"]["openid_provider"]["issuer"] == _ISSUER


def test_discovery_publishes_the_federation_registration_types() -> None:
    """Le discovery annonce les modes d'enregistrement fédérés (§12)."""
    with TestClient(_app(enabled=True)) as client:
        metadata = client.get("/.well-known/openid-configuration").json()

    assert "automatic" in metadata["client_registration_types_supported"]


def test_discovery_omits_the_federation_members_by_default() -> None:
    """Sans le drapeau, le discovery ne publie aucun membre de Fédération."""
    with TestClient(_app(enabled=False)) as client:
        metadata = client.get("/.well-known/openid-configuration").json()

    assert "client_registration_types_supported" not in metadata
    assert "federation_registration_endpoint" not in metadata


def test_metadata_provider_returns_the_op_metadata() -> None:
    """Le provider de metadata expose les metadata de l'OP (spec §5.2)."""
    from puridentityserver.application.discovery import DiscoveryConfig, DiscoveryUseCase

    provider = DiscoveryFederationMetadataProvider(
        DiscoveryUseCase(DiscoveryConfig(issuer=_ISSUER))
    )

    metadata = run(provider.federation_metadata())

    assert "openid_provider" in metadata
    assert metadata["openid_provider"]["issuer"] == _ISSUER


# --- Enregistrement automatique (OpenID Federation 1.1 §12.1) ---------------

_RP = "https://rp.example"
_RP_JWK = {"kty": "EC", "crv": "P-256", "x": "aq", "y": "AQ"}


def _rp_usecase(rp_metadata: dict[str, Any]) -> FederationUseCase:
    """Cas d'usage dont la fédération résout un RP avec ses metadata."""
    key_manager = _key_manager()
    token_manager = PyJWTFederationTokenManager(key_manager, JWTAlgorithm.ES256)
    jwks = run(KeyManagerFederationKeyProvider(key_manager).public_jwks())
    anchor = "https://ta.example"

    anchor_claims = {
        "iss": anchor,
        "sub": anchor,
        "iat": _now(),
        "exp": _now() + 3600,
        "jwks": jwks,
        "metadata": {"federation_entity": {"federation_fetch_endpoint": f"{anchor}/fetch"}},
    }
    subject_claims = {
        "iss": _RP,
        "sub": _RP,
        "iat": _now(),
        "exp": _now() + 3600,
        "jwks": jwks,
        "metadata": {"openid_relying_party": rp_metadata},
        "authority_hints": [anchor],
    }
    subordinate_claims = {
        "iss": anchor,
        "sub": _RP,
        "iat": _now(),
        "exp": _now() + 3600,
        "jwks": jwks,
    }
    sign = lambda claims: run(  # ruff: ignore[lambda-assignment]
        token_manager.sign_entity_statement(algorithm=JWTAlgorithm.ES256, claims=claims, key_id="")
    )
    fetcher = _StaticFetcher(
        {
            f"{_RP}{ENTITY_CONFIGURATION_PATH}": sign(subject_claims),
            f"{anchor}{ENTITY_CONFIGURATION_PATH}": sign(anchor_claims),
            f"{anchor}/fetch?sub={_RP}": sign(subordinate_claims),
        }
    )
    return FederationUseCase(
        config=FederationConfig(
            entity_identifier=_ISSUER, trust_anchors=(anchor,), algorithm=JWTAlgorithm.ES256
        ),
        token_manager=token_manager,
        key_provider=KeyManagerFederationKeyProvider(key_manager),
        fetcher=fetcher,
    )


class _ChainUseCase:
    """Cas d'usage factice renvoyant une chaîne de confiance pré-construite."""

    def __init__(self, chain: TrustChain | None) -> None:
        self._chain = chain

    async def resolve_trust_chain(self, subject: str, trust_anchor: str) -> TrustChain | None:
        return self._chain


def _chain_with_metadata(metadata: dict[str, Any]) -> TrustChain:
    """Chaîne d'un seul statement portant les metadata du RP."""
    statement = EntityStatement(
        issuer=_RP,
        subject=_RP,
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC),
        jwks={"keys": []},
        metadata=metadata,
    )
    return TrustChain(statements=(statement,))


def _client_reader(
    client: Client | None = None,
) -> tuple[ClientReader, list[str]]:
    """Lecteur de registre factice retenant les appels reçus."""
    calls: list[str] = []

    class _Reader:
        async def find_by_id(self, client_id: str) -> Client | None:
            calls.append(f"find_by_id:{client_id}")
            return client

        async def find_all(self) -> list[Client]:
            calls.append("find_all")
            return [client] if client is not None else []

        async def is_cors_origin_allowed(self, origin: str) -> bool:
            calls.append(f"is_cors_origin_allowed:{origin}")
            return origin == "https://app.example"

    return _Reader(), calls  # type: ignore[return-value]


def test_resolver_derives_the_client_from_the_rp_entity_statement() -> None:
    """Le client dérive de l'entity statement du RP (spec §12.1, §5.1)."""
    usecase = _rp_usecase({"redirect_uris": [_RP + "/callback"], "jwks": {"keys": [_RP_JWK]}})
    resolver = TrustChainClientResolver(lambda: usecase)

    client = run(resolver.resolve(_RP))

    assert client is not None
    assert client.client_id == _RP
    assert client.redirect_uris == frozenset({_RP + "/callback"})
    assert client.client_type == ClientType.PUBLIC
    assert client.token_endpoint_auth_method == TokenEndpointAuthMethod.PRIVATE_KEY_JWT
    assert client.scopes == frozenset({Scope.OPENID})
    assert client.is_active
    assert _RP_JWK in client.jwks


def test_resolver_returns_none_without_a_use_case() -> None:
    """Sans cas d'usage de la Fédération, aucun client n'est dérivé."""
    resolver = TrustChainClientResolver(lambda: None)

    assert run(resolver.resolve(_RP)) is None


def test_resolver_returns_none_for_an_unknown_entity() -> None:
    """Une entité hors chaîne de confiance ne dérive aucun client."""
    resolver = TrustChainClientResolver(lambda: _ChainUseCase(None))  # type: ignore[arg-type]

    assert run(resolver.resolve(_RP)) is None


def test_resolver_rejects_metadata_without_relying_party() -> None:
    """Un entity statement sans type `openid_relying_party` est refusé."""
    resolver = TrustChainClientResolver(
        lambda: _ChainUseCase(  # type: ignore[arg-type]
            _chain_with_metadata({"openid_provider": {"issuer": _RP}})
        )
    )

    assert run(resolver.resolve(_RP)) is None


def test_resolver_rejects_missing_or_empty_redirect_uris() -> None:
    """Sans `redirect_uris` exploitables, aucun client n'est dérivé."""
    jwks = {"keys": [_RP_JWK]}
    for metadata in ({"jwks": jwks}, {"redirect_uris": [], "jwks": jwks}, {"redirect_uris": "x"}):
        resolver = TrustChainClientResolver(
            lambda metadata=metadata: _ChainUseCase(  # type: ignore[arg-type]
                _chain_with_metadata({"openid_relying_party": metadata})
            )
        )

        assert run(resolver.resolve(_RP)) is None


def test_resolver_rejects_an_invalid_jwks() -> None:
    """Un `jwks` absent ou mal formé est refusé (spec §5.1)."""
    uris = [_RP + "/callback"]
    for jwks in ({}, {"keys": "x"}):
        resolver = TrustChainClientResolver(
            lambda jwks=jwks: _ChainUseCase(  # type: ignore[arg-type]
                _chain_with_metadata(
                    {"openid_relying_party": {"redirect_uris": uris, "jwks": jwks}}
                )
            )
        )

        assert run(resolver.resolve(_RP)) is None


def test_resolver_normalizes_non_mapping_jwk_entries() -> None:
    """Une entrée de `keys` qui n'est pas un objet devient une clé vide."""
    resolver = TrustChainClientResolver(
        lambda: _ChainUseCase(  # type: ignore[arg-type]
            _chain_with_metadata(
                {"openid_relying_party": {"redirect_uris": [_RP + "/c"], "jwks": {"keys": ["x"]}}}
            )
        )
    )

    client = run(resolver.resolve(_RP))

    assert client is not None
    assert client.jwks == ({},)


def test_reader_prefers_the_registered_client() -> None:
    """Le registre reste la source de vérité : la fédération n'est pas consultée."""
    registered = Client(client_id="web-app")
    registry, calls = _client_reader(registered)
    called = False

    def _should_not_resolve() -> None:
        nonlocal called
        called = True

    reader = FederatedClientReader(
        registry,  # type: ignore[arg-type]
        TrustChainClientResolver(_should_not_resolve),  # type: ignore[arg-type]
    )

    assert run(reader.find_by_id("web-app")) is registered
    assert calls == ["find_by_id:web-app"]
    assert not called


def test_reader_resolves_an_unknown_entity_identifier() -> None:
    """Un `client_id` inconnu est résolu dans la fédération (spec §12.1)."""
    derived = Client(client_id=_RP)
    registry, calls = _client_reader()
    resolver = TrustChainClientResolver(
        lambda: _ChainUseCase(  # type: ignore[arg-type]
            TrustChain(statements=())
        )
    )

    async def _resolve(entity_identifier: str) -> Client | None:
        calls.append(f"resolve:{entity_identifier}")
        await asyncio.sleep(0)
        return derived

    resolver.resolve = _resolve  # type: ignore[method-assign]
    reader = FederatedClientReader(registry, resolver)  # type: ignore[arg-type]

    assert run(reader.find_by_id(_RP)) is derived
    assert calls == [f"find_by_id:{_RP}", f"resolve:{_RP}"]


def test_reader_returns_none_without_a_resolver() -> None:
    """Sans résolveur (Fédération désactivée), un client inconnu est refusé."""
    registry, _ = _client_reader()
    reader = FederatedClientReader(registry)  # type: ignore[arg-type]

    assert run(reader.find_by_id("inconnu")) is None


def test_reader_delegates_find_all_and_cors() -> None:
    """Les autres accès du registre sont délégués tels quels."""
    registered = Client(client_id="web-app")
    registry, calls = _client_reader(registered)
    reader = FederatedClientReader(registry, None)  # type: ignore[arg-type]

    assert run(reader.find_all()) == [registered]
    assert run(reader.is_cors_origin_allowed("https://app.example"))
    assert not run(reader.is_cors_origin_allowed("https://evil.example"))
    assert calls == [
        "find_all",
        "is_cors_origin_allowed:https://app.example",
        "is_cors_origin_allowed:https://evil.example",
    ]
