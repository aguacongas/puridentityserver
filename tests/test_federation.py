"""Tests de la Fédération (OpenID Federation 1.1).

Couvre l'entity statement (structure §3.2), la chaîne de confiance
(§4, §10), l'endpoint de configuration de l'OP (§9), les endpoints de
supérieur — fetch, list, resolve (§8.1-§8.3) — et l'enregistrement
(§12.1, §12.2).
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
    ENTITY_STATEMENT_TYP,
    EXPLICIT_REGISTRATION_RESPONSE_MEDIA_TYPE,
    EXPLICIT_REGISTRATION_RESPONSE_TYP,
    RESOLVE_RESPONSE_MEDIA_TYPE,
    RESOLVE_RESPONSE_TYP,
    TRUST_CHAIN_MEDIA_TYPE,
    EntityStatement,
    FederationError,
    FederationRegistrationError,
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
from puridentityserver.interfaces.api.federation import federation_router
from puridentityserver.interfaces.domain.federation import (
    FederationEntityFetcher,
    FederationSubordinateSource,
)
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
    subordinate_source: FederationSubordinateSource | None = None,
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
        subordinate_source=subordinate_source,
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
    assert header["typ"] == ENTITY_STATEMENT_TYP
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
    assert metadata["federation_registration_endpoint"].endswith("/federation/register")


def test_discovery_omits_the_federation_members_by_default() -> None:
    """Sans le drapeau, le discovery ne publie aucun membre de Fédération."""
    with TestClient(_app(enabled=False)) as client:
        metadata = client.get("/.well-known/openid-configuration").json()

    assert "client_registration_types_supported" not in metadata
    assert "federation_registration_endpoint" not in metadata


def test_metadata_provider_returns_the_op_metadata() -> None:
    """Le provider expose l'OP et les endpoints de la fédération (§5.2, §5.1.1)."""
    from puridentityserver.application.discovery import DiscoveryConfig, DiscoveryUseCase

    provider = DiscoveryFederationMetadataProvider(
        DiscoveryUseCase(DiscoveryConfig(issuer=_ISSUER)), _ISSUER
    )

    metadata = run(provider.federation_metadata())

    assert "openid_provider" in metadata
    assert metadata["openid_provider"]["issuer"] == _ISSUER
    federation = metadata["federation_entity"]
    assert federation["federation_fetch_endpoint"] == f"{_ISSUER}/federation/fetch"
    assert federation["federation_list_endpoint"] == f"{_ISSUER}/federation/list"
    assert federation["federation_resolve_endpoint"] == f"{_ISSUER}/federation/resolve"


def test_metadata_provider_publishes_the_required_discovery_fields() -> None:
    """OIDC Discovery 1.0 §3 : les deux champs REQUIRED figurent dans l'EC (§5.1.1).

    La suite de certification les valide dans ``metadata.openid_provider``
    de l'entity statement (``OIDCCCheckDiscEndpointResponseTypesSupported-
    Dynamic``, ``CheckDiscEndpointSubjectTypesSupported``).
    """
    from puridentityserver.application.discovery import DiscoveryConfig, DiscoveryUseCase

    provider = DiscoveryFederationMetadataProvider(
        DiscoveryUseCase(DiscoveryConfig(issuer=_ISSUER)), _ISSUER
    )

    metadata = run(provider.federation_metadata())["openid_provider"]

    assert metadata["response_types_supported"] == [
        "code",
        "id_token",
        "token",
        "id_token token",
        "code id_token",
        "code token",
        "code id_token token",
    ]
    assert metadata["subject_types_supported"] == ["public", "pairwise", "ephemeral"]


def test_federation_allow_local_targets_env_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    """`PURIDENTITYSERVER_FEDERATION_ALLOW_LOCAL_TARGETS` ouvre les cibles locales."""
    assert Settings(_env_file=None).federation_allow_local_targets is False

    monkeypatch.setenv("PURIDENTITYSERVER_FEDERATION_ALLOW_LOCAL_TARGETS", "true")
    assert Settings(_env_file=None).federation_allow_local_targets is True


# --- Enregistrement automatique (OpenID Federation 1.1 §12.1) ---------------

_RP = "https://rp.example"
_ANCHOR = "https://ta.example"
_RP_JWK = {"kty": "EC", "crv": "P-256", "x": "aq", "y": "AQ"}
_RP_METADATA = {
    "redirect_uris": ["https://rp.example/cb"],
    "jwks": {"keys": [_RP_JWK]},
}


def _rp_usecase(
    rp_metadata: dict[str, Any],
    *,
    trust_anchors: tuple[str, ...] = (_ANCHOR,),
    rp_authority_hints: tuple[str, ...] = (_ANCHOR,),
) -> FederationUseCase:
    """Cas d'usage dont la fédération résout un RP avec ses metadata."""
    key_manager = _key_manager()
    token_manager = PyJWTFederationTokenManager(key_manager, JWTAlgorithm.ES256)
    jwks = run(KeyManagerFederationKeyProvider(key_manager).public_jwks())
    anchor = _ANCHOR

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
        "aud": _ISSUER,
        "jwks": jwks,
        "metadata": {"openid_relying_party": rp_metadata},
        "authority_hints": list(rp_authority_hints),
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
            entity_identifier=_ISSUER, trust_anchors=trust_anchors, algorithm=JWTAlgorithm.ES256
        ),
        token_manager=token_manager,
        key_provider=KeyManagerFederationKeyProvider(key_manager),
        fetcher=fetcher,
    )


# --- Ancres de confiance (périmètre `trust_anchors`) -----------------------


def test_resolve_rejects_a_chain_anchored_outside_the_configured_anchors() -> None:
    """Une ancre absente de `trust_anchors` n'inaugure aucune chaîne (§10)."""
    usecase = _rp_usecase(_RP_METADATA, trust_anchors=("https://autre.example",))

    chain = run(usecase.resolve_trust_chain(_RP, ""))

    assert chain is None


def test_resolve_rejects_a_self_rooted_entity_when_anchors_are_configured() -> None:
    """Un RP sans `authority_hints` ne peut pas s'auto-déclarer ancre."""
    usecase = _rp_usecase(_RP_METADATA, rp_authority_hints=())

    chain = run(usecase.resolve_trust_chain(_RP, ""))

    assert chain is None


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
    assert client.client_type == ClientType.CONFIDENTIAL
    assert client.token_endpoint_auth_method == TokenEndpointAuthMethod.PRIVATE_KEY_JWT
    assert client.scopes == frozenset({Scope.OPENID})
    assert client.is_active
    assert client.federated is True
    assert _RP_JWK in client.jwks


def test_resolver_derives_the_client_when_keys_are_referenced_by_jwks_uri() -> None:
    """Le client dérive aussi avec les clés publiées à `jwks_uri` (spec §6.1).

    Le RP peut publier ses clés par référence (comme le fait la suite de
    certification) : le client dérivé porte alors ``jwks_uri`` et sa clé est
    résolue à la demande lors de la vérification des signatures.
    """
    usecase = _rp_usecase({"redirect_uris": [_RP + "/callback"], "jwks_uri": _RP + "/jwks"})
    resolver = TrustChainClientResolver(lambda: usecase)

    client = run(resolver.resolve(_RP))

    assert client is not None
    assert client.client_id == _RP
    assert client.redirect_uris == frozenset({_RP + "/callback"})
    assert client.jwks == ()
    assert client.jwks_uri == _RP + "/jwks"


def test_resolver_prefers_inline_jwks_over_jwks_uri() -> None:
    """Le ``jwks`` inline prime sur la référence ``jwks_uri`` (pas de fetch)."""
    usecase = _rp_usecase(
        {**_RP_METADATA, "jwks_uri": _RP + "/jwks"},
    )
    resolver = TrustChainClientResolver(lambda: usecase)

    client = run(resolver.resolve(_RP))

    assert client is not None
    assert _RP_JWK in client.jwks
    assert client.jwks_uri == ""


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
    """Un `jwks` absent ou mal formé, sans `jwks_uri`, est refusé (spec §5.1)."""
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


def test_resolver_rejects_metadata_without_any_keys() -> None:
    """Sans clés ni inline ni référencées, aucun client n'est dérivé."""
    resolver = TrustChainClientResolver(
        lambda: _ChainUseCase(  # type: ignore[arg-type]
            _chain_with_metadata({"openid_relying_party": {"redirect_uris": [_RP + "/c"]}})
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


# --- Enregistrement explicite (OpenID Federation 1.1 §12.2) ----------------


def _registration_ec(
    usecase: FederationUseCase,
    *,
    aud: str = _ISSUER,
    sub: str = _RP,
    authority_hints: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> str:
    """Entity configuration valide pour l'enregistrement explicite.

    Signée par la clé du cas d'usage : sa signature est donc vérifiable avec
    les clés que l'ancre lui a attestées dans le subordinate statement. Les
    paramètres déforment la demande pour les chemins d'erreur.
    """
    claims: dict[str, Any] = {
        "iss": _RP,
        "sub": sub,
        "iat": _now(),
        "exp": _now() + 3600,
        "aud": aud,
        "jwks": run(usecase.key_provider.public_jwks()),
        "authority_hints": authority_hints if authority_hints is not None else [_ANCHOR],
        "metadata": metadata if metadata is not None else {"openid_relying_party": _RP_METADATA},
    }
    return run(
        usecase.token_manager.sign_entity_statement(
            algorithm=JWTAlgorithm.ES256, claims=claims, key_id=""
        )
    )


def _registration_app(usecase: FederationUseCase) -> FastAPI:
    """Application de test montant le routeur de la Fédération seul."""
    app = FastAPI()
    app.include_router(federation_router(usecase))
    return app


def test_explicit_registration_returns_a_signed_response() -> None:
    """La réponse reprend le client provisionné (spec §12.2.3, §12.3)."""
    usecase = _rp_usecase(_RP_METADATA)
    entity_configuration = _registration_ec(usecase)

    response = run(usecase.explicit_register(entity_configuration))

    assert pyjwt.get_unverified_header(response)["typ"] == EXPLICIT_REGISTRATION_RESPONSE_TYP
    claims = pyjwt.decode(response, options={"verify_signature": False})
    assert claims["iss"] == _ISSUER
    assert claims["sub"] == _RP
    assert claims["aud"] == _RP
    assert claims["trust_anchor"] == _ANCHOR
    assert claims["authority_hints"] == [_ANCHOR]
    registered = claims["metadata"]["openid_relying_party"]
    assert registered["client_id"] == _RP
    assert registered["token_endpoint_auth_method"] == "private_key_jwt"
    assert registered["redirect_uris"] == ["https://rp.example/cb"]
    assert registered["jwks"] == {"keys": [_RP_JWK]}
    source = pyjwt.decode(entity_configuration, options={"verify_signature": False})
    assert claims["jwks"] == source["jwks"]
    assert claims["exp"] <= source["exp"]


def test_explicit_registration_rejects_a_wrong_audience() -> None:
    """L'audience doit nommer l'OP et lui seul (spec §12.2.1)."""
    usecase = _rp_usecase(_RP_METADATA)
    entity_configuration = _registration_ec(usecase, aud="https://autre.example")

    registration = usecase.explicit_register(entity_configuration)

    with pytest.raises(FederationRegistrationError) as error:
        run(registration)

    assert error.value.code == "invalid_client"


def test_explicit_registration_rejects_an_unreadable_statement() -> None:
    """Un corps qui n'est pas un JWT est refusé (invalid_client, §12.2.4)."""
    usecase = _rp_usecase(_RP_METADATA)

    registration = usecase.explicit_register("pas-un-jwt")

    with pytest.raises(FederationRegistrationError) as error:
        run(registration)

    assert error.value.code == "invalid_client"


def test_explicit_registration_rejects_a_bad_signature() -> None:
    """Un EC signé par une autre clé que celle du `jwks` est refusé (§3.2)."""
    usecase = _rp_usecase(_RP_METADATA)
    intruder = PyJWTFederationTokenManager(_key_manager(), JWTAlgorithm.ES256)
    entity_configuration = run(
        intruder.sign_entity_statement(
            algorithm=JWTAlgorithm.ES256,
            claims={
                "iss": _RP,
                "sub": _RP,
                "iat": _now(),
                "exp": _now() + 3600,
                "aud": _ISSUER,
                # Clés attestées du RP : la signature de l'intrus est fausse.
                "jwks": run(usecase.key_provider.public_jwks()),
                "authority_hints": [_ANCHOR],
                "metadata": {"openid_relying_party": _RP_METADATA},
            },
            key_id="",
        )
    )

    registration = usecase.explicit_register(entity_configuration)

    with pytest.raises(FederationRegistrationError) as error:
        run(registration)

    assert error.value.code == "invalid_client"


def test_explicit_registration_rejects_an_iss_sub_mismatch() -> None:
    """`iss` et `sub` doivent valoir l'Entity Identifier du RP (§12.2.1)."""
    usecase = _rp_usecase(_RP_METADATA)
    entity_configuration = _registration_ec(usecase, sub="https://autre.example")

    registration = usecase.explicit_register(entity_configuration)

    with pytest.raises(FederationRegistrationError) as error:
        run(registration)

    assert error.value.code == "invalid_client"


def test_explicit_registration_requires_authority_hints() -> None:
    """Sans `authority_hints`, la chaîne n'est pas résoluble (§12.2.1)."""
    usecase = _rp_usecase(_RP_METADATA)
    entity_configuration = _registration_ec(usecase, authority_hints=[])

    registration = usecase.explicit_register(entity_configuration)

    with pytest.raises(FederationRegistrationError) as error:
        run(registration)

    assert error.value.code == "invalid_trust_chain"


def test_explicit_registration_rejects_an_unresolvable_chain() -> None:
    """Un supérieur injoignable refuse la demande (invalid_trust_chain)."""
    usecase = _rp_usecase(_RP_METADATA)
    entity_configuration = _registration_ec(usecase, authority_hints=["https://inconnu.example"])

    registration = usecase.explicit_register(entity_configuration)

    with pytest.raises(FederationRegistrationError) as error:
        run(registration)

    assert error.value.code == "invalid_trust_chain"


def test_explicit_registration_rejects_an_unconfigured_anchor() -> None:
    """Une chaîne aboutissant hors `trust_anchors` est refusée (§10.1)."""
    usecase = _rp_usecase(_RP_METADATA, trust_anchors=("https://autre.example",))
    entity_configuration = _registration_ec(usecase)

    registration = usecase.explicit_register(entity_configuration)

    with pytest.raises(FederationRegistrationError) as error:
        run(registration)

    assert error.value.code == "invalid_trust_chain"


def test_explicit_registration_rejects_an_unattested_key() -> None:
    """Un EC auto-signé par une clé non attestée de l'ancre est refusé.

    C'est la liaison `subordinate statement` → `jwks` de l'EC (§10.2, étape 6)
    qui empêche un tiers de se substituer au RP légitime : l'intrus contrôle
    sa propre clé, mais l'ancre n'a pas attesté celle-là.
    """
    usecase = _rp_usecase(_RP_METADATA)
    intruder_keys = _key_manager()
    intruder = PyJWTFederationTokenManager(intruder_keys, JWTAlgorithm.ES256)
    entity_configuration = run(
        intruder.sign_entity_statement(
            algorithm=JWTAlgorithm.ES256,
            claims={
                "iss": _RP,
                "sub": _RP,
                "iat": _now(),
                "exp": _now() + 3600,
                "aud": _ISSUER,
                # Clés de l'intrus : auto-cohérentes, donc auto-vérifiables.
                "jwks": run(KeyManagerFederationKeyProvider(intruder_keys).public_jwks()),
                "authority_hints": [_ANCHOR],
                "metadata": {"openid_relying_party": _RP_METADATA},
            },
            key_id="",
        )
    )

    registration = usecase.explicit_register(entity_configuration)

    with pytest.raises(FederationRegistrationError) as error:
        run(registration)

    assert error.value.code == "invalid_trust_chain"


def test_explicit_registration_rejects_incomplete_rp_metadata() -> None:
    """Des metadata sans `jwks` inline refusent la demande (§12.2.4)."""
    usecase = _rp_usecase(_RP_METADATA)
    entity_configuration = _registration_ec(
        usecase, metadata={"openid_relying_party": {"redirect_uris": ["https://rp.example/cb"]}}
    )

    registration = usecase.explicit_register(entity_configuration)

    with pytest.raises(FederationRegistrationError) as error:
        run(registration)

    assert error.value.code == "invalid_client_metadata"


def test_explicit_registration_route_returns_the_response() -> None:
    """La route POST répond 200 avec le type MIME dédié (spec §15.8)."""
    usecase = _rp_usecase(_RP_METADATA)
    entity_configuration = _registration_ec(usecase)

    with TestClient(_registration_app(usecase)) as client:
        response = client.post(
            "/federation/register",
            content=entity_configuration,
            headers={"content-type": ENTITY_STATEMENT_MEDIA_TYPE},
        )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(EXPLICIT_REGISTRATION_RESPONSE_MEDIA_TYPE)
    claims = pyjwt.decode(response.text, options={"verify_signature": False})
    assert claims["sub"] == _RP
    assert claims["metadata"]["openid_relying_party"]["client_id"] == _RP


def test_explicit_registration_route_accepts_a_trust_chain_body() -> None:
    """Un corps `trust-chain+json` vaut : son premier statement est retenu (§12.2.2)."""
    usecase = _rp_usecase(_RP_METADATA)
    body = json.dumps([_registration_ec(usecase), "ignoré"])

    with TestClient(_registration_app(usecase)) as client:
        response = client.post(
            "/federation/register",
            content=body,
            headers={"content-type": TRUST_CHAIN_MEDIA_TYPE},
        )

    assert response.status_code == 200
    claims = pyjwt.decode(response.text, options={"verify_signature": False})
    assert claims["sub"] == _RP


def test_explicit_registration_route_rejects_an_unsupported_content_type() -> None:
    """Un Content-Type inconnu est refusé : invalid_request (spec §12.2.4)."""
    usecase = _rp_usecase(_RP_METADATA)

    with TestClient(_registration_app(usecase)) as client:
        response = client.post(
            "/federation/register",
            content="{}",
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"
    assert response.json()["error_description"]


def test_explicit_registration_route_rejects_an_invalid_json_chain() -> None:
    """Une chaîne JSON non déchiffrable est refusée : invalid_request."""
    usecase = _rp_usecase(_RP_METADATA)

    with TestClient(_registration_app(usecase)) as client:
        response = client.post(
            "/federation/register",
            content="pas-du-json",
            headers={"content-type": TRUST_CHAIN_MEDIA_TYPE},
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_explicit_registration_route_rejects_an_empty_chain() -> None:
    """Une chaîne vide est refusée : invalid_request (§12.2.1)."""
    usecase = _rp_usecase(_RP_METADATA)

    with TestClient(_registration_app(usecase)) as client:
        response = client.post(
            "/federation/register",
            content="[]",
            headers={"content-type": TRUST_CHAIN_MEDIA_TYPE},
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_explicit_registration_route_maps_a_signature_rejection_to_401() -> None:
    """Un client dont la demande est rejetée reçoit 401 + error_description (§8.9)."""
    usecase = _rp_usecase(_RP_METADATA)

    with TestClient(_registration_app(usecase)) as client:
        response = client.post(
            "/federation/register",
            content="pas-un-jwt",
            headers={"content-type": ENTITY_STATEMENT_MEDIA_TYPE},
        )

    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"
    assert response.json()["error_description"]


def test_explicit_registration_route_is_absent_by_default() -> None:
    """Sans le drapeau, aucune route d'enregistrement n'est exposée (404)."""
    with TestClient(_app(enabled=False)) as client:
        response = client.post(
            "/federation/register",
            content="x",
            headers={"content-type": ENTITY_STATEMENT_MEDIA_TYPE},
        )

    assert response.status_code == 404


# --- Endpoints de supérieur : fetch, list, resolve (OpenID Federation §8) ---


class _SubordinateSource:
    """Source de subordonnés factice (les clients enregistrés de l'OP)."""

    def __init__(self, clients: tuple[Client, ...]) -> None:
        self._clients = clients

    async def subordinates(self) -> list[Client]:
        return list(self._clients)


def _federated_client(client_id: str = _RP) -> Client:
    """Client enregistré identifié par un Entity Identifier, avec clés."""
    return Client(
        client_id=client_id,
        redirect_uris=frozenset({f"{client_id}/cb"}),
        jwks=(_RP_JWK,),
    )


def test_fetch_requires_a_sub_parameter() -> None:
    """Sans `sub`, le fetch répond `invalid_request` (spec §8.1.2, §8.9)."""
    with TestClient(_registration_app(_usecase())) as client:
        response = client.get("/federation/fetch")

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"
    assert response.json()["error_description"]


def test_fetch_rejects_the_issuing_entity_as_sub() -> None:
    """`sub` valant l'Entity Identifier de l'OP est un `invalid_request` (§8.1.2)."""
    with TestClient(_registration_app(_usecase())) as client:
        response = client.get("/federation/fetch", params={"sub": _ISSUER})

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_fetch_returns_not_found_for_an_unknown_subordinate() -> None:
    """Une entité qui n'est pas un subordonné immédiat répond `not_found` (§8.1.3)."""
    usecase = _usecase(subordinate_source=_SubordinateSource((_federated_client(),)))

    with TestClient(_registration_app(usecase)) as client:
        response = client.get("/federation/fetch", params={"sub": "https://inconnu.example"})

    assert response.status_code == 404
    assert response.json()["error"] == "not_found"
    assert response.json()["error_description"]


def test_fetch_returns_the_subordinate_statement() -> None:
    """Le fetch rend le statement attestant le subordonné (spec §8.1, §3.1.2)."""
    usecase = _usecase(subordinate_source=_SubordinateSource((_federated_client(),)))

    with TestClient(_registration_app(usecase)) as client:
        response = client.get("/federation/fetch", params={"sub": _RP})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(ENTITY_STATEMENT_MEDIA_TYPE)
    assert pyjwt.get_unverified_header(response.text)["typ"] == ENTITY_STATEMENT_TYP
    claims = pyjwt.decode(response.text, options={"verify_signature": False})
    assert claims["iss"] == _ISSUER
    assert claims["sub"] == _RP
    assert claims["jwks"] == {"keys": [_RP_JWK]}
    registered = claims["metadata"]["openid_relying_party"]
    assert registered["redirect_uris"] == [f"{_RP}/cb"]
    assert registered["jwks"] == {"keys": [_RP_JWK]}
    assert "authority_hints" not in claims
    verified = usecase.token_manager.verify_entity_statement(
        token=response.text,
        jwks=run(usecase.key_provider.public_jwks()),
        issuer=_ISSUER,
        subject=_RP,
    )
    assert verified is not None


def test_fetch_ignores_clients_without_federation_keys() -> None:
    """Un client sans clés ou sans Entity Identifier n'est pas un subordonné."""
    without_keys = Client(client_id=_RP, redirect_uris=frozenset({f"{_RP}/cb"}))
    not_an_entity = Client(client_id="web-app", jwks=(_RP_JWK,))
    usecase = _usecase(subordinate_source=_SubordinateSource((without_keys, not_an_entity)))

    with TestClient(_registration_app(usecase)) as client:
        response = client.get("/federation/fetch", params={"sub": _RP})

    assert response.status_code == 404
    assert response.json()["error"] == "not_found"


def test_list_returns_the_subordinate_identifiers() -> None:
    """La liste rend triés les Entity Identifier des subordonnés (§8.2.2)."""
    source = _SubordinateSource(
        (
            _federated_client("https://deuxieme.example"),
            _federated_client(),
            Client(client_id="web-app", jwks=(_RP_JWK,)),
        )
    )

    with TestClient(_registration_app(_usecase(subordinate_source=source))) as client:
        response = client.get("/federation/list")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == ["https://deuxieme.example", _RP]


def test_list_rejects_unsupported_filter_parameters() -> None:
    """Un filtre non supporté répond `unsupported_parameter` (§8.2.1)."""
    with TestClient(_registration_app(_usecase())) as client:
        response = client.get("/federation/list", params={"entity_type": "openid_relying_party"})

    assert response.status_code == 400
    assert response.json()["error"] == "unsupported_parameter"


def test_list_returns_an_empty_array_without_subordinates() -> None:
    """Sans source de subordonnés, la liste est vide (§8.2.2)."""
    with TestClient(_registration_app(_usecase())) as client:
        response = client.get("/federation/list")

    assert response.status_code == 200
    assert response.json() == []


def test_resolve_requires_sub_and_trust_anchor() -> None:
    """Sans paramètre obligatoire, le resolve répond `invalid_request` (§8.3)."""
    with TestClient(_registration_app(_rp_usecase(_RP_METADATA))) as client:
        response = client.get("/federation/resolve")

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


def test_resolve_returns_the_resolved_trust_chain() -> None:
    """La résolution signée porte `trust_chain` et les metadata (§8.3.2)."""
    usecase = _rp_usecase(_RP_METADATA)

    with TestClient(_registration_app(usecase)) as client:
        response = client.get("/federation/resolve", params={"sub": _RP, "trust_anchor": _ANCHOR})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(RESOLVE_RESPONSE_MEDIA_TYPE)
    assert pyjwt.get_unverified_header(response.text)["typ"] == RESOLVE_RESPONSE_TYP
    claims = pyjwt.decode(response.text, options={"verify_signature": False})
    assert claims["iss"] == _ISSUER
    assert claims["sub"] == _RP
    assert claims["metadata"]["openid_relying_party"] == _RP_METADATA
    assert len(claims["trust_chain"]) == 3
    first = pyjwt.decode(claims["trust_chain"][0], options={"verify_signature": False})
    assert first["sub"] == _RP
    assert claims["exp"] <= first["exp"]


def test_resolve_returns_not_found_for_an_unconfigured_anchor() -> None:
    """Une ancre hors `trust_anchors` configuré répond `not_found` (§10.1)."""
    usecase = _rp_usecase(_RP_METADATA, trust_anchors=("https://autre.example",))

    with TestClient(_registration_app(usecase)) as client:
        response = client.get("/federation/resolve", params={"sub": _RP, "trust_anchor": _ANCHOR})

    assert response.status_code == 404
    assert response.json()["error"] == "not_found"
