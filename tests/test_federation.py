"""Tests de la Fédération (OpenID Federation 1.1).

Couvre l'entity statement (structure §3.2), la chaîne de confiance
(§4, §10) et l'endpoint de configuration de l'OP (§9).
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Coroutine
from typing import Any, TypeVar

import jwt as pyjwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from puridentityserver.application.federation import (
    DiscoveryFederationMetadataProvider,
    FederationConfig,
    FederationUseCase,
)
from puridentityserver.domain.federation import (
    ENTITY_STATEMENT_MEDIA_TYPE,
    FederationError,
    parse_entity_statement,
)
from puridentityserver.domain.jwks import JWTAlgorithm, KeyUse
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
