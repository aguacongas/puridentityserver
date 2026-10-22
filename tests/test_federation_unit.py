"""Tests unitaires complémentaires de la Fédération (couverture des branches).

Complète `tests/test_federation.py` : chaque membre optionnel d'un entity
statement, la politique de metadata, les rejets de validation et les refus du
lecteur HTTP.
"""

from __future__ import annotations

import asyncio
from typing import Any

import jwt as pyjwt
import pytest

from puridentityserver.application.federation import FederationConfig, FederationUseCase
from puridentityserver.domain.federation import (
    FederationError,
    TrustChain,
    parse_entity_statement,
    validate_metadata_policy,
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

_ISSUER = "https://id.example"


def _now() -> int:
    """Horodatage courant (secondes)."""
    import time

    return int(time.time())


def _key_manager() -> DefaultKeyManager:
    """Gestionnaire de clés de la fédération (ES256), clé générée."""
    manager = DefaultKeyManager(InMemoryKeyPairRepository(), use=KeyUse.FEDERATION)
    asyncio.run(manager.ensure_active_key(2048, JWTAlgorithm.ES256))
    return manager


def _claims(**overrides: object) -> dict[str, object]:
    """Claims d'un entity statement valide, avec les surcharges appliquées."""
    base: dict[str, Any] = {
        "iss": _ISSUER,
        "sub": _ISSUER,
        "iat": _now(),
        "exp": _now() + 3600,
        "jwks": {"keys": []},
    }
    base.update(overrides)
    return base


def test_parse_entity_statement_reads_the_optional_members() -> None:
    """Les membres optionnels de l'entity statement sont lus (spec §3.1)."""
    statement = parse_entity_statement(
        _claims(
            metadata={"openid_provider": {"issuer": _ISSUER}},
            authority_hints=["https://intermediate.example"],
            trust_anchor_hints=["https://ta.example"],
            trust_marks=[{"trust_mark_type": "x", "trust_mark": "jwt"}],
            constraints={"max_path_length": 2},
            metadata_policy={"openid_provider": {"issuer": {"value": _ISSUER}}},
            metadata_policy_crit=["regexp"],
            source_endpoint="https://intermediate.example/fetch",
        )
    )

    assert statement.authority_hints == ("https://intermediate.example",)
    assert statement.trust_anchor_hints == ("https://ta.example",)
    assert statement.constraints == {"max_path_length": 2}
    assert statement.metadata_policy is not None
    assert statement.metadata_policy_crit == ("regexp",)
    assert statement.source_endpoint == "https://intermediate.example/fetch"
    assert statement.entity_types == ("openid_provider",)
    assert statement.is_self_signed


def test_entity_statement_serialises_its_claims() -> None:
    """`to_claims` restitue les claims de l'entity statement (spec §3.1)."""
    statement = parse_entity_statement(_claims(metadata={"openid_provider": {"issuer": _ISSUER}}))

    claims = statement.to_claims()

    assert claims["iss"] == _ISSUER
    assert claims["sub"] == _ISSUER
    assert claims["iat"] <= claims["exp"]
    assert claims["metadata"] == {"openid_provider": {"issuer": _ISSUER}}
    assert "authority_hints" not in claims
    assert set(statement.to_claims_for_comparison()) == {"iss", "sub", "jwks", "metadata"}


def test_parse_entity_statement_rejects_invalid_values() -> None:
    """Les formes invalides sont rejetées (spec §3.2)."""
    with pytest.raises(FederationError):
        parse_entity_statement(_claims(iss="http://pas-https.example"))
    with pytest.raises(FederationError):
        parse_entity_statement(_claims(sub=""))
    with pytest.raises(FederationError):
        parse_entity_statement(_claims(jwks={"pas_une_cle": []}))
    with pytest.raises(FederationError):
        parse_entity_statement(_claims(metadata="pas un objet"))
    with pytest.raises(FederationError):
        parse_entity_statement(_claims(authority_hints="pas une liste"))
    with pytest.raises(FederationError):
        parse_entity_statement(_claims(authority_hints=["http://pas-https.example"]))
    with pytest.raises(FederationError):
        parse_entity_statement(_claims(metadata_policy="pas un objet"))
    with pytest.raises(FederationError):
        parse_entity_statement(_claims(constraints="pas un objet"))
    with pytest.raises(FederationError):
        parse_entity_statement(_claims(source_endpoint=42))


def test_validate_metadata_policy_rejects_unknown_operators() -> None:
    """Un opérateur inconnu invalide la metadata policy (spec §3.2, étape 18)."""
    validate_metadata_policy({"openid_provider": {"issuer": {"value": _ISSUER}}})

    with pytest.raises(FederationError):
        validate_metadata_policy({"openid_provider": {"issuer": {"inconnu": 1}}})
    with pytest.raises(FederationError):
        validate_metadata_policy({"openid_provider": "pas un objet"})
    with pytest.raises(FederationError):
        validate_metadata_policy({"openid_provider": {"issuer": "pas un objet"}})


def test_trust_chain_resolves_the_metadata_with_the_policy() -> None:
    """La metadata du supérieur s'applique au sujet (spec §6.1)."""
    subject = parse_entity_statement(
        _claims(metadata={"openid_provider": {"issuer": _ISSUER, "organization_name": "Demo"}})
    )
    superior = parse_entity_statement(
        _claims(
            iss="https://ta.example",
            sub="https://ta.example",
            metadata_policy={"openid_provider": {"organization_name": {"value": "Fédération"}}},
        )
    )

    chain = TrustChain(statements=(subject, superior))
    metadata = chain.resolved_metadata()

    assert metadata["openid_provider"]["organization_name"] == "Fédération"
    assert chain.subject.subject == _ISSUER
    assert chain.trust_anchor.issuer == "https://ta.example"


def test_trust_chain_rejects_an_empty_chain() -> None:
    """Une chaîne vide n'a ni sujet ni ancre (spec §4)."""
    chain = TrustChain(statements=())

    with pytest.raises(FederationError):
        _ = chain.subject
    with pytest.raises(FederationError):
        _ = chain.trust_anchor


def test_verifier_rejects_invalid_statements() -> None:
    """Le vérificateur refuse les statements invalides (spec §3.2)."""
    manager = PyJWTFederationTokenManager(_key_manager(), JWTAlgorithm.ES256)

    assert manager.unverified_claims("pas un jwt") is None
    assert manager.verify_entity_statement(token="pas un jwt", jwks={"keys": []}) is None
    assert (
        manager.verify_entity_statement(
            token="pas un jwt", jwks={"keys": [{"kid": "k1", "kty": "EC"}]}
        )
        is None
    )


def test_verifier_checks_the_typ_and_the_kid() -> None:
    """`typ` et `kid` sont obligatoires dans l'en-tête JWS (spec §3)."""
    key_manager = _key_manager()
    manager = PyJWTFederationTokenManager(key_manager, JWTAlgorithm.ES256)
    jwks = asyncio.run(KeyManagerFederationKeyProvider(key_manager).public_jwks())

    token = pyjwt.encode(
        {"iss": _ISSUER, "sub": _ISSUER, "iat": _now(), "exp": _now() + 60},
        "secret-de-test-32-octets-minimum-longueur",
        algorithm="HS256",
        headers={"typ": "autre-type", "kid": "k1"},
    )
    assert manager.verify_entity_statement(token=token, jwks=jwks) is None

    token = pyjwt.encode(
        {"iss": _ISSUER, "sub": _ISSUER, "iat": _now(), "exp": _now() + 60},
        "secret-de-test-32-octets-minimum-longueur",
        algorithm="HS256",
        headers={"typ": "entity-statement+jwt"},
    )
    assert manager.verify_entity_statement(token=token, jwks=jwks) is None


def test_verifier_checks_the_issuer_and_the_subject() -> None:
    """`iss` et `sub` doivent correspondre à l'entité attendue (spec §3.2)."""
    key_manager = _key_manager()
    manager = PyJWTFederationTokenManager(key_manager, JWTAlgorithm.ES256)
    jwks = asyncio.run(KeyManagerFederationKeyProvider(key_manager).public_jwks())

    token = asyncio.run(
        manager.sign_entity_statement(
            algorithm=JWTAlgorithm.ES256,
            claims=_claims(),
            key_id="",
        )
    )

    assert manager.verify_entity_statement(token=token, jwks=jwks) is not None
    assert manager.verify_entity_statement(token=token, jwks=jwks, issuer="https://autre") is None
    assert manager.verify_entity_statement(token=token, jwks=jwks, subject="https://autre") is None


def test_fetcher_refuses_the_unsafe_targets() -> None:
    """Le lecteur n'accepte que les URL https publiques (spec §9)."""
    fetcher = HTTPFederationEntityFetcher(allow_local_targets=False)

    assert asyncio.run(fetcher.fetch_entity_statement("http://insecure.example")) is None
    assert asyncio.run(fetcher.fetch_entity_statement("ftp://insecure.example")) is None
    assert asyncio.run(fetcher.fetch_entity_statement("https://user:pwd@example")) is None
    assert asyncio.run(fetcher.fetch_entity_statement("https://127.0.0.1/statement")) is None
    assert asyncio.run(fetcher.fetch_entity_statement("https://192.168.0.1/statement")) is None
    assert asyncio.run(fetcher.fetch_entity_statement("https://10.0.0.1/statement")) is None
    assert asyncio.run(fetcher.fetch_entity_statement("https://172.16.0.1/statement")) is None
    assert asyncio.run(fetcher.fetch_entity_statement("https://169.254.0.1/statement")) is None


def test_fetcher_returns_none_on_an_unreachable_host() -> None:
    """Un hôte injoignable ne remonte aucun statement."""
    fetcher = HTTPFederationEntityFetcher(allow_local_targets=True)

    assert asyncio.run(fetcher.fetch_entity_statement("https://localhost:1/statement")) is None


def test_resolution_stops_when_the_superior_has_no_fetch_endpoint() -> None:
    """Sans `federation_fetch_endpoint`, le superior ne peut pas attester (spec §8.1)."""
    key_manager = _key_manager()
    token_manager = PyJWTFederationTokenManager(key_manager, JWTAlgorithm.ES256)
    anchor = "https://ta.example"
    jwks = asyncio.run(KeyManagerFederationKeyProvider(key_manager).public_jwks())

    subject = asyncio.run(
        token_manager.sign_entity_statement(
            algorithm=JWTAlgorithm.ES256,
            claims=_claims(
                sub="https://rp.example",
                iss="https://rp.example",
                jwks=jwks,
                authority_hints=[anchor],
            ),
            key_id="",
        )
    )
    anchor_statement = asyncio.run(
        token_manager.sign_entity_statement(
            algorithm=JWTAlgorithm.ES256,
            claims=_claims(iss=anchor, sub=anchor, jwks=jwks),
            key_id="",
        )
    )

    usecase = FederationUseCase(
        config=FederationConfig(entity_identifier=_ISSUER, trust_anchors=(anchor,)),
        token_manager=token_manager,
        key_provider=KeyManagerFederationKeyProvider(key_manager),
        fetcher=_MapFetcher(
            {
                "https://rp.example/.well-known/openid-federation": subject,
                f"{anchor}/.well-known/openid-federation": anchor_statement,
            }
        ),
    )

    assert asyncio.run(usecase.resolve_trust_chain("https://rp.example", anchor)) is None


class _MapFetcher:
    """Fetcher renvoyant des statements pré-construits (par URL)."""

    def __init__(self, statements: dict[str, str]) -> None:
        self._statements = statements

    async def fetch_entity_statement(self, url: str) -> str | None:
        return self._statements.get(url)


def test_entity_statement_of_an_entity_without_superior() -> None:
    """Une entité sans supérieur ne publie pas d'`authority_hints` (spec §3.1.2)."""
    key_manager = _key_manager()
    manager = PyJWTFederationTokenManager(key_manager, JWTAlgorithm.ES256)
    usecase = FederationUseCase(
        config=FederationConfig(entity_identifier=_ISSUER),
        token_manager=manager,
        key_provider=KeyManagerFederationKeyProvider(key_manager),
        fetcher=HTTPFederationEntityFetcher(allow_local_targets=True),
    )

    statement = asyncio.run(usecase.entity_statement())
    claims = pyjwt.decode(statement, options={"verify_signature": False})

    assert "authority_hints" not in claims
    assert claims["sub"] == _ISSUER
