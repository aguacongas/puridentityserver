"""Cas d'usage : Fédération (OpenID Federation 1.1).

Deux opérations :

- **publier** l'entity statement de l'OP (``/.well-known/openid-federation``) ;
- **résoudre** la chaîne de confiance d'une entité (le RP fédéré) jusqu'à une
  ancre de confiance configurée, en vérifiant chaque statement au fil de
  l'eau (spec §10.1, §10.2).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from puridentityserver.application.discovery import DiscoveryUseCase
from puridentityserver.domain.federation import (
    EntityStatement,
    FederationError,
    TrustChain,
    parse_entity_statement,
)
from puridentityserver.domain.jwks import JWTAlgorithm
from puridentityserver.interfaces.domain.federation import (
    FederationEntityFetcher,
    FederationKeyProvider,
    FederationMetadataProvider,
    FederationTokenManager,
)

#: Suffixe de découverte de l'entity configuration (spec §9.1).
ENTITY_CONFIGURATION_PATH = "/.well-known/openid-federation"

#: Tolérance d'horloge sur ``iat``/``exp`` (spec §3.2, étapes 7 et 8).
_CLOCK_SKEW_SECONDS = 300


@dataclass(frozen=True, slots=True)
class FederationConfig:
    """Configuration de la Fédération côté OP.

    ``entity_identifier`` est l'Entity Identifier de l'OP : il doit être une
    URL ``https`` sans query ni fragment (spec §1.2). ``trust_anchors``
    liste les ancres de confiance acceptées : une liste vide autorise la
    résolution vers n'importe quelle ancre (développement uniquement).
    """

    entity_identifier: str
    trust_anchors: tuple[str, ...] = ()
    statement_ttl_seconds: int = 3600
    algorithm: JWTAlgorithm = JWTAlgorithm.ES256
    registration_types: tuple[str, ...] = ("automatic", "explicit")


class DiscoveryFederationMetadataProvider:
    """Metadata de l'OP publiées dans l'entity statement (spec §5.2).

    L'entity statement porte les metadata de l'OP sous le type d'entité
    ``openid_provider`` : ce sont les metadata de discovery, telles que
    publiées par l'OP (spec §5.1).
    """

    def __init__(self, discovery: DiscoveryUseCase) -> None:
        """Injection du cas d'usage de discovery."""
        self._discovery = discovery

    async def federation_metadata(self) -> Mapping[str, Any]:
        """Retourne les metadata de l'OP par type d'entité."""
        return {"openid_provider": await self._discovery.execute()}


@dataclass(slots=True)
class FederationUseCase:
    """Publie l'entity statement de l'OP et résout les chaînes de confiance."""

    config: FederationConfig
    token_manager: FederationTokenManager
    key_provider: FederationKeyProvider
    fetcher: FederationEntityFetcher
    metadata_provider: FederationMetadataProvider | None = None

    async def entity_statement(self) -> str:
        """Construit et signe l'entity statement de l'OP (spec §9.2).

        Le statement est **auto-signé** : ``iss`` et ``sub`` valent l'Entity
        Identifier de l'OP et le claim ``jwks`` porte ses propres clés de
        signature (spec §3.1.1).
        """
        metadata = await self._metadata()
        claims: dict[str, Any] = {
            "iss": self.config.entity_identifier,
            "sub": self.config.entity_identifier,
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int(
                (
                    datetime.now(timezone.utc)
                    + timedelta(seconds=self.config.statement_ttl_seconds)
                ).timestamp()
            ),
            "jwks": await self.key_provider.public_jwks(),
        }
        if metadata:
            claims["metadata"] = metadata
        if self.config.trust_anchors:
            claims["authority_hints"] = list(self.config.trust_anchors)
        return await self.token_manager.sign_entity_statement(
            algorithm=self.config.algorithm,
            claims=claims,
            key_id="",
        )

    async def resolve_trust_chain(self, subject: str, trust_anchor: str) -> TrustChain | None:
        """Résout la chaîne de confiance de ``subject`` jusqu'à l'ancre (spec §10.1).

        La résolution part de l'entity configuration du sujet et remonte ses
        ``authority_hints`` ; chaque supérieur est validé (signature contre
        ses propres clés) et fournit le *subordinate statement* attestant
        l'entité. Retourne ``None`` si la chaîne est incomplète, expirée ou
        mal signée.
        """
        statement = await self._fetch_configuration(subject)
        if statement is None:
            return None
        chain: list[EntityStatement] = [statement]
        current = statement
        seen = {subject}
        while not self._is_trust_anchor(current, trust_anchor):
            superior = await self._next_superior(current, seen)
            if superior is None:
                return None
            subordinate = await self._fetch_subordinate_statement(superior, subject)
            if subordinate is None:
                return None
            chain.append(subordinate)
            current = superior
        anchor = await self._fetch_configuration(trust_anchor)
        if anchor is None:
            return None
        chain.append(anchor)
        return TrustChain(statements=tuple(chain))

    async def _metadata(self) -> dict[str, Any]:
        """Metadata de l'OP publiées dans l'entity statement."""
        if self.metadata_provider is None:
            return {}
        metadata = await self.metadata_provider.federation_metadata()
        return dict(metadata)

    def _is_trust_anchor(self, statement: EntityStatement, trust_anchor: str) -> bool:
        """Indique si le statement est l'ancre de confiance visée."""
        if not statement.is_self_signed:
            return False
        if trust_anchor:
            return statement.issuer == trust_anchor
        return not statement.authority_hints

    async def _next_superior(
        self, statement: EntityStatement, seen: set[str]
    ) -> EntityStatement | None:
        """Entity configuration du supérieur (premier `authority_hints` valide)."""
        for hint in statement.authority_hints:
            if hint in seen:
                continue
            superior = await self._fetch_configuration(hint)
            if superior is not None:
                seen.add(hint)
                return superior
        return None

    async def _fetch_configuration(self, entity_identifier: str) -> EntityStatement | None:
        """Lit et valide l'entity configuration d'une entité (spec §9, §10.2).

        L'entity configuration est **auto-signée** : sa signature se vérifie
        contre le claim ``jwks`` qu'elle porte elle-même (spec §3.2, étape 10).
        """
        token = await self.fetcher.fetch_entity_statement(
            f"{entity_identifier.rstrip('/')}{ENTITY_CONFIGURATION_PATH}"
        )
        if token is None:
            return None
        unverified = self.token_manager.unverified_claims(token)
        if unverified is None:
            return None
        jwks = unverified.get("jwks")
        if not isinstance(jwks, Mapping):
            return None
        claims = self.token_manager.verify_entity_statement(
            token=token,
            jwks=jwks,
            issuer=entity_identifier,
            subject=entity_identifier,
        )
        if claims is None:
            return None
        try:
            return parse_entity_statement(claims)
        except FederationError:
            return None

    async def _fetch_subordinate_statement(
        self, superior: EntityStatement, subject: str
    ) -> EntityStatement | None:
        """Lit le subordinate statement émis par le supérieur (spec §8.1).

        Le supérieur publie un endpoint ``federation_fetch_endpoint`` : il
        renvoie le statement attestant l'entité subordonnée, signé par le
        supérieur.
        """
        endpoint = _federation_endpoint(superior, "federation_fetch_endpoint")
        if not endpoint:
            return None
        separator = "&" if "?" in endpoint else "?"
        token = await self.fetcher.fetch_entity_statement(f"{endpoint}{separator}sub={subject}")
        if token is None:
            return None
        claims = self.token_manager.verify_entity_statement(
            token=token,
            jwks=superior.jwks,
            issuer=superior.issuer,
            subject=subject,
        )
        if claims is None:
            return None
        try:
            return parse_entity_statement(claims)
        except FederationError:
            return None


def _federation_endpoint(statement: EntityStatement, name: str) -> str:
    """URL d'un endpoint de l'entité `federation_entity` (spec §5.2.2)."""
    metadata = statement.metadata.get("federation_entity")
    if not isinstance(metadata, Mapping):
        return ""
    value = metadata.get(name)
    return value if isinstance(value, str) else ""
